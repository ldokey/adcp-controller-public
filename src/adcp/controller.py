"""Controller-owned C4 orchestration over the frozen C1/C2/C3 primitives."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
from typing import Any, Callable, Mapping
from uuid import uuid4

from adcp.canonical import canonical_json, canonical_sha256
from adcp.artifact_seal import (
    ArtifactSealError,
    collect_manifest,
    legacy_attestation_roles,
    post_execution_roles,
    verify_manifest_bytes,
)
from adcp.capsule import CapsuleRole, ContextCapsule, build_context_capsule
from adcp.domain import (
    ActorRole,
    CandidateManifestEntry,
    CandidateWriteFence,
    EvaluatorArtifactProducerKind,
    EvaluatorArtifactSealCreate,
    EvaluatorArtifactSealPhase,
    ExecutionCreate,
    ExecutionState,
    StoreError,
    operation_key,
    timestamp,
)
from adcp.evaluator import (
    CandidateEvaluationResultRecord,
    EvaluatorArtifactBinding,
    build_evaluation_result,
    evaluation_result_identity,
    GitFingerprint,
    capture_git_fingerprint,
    evaluator_invocation,
    load_canonical_evaluation_artifact,
    maker_invocation,
)
from adcp.evidence import build_evidence_manifest
from adcp.runner import CodexRunResult, RunnerError, run_codex
from adcp.store.sqlite import (
    ControlStore,
    canonical_source_root,
    control_state_authority_fingerprint,
)
from adcp.verifier import CandidateVerificationResultRecord, VerificationResultRecord


class ControllerError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class CandidateWorktree:
    execution_id: str
    path: Path
    branch: str
    base_commit: str
    branch_created: bool = False
    worktree_created: bool = False


@dataclass(frozen=True)
class CandidateFingerprint:
    git: GitFingerprint
    refs_sha256: str


@dataclass(frozen=True)
class MakerRun:
    attempt_id: str
    candidate: CandidateWorktree
    before: CandidateFingerprint
    capsule: ContextCapsule


@dataclass(frozen=True)
class CandidateContentBinding:
    candidate_id: str
    execution_id: str
    serialization_format: str
    serialization_version: int
    repository_identity: str
    expected_parent: str
    manifest_json: str
    manifest_sha256: str
    candidate_content_sha256: str


@dataclass(frozen=True)
class ApprovalBinding:
    approval_id: str
    authority_ref: str


def _run_git(
    repository: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise ControllerError("GIT_COMMAND_FAILED", detail)
    return completed


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def _candidate_git(
    repository: Path, *arguments: str, input: bytes | None = None,
    environment: Mapping[str, str] | None = None, check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    # Candidate-only plumbing: exact paths/objects, no ambient repository routing,
    # replacement objects, hooks, external diffs, or content conversion.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull})
    if environment:
        env.update(environment)
    result = subprocess.run(
        ["git", "--literal-pathspecs", "-c", "core.hooksPath=" + os.devnull,
         "-c", "core.fsmonitor=false", "-C", str(repository), *arguments],
        input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        timeout=30, check=False,
    )
    if check and result.returncode != 0:
        raise ControllerError("CANDIDATE_GIT_FAILED", result.stderr.decode("utf-8", "replace"))
    return result


def _candidate_file(repository: Path, path: str) -> Path:
    _candidate_path(path.encode("utf-8", "strict"))
    target = repository
    for component in Path(path).parts[:-1]:
        target = target / component
        if target.is_symlink():
            raise ControllerError("CANDIDATE_PATH_ESCAPE", path)
    return repository / path


def _candidate_path(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ControllerError("INVALID_CANDIDATE_PATH", "UTF-8 required") from error
    entry = CandidateManifestEntry("A", value, "100644", 0, "0" * 64)
    try:
        entry.validate()
    except StoreError as error:
        raise ControllerError(error.code, error.detail) from error
    if value.startswith(".git/") or value == ".git":
        raise ControllerError("INVALID_CANDIDATE_PATH", value)
    return value


def _worktree_bytes(path: Path) -> tuple[str, bytes]:
    try:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            return "120000", os.readlink(path).encode("utf-8", "strict")
        if not stat.S_ISREG(mode):
            raise ControllerError("INVALID_CANDIDATE_FILE_TYPE", str(path))
        return ("100755" if mode & stat.S_IXUSR else "100644"), path.read_bytes()
    except (OSError, UnicodeError) as error:
        raise ControllerError("CANDIDATE_MATERIALIZATION_FAILED", str(path)) from error


def materialize_uncommitted_candidate(
    candidate: CandidateWorktree,
    *,
    repository_identity: str | Path,
) -> CandidateContentBinding:
    """Materialize the exact worktree delta using frozen integrated-candidate V1."""

    head = _candidate_git(candidate.path, "rev-parse", "HEAD").stdout.decode().strip()
    if head != candidate.base_commit:
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "expected parent drift")
    branch = _candidate_git(candidate.path, "symbolic-ref", "--short", "-q", "HEAD", check=False)
    if branch.returncode or branch.stdout.decode().strip() != candidate.branch:
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "branch drift")
    changed = set(
        item for item in _candidate_git(candidate.path, "diff", "--name-only", "-z", candidate.base_commit, "--").stdout.split(b"\0") if item
    )
    changed.update(
        item for item in _candidate_git(candidate.path, "ls-files", "--others", "--exclude-standard", "-z").stdout.split(b"\0") if item
    )
    if not changed:
        raise ControllerError("EMPTY_CANDIDATE")
    entries: list[dict[str, Any]] = []
    aggregate = bytearray(b"ADCP_INTEGRATED_CANDIDATE_V1\0")
    base_bytes = candidate.base_commit.encode("ascii")
    aggregate += b"BASE_HEAD\0" + struct.pack(">Q", len(base_bytes)) + base_bytes
    for raw in sorted(changed):
        path = _candidate_path(raw)
        base = _candidate_git(candidate.path, "ls-tree", "-z", candidate.base_commit, "--", path).stdout
        base_mode = base_oid = None
        if base:
            header = base.split(b"\t", 1)[0].split(b" ")
            if len(header) != 3 or header[1] != b"blob":
                raise ControllerError("INVALID_CANDIDATE_FILE_TYPE", path)
            base_mode, base_oid = header[0].decode("ascii"), header[2].decode("ascii")
        current = _candidate_file(candidate.path, path)
        if current.exists() or current.is_symlink():
            mode, content = _worktree_bytes(current)
            operation = "A" if base_oid is None else "M"
            item = CandidateManifestEntry(
                operation, path, mode, len(content), hashlib.sha256(content).hexdigest()
            )
        else:
            if base_oid is None or base_mode is None:
                raise ControllerError("CANDIDATE_MATERIALIZATION_FAILED", path)
            content = b""
            item = CandidateManifestEntry("D", path, base_mode, None, None, base_oid)
        try:
            item.validate()
        except StoreError as error:
            raise ControllerError(error.code, error.detail) from error
        entries.append({
            "operation": item.operation, "path": item.path, "mode": item.mode,
            "byte_length": item.byte_length, "content_sha256": item.content_sha256,
            "base_object_id": item.base_object_id,
        })
        path_bytes = path.encode("utf-8")
        aggregate += b"PATH\0" + struct.pack(">Q", len(path_bytes)) + path_bytes
        aggregate += b"CONTENT\0" + struct.pack(">Q", len(content)) + content
    digest = hashlib.sha256(aggregate).hexdigest()
    manifest = {
        "serialization_format": "ADCP_INTEGRATED_CANDIDATE_V1",
        "serialization_version": 1,
        "repository_identity": str(Path(repository_identity).resolve(strict=True)),
        "expected_parent": candidate.base_commit,
        "entries": entries,
        "candidate_content_sha256": digest,
    }
    manifest_json = canonical_json(manifest)
    return CandidateContentBinding(
        f"candidate-{candidate.execution_id}-{hashlib.sha256(manifest_json.encode()).hexdigest()}", candidate.execution_id,
        "ADCP_INTEGRATED_CANDIDATE_V1", 1, manifest["repository_identity"],
        candidate.base_commit, manifest_json, hashlib.sha256(manifest_json.encode()).hexdigest(), digest,
    )


def verify_committed_candidate(repository: Path, result_commit: str, stored: Mapping[str, Any]) -> None:
    """Verify one exact parent, path/action/mode/base blob and raw committed bytes."""
    parents = _candidate_git(repository, "rev-list", "--parents", "-n", "1", result_commit).stdout.decode().split()
    if len(parents) != 2 or parents[1] != stored["expected_parent"]:
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "commit parent")
    parent = parents[1]
    manifest = json.loads(stored["manifest_json"])
    if canonical_json(manifest) != stored["manifest_json"] or canonical_sha256(manifest) != stored["manifest_sha256"]:
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "manifest")
    entries = manifest["entries"]
    expected_paths = [entry["path"] for entry in entries]
    if expected_paths != sorted(set(expected_paths), key=lambda path: path.encode("utf-8")):
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "path ordering")
    raw = _candidate_git(repository, "diff-tree", "--no-renames", "--no-commit-id", "--name-only", "-r", "-z", result_commit).stdout
    actual_paths = {path.decode("utf-8", "strict") for path in raw.split(b"\0") if path}
    if actual_paths != set(expected_paths):
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed path set")
    aggregate = bytearray(b"ADCP_INTEGRATED_CANDIDATE_V1\0")
    base = parent.encode("ascii")
    aggregate += b"BASE_HEAD\0" + struct.pack(">Q", len(base)) + base
    for entry in entries:
        CandidateManifestEntry(**entry).validate()
        path = entry["path"]
        _candidate_path(path.encode("utf-8"))
        before = _candidate_git(repository, "ls-tree", "-z", parent, "--", path).stdout
        after = _candidate_git(repository, "ls-tree", "-z", result_commit, "--", path).stdout
        old_meta = before.split(b"\t", 1)[0].split() if before else []
        new_meta = after.split(b"\t", 1)[0].split() if after else []
        operation = entry["operation"]
        if (operation == "A" and before) or (operation in {"M", "D"} and not before):
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed action")
        if operation == "D":
            if after or old_meta != [entry["mode"].encode(), b"blob", entry["base_object_id"].encode()]:
                raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "deletion identity")
            content = b""
        else:
            if len(new_meta) != 3 or new_meta[:2] != [entry["mode"].encode(), b"blob"]:
                raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed mode")
            content = _candidate_git(repository, "cat-file", "blob", new_meta[2].decode()).stdout
            if len(content) != entry["byte_length"] or hashlib.sha256(content).hexdigest() != entry["content_sha256"]:
                raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed bytes")
        raw_path = path.encode("utf-8")
        aggregate += b"PATH\0" + struct.pack(">Q", len(raw_path)) + raw_path
        aggregate += b"CONTENT\0" + struct.pack(">Q", len(content)) + content
    if hashlib.sha256(aggregate).hexdigest() != stored["candidate_content_sha256"]:
        raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed aggregate")


class WorktreeOrchestrator:
    """Create and commit isolated candidates without granting Maker Git authority."""

    def __init__(self, source_root: Path, worktree_root: Path) -> None:
        self.source_root = canonical_source_root(source_root)
        self.worktree_root = Path(worktree_root).expanduser().resolve(strict=False)
        if _inside(self.worktree_root, self.source_root) or _inside(
            self.source_root, self.worktree_root
        ):
            raise ControllerError("WORKTREE_ROOT_INSIDE_SOURCE")
        self.worktree_root.mkdir(parents=True, exist_ok=True)

    def create(self, execution_id: str, base_commit: str) -> CandidateWorktree:
        if _run_git(self.source_root, "cat-file", "-e", f"{base_commit}^{{commit}}", check=False).returncode:
            raise ControllerError("BASE_COMMIT_NOT_FOUND", base_commit)
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", execution_id).strip("-.") or "execution"
        nonce = uuid4().hex[:12]
        branch = f"adcp/{slug}-{nonce}"
        target = (self.worktree_root / f"{slug}-{nonce}").resolve(strict=False)
        if not _inside(target, self.worktree_root) or _inside(target, self.source_root):
            raise ControllerError("INVALID_WORKTREE_TARGET")
        _run_git(self.source_root, "worktree", "add", "-b", branch, str(target), base_commit)
        return CandidateWorktree(
            execution_id,
            target.resolve(strict=True),
            branch,
            base_commit,
            branch_created=True,
            worktree_created=True,
        )

    def expected_bound_path(self, execution_id: str) -> Path:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", execution_id).strip("-.") or "execution"
        suffix = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:12]
        target = (self.worktree_root / f"{slug}-prebound-{suffix}").resolve(strict=False)
        if not _inside(target, self.worktree_root) or _inside(target, self.source_root):
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "invalid deterministic path")
        return target

    def _branch_ref(self, branch: str) -> str:
        if not branch or _run_git(
            self.source_root, "check-ref-format", "--branch", branch, check=False
        ).returncode:
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "invalid logical branch")
        return f"refs/heads/{branch}"

    def _common_dir(self, repository: Path) -> Path:
        raw = _run_git(
            repository, "rev-parse", "--path-format=absolute", "--git-common-dir"
        ).stdout.decode().strip()
        return Path(raw).resolve(strict=True)

    def _registered_worktrees(self) -> list[dict[str, str]]:
        output = _run_git(self.source_root, "worktree", "list", "--porcelain").stdout.decode(
            "utf-8", "surrogateescape"
        )
        entries: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in output.splitlines():
            if not line:
                if current:
                    entries.append(current)
                    current = {}
                continue
            key, _, value = line.partition(" ")
            current[key] = value
        if current:
            entries.append(current)
        return entries

    def validate_bound(
        self,
        candidate: CandidateWorktree,
        *,
        expected_head: str | None = None,
    ) -> CandidateWorktree:
        expected_path = self.expected_bound_path(candidate.execution_id)
        if candidate.path.resolve(strict=False) != expected_path:
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "unexpected worktree path")
        try:
            observed_path = candidate.path.resolve(strict=True)
        except FileNotFoundError as error:
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "worktree missing") from error
        top = Path(
            _run_git(observed_path, "rev-parse", "--show-toplevel").stdout.decode().strip()
        ).resolve(strict=True)
        if top != observed_path or self._common_dir(top) != self._common_dir(self.source_root):
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "repository common-dir mismatch")
        branch = _run_git(top, "symbolic-ref", "--short", "-q", "HEAD", check=False)
        if branch.returncode or branch.stdout.decode().strip() != candidate.branch:
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "logical branch mismatch")
        head = _run_git(top, "rev-parse", "HEAD").stdout.decode().strip()
        required_head = expected_head or candidate.base_commit
        if head != required_head:
            raise ControllerError("BOUND_BRANCH_HEAD_MISMATCH", f"{head}!={required_head}")
        if _run_git(top, "status", "--porcelain", "--untracked-files=no").stdout:
            raise ControllerError("BOUND_WORKTREE_DIRTY")
        return candidate

    def prepare_bound(
        self,
        execution_id: str,
        branch: str,
        base_commit: str,
        *,
        provision_branch_if_missing: bool,
    ) -> CandidateWorktree:
        branch_ref = self._branch_ref(branch)
        if _run_git(
            self.source_root, "cat-file", "-e", f"{base_commit}^{{commit}}", check=False
        ).returncode:
            raise ControllerError("BASE_COMMIT_NOT_FOUND", base_commit)
        reachable = _run_git(
            self.source_root,
            "for-each-ref",
            f"--contains={base_commit}",
            "--format=%(refname)",
            "refs/heads",
            "refs/remotes",
        ).stdout
        if not reachable:
            raise ControllerError("BASE_COMMIT_NOT_FOUND", "commit is not reachable from a ref")

        target = self.expected_bound_path(execution_id)
        entries = self._registered_worktrees()
        branch_entries = [entry for entry in entries if entry.get("branch") == branch_ref]
        if branch_entries:
            if len(branch_entries) != 1:
                raise ControllerError("BOUND_WORKTREE_CONFLICT", "branch has multiple worktrees")
            registered = Path(branch_entries[0]["worktree"]).resolve(strict=False)
            if registered != target:
                raise ControllerError("BOUND_WORKTREE_CONFLICT", str(registered))
            candidate = CandidateWorktree(execution_id, target, branch, base_commit)
            return self.validate_bound(candidate)
        if any(
            Path(entry.get("worktree", "")).resolve(strict=False) == target
            for entry in entries
        ) or target.exists():
            raise ControllerError("BOUND_WORKTREE_CONFLICT", "target already exists")

        branch_head = _run_git(
            self.source_root, "rev-parse", "--verify", f"{branch_ref}^{{commit}}", check=False
        )
        branch_created = False
        if branch_head.returncode:
            if not provision_branch_if_missing:
                raise ControllerError("BOUND_BRANCH_NOT_FOUND", branch)
            _run_git(self.source_root, "branch", branch, base_commit)
            branch_created = True
        elif branch_head.stdout.decode().strip() != base_commit:
            raise ControllerError("BOUND_BRANCH_HEAD_MISMATCH")

        try:
            _run_git(self.source_root, "worktree", "add", str(target), branch)
        except BaseException:
            if branch_created:
                _run_git(
                    self.source_root,
                    "update-ref",
                    "-d",
                    branch_ref,
                    base_commit,
                    check=False,
                )
            raise
        candidate = CandidateWorktree(
            execution_id,
            target.resolve(strict=True),
            branch,
            base_commit,
            branch_created=branch_created,
            worktree_created=True,
        )
        try:
            return self.validate_bound(candidate)
        except BaseException as error:
            if not self.compensate_bound(candidate):
                raise ControllerError(
                    "GIT_PROVISIONED_DB_BIND_FAILED_REVIEW_REQUIRED",
                    "post-provision Git validation failed",
                ) from error
            raise

    def reuse_bound(
        self,
        execution_id: str,
        path: Path,
        branch: str,
        expected_head: str,
        *,
        branch_created: bool,
        worktree_created: bool,
    ) -> CandidateWorktree:
        candidate = CandidateWorktree(
            execution_id,
            Path(path).expanduser().resolve(strict=False),
            branch,
            expected_head,
            branch_created=branch_created,
            worktree_created=worktree_created,
        )
        return self.validate_bound(candidate, expected_head=expected_head)

    def compensate_bound(self, candidate: CandidateWorktree) -> bool:
        """Remove only unchanged Git artifacts created by this binding attempt."""

        try:
            self.validate_bound(candidate)
            if candidate.worktree_created:
                _run_git(self.source_root, "worktree", "remove", str(candidate.path))
            if candidate.branch_created:
                branch_ref = self._branch_ref(candidate.branch)
                head = _run_git(
                    self.source_root,
                    "rev-parse",
                    "--verify",
                    f"{branch_ref}^{{commit}}",
                ).stdout.decode().strip()
                if head != candidate.base_commit:
                    return False
                deleted = _run_git(
                    self.source_root,
                    "update-ref",
                    "-d",
                    branch_ref,
                    candidate.base_commit,
                    check=False,
                )
                if deleted.returncode:
                    return False
            return True
        except (ControllerError, FileNotFoundError):
            return False

    def validate_release_candidate(self, candidate: CandidateWorktree) -> CandidateWorktree:
        """Require the exact historical candidate and a completely empty status."""

        candidate = self.validate_bound(candidate)
        if _run_git(candidate.path, "status", "--porcelain").stdout:
            raise ControllerError("BOUND_WORKTREE_DIRTY")
        return candidate

    def cleanup_released(self, candidate: CandidateWorktree) -> bool:
        """Remove only a proven Controller-created worktree; preserve branch history."""

        branch_ref = self._branch_ref(candidate.branch)
        entries = self._registered_worktrees()
        path = candidate.path.resolve(strict=False)
        path_entries = [
            entry for entry in entries
            if Path(entry.get("worktree", "")).resolve(strict=False) == path
        ]

        if candidate.worktree_created:
            if path.exists():
                self.validate_release_candidate(candidate)
                _run_git(self.source_root, "worktree", "remove", str(path))
            elif path_entries:
                raise ControllerError(
                    "BOUND_WORKTREE_CONFLICT", "historical candidate registry is inconsistent"
                )

        if candidate.branch_created:
            branch_exists = _run_git(
                self.source_root, "show-ref", "--verify", branch_ref, check=False
            ).returncode == 0
            if branch_exists:
                return False
        return True

    def fingerprint(self, candidate: CandidateWorktree) -> CandidateFingerprint:
        if candidate.path.resolve(strict=True) != candidate.path:
            raise ControllerError("WORKTREE_IDENTITY_CHANGED")
        tracked = _run_git(candidate.path, "ls-files", "-z").stdout.split(b"\0")
        source_paths = [
            candidate.path / raw.decode("utf-8", "surrogateescape")
            for raw in tracked
            if raw and (candidate.path / raw.decode("utf-8", "surrogateescape")).is_file()
        ]
        fingerprint = capture_git_fingerprint(candidate.path, source_paths)
        refs = _run_git(
            candidate.path,
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/heads",
        ).stdout
        return CandidateFingerprint(fingerprint, hashlib.sha256(refs).hexdigest())

    def validate_maker_boundary(
        self, before: CandidateFingerprint, after: CandidateFingerprint
    ) -> None:
        changed: list[str] = []
        for field in ("branch", "head", "index_sha256"):
            if getattr(before.git, field) != getattr(after.git, field):
                changed.append(field)
        if before.refs_sha256 != after.refs_sha256:
            changed.append("refs")
        if changed:
            raise ControllerError("MAKER_GIT_POLICY_VIOLATION", ",".join(changed))

    def create_candidate_commit(
        self,
        candidate: CandidateWorktree,
        before: CandidateFingerprint,
        *,
        message: str,
    ) -> str:
        after = self.fingerprint(candidate)
        self.validate_maker_boundary(before, after)
        _run_git(candidate.path, "add", "-A")
        if _run_git(candidate.path, "diff", "--cached", "--quiet", check=False).returncode == 0:
            raise ControllerError("EMPTY_CANDIDATE")
        _run_git(
            candidate.path,
            "-c", "user.name=ADCP Controller",
            "-c", "user.email=adcp-controller@local.invalid",
            "commit", "-m", message,
        )
        result = _run_git(candidate.path, "rev-parse", "HEAD").stdout.decode().strip()
        parent = _run_git(candidate.path, "rev-parse", "HEAD^").stdout.decode().strip()
        if parent != before.git.head:
            raise ControllerError("CANDIDATE_PARENT_MISMATCH")
        return result

    def record_disposition(self, candidate: CandidateWorktree, disposition: str) -> Path:
        if not disposition.strip():
            raise ControllerError("WORKTREE_DISPOSITION_REQUIRED")
        root = self.worktree_root / ".adcp-dispositions"
        root.mkdir(exist_ok=True)
        identity = hashlib.sha256(
            f"{candidate.execution_id}\0{candidate.branch}".encode("utf-8")
        ).hexdigest()[:16]
        target = root / f"{identity}.json"
        target.write_text(
            canonical_json(
                {"execution_id": candidate.execution_id, "path": str(candidate.path),
                 "branch": candidate.branch, "disposition": disposition}
            ),
            encoding="utf-8",
        )
        return target

    def remove(self, candidate: CandidateWorktree, *, disposition_record: Path) -> None:
        if not disposition_record.is_file():
            raise ControllerError("WORKTREE_DISPOSITION_REQUIRED")
        if not candidate.worktree_created:
            raise ControllerError("WORKTREE_NOT_CONTROLLER_OWNED")
        _run_git(self.source_root, "worktree", "remove", str(candidate.path))
        if candidate.branch_created:
            _run_git(self.source_root, "branch", "-D", candidate.branch)


class Controller:
    """The sole semantic orchestration writer for one configured control store."""

    def __init__(
        self,
        store: ControlStore,
        *,
        source_root: Path,
        worktree_root: Path,
        controller_id: str = "adcp-controller",
    ) -> None:
        self.store = store
        self.controller_id = controller_id
        self._candidate_authorizations: dict[str, tuple[int, int, str, str]] = {}
        self.worktrees = WorktreeOrchestrator(source_root, worktree_root)

    def _validate_artifact_directory(
        self, artifact_directory: Path, candidate: CandidateWorktree
    ) -> Path:
        target = Path(artifact_directory).expanduser().resolve(strict=False)
        if _inside(target, candidate.path) or _inside(target, self.worktrees.source_root):
            raise ControllerError("ARTIFACT_ROOT_INSIDE_SOURCE")
        return target

    def register_slice(
        self,
        *,
        slice_id: str,
        stage: str,
        status: str,
        migration_class: str,
        execution_eligibility: str,
        defer_reason: str,
        logical_source_root: str,
        registration_ref: str,
        expected_authority_generation: int,
        repository_toplevel: str | None = None,
        branch: str | None = None,
        base_commit: str | None = None,
        implementation_result_commit: str | None = None,
        current_branch_head: str | None = None,
        active_execution_id: str | None = None,
    ) -> dict[str, Any]:
        """Register one new non-executable Slice lifecycle under Store authority."""

        for field, value in (("slice_id", slice_id), ("stage", stage), ("status", status)):
            if not isinstance(value, str) or not value.strip():
                raise ControllerError("SLICE_CONTROL_STATE_FIELD_REQUIRED", field)
        if not isinstance(registration_ref, str) or not registration_ref.strip():
            raise ControllerError("REGISTRATION_REF_REQUIRED")
        if not isinstance(defer_reason, str) or not defer_reason.strip():
            raise ControllerError("DEFER_REASON_REQUIRED")
        if not isinstance(logical_source_root, str) or not logical_source_root.strip():
            raise ControllerError("SOURCE_ROOT_MISMATCH")
        if type(expected_authority_generation) is not int:
            raise ControllerError("STALE_AUTHORITY_GENERATION")

        bound_fields = {
            "repository_toplevel": repository_toplevel,
            "branch": branch,
            "base_commit": base_commit,
            "implementation_result_commit": implementation_result_commit,
            "current_branch_head": current_branch_head,
            "active_execution_id": active_execution_id,
        }
        if execution_eligibility in {
            "ELIGIBLE_PREEXECUTION_BOUND",
            "ELIGIBLE_BOUND",
        } or any(value is not None for value in bound_fields.values()):
            raise ControllerError("SLICE_REGISTRATION_EXECUTABLE_STATE_FORBIDDEN")

        disposition = (migration_class, execution_eligibility)
        if disposition not in {
            ("DEFER_BINDING", "INELIGIBLE_UNTIL_PREFLIGHT"),
            ("DEFER_PREREQUISITE", "INELIGIBLE_UNTIL_PREREQUISITE"),
        }:
            raise ControllerError("SLICE_REGISTRATION_DISPOSITION_FORBIDDEN")

        try:
            declared_source_root = canonical_source_root(logical_source_root)
        except StoreError as error:
            raise ControllerError("SOURCE_ROOT_MISMATCH", error.detail) from error
        if declared_source_root != self.worktrees.source_root:
            raise ControllerError("SOURCE_ROOT_MISMATCH")

        authority = self.store.get_control_authority_state()
        if authority["mode"] != "CONTROL_STORE_AUTHORITY":
            raise ControllerError("CONTROL_AUTHORITY_MODE_REQUIRED")
        if authority["authority_generation"] != expected_authority_generation:
            raise ControllerError("STALE_AUTHORITY_GENERATION")

        target: dict[str, Any] = {
            "slice_id": slice_id,
            "stage": stage,
            "status": status,
            "migration_class": migration_class,
            "execution_eligibility": execution_eligibility,
            "defer_reason": defer_reason,
            "logical_source_root": str(self.worktrees.source_root),
            "repository_toplevel": None,
            "branch": None,
            "base_commit": None,
            "implementation_result_commit": None,
            "current_branch_head": None,
            "active_execution_id": None,
        }
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        key = operation_key(
            "controller-register-slice",
            {
                "target": target,
                "registration_ref": registration_ref,
                "expected_authority_generation": expected_authority_generation,
            },
        )
        try:
            row, replayed = self.store.reconcile_slice_control_state(
                target,
                -1,
                key,
                reason_code="SLICE_REGISTERED",
                metadata={"registration_ref": registration_ref},
                required_authority_mode="CONTROL_STORE_AUTHORITY",
                expected_authority_generation=expected_authority_generation,
                insert_only=True,
            )
        except StoreError as error:
            if error.code in {
                "CONTROL_AUTHORITY_MODE_REQUIRED",
                "STALE_AUTHORITY_GENERATION",
                "SLICE_ALREADY_REGISTERED_CONFLICT",
                "SLICE_REGISTRATION_IDEMPOTENCY_CONFLICT",
            }:
                raise ControllerError(error.code, error.detail) from error
            raise
        return {"slice_control_state": dict(row), "replayed": replayed}

    def create_execution(self, spec: ExecutionCreate):
        if canonical_source_root(spec.source_root) != self.worktrees.source_root:
            raise ControllerError("SOURCE_ROOT_MISMATCH")
        controlled = self.store.connection.execute(
            "SELECT * FROM slice_control_state WHERE slice_id = ?", (spec.slice_id,)
        ).fetchone()
        if controlled is not None:
            raise ControllerError(
                "SLICE_EXECUTION_INELIGIBLE",
                f"{controlled['migration_class']}:{controlled['execution_eligibility']}",
            )
        key = operation_key("controller-create", {"execution_id": spec.execution_id})
        return self.store.create_execution(spec, key)

    def _validate_prebound_capsule(
        self,
        row: Mapping[str, Any],
        capsule: ContextCapsule,
        candidate: CandidateWorktree,
        *,
        current_commit: str,
    ) -> None:
        if capsule.role is not CapsuleRole.MAKER:
            raise ControllerError("CAPSULE_BINDING_MISMATCH", "Maker capsule required")
        required_fields = {
            "slice",
            "current_task",
            "contract_fingerprint",
            "authority_fingerprint",
            "source_root",
            "branch",
            "base_commit",
            "current_commit",
            "acceptance_criteria",
            "constraints",
            "risk",
            "environment",
            "allowed_actions",
            "forbidden_actions",
            "relevant_authority_refs",
            "relevant_authority_excerpts",
        }
        missing = required_fields.difference(capsule.content)
        if missing:
            raise ControllerError(
                "CAPSULE_BINDING_MISMATCH", f"missing:{','.join(sorted(missing))}"
            )
        slice_content = capsule.content["slice"]
        capsule_slice_id = (
            slice_content.get("slice_id")
            if isinstance(slice_content, dict)
            else slice_content
        )
        if capsule_slice_id != row["slice_id"]:
            raise ControllerError("CAPSULE_BINDING_MISMATCH", "slice")
        expected = {
            "contract_fingerprint": row["contract_fingerprint"],
            "authority_fingerprint": row["authority_fingerprint"],
            "source_root": str(candidate.path),
            "branch": row["branch"],
            "base_commit": row["base_commit"],
            "current_commit": current_commit,
            "risk": row["risk_level"],
            "environment": row["environment"],
        }
        for field, value in expected.items():
            if capsule.content.get(field) != value:
                code = {
                    "contract_fingerprint": "CONTRACT_FINGERPRINT_MISMATCH",
                    "authority_fingerprint": "AUTHORITY_FINGERPRINT_MISMATCH",
                }.get(field, "CAPSULE_BINDING_MISMATCH")
                raise ControllerError(code, field)
        if str(self.worktrees.source_root) in capsule.canonical_json:
            raise ControllerError("SOURCE_ROOT_EXPOSED_TO_MAKER")

    def bind_deferred_execution(
        self,
        spec: ExecutionCreate,
        *,
        expected_state_version: int,
        maker_capsule: ContextCapsule,
        packet_ref: str,
        provision_branch_if_missing: bool = False,
        fault_injector: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Provision and atomically persist one exact deferred pre-execution binding."""

        if canonical_source_root(spec.source_root) != self.worktrees.source_root:
            raise ControllerError("SOURCE_ROOT_MISMATCH")
        try:
            persisted = self.store.get_deferred_binding(spec.execution_id)
        except StoreError as error:
            if error.code != "PREEXECUTION_BINDING_NOT_FOUND":
                raise
            persisted = None
        if persisted is None:
            prepared = self.worktrees.prepare_bound(
                spec.execution_id,
                spec.branch,
                spec.base_commit,
                provision_branch_if_missing=provision_branch_if_missing,
            )
            candidate = prepared
            created_this_call = prepared.branch_created or prepared.worktree_created
        else:
            execution = self.store.get_execution(spec.execution_id)
            state = self.store.get_slice_control_state(persisted["slice_id"])
            if (
                persisted["slice_id"] != spec.slice_id
                or persisted["repository_toplevel"] != str(self.worktrees.source_root)
                or persisted["branch"] != spec.branch
                or persisted["base_commit"] != spec.base_commit
                or persisted["contract_fingerprint"] != spec.contract_fingerprint
                or persisted["authority_fingerprint"] != spec.authority_fingerprint
                or persisted["risk_level"] != spec.risk_level.value
                or persisted["environment"] != spec.environment.value
                or execution["slice_id"] != spec.slice_id
                or state["active_execution_id"] != spec.execution_id
            ):
                raise ControllerError("PREEXECUTION_BIND_CONFLICT")
            candidate = self.worktrees.reuse_bound(
                spec.execution_id,
                Path(persisted["worktree_path"]),
                spec.branch,
                state["current_branch_head"],
                branch_created=bool(persisted["branch_created"]),
                worktree_created=bool(persisted["worktree_created"]),
            )
            prepared = candidate
            created_this_call = False
        try:
            row_material = {
                "slice_id": spec.slice_id,
                "contract_fingerprint": spec.contract_fingerprint,
                "authority_fingerprint": spec.authority_fingerprint,
                "branch": spec.branch,
                "base_commit": spec.base_commit,
                "risk_level": spec.risk_level.value,
                "environment": spec.environment.value,
            }
            self._validate_prebound_capsule(
                row_material,
                maker_capsule,
                candidate,
                current_commit=spec.base_commit,
            )
            key = operation_key(
                "controller-bind-deferred",
                {
                    "execution_id": spec.execution_id,
                    "slice_id": spec.slice_id,
                    "expected_state_version": expected_state_version,
                    "risk_level": spec.risk_level.value,
                    "environment": spec.environment.value,
                    "contract_fingerprint": spec.contract_fingerprint,
                    "authority_fingerprint": spec.authority_fingerprint,
                    "source_root": str(self.worktrees.source_root),
                    "worktree_path": str(candidate.path),
                    "branch": spec.branch,
                    "base_commit": spec.base_commit,
                    "packet_ref": packet_ref,
                    "context_fingerprint": maker_capsule.fingerprint,
                },
            )
            context_id = f"context-maker-prebind-{key}"
            execution, state, context, replayed = self.store.bind_deferred_execution(
                spec,
                expected_state_version,
                key,
                maker_context_snapshot_id=context_id,
                maker_capsule=maker_capsule,
                packet_ref=packet_ref,
                worktree_path=str(candidate.path),
                branch_created=candidate.branch_created,
                worktree_created=candidate.worktree_created,
                actor_id=self.controller_id,
                fault_injector=fault_injector,
            )
        except BaseException as error:
            if created_this_call and not self.worktrees.compensate_bound(prepared):
                detail = getattr(error, "code", type(error).__name__)
                raise ControllerError(
                    "GIT_PROVISIONED_DB_BIND_FAILED_REVIEW_REQUIRED", str(detail)
                ) from error
            raise
        return {
            "execution": dict(execution),
            "slice_control_state": dict(state),
            "context_snapshot": {
                "context_snapshot_id": context["context_snapshot_id"],
                "role": context["role"],
                "capsule_version": context["capsule_version"],
                "fingerprint": context["fingerprint"],
            },
            "worktree_path": str(candidate.path),
            "replayed": replayed,
        }

    def release_prebound_execution(
        self,
        execution_id: str,
        slice_id: str,
        *,
        expected_execution_state_version: int,
        expected_slice_state_version: int,
        release_reason: str,
        authority_ref: str,
        fault_injector: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Release one untouched pre-Maker binding, then safely clean owned Git artifacts."""

        allowed_reasons = {
            "BASE_STALE",
            "CONTRACT_STALE",
            "AUTHORITY_STALE",
            "BRANCH_STALE",
            "ENVIRONMENT_STALE",
            "PREMAKER_PREREQUISITE_CHANGED",
        }
        if release_reason not in allowed_reasons:
            raise ControllerError("PREBOUND_RELEASE_REASON_INVALID", release_reason)
        if not authority_ref.strip():
            raise ControllerError("PREBOUND_RELEASE_AUTHORITY_REQUIRED")

        binding = self.store.get_deferred_binding(execution_id)
        if binding["slice_id"] != slice_id:
            raise StoreError("PREBOUND_RELEASE_EXECUTION_MISMATCH")
        candidate = CandidateWorktree(
            execution_id=execution_id,
            path=Path(binding["worktree_path"]).expanduser().resolve(strict=False),
            branch=binding["branch"],
            base_commit=binding["base_commit"],
            branch_created=bool(binding["branch_created"]),
            worktree_created=bool(binding["worktree_created"]),
        )
        key = operation_key(
            "release-deferred-preexecution-binding",
            {
                "execution_id": execution_id,
                "slice_id": slice_id,
                "expected_execution_state_version": expected_execution_state_version,
                "expected_slice_state_version": expected_slice_state_version,
                "release_reason": release_reason,
                "authority_ref": authority_ref,
                "old_repository_toplevel": binding["repository_toplevel"],
                "old_worktree_path": binding["worktree_path"],
                "old_branch": binding["branch"],
                "old_base_commit": binding["base_commit"],
                "old_contract_fingerprint": binding["contract_fingerprint"],
                "old_authority_fingerprint": binding["authority_fingerprint"],
                "old_context_snapshot_id": binding["context_snapshot_id"],
                "old_context_fingerprint": binding["context_fingerprint"],
                "branch_created": bool(binding["branch_created"]),
                "worktree_created": bool(binding["worktree_created"]),
            },
        )
        execution, state, metadata, replayed = (
            self.store.release_deferred_preexecution_binding(
                execution_id,
                slice_id,
                expected_execution_state_version,
                expected_slice_state_version,
                key,
                release_reason=release_reason,
                authority_ref=authority_ref,
                actor_id=self.controller_id,
                fault_injector=fault_injector,
            )
        )
        cleanup_complete = False
        cleanup_error = None
        try:
            cleanup_complete = self.worktrees.cleanup_released(candidate)
        except (ControllerError, FileNotFoundError) as error:
            cleanup_error = getattr(error, "code", type(error).__name__)
        result_code = (
            "PREEXECUTION_RELEASED"
            if cleanup_complete
            else "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED"
        )
        return {
            "result": result_code,
            "execution": dict(execution),
            "slice_control_state": dict(state),
            "release_metadata": metadata,
            "git_cleanup_complete": cleanup_complete,
            "git_cleanup_error": cleanup_error,
            "replayed": replayed,
        }

    def acquire(self, execution_id: str):
        row = self.store.get_execution(execution_id)
        leased = self.store.acquire_lease(
            execution_id,
            row["state_version"],
            operation_key("controller-lease", {"execution_id": execution_id, "version": row["state_version"]}),
            self.controller_id,
        )

        self._candidate_authorizations[execution_id] = (
            leased["lease_generation"], self.store.get_control_authority_state()["authority_generation"],
            leased["contract_fingerprint"], leased["authority_fingerprint"],
        )
        return leased

    def inspect(self, execution_id: str) -> dict[str, Any]:
        row = self.store.get_execution(execution_id)
        attempts = {
            role: dict(attempt)
            for role in ("MAKER", "EVALUATOR")
            if (
                attempt := self.store.connection.execute(
                    """SELECT attempt_id, attempt_no, status, failure_code
                         FROM agent_attempt WHERE execution_id = ? AND role = ?
                         ORDER BY attempt_no DESC LIMIT 1""",
                    (execution_id, role),
                ).fetchone()
            )
        }
        return {
            "execution_id": execution_id,
            "state": row["state"],
            "state_version": row["state_version"],
            "maker_rework_count": row["maker_rework_count"],
            "max_auto_reworks": row["max_auto_reworks"],
            "result_commit": row["result_commit"],
            "blocker_code": row["blocker_code"],
            "attempts": attempts,
        }

    def _transition(
        self,
        execution_id: str,
        to_state: ExecutionState,
        *,
        reason: str,
        resume_state: ExecutionState | None = None,
        blocker_code: str | None = None,
        blocker_detail: str | None = None,
        candidate_write_fence: CandidateWriteFence | None = None,
    ):
        row = self.store.get_execution(execution_id)
        return self.store.transition(
            execution_id,
            row["state_version"],
            operation_key(
                "controller-transition",
                {"execution_id": execution_id, "from_version": row["state_version"],
                 "to_state": to_state.value, "reason": reason},
            ),
            to_state,
            actor_role=ActorRole.CONTROLLER,
            actor_id=self.controller_id,
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
            resume_state=resume_state,
            blocker_code=blocker_code,
            blocker_detail=blocker_detail,
            candidate_write_fence=candidate_write_fence,
            reason_code=reason,
        )

    def _maker_resume_state(self, row, attempt_id: str) -> ExecutionState:
        attempt = self.store.get_agent_attempt(attempt_id)
        return (
            ExecutionState.REWORK_READY
            if row["maker_rework_count"] or attempt["attempt_no"] > 1
            else ExecutionState.READY
        )

    def _high_rework_binding(self, execution_id: str):
        row = self.store.get_execution(execution_id)
        if (
            row["risk_level"] != "HIGH"
            or row["max_auto_reworks"] != 0
            or row["state"] != ExecutionState.BLOCKED.value
            or row["resume_state"] != ExecutionState.VERIFYING.value
            or row["blocker_code"] != "VERIFICATION_FAILED"
            or row["result_commit"] is None
        ):
            raise ControllerError("HIGH_REWORK_STATE_INVALID")
        maker_attempts = self.store.connection.execute(
            """SELECT count(*) AS total,
                      sum(CASE WHEN status='SUCCEEDED' AND result_commit=? THEN 1 ELSE 0 END) AS matching
                 FROM agent_attempt WHERE execution_id=? AND role='MAKER'""",
            (row["result_commit"], execution_id),
        ).fetchone()
        if maker_attempts["total"] != 1 or maker_attempts["matching"] != 1:
            raise ControllerError("HIGH_REWORK_ATTEMPT_TOPOLOGY_INVALID")
        verification = self.store.find_verification_failure(
            execution_id,
            row["result_commit"],
            row["contract_fingerprint"],
            row["authority_fingerprint"],
        )
        if verification is None:
            raise ControllerError("HIGH_REWORK_VERIFICATION_FAILURE_REQUIRED")
        authority_ref = canonical_sha256(
            {
                "approval_type": "HIGH_REWORK",
                "execution_id": execution_id,
                "risk_level": row["risk_level"],
                "state": row["state"],
                "state_version": row["state_version"],
                "maker_rework_count": row["maker_rework_count"],
                "max_auto_reworks": row["max_auto_reworks"],
                "result_commit": row["result_commit"],
                "contract_fingerprint": row["contract_fingerprint"],
                "authority_fingerprint": row["authority_fingerprint"],
                "verification_id": verification["verification_id"],
                "verification_verdict": verification["verdict"],
                "verification_manifest_sha256": verification["command_manifest_sha256"],
                "verification_result_sha256": hashlib.sha256(
                    verification["result_json"].encode("utf-8")
                ).hexdigest(),
            }
        )
        return row, verification, authority_ref

    def request_high_rework_approval(self, execution_id: str) -> ApprovalBinding:
        """Request Human authority for one exact HIGH verification-failure disposition."""

        row, verification, authority_ref = self._high_rework_binding(execution_id)
        approval_id = f"approval-{uuid4().hex}"
        requested = self.store.request_approval(
            approval_id=approval_id,
            idempotency_key=operation_key(
                "high-rework-approval-request",
                {
                    "approval_id": approval_id,
                    "execution_id": execution_id,
                    "state_version": row["state_version"],
                    "verification_id": verification["verification_id"],
                    "authority_ref": authority_ref,
                },
            ),
            execution_id=execution_id,
            approval_type="HIGH_REWORK",
            authority_ref=authority_ref,
            expected_state_version=row["state_version"],
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
        )
        return ApprovalBinding(requested["approval_id"], requested["authority_ref"])

    def authorize_high_rework(
        self,
        execution_id: str,
        approval: ApprovalBinding,
    ):
        """Apply approved HIGH disposition without enabling automatic HIGH retry."""

        row, verification, expected_ref = self._high_rework_binding(execution_id)
        if approval.authority_ref != expected_ref:
            raise ControllerError("HIGH_REWORK_APPROVAL_STALE")
        stored = self.store.get_approval(approval.approval_id)
        if stored["execution_id"] != execution_id:
            raise ControllerError("HIGH_REWORK_APPROVAL_EXECUTION_MISMATCH")
        if stored["approval_type"] != "HIGH_REWORK":
            raise ControllerError("HIGH_REWORK_APPROVAL_TYPE_MISMATCH")
        if stored["authority_ref"] != expected_ref:
            raise ControllerError("HIGH_REWORK_APPROVAL_STALE")
        if stored["consumed_at"] is not None:
            raise ControllerError("HIGH_REWORK_APPROVAL_CONSUMED")
        if stored["status"] != "APPROVED":
            raise ControllerError("HIGH_REWORK_APPROVAL_REQUIRED")
        semantic = {
            "execution_id": execution_id,
            "state_version": row["state_version"],
            "approval_id": approval.approval_id,
            "authority_ref": expected_ref,
            "verification_id": verification["verification_id"],
            "result_commit": row["result_commit"],
        }
        return self.store.authorize_high_rework(
            execution_id,
            row["state_version"],
            operation_key("human-high-rework-resume", semantic),
            operation_key("human-high-rework-ready", semantic),
            approval_id=approval.approval_id,
            authority_ref=expected_ref,
            verification_id=verification["verification_id"],
            result_commit=row["result_commit"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
            actor_id=self.controller_id,
        )

    def _validate_high_rework_schedule_binding(
        self, row, approval: ApprovalBinding
    ) -> None:
        if (
            row["risk_level"] != "HIGH"
            or row["max_auto_reworks"] != 0
            or row["maker_rework_count"] != 0
            or row["state"] != ExecutionState.REWORK_READY.value
            or row["result_commit"] is None
        ):
            raise ControllerError("HIGH_REWORK_SCHEDULING_STATE_INVALID")
        attempts = self.store.connection.execute(
            """SELECT count(*) AS total,
                      sum(CASE WHEN status='SUCCEEDED' AND result_commit=? THEN 1 ELSE 0 END) AS matching
                 FROM agent_attempt WHERE execution_id=? AND role='MAKER'""",
            (row["result_commit"], row["execution_id"]),
        ).fetchone()
        if attempts["total"] != 1 or attempts["matching"] != 1:
            raise ControllerError("HIGH_REWORK_ATTEMPT_TOPOLOGY_INVALID")
        stored = self.store.get_approval(approval.approval_id)
        if stored["execution_id"] != row["execution_id"]:
            raise ControllerError("HIGH_REWORK_APPROVAL_EXECUTION_MISMATCH")
        if stored["approval_type"] != "HIGH_REWORK":
            raise ControllerError("HIGH_REWORK_APPROVAL_TYPE_MISMATCH")
        if stored["authority_ref"] != approval.authority_ref:
            raise ControllerError("HIGH_REWORK_APPROVAL_STALE")
        if stored["status"] != "APPROVED":
            raise ControllerError("HIGH_REWORK_APPROVAL_REQUIRED")
        if stored["consumed_at"] is not None:
            raise ControllerError("HIGH_REWORK_APPROVAL_CONSUMED")
        authorization = self.store.connection.execute(
            """SELECT * FROM transition_event
                 WHERE execution_id=? AND reason_code='HUMAN_AUTHORIZED_HIGH_REWORK'
                 ORDER BY event_seq DESC LIMIT 1""",
            (row["execution_id"],),
        ).fetchone()
        if authorization is None or authorization["to_state_version"] != row["state_version"]:
            raise ControllerError("HIGH_REWORK_AUTHORIZATION_REQUIRED")
        try:
            metadata = json.loads(authorization["metadata_json"])
        except json.JSONDecodeError as error:
            raise ControllerError("HIGH_REWORK_AUTHORIZATION_INVALID") from error
        if (
            metadata.get("approval_id") != approval.approval_id
            or metadata.get("authority_ref") != approval.authority_ref
            or metadata.get("result_commit") != row["result_commit"]
            or metadata.get("contract_fingerprint") != row["contract_fingerprint"]
            or metadata.get("authority_fingerprint") != row["authority_fingerprint"]
        ):
            raise ControllerError("HIGH_REWORK_AUTHORIZATION_STALE")

    def begin_maker(
        self,
        execution_id: str,
        capsule: ContextCapsule,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
    ) -> MakerRun:
        return self._begin_maker(
            execution_id,
            capsule,
            model=model,
            reasoning_effort=reasoning_effort,
            high_rework_approval=None,
        )

    def begin_human_authorized_high_rework(
        self,
        execution_id: str,
        capsule: ContextCapsule,
        approval: ApprovalBinding,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
    ) -> MakerRun:
        return self._begin_maker(
            execution_id,
            capsule,
            model=model,
            reasoning_effort=reasoning_effort,
            high_rework_approval=approval,
        )

    def _begin_maker(
        self,
        execution_id: str,
        capsule: ContextCapsule,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
        high_rework_approval: ApprovalBinding | None,
    ) -> MakerRun:
        if capsule.role is not CapsuleRole.MAKER:
            raise ControllerError("MAKER_CONTEXT_REQUIRED")
        row = self.store.get_execution(execution_id)
        prior_state = ExecutionState(row["state"])
        if prior_state not in {ExecutionState.READY, ExecutionState.REWORK_READY}:
            raise ControllerError("MAKER_NOT_SCHEDULABLE", row["state"])
        if (
            prior_state is ExecutionState.REWORK_READY
            and row["risk_level"] == "HIGH"
            and row["max_auto_reworks"] == 0
        ):
            if high_rework_approval is None:
                raise ControllerError("HUMAN_HIGH_REWORK_APPROVAL_REQUIRED")
            self._validate_high_rework_schedule_binding(row, high_rework_approval)
        elif high_rework_approval is not None:
            raise ControllerError("HIGH_REWORK_SCHEDULING_STATE_INVALID")
        controlled = self.store.connection.execute(
            "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
            (execution_id,),
        ).fetchone()
        if controlled is not None and controlled["migration_class"] == "DEFER_BINDING":
            binding = self.store.get_deferred_binding(execution_id)
            current_commit = row["result_commit"] or row["base_commit"]
            if (
                binding["slice_id"] != row["slice_id"]
                or binding["repository_toplevel"] != row["source_root"]
                or binding["branch"] != row["branch"]
                or binding["base_commit"] != row["base_commit"]
                or binding["contract_fingerprint"] != row["contract_fingerprint"]
                or binding["authority_fingerprint"] != row["authority_fingerprint"]
                or binding["risk_level"] != row["risk_level"]
                or binding["environment"] != row["environment"]
                or controlled["branch"] != row["branch"]
                or controlled["base_commit"] != row["base_commit"]
                or controlled["current_branch_head"] != current_commit
                or controlled["implementation_result_commit"] != row["result_commit"]
            ):
                raise ControllerError("PREEXECUTION_BIND_CONFLICT")
            candidate = self.worktrees.reuse_bound(
                execution_id,
                Path(binding["worktree_path"]),
                row["branch"],
                current_commit,
                branch_created=bool(binding["branch_created"]),
                worktree_created=bool(binding["worktree_created"]),
            )
            self._validate_prebound_capsule(
                row, capsule, candidate, current_commit=current_commit
            )
            if controlled["execution_eligibility"] == "ELIGIBLE_PREEXECUTION_BOUND":
                context = self.store.get_context_snapshot(binding["context_snapshot_id"])
                if (
                    context["execution_id"] != execution_id
                    or context["role"] != CapsuleRole.MAKER.value
                    or context["fingerprint"] != capsule.fingerprint
                    or context["canonical_json"] != capsule.canonical_json
                    or binding["context_fingerprint"] != capsule.fingerprint
                ):
                    raise ControllerError("CAPSULE_BINDING_MISMATCH")
        else:
            candidate = self.worktrees.create(
                execution_id, row["result_commit"] or row["base_commit"]
            )
            maker_content = dict(capsule.content)
            for field, value in (
                ("source_root", str(candidate.path)),
                ("branch", candidate.branch),
                ("base_commit", candidate.base_commit),
                ("current_commit", candidate.base_commit),
            ):
                if field in maker_content:
                    maker_content[field] = value
            capsule = build_context_capsule(
                CapsuleRole.MAKER,
                maker_content,
                capsule_version=capsule.capsule_version,
            )
        if str(self.worktrees.source_root) in capsule.canonical_json:
            raise ControllerError("SOURCE_ROOT_EXPOSED_TO_MAKER")
        if prior_state is ExecutionState.READY:
            row = self._transition(execution_id, ExecutionState.MAKER_RUNNING, reason="MAKER_SCHEDULED")
        else:
            if high_rework_approval is None:
                row = self.store.schedule_rework(
                    execution_id,
                    row["state_version"],
                    operation_key(
                        "schedule-rework",
                        {"execution_id": execution_id, "version": row["state_version"]},
                    ),
                    lease_owner=self.controller_id,
                    lease_generation=row["lease_generation"],
                    actor_id=self.controller_id,
                )
            else:
                row = self.store.schedule_human_authorized_rework(
                    execution_id,
                    row["state_version"],
                    operation_key(
                        "schedule-human-authorized-high-rework",
                        {
                            "execution_id": execution_id,
                            "version": row["state_version"],
                            "approval_id": high_rework_approval.approval_id,
                            "authority_ref": high_rework_approval.authority_ref,
                        },
                    ),
                    approval_id=high_rework_approval.approval_id,
                    authority_ref=high_rework_approval.authority_ref,
                    lease_owner=self.controller_id,
                    lease_generation=row["lease_generation"],
                    actor_id=self.controller_id,
                )
        context_id = f"context-maker-{uuid4().hex}"
        context = self.store.register_context_snapshot(
            context_id, execution_id, capsule.role, capsule.capsule_version, capsule
        )
        context_id = context["context_snapshot_id"]
        attempt_no = self.store.connection.execute(
            "SELECT count(*) + 1 FROM agent_attempt WHERE execution_id = ? AND role = 'MAKER'",
            (execution_id,),
        ).fetchone()[0]
        attempt_id = f"maker-{uuid4().hex}"
        self.store.register_agent_attempt(
            attempt_id=attempt_id,
            operation_key=operation_key("maker-attempt", {"attempt_id": attempt_id}),
            execution_id=execution_id,
            role=CapsuleRole.MAKER,
            attempt_no=attempt_no,
            model=model,
            reasoning_effort=reasoning_effort,
            session_id=f"session-{uuid4().hex}",
            context_snapshot_id=context_id,
            base_commit=candidate.base_commit,
            result_commit=None,
            started_at=timestamp(self.store._now()),
        )
        return MakerRun(
            attempt_id, candidate, self.worktrees.fingerprint(candidate), capsule
        )

    def complete_maker(
        self,
        run: MakerRun,
        *,
        commit_message: str,
        run_result: CodexRunResult | None = None,
    ) -> str:
        row = self.store.get_execution(run.candidate.execution_id)
        if row["state"] != ExecutionState.MAKER_RUNNING.value:
            raise ControllerError("MAKER_COMPLETION_STATE_INVALID")
        try:
            result_commit = self.worktrees.create_candidate_commit(
                run.candidate, run.before, message=commit_message
            )
        except ControllerError as error:
            artifacts = run_result.artifacts if run_result else None
            self.store.finish_agent_attempt(
                run.attempt_id,
                status="FAILED",
                ended_at=timestamp(self.store._now()),
                failure_code=error.code,
                stdout_artifact=str(artifacts.stdout.path) if artifacts else None,
                stdout_sha256=artifacts.stdout.sha256 if artifacts else None,
                stderr_artifact=str(artifacts.stderr.path) if artifacts else None,
                stderr_sha256=artifacts.stderr.sha256 if artifacts else None,
                result_artifact=str(artifacts.result.path) if artifacts else None,
                result_sha256=artifacts.result.sha256 if artifacts else None,
            )
            resume = self._maker_resume_state(row, run.attempt_id)
            self._transition(
                run.candidate.execution_id,
                ExecutionState.BLOCKED,
                reason="MAKER_GIT_POLICY_VIOLATION" if error.code == "MAKER_GIT_POLICY_VIOLATION" else "MAKER_FAILED",
                resume_state=resume,
                blocker_code=error.code,
                blocker_detail=error.detail,
            )
            raise
        artifacts = run_result.artifacts if run_result else None
        self.store.finish_agent_attempt(
            run.attempt_id,
            status="SUCCEEDED",
            result_commit=result_commit,
            exit_code=0,
            ended_at=timestamp(self.store._now()),
            stdout_artifact=str(artifacts.stdout.path) if artifacts else None,
            stdout_sha256=artifacts.stdout.sha256 if artifacts else None,
            stderr_artifact=str(artifacts.stderr.path) if artifacts else None,
            stderr_sha256=artifacts.stderr.sha256 if artifacts else None,
            result_artifact=str(artifacts.result.path) if artifacts else None,
            result_sha256=artifacts.result.sha256 if artifacts else None,
        )
        row = self.store.get_execution(run.candidate.execution_id)
        controlled = self.store.connection.execute(
            "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
            (run.candidate.execution_id,),
        ).fetchone()
        if controlled is not None and controlled["migration_class"] == "DEFER_BINDING":
            self.worktrees.validate_bound(run.candidate, expected_head=result_commit)
            self.store.finalize_deferred_result_commit(
                run.candidate.execution_id,
                row["state_version"],
                controlled["state_version"],
                operation_key(
                    "candidate-result",
                    {
                        "execution_id": run.candidate.execution_id,
                        "commit": result_commit,
                    },
                ),
                result_commit,
                expected_current_branch_head=run.before.git.head,
                lease_owner=self.controller_id,
                lease_generation=row["lease_generation"],
                actor_role=ActorRole.CONTROLLER,
                actor_id=self.controller_id,
            )
        else:
            self.store.register_result_commit(
                run.candidate.execution_id,
                row["state_version"],
                operation_key(
                    "candidate-result",
                    {
                        "execution_id": run.candidate.execution_id,
                        "commit": result_commit,
                    },
                ),
                result_commit,
                lease_owner=self.controller_id,
                lease_generation=row["lease_generation"],
                actor_role=ActorRole.CONTROLLER,
                actor_id=self.controller_id,
            )
        self._transition(run.candidate.execution_id, ExecutionState.VERIFYING, reason="MAKER_SUCCEEDED")
        return result_commit

    def _candidate_fence(self, execution_id: str) -> CandidateWriteFence:
        authority = self._candidate_authorizations.get(execution_id)
        if authority is None:
            raise ControllerError("CANDIDATE_CALLER_ACQUISITION_REQUIRED")
        row = self.store.get_execution(execution_id)
        fence = CandidateWriteFence(
            execution_id, row["state_version"], self.controller_id,
            authority[0], authority[1], authority[2], authority[3],
        )
        self.store._require_candidate_fence(execution_id, fence)
        return fence

    def _transition_candidate(self, execution_id: str, to_state: ExecutionState, *,
                              fence: CandidateWriteFence | None = None, **kwargs):
        return self._transition(
            execution_id, to_state,
            candidate_write_fence=fence or self._candidate_fence(execution_id), **kwargs,
        )

    def _verify_candidate_commands(self, candidate: CandidateWorktree, record) -> None:
        from adcp.verifier import validate_candidate_verification_payload

        commands = validate_candidate_verification_payload(
            record.command_manifest, record.command_manifest_sha256, record.result_json, record.verdict
        )
        for command in commands:
            for channel in ("stdout", "stderr"):
                raw_path = getattr(command, channel + "_artifact")
                expected = getattr(command, channel + "_sha256")
                if raw_path is None or expected is None:
                    raise ControllerError("CANDIDATE_COMMAND_ARTIFACT_REQUIRED", channel)
                path = Path(raw_path)
                if not path.is_absolute():
                    raise ControllerError("CANDIDATE_COMMAND_ARTIFACT_REQUIRED", channel)
                root = self._validate_artifact_directory(path.parent, candidate)
                _, _, entries = collect_manifest(root, {channel: path.name})
                if entries[0].sha256 != expected:
                    raise ControllerError("CANDIDATE_COMMAND_ARTIFACT_MISMATCH", channel)

    def _materialize_bound_candidate(
        self, candidate: CandidateWorktree, stored: Mapping[str, Any]
    ) -> CandidateContentBinding:
        observed = materialize_uncommitted_candidate(
            candidate, repository_identity=self.worktrees.source_root
        )
        dimensions = {
            "serialization_format": observed.serialization_format,
            "serialization_version": observed.serialization_version,
            "repository_identity": observed.repository_identity,
            "expected_parent": observed.expected_parent,
            "manifest_json": observed.manifest_json,
            "manifest_sha256": observed.manifest_sha256,
            "candidate_content_sha256": observed.candidate_content_sha256,
        }
        if any(stored[key] != value for key, value in dimensions.items()):
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF")
        return observed

    def complete_maker_precommit(
        self, run: MakerRun, *, run_result: CodexRunResult | None = None
    ) -> CandidateContentBinding:
        """Hand off immutable uncommitted content without staging or committing it."""
        fence = self._candidate_fence(run.candidate.execution_id)
        if run_result is not None and (run_result.exit_code != 0 or run_result.timed_out):
            raise ControllerError("MAKER_RUNTIME_FAILURE")
        row = self.store.get_execution(run.candidate.execution_id)
        if row["state"] != ExecutionState.MAKER_RUNNING.value or row["result_commit"] is not None:
            raise ControllerError("MAKER_COMPLETION_STATE_INVALID")
        self.worktrees.validate_maker_boundary(run.before, self.worktrees.fingerprint(run.candidate))
        binding = materialize_uncommitted_candidate(
            run.candidate, repository_identity=self.worktrees.source_root
        )
        authority = self.store.get_control_authority_state()
        persisted = self.store.bind_precommit_candidate(
            binding, maker_attempt_id=run.attempt_id,
            canonical_source_root=str(self.worktrees.source_root),
            worktree_identity=str(run.candidate.path.resolve(strict=True)),
            branch=run.candidate.branch, contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            authority_generation=authority["authority_generation"],
            fence=fence,
        )
        self._transition_candidate(run.candidate.execution_id, ExecutionState.VERIFYING,
                         reason="MAKER_PRECOMMIT_SUCCEEDED", fence=fence)
        if persisted["candidate_id"] == binding.candidate_id:
            return binding
        return CandidateContentBinding(
            persisted["candidate_id"], binding.execution_id, binding.serialization_format,
            binding.serialization_version, binding.repository_identity, binding.expected_parent,
            binding.manifest_json, binding.manifest_sha256, binding.candidate_content_sha256,
        )

    def record_candidate_verification(
        self, candidate: CandidateWorktree, record: CandidateVerificationResultRecord
    ):
        fence = self._candidate_fence(record.execution_id)
        self._verify_candidate_commands(candidate, record)
        row = self.store.get_execution(record.execution_id)
        if row["state"] != ExecutionState.VERIFYING.value or row["result_commit"] is not None:
            raise ControllerError("VERIFICATION_STATE_INVALID")
        binding = self.store.get_candidate_binding(record.candidate_id)
        self._materialize_bound_candidate(candidate, binding)
        authority = self.store.get_control_authority_state()
        if (record.candidate_content_sha256 != binding["candidate_content_sha256"]
                or record.contract_fingerprint != row["contract_fingerprint"]
                or record.authority_fingerprint != row["authority_fingerprint"]
                or record.authority_generation != authority["authority_generation"]):
            raise ControllerError("VERIFICATION_BINDING_MISMATCH")
        result = self.store.register_candidate_verification(
            **{field: getattr(record, field) for field in record.__dataclass_fields__},
            fence=fence,
        )
        if result["verdict"] == "PASS":
            self._transition_candidate(record.execution_id, ExecutionState.EVALUATING,
                             reason="CANDIDATE_VERIFICATION_PASSED", fence=fence)
        else:
            self._transition_candidate(record.execution_id, ExecutionState.BLOCKED,
                reason="CANDIDATE_VERIFICATION_BLOCKED", fence=fence, resume_state=ExecutionState.VERIFYING,
                blocker_code="BLOCKED_ENVIRONMENT" if result["verdict"] == "BLOCKED_ENVIRONMENT" else "VERIFICATION_FAILED")
        return result

    def run_maker(
        self,
        execution_id: str,
        capsule: ContextCapsule,
        *,
        binary: Path,
        artifact_directory: Path,
        output_schema: dict[str, Any],
        commit_message: str,
        model: str | None = None,
        reasoning_effort: str | None = None,
        timeout_seconds: int = 300,
    ) -> str:
        """Run one Maker via the accepted C3 workspace-write boundary."""

        run = self.begin_maker(
            execution_id, capsule, model=model, reasoning_effort=reasoning_effort
        )
        artifact_directory = self._validate_artifact_directory(
            artifact_directory, run.candidate
        )
        invocation = maker_invocation(
            workspace=run.candidate.path,
            prompt=run.capsule.canonical_json,
            output_schema=output_schema,
            artifact_directory=artifact_directory,
            binary=binary,
            model=model,
            reasoning_effort=reasoning_effort,
            timeout_seconds=timeout_seconds,
        )
        try:
            run_result = run_codex(invocation)
        except RunnerError as error:
            artifacts = error.artifacts
            self.store.finish_agent_attempt(
                run.attempt_id,
                status="FAILED",
                ended_at=timestamp(self.store._now()),
                failure_code=error.code,
                stdout_artifact=str(artifacts.stdout.path) if artifacts else None,
                stdout_sha256=artifacts.stdout.sha256 if artifacts else None,
                stderr_artifact=str(artifacts.stderr.path) if artifacts else None,
                stderr_sha256=artifacts.stderr.sha256 if artifacts else None,
                result_artifact=str(artifacts.result.path) if artifacts else None,
                result_sha256=artifacts.result.sha256 if artifacts else None,
            )
            row = self.store.get_execution(execution_id)
            resume = self._maker_resume_state(row, run.attempt_id)
            self._transition(
                execution_id, ExecutionState.BLOCKED, reason="MAKER_RUNTIME_FAILURE",
                resume_state=resume, blocker_code=error.code,
            )
            raise
        return self.complete_maker(run, commit_message=commit_message, run_result=run_result)

    def record_verification(self, record: VerificationResultRecord):
        row = self.store.get_execution(record.execution_id)
        if row["state"] != ExecutionState.VERIFYING.value:
            raise ControllerError("VERIFICATION_STATE_INVALID")
        if (
            record.result_commit != row["result_commit"]
            or record.contract_fingerprint != row["contract_fingerprint"]
            or record.authority_fingerprint != row["authority_fingerprint"]
        ):
            raise ControllerError("VERIFICATION_BINDING_MISMATCH")
        result = self.store.register_verification_result(record)
        if result["verdict"] == "PASS":
            self._transition(record.execution_id, ExecutionState.EVALUATING, reason="VERIFICATION_PASSED")
        else:
            self._transition(
                record.execution_id,
                ExecutionState.BLOCKED,
                reason="VERIFICATION_BLOCKED",
                resume_state=ExecutionState.VERIFYING,
                blocker_code=("BLOCKED_ENVIRONMENT" if result["verdict"] == "BLOCKED_ENVIRONMENT" else "VERIFICATION_FAILED"),
            )
        return result

    def begin_precommit_evaluator(
        self, execution_id: str, candidate: CandidateWorktree, capsule: ContextCapsule
    ) -> str:
        fence = self._candidate_fence(execution_id)
        if capsule.role is not CapsuleRole.EVALUATOR:
            raise ControllerError("EVALUATOR_CONTEXT_REQUIRED")
        row = self.store.get_execution(execution_id)
        if row["state"] != ExecutionState.EVALUATING.value or row["result_commit"] is not None:
            raise ControllerError("EVALUATOR_STATE_INVALID")
        binding = self.store.find_current_candidate_binding(execution_id)
        if binding is None:
            raise ControllerError("CANDIDATE_BINDING_REQUIRED")
        self._materialize_bound_candidate(candidate, binding)
        verification = self.store.connection.execute(
            """SELECT * FROM candidate_verification_result WHERE execution_id=? AND candidate_id=?
                 AND verdict='PASS' ORDER BY rowid DESC LIMIT 1""", (execution_id,binding["candidate_id"])
        ).fetchone()
        if verification is None:
            raise ControllerError("VERIFICATION_PASS_REQUIRED")
        expected_context = {
            "review_target_type": "UNCOMMITTED_CANDIDATE", "candidate_id": binding["candidate_id"],
            "candidate_content_sha256": binding["candidate_content_sha256"],
            "manifest_sha256": binding["manifest_sha256"], "expected_parent": binding["expected_parent"],
            "repository_identity": binding["repository_identity"],
            "contract_fingerprint": row["contract_fingerprint"], "authority_fingerprint": row["authority_fingerprint"],
            "authority_generation": self._candidate_fence(execution_id).authority_generation,
            "verification_id": verification["verification_id"],
            "command_manifest_sha256": verification["command_manifest_sha256"],
        }
        if any(capsule.content.get(key) != value for key, value in expected_context.items()):
            raise ControllerError("CANDIDATE_EVALUATOR_CONTEXT_MISMATCH")
        if not capsule.content.get("frozen_contract") or not capsule.content.get("acceptance_criteria"):
            raise ControllerError("CANDIDATE_EVALUATOR_CONTEXT_MISMATCH", "contract and acceptance required")
        context_id = f"context-evaluator-candidate-{uuid4().hex}"
        context = self.store.register_context_snapshot(
            context_id, execution_id, capsule.role, capsule.capsule_version, capsule,
            candidate_write_fence=fence,
        )
        attempt_id = f"candidate-evaluator-{uuid4().hex}"
        self.store.begin_candidate_evaluator_attempt(
            evaluator_attempt_id=attempt_id, execution_id=execution_id,
            candidate_id=binding["candidate_id"], verification_id=verification["verification_id"],
            context_snapshot_id=context["context_snapshot_id"],
            fence=fence,
        )
        return attempt_id

    def complete_precommit_evaluator(
        self, candidate: CandidateWorktree, record: CandidateEvaluationResultRecord,
        *, approval_required: bool = True
    ) -> ApprovalBinding | None:
        fence = self._candidate_fence(record.execution_id)
        binding = self.store.get_candidate_binding(record.candidate_id)
        self._materialize_bound_candidate(candidate,binding)
        authority = self.store.get_control_authority_state()
        row = self.store.get_execution(record.execution_id)
        if (record.candidate_content_sha256 != binding["candidate_content_sha256"]
                or record.contract_fingerprint != row["contract_fingerprint"]
                or record.authority_fingerprint != row["authority_fingerprint"]
                or record.authority_generation != authority["authority_generation"]):
            raise ControllerError("CANDIDATE_EVALUATOR_TARGET_MISMATCH")
        evaluation = self.store.register_candidate_evaluation(
            **{field:getattr(record,field) for field in record.__dataclass_fields__},
            fence=fence,
        )
        if evaluation["verdict"] == "PASS" and approval_required:
            self._transition_candidate(record.execution_id,ExecutionState.WAITING_APPROVAL,
                             reason="CANDIDATE_EVALUATION_PASSED", fence=fence,resume_state=ExecutionState.EVALUATING)
            current=self.store.get_execution(record.execution_id)
            approval_id=f"approval-candidate-{uuid4().hex}"
            authority_ref=f"candidate:{record.candidate_id}:evaluation:{record.evaluation_id}:generation:{record.authority_generation}"
            approval=self.store.request_approval(
                approval_id=approval_id,idempotency_key=operation_key("candidate-approval",{"evaluation_id":record.evaluation_id}),
                execution_id=record.execution_id,approval_type="DEVELOPMENT_ACCEPTANCE",authority_ref=authority_ref,
                expected_state_version=current["state_version"],lease_owner=self.controller_id,
                lease_generation=self._candidate_fence(record.execution_id).lease_generation,
                candidate_write_fence=self._candidate_fence(record.execution_id),
            )
            self.store.bind_candidate_approval(approval_id=approval_id,evaluation_id=record.evaluation_id,
                                               candidate_id=record.candidate_id,authority_generation=record.authority_generation,
                                               fence=self._candidate_fence(record.execution_id))
            return ApprovalBinding(approval["approval_id"],approval["authority_ref"])
        if evaluation["verdict"] == "PASS":
            return None
        destination = ExecutionState.REWORK_READY if evaluation["verdict"] == "REWORK_REQUIRED" else ExecutionState.BLOCKED
        self._transition_candidate(record.execution_id,destination,reason="CANDIDATE_EVALUATION_FAILED",fence=fence,
            **({"resume_state":ExecutionState.EVALUATING,"blocker_code":"EVALUATION_BLOCKED"} if destination is ExecutionState.BLOCKED else {}))
        return None

    def seal_precommit_evaluator_artifacts(
        self, candidate: CandidateWorktree, *, evaluator_attempt_id: str,
        phase: EvaluatorArtifactSealPhase, manifest_json: str, manifest_sha256: str,
        evidence_root: Path
    ):
        fence = self._candidate_fence(candidate.execution_id)
        if phase not in {EvaluatorArtifactSealPhase.PRE_EXECUTION,EvaluatorArtifactSealPhase.POST_EXECUTION}:
            raise ControllerError("INVALID_EVALUATOR_ARTIFACT_SEAL")
        attempt=self.store.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?",(evaluator_attempt_id,)).fetchone()
        if attempt is None:
            raise ControllerError("CANDIDATE_EVALUATOR_ATTEMPT_NOT_FOUND")
        root = self._validate_artifact_directory(evidence_root, candidate)
        binding=self.store.get_candidate_binding(attempt["candidate_id"])
        self._materialize_bound_candidate(candidate,binding)
        return self.store.create_candidate_evaluator_artifact_seal(
            seal_id=f"candidate-seal-{uuid4().hex}",evaluator_attempt_id=evaluator_attempt_id,
            phase=phase.value,manifest_json=manifest_json,manifest_sha256=manifest_sha256,
            evidence_root=str(root), fence=fence)

    def _prepare_candidate_git_plan(
        self, candidate: CandidateWorktree, binding: Mapping[str, Any], *,
        closure_id: str, evaluation_id: str, approval_id: str, commit_message: str,
        fence: CandidateWriteFence,
    ) -> dict[str, Any]:
        self.store._require_candidate_fence(candidate.execution_id, fence)
        self._materialize_bound_candidate(candidate, binding)
        if not isinstance(commit_message, str) or not commit_message.strip() or "\x00" in commit_message:
            raise ControllerError("CANDIDATE_COMMIT_MESSAGE_INVALID")
        if _candidate_git(candidate.path, "diff", "--cached", "--name-only", "-z").stdout:
            raise ControllerError("CANDIDATE_INDEX_NOT_EMPTY")
        base_tree = _candidate_git(candidate.path, "rev-parse", binding["expected_parent"] + "^{tree}").stdout.decode().strip()
        # An isolated index avoids mutating the reviewed candidate's index while
        # preparing raw blobs. No clean/smudge filters or rename inference run.
        with tempfile.TemporaryDirectory(prefix="adcp-candidate-index-") as temporary:
            env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
            _candidate_git(candidate.path, "read-tree", binding["expected_parent"], environment=env)
            for entry in json.loads(binding["manifest_json"])["entries"]:
                self.store._require_candidate_fence(candidate.execution_id, fence)
                if entry["operation"] == "D":
                    _candidate_git(candidate.path, "update-index", "--force-remove", "--", entry["path"], environment=env)
                    continue
                mode, content = _worktree_bytes(_candidate_file(candidate.path, entry["path"]))
                if (mode != entry["mode"] or len(content) != entry["byte_length"]
                        or hashlib.sha256(content).hexdigest() != entry["content_sha256"]):
                    raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", entry["path"])
                oid = _candidate_git(candidate.path, "hash-object", "-w", "--stdin", input=content).stdout.decode().strip()
                index_info = f"{mode} {oid}\t{entry['path']}\0".encode("utf-8")
                _candidate_git(candidate.path, "update-index", "-z", "--index-info", input=index_info, environment=env)
            self.store._require_candidate_fence(candidate.execution_id, fence)
            tree = _candidate_git(candidate.path, "write-tree", environment=env).stdout.decode().strip()
        self._materialize_bound_candidate(candidate, binding)
        seconds = int(self.store._now().timestamp())
        identity = f"ADCP Controller <adcp-controller@local.invalid> {seconds} +0000"
        commit_bytes = (f"tree {tree}\nparent {binding['expected_parent']}\n"
            f"author {identity}\ncommitter {identity}\n\n{commit_message.strip()}\n\n"
            f"ADCP-Candidate: {binding['candidate_id']}\nADCP-Closure: {closure_id}\n"
            f"ADCP-Approval: {approval_id}\nADCP-Evaluation: {evaluation_id}\n").encode("utf-8")
        commit = _candidate_git(candidate.path, "hash-object", "-t", "commit", "--stdin", input=commit_bytes).stdout.decode().strip()
        return {"closure_id":closure_id,"execution_id":candidate.execution_id,
            "candidate_id":binding["candidate_id"],"approval_id":approval_id,"evaluation_id":evaluation_id,
            "repository_identity":binding["repository_identity"],"worktree_identity":str(candidate.path.resolve(strict=True)),
            "branch":candidate.branch,"expected_parent":binding["expected_parent"],"base_tree":base_tree,
            "expected_tree":tree,"result_commit":commit,"commit_object_hex":commit_bytes.hex(),
            "manifest_sha256":binding["manifest_sha256"],"candidate_content_sha256":binding["candidate_content_sha256"]}

    def _apply_candidate_git_plan(
        self, candidate: CandidateWorktree, binding: Mapping[str, Any],
        plan: Mapping[str, Any], fence: CandidateWriteFence,
    ) -> str:
        self.store._require_candidate_fence(candidate.execution_id, fence)
        identity = {"execution_id":candidate.execution_id,"candidate_id":binding["candidate_id"],
            "repository_identity":str(self.worktrees.source_root),"worktree_identity":str(candidate.path.resolve(strict=True)),
            "branch":candidate.branch,"expected_parent":binding["expected_parent"],
            "manifest_sha256":binding["manifest_sha256"],"candidate_content_sha256":binding["candidate_content_sha256"]}
        if any(plan.get(key) != value for key, value in identity.items()):
            raise ControllerError("CANDIDATE_COMMIT_INTENT_CONFLICT")
        if _candidate_git(candidate.path, "symbolic-ref", "--short", "HEAD").stdout.decode().strip() != candidate.branch:
            raise ControllerError("CANDIDATE_COMMIT_INTENT_CONFLICT", "branch")
        result_commit = plan["result_commit"]
        parent = plan["expected_parent"]
        head = _candidate_git(candidate.path, "rev-parse", "HEAD").stdout.decode().strip()
        if head not in {parent, result_commit}:
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "unrecognized HEAD")
        index_tree = _candidate_git(candidate.path, "write-tree").stdout.decode().strip()
        if index_tree not in {plan["base_tree"], plan["expected_tree"]}:
            raise ControllerError("CANDIDATE_INDEX_CHANGED_AFTER_APPROVAL")
        if head == parent:
            self._materialize_bound_candidate(candidate, binding)
            if index_tree != plan["base_tree"]:
                raise ControllerError("CANDIDATE_INDEX_CHANGED_AFTER_APPROVAL")
            commit_bytes = bytes.fromhex(plan["commit_object_hex"])
            calculated = _candidate_git(candidate.path, "hash-object", "-t", "commit", "--stdin", input=commit_bytes).stdout.decode().strip()
            if calculated != result_commit:
                raise ControllerError("CANDIDATE_COMMIT_INTENT_CONFLICT", "commit object")
            self.store._require_candidate_fence(candidate.execution_id, fence)
            written = _candidate_git(candidate.path, "hash-object", "-t", "commit", "-w", "--stdin", input=commit_bytes).stdout.decode().strip()
            if written != result_commit:
                raise ControllerError("CANDIDATE_COMMIT_INTENT_CONFLICT", "commit write")
            verify_committed_candidate(candidate.path, result_commit, binding)
            self.store._require_candidate_fence(candidate.execution_id, fence)
            _candidate_git(candidate.path, "update-ref", "refs/heads/" + candidate.branch, result_commit, parent)
            self.store._require_candidate_fence(candidate.execution_id, fence)
        # This is also the crash retry path: validate the exact intent and every
        # accepted byte, not merely that a HEAD exists or resembles the candidate.
        verify_committed_candidate(candidate.path, result_commit, binding)
        if _candidate_git(candidate.path, "rev-parse", result_commit + "^{tree}").stdout.decode().strip() != plan["expected_tree"]:
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "committed tree")
        if _candidate_git(candidate.path, "cat-file", "commit", result_commit).stdout != bytes.fromhex(plan["commit_object_hex"]):
            raise ControllerError("CANDIDATE_COMMIT_INTENT_CONFLICT", "committed identity")
        entries = json.loads(binding["manifest_json"])["entries"]
        for entry in entries:
            path = _candidate_file(candidate.path, entry["path"])
            if entry["operation"] == "D":
                if path.exists() or path.is_symlink():
                    raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", entry["path"])
            else:
                mode, content = _worktree_bytes(path)
                if mode != entry["mode"] or len(content) != entry["byte_length"] or hashlib.sha256(content).hexdigest() != entry["content_sha256"]:
                    raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", entry["path"])
        if _candidate_git(candidate.path, "diff", "--no-ext-diff", "--no-textconv", "--name-only", result_commit, "--").stdout:
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "working tree")
        untracked = {item.decode("utf-8") for item in _candidate_git(candidate.path,"ls-files","--others","--exclude-standard","-z").stdout.split(b"\0") if item}
        if untracked - {entry["path"] for entry in entries if entry["operation"] == "A"}:
            raise ControllerError("CANDIDATE_CHANGED_AFTER_HANDOFF", "untracked paths")
        if index_tree != plan["expected_tree"]:
            self.store._require_candidate_fence(candidate.execution_id, fence)
            _candidate_git(candidate.path, "read-tree", plan["expected_tree"])
        self.store._require_candidate_fence(candidate.execution_id, fence)
        return result_commit

    def close_precommit_candidate(self, candidate: CandidateWorktree, *, candidate_id: str,
        evaluation_id: str, approval_id: str, commit_message: str) -> str:
        """Close only a current candidate-bound approval; reconcile the same intent."""
        binding = self.store.get_candidate_binding(candidate_id)
        provenance = self.store.connection.execute(
            "SELECT * FROM candidate_provenance WHERE candidate_id=? ORDER BY rowid DESC LIMIT 1", (candidate_id,)
        ).fetchone()
        if (provenance is None or binding["execution_id"] != candidate.execution_id
                or provenance["worktree_identity"] != str(candidate.path.resolve(strict=True))
                or provenance["branch"] != candidate.branch or candidate.base_commit != binding["expected_parent"]):
            raise ControllerError("CANDIDATE_PROVENANCE_MISMATCH")
        closure_id = "closure-" + canonical_sha256({"candidate_id":candidate_id,"approval_id":approval_id,
                                                   "evaluation_id":evaluation_id,"manifest_sha256":binding["manifest_sha256"]})
        fence = self._candidate_fence(candidate.execution_id)
        self.store.prepare_candidate_commit(
            execution_id=candidate.execution_id,candidate_id=candidate_id,evaluation_id=evaluation_id,
            approval_id=approval_id,closure_id=closure_id,fence=fence,
            prepare=lambda: self._prepare_candidate_git_plan(candidate,binding,closure_id=closure_id,
                evaluation_id=evaluation_id,approval_id=approval_id,commit_message=commit_message,fence=fence),
        )
        self.store._require_candidate_fence(candidate.execution_id, fence)
        closed = self.store.close_candidate_to_commit(
            execution_id=candidate.execution_id,candidate_id=candidate_id,evaluation_id=evaluation_id,
            approval_id=approval_id,closure_id=closure_id,fence=fence,
            apply=lambda plan: self._apply_candidate_git_plan(candidate,binding,plan,fence),
        )
        return closed["result_commit"]

    def resolve_precommit_approval(
        self, execution_id: str, binding: ApprovalBinding, *, approved: bool
    ):
        """Resolve the candidate approval without consuming or leaving its closure gate."""
        linked=self.store.connection.execute(
            "SELECT 1 FROM approval_candidate_binding WHERE approval_id=? AND execution_id=?",
            (binding.approval_id,execution_id),
        ).fetchone()
        if linked is None or self.store.get_execution(execution_id)["state"] != ExecutionState.WAITING_APPROVAL.value:
            raise ControllerError("CANDIDATE_APPROVAL_BINDING_MISMATCH")
        resolved=self.store.resolve_approval(binding.approval_id,execution_id=execution_id,
            authority_ref=binding.authority_ref,approved=approved,
            candidate_write_fence=self._candidate_fence(execution_id))
        if not approved:
            self._transition_candidate(execution_id,ExecutionState.DESIGN_ESCALATION,
                             reason="APPROVAL_REJECTED",blocker_code="APPROVAL_REJECTED")
        return resolved

    def begin_evaluator(
        self,
        execution_id: str,
        capsule: ContextCapsule,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        if capsule.role is not CapsuleRole.EVALUATOR:
            raise ControllerError("EVALUATOR_CONTEXT_REQUIRED")
        allowed_fields = {
            "frozen_contract",
            "acceptance_criteria",
            "base_commit",
            "result_commit",
            "changed_file_manifest",
            "diff",
            "deterministic_verification_result",
            "relevant_authority_refs",
            "relevant_authority_excerpts",
        }
        if set(capsule.content) != allowed_fields:
            raise ControllerError("EVALUATOR_CONTEXT_BOUNDARY_INVALID")
        row = self.store.get_execution(execution_id)
        if row["state"] != ExecutionState.EVALUATING.value:
            raise ControllerError("EVALUATOR_STATE_INVALID")
        if not self.store.has_verification_pass(
            execution_id, row["result_commit"], row["contract_fingerprint"], row["authority_fingerprint"]
        ):
            raise ControllerError("VERIFICATION_PASS_REQUIRED")
        verification = self.store.find_verification_pass(
            execution_id, row["result_commit"], row["contract_fingerprint"], row["authority_fingerprint"]
        )
        verification_content = capsule.content["deterministic_verification_result"]
        if (
            capsule.content["base_commit"] != row["base_commit"]
            or capsule.content["result_commit"] != row["result_commit"]
            or not isinstance(verification_content, dict)
            or verification_content.get("verification_id") != verification["verification_id"]
            or verification_content.get("result_commit") != row["result_commit"]
            or verification_content.get("contract_fingerprint") != row["contract_fingerprint"]
            or verification_content.get("authority_fingerprint") != row["authority_fingerprint"]
            or verification_content.get("verdict") != "PASS"
        ):
            raise ControllerError("EVALUATOR_CONTEXT_BINDING_MISMATCH")
        context_id = f"context-evaluator-{uuid4().hex}"
        context = self.store.register_context_snapshot(
            context_id, execution_id, capsule.role, capsule.capsule_version, capsule
        )
        context_id = context["context_snapshot_id"]
        attempt_no = self.store.connection.execute(
            "SELECT count(*) + 1 FROM agent_attempt WHERE execution_id = ? AND role = 'EVALUATOR'",
            (execution_id,),
        ).fetchone()[0]
        attempt_id = f"evaluator-{uuid4().hex}"
        self.store.register_agent_attempt(
            attempt_id=attempt_id,
            operation_key=operation_key("evaluator-attempt", {"attempt_id": attempt_id}),
            execution_id=execution_id,
            role=CapsuleRole.EVALUATOR,
            attempt_no=attempt_no,
            model=model,
            reasoning_effort=reasoning_effort,
            session_id=f"session-{uuid4().hex}",
            context_snapshot_id=context_id,
            base_commit=row["base_commit"],
            result_commit=row["result_commit"],
            started_at=timestamp(self.store._now()),
        )
        return attempt_id

    def _persist_evaluator_artifact_seal(
        self,
        attempt_id: str,
        *,
        phase: EvaluatorArtifactSealPhase,
        evidence_root: Path,
        manifest_json: str,
        manifest_sha256: str,
        producer_kind: EvaluatorArtifactProducerKind,
        producer_ref: str,
        approval_id: str | None = None,
    ):
        attempt = self.store.get_agent_attempt(attempt_id)
        row = self.store.get_execution(attempt["execution_id"])
        context = self.store.get_context_snapshot(attempt["context_snapshot_id"])
        verification = self.store.find_verification_pass(
            row["execution_id"], row["result_commit"],
            row["contract_fingerprint"], row["authority_fingerprint"],
        )
        if verification is None:
            raise ControllerError("VERIFICATION_PASS_REQUIRED")
        authority = self.store.get_control_authority_state()
        seal_id = f"seal-{phase.value.lower().replace('_', '-')}-{attempt_id}"
        spec = EvaluatorArtifactSealCreate(
            seal_id=seal_id,
            execution_id=row["execution_id"],
            result_commit=row["result_commit"],
            verification_id=verification["verification_id"],
            evaluator_attempt_id=attempt_id,
            context_snapshot_id=context["context_snapshot_id"],
            context_fingerprint=context["fingerprint"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            phase=phase,
            producer_kind=producer_kind,
            producer_ref=producer_ref,
            evidence_root=str(Path(evidence_root).absolute()),
            manifest_version=1,
            manifest_json=manifest_json,
            manifest_sha256=manifest_sha256,
            authority_generation=authority["authority_generation"],
            operation_key=operation_key(
                "evaluator-artifact-seal",
                {"attempt_id": attempt_id, "phase": phase.value},
            ),
            approval_id=approval_id,
        )
        try:
            return self.store.create_evaluator_artifact_seal(
                spec,
                lease_owner=self.controller_id,
                lease_generation=row["lease_generation"],
                required_execution_state=ExecutionState.EVALUATING,
            )
        except StoreError as error:
            raise ControllerError(error.code, error.detail) from error

    def _create_pre_execution_seal(
        self,
        attempt_id: str,
        capsule: ContextCapsule,
        invocation: Any,
        evidence_root: Path,
    ):
        pre_root = evidence_root / ".adcp-pre"
        try:
            pre_root.mkdir(parents=False, exist_ok=False)
            context = self.store.get_context_snapshot(
                self.store.get_agent_attempt(attempt_id)["context_snapshot_id"]
            )
            context_path = pre_root / "context-snapshot.json"
            prompt_path = pre_root / "prompt.txt"
            schema_path = pre_root / "output-schema.json"
            context_path.write_text(context["canonical_json"], encoding="utf-8")
            prompt_path.write_text(invocation.prompt, encoding="utf-8")
            schema_path.write_text(canonical_json(invocation.output_schema), encoding="utf-8")
            manifest_json, manifest_sha256, _ = collect_manifest(
                evidence_root,
                {
                    "context_snapshot": context_path,
                    "prompt": prompt_path,
                    "output_schema": schema_path,
                },
            )
        except (OSError, ArtifactSealError) as error:
            code = getattr(error, "code", "EVALUATOR_PRE_SEAL_FILESYSTEM_FAILURE")
            raise ControllerError(code, str(error)) from error
        return self._persist_evaluator_artifact_seal(
            attempt_id,
            phase=EvaluatorArtifactSealPhase.PRE_EXECUTION,
            evidence_root=evidence_root,
            manifest_json=manifest_json,
            manifest_sha256=manifest_sha256,
            producer_kind=EvaluatorArtifactProducerKind.CONTROLLER_RUNNER,
            producer_ref=self.controller_id,
        )

    def _create_post_execution_seal(
        self,
        attempt_id: str,
        run_result: CodexRunResult,
        evidence_root: Path,
    ):
        try:
            roles = post_execution_roles(
                evidence_root,
                stdout_path=run_result.artifacts.stdout.path,
                stderr_path=run_result.artifacts.stderr.path,
                result_path=run_result.artifacts.result.path,
                metadata_path=run_result.artifacts.metadata.path,
            )
            manifest_json, manifest_sha256, _ = collect_manifest(
                evidence_root, roles
            )
        except ArtifactSealError as error:
            raise ControllerError(error.code, error.detail) from error
        return self._persist_evaluator_artifact_seal(
            attempt_id,
            phase=EvaluatorArtifactSealPhase.POST_EXECUTION,
            evidence_root=evidence_root,
            manifest_json=manifest_json,
            manifest_sha256=manifest_sha256,
            producer_kind=EvaluatorArtifactProducerKind.CONTROLLER_RUNNER,
            producer_ref=self.controller_id,
        )

    def attest_legacy_evaluator_artifacts(
        self,
        attempt_id: str,
        *,
        approval_id: str,
        producer_ref: str,
    ):
        """Explicit one-time bridge for a frozen pre-seal evaluator attempt."""

        if not approval_id or not producer_ref:
            raise ControllerError("LEGACY_ATTESTATION_APPROVAL_REQUIRED")
        attempt = self.store.get_agent_attempt(attempt_id)
        if attempt["role"] != "EVALUATOR" or attempt["status"] != "SUCCEEDED":
            raise ControllerError("EVALUATOR_LEGACY_ATTESTATION_ATTEMPT_INVALID")
        required = (
            attempt["stdout_artifact"], attempt["stderr_artifact"],
            attempt["result_artifact"],
        )
        if not all(isinstance(value, str) and value for value in required):
            raise ControllerError("EVALUATOR_LEGACY_ARTIFACT_MISSING")
        roots = {str(Path(value).expanduser().absolute().parent) for value in required}
        if len(roots) != 1:
            raise ControllerError("EVALUATOR_LEGACY_EVIDENCE_ROOT_AMBIGUOUS")
        evidence_root = Path(next(iter(roots)))
        try:
            roles = legacy_attestation_roles(
                evidence_root,
                stdout_path=attempt["stdout_artifact"],
                stderr_path=attempt["stderr_artifact"],
                result_path=attempt["result_artifact"],
            )
            manifest_json, manifest_sha256, _ = collect_manifest(
                evidence_root, roles
            )
        except ArtifactSealError as error:
            raise ControllerError(error.code, error.detail) from error
        return self._persist_evaluator_artifact_seal(
            attempt_id,
            phase=EvaluatorArtifactSealPhase.LEGACY_ATTESTED,
            evidence_root=evidence_root,
            manifest_json=manifest_json,
            manifest_sha256=manifest_sha256,
            producer_kind=EvaluatorArtifactProducerKind.LEGACY_HUMAN_ATTESTATION,
            producer_ref=producer_ref,
            approval_id=approval_id,
        )

    def complete_evaluator(
        self,
        attempt_id: str,
        *,
        verdict: str,
        result: Mapping[str, Any],
        post_execution_seal_id: str | None = None,
        approval_required: bool = False,
        run_result: CodexRunResult | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> ApprovalBinding | None:
        attempt = self.store.get_agent_attempt(attempt_id)
        execution_id = attempt["execution_id"]
        row = self.store.get_execution(execution_id)
        if row["state"] != ExecutionState.EVALUATING.value:
            raise ControllerError("EVALUATOR_COMPLETION_STATE_INVALID")
        if (
            attempt["role"] != CapsuleRole.EVALUATOR.value
            or attempt["status"] not in {"RUNNING", "SUCCEEDED"}
            or attempt["result_commit"] != row["result_commit"]
        ):
            raise ControllerError("EVALUATOR_COMPLETION_ATTEMPT_INVALID")
        artifacts = run_result.artifacts if run_result else None
        ended_at = attempt["ended_at"] or timestamp(self.store._now())
        evaluation_id, evaluation_operation_key = evaluation_result_identity(attempt_id)
        record = build_evaluation_result(
            evaluation_id=evaluation_id,
            operation_key=evaluation_operation_key,
            execution_id=execution_id,
            evaluator_attempt_id=attempt_id,
            context_snapshot_id=attempt["context_snapshot_id"],
            result_commit=row["result_commit"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            verdict=verdict,
            result=result,
            started_at=attempt["started_at"],
            ended_at=ended_at,
        )
        if post_execution_seal_id is None:
            raise ControllerError("EVALUATOR_POST_EXECUTION_SEAL_REQUIRED")
        if run_result is not None and (
            run_result.exit_code != 0
            or run_result.timed_out
            or canonical_json(run_result.structured_result) != record.result_json
        ):
            raise ControllerError("EVALUATOR_RUNNER_RESULT_MISMATCH")
        artifact_binding = (
            EvaluatorArtifactBinding(
                result_artifact=str(artifacts.result.path),
                result_sha256=artifacts.result.sha256,
                stdout_artifact=str(artifacts.stdout.path),
                stdout_sha256=artifacts.stdout.sha256,
                stderr_artifact=str(artifacts.stderr.path),
                stderr_sha256=artifacts.stderr.sha256,
            )
            if artifacts is not None
            else None
        )
        try:
            seal, _ = self.store.verify_evaluator_artifact_seal(
                post_execution_seal_id, expected_attempt_id=attempt_id
            )
            if seal["phase"] != EvaluatorArtifactSealPhase.POST_EXECUTION.value:
                raise StoreError("EVALUATOR_POST_EXECUTION_SEAL_REQUIRED")
            self.store.validate_evaluation_completion_binding(
                record,
                artifact_seal_id=post_execution_seal_id,
                artifact_bundle=artifact_binding,
                allowed_attempt_statuses=("RUNNING", "SUCCEEDED"),
            )
        except StoreError as error:
            raise ControllerError(error.code, error.detail) from error
        self.store._require_fence(
            row,
            self.controller_id,
            row["lease_generation"],
            timestamp(self.store._now()),
        )
        self.store.finish_agent_attempt(
            attempt_id,
            status="SUCCEEDED",
            result_commit=row["result_commit"],
            exit_code=0,
            ended_at=ended_at,
            stdout_artifact=str(artifacts.stdout.path) if artifacts else None,
            stdout_sha256=artifacts.stdout.sha256 if artifacts else None,
            stderr_artifact=str(artifacts.stderr.path) if artifacts else None,
            stderr_sha256=artifacts.stderr.sha256 if artifacts else None,
            result_artifact=str(artifacts.result.path) if artifacts else None,
            result_sha256=artifacts.result.sha256 if artifacts else None,
            post_execution_seal_id=post_execution_seal_id,
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
            required_execution_state=ExecutionState.EVALUATING,
        )
        if fault_injector is not None:
            fault_injector("attempt_succeeded")
        evaluation = self.store.register_evaluation_result(
            record,
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
            required_execution_state=ExecutionState.EVALUATING,
        )
        if fault_injector is not None:
            fault_injector("evaluation_result")
        if verdict == "PASS":
            if not approval_required:
                return None
            waiting = self._transition(
                execution_id,
                ExecutionState.WAITING_APPROVAL,
                reason="HUMAN_APPROVAL_REQUIRED",
                resume_state=ExecutionState.EVALUATING,
            )
            if fault_injector is not None:
                fault_injector("state_transition")
            authority_ref = canonical_sha256(
                {
                    "execution_id": execution_id,
                    "state_version": waiting["state_version"],
                    "result_commit": row["result_commit"],
                    "evaluation_id": evaluation["evaluation_id"],
                    "contract_fingerprint": row["contract_fingerprint"],
                    "authority_fingerprint": row["authority_fingerprint"],
                }
            )
            approval_id = f"approval-{uuid4().hex}"
            self.store.request_approval(
                approval_id=approval_id,
                idempotency_key=operation_key(
                    "approval-request", {"approval_id": approval_id}
                ),
                execution_id=execution_id,
                approval_type="DEVELOPMENT_ACCEPTANCE",
                authority_ref=authority_ref,
                expected_state_version=waiting["state_version"],
                lease_owner=self.controller_id,
                lease_generation=waiting["lease_generation"],
            )
            if fault_injector is not None:
                fault_injector("approval_request")
            return ApprovalBinding(approval_id, authority_ref)
        if verdict == "REWORK_REQUIRED":
            if row["maker_rework_count"] >= row["max_auto_reworks"]:
                self._transition(
                    execution_id,
                    ExecutionState.DESIGN_ESCALATION,
                    reason="REWORK_BUDGET_EXHAUSTED",
                    blocker_code="REWORK_BUDGET_EXHAUSTED",
                )
            else:
                self._transition(
                    execution_id,
                    ExecutionState.REWORK_READY,
                    reason="REWORK_REQUIRED",
                )
        elif verdict == "DESIGN_REVIEW_REQUIRED":
            self._transition(
                execution_id,
                ExecutionState.DESIGN_ESCALATION,
                reason="DESIGN_REVIEW_REQUIRED",
                blocker_code="DESIGN_REVIEW_REQUIRED",
            )
        elif verdict in {"BLOCKED_ENVIRONMENT", "BLOCKED_EVIDENCE"}:
            self._transition(
                execution_id,
                ExecutionState.BLOCKED,
                reason=verdict,
                resume_state=ExecutionState.EVALUATING,
                blocker_code=verdict,
            )
        if fault_injector is not None:
            fault_injector("state_transition")
        return None

    def run_evaluator(
        self,
        execution_id: str,
        candidate: CandidateWorktree,
        capsule: ContextCapsule,
        *,
        binary: Path,
        artifact_directory: Path,
        model: str | None = None,
        reasoning_effort: str | None = None,
        timeout_seconds: int = 300,
        approval_required: bool = False,
        fault_injector: Callable[[str], None] | None = None,
    ) -> ApprovalBinding | None:
        """Run one Evaluator only after PRE seal and finalize only after POST seal."""

        row = self.store.get_execution(execution_id)
        if candidate.execution_id != execution_id:
            raise ControllerError("WORKTREE_EXECUTION_MISMATCH")
        artifact_base = self._validate_artifact_directory(
            artifact_directory, candidate
        )
        candidate_head = _run_git(
            candidate.path, "rev-parse", "HEAD"
        ).stdout.decode().strip()
        if candidate_head != row["result_commit"]:
            raise ControllerError("EVALUATOR_RESULT_COMMIT_MISMATCH")
        attempt_id = self.begin_evaluator(
            execution_id, capsule, model=model, reasoning_effort=reasoning_effort
        )
        evidence_root = artifact_base / attempt_id
        try:
            evidence_root.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            self.fail_evaluator(
                attempt_id, failure_code="EVALUATOR_EVIDENCE_ROOT_CREATE_FAILED"
            )
            raise ControllerError(
                "EVALUATOR_EVIDENCE_ROOT_CREATE_FAILED", str(evidence_root)
            ) from error
        invocation = evaluator_invocation(
            workspace=candidate.path,
            prompt=capsule.canonical_json,
            artifact_directory=evidence_root,
            binary=binary,
            model=model,
            reasoning_effort=reasoning_effort,
            timeout_seconds=timeout_seconds,
        )
        try:
            self._create_pre_execution_seal(
                attempt_id, capsule, invocation, evidence_root
            )
            if fault_injector is not None:
                fault_injector("pre_execution_seal")
            run_result = run_codex(invocation)
            if fault_injector is not None:
                fault_injector("evaluator_finished")
            post = self._create_post_execution_seal(
                attempt_id, run_result, evidence_root
            )
            if fault_injector is not None:
                fault_injector("post_execution_seal")
        except RunnerError as error:
            self.fail_evaluator(
                attempt_id, failure_code=error.code, artifacts=error.artifacts
            )
            raise
        except ControllerError as error:
            current = self.store.get_agent_attempt(attempt_id)
            if current["status"] == "RUNNING":
                self.fail_evaluator(
                    attempt_id,
                    failure_code=(
                        "BLOCKED_EVIDENCE"
                        if error.code.startswith("EVALUATOR_")
                        else error.code
                    ),
                )
            raise
        return self.complete_evaluator(
            attempt_id,
            verdict=run_result.structured_result["verdict"],
            result=run_result.structured_result,
            post_execution_seal_id=post["seal_id"],
            approval_required=approval_required,
            run_result=run_result,
            fault_injector=fault_injector,
        )

    def fail_evaluator(
        self,
        attempt_id: str,
        *,
        failure_code: str,
        artifacts: Any | None = None,
    ) -> None:
        attempt = self.store.get_agent_attempt(attempt_id)
        self.store.finish_agent_attempt(
            attempt_id, status="FAILED", failure_code=failure_code,
            result_commit=attempt["result_commit"], ended_at=timestamp(self.store._now()),
            stdout_artifact=str(artifacts.stdout.path) if artifacts else None,
            stdout_sha256=artifacts.stdout.sha256 if artifacts else None,
            stderr_artifact=str(artifacts.stderr.path) if artifacts else None,
            stderr_sha256=artifacts.stderr.sha256 if artifacts else None,
            result_artifact=str(artifacts.result.path) if artifacts else None,
            result_sha256=artifacts.result.sha256 if artifacts else None,
        )
        self._transition(
            attempt["execution_id"], ExecutionState.BLOCKED,
            reason="EVALUATOR_INFRASTRUCTURE_FAILURE", resume_state=ExecutionState.EVALUATING,
            blocker_code=failure_code,
        )

    def resolve_approval(
        self,
        execution_id: str,
        binding: ApprovalBinding,
        *,
        approved: bool,
    ):
        state_before = self.store.get_execution(execution_id)["state"]
        resolved = self.store.resolve_approval(
            binding.approval_id,
            execution_id=execution_id,
            authority_ref=binding.authority_ref,
            approved=approved,
        )
        if approved and state_before == ExecutionState.WAITING_APPROVAL.value:
            self._transition(execution_id, ExecutionState.EVALUATING, reason="APPROVAL_RECORDED")
        elif not approved and state_before == ExecutionState.WAITING_APPROVAL.value:
            self._transition(
                execution_id, ExecutionState.DESIGN_ESCALATION,
                reason="APPROVAL_REJECTED", blocker_code="APPROVAL_REJECTED"
            )
        return resolved

    def accept(
        self,
        execution_id: str,
        *,
        approval: ApprovalBinding | None = None,
    ):
        row = self.store.get_execution(execution_id)
        if row["state"] == ExecutionState.ACCEPTED.value:
            return row
        if row["state"] != ExecutionState.EVALUATING.value:
            raise ControllerError("ACCEPTANCE_STATE_INVALID")
        verification = self.store.find_verification_pass(
            execution_id, row["result_commit"], row["contract_fingerprint"], row["authority_fingerprint"]
        )
        evaluation = self.store.find_evaluation_pass(
            execution_id, row["result_commit"], row["contract_fingerprint"], row["authority_fingerprint"]
        )
        if verification is None or evaluation is None:
            raise ControllerError("ACCEPTANCE_EVIDENCE_REQUIRED")
        evaluator = self.store.get_agent_attempt(evaluation["evaluator_attempt_id"])
        maker = self.store.connection.execute(
            """SELECT * FROM agent_attempt WHERE execution_id = ? AND role = 'MAKER'
                 AND status = 'SUCCEEDED' AND result_commit = ? ORDER BY attempt_no DESC LIMIT 1""",
            (execution_id, row["result_commit"]),
        ).fetchone()
        if maker is None:
            raise ControllerError("MAKER_EVIDENCE_REQUIRED")
        contexts = []
        for context_id in (maker["context_snapshot_id"], evaluator["context_snapshot_id"]):
            context = self.store.get_context_snapshot(context_id)
            contexts.append(
                {"role": context["role"], "context_snapshot_id": context_id,
                 "fingerprint": context["fingerprint"]}
            )
        events = [
            {"event_id": event["event_id"], "event_type": event["event_type"],
             "to_state": event["to_state"], "to_state_version": event["to_state_version"]}
            for event in self.store.events(execution_id)
        ]
        approval_refs: list[dict[str, Any]] = []
        if approval is not None:
            approval_row = self.store.get_approval(approval.approval_id)
            approval_refs.append(
                {"approval_id": approval.approval_id, "authority_ref": approval.authority_ref,
                 "status": approval_row["status"]}
            )
        created_at = timestamp(self.store._now())
        manifest_id = f"manifest-{uuid4().hex}"
        manifest = build_evidence_manifest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            slice_id=row["slice_id"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            base_commit=row["base_commit"],
            result_commit=row["result_commit"],
            maker_attempt_evidence={"attempt_id": maker["attempt_id"], "status": maker["status"]},
            verification_evidence={"verification_id": verification["verification_id"], "verdict": verification["verdict"]},
            evaluator_attempt_evidence={"attempt_id": evaluator["attempt_id"], "status": evaluator["status"]},
            evaluation_evidence={"evaluation_id": evaluation["evaluation_id"], "verdict": evaluation["verdict"]},
            approval_refs=approval_refs,
            context_fingerprints=contexts,
            transition_evidence=events,
            created_at=created_at,
        )
        return self.store.accept_execution(
            execution_id,
            row["state_version"],
            operation_key("accept-execution", {"execution_id": execution_id, "result_commit": row["result_commit"]}),
            manifest,
            lease_owner=self.controller_id,
            lease_generation=row["lease_generation"],
            approval_id=approval.approval_id if approval else None,
            approval_authority_ref=approval.authority_ref if approval else None,
            actor_id=self.controller_id,
        )

    def advance(self, execution_id: str, *, limit: int = 1):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ControllerError("INVALID_ADVANCE_LIMIT")
        row = self.store.get_execution(execution_id)
        for _ in range(limit):
            if row["state"] not in {
                ExecutionState.WAITING_APPROVAL.value,
                ExecutionState.EVALUATING.value,
            }:
                break
            approval = self.store.connection.execute(
                """SELECT * FROM approval_request WHERE execution_id = ?
                     AND status = 'APPROVED' AND consumed_at IS NULL ORDER BY requested_at DESC LIMIT 1""",
                (execution_id,),
            ).fetchone()
            if approval is None:
                break
            binding = ApprovalBinding(approval["approval_id"], approval["authority_ref"])
            if row["state"] == ExecutionState.WAITING_APPROVAL.value:
                self._transition(execution_id, ExecutionState.EVALUATING, reason="APPROVAL_RECORDED")
            row = self.accept(execution_id, approval=binding)
        return row

    def cancel(self, execution_id: str):
        return self._transition(execution_id, ExecutionState.CANCELLED, reason="OPERATOR_CANCELLED")


__all__ = [
    "ApprovalBinding",
    "CandidateFingerprint",
    "CandidateWorktree",
    "Controller",
    "ControllerError",
    "MakerRun",
    "WorktreeOrchestrator",
]
