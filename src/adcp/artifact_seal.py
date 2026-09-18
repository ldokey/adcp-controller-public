"""Trusted evaluator artifact collection and immutable seal verification.

Artifact authority is established from bytes read by the trusted parent through a
no-symlink, descriptor-bound filesystem walk.  Caller-provided hashes are claims,
never authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Mapping

from adcp.canonical import canonical_json, canonical_sha256


MANIFEST_VERSION = 1


class ArtifactSealError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class SealedArtifactEntry:
    role: str
    relative_path: str
    sha256: str
    byte_size: int

    def as_json(self) -> dict[str, object]:
        return {
            "role": self.role,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
        }


@dataclass(frozen=True)
class VerifiedArtifactManifest:
    evidence_root: Path
    entries: tuple[SealedArtifactEntry, ...]
    bytes_by_path: Mapping[str, bytes]

    def entry_for_role(self, role: str) -> SealedArtifactEntry:
        matches = [entry for entry in self.entries if entry.role == role]
        if len(matches) != 1:
            raise ArtifactSealError("EVALUATOR_SEALED_ROLE_INVALID", role)
        return matches[0]

    def entry_for_path(self, relative_path: str) -> SealedArtifactEntry:
        matches = [entry for entry in self.entries if entry.relative_path == relative_path]
        if len(matches) != 1:
            raise ArtifactSealError("EVALUATOR_ARTIFACT_NOT_SEALED", relative_path)
        return matches[0]

    def bytes_for_role(self, role: str) -> bytes:
        entry = self.entry_for_role(role)
        return self.bytes_by_path[entry.relative_path]


def _lexical_root(root: str | Path) -> Path:
    path = Path(root).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    # abspath normalizes '.' but does not resolve symlinks.  The evidence root is
    # a trusted Controller-owned directory; every component below it is walked
    # with O_NOFOLLOW.
    return Path(os.path.abspath(path))


def relative_artifact_path(path: str | Path, evidence_root: str | Path) -> str:
    raw = Path(path).expanduser()
    if any(part == ".." for part in raw.parts):
        raise ArtifactSealError("EVALUATOR_ARTIFACT_PATH_TRAVERSAL", str(path))
    root = _lexical_root(evidence_root)
    if raw.is_absolute():
        absolute = Path(os.path.abspath(raw))
        try:
            relative = absolute.relative_to(root)
        except ValueError as error:
            raise ArtifactSealError(
                "EVALUATOR_ARTIFACT_PATH_ESCAPE", str(path)
            ) from error
    else:
        relative = raw
    if relative in (Path("."), Path("")) or relative.is_absolute():
        raise ArtifactSealError("EVALUATOR_ARTIFACT_PATH_INVALID", str(path))
    if any(part in ("", ".", "..") for part in relative.parts):
        raise ArtifactSealError("EVALUATOR_ARTIFACT_PATH_TRAVERSAL", str(path))
    return PurePosixPath(*relative.parts).as_posix()


def _open_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        code = (
            "EVALUATOR_ARTIFACT_SYMLINK_FORBIDDEN"
            if error.errno in {errno.ELOOP, errno.ENOTDIR}
            else "EVALUATOR_EVIDENCE_ROOT_UNAVAILABLE"
        )
        raise ArtifactSealError(code, str(path)) from error
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise ArtifactSealError("EVALUATOR_EVIDENCE_ROOT_INVALID", str(path))
    return fd


def _open_regular_file(root_fd: int, relative_path: str) -> tuple[int, int, os.stat_result]:
    parts = PurePosixPath(relative_path).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ArtifactSealError("EVALUATOR_ARTIFACT_PATH_TRAVERSAL", relative_path)
    directory_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            except OSError as error:
                code = (
                    "EVALUATOR_ARTIFACT_SYMLINK_FORBIDDEN"
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}
                    else "EVALUATOR_ARTIFACT_UNAVAILABLE"
                )
                raise ArtifactSealError(code, relative_path) from error
            os.close(directory_fd)
            directory_fd = child_fd
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=directory_fd)
        except OSError as error:
            code = (
                "EVALUATOR_ARTIFACT_SYMLINK_FORBIDDEN"
                if error.errno in {errno.ELOOP, errno.ENOTDIR}
                else "EVALUATOR_ARTIFACT_UNAVAILABLE"
            )
            raise ArtifactSealError(code, relative_path) from error
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(file_fd)
            raise ArtifactSealError("EVALUATOR_ARTIFACT_NOT_REGULAR", relative_path)
        # A child-controlled second hard link can preserve inode identity while
        # moving the mutation surface outside the sealed tree.  Reject it.
        if info.st_nlink != 1:
            os.close(file_fd)
            raise ArtifactSealError("EVALUATOR_ARTIFACT_HARDLINK_FORBIDDEN", relative_path)
        return directory_fd, file_fd, info
    except BaseException:
        os.close(directory_fd)
        raise


def _read_one(root_fd: int, relative_path: str) -> tuple[bytes, str, int]:
    parent_fd, file_fd, before = _open_regular_file(root_fd, relative_path)
    try:
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(file_fd)
        try:
            lexical = os.stat(
                PurePosixPath(relative_path).name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ArtifactSealError("EVALUATOR_ARTIFACT_TOCTOU_DETECTED", relative_path) from error
        stable_fields = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if stable_fields != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            lexical.st_dev,
            lexical.st_ino,
            lexical.st_mode,
            lexical.st_nlink,
            lexical.st_size,
            lexical.st_mtime_ns,
            lexical.st_ctime_ns,
        ):
            raise ArtifactSealError("EVALUATOR_ARTIFACT_TOCTOU_DETECTED", relative_path)
        data = b"".join(chunks)
        if len(data) != after.st_size:
            raise ArtifactSealError("EVALUATOR_ARTIFACT_TOCTOU_DETECTED", relative_path)
        return data, digest.hexdigest(), len(data)
    finally:
        os.close(file_fd)
        os.close(parent_fd)


def _validate_roles(role_paths: Mapping[str, str | Path]) -> tuple[tuple[str, str], ...]:
    if not role_paths:
        raise ArtifactSealError("EVALUATOR_ARTIFACT_MANIFEST_EMPTY")
    pairs: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for role, path in role_paths.items():
        if not isinstance(role, str) or not role:
            raise ArtifactSealError("EVALUATOR_ARTIFACT_ROLE_INVALID")
        relative = str(path)
        if relative in seen_paths:
            raise ArtifactSealError("EVALUATOR_ARTIFACT_PATH_DUPLICATE", relative)
        seen_paths.add(relative)
        pairs.append((role, relative))
    return tuple(sorted(pairs))


def collect_manifest(
    evidence_root: str | Path,
    role_paths: Mapping[str, str | Path],
) -> tuple[str, str, tuple[SealedArtifactEntry, ...]]:
    root = _lexical_root(evidence_root)
    normalized = {
        role: relative_artifact_path(path, root)
        for role, path in role_paths.items()
    }
    pairs = _validate_roles(normalized)
    root_fd = _open_directory(root)
    try:
        entries = []
        for role, relative in pairs:
            _, digest, size = _read_one(root_fd, relative)
            entries.append(SealedArtifactEntry(role, relative, digest, size))
    finally:
        os.close(root_fd)
    entries_tuple = tuple(sorted(entries, key=lambda item: (item.role, item.relative_path)))
    payload = {
        "manifest_version": MANIFEST_VERSION,
        "artifacts": [entry.as_json() for entry in entries_tuple],
    }
    manifest_json = canonical_json(payload)
    return manifest_json, canonical_sha256(payload), entries_tuple


def parse_manifest(manifest_json: str, manifest_sha256: str) -> tuple[SealedArtifactEntry, ...]:
    try:
        parsed = json.loads(manifest_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_INVALID") from error
    if canonical_json(parsed) != manifest_json or canonical_sha256(parsed) != manifest_sha256:
        raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_HASH_MISMATCH")
    if not isinstance(parsed, dict) or parsed.get("manifest_version") != MANIFEST_VERSION:
        raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_VERSION_INVALID")
    raw_entries = parsed.get("artifacts")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ArtifactSealError("EVALUATOR_ARTIFACT_MANIFEST_EMPTY")
    entries: list[SealedArtifactEntry] = []
    roles: set[str] = set()
    paths: set[str] = set()
    for item in raw_entries:
        if not isinstance(item, dict) or set(item) != {"role", "relative_path", "sha256", "byte_size"}:
            raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_INVALID")
        role = item["role"]
        relative = item["relative_path"]
        digest = item["sha256"]
        size = item["byte_size"]
        if (
            not isinstance(role, str) or not role
            or not isinstance(relative, str) or not relative
            or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in PurePosixPath(relative).parts)
            or not isinstance(digest, str) or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
            or isinstance(size, bool) or not isinstance(size, int) or size < 0
            or role in roles or relative in paths
        ):
            raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_INVALID")
        roles.add(role)
        paths.add(relative)
        entries.append(SealedArtifactEntry(role, relative, digest, size))
    ordered = tuple(sorted(entries, key=lambda entry: (entry.role, entry.relative_path)))
    if [entry.as_json() for entry in ordered] != raw_entries:
        raise ArtifactSealError("EVALUATOR_SEAL_MANIFEST_NOT_CANONICAL")
    return ordered


def verify_manifest_bytes(
    evidence_root: str | Path,
    manifest_json: str,
    manifest_sha256: str,
) -> VerifiedArtifactManifest:
    root = _lexical_root(evidence_root)
    entries = parse_manifest(manifest_json, manifest_sha256)
    root_fd = _open_directory(root)
    observed: dict[str, bytes] = {}
    try:
        for entry in entries:
            data, digest, size = _read_one(root_fd, entry.relative_path)
            if digest != entry.sha256 or size != entry.byte_size:
                raise ArtifactSealError(
                    "EVALUATOR_SEALED_ARTIFACT_MISMATCH", entry.relative_path
                )
            observed[entry.relative_path] = data
    finally:
        os.close(root_fd)
    return VerifiedArtifactManifest(root, entries, observed)


def discover_regular_files(evidence_root: str | Path) -> tuple[str, ...]:
    """Discover a closed evidence tree without following any symlink."""

    root = _lexical_root(evidence_root)
    if not root.is_dir():
        raise ArtifactSealError("EVALUATOR_EVIDENCE_ROOT_UNAVAILABLE", str(root))
    discovered: list[str] = []

    def walk(directory: Path, relative: PurePosixPath) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise ArtifactSealError("EVALUATOR_EVIDENCE_ROOT_UNAVAILABLE", str(directory)) from error
        for entry in entries:
            child_relative = relative / entry.name
            if entry.is_symlink():
                raise ArtifactSealError(
                    "EVALUATOR_ARTIFACT_SYMLINK_FORBIDDEN", child_relative.as_posix()
                )
            if entry.is_dir(follow_symlinks=False):
                walk(Path(entry.path), child_relative)
            elif entry.is_file(follow_symlinks=False):
                discovered.append(child_relative.as_posix())
            else:
                raise ArtifactSealError(
                    "EVALUATOR_ARTIFACT_NOT_REGULAR", child_relative.as_posix()
                )

    walk(root, PurePosixPath())
    return tuple(sorted(discovered))


def post_execution_roles(
    evidence_root: str | Path,
    *,
    stdout_path: str | Path,
    stderr_path: str | Path,
    result_path: str | Path,
    metadata_path: str | Path,
) -> dict[str, str]:
    root = _lexical_root(evidence_root)
    preferred = {
        "stdout": relative_artifact_path(stdout_path, root),
        "stderr": relative_artifact_path(stderr_path, root),
        "result": relative_artifact_path(result_path, root),
        "runner_metadata": relative_artifact_path(metadata_path, root),
    }
    paths = discover_regular_files(root)
    if not set(preferred.values()).issubset(paths):
        raise ArtifactSealError("EVALUATOR_RUNNER_ARTIFACT_MISSING")
    roles: dict[str, str] = dict(preferred)
    occupied = set(preferred.values())
    for relative in paths:
        if relative not in occupied:
            roles[f"evidence:{relative}"] = relative
    return roles



def legacy_attestation_roles(
    evidence_root: str | Path,
    *,
    stdout_path: str | Path,
    stderr_path: str | Path,
    result_path: str | Path,
) -> dict[str, str]:
    """Build an explicit closed manifest for an already-terminal legacy corpus."""

    root = _lexical_root(evidence_root)
    preferred = {
        "stdout": relative_artifact_path(stdout_path, root),
        "stderr": relative_artifact_path(stderr_path, root),
        "result": relative_artifact_path(result_path, root),
    }
    paths = discover_regular_files(root)
    if not set(preferred.values()).issubset(paths):
        raise ArtifactSealError("EVALUATOR_LEGACY_ARTIFACT_MISSING")
    roles: dict[str, str] = dict(preferred)
    occupied = set(preferred.values())
    for relative in paths:
        if relative not in occupied:
            roles[f"evidence:{relative}"] = relative
    return roles
