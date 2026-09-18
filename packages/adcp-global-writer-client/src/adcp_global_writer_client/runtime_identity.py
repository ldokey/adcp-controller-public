from __future__ import annotations

import ast
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .client import client_build_identity

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_PRODUCT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CLIENT_BUILD = re.compile(
    r"^adcp-global-writer-client@([0-9]+\.[0-9]+\.[0-9]+)"
    r"\+g([0-9a-f]{12})\|source=([0-9a-f]{40})\|artifact=(.+)$"
)
_PRODUCT_BUILD = re.compile(
    r"^product:([A-Za-z0-9][A-Za-z0-9._-]{0,127})@g([0-9a-f]{12})"
    r"\|source=([0-9a-f]{40})\|artifact=(.+)$"
)
RUNTIME_IDENTITY_SCHEMA_VERSION = 3
TRUSTED_PRODUCT_IDENTITY_MODULE = "propertyai_core._global_writer_build_identity"
_TRUSTED_PRODUCT_NAME = "PropertyAI"
_TRUSTED_PRODUCT_IDENTITY_RELATIVE_PATH = Path("propertyai_core/_global_writer_build_identity.py")
_PRODUCT_ROOT_ENV = "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"
_PRODUCT_COMMIT_ENV = "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"
# Startup/deployment authority is snapshotted at module import. Request-level callers cannot reselect it.
_AUTHORIZED_PRODUCT_ROOT_AT_STARTUP = os.environ.get(_PRODUCT_ROOT_ENV)
_EXPECTED_PRODUCT_COMMIT_AT_STARTUP = os.environ.get(_PRODUCT_COMMIT_ENV)
_PROCESS_INCARNATION_PID = os.getpid()
_PROCESS_INCARNATION_ID = secrets.token_hex(32)
_INCARNATION = re.compile(r"^[0-9a-f]{64}$")
AUTHORIZED_IDENTITY_SCHEMA_VERSION = 2
MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNKNOWN = "UNKNOWN"
STALE = "STALE"


class RuntimeIdentityError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class ProductBuildIdentity:
    product_name: str
    product_build_commit: str
    product_build_identity: str
    source_artifact_identity: str


@dataclass(frozen=True)
class _ProductAuthoritySnapshot:
    canonical_root: Path
    identity_path: Path
    expected_commit: str
    product_build_identity: ProductBuildIdentity


@dataclass(frozen=True)
class ProcessAuthorityIdentity:
    pid: int
    process_started_at: str
    incarnation_id: str


class ProcessIdentityVerifier(Protocol):
    def current_process_identity(self) -> ProcessAuthorityIdentity: ...


@dataclass(frozen=True)
class RuntimeIdentity:
    service_code: str
    pid: int
    process_started_at: str
    process_incarnation_id: str
    product_build_commit: str
    product_build_identity: str
    global_writer_client_build: str
    interpreter_or_executable: str
    source_root_or_artifact_identity: str
    identity_generated_at: str
    config_artifact_identity: str | None = None
    schema_version: int = RUNTIME_IDENTITY_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthorizedProductionIdentity:
    service_code: str
    product_build_commit: str
    product_build_identity: str
    global_writer_client_build: str
    source_root_or_artifact_identity: str
    config_artifact_identity: str | None = None
    authorized_at: str | None = None
    schema_version: int = AUTHORIZED_IDENTITY_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    return value


def _require_pid(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "pid")
    return value


def _require_commit(value: Any, field: str) -> str:
    value = _require_text(value, field)
    if _SHA40.fullmatch(value) is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    return value


def _require_artifact_identity(value: Any, field: str) -> str:
    value = _require_text(value, field)
    if value.startswith("source-commit:") and _SHA40.fullmatch(value[14:]):
        return value
    if value.startswith("sha256:") and _SHA64.fullmatch(value[7:]):
        return value
    if value.startswith("wheel-sha256:") and _SHA64.fullmatch(value[13:]):
        return value
    raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)


def _parse_canonical_timestamp(value: Any, field: str) -> datetime:
    text = _require_text(value, field)
    if not text.endswith("+00:00"):
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if text != normalized:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "naive datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _require_client_build(value: Any) -> str:
    value = _require_text(value, "global_writer_client_build")
    match = _CLIENT_BUILD.fullmatch(value)
    if match is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "global_writer_client_build")
    version, prefix, commit, artifact = match.groups()
    artifact = _require_artifact_identity(artifact, "global_writer_client_build.artifact")
    if prefix != commit[:12]:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "global_writer_client_build.prefix")
    if artifact.startswith("source-commit:") and artifact[14:] != commit:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "global_writer_client_build.artifact")
    if not version:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "global_writer_client_build.version")
    return value


def _require_product_build(value: Any, *, commit: str, artifact: str) -> str:
    value = _require_text(value, "product_build_identity")
    match = _PRODUCT_BUILD.fullmatch(value)
    if match is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "product_build_identity")
    name, prefix, embedded_commit, embedded_artifact = match.groups()
    if _PRODUCT_NAME.fullmatch(name) is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "product_build_identity.product")
    embedded_artifact = _require_artifact_identity(embedded_artifact, "product_build_identity.artifact")
    if prefix != embedded_commit[:12] or embedded_commit != commit or embedded_artifact != artifact:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "product_build_identity.binding")
    return value


def _canonical_product_identity(product_name: str, commit: str, artifact: str) -> str:
    if _PRODUCT_NAME.fullmatch(product_name) is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "product_name")
    commit = _require_commit(commit, "product_build_commit")
    artifact = _require_artifact_identity(artifact, "source_artifact_identity")
    return f"product:{product_name}@g{commit[:12]}|source={commit}|artifact={artifact}"


_PRODUCT_IDENTITY_FIELDS = frozenset(
    {
        "PRODUCT_IDENTITY_MODULE",
        "PRODUCT_NAME",
        "PRODUCT_BUILD_COMMIT",
        "SOURCE_ARTIFACT_IDENTITY",
        "PRODUCT_BUILD_IDENTITY",
    }
)


def _product_identity_from_mapping(values: Mapping[str, Any]) -> ProductBuildIdentity:
    if values.get("PRODUCT_IDENTITY_MODULE") != TRUSTED_PRODUCT_IDENTITY_MODULE:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product identity module declaration")
    product_name = values.get("PRODUCT_NAME")
    commit = values.get("PRODUCT_BUILD_COMMIT")
    artifact = values.get("SOURCE_ARTIFACT_IDENTITY")
    declared = values.get("PRODUCT_BUILD_IDENTITY")
    if product_name != _TRUSTED_PRODUCT_NAME:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product build product name")
    try:
        commit = _require_commit(commit, "product_build_commit")
        artifact = _require_artifact_identity(artifact, "source_artifact_identity")
        expected = _canonical_product_identity(product_name, commit, artifact)
        if declared != expected:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "Product build identity declaration")
    except RuntimeIdentityError as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", error.detail) from error
    return ProductBuildIdentity(product_name, commit, expected, artifact)


def _read_product_identity_artifact(path: Path) -> ProductBuildIdentity:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=os.fspath(path), mode="exec")
    except (OSError, UnicodeError, SyntaxError) as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact unreadable") from error
    values: dict[str, Any] = {}
    for index, node in enumerate(tree.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact is not declarative")
        name = node.targets[0].id
        if name not in _PRODUCT_IDENTITY_FIELDS or name in values:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact field mismatch")
        try:
            values[name] = ast.literal_eval(node.value)
        except (ValueError, TypeError) as error:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact value invalid") from error
    if set(values) != _PRODUCT_IDENTITY_FIELDS:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact incomplete")
    return _product_identity_from_mapping(values)


def _seal_product_authority_from_anchor(
    authorized_root: str | Path, expected_commit: str
) -> _ProductAuthoritySnapshot:
    try:
        configured_root = Path(authorized_root).expanduser()
        if not configured_root.is_absolute():
            raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "authorized Product root must be absolute")
        root = configured_root.resolve(strict=True)
    except (OSError, TypeError) as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "authorized Product root unavailable") from error
    if not root.is_dir():
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "authorized Product root is not a directory")
    try:
        expected_commit = _require_commit(expected_commit, "expected_product_build_commit")
    except RuntimeIdentityError as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", error.detail) from error
    lexical_identity_path = root / _TRUSTED_PRODUCT_IDENTITY_RELATIVE_PATH
    try:
        identity_path = lexical_identity_path.resolve(strict=True)
        identity_path.relative_to(root)
    except (OSError, ValueError) as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity path escapes authorized root") from error
    if not identity_path.is_file():
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "trusted Product identity artifact missing")
    identity = _read_product_identity_artifact(identity_path)
    if identity.product_build_commit != expected_commit:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product build commit does not match startup authority")
    if identity.source_artifact_identity != f"source-commit:{expected_commit}":
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product source artifact does not match startup authority")
    return _ProductAuthoritySnapshot(
        canonical_root=root,
        identity_path=identity_path,
        expected_commit=expected_commit,
        product_build_identity=identity,
    )


def _load_product_build_identity_from_anchor(authorized_root: str | Path, expected_commit: str) -> ProductBuildIdentity:
    """Validate a Product authority anchor without changing startup authority."""

    return _seal_product_authority_from_anchor(authorized_root, expected_commit).product_build_identity


def _seal_startup_product_authority() -> tuple[_ProductAuthoritySnapshot | None, str | None]:
    """Resolve Product authority exactly once at module startup; capture never retries it."""

    if _AUTHORIZED_PRODUCT_ROOT_AT_STARTUP is None or _EXPECTED_PRODUCT_COMMIT_AT_STARTUP is None:
        return None, "startup Product authority is not configured"
    try:
        snapshot = _seal_product_authority_from_anchor(
            _AUTHORIZED_PRODUCT_ROOT_AT_STARTUP,
            _EXPECTED_PRODUCT_COMMIT_AT_STARTUP,
        )
    except RuntimeIdentityError as error:
        return None, error.detail or "startup Product authority is invalid"
    return snapshot, None


_STARTUP_PRODUCT_AUTHORITY_SNAPSHOT, _STARTUP_PRODUCT_AUTHORITY_ERROR = _seal_startup_product_authority()


def _load_trusted_product_build_identity() -> ProductBuildIdentity:
    """Return only the immutable startup snapshot; never discover or retry authority here."""

    if _STARTUP_PRODUCT_AUTHORITY_SNAPSHOT is None:
        raise RuntimeIdentityError(
            "RUNTIME_IDENTITY_UNKNOWN",
            _STARTUP_PRODUCT_AUTHORITY_ERROR or "startup Product authority is not ready",
        )
    return _STARTUP_PRODUCT_AUTHORITY_SNAPSHOT.product_build_identity


def _require_incarnation(value: Any, field: str = "process_incarnation_id") -> str:
    value = _require_text(value, field)
    if _INCARNATION.fullmatch(value) is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", field)
    return value


def _current_process_incarnation_id() -> str:
    """Return a process-owned nonce, regenerating after fork when the PID changes."""

    global _PROCESS_INCARNATION_PID, _PROCESS_INCARNATION_ID
    pid = os.getpid()
    if _PROCESS_INCARNATION_PID != pid:
        # Generate and validate first. Only then commit PID + nonce together.
        # A failed CSPRNG call leaves the inherited parent state visibly stale,
        # so the next child call retries instead of reusing the parent nonce.
        new_incarnation_id = _require_incarnation(secrets.token_hex(32))
        _PROCESS_INCARNATION_PID, _PROCESS_INCARNATION_ID = pid, new_incarnation_id
    return _PROCESS_INCARNATION_ID


class LiveOSProcessIdentityVerifier:
    """Current-process authority = self PID + OS start evidence + process-owned nonce."""

    def process_started_at(self, pid: int) -> str:
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "invalid pid")
        try:
            completed = subprocess.run(
                ["ps", "-p", str(pid), "-o", "lstart="],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process evidence unavailable") from error
        raw = completed.stdout.strip()
        if completed.returncode != 0 or not raw:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process not live")
        try:
            parsed = datetime.strptime(raw, "%a %b %d %H:%M:%S %Y").astimezone()
        except ValueError as error:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process start unparseable") from error
        return _timestamp(parsed)

    def current_process_identity(self) -> ProcessAuthorityIdentity:
        pid = _require_pid(os.getpid())
        return ProcessAuthorityIdentity(
            pid=pid,
            process_started_at=self.process_started_at(pid),
            incarnation_id=_current_process_incarnation_id(),
        )


def process_started_at(pid: int) -> str:
    return LiveOSProcessIdentityVerifier().process_started_at(pid)


def installed_global_writer_client_build() -> str:
    identity = client_build_identity()
    commit = _require_commit(identity.source_commit, "client source commit")
    artifact = _require_artifact_identity(identity.artifact_identity, "client artifact identity")
    expected_build_id = f"{identity.package_name}@{identity.version}+g{commit[:12]}"
    if identity.package_name != "adcp-global-writer-client" or identity.build_id != expected_build_id:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "client build metadata inconsistent")
    value = f"{identity.build_id}|source={commit}|artifact={artifact}"
    return _require_client_build(value)


def _validate_product_identity(identity: ProductBuildIdentity) -> ProductBuildIdentity:
    if not isinstance(identity, ProductBuildIdentity):
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product build identity invalid type")
    commit = _require_commit(identity.product_build_commit, "product_build_commit")
    artifact = _require_artifact_identity(identity.source_artifact_identity, "source_artifact_identity")
    _require_product_build(identity.product_build_identity, commit=commit, artifact=artifact)
    if _PRODUCT_NAME.fullmatch(identity.product_name) is None:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "Product build identity product name")
    return identity


def _capture_runtime_identity_with_verifier(
    *,
    service_code: str,
    product_build_identity: ProductBuildIdentity,
    verifier: ProcessIdentityVerifier,
    config_artifact_identity: str | None = None,
    generated_at: datetime | None = None,
) -> RuntimeIdentity:
    service_code = _require_text(service_code, "service_code")
    product = _validate_product_identity(product_build_identity)
    process = verifier.current_process_identity()
    pid = _require_pid(process.pid)
    if pid != os.getpid():
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process identity adapter is not current process")
    started = process.process_started_at
    started_at = _parse_canonical_timestamp(started, "process_started_at")
    incarnation = _require_incarnation(process.incarnation_id)
    generated_value = generated_at or datetime.now(timezone.utc)
    generated = _timestamp(generated_value)
    generated_dt = _parse_canonical_timestamp(generated, "identity_generated_at")
    if generated_dt < started_at:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "identity generated before process start")
    config = None if config_artifact_identity is None else _require_artifact_identity(
        config_artifact_identity, "config_artifact_identity"
    )
    return RuntimeIdentity(
        service_code=service_code,
        pid=pid,
        process_started_at=started,
        process_incarnation_id=incarnation,
        product_build_commit=product.product_build_commit,
        product_build_identity=product.product_build_identity,
        global_writer_client_build=installed_global_writer_client_build(),
        interpreter_or_executable=_require_text(sys.executable, "interpreter_or_executable"),
        source_root_or_artifact_identity=product.source_artifact_identity,
        identity_generated_at=generated,
        config_artifact_identity=config,
    )


def capture_runtime_identity(
    *,
    service_code: str,
    config_artifact_identity: str | None = None,
) -> RuntimeIdentity:
    """Capture current-process identity from fixed Product/build and process authority origins."""

    return _capture_runtime_identity_with_verifier(
        service_code=service_code,
        product_build_identity=_load_trusted_product_build_identity(),
        verifier=LiveOSProcessIdentityVerifier(),
        config_artifact_identity=config_artifact_identity,
    )


def _validate_runtime(identity: RuntimeIdentity) -> RuntimeIdentity:
    if not isinstance(identity, RuntimeIdentity) or identity.schema_version != RUNTIME_IDENTITY_SCHEMA_VERSION:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "runtime identity schema")
    _require_text(identity.service_code, "service_code")
    _require_pid(identity.pid)
    started = _parse_canonical_timestamp(identity.process_started_at, "process_started_at")
    _require_incarnation(identity.process_incarnation_id)
    generated = _parse_canonical_timestamp(identity.identity_generated_at, "identity_generated_at")
    if generated < started:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "identity generated before process start")
    commit = _require_commit(identity.product_build_commit, "product_build_commit")
    artifact = _require_artifact_identity(identity.source_root_or_artifact_identity, "source_root_or_artifact_identity")
    _require_product_build(identity.product_build_identity, commit=commit, artifact=artifact)
    _require_client_build(identity.global_writer_client_build)
    _require_text(identity.interpreter_or_executable, "interpreter_or_executable")
    if identity.config_artifact_identity is not None:
        _require_artifact_identity(identity.config_artifact_identity, "config_artifact_identity")
    return identity


def _validate_authorized(identity: AuthorizedProductionIdentity) -> AuthorizedProductionIdentity:
    if not isinstance(identity, AuthorizedProductionIdentity) or identity.schema_version != AUTHORIZED_IDENTITY_SCHEMA_VERSION:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_INVALID", "authorized identity schema")
    _require_text(identity.service_code, "service_code")
    commit = _require_commit(identity.product_build_commit, "product_build_commit")
    artifact = _require_artifact_identity(identity.source_root_or_artifact_identity, "source_root_or_artifact_identity")
    _require_product_build(identity.product_build_identity, commit=commit, artifact=artifact)
    _require_client_build(identity.global_writer_client_build)
    if identity.config_artifact_identity is not None:
        _require_artifact_identity(identity.config_artifact_identity, "config_artifact_identity")
    if identity.authorized_at is not None:
        _parse_canonical_timestamp(identity.authorized_at, "authorized_at")
    return identity


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _runtime_authority_tuple(identity: RuntimeIdentity) -> tuple[Any, ...]:
    return (
        identity.service_code,
        identity.product_build_commit,
        identity.product_build_identity,
        identity.global_writer_client_build,
        identity.source_root_or_artifact_identity,
        identity.config_artifact_identity,
        identity.schema_version,
    )


def write_runtime_identity(path: str | Path, identity: RuntimeIdentity) -> None:
    try:
        _validate_runtime(identity)
    except RuntimeIdentityError as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", error.detail) from error
    destination = Path(path)
    if destination.exists():
        existing = read_runtime_identity(destination)
        if existing.pid == identity.pid and existing.process_incarnation_id == identity.process_incarnation_id:
            if (
                existing.process_started_at != identity.process_started_at
                or _runtime_authority_tuple(existing) != _runtime_authority_tuple(identity)
            ):
                raise RuntimeIdentityError("RUNTIME_IDENTITY_REBIND_FORBIDDEN", "same process cannot rebind build authority")
            return
    _atomic_write_json(destination, identity.as_dict())


def write_authorized_identity(path: str | Path, identity: AuthorizedProductionIdentity) -> None:
    try:
        _validate_authorized(identity)
    except RuntimeIdentityError as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", error.detail) from error
    _atomic_write_json(Path(path), identity.as_dict())


def _read_json(path: str | Path, kind: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", f"{kind} unreadable") from error
    if not isinstance(payload, dict):
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", f"{kind} invalid")
    return payload


def read_runtime_identity(path: str | Path) -> RuntimeIdentity:
    payload = _read_json(path, "runtime identity")
    try:
        identity = RuntimeIdentity(
            service_code=payload["service_code"],
            pid=payload["pid"],
            process_started_at=payload["process_started_at"],
            process_incarnation_id=payload["process_incarnation_id"],
            product_build_commit=payload["product_build_commit"],
            product_build_identity=payload["product_build_identity"],
            global_writer_client_build=payload["global_writer_client_build"],
            interpreter_or_executable=payload["interpreter_or_executable"],
            source_root_or_artifact_identity=payload["source_root_or_artifact_identity"],
            identity_generated_at=payload["identity_generated_at"],
            config_artifact_identity=payload.get("config_artifact_identity"),
            schema_version=payload["schema_version"],
        )
        return _validate_runtime(identity)
    except (KeyError, TypeError, RuntimeIdentityError) as error:
        detail = error.detail if isinstance(error, RuntimeIdentityError) else "runtime identity invalid"
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", detail) from error


def read_authorized_identity(path: str | Path) -> AuthorizedProductionIdentity:
    payload = _read_json(path, "authorized identity")
    try:
        identity = AuthorizedProductionIdentity(
            service_code=payload["service_code"],
            product_build_commit=payload["product_build_commit"],
            product_build_identity=payload["product_build_identity"],
            global_writer_client_build=payload["global_writer_client_build"],
            source_root_or_artifact_identity=payload["source_root_or_artifact_identity"],
            config_artifact_identity=payload.get("config_artifact_identity"),
            authorized_at=payload.get("authorized_at"),
            schema_version=payload["schema_version"],
        )
        return _validate_authorized(identity)
    except (KeyError, TypeError, RuntimeIdentityError) as error:
        detail = error.detail if isinstance(error, RuntimeIdentityError) else "authorized identity invalid"
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", detail) from error


def compare_runtime_identity(loaded: RuntimeIdentity, authorized: AuthorizedProductionIdentity) -> str:
    try:
        _validate_runtime(loaded)
        _validate_authorized(authorized)
    except RuntimeIdentityError:
        return UNKNOWN
    same = (
        loaded.service_code == authorized.service_code
        and loaded.product_build_commit == authorized.product_build_commit
        and loaded.product_build_identity == authorized.product_build_identity
        and loaded.global_writer_client_build == authorized.global_writer_client_build
        and loaded.source_root_or_artifact_identity == authorized.source_root_or_artifact_identity
        and loaded.config_artifact_identity == authorized.config_artifact_identity
    )
    return MATCH if same else MISMATCH


def _authorize_new_mutation_with_verifier(
    *,
    runtime_identity_path: str | Path,
    authorized_identity_path: str | Path,
    verifier: ProcessIdentityVerifier,
) -> str:
    loaded = read_runtime_identity(runtime_identity_path)
    authorized = read_authorized_identity(authorized_identity_path)
    try:
        current = verifier.current_process_identity()
        current_pid = _require_pid(current.pid)
        if current_pid != os.getpid():
            raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process identity adapter is not current process")
        actual_start = current.process_started_at
        _parse_canonical_timestamp(actual_start, "actual_process_started_at")
        actual_incarnation = _require_incarnation(current.incarnation_id, "actual_process_incarnation_id")
    except RuntimeIdentityError as error:
        if error.code == "RUNTIME_IDENTITY_STALE":
            raise
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "current process identity unavailable") from error
    except Exception as error:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "current process identity unavailable") from error
    if loaded.pid != current_pid:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "runtime identity belongs to a different live process")
    if loaded.process_incarnation_id != actual_incarnation:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "process incarnation mismatch")
    if loaded.process_started_at != actual_start:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "PID/process start mismatch")
    comparison = compare_runtime_identity(loaded, authorized)
    if comparison == UNKNOWN:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_UNKNOWN", "authority identity is malformed")
    if comparison != MATCH:
        raise RuntimeIdentityError("RUNTIME_IDENTITY_MISMATCH")
    return MATCH


def authorize_new_mutation(*, runtime_identity_path: str | Path, authorized_identity_path: str | Path) -> str:
    """Production trust path. No caller-supplied PID/start override is accepted."""

    return _authorize_new_mutation_with_verifier(
        runtime_identity_path=runtime_identity_path,
        authorized_identity_path=authorized_identity_path,
        verifier=LiveOSProcessIdentityVerifier(),
    )


__all__ = [
    "AUTHORIZED_IDENTITY_SCHEMA_VERSION",
    "AuthorizedProductionIdentity",
    "LiveOSProcessIdentityVerifier",
    "MATCH",
    "MISMATCH",
    "ProcessAuthorityIdentity",
    "ProductBuildIdentity",
    "RUNTIME_IDENTITY_SCHEMA_VERSION",
    "RuntimeIdentity",
    "RuntimeIdentityError",
    "STALE",
    "TRUSTED_PRODUCT_IDENTITY_MODULE",
    "UNKNOWN",
    "authorize_new_mutation",
    "capture_runtime_identity",
    "compare_runtime_identity",
    "installed_global_writer_client_build",
    "process_started_at",
    "read_authorized_identity",
    "read_runtime_identity",
    "write_authorized_identity",
    "write_runtime_identity",
]
