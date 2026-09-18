"""Dedicated, typed Production DCS schema-v8 adoption controller.

This is deliberately not the historical Production migration CLI and not a
"migrate to latest" surface.  The public request carries only an operation id;
the canonical DCS, writer inventory sources, service-control authority and exact
v6 -> v7 -> v8 transition are sealed inside this module.

Production invocation is a separately authorized operation.  Importing or
inspecting this module performs no Production mutation.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import sqlite3
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import uuid4

from adcp.dcs_v7_v8_adoption import (
    V7_SCHEMA_PROFILE,
    V8_SCHEMA_PROFILE,
    run_v7_to_v8_adoption,
)
from adcp.production_migration_orchestrator import (
    EXPECTED_WRITER_CODES,
    ExecutionContext,
    ProductionMigrationOrchestrator,
    RuntimeWriter,
)
from adcp.runtime_artifact_attestation import RuntimeArtifactAttestation
from adcp.domain import StoreError, operation_key
from adcp.store.migrations import schema_profile_identity
from adcp.store.sqlite import CANONICAL_PRODUCTION_CONTROL_STORE, ControlStore


CHANGE_ID = "P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01"
HQ_DCS_DECISION = "CHAT.PROJ.HQ:DECISION:PRODUCTION_DCS_V8_ADOPTION_EXECUTION_SURFACE:V1"
TARGET_SCHEMA_VERSION = 8
V6_SCHEMA_PROFILE = "sha256:047dd3c4cb1449bd428c0c8519f2baf29e876a9a96e5427767a577f5d5be94dd"
CANONICAL_DCS_PATH = CANONICAL_PRODUCTION_CONTROL_STORE
CANONICAL_RUNTIME_IDENTITY_ROOT = Path(
    "/Users/kate/DKATE/adcp-runtime/propertyai-global-writer-runtime"
)
CANONICAL_LAUNCH_AGENTS_ROOT = Path.home() / "Library" / "LaunchAgents"
CANONICAL_EVIDENCE_ROOT = Path(
    "/Users/kate/DKATE/adcp-runtime/production-dcs-v8-adoption-evidence"
)
_LAUNCHCTL = Path("/bin/launchctl")
_PS = Path("/bin/ps")
_QUIESCENCE_TIMEOUT_SECONDS = 15.0
_QUIESCENCE_POLL_SECONDS = 0.2
_QUIESCENCE_STABLE_OBSERVATIONS = 2
_ACTIVE_RESUME_TIMEOUT_SECONDS = 15.0
_ACTIVE_RESUME_POLL_SECONDS = 0.2
_ACTIVE_RESUME_STABLE_OBSERVATIONS = 2

# Exact historical identities which remain useful when classifying a deployed
# runtime.  0.3 compatibility is recognized only from an authorized deployed
# runtime identity, never from repository HEAD.
_LEGACY_0_1_SOURCE = "267d79e3122da1eae0233e462326f8d096122d07"
_TRANSITION_0_2_SOURCE = "d535e00b8997e470c45dddc9efb9e8c10e656dbe"
_V9_COMPAT_0_4_SOURCE = "23ce586dd369a60ac7bbbd24b33175deb05a402d"
_V9_COMPAT_0_4_BUILD_ID = "adcp-global-writer-client@0.4.0+g23ce586dd369"
_V9_COMPAT_0_4_CONTRACT = "sha256:1deb066c05c1cfec1b5945e8e2b31bfd212eb80bd4021b0696ee1ee93364a0f6"
# DL-82 Ordered Successor 2: externally accepted exact v0.5 wheel.
_V10_COMPAT_0_5_SOURCE = "4e3bd2691b2ed58eccb65c32ad127467c89a6ebb"
_V10_COMPAT_0_5_BUILD_ID = "adcp-global-writer-client@0.5.0+g4e3bd2691b2e"
_V10_COMPAT_0_5_CONTRACT = "sha256:288a69e75d8bd4399bbac1973a8632d54a79c0052debec79636a184b715db2a5"
_V10_COMPAT_0_5_WHEEL_SHA256 = "365e39886a6169b20d358e3dd331825ef6c8187987055f83cb04fae453e0c61e"
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLIENT_BUILD = re.compile(
    r"^adcp-global-writer-client@(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    r"\+g(?P<short>[0-9a-f]{12})\|source=(?P<source>[0-9a-f]{40})"
    r"\|artifact=(?P<artifact>.+)$"
)
_WRITER_CODE = re.compile(r"PROPERTYAI_(W[0-9]{2})_")
_PROFILE_BY_VERSION = {
    6: V6_SCHEMA_PROFILE,
    7: V7_SCHEMA_PROFILE,
    8: V8_SCHEMA_PROFILE,
}
_STARTUP_PRODUCT_ROOT_ENV = "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"
_STARTUP_PRODUCT_COMMIT_ENV = "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"
_W01_RUNTIME_CONFIG_ENV = "PROPERTYAI_GMAIL_INGEST_CONFIG_PATH"
_W01_CONFIG_TEMPLATE_SENTINEL = "/REPLACE_AT_CUTOVER/propertyai/gmail-ingest-config"
_CUTOVER_SENTINEL = "REPLACE_AT_CUTOVER"
_TRUSTED_PRODUCT_IDENTITY_RELATIVE = Path("propertyai_core/_global_writer_build_identity.py")
_STARTUP_CONFIG_ENV_KEYS = (
    _STARTUP_PRODUCT_ROOT_ENV,
    _STARTUP_PRODUCT_COMMIT_ENV,
    "PROPERTYAI_GLOBAL_WRITER_DCS_PATH",
    "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH",
    "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH",
    _W01_RUNTIME_CONFIG_ENV,
)


class ProductionDcsV8AdoptionError(RuntimeError):
    """Fail-closed controller error carrying only non-secret recovery facts."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        phase: str = "PREFLIGHT",
        schema_version: int | None = None,
        recovery_status: str = "NOT_REQUIRED",
    ) -> None:
        self.code = code
        self.detail = detail
        self.phase = phase
        self.schema_version = schema_version
        self.recovery_status = recovery_status
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class ProductionDcsV8AdoptionRequest:
    """Authority-free request for the one canonical Production v8 adoption."""

    operation_id: str


@dataclass(frozen=True)
class W01StartupPlistMaterialization:
    """Deterministic non-secret readback for one W01 startup plist materialization."""

    staged_plist_path: Path
    staged_plist_sha256: str
    service_config_fingerprint: str
    resolved_config_path: Path


@dataclass(frozen=True)
class DcsWriterClientIdentity:
    package_name: str
    version: str
    build_identity: str
    source_commit: str
    artifact_identity: str
    classification: str
    supported_dcs_schema_versions: tuple[int, ...] | None

    def supports_schema(self, version: int) -> bool:
        return self.supported_dcs_schema_versions is not None and version in self.supported_dcs_schema_versions

    @property
    def supports_v8(self) -> bool:
        return self.supports_schema(8)


@dataclass(frozen=True)
class _AuthorizedThinStartupIdentity:
    version: str
    build_id: str
    source_commit: str
    artifact_identity: str
    thin_contract_format_version: int
    schema_contract_identity: str
    supported_dcs_schema_versions: tuple[int, ...]

    @property
    def client_build_identity(self) -> str:
        return (
            f"{self.build_id}|source={self.source_commit}"
            f"|artifact={self.artifact_identity}"
        )


# External accepted-build anchors for INACTIVE startup attestation.  Product and
# thin-client authority are sealed as exact pairs below; contract facts are never
# accepted from caller configuration or from the startup package being attested.
_CURRENT_AUTHORIZED_PROPERTYAI_SOURCE = "379801b5bbb68549ebdb1dbf12621c6ad38b7652"
_PRODUCTION_AUTHORIZED_PROPERTYAI_SOURCE = "1496d9ea5f4b91df2958d948970e859f790fa7f5"
_DL95_RECOVERY_AUTHORIZED_PROPERTYAI_SOURCE = "45dafdcbaecd32a929d4b2a87bc9ec3eb5548af4"
_DL98_CUTOVER_AUTHORIZED_PROPERTYAI_SOURCE = "9e50c7306752961f18ee4d0ef0ecb5a7f0dea6c7"
_DL98_WORKER_AUTHORIZED_PROPERTYAI_SOURCE = "ebd7f756e35610c3ce5a8e33e71fc610e3c84f00"
_TELEGRAM_T1_W07_PREDECESSOR_PROPERTYAI_SOURCE = (
    "1ab6715b413d5befe1e93c7628efe49f9d6e76c2"
)
_TELEGRAM_T1_W07_AUTHORIZED_PROPERTYAI_SOURCE = (
    "f90303f95cf4df772c7a89dd90cf589fa6620f27"
)
_TELEGRAM_T1_W07_SERVICE_CODE = "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"
_ROLLBACK_AUTHORIZED_PROPERTYAI_SOURCE = "e9adb4f3635e3b13aa22f674487f589befdbbd41"
_AUTHORIZED_THIN_STARTUP = _AuthorizedThinStartupIdentity(
    version="0.3.0",
    build_id="adcp-global-writer-client@0.3.0+geb06cb8a8c4f",
    source_commit="eb06cb8a8c4f6a0a1534b9bd9d5c49cec54fe79c",
    artifact_identity="source-commit:eb06cb8a8c4f6a0a1534b9bd9d5c49cec54fe79c",
    thin_contract_format_version=2,
    schema_contract_identity=(
        "sha256:b5601f47b0447e5ad47a7a1d5cee7d20692c96b5105b925ed71cd4ddfe98ba6b"
    ),
    supported_dcs_schema_versions=(6, 7, 8),
)
_AUTHORIZED_THIN_STARTUP_V9 = _AuthorizedThinStartupIdentity(
    version="0.4.0",
    build_id=_V9_COMPAT_0_4_BUILD_ID,
    source_commit=_V9_COMPAT_0_4_SOURCE,
    artifact_identity=f"source-commit:{_V9_COMPAT_0_4_SOURCE}",
    thin_contract_format_version=2,
    schema_contract_identity=_V9_COMPAT_0_4_CONTRACT,
    supported_dcs_schema_versions=(6, 7, 8, 9),
)
_AUTHORIZED_THIN_STARTUP_V10 = _AuthorizedThinStartupIdentity(
    version="0.5.0",
    build_id=_V10_COMPAT_0_5_BUILD_ID,
    source_commit=_V10_COMPAT_0_5_SOURCE,
    artifact_identity=f"source-commit:{_V10_COMPAT_0_5_SOURCE}",
    thin_contract_format_version=2,
    schema_contract_identity=_V10_COMPAT_0_5_CONTRACT,
    supported_dcs_schema_versions=(6, 7, 8, 9, 10),
)
_AUTHORIZED_W07_INACTIVE_STARTUP_BY_IDENTITY = {
    (
        "W07",
        _TELEGRAM_T1_W07_SERVICE_CODE,
        _TELEGRAM_T1_W07_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        "W07",
        _TELEGRAM_T1_W07_SERVICE_CODE,
        _TELEGRAM_T1_W07_PREDECESSOR_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
}
_AUTHORIZED_INACTIVE_STARTUP_BY_PRODUCT_AND_BUILD = {
    (
        _DL98_WORKER_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        _DL98_CUTOVER_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        _DL95_RECOVERY_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        _PRODUCTION_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        _PRODUCTION_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V9.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V9,
    (
        _CURRENT_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V10,
    (
        _ROLLBACK_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP,
    (
        _CURRENT_AUTHORIZED_PROPERTYAI_SOURCE,
        _AUTHORIZED_THIN_STARTUP_V9.client_build_identity,
    ): _AUTHORIZED_THIN_STARTUP_V9,
}


@dataclass(frozen=True)
class DcsWriterStartupResolution:
    """Mutation-free identity that an INACTIVE writer would use on its next real start."""

    writer_id: str
    service_label: str
    service_config_fingerprint: str
    active_state: str
    resolved_propertyai_release: Path
    resolved_propertyai_source_commit: str
    python_executable: Path
    environment_path: Path
    thin_client_version: str
    thin_client_build_id: str
    thin_client_source_commit: str
    thin_client_artifact_identity: str
    thin_contract_format_version: int
    thin_client_schema_contract_identity: str
    supported_dcs_schema_versions: tuple[int, ...]

    @property
    def client_build_identity(self) -> str:
        return (
            f"{self.thin_client_build_id}|source={self.thin_client_source_commit}"
            f"|artifact={self.thin_client_artifact_identity}"
        )

    @property
    def stable_identity(self) -> tuple[str, ...]:
        return (
            self.writer_id,
            self.service_label,
            self.service_config_fingerprint,
            os.fspath(self.resolved_propertyai_release),
            self.resolved_propertyai_source_commit,
            os.fspath(self.python_executable),
            os.fspath(self.environment_path),
            self.thin_client_version,
            self.thin_client_build_id,
            self.thin_client_source_commit,
            self.thin_client_artifact_identity,
            str(self.thin_contract_format_version),
            self.thin_client_schema_contract_identity,
            ",".join(str(value) for value in self.supported_dcs_schema_versions),
        )


@dataclass(frozen=True)
class DcsWriterInventoryEntry:
    writer_id: str
    launchd_label: str
    service_code: str
    runtime_identity_path: Path
    authorized_identity_path: Path
    pid: int | None
    process_incarnation_id: str
    product_build_commit: str
    product_build_identity: str
    source_root_or_artifact_identity: str
    client: DcsWriterClientIdentity
    state: str
    service_config_fingerprint: str = ""
    authority_source: str = "LIVE_RUNTIME_IDENTITY"
    startup_resolution: DcsWriterStartupResolution | None = None
    last_runtime_identity_fingerprint: str | None = None
    before_class: str = "LEGACY_UNCLASSIFIED"
    autonomous_write_capable: bool = False
    invocation_only: bool = False
    runtime_state: str = "UNRESOLVED"
    load_state: str = "UNRESOLVED"
    enabled_state: str = "UNRESOLVED"
    plist_path: Path | None = None
    plist_realpath: Path | None = None
    plist_sha256: str = ""
    program_arguments: tuple[str, ...] = ()
    run_at_load_present: bool = False
    run_at_load_value: Any = None
    start_interval_present: bool = False
    start_interval_value: Any = None
    keep_alive_present: bool = False
    keep_alive_value: Any = None
    working_directory: str | None = None
    scheduler_config_fingerprint: str = ""
    dcs_binding: str = ""

    @property
    def stable_identity(self) -> tuple[str, ...]:
        return (
            self.writer_id,
            self.launchd_label,
            self.service_code,
            self.product_build_commit,
            self.product_build_identity,
            self.source_root_or_artifact_identity,
            self.client.build_identity,
            self.service_config_fingerprint,
            os.fspath(self.plist_path) if self.plist_path is not None else "",
            os.fspath(self.plist_realpath) if self.plist_realpath is not None else "",
            self.plist_sha256,
            "\0".join(self.program_arguments),
            self.scheduler_config_fingerprint,
            self.working_directory or "",
            self.dcs_binding,
        )


@dataclass(frozen=True)
class DcsWriterInventory:
    entries: tuple[DcsWriterInventoryEntry, ...]
    fingerprint: str

    @property
    def all_support_v8(self) -> bool:
        return bool(self.entries) and all(entry.client.supports_v8 for entry in self.entries)


@dataclass(frozen=True)
class _LaunchdRuntimeEvidence:
    """Read-only runtime evidence; enable/load authority is intentionally separate."""

    launchd_declared_state: str | None
    pid_field: int | None
    pid_liveness: bool
    pid_service_ownership: bool
    runtime_state: str
    load_state: str
    pid_probe_resolved: bool

    @property
    def stale_pid(self) -> bool:
        return (
            self.runtime_state == "INACTIVE"
            and self.pid_field is not None
            and not (self.pid_liveness and self.pid_service_ownership)
        )


@dataclass(frozen=True)
class _DcsProfile:
    version: int
    schema_profile_identity: str
    integrity_check: str
    foreign_key_violations: int


@dataclass(frozen=True)
class _QuiescenceToken:
    before: DcsWriterInventory
    quiesced_stable_identities: tuple[tuple[str, ...], ...]
    before_classes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ProductionDcsV8AdoptionResult:
    operation_id: str
    previous_version: int
    version: int
    status: str
    migration_versions: tuple[int, ...]
    writer_inventory_fingerprint: str
    writer_count: int
    writer_client_identities: tuple[str, ...]
    all_resumed_writers_support_v8: bool
    runtime_client_compatibility_rollout_required: bool
    final_w08_state: str
    schema_profile_identity: str


class _WriterAuthority(Protocol):
    def discover(self) -> DcsWriterInventory: ...
    def quiesce(self, inventory: DcsWriterInventory) -> _QuiescenceToken: ...
    def verify_quiesced(self, token: _QuiescenceToken) -> None: ...
    def resume(self, token: _QuiescenceToken) -> None: ...
    def verify_resumed(self, token: _QuiescenceToken) -> DcsWriterInventory: ...


class _MigrationAuthority(Protocol):
    def run_v6_to_v7(self, path: Path, inventory: DcsWriterInventory) -> None: ...
    def run_v7_to_v8(self, path: Path) -> None: ...


class _HeldW08LeaseAuthority(Protocol):
    fencing_token: int

    def assert_current(self) -> int: ...
    def reopen_exact_schema(self, version: int) -> int: ...
    def release(self) -> Mapping[str, Any]: ...
    def close(self) -> None: ...


class _W08LeaseAuthority(Protocol):
    def acquire(
        self, path: Path, request: ProductionDcsV8AdoptionRequest
    ) -> _HeldW08LeaseAuthority: ...


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_json(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_WRITER_IDENTITY_UNREADABLE", path.name
        ) from error
    if not isinstance(value, dict):
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_IDENTITY_INVALID", path.name)
    return value


def _require_absolute_plain_file(path: Path, *, code: str) -> None:
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise ProductionDcsV8AdoptionError(code, path.name) from error
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ProductionDcsV8AdoptionError(code, path.name)
    if stat_result.st_mode & 0o022:
        raise ProductionDcsV8AdoptionError(code, f"unsafe-mode:{path.name}")


def _require_absolute_regular_file_allow_symlink(path: Path, *, code: str) -> None:
    if not path.is_absolute():
        raise ProductionDcsV8AdoptionError(code, path.name)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ProductionDcsV8AdoptionError(code, path.name) from error
    if not resolved.is_file():
        raise ProductionDcsV8AdoptionError(code, path.name)


def _read_literal_assignments(
    path: Path, names: Sequence[str], *, code: str, require_all: bool = True
) -> Mapping[str, Any]:
    _require_absolute_plain_file(path, code=code)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=os.fspath(path), mode="exec")
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ProductionDcsV8AdoptionError(code, path.name) from error
    wanted = set(names)
    values: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name not in wanted:
            continue
        try:
            values[name] = ast.literal_eval(node.value)
        except (ValueError, TypeError) as error:
            raise ProductionDcsV8AdoptionError(code, f"{path.name}:{name}") from error
    if require_all and set(values) != wanted:
        missing = ",".join(sorted(wanted - set(values)))
        raise ProductionDcsV8AdoptionError(code, f"{path.name}:{missing}")
    return values


def _scheduler_field(document: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return {"present": key in document, "value": document.get(key)}


def _scheduler_config_material(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "RunAtLoad": _scheduler_field(document, "RunAtLoad"),
        "StartInterval": _scheduler_field(document, "StartInterval"),
        "KeepAlive": _scheduler_field(document, "KeepAlive"),
    }


def _scheduler_config_fingerprint(document: Mapping[str, Any]) -> str:
    return "sha256:" + _hash(_scheduler_config_material(document))


def _scheduled_autonomous_write_capable(document: Mapping[str, Any]) -> bool:
    run_at_load = document.get("RunAtLoad") is True
    start_interval = document.get("StartInterval")
    scheduled = isinstance(start_interval, int) and not isinstance(start_interval, bool) and start_interval > 0
    keep_alive = document.get("KeepAlive")
    keep_alive_capable = keep_alive is True or (isinstance(keep_alive, Mapping) and bool(keep_alive))
    return run_at_load or scheduled or keep_alive_capable


def _service_config_fingerprint(document: Mapping[str, Any]) -> str:
    environment = document.get("EnvironmentVariables") or {}
    if not isinstance(environment, Mapping):
        environment = {}
    material = {
        "Label": document.get("Label"),
        "ProgramArguments": document.get("ProgramArguments"),
        "WorkingDirectory": document.get("WorkingDirectory"),
        "EnvironmentVariables": {key: environment.get(key) for key in _STARTUP_CONFIG_ENV_KEYS},
        "Scheduler": _scheduler_config_material(document),
    }
    return "sha256:" + _hash(material)


def _validated_w01_runtime_config_path(
    environment: Mapping[str, Any], *, code: str
) -> Path:
    raw = environment.get(_W01_RUNTIME_CONFIG_ENV)
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise ProductionDcsV8AdoptionError(code, "missing-or-malformed")
    if _CUTOVER_SENTINEL in raw:
        raise ProductionDcsV8AdoptionError(code, "cutover-placeholder")
    try:
        path = Path(raw)
    except (TypeError, ValueError) as error:
        raise ProductionDcsV8AdoptionError(code, "malformed-path") from error
    # Raw input itself must be absolute.  No expanduser/user-home fallback is allowed.
    if not path.is_absolute():
        raise ProductionDcsV8AdoptionError(code, "not-absolute")
    try:
        if path.is_symlink():
            raise ProductionDcsV8AdoptionError(code, "symlink-forbidden")
        resolved = path.resolve(strict=True)
    except ProductionDcsV8AdoptionError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ProductionDcsV8AdoptionError(code, "unresolvable") from error
    if not resolved.is_file():
        raise ProductionDcsV8AdoptionError(code, "not-file")
    return resolved


def materialize_w01_startup_plist(
    source_plist_path: str | Path,
    staged_plist_path: str | Path,
    *,
    runtime_environment: Mapping[str, str],
) -> W01StartupPlistMaterialization:
    """Materialize W01 cutover/runtime inputs and verify exact staged-plist readback.

    This is a staging-only function.  It does not touch LaunchAgents, launchctl,
    Production DCS, runtime identities, packages, or processes.
    """

    code = "PRODUCTION_DCS_W01_PLIST_MATERIALIZATION_INVALID"
    source = Path(source_plist_path)
    staged = Path(staged_plist_path)
    _require_absolute_plain_file(source, code=code)
    if not staged.is_absolute() or staged == source:
        raise ProductionDcsV8AdoptionError(code, "staged-path-invalid")
    try:
        if staged.exists() and staged.is_symlink():
            raise ProductionDcsV8AdoptionError(code, "staged-symlink-forbidden")
        parent = staged.parent.resolve(strict=True)
    except ProductionDcsV8AdoptionError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ProductionDcsV8AdoptionError(code, "staged-parent-invalid") from error
    if not parent.is_dir():
        raise ProductionDcsV8AdoptionError(code, "staged-parent-invalid")

    try:
        document = plistlib.loads(source.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise ProductionDcsV8AdoptionError(code, "source-plist-invalid") from error
    if not isinstance(document, dict) or document.get("Label") != "com.propertyai.gmail-readonly":
        raise ProductionDcsV8AdoptionError(code, "source-plist-not-w01")
    source_environment = document.get("EnvironmentVariables")
    if not isinstance(source_environment, dict):
        raise ProductionDcsV8AdoptionError(code, "source-environment-invalid")
    if source_environment.get(_W01_RUNTIME_CONFIG_ENV) != _W01_CONFIG_TEMPLATE_SENTINEL:
        raise ProductionDcsV8AdoptionError(code, "source-config-sentinel-invalid")

    allowed_keys = set(source_environment) | set(_STARTUP_CONFIG_ENV_KEYS)
    supplied_keys = set(runtime_environment)
    unexpected = supplied_keys - allowed_keys
    if unexpected:
        raise ProductionDcsV8AdoptionError(code, "unexpected-runtime-key")
    placeholder_keys = {
        key
        for key, value in source_environment.items()
        if isinstance(value, str) and _CUTOVER_SENTINEL in value
    }
    required_keys = placeholder_keys | set(_STARTUP_CONFIG_ENV_KEYS)
    if not required_keys.issubset(supplied_keys):
        raise ProductionDcsV8AdoptionError(code, "required-runtime-key-missing")
    if any(
        not isinstance(value, str) or not value or value != value.strip()
        for value in runtime_environment.values()
    ):
        raise ProductionDcsV8AdoptionError(code, "runtime-value-malformed")

    resolved_config = _validated_w01_runtime_config_path(runtime_environment, code=code)
    release_raw = runtime_environment.get(_STARTUP_PRODUCT_ROOT_ENV)
    commit = runtime_environment.get(_STARTUP_PRODUCT_COMMIT_ENV)
    if not isinstance(release_raw, str) or not Path(release_raw).is_absolute():
        raise ProductionDcsV8AdoptionError(code, "release-root-not-absolute")
    try:
        release = Path(release_raw).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise ProductionDcsV8AdoptionError(code, "release-root-unresolvable") from error
    if not release.is_dir():
        raise ProductionDcsV8AdoptionError(code, "release-root-not-directory")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ProductionDcsV8AdoptionError(code, "product-commit-invalid")
    for key in (
        "PROPERTYAI_GLOBAL_WRITER_DCS_PATH",
        "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH",
        "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH",
    ):
        raw = runtime_environment.get(key)
        if not isinstance(raw, str) or not Path(raw).is_absolute():
            raise ProductionDcsV8AdoptionError(code, f"{key}:not-absolute")

    materialized_environment = dict(source_environment)
    materialized_environment.update(runtime_environment)
    if any(
        isinstance(value, str) and _CUTOVER_SENTINEL in value
        for value in materialized_environment.values()
    ):
        raise ProductionDcsV8AdoptionError(code, "cutover-placeholder-remains")
    materialized = dict(document)
    materialized["WorkingDirectory"] = os.fspath(release)
    materialized["EnvironmentVariables"] = materialized_environment
    materialized_bytes = plistlib.dumps(materialized, fmt=plistlib.FMT_XML, sort_keys=True)
    try:
        staged.write_bytes(materialized_bytes)
        readback_bytes = staged.read_bytes()
        readback = plistlib.loads(readback_bytes)
    except (OSError, plistlib.InvalidFileException) as error:
        raise ProductionDcsV8AdoptionError(code, "staged-readback-failed") from error
    if readback_bytes != materialized_bytes or not isinstance(readback, dict):
        raise ProductionDcsV8AdoptionError(code, "staged-readback-drift")
    readback_environment = readback.get("EnvironmentVariables")
    if not isinstance(readback_environment, Mapping):
        raise ProductionDcsV8AdoptionError(code, "staged-environment-invalid")
    readback_config = _validated_w01_runtime_config_path(readback_environment, code=code)
    if readback_config != resolved_config:
        raise ProductionDcsV8AdoptionError(code, "staged-config-readback-drift")
    if readback.get("WorkingDirectory") != os.fspath(release):
        raise ProductionDcsV8AdoptionError(code, "staged-working-directory-drift")
    return W01StartupPlistMaterialization(
        staged_plist_path=staged,
        staged_plist_sha256=hashlib.sha256(readback_bytes).hexdigest(),
        service_config_fingerprint=_service_config_fingerprint(readback),
        resolved_config_path=resolved_config,
    )


def _metadata_name_version(path: Path) -> tuple[str, str]:
    _require_absolute_plain_file(path, code="PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED", path.name
        ) from error
    fields: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"Name", "Version"} and key not in fields:
            fields[key] = value.strip()
    if set(fields) != {"Name", "Version"}:
        raise ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED", path.name
        )
    return fields["Name"], fields["Version"]


def _parse_client_identity(build: object) -> DcsWriterClientIdentity:
    if not isinstance(build, str) or not build:
        return DcsWriterClientIdentity(
            "adcp-global-writer-client", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", None
        )
    match = _CLIENT_BUILD.fullmatch(build)
    if match is None:
        classification = "SOURCE_TREE_OR_VENDORED" if "source-tree" in build.lower() else "UNKNOWN"
        return DcsWriterClientIdentity(
            "adcp-global-writer-client", "UNKNOWN", build, "UNKNOWN", "UNKNOWN", classification, None
        )
    version = match.group("version")
    source = match.group("source")
    artifact = match.group("artifact")
    if artifact != f"source-commit:{source}":
        return DcsWriterClientIdentity(
            "adcp-global-writer-client", version, build, source, artifact, "VENDORED_OR_NONCANONICAL", None
        )
    if version == "0.1.0" and source == _LEGACY_0_1_SOURCE:
        supported: tuple[int, ...] | None = (6,)
        classification = "LEGACY_0_1_EXACT"
    elif version == "0.2.0" and source == _TRANSITION_0_2_SOURCE:
        supported = (6, 7)
        classification = "TRANSITION_0_2_EXACT"
    elif version == "0.3.0":
        # This fact is bound to the deployed runtime identity below, not inferred
        # from source HEAD.  0.3.0 is the accepted exact {6,7,8} thin-client line.
        supported = (6, 7, 8)
        classification = "V8_0_3_DEPLOYED_EXACT"
    elif (
        version == "0.4.0"
        and source == _V9_COMPAT_0_4_SOURCE
        and match.group("short") == source[:12]
    ):
        # Metadata identifies the accepted 0.4 contract line only.  Artifact-byte
        # trust for schema 9 is supplied by fresh RuntimeArtifactAttestation.
        supported = (6, 7, 8, 9)
        classification = "V9_0_4_METADATA_EXACT"
    elif (
        version == "0.5.0"
        and source == _V10_COMPAT_0_5_SOURCE
        and match.group("short") == source[:12]
    ):
        supported = (6, 7, 8, 9, 10)
        classification = "V10_0_5_METADATA_EXACT"
    else:
        supported = None
        classification = "OTHER"
    return DcsWriterClientIdentity(
        "adcp-global-writer-client", version, build, source, artifact, classification, supported
    )


def _authorized_runtime_match(runtime: Mapping[str, Any], authorized: Mapping[str, Any]) -> bool:
    fields = (
        "service_code",
        "product_build_commit",
        "product_build_identity",
        "global_writer_client_build",
        "source_root_or_artifact_identity",
        "config_artifact_identity",
    )
    return all(runtime.get(field) == authorized.get(field) for field in fields)


def _inventory_fingerprint(entries: Sequence[DcsWriterInventoryEntry]) -> str:
    material = [
        {
            "stable": entry.stable_identity,
            "state": entry.state,
            "pid": entry.pid,
            "incarnation": entry.process_incarnation_id,
        }
        for entry in sorted(entries, key=lambda item: item.writer_id)
    ]
    return "sha256:" + _hash(material)


def _stable_inventory_fingerprint(entries: Sequence[DcsWriterInventoryEntry]) -> str:
    return "sha256:" + _hash(
        [entry.stable_identity for entry in sorted(entries, key=lambda item: item.writer_id)]
    )


def _executable_matches(actual: str, expected: str) -> bool:
    try:
        return (
            Path(actual).expanduser().resolve(strict=False)
            == Path(expected).expanduser().resolve(strict=False)
        )
    except (OSError, RuntimeError):
        return actual == expected


def _service_command_matches(command: str, expected_arguments: Sequence[str]) -> bool:
    try:
        actual = shlex.split(command)
    except ValueError as error:
        raise RuntimeError("process command line malformed") from error
    expected = tuple(expected_arguments)
    return (
        len(actual) == len(expected)
        and bool(expected)
        and _executable_matches(actual[0], expected[0])
        and tuple(actual[1:]) == expected[1:]
    )


def _probe_service_process(pid: int, expected_arguments: Sequence[str]) -> tuple[bool, bool]:
    """Return (live, service-owned) from read-only process evidence.

    A PID is service-owned only when its live command line matches the launchd
    ProgramArguments for the expected service.  Any inspection ambiguity raises
    so callers can classify the runtime UNRESOLVED instead of guessing.
    """

    if pid <= 0 or not expected_arguments:
        return False, False
    try:
        result = subprocess.run(
            [str(_PS), "-ww", "-p", str(pid), "-o", "state=", "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("process inspection failed") from error
    if result.returncode == 1 or not result.stdout.strip():
        return False, False
    if result.returncode != 0:
        raise RuntimeError("process inspection unresolved")
    observed = result.stdout.strip().split(None, 1)
    if len(observed) != 2:
        raise RuntimeError("process inspection malformed")
    process_state, command = observed
    if process_state.upper().startswith("Z"):
        return False, False
    return True, _service_command_matches(command, expected_arguments)


def _scan_service_processes(expected_arguments: Sequence[str]) -> tuple[int, ...]:
    """Return every live PID whose command exactly matches ProgramArguments."""

    expected = tuple(expected_arguments)
    if not expected:
        raise RuntimeError("service process scan missing expected arguments")
    try:
        result = subprocess.run(
            [str(_PS), "-ww", "-axo", "pid=,state=,command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("service process scan failed") from error
    if result.returncode != 0:
        raise RuntimeError("service process scan unresolved")

    matches: list[int] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        observed = line.split(None, 2)
        if len(observed) != 3:
            raise RuntimeError("service process scan malformed")
        pid_raw, process_state, command = observed
        try:
            pid = int(pid_raw)
        except ValueError as error:
            raise RuntimeError("service process scan malformed pid") from error
        if pid <= 0 or process_state.upper().startswith("Z"):
            continue
        # Avoid parsing arbitrary unrelated command lines.  If the executable is
        # a possible match, require the same exact argv comparison as PID probing.
        lexical_executable = command.split(None, 1)[0]
        if not _executable_matches(lexical_executable, expected[0]):
            continue
        if _service_command_matches(command, expected):
            matches.append(pid)
    return tuple(sorted(set(matches)))


def _entry_before_class(entry: DcsWriterInventoryEntry) -> str:
    if entry.before_class in {"A", "B", "C", "D"}:
        return entry.before_class
    return "A" if entry.state == "ACTIVE" else "C"


def _inactive_startup_authority_changed(
    before: DcsWriterInventory, after: DcsWriterInventory
) -> bool:
    previous = {entry.writer_id: entry for entry in before.entries}
    current = {entry.writer_id: entry for entry in after.entries}
    if set(previous) != set(current):
        return False
    for writer_id, old in previous.items():
        new = current[writer_id]
        if old.state != "INACTIVE" or new.state != "INACTIVE":
            continue
        if old.service_config_fingerprint != new.service_config_fingerprint:
            return True
        if old.startup_resolution is None or new.startup_resolution is None:
            if old.startup_resolution != new.startup_resolution:
                return True
            continue
        if old.startup_resolution.stable_identity != new.startup_resolution.stable_identity:
            return True
    return False


class _LaunchdWriterAuthority:
    """Exact launchd authority derived only from canonical writer service metadata."""

    def __init__(
        self,
        *,
        dcs_path: Path = CANONICAL_DCS_PATH,
        launch_agents_root: Path = CANONICAL_LAUNCH_AGENTS_ROOT,
        runtime_root: Path = CANONICAL_RUNTIME_IDENTITY_ROOT,
        uid: int | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        process_probe: Callable[[int, Sequence[str]], tuple[bool, bool]] = _probe_service_process,
        process_scan: Callable[[Sequence[str]], Sequence[int]] = _scan_service_processes,
        sleep: Callable[[float], None] = time.sleep,
        runtime_artifact_attestation: (
            Callable[[DcsWriterInventoryEntry, int], RuntimeArtifactAttestation] | None
        ) = None,
    ) -> None:
        self.dcs_path = dcs_path.expanduser().resolve(strict=False)
        self.launch_agents_root = launch_agents_root.expanduser().resolve(strict=False)
        self.runtime_root = runtime_root.expanduser().resolve(strict=False)
        self.uid = os.getuid() if uid is None else uid
        self.runner = runner
        self.process_probe = process_probe
        self.process_scan = process_scan
        self.sleep = sleep
        self.runtime_artifact_attestation = runtime_artifact_attestation
        # Entries are added only after this controller has successfully issued a
        # start for an ACTIVE_BEFORE writer.  Generic discover() remains strict;
        # this marker only selects the bounded transition gate before that proof.
        self._active_resume_pending: dict[str, DcsWriterInventoryEntry] = {}

    def _launchctl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.runner(
            [str(_LAUNCHCTL), *args], capture_output=True, text=True, check=False, timeout=5.0
        )

    def _enabled_state(self, label: str) -> str:
        """Read the per-user launchd disabled override as typed authority."""
        result = self._launchctl("print-disabled", f"gui/{self.uid}")
        if result.returncode != 0:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", label
            )

        output = result.stdout
        if output.count("{") != 1 or output.count("}") != 1:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", label
            )
        map_start = output.find("{")
        map_end = output.find("}")
        if map_end <= map_start or output[map_end + 1 :].strip():
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", label
            )

        escaped_label = re.escape(label)
        label_token = rf"(?:\"{escaped_label}\"|'{escaped_label}'|{escaped_label})"
        exact_label = re.compile(
            rf"(?<![A-Za-z0-9_.-]){label_token}(?![A-Za-z0-9_.-])"
        )
        if len(exact_label.findall(output)) != 1:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", label
            )

        entry = re.compile(
            rf"^[ \t]*{label_token}[ \t]*=>[ \t]*"
            rf"(?P<token>(?i:enabled|disabled|true|false))[ \t]*$",
            re.MULTILINE,
        )
        matches = [
            match.group("token").lower()
            for match in entry.finditer(output[map_start + 1 : map_end])
        ]
        if len(matches) != 1:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", label
            )
        return {
            "enabled": "ENABLED",
            "disabled": "DISABLED",
            "false": "ENABLED",
            "true": "DISABLED",
        }[matches[0]]

    def _launch_state(
        self, label: str, expected_arguments: Sequence[str]
    ) -> _LaunchdRuntimeEvidence:
        result = self._launchctl("print", f"gui/{self.uid}/{label}")
        state_match = re.search(r"(?m)^\s*state = (.+?)\s*$", result.stdout)
        declared_state = state_match.group(1).strip().lower() if state_match is not None else None
        pid_match = re.search(r"(?m)^\s*pid = ([0-9]+)\s*$", result.stdout)
        pid_field = int(pid_match.group(1)) if pid_match is not None else None

        pid_liveness = False
        pid_service_ownership = False
        probe_resolved = pid_field is None
        if pid_field is not None:
            try:
                pid_liveness, pid_service_ownership = self.process_probe(
                    pid_field, tuple(expected_arguments)
                )
                pid_liveness = bool(pid_liveness)
                pid_service_ownership = bool(pid_liveness and pid_service_ownership)
                probe_resolved = True
            except Exception:
                probe_resolved = False

        known_not_loaded = (
            result.returncode == 113
            and (
                "not loaded" in result.stderr.lower()
                or "could not find service" in result.stderr.lower()
                or "could not find service" in result.stdout.lower()
            )
        )
        if known_not_loaded:
            load_state = "UNLOADED"
        elif result.returncode == 0:
            load_state = "LOADED"
        else:
            load_state = "UNRESOLVED"
        if not probe_resolved:
            runtime_state = "UNRESOLVED"
        elif result.returncode != 0:
            if pid_liveness and pid_service_ownership:
                runtime_state = "INCONSISTENT"
            elif known_not_loaded:
                runtime_state = "INACTIVE"
            else:
                runtime_state = "UNRESOLVED"
        elif declared_state == "running":
            runtime_state = (
                "ACTIVE"
                if pid_field is not None and pid_liveness and pid_service_ownership
                else "UNRESOLVED"
            )
        elif declared_state in {"inactive", "not running"}:
            runtime_state = (
                "INCONSISTENT" if pid_liveness and pid_service_ownership else "INACTIVE"
            )
        else:
            runtime_state = "UNRESOLVED"

        return _LaunchdRuntimeEvidence(
            launchd_declared_state=declared_state,
            pid_field=pid_field,
            pid_liveness=pid_liveness,
            pid_service_ownership=pid_service_ownership,
            runtime_state=runtime_state,
            load_state=load_state,
            pid_probe_resolved=probe_resolved,
        )

    def _resolve_inactive_startup_authority(
        self,
        *,
        document: Mapping[str, Any],
        writer_id: str,
        label: str,
    ) -> DcsWriterStartupResolution:
        code = "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED"
        environment = document.get("EnvironmentVariables") or {}
        if not isinstance(environment, Mapping):
            raise ProductionDcsV8AdoptionError(code, writer_id)
        release_raw = environment.get(_STARTUP_PRODUCT_ROOT_ENV)
        source_commit = environment.get(_STARTUP_PRODUCT_COMMIT_ENV)
        if not isinstance(release_raw, str) or not release_raw or not isinstance(source_commit, str):
            raise ProductionDcsV8AdoptionError(code, writer_id)
        if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            raise ProductionDcsV8AdoptionError(code, writer_id)
        release_lexical = Path(release_raw).expanduser()
        if not release_lexical.is_absolute():
            raise ProductionDcsV8AdoptionError(code, writer_id)
        try:
            release = release_lexical.resolve(strict=True)
        except OSError as error:
            raise ProductionDcsV8AdoptionError(code, writer_id) from error
        if not release.is_dir():
            raise ProductionDcsV8AdoptionError(code, writer_id)
        working_directory = document.get("WorkingDirectory")
        if not isinstance(working_directory, str):
            raise ProductionDcsV8AdoptionError(code, writer_id)
        try:
            if Path(working_directory).expanduser().resolve(strict=True) != release:
                raise ProductionDcsV8AdoptionError(code, writer_id)
        except OSError as error:
            raise ProductionDcsV8AdoptionError(code, writer_id) from error

        product_values = _read_literal_assignments(
            release / _TRUSTED_PRODUCT_IDENTITY_RELATIVE,
            (
                "PRODUCT_IDENTITY_MODULE",
                "PRODUCT_NAME",
                "PRODUCT_BUILD_COMMIT",
                "SOURCE_ARTIFACT_IDENTITY",
                "PRODUCT_BUILD_IDENTITY",
            ),
            code=code,
        )
        product_artifact = f"source-commit:{source_commit}"
        expected_product_identity = (
            f"product:PropertyAI@g{source_commit[:12]}|source={source_commit}|artifact={product_artifact}"
        )
        if (
            product_values.get("PRODUCT_IDENTITY_MODULE") != "propertyai_core._global_writer_build_identity"
            or product_values.get("PRODUCT_NAME") != "PropertyAI"
            or product_values.get("PRODUCT_BUILD_COMMIT") != source_commit
            or product_values.get("SOURCE_ARTIFACT_IDENTITY") != product_artifact
            or product_values.get("PRODUCT_BUILD_IDENTITY") != expected_product_identity
        ):
            raise ProductionDcsV8AdoptionError(code, writer_id)

        arguments = document.get("ProgramArguments")
        if (
            not isinstance(arguments, list)
            or not arguments
            or any(not isinstance(value, str) or not value for value in arguments)
        ):
            raise ProductionDcsV8AdoptionError(code, writer_id)
        python_executable = Path(arguments[0]).expanduser()
        _require_absolute_regular_file_allow_symlink(python_executable, code=code)
        environment_path = python_executable.parent.parent
        if not environment_path.is_absolute() or not environment_path.is_dir():
            raise ProductionDcsV8AdoptionError(code, writer_id)
        site_packages = [
            candidate
            for candidate in sorted((environment_path / "lib").glob("python*/site-packages"))
            if (candidate / "adcp_global_writer_client").is_dir()
        ]
        if len(site_packages) != 1:
            raise ProductionDcsV8AdoptionError(code, writer_id)
        site = site_packages[0]
        dist_infos = sorted(site.glob("adcp_global_writer_client-*.dist-info"))
        if len(dist_infos) != 1 or not dist_infos[0].is_dir():
            raise ProductionDcsV8AdoptionError(code, writer_id)
        metadata_name, metadata_version = _metadata_name_version(dist_infos[0] / "METADATA")

        package_root = site / "adcp_global_writer_client"
        build_values = _read_literal_assignments(
            package_root / "_build_identity.py",
            (
                "CLIENT_PACKAGE_NAME",
                "CLIENT_VERSION",
                "SOURCE_COMMIT",
                "BUILD_ID",
                "ARTIFACT_IDENTITY",
                "EXPECTED_THIN_CONTRACT_FORMAT_VERSION",
                "EXPECTED_SCHEMA_CONTRACT_IDENTITY",
            ),
            code=code,
        )
        optional_build = _read_literal_assignments(
            package_root / "_build_identity.py",
            ("EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS",),
            code=code,
            require_all=False,
        )
        package_name = build_values.get("CLIENT_PACKAGE_NAME")
        version = build_values.get("CLIENT_VERSION")
        client_source = build_values.get("SOURCE_COMMIT")
        build_id = build_values.get("BUILD_ID")
        artifact = build_values.get("ARTIFACT_IDENTITY")
        if (
            package_name != "adcp-global-writer-client"
            or metadata_name != "adcp-global-writer-client"
            or not isinstance(version, str)
            or metadata_version != version
            or not isinstance(client_source, str)
            or re.fullmatch(r"[0-9a-f]{40}", client_source) is None
            or build_id != f"adcp-global-writer-client@{version}+g{client_source[:12]}"
            or artifact != f"source-commit:{client_source}"
        ):
            raise ProductionDcsV8AdoptionError(code, writer_id)

        schema_values = _read_literal_assignments(
            package_root / "_schema_contract.py",
            (
                "THIN_CONTRACT_FORMAT_VERSION",
                "SCHEMA_CONTRACT_IDENTITY",
                "SUPPORTED_DCS_SCHEMA_VERSIONS",
                "SCHEMA_CONTRACT_VERSION",
            ),
            code=code,
            require_all=False,
        )
        thin_contract_format_version = schema_values.get("THIN_CONTRACT_FORMAT_VERSION")
        schema_identity = schema_values.get("SCHEMA_CONTRACT_IDENTITY")
        supported_raw = schema_values.get("SUPPORTED_DCS_SCHEMA_VERSIONS")
        if supported_raw is None:
            legacy_version = schema_values.get("SCHEMA_CONTRACT_VERSION")
            supported_raw = (legacy_version,) if isinstance(legacy_version, int) else None
        if (
            not isinstance(thin_contract_format_version, int)
            or isinstance(thin_contract_format_version, bool)
            or thin_contract_format_version <= 0
            or build_values.get("EXPECTED_THIN_CONTRACT_FORMAT_VERSION")
            != thin_contract_format_version
            or not isinstance(schema_identity, str)
            or build_values.get("EXPECTED_SCHEMA_CONTRACT_IDENTITY") != schema_identity
            or not isinstance(supported_raw, (tuple, list))
            or not supported_raw
            or any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in supported_raw)
        ):
            raise ProductionDcsV8AdoptionError(code, writer_id)
        supported = tuple(supported_raw)
        declared_supported = optional_build.get("EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS")
        if declared_supported is not None and tuple(declared_supported) != supported:
            raise ProductionDcsV8AdoptionError(code, writer_id)

        return DcsWriterStartupResolution(
            writer_id=writer_id,
            service_label=label,
            service_config_fingerprint=_service_config_fingerprint(document),
            active_state="INACTIVE",
            resolved_propertyai_release=release,
            resolved_propertyai_source_commit=source_commit,
            python_executable=python_executable,
            environment_path=environment_path,
            thin_client_version=version,
            thin_client_build_id=str(build_id),
            thin_client_source_commit=client_source,
            thin_client_artifact_identity=str(artifact),
            thin_contract_format_version=thin_contract_format_version,
            thin_client_schema_contract_identity=schema_identity,
            supported_dcs_schema_versions=supported,
        )

    @staticmethod
    def _startup_matches_authorized(
        startup: DcsWriterStartupResolution, authorized: Mapping[str, Any], service_code: str
    ) -> bool:
        source = startup.resolved_propertyai_source_commit
        artifact = f"source-commit:{source}"
        product = f"product:PropertyAI@g{source[:12]}|source={source}|artifact={artifact}"
        authorized_build = authorized.get("global_writer_client_build")
        thin = None
        if isinstance(authorized_build, str):
            thin = _AUTHORIZED_W07_INACTIVE_STARTUP_BY_IDENTITY.get(
                (startup.writer_id, service_code, source, authorized_build)
            )
            if thin is None:
                thin = _AUTHORIZED_INACTIVE_STARTUP_BY_PRODUCT_AND_BUILD.get(
                    (source, authorized_build)
                )
        w07_identity_shape_valid = (
            service_code != _TELEGRAM_T1_W07_SERVICE_CODE
            or (
                authorized.get("schema_version") == 2
                and authorized.get("config_artifact_identity") is None
            )
        )
        return (
            thin is not None
            and w07_identity_shape_valid
            and authorized.get("service_code") == service_code
            and authorized.get("product_build_commit") == source
            and authorized.get("product_build_identity") == product
            and authorized.get("source_root_or_artifact_identity") == artifact
            and startup.client_build_identity == thin.client_build_identity
            and startup.thin_client_version == thin.version
            and startup.thin_client_build_id == thin.build_id
            and startup.thin_client_source_commit == thin.source_commit
            and startup.thin_client_artifact_identity == thin.artifact_identity
            and startup.thin_contract_format_version == thin.thin_contract_format_version
            and startup.thin_client_schema_contract_identity == thin.schema_contract_identity
            and startup.supported_dcs_schema_versions == thin.supported_dcs_schema_versions
        )

    @staticmethod
    def _physical_before_class(
        *, runtime_state: str, load_state: str, enabled_state: str,
        autonomous_write_capable: bool, writer_id: str,
    ) -> str:
        if runtime_state == "ACTIVE":
            if load_state != "LOADED" or enabled_state != "ENABLED":
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_PHYSICAL_STATE_INCONSISTENT", writer_id
                )
            return "A"
        if runtime_state != "INACTIVE":
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_PHYSICAL_STATE_UNRESOLVED", writer_id
            )
        if load_state == "LOADED" and enabled_state == "ENABLED" and autonomous_write_capable:
            return "B"
        if load_state == "UNLOADED" and enabled_state == "DISABLED":
            return "C"
        raise ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_WRITER_PHYSICAL_STATE_AMBIGUOUS", writer_id
        )

    @staticmethod
    def _baseline_kwargs(
        *, document: Mapping[str, Any], plist_path: Path, arguments: Sequence[str],
        runtime_evidence: _LaunchdRuntimeEvidence, enabled_state: str,
        before_class: str, raw_dcs: str,
    ) -> Mapping[str, Any]:
        try:
            frozen_bytes = plist_path.read_bytes()
            frozen_document = plistlib.loads(frozen_bytes)
            frozen_realpath = plist_path.resolve(strict=True)
        except (OSError, plistlib.InvalidFileException) as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_SERVICE_DEFINITION_INVALID", plist_path.name
            ) from error
        if (
            not isinstance(frozen_document, Mapping)
            or frozen_document.get("Label") != document.get("Label")
            or _service_config_fingerprint(frozen_document) != _service_config_fingerprint(document)
            or tuple(frozen_document.get("ProgramArguments") or ()) != tuple(arguments)
        ):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", str(document.get("Label") or "")
            )
        scheduler = _scheduler_config_material(frozen_document)
        return {
            "before_class": before_class,
            "autonomous_write_capable": _scheduled_autonomous_write_capable(frozen_document),
            "invocation_only": False,
            "runtime_state": runtime_evidence.runtime_state,
            "load_state": runtime_evidence.load_state,
            "enabled_state": enabled_state,
            # Keep the lexical path separate from its strict target.  Resolving the
            # path here would erase symlink-retarget evidence.
            "plist_path": plist_path,
            "plist_realpath": frozen_realpath,
            "plist_sha256": hashlib.sha256(frozen_bytes).hexdigest(),
            "program_arguments": tuple(arguments),
            "run_at_load_present": bool(scheduler["RunAtLoad"]["present"]),
            "run_at_load_value": scheduler["RunAtLoad"]["value"],
            "start_interval_present": bool(scheduler["StartInterval"]["present"]),
            "start_interval_value": scheduler["StartInterval"]["value"],
            "keep_alive_present": bool(scheduler["KeepAlive"]["present"]),
            "keep_alive_value": scheduler["KeepAlive"]["value"],
            "working_directory": document.get("WorkingDirectory") if isinstance(document.get("WorkingDirectory"), str) else None,
            "scheduler_config_fingerprint": _scheduler_config_fingerprint(document),
            "dcs_binding": os.fspath(Path(raw_dcs).expanduser().resolve(strict=False)),
        }

    def discover(self) -> DcsWriterInventory:
        entries: list[DcsWriterInventoryEntry] = []
        if not self.launch_agents_root.is_dir():
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_SERVICE_ROOT_UNAVAILABLE")
        for plist_path in sorted(self.launch_agents_root.glob("com.propertyai*.plist")):
            try:
                document = plistlib.loads(plist_path.read_bytes())
            except (OSError, plistlib.InvalidFileException) as error:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_SERVICE_DEFINITION_INVALID", plist_path.name
                ) from error
            environment = document.get("EnvironmentVariables") or {}
            if not isinstance(environment, Mapping):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_SERVICE_DEFINITION_INVALID", plist_path.name
                )
            raw_dcs = environment.get("PROPERTYAI_GLOBAL_WRITER_DCS_PATH")
            if not isinstance(raw_dcs, str):
                continue
            if Path(raw_dcs).expanduser().resolve(strict=False) != self.dcs_path:
                continue
            label = document.get("Label")
            runtime_raw = environment.get("PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH")
            authorized_raw = environment.get("PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH")
            if not all(isinstance(value, str) and value for value in (label, runtime_raw, authorized_raw)):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_SERVICE_IDENTITY_BINDING_MISSING", plist_path.name
                )
            runtime_path = Path(str(runtime_raw)).expanduser()
            authorized_path = Path(str(authorized_raw)).expanduser()
            if not runtime_path.is_absolute():
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID", runtime_path.name
                )
            _require_absolute_plain_file(
                authorized_path, code="PRODUCTION_DCS_WRITER_AUTHORIZED_IDENTITY_INVALID"
            )
            try:
                runtime_path.resolve(strict=False).relative_to(self.runtime_root)
            except ValueError as error:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_OUTSIDE_AUTHORITY_ROOT", runtime_path.name
                ) from error
            authorized = _safe_json(authorized_path)
            service_code = authorized.get("service_code")
            if not isinstance(service_code, str):
                raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_SERVICE_CODE_INVALID")
            match = _WRITER_CODE.search(service_code)
            if match is None:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_SERVICE_CODE_INVALID", service_code
                )
            writer_id = match.group(1)
            if runtime_path.name != f"{writer_id}.runtime.json":
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_RUNTIME_PATH_IDENTITY_MISMATCH", writer_id
                )
            if writer_id == "W01":
                _validated_w01_runtime_config_path(
                    environment, code="PRODUCTION_DCS_W01_STARTUP_CONFIG_INVALID"
                )
            arguments = document.get("ProgramArguments")
            if (
                not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(value, str) or not value for value in arguments)
            ):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_SERVICE_DEFINITION_INVALID", writer_id
                )
            runtime_evidence = self._launch_state(str(label), tuple(arguments))
            if runtime_evidence.runtime_state == "UNRESOLVED":
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_RUNTIME_STATE_UNRESOLVED", writer_id
                )
            if runtime_evidence.runtime_state == "INCONSISTENT":
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_RUNTIME_STATE_INCONSISTENT", writer_id
                )
            state = runtime_evidence.runtime_state
            enabled_state = self._enabled_state(str(label))
            autonomous = _scheduled_autonomous_write_capable(document)
            before_class = self._physical_before_class(
                runtime_state=state,
                load_state=runtime_evidence.load_state,
                enabled_state=enabled_state,
                autonomous_write_capable=autonomous,
                writer_id=writer_id,
            )
            launch_pid = runtime_evidence.pid_field if state == "ACTIVE" else None
            config_fingerprint = _service_config_fingerprint(document)
            baseline_kwargs = self._baseline_kwargs(
                document=document,
                plist_path=plist_path,
                arguments=tuple(arguments),
                runtime_evidence=runtime_evidence,
                enabled_state=enabled_state,
                before_class=before_class,
                raw_dcs=raw_dcs,
            )

            if state == "ACTIVE":
                _require_absolute_plain_file(
                    runtime_path, code="PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID"
                )
                runtime = _safe_json(runtime_path)
                if not _authorized_runtime_match(runtime, authorized):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_RUNTIME_AUTHORITY_MISMATCH", str(label)
                    )
                runtime_pid = runtime.get("pid")
                if runtime_pid != launch_pid:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_PROCESS_IDENTITY_MISMATCH", writer_id
                    )
                client = _parse_client_identity(runtime.get("global_writer_client_build"))
                fields = {
                    "process_incarnation_id": runtime.get("process_incarnation_id"),
                    "product_build_commit": runtime.get("product_build_commit"),
                    "product_build_identity": runtime.get("product_build_identity"),
                    "source_root_or_artifact_identity": runtime.get("source_root_or_artifact_identity"),
                }
                if any(not isinstance(value, str) or not value for value in fields.values()):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID", writer_id
                    )
                entry = DcsWriterInventoryEntry(
                    writer_id=writer_id,
                    launchd_label=str(label),
                    service_code=service_code,
                    runtime_identity_path=runtime_path,
                    authorized_identity_path=authorized_path,
                    pid=launch_pid,
                    process_incarnation_id=str(fields["process_incarnation_id"]),
                    product_build_commit=str(fields["product_build_commit"]),
                    product_build_identity=str(fields["product_build_identity"]),
                    source_root_or_artifact_identity=str(fields["source_root_or_artifact_identity"]),
                    client=client,
                    state=state,
                    service_config_fingerprint=config_fingerprint,
                    authority_source="LIVE_RUNTIME_IDENTITY",
                    last_runtime_identity_fingerprint="sha256:" + _hash(runtime),
                    **baseline_kwargs,
                )
            else:
                last_runtime: Mapping[str, Any] | None = None
                if runtime_path.exists():
                    _require_absolute_plain_file(
                        runtime_path, code="PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID"
                    )
                    last_runtime = _safe_json(runtime_path)
                startup = self._resolve_inactive_startup_authority(
                    document=document, writer_id=writer_id, label=str(label)
                )
                if not self._startup_matches_authorized(startup, authorized, service_code):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", writer_id
                    )
                # Close the intra-attestation race as well as the controller's
                # cross-attestation race: neither activation nor sealed service
                # config/authorized-identity drift may occur while resolution is read.
                try:
                    confirmed_document = plistlib.loads(plist_path.read_bytes())
                except (OSError, plistlib.InvalidFileException) as error:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                    ) from error
                if (
                    not isinstance(confirmed_document, Mapping)
                    or _service_config_fingerprint(confirmed_document)
                    != startup.service_config_fingerprint
                    or _hash(_safe_json(authorized_path)) != _hash(authorized)
                ):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                    )
                try:
                    confirmed_startup = self._resolve_inactive_startup_authority(
                        document=confirmed_document, writer_id=writer_id, label=str(label)
                    )
                except ProductionDcsV8AdoptionError as error:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                    ) from error
                if confirmed_startup.stable_identity != startup.stable_identity:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                    )
                confirmed_arguments = confirmed_document.get("ProgramArguments")
                if (
                    not isinstance(confirmed_arguments, list)
                    or not confirmed_arguments
                    or any(not isinstance(value, str) or not value for value in confirmed_arguments)
                ):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                    )
                confirmed_runtime = self._launch_state(str(label), tuple(confirmed_arguments))
                confirmed_enabled = self._enabled_state(str(label))
                if (
                    confirmed_runtime.runtime_state != "INACTIVE"
                    or confirmed_runtime.load_state != runtime_evidence.load_state
                    or confirmed_enabled != enabled_state
                    or _service_config_fingerprint(confirmed_document) != config_fingerprint
                ):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_INVENTORY_CHANGED", writer_id
                    )
                client = _parse_client_identity(startup.client_build_identity)
                if client.supported_dcs_schema_versions != startup.supported_dcs_schema_versions:
                    client = DcsWriterClientIdentity(
                        package_name="adcp-global-writer-client",
                        version=startup.thin_client_version,
                        build_identity=startup.client_build_identity,
                        source_commit=startup.thin_client_source_commit,
                        artifact_identity=startup.thin_client_artifact_identity,
                        classification="STARTUP_RESOLVED_EXACT",
                        supported_dcs_schema_versions=startup.supported_dcs_schema_versions,
                    )
                incarnation = (
                    last_runtime.get("process_incarnation_id") if last_runtime is not None else None
                )
                if not isinstance(incarnation, str) or not incarnation:
                    incarnation = "INACTIVE"
                source = startup.resolved_propertyai_source_commit
                artifact = f"source-commit:{source}"
                entry = DcsWriterInventoryEntry(
                    writer_id=writer_id,
                    launchd_label=str(label),
                    service_code=service_code,
                    runtime_identity_path=runtime_path,
                    authorized_identity_path=authorized_path,
                    pid=None,
                    process_incarnation_id=incarnation,
                    product_build_commit=source,
                    product_build_identity=(
                        f"product:PropertyAI@g{source[:12]}|source={source}|artifact={artifact}"
                    ),
                    source_root_or_artifact_identity=artifact,
                    client=client,
                    state="INACTIVE",
                    service_config_fingerprint=startup.service_config_fingerprint,
                    authority_source="FRESH_STARTUP_RESOLUTION",
                    startup_resolution=startup,
                    last_runtime_identity_fingerprint=(
                        "sha256:" + _hash(last_runtime) if last_runtime is not None else None
                    ),
                    **baseline_kwargs,
                )
            entries.append(entry)
        writer_ids = [entry.writer_id for entry in entries]
        labels = [entry.launchd_label for entry in entries]
        if not entries:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_INVENTORY_EMPTY")
        if len(writer_ids) != len(set(writer_ids)) or len(labels) != len(set(labels)):
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_INVENTORY_DUPLICATE")
        ordered = tuple(sorted(entries, key=lambda item: item.writer_id))
        return DcsWriterInventory(ordered, _inventory_fingerprint(ordered))

    def _service_definition_for_entry(
        self, entry: DcsWriterInventoryEntry, *, phase: str = "QUIESCENCE"
    ) -> tuple[Path, tuple[str, ...]]:
        code = "PRODUCTION_DCS_WRITER_IDENTITY_CHANGED_DURING_QUIESCENCE"
        if phase == "RECOVERY":
            code = "PRODUCTION_DCS_WRITER_RESTORE_PLIST_AUTHORITY_DRIFT"
        frozen_path = entry.plist_path
        frozen_realpath = entry.plist_realpath
        if (
            frozen_path is None
            or frozen_realpath is None
            or not _HEX_SHA256.fullmatch(entry.plist_sha256)
            or not entry.service_config_fingerprint
            or not entry.program_arguments
        ):
            raise ProductionDcsV8AdoptionError(
                code, entry.writer_id, phase=phase, recovery_status=(
                    "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                )
            )

        matches: list[tuple[Path, Path, str, str, tuple[str, ...]]] = []
        for plist_path in sorted(self.launch_agents_root.glob("com.propertyai*.plist")):
            try:
                raw = plist_path.read_bytes()
                document = plistlib.loads(raw)
                realpath = plist_path.resolve(strict=True)
            except (OSError, plistlib.InvalidFileException) as error:
                # If this is the frozen lexical path, missing/invalid bytes are
                # themselves authority drift. Other unrelated malformed plists
                # retain the existing fail-closed inventory behavior.
                if plist_path == frozen_path:
                    raise ProductionDcsV8AdoptionError(
                        code, entry.writer_id, phase=phase, recovery_status=(
                            "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                        )
                    ) from error
                raise ProductionDcsV8AdoptionError(
                    code, entry.writer_id, phase=phase, recovery_status=(
                        "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                    )
                ) from error
            if not isinstance(document, Mapping) or document.get("Label") != entry.launchd_label:
                continue
            arguments = document.get("ProgramArguments")
            if (
                not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(value, str) or not value for value in arguments)
            ):
                raise ProductionDcsV8AdoptionError(
                    code, entry.writer_id, phase=phase, recovery_status=(
                        "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                    )
                )
            matches.append(
                (
                    plist_path,
                    realpath,
                    hashlib.sha256(raw).hexdigest(),
                    _service_config_fingerprint(document),
                    tuple(arguments),
                )
            )
        if len(matches) != 1:
            raise ProductionDcsV8AdoptionError(
                code, entry.writer_id, phase=phase, recovery_status=(
                    "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                )
            )
        current_path, current_realpath, current_sha, current_config, current_arguments = matches[0]
        if (
            current_path != frozen_path
            or current_realpath != frozen_realpath
            or current_sha != entry.plist_sha256
            or current_config != entry.service_config_fingerprint
            or current_arguments != entry.program_arguments
        ):
            raise ProductionDcsV8AdoptionError(
                code, entry.writer_id, phase=phase, recovery_status=(
                    "RECOVERY_REQUIRED" if phase == "RECOVERY" else "NOT_REQUIRED"
                )
            )
        return frozen_path, current_arguments

    @staticmethod
    def _runtime_identity_pid_for_diagnostics(entry: DcsWriterInventoryEntry) -> int | None:
        try:
            value = json.loads(entry.runtime_identity_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(value, Mapping):
            return None
        pid = value.get("pid")
        return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None

    def _transition_evidence_detail(
        self,
        entry: DcsWriterInventoryEntry,
        stage: str,
        evidence: _LaunchdRuntimeEvidence | None,
        *,
        service_owned_live_pids: Sequence[int] | None = None,
    ) -> str:
        return _canonical_json(
            {
                "writer_code": entry.writer_id,
                "transition_stage": stage,
                "launchd_declared_state": (
                    evidence.launchd_declared_state if evidence is not None else None
                ),
                "launchd_pid": evidence.pid_field if evidence is not None else None,
                "pid_live": evidence.pid_liveness if evidence is not None else None,
                "pid_service_owned": (
                    evidence.pid_service_ownership if evidence is not None else None
                ),
                "runtime_identity_pid": self._runtime_identity_pid_for_diagnostics(entry),
                "load_state": evidence.load_state if evidence is not None else None,
                "service_owned_live_pids": (
                    list(service_owned_live_pids)
                    if service_owned_live_pids is not None
                    else None
                ),
                "timestamp": time.time(),
            }
        )

    def _wait_for_stable_nonrunning(
        self,
        transitions: Sequence[tuple[DcsWriterInventoryEntry, tuple[str, ...]]],
        *,
        deadline: float,
        assert_current: Callable[[], Any] | None = None,
        assert_event_guard: Callable[[], Any] | None = None,
    ) -> None:
        stable_observations = 0
        last_unstable: tuple[DcsWriterInventoryEntry, _LaunchdRuntimeEvidence] | None = None
        while True:
            cycle_stable = True
            cycle_unstable: tuple[DcsWriterInventoryEntry, _LaunchdRuntimeEvidence] | None = None
            for entry, arguments in transitions:
                if assert_current is not None:
                    assert_current()
                if assert_event_guard is not None:
                    assert_event_guard()
                _plist_path, observed_arguments = self._service_definition_for_entry(entry)
                if tuple(observed_arguments) != tuple(arguments):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_IDENTITY_CHANGED_DURING_QUIESCENCE",
                        entry.writer_id, phase="QUIESCENCE",
                    )
                enabled_state = self._enabled_state(entry.launchd_label)
                evidence = self._launch_state(entry.launchd_label, arguments)
                if enabled_state != "DISABLED":
                    cycle_stable = False
                    cycle_unstable = (entry, evidence)
                    continue
                if evidence.runtime_state == "ACTIVE":
                    # ACTIVE is allowed only as a bounded transition observation.
                    # _launch_state already proved the reported PID is live and
                    # service-owned; generic discover() remains strictly PID-bound.
                    cycle_stable = False
                    cycle_unstable = (entry, evidence)
                    continue
                if evidence.runtime_state == "INACTIVE":
                    if evidence.load_state == "UNLOADED":
                        try:
                            service_owned_live_pids = tuple(self.process_scan(arguments))
                        except Exception as error:
                            raise ProductionDcsV8AdoptionError(
                                "PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT",
                                self._transition_evidence_detail(
                                    entry, "PROCESS_SCAN_UNRESOLVED", evidence
                                ),
                                phase="QUIESCENCE",
                            ) from error
                        if service_owned_live_pids:
                            raise ProductionDcsV8AdoptionError(
                                "PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT",
                                self._transition_evidence_detail(
                                    entry,
                                    "STABILIZE_ORPHAN_PROCESS",
                                    evidence,
                                    service_owned_live_pids=service_owned_live_pids,
                                ),
                                phase="QUIESCENCE",
                            )
                        continue
                    # A loaded-but-inactive service is not yet a completed bootout.
                    cycle_stable = False
                    cycle_unstable = (entry, evidence)
                    continue
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT",
                    self._transition_evidence_detail(entry, "STABILIZE", evidence),
                    phase="QUIESCENCE",
                )

            last_unstable = cycle_unstable
            stable_observations = stable_observations + 1 if cycle_stable else 0
            if stable_observations >= _QUIESCENCE_STABLE_OBSERVATIONS:
                return
            if time.monotonic() >= deadline:
                if last_unstable is None:
                    entry, arguments = transitions[0]
                    evidence = self._launch_state(entry.launchd_label, arguments)
                else:
                    entry, evidence = last_unstable
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_QUIESCENCE_TIMEOUT",
                    self._transition_evidence_detail(entry, "STABILIZE_TIMEOUT", evidence),
                    phase="QUIESCENCE",
                )
            self.sleep(_QUIESCENCE_POLL_SECONDS)

    def _active_resume_error(
        self,
        entry: DcsWriterInventoryEntry,
        stage: str,
        evidence: _LaunchdRuntimeEvidence | None,
        *,
        code: str = "PRODUCTION_DCS_WRITER_ACTIVE_RESUME_INCONSISTENT",
        service_owned_live_pids: Sequence[int] | None = None,
    ) -> ProductionDcsV8AdoptionError:
        return ProductionDcsV8AdoptionError(
            code,
            self._transition_evidence_detail(
                entry,
                stage,
                evidence,
                service_owned_live_pids=service_owned_live_pids,
            ),
            phase="ACTIVE_RESUME",
            recovery_status="RECOVERY_REQUIRED",
        )

    def _observe_active_resume_entry(
        self,
        entry: DcsWriterInventoryEntry,
        arguments: Sequence[str],
        *,
        prior_process_pids: set[int],
    ) -> tuple[bool, tuple[int, str] | None, _LaunchdRuntimeEvidence, tuple[int, ...]]:
        """Return one fresh transition observation without weakening discover()."""

        evidence = self._launch_state(entry.launchd_label, arguments)
        if evidence.load_state != "LOADED":
            raise self._active_resume_error(entry, "LOAD_STATE_NOT_LOADED", evidence)

        # A loaded service can be briefly inactive after a successful kickstart.
        # It is transition evidence only when no live wrong/unknown PID is present.
        if evidence.runtime_state == "INACTIVE":
            if evidence.pid_field is not None and (
                not evidence.pid_probe_resolved
                or (evidence.pid_liveness and not evidence.pid_service_ownership)
            ):
                raise self._active_resume_error(
                    entry, "INACTIVE_PROCESS_OWNERSHIP_UNSAFE", evidence
                )
            return False, None, evidence, ()
        if evidence.runtime_state != "ACTIVE":
            stage = (
                "PROCESS_OWNERSHIP_UNRESOLVED"
                if evidence.pid_field is not None and not evidence.pid_probe_resolved
                else "LAUNCHD_ACTIVE_STATE_UNSAFE"
            )
            raise self._active_resume_error(entry, stage, evidence)
        if (
            evidence.pid_field is None
            or not evidence.pid_liveness
            or not evidence.pid_service_ownership
            or not evidence.pid_probe_resolved
        ):
            raise self._active_resume_error(entry, "PROCESS_OWNERSHIP_UNSAFE", evidence)

        launch_pid = evidence.pid_field
        try:
            service_owned_live_pids = tuple(sorted(set(int(pid) for pid in self.process_scan(arguments))))
        except Exception as error:
            raise self._active_resume_error(
                entry, "PROCESS_SCAN_UNRESOLVED", evidence
            ) from error
        if service_owned_live_pids != (launch_pid,):
            raise self._active_resume_error(
                entry,
                "SERVICE_PROCESS_SET_INCONSISTENT",
                evidence,
                service_owned_live_pids=service_owned_live_pids,
            )

        runtime_path = entry.runtime_identity_path
        if not runtime_path.exists():
            return False, None, evidence, service_owned_live_pids
        _require_absolute_plain_file(
            runtime_path, code="PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID"
        )
        runtime = _safe_json(runtime_path)
        _require_absolute_plain_file(
            entry.authorized_identity_path,
            code="PRODUCTION_DCS_WRITER_AUTHORIZED_IDENTITY_INVALID",
        )
        authorized = _safe_json(entry.authorized_identity_path)
        if not _authorized_runtime_match(runtime, authorized):
            raise self._active_resume_error(
                entry,
                "RUNTIME_AUTHORITY_MISMATCH",
                evidence,
                code="PRODUCTION_DCS_WRITER_RUNTIME_AUTHORITY_MISMATCH",
                service_owned_live_pids=service_owned_live_pids,
            )

        client = _parse_client_identity(runtime.get("global_writer_client_build"))
        if (
            runtime.get("service_code") != entry.service_code
            or runtime.get("product_build_commit") != entry.product_build_commit
            or runtime.get("product_build_identity") != entry.product_build_identity
            or runtime.get("source_root_or_artifact_identity")
            != entry.source_root_or_artifact_identity
            or client != entry.client
            or not client.supports_v8
        ):
            raise self._active_resume_error(
                entry,
                "RUNTIME_BUILD_OR_THIN_AUTHORITY_MISMATCH",
                evidence,
                code="PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_INVENTORY_CHANGED",
                service_owned_live_pids=service_owned_live_pids,
            )

        runtime_pid = runtime.get("pid")
        if (
            not isinstance(runtime_pid, int)
            or isinstance(runtime_pid, bool)
            or runtime_pid <= 0
        ):
            raise self._active_resume_error(
                entry,
                "RUNTIME_IDENTITY_PID_INVALID",
                evidence,
                code="PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID",
                service_owned_live_pids=service_owned_live_pids,
            )
        if runtime_pid != launch_pid:
            # Only a retained PID from a process identity previously observed for
            # this exact ACTIVE_BEFORE writer is a permitted publication gap.
            if runtime_pid not in prior_process_pids:
                raise self._active_resume_error(
                    entry,
                    "RUNTIME_IDENTITY_PID_MISMATCH",
                    evidence,
                    code="PRODUCTION_DCS_WRITER_PROCESS_IDENTITY_MISMATCH",
                    service_owned_live_pids=service_owned_live_pids,
                )
            try:
                prior_live, prior_owned = self.process_probe(runtime_pid, arguments)
            except Exception as error:
                raise self._active_resume_error(
                    entry, "PRIOR_PID_OWNERSHIP_UNRESOLVED", evidence,
                    service_owned_live_pids=service_owned_live_pids,
                ) from error
            if prior_live:
                stage = "PRIOR_PID_DUPLICATE_SERVICE" if prior_owned else "PRIOR_PID_REUSED_UNRELATED"
                raise self._active_resume_error(
                    entry, stage, evidence, service_owned_live_pids=service_owned_live_pids
                )
            return False, None, evidence, service_owned_live_pids

        incarnation = runtime.get("process_incarnation_id")
        if not isinstance(incarnation, str) or not incarnation:
            raise self._active_resume_error(
                entry,
                "PROCESS_INCARNATION_INVALID",
                evidence,
                code="PRODUCTION_DCS_WRITER_RUNTIME_IDENTITY_INVALID",
                service_owned_live_pids=service_owned_live_pids,
            )
        return True, (launch_pid, incarnation), evidence, service_owned_live_pids

    def _wait_for_stable_active_resume(
        self,
        entries: Sequence[DcsWriterInventoryEntry],
        *,
        deadline: float,
    ) -> Mapping[str, tuple[int, str]]:
        targets = tuple(sorted(entries, key=lambda item: item.writer_id))
        if not targets:
            return {}
        definitions: dict[str, tuple[str, ...]] = {}
        for entry in targets:
            try:
                _plist_path, arguments = self._service_definition_for_entry(entry)
            except ProductionDcsV8AdoptionError as error:
                raise self._active_resume_error(
                    entry, "SERVICE_DEFINITION_CHANGED", None
                ) from error
            definitions[entry.writer_id] = arguments

        prior_process_pids: dict[str, set[int]] = {
            entry.writer_id: ({entry.pid} if isinstance(entry.pid, int) and entry.pid > 0 else set())
            for entry in targets
        }
        stable_observations = 0
        last_stable_identity: tuple[tuple[str, int, str], ...] | None = None
        last_evidence: tuple[DcsWriterInventoryEntry, _LaunchdRuntimeEvidence, tuple[int, ...]] | None = None

        while True:
            current: list[tuple[str, int, str]] = []
            cycle_stable = True
            for entry in targets:
                stable, identity, evidence, live_pids = self._observe_active_resume_entry(
                    entry,
                    definitions[entry.writer_id],
                    prior_process_pids=prior_process_pids[entry.writer_id],
                )
                last_evidence = (entry, evidence, live_pids)
                if not stable or identity is None:
                    cycle_stable = False
                    continue
                pid, incarnation = identity
                current.append((entry.writer_id, pid, incarnation))
                prior_process_pids[entry.writer_id].add(pid)

            if cycle_stable and len(current) == len(targets):
                current_identity = tuple(current)
                if current_identity == last_stable_identity:
                    stable_observations += 1
                else:
                    last_stable_identity = current_identity
                    stable_observations = 1
                if stable_observations >= _ACTIVE_RESUME_STABLE_OBSERVATIONS:
                    return {writer_id: (pid, incarnation) for writer_id, pid, incarnation in current}
            else:
                stable_observations = 0
                last_stable_identity = None

            if time.monotonic() >= deadline:
                if last_evidence is None:
                    entry = targets[0]
                    evidence = None
                    live_pids: tuple[int, ...] = ()
                else:
                    entry, evidence, live_pids = last_evidence
                raise self._active_resume_error(
                    entry,
                    "ACTIVE_RESUME_STABILIZATION_TIMEOUT",
                    evidence,
                    code="PRODUCTION_DCS_WRITER_ACTIVE_RESUME_STABILIZATION_TIMEOUT",
                    service_owned_live_pids=live_pids,
                )
            self.sleep(_ACTIVE_RESUME_POLL_SECONDS)

    def _record_active_resume_targets(
        self, entries: Sequence[DcsWriterInventoryEntry]
    ) -> None:
        for entry in entries:
            self._active_resume_pending[entry.writer_id] = entry

    def _resume_booted_out_entries(
        self, entries: Sequence[DcsWriterInventoryEntry]
    ) -> None:
        failures: list[str] = []
        started_entries: list[DcsWriterInventoryEntry] = []
        for entry in entries:
            if entry.state != "ACTIVE":
                continue
            try:
                plist_path, _arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            except ProductionDcsV8AdoptionError:
                failures.append(entry.writer_id)
                continue
            target = f"gui/{self.uid}/{entry.launchd_label}"
            plist_path, _arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            enabled = self._launchctl("enable", target)
            if enabled.returncode != 0:
                failures.append(entry.writer_id)
                continue
            plist_path, _arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            bootstrapped = self._launchctl(
                "bootstrap", f"gui/{self.uid}", os.fspath(plist_path)
            )
            if bootstrapped.returncode != 0:
                failures.append(entry.writer_id)
                continue
            self._service_definition_for_entry(entry, phase="RECOVERY")
            started = self._launchctl("kickstart", target)
            if started.returncode != 0:
                failures.append(entry.writer_id)
                continue
            started_entries.append(entry)
        self._record_active_resume_targets(started_entries)
        if failures:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_RESTORE_FAILED",
                ",".join(sorted(failures)),
                phase="RECOVERY",
                recovery_status="RECOVERY_REQUIRED",
            )

    def _resume_entries(self, entries: Sequence[DcsWriterInventoryEntry]) -> None:
        # Exact-state restoration: only writers observed ACTIVE before quiescence
        # are resume targets.  An INACTIVE discovered writer must stay disabled
        # and must never be enabled merely because it exists in the inventory.
        failures: list[str] = []
        started_entries: list[DcsWriterInventoryEntry] = []
        for entry in entries:
            if entry.state != "ACTIVE":
                continue
            target = f"gui/{self.uid}/{entry.launchd_label}"
            self._service_definition_for_entry(entry, phase="RECOVERY")
            enabled = self._launchctl("enable", target)
            if enabled.returncode != 0:
                failures.append(entry.writer_id)
                continue
            self._service_definition_for_entry(entry, phase="RECOVERY")
            started = self._launchctl("kickstart", target)
            if started.returncode != 0:
                failures.append(entry.writer_id)
                continue
            started_entries.append(entry)
        self._record_active_resume_targets(started_entries)
        if failures:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_RESTORE_FAILED",
                ",".join(sorted(failures)),
                phase="RECOVERY",
                recovery_status="RECOVERY_REQUIRED",
            )

    def _require_restore_client_compatible(
        self, entry: DcsWriterInventoryEntry, schema_version: int
    ) -> RuntimeArtifactAttestation | None:
        if type(schema_version) is not int or schema_version not in {6, 7, 8, 9, 10} or not entry.client.supports_schema(schema_version):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_RESTORE_SCHEMA_CLIENT_INCOMPATIBLE",
                f"{entry.writer_id}:v{schema_version}:{entry.client.version}",
                phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )
        if schema_version not in {9, 10}:
            return None

        accepted = _AUTHORIZED_THIN_STARTUP_V10 if schema_version == 10 or entry.client.version == "0.5.0" else _AUTHORIZED_THIN_STARTUP_V9
        accepted_label = "0_5" if accepted.version == "0.5.0" else "0_4"
        expected_build = (
            f"{accepted.build_id}|source={accepted.source_commit}"
            f"|artifact=source-commit:{accepted.source_commit}"
        )
        if (
            entry.client.version != accepted.version
            or entry.client.build_identity != expected_build
            or entry.client.source_commit != accepted.source_commit
            or entry.client.artifact_identity != f"source-commit:{accepted.source_commit}"
        ):
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RESTORE_REQUIRES_ACCEPTED_{accepted_label}_CLIENT",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )
        provider = self.runtime_artifact_attestation
        if provider is None:
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_ATTESTATION_MISSING",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )
        try:
            attestation = provider(entry, schema_version)
        except Exception as error:
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_ATTESTATION_FAILED",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            ) from error
        if type(attestation) is not RuntimeArtifactAttestation:
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_ATTESTATION_INCOMPLETE",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )

        expected_interpreter = entry.program_arguments[0] if entry.program_arguments else ""
        expected_venv = Path(expected_interpreter).expanduser().parent.parent if expected_interpreter else Path()
        hash_fields = (
            attestation.accepted_wheel_sha256,
            attestation.installed_member_manifest_sha256,
            attestation.binding_facts_sha256,
            attestation.deterministic_attestation_sha256,
        )
        paths = (
            attestation.accepted_wheel_realpath,
            attestation.interpreter_path,
            attestation.interpreter_realpath,
            attestation.sys_executable,
            attestation.sys_executable_realpath,
            attestation.sys_prefix,
            attestation.purelib_path,
            attestation.purelib_realpath,
            attestation.installed_distribution_root,
            attestation.installed_dist_info_path,
            attestation.installed_package_root,
            attestation.installed_module_file,
        )
        try:
            binding_facts = json.loads(attestation.binding_facts_json)
            wheel_path = Path(attestation.accepted_wheel_realpath)
            current_wheel_sha = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
            interpreter_realpath = Path(expected_interpreter).expanduser().resolve(strict=True)
        except (OSError, json.JSONDecodeError) as error:
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_ATTESTATION_INCOMPLETE",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            ) from error
        if (
            not expected_interpreter
            or not Path(expected_interpreter).is_absolute()
            or any(not isinstance(value, str) or not Path(value).is_absolute() for value in paths)
            or any(not isinstance(value, str) or _HEX_SHA256.fullmatch(value) is None for value in hash_fields)
            or current_wheel_sha != attestation.accepted_wheel_sha256
            or (accepted.version == "0.5.0" and (
                current_wheel_sha != _V10_COMPAT_0_5_WHEEL_SHA256
                or attestation.installed_supported_dcs_schemas != accepted.supported_dcs_schema_versions
                or attestation.installed_thin_contract_format_version != accepted.thin_contract_format_version
            ))
            or attestation.installed_member_count <= 0
            or attestation.installed_version != accepted.version
            or attestation.installed_build_id != accepted.build_id
            or attestation.installed_source_commit != accepted.source_commit
            or schema_version not in attestation.installed_supported_dcs_schemas
            or attestation.installed_schema_contract_identity != accepted.schema_contract_identity
            or attestation.interpreter_path != expected_interpreter
            or attestation.sys_executable != expected_interpreter
            or Path(attestation.interpreter_realpath) != interpreter_realpath
            or Path(attestation.sys_executable_realpath) != interpreter_realpath
            or Path(attestation.sys_prefix).resolve(strict=False) != expected_venv.resolve(strict=False)
            or Path(attestation.sys_prefix_realpath).resolve(strict=False) != expected_venv.resolve(strict=False)
            or Path(attestation.purelib_path).resolve(strict=False)
            != Path(attestation.purelib_realpath).resolve(strict=False)
            or not Path(attestation.purelib_realpath).resolve(strict=False).is_relative_to(
                expected_venv.resolve(strict=False)
            )
            or Path(attestation.installed_distribution_root).resolve(strict=False)
            != Path(attestation.purelib_realpath).resolve(strict=False)
            or not Path(attestation.installed_dist_info_path).resolve(strict=False).is_relative_to(
                Path(attestation.purelib_realpath).resolve(strict=False)
            )
            or not Path(attestation.installed_package_root).resolve(strict=False).is_relative_to(
                Path(attestation.purelib_realpath).resolve(strict=False)
            )
            or not Path(attestation.installed_module_file).resolve(strict=False).is_relative_to(
                Path(attestation.installed_package_root).resolve(strict=False)
            )
            or hashlib.sha256(attestation.binding_facts_json.encode("utf-8")).hexdigest()
            != attestation.binding_facts_sha256
            or not isinstance(binding_facts, Mapping)
            or binding_facts.get("writer") != entry.writer_id
            or binding_facts.get("label") != entry.launchd_label
            or binding_facts.get("interpreter") != expected_interpreter
        ):
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_ATTESTATION_MISMATCH",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )
        if entry.runtime_state == "ACTIVE" and binding_facts.get("incarnation") != entry.process_incarnation_id:
            raise ProductionDcsV8AdoptionError(
                f"PRODUCTION_DCS_WRITER_V{schema_version}_RUNTIME_ARTIFACT_GENERATION_MISMATCH",
                entry.writer_id, phase="RECOVERY", schema_version=schema_version,
                recovery_status="RECOVERY_REQUIRED",
            )
        # The only package SHA observed by this consumer comes from the accepted
        # attestation and is immediately tied back to the same wheel bytes above.
        return attestation

    def _wait_for_scheduled_baseline(
        self,
        entries: Sequence[DcsWriterInventoryEntry],
        *,
        deadline: float,
        assert_current: Callable[[], Any] | None = None,
        assert_event_guard: Callable[[], Any] | None = None,
    ) -> None:
        targets = tuple(sorted(entries, key=lambda item: item.writer_id))
        stable = 0
        while True:
            cycle = True
            for entry in targets:
                if assert_current is not None:
                    assert_current()
                if assert_event_guard is not None:
                    assert_event_guard()
                _plist, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
                enabled = self._enabled_state(entry.launchd_label)
                evidence = self._launch_state(entry.launchd_label, arguments)
                try:
                    pids = tuple(self.process_scan(arguments))
                except Exception as error:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_B_RESTORE_PROCESS_SCAN_UNRESOLVED",
                        entry.writer_id, phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                    ) from error
                if not (
                    enabled == "ENABLED"
                    and evidence.runtime_state == "INACTIVE"
                    and evidence.load_state == "LOADED"
                    and not pids
                ):
                    cycle = False
            stable = stable + 1 if cycle else 0
            if stable >= _QUIESCENCE_STABLE_OBSERVATIONS:
                return
            if time.monotonic() >= deadline:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_B_RESTORE_STABILIZATION_TIMEOUT",
                    phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                )
            self.sleep(_QUIESCENCE_POLL_SECONDS)

    def _restore_b_entries(
        self,
        entries: Sequence[DcsWriterInventoryEntry],
        *,
        schema_version: int,
        assert_current: Callable[[], Any] | None = None,
        assert_event_guard: Callable[[], Any] | None = None,
    ) -> None:
        targets = tuple(entry for entry in entries if _entry_before_class(entry) == "B")
        for entry in targets:
            self._require_restore_client_compatible(entry, schema_version)
            if assert_current is not None:
                assert_current()
            if assert_event_guard is not None:
                assert_event_guard()
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            current_enabled = self._enabled_state(entry.launchd_label)
            current_evidence = self._launch_state(entry.launchd_label, arguments)
            try:
                current_pids = tuple(self.process_scan(arguments))
            except Exception as error:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_B_RESTORE_PROCESS_SCAN_UNRESOLVED",
                    entry.writer_id, phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                ) from error
            if (
                current_enabled == "ENABLED"
                and current_evidence.runtime_state == "INACTIVE"
                and current_evidence.load_state == "LOADED"
                and not current_pids
            ):
                continue
            target = f"gui/{self.uid}/{entry.launchd_label}"
            # Exact frozen authority immediately before the first physical restore effect.
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            enabled = self._launchctl("enable", target)
            if enabled.returncode != 0 or self._enabled_state(entry.launchd_label) != "ENABLED":
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_B_RESTORE_ENABLE_FAILED",
                    entry.writer_id, phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                )
            if assert_current is not None:
                assert_current()
            if assert_event_guard is not None:
                assert_event_guard()
            # Re-resolve after enable and immediately before bootstrap.
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            bootstrapped = self._launchctl("bootstrap", f"gui/{self.uid}", os.fspath(plist_path))
            if bootstrapped.returncode != 0:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_B_RESTORE_BOOTSTRAP_FAILED",
                    entry.writer_id, phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                )
            # B restore deliberately has no kickstart. RunAtLoad may transiently
            # activate only while the caller's migration fence is still held.
        if targets:
            self._wait_for_scheduled_baseline(
                targets,
                deadline=time.monotonic() + _ACTIVE_RESUME_TIMEOUT_SECONDS,
                assert_current=assert_current,
                assert_event_guard=assert_event_guard,
            )

    def quiesce(self, inventory: DcsWriterInventory) -> _QuiescenceToken:
        return self._quiesce_impl(inventory, fenced=False)

    def quiesce_fenced(
        self,
        inventory: DcsWriterInventory,
        *,
        assert_current: Callable[[], Any],
        assert_event_guard: Callable[[], Any],
    ) -> _QuiescenceToken:
        return self._quiesce_impl(
            inventory,
            fenced=True,
            assert_current=assert_current,
            assert_event_guard=assert_event_guard,
        )

    def _quiesce_impl(
        self,
        inventory: DcsWriterInventory,
        *,
        fenced: bool,
        assert_current: Callable[[], Any] | None = None,
        assert_event_guard: Callable[[], Any] | None = None,
    ) -> _QuiescenceToken:
        targets = sorted(
            (entry for entry in inventory.entries if _entry_before_class(entry) in {"A", "B"}),
            key=lambda entry: (0 if _entry_before_class(entry) == "B" else 1, entry.writer_id),
        )
        definitions: dict[str, tuple[Path, tuple[str, ...]]] = {}
        disabled: list[DcsWriterInventoryEntry] = []
        booted_out: list[DcsWriterInventoryEntry] = []
        try:
            # Resolve every A/B service before the first effect; B is ordered first-off.
            for entry in targets:
                definitions[entry.writer_id] = self._service_definition_for_entry(entry)

            for entry in targets:
                if assert_current is not None:
                    assert_current()
                if assert_event_guard is not None:
                    assert_event_guard()
                target = f"gui/{self.uid}/{entry.launchd_label}"
                result = self._launchctl("disable", target)
                if result.returncode != 0:
                    evidence = self._launch_state(
                        entry.launchd_label, definitions[entry.writer_id][1]
                    )
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED",
                        self._transition_evidence_detail(entry, "DISABLE", evidence),
                        phase="QUIESCENCE",
                    )
                disabled.append(entry)
                if self._enabled_state(entry.launchd_label) != "DISABLED":
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_DISABLE_READBACK_FAILED",
                        entry.writer_id, phase="QUIESCENCE",
                        recovery_status="RECOVERY_REQUIRED" if fenced else "NOT_REQUIRED",
                    )
                if assert_current is not None:
                    assert_current()
                if assert_event_guard is not None:
                    assert_event_guard()
                result = self._launchctl("bootout", target)
                if result.returncode != 0:
                    evidence = self._launch_state(
                        entry.launchd_label, definitions[entry.writer_id][1]
                    )
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED",
                        self._transition_evidence_detail(entry, "BOOTOUT", evidence),
                        phase="QUIESCENCE",
                    )
                booted_out.append(entry)

            deadline = time.monotonic() + _QUIESCENCE_TIMEOUT_SECONDS
            transitions = tuple(
                (entry, definitions[entry.writer_id][1]) for entry in targets
            )
            if transitions:
                self._wait_for_stable_nonrunning(
                    transitions,
                    deadline=deadline,
                    assert_current=assert_current,
                    assert_event_guard=assert_event_guard,
                )

            # Only after launchd/process stabilization do we return to the normal
            # strict authority path.  ACTIVE PID comparison is never weakened.
            after = self.discover()
            after_by_id = {entry.writer_id: entry for entry in after.entries}
            if any(
                after_by_id[entry.writer_id].state != "INACTIVE"
                or after_by_id[entry.writer_id].load_state != "UNLOADED"
                or after_by_id[entry.writer_id].enabled_state != "DISABLED"
                for entry in targets
            ):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED", phase="QUIESCENCE"
                )
            if _stable_inventory_fingerprint(after.entries) != _stable_inventory_fingerprint(inventory.entries):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_IDENTITY_CHANGED_DURING_QUIESCENCE", phase="QUIESCENCE"
                )
            return _QuiescenceToken(
                before=inventory,
                quiesced_stable_identities=tuple(entry.stable_identity for entry in after.entries),
                before_classes=tuple((entry.writer_id, _entry_before_class(entry)) for entry in inventory.entries),
            )
        except BaseException as error:
            if fenced:
                if isinstance(error, ProductionDcsV8AdoptionError):
                    if disabled and not booted_out:
                        raise ProductionDcsV8AdoptionError(
                            error.code, error.detail, phase=error.phase,
                            schema_version=error.schema_version,
                            recovery_status="RECOVERY_REQUIRED_UNDER_FRESH_AUTHORITY",
                        ) from error
                    raise
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED",
                    type(error).__name__, phase="QUIESCENCE",
                    recovery_status=(
                        "RECOVERY_REQUIRED_UNDER_FRESH_AUTHORITY" if disabled else "NOT_REQUIRED"
                    ),
                ) from error
            try:
                if booted_out:
                    self._resume_booted_out_entries(booted_out)
                booted_ids = {entry.writer_id for entry in booted_out}
                still_loaded = [entry for entry in disabled if entry.writer_id not in booted_ids]
                if still_loaded:
                    self._resume_entries(still_loaded)
                if booted_out or still_loaded:
                    recovery_token = _QuiescenceToken(
                        before=inventory,
                        quiesced_stable_identities=tuple(
                            entry.stable_identity for entry in inventory.entries
                        ),
                        before_classes=tuple((entry.writer_id, _entry_before_class(entry)) for entry in inventory.entries),
                    )
                    self.verify_resumed(recovery_token)
            except BaseException as recovery_error:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_RECOVERY_REQUIRED",
                    type(error).__name__,
                    phase="RECOVERY",
                    recovery_status="WRITER_RESTORE_FAILED",
                ) from recovery_error
            if isinstance(error, ProductionDcsV8AdoptionError):
                raise
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED", type(error).__name__, phase="QUIESCENCE"
            ) from error

    def verify_quiesced(self, token: _QuiescenceToken) -> None:
        after = self.discover()
        if _stable_inventory_fingerprint(after.entries) != _stable_inventory_fingerprint(token.before.entries):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_INVENTORY_CHANGED_AFTER_QUIESCENCE", phase="QUIESCENCE"
            )
        if any(entry.state != "INACTIVE" for entry in after.entries):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED", phase="QUIESCENCE"
            )

    def resume(self, token: _QuiescenceToken) -> None:
        self._resume_booted_out_entries(
            tuple(entry for entry in token.before.entries if _entry_before_class(entry) == "A")
        )
        self._restore_b_entries(token.before.entries, schema_version=8)

    def resume_fenced(
        self,
        token: _QuiescenceToken,
        *,
        schema_version: int,
        assert_current: Callable[[], Any],
        assert_event_guard: Callable[[], Any],
    ) -> None:
        # A retains exact enable/bootstrap/kickstart semantics, but every effect is fenced.
        active_entries = tuple(entry for entry in token.before.entries if _entry_before_class(entry) == "A")
        for entry in active_entries:
            self._require_restore_client_compatible(entry, schema_version)
            assert_current(); assert_event_guard()
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            current_enabled = self._enabled_state(entry.launchd_label)
            current_evidence = self._launch_state(entry.launchd_label, arguments)
            try:
                current_pids = tuple(self.process_scan(arguments))
            except Exception as error:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_A_RESTORE_PROCESS_SCAN_UNRESOLVED",
                    entry.writer_id, phase="RECOVERY", recovery_status="RECOVERY_REQUIRED",
                ) from error
            if (
                current_enabled == "ENABLED"
                and current_evidence.runtime_state == "ACTIVE"
                and current_evidence.load_state == "LOADED"
                and current_evidence.pid_field is not None
                and current_pids == (current_evidence.pid_field,)
            ):
                continue
            target = f"gui/{self.uid}/{entry.launchd_label}"
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            if self._launchctl("enable", target).returncode != 0:
                raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_RESTORE_FAILED", entry.writer_id)
            assert_current(); assert_event_guard()
            plist_path, arguments = self._service_definition_for_entry(entry, phase="RECOVERY")
            if self._launchctl("bootstrap", f"gui/{self.uid}", os.fspath(plist_path)).returncode != 0:
                raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_RESTORE_FAILED", entry.writer_id)
            assert_current(); assert_event_guard()
            self._service_definition_for_entry(entry, phase="RECOVERY")
            if self._launchctl("kickstart", target).returncode != 0:
                raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_WRITER_RESTORE_FAILED", entry.writer_id)
        self._record_active_resume_targets(active_entries)
        self._restore_b_entries(
            token.before.entries,
            schema_version=schema_version,
            assert_current=assert_current,
            assert_event_guard=assert_event_guard,
        )
        assert_current(); assert_event_guard()

    def verify_resumed(self, token: _QuiescenceToken) -> DcsWriterInventory:
        expected_stable = _stable_inventory_fingerprint(token.before.entries)
        active_expected = {entry.writer_id for entry in token.before.entries if entry.state == "ACTIVE"}
        pending_ids = set(self._active_resume_pending)
        if pending_ids - active_expected:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                ",".join(sorted(pending_ids - active_expected)),
                phase="POST_MIGRATION",
                schema_version=8,
                recovery_status="RECOVERY_REQUIRED",
            )

        pending = tuple(
            self._active_resume_pending[writer_id]
            for writer_id in sorted(pending_ids & active_expected)
        )
        if pending:
            stabilized = self._wait_for_stable_active_resume(
                pending, deadline=time.monotonic() + _ACTIVE_RESUME_TIMEOUT_SECONDS
            )
            # After transition stabilization, authority returns to the unchanged
            # generic strict discovery path.  No PID mismatch exception is relaxed.
            observed = self.discover()
            if _stable_inventory_fingerprint(observed.entries) != expected_stable:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_INVENTORY_CHANGED",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            active_now = {entry.writer_id for entry in observed.entries if entry.state == "ACTIVE"}
            if active_now != active_expected:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                    ",".join(sorted(active_expected.symmetric_difference(active_now))),
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            observed_by_id = {entry.writer_id: entry for entry in observed.entries}
            for writer_id, identity in stabilized.items():
                entry = observed_by_id.get(writer_id)
                if entry is None or (entry.pid, entry.process_incarnation_id) != identity:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
                        writer_id, phase="POST_MIGRATION", schema_version=8,
                        recovery_status="RECOVERY_REQUIRED",
                    )
            if not observed.all_support_v8:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            expected_classes = {entry.writer_id: _entry_before_class(entry) for entry in token.before.entries}
            observed_classes = {entry.writer_id: _entry_before_class(entry) for entry in observed.entries}
            if observed_classes != expected_classes:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                    "physical-before-class", phase="POST_MIGRATION", schema_version=8,
                    recovery_status="RECOVERY_REQUIRED",
                )
            for writer_id in stabilized:
                self._active_resume_pending.pop(writer_id, None)
            return observed

        # No writer was explicitly restarted by this authority instance.  Preserve
        # the existing strict validation behavior for mutation-free callers/tests;
        # the real controller's resume and recovery paths always populate pending.
        deadline = time.monotonic() + _ACTIVE_RESUME_TIMEOUT_SECONDS
        while True:
            observed = self.discover()
            if _stable_inventory_fingerprint(observed.entries) != expected_stable:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_INVENTORY_CHANGED",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            active_now = {entry.writer_id for entry in observed.entries if entry.state == "ACTIVE"}
            if active_now - active_expected:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                    ",".join(sorted(active_now - active_expected)),
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            if active_now == active_expected:
                if not observed.all_support_v8:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
                        phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                    )
                expected_classes = {entry.writer_id: _entry_before_class(entry) for entry in token.before.entries}
                observed_classes = {entry.writer_id: _entry_before_class(entry) for entry in observed.entries}
                if observed_classes != expected_classes:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                        "physical-before-class", phase="POST_MIGRATION", schema_version=8,
                        recovery_status="RECOVERY_REQUIRED",
                    )
                return observed
            if time.monotonic() >= deadline:
                missing = active_expected - active_now
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                    ",".join(sorted(missing)),
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            self.sleep(_ACTIVE_RESUME_POLL_SECONDS)


class _AlreadyQuiescedFrozenAdapter:
    """Bridge actual outer quiescence into the FINAL_ACCEPTED v6->v7 contract."""

    def __init__(self, inventory: DcsWriterInventory) -> None:
        by_code = {entry.writer_id: entry for entry in inventory.entries}
        self._writers: dict[tuple[str, str], RuntimeWriter] = {}
        for code in sorted(EXPECTED_WRITER_CODES):
            entry = by_code.get(code)
            runtime_id = (
                "outer-quiesced:" + _hash(entry.stable_identity)[:24]
                if entry is not None
                else f"outer-quiesced:no-effective-runtime:{code.lower()}"
            )
            writer = RuntimeWriter(
                code,
                runtime_id,
                "PROPERTYAI" if code <= "W07" else "ADCP",
                "QUIESCED",
            )
            self._writers[writer.identity] = writer

    def discover(self) -> Sequence[RuntimeWriter]:
        return tuple(self._writers.values())

    def quiesce(self, writer: RuntimeWriter) -> None:  # pragma: no cover - fail-closed bridge invariant
        raise ProductionDcsV8AdoptionError("FROZEN_V6_V7_BRIDGE_DOUBLE_QUIESCE_FORBIDDEN")

    def inspect(self, writer: RuntimeWriter) -> RuntimeWriter:
        return self._writers[writer.identity]

    def reactivate(self, writer: RuntimeWriter) -> None:  # pragma: no cover - no inner activation authority
        raise ProductionDcsV8AdoptionError("FROZEN_V6_V7_BRIDGE_REACTIVATION_FORBIDDEN")


class _FencedFrozenWriterAdapter:
    """Bind real launchd A/B quiescence to the frozen migration lease."""

    def __init__(self, authority: _LaunchdWriterAuthority, inventory: DcsWriterInventory) -> None:
        self.authority = authority
        self.inventory = inventory
        self._entry_by_code = {entry.writer_id: entry for entry in inventory.entries}
        self._writers: dict[tuple[str, str], RuntimeWriter] = {}
        self._target_codes = {
            entry.writer_id for entry in inventory.entries if _entry_before_class(entry) in {"A", "B"}
        }
        for code in sorted(EXPECTED_WRITER_CODES):
            entry = self._entry_by_code.get(code)
            runtime_id = (
                "fenced-physical:" + _hash(entry.stable_identity)[:24]
                if entry is not None
                else f"fenced-physical:invocation-only:{code.lower()}"
            )
            state = "ACTIVE" if code in self._target_codes else "QUIESCED"
            writer = RuntimeWriter(
                code,
                runtime_id,
                "PROPERTYAI" if code <= "W07" else "ADCP",
                state,
            )
            self._writers[writer.identity] = writer
        self._assert_current: Callable[[], Any] | None = None
        self._assert_event_guard: Callable[[], Any] | None = None
        self._schema_version: Callable[[], int] | None = None
        self._token: _QuiescenceToken | None = None
        self._restored = False

    def bind_migration_guard(
        self,
        *,
        assert_current: Callable[[], Any],
        assert_event_guard: Callable[[], Any],
        schema_version: Callable[[], int],
    ) -> None:
        self._assert_current = assert_current
        self._assert_event_guard = assert_event_guard
        self._schema_version = schema_version

    def _require_guard(self) -> tuple[Callable[[], Any], Callable[[], Any], Callable[[], int]]:
        if self._assert_current is None or self._assert_event_guard is None or self._schema_version is None:
            raise ProductionDcsV8AdoptionError("FENCED_QUIESCENCE_GUARD_UNBOUND")
        return self._assert_current, self._assert_event_guard, self._schema_version

    def discover(self) -> Sequence[RuntimeWriter]:
        return tuple(self._writers[key] for key in sorted(self._writers))

    def quiesce(self, writer: RuntimeWriter) -> None:
        if writer.service_code not in self._target_codes:
            return
        assert_current, assert_event_guard, _schema = self._require_guard()
        if self._token is None:
            self._token = self.authority.quiesce_fenced(
                self.inventory,
                assert_current=assert_current,
                assert_event_guard=assert_event_guard,
            )
            for identity, current in tuple(self._writers.items()):
                if current.service_code in self._target_codes:
                    self._writers[identity] = RuntimeWriter(
                        current.service_code, current.runtime_id, current.classification, "QUIESCED"
                    )

    def inspect(self, writer: RuntimeWriter) -> RuntimeWriter:
        return self._writers[writer.identity]

    def reactivate(self, writer: RuntimeWriter) -> None:
        if writer.service_code not in self._target_codes:
            return
        assert_current, assert_event_guard, schema_version = self._require_guard()
        if self._token is None:
            raise ProductionDcsV8AdoptionError("FENCED_QUIESCENCE_TOKEN_MISSING")
        if not self._restored:
            self.authority.resume_fenced(
                self._token,
                schema_version=schema_version(),
                assert_current=assert_current,
                assert_event_guard=assert_event_guard,
            )
            self.authority.verify_resumed(self._token)
            self._restored = True
        current = self._writers[writer.identity]
        self._writers[writer.identity] = RuntimeWriter(
            current.service_code, current.runtime_id, current.classification, "ACTIVE"
        )


def _source_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git_read(*args: str) -> str:
    root = _source_root()
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=5.0,
    )
    if result.returncode != 0:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_SOURCE_AUTHORITY_UNREADABLE")
    return result.stdout.strip()


def _source_binding() -> Mapping[str, str]:
    if _git_read("status", "--porcelain=v1"):
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_SOURCE_AUTHORITY_DIRTY")
    head = _git_read("rev-parse", "HEAD")
    tree = _git_read("rev-parse", "HEAD^{tree}")
    if len(head) != 40 or len(tree) != 40:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_SOURCE_AUTHORITY_INVALID")
    return {"head": head, "tree": tree, "authority_ref": HQ_DCS_DECISION}


class _ExactMigrationAuthority:
    def __init__(self, writers: _LaunchdWriterAuthority | None = None) -> None:
        self.writers = writers

    @property
    def handles_physical_quiescence(self) -> bool:
        return self.writers is not None

    def run_v6_to_v7(self, path: Path, inventory: DcsWriterInventory) -> None:
        binding = _source_binding()
        CANONICAL_EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        context = ExecutionContext(
            dcs_path=path,
            evidence_root=CANONICAL_EVIDENCE_ROOT,
            accepted_git_head=binding["head"],
            accepted_git_tree=binding["tree"],
            authority_ref=HQ_DCS_DECISION,
            canonical_production_path=CANONICAL_DCS_PATH,
            canonical_production_authorization=HQ_DCS_DECISION,
        )
        adapter = (
            _FencedFrozenWriterAdapter(self.writers, inventory)
            if self.writers is not None
            else _AlreadyQuiescedFrozenAdapter(inventory)
        )
        result = ProductionMigrationOrchestrator(
            context,
            authority=lambda: _source_binding(),
            quiescence=adapter,
        ).run()
        if result.previous_version != 6 or result.version != 7:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V6_TO_V7_RESULT_INVALID", phase="MIGRATION", schema_version=result.version
            )

    def run_v7_to_v8(self, path: Path) -> None:
        CANONICAL_EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(path, isolation_level=None, timeout=5.0)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            result = run_v7_to_v8_adoption(connection, backup_root=CANONICAL_EVIDENCE_ROOT)
        finally:
            connection.close()
        if result.previous_version != 7 or result.version != 8 or result.status != "APPLIED_EXACT":
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V7_TO_V8_RESULT_INVALID", phase="MIGRATION", schema_version=result.version
            )


class _ControlStoreHeldW08Lease:
    """One exact W08 lease that survives the v7 -> v8 schema generation change."""

    def __init__(
        self,
        *,
        path: Path,
        store: ControlStore,
        owner_id: str,
        fencing_token: int,
        release_operation_key: str,
        event_cursor: int,
    ) -> None:
        self.path = path
        self.store = store
        self.owner_id = owner_id
        self.fencing_token = fencing_token
        self.release_operation_key = release_operation_key
        self.event_cursor = event_cursor
        self._closed = False

    def assert_event_guard(self) -> None:
        rows = self.store.global_production_writer_events()
        conflicts = [row for row in rows if int(row["event_seq"]) > self.event_cursor]
        if conflicts:
            row = conflicts[0]
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_GLOBAL_WRITER_EVENT_CONFLICT",
                f"{row['event_type']}:{row['event_seq']}",
                phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
            )

    def assert_current(self) -> int:
        try:
            row = self.store.assert_current_global_writer(self.owner_id, self.fencing_token)
        except StoreError as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_AUTHORITY_LOST",
                error.code,
                phase="SERIALIZATION",
                recovery_status="RECOVERY_REQUIRED",
            ) from error
        token = int(row["fencing_token"])
        if row["state"] != "HELD" or token != self.fencing_token:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_AUTHORITY_LOST",
                phase="SERIALIZATION",
                recovery_status="RECOVERY_REQUIRED",
            )
        return token

    def reopen_exact_schema(self, version: int) -> int:
        # Migration 8 changes the schema generation.  Do not weaken version
        # validation: close the v7 handle and reopen exact v8 while retaining
        # the same durable owner/fencing identity in the database.
        self.store.close()
        try:
            self.store = ControlStore(
                self.path,
                migrate_schema=False,
                require_schema_version=version,
                global_writer_guard_required=False,
            )
        except BaseException as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_SCHEMA_REBIND_FAILED",
                type(error).__name__,
                phase="POST_MIGRATION",
                schema_version=version,
                recovery_status="RECOVERY_REQUIRED",
            ) from error
        token = self.assert_current()
        if token != self.fencing_token:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_FENCING_TOKEN_CHANGED",
                phase="POST_MIGRATION",
                schema_version=version,
                recovery_status="RECOVERY_REQUIRED",
            )
        return token

    def release(self) -> Mapping[str, Any]:
        self.assert_current()
        try:
            row = self.store.release_global_production_writer(
                operation_key=self.release_operation_key,
                owner_id=self.owner_id,
                fencing_token=self.fencing_token,
                control_decision_ref=HQ_DCS_DECISION,
            )
        except StoreError as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED",
                error.code,
                phase="SERIALIZATION",
                recovery_status="RECOVERY_REQUIRED",
            ) from error
        if row["state"] != "FREE" or int(row["fencing_token"]) != self.fencing_token:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED",
                "readback",
                phase="SERIALIZATION",
                recovery_status="RECOVERY_REQUIRED",
            )
        return {"state": "FREE", "fencing_token": self.fencing_token}

    def close(self) -> None:
        if not self._closed:
            self.store.close()
            self._closed = True


class _ControlStoreW08LeaseAuthority:
    """Accepted ControlStore W08 acquisition/fencing authority for exact migration 8."""

    def acquire(
        self, path: Path, request: ProductionDcsV8AdoptionRequest
    ) -> _ControlStoreHeldW08Lease:
        attempt_id = uuid4().hex
        owner_id = f"DCS_V8_ADOPTION:{attempt_id}"
        semantic = {
            "change_id": CHANGE_ID,
            "operation_id": request.operation_id,
            "attempt_id": attempt_id,
            "target_schema_version": 8,
        }
        acquire_key = operation_key("production-dcs-v8-adoption-w08-acquire", semantic)
        release_key = operation_key("production-dcs-v8-adoption-w08-release", semantic)
        try:
            store = ControlStore(
                path,
                migrate_schema=False,
                require_schema_version=7,
                global_writer_guard_required=False,
            )
        except BaseException as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_STORE_OPEN_FAILED",
                type(error).__name__,
                phase="SERIALIZATION",
            ) from error
        try:
            row = store.acquire_global_production_writer(
                operation_key=acquire_key,
                owner_id=owner_id,
                owner_execution_id=attempt_id,
                change_id=CHANGE_ID,
                slice_id=request.operation_id,
                writer_class="DCS_V8_ADOPTION_CONTROL",
                owner_session_role="CONTROL_PATH",
                track="CLEANER_POSTGRES_AUTHORITY_CUTOVER",
                repository_or_runtime="ADCP_CONTROL_DCS",
                operation_class="DCS_SCHEMA_V7_TO_V8_MIGRATION",
                target="GLOBAL_PRODUCTION",
                control_decision_ref=HQ_DCS_DECISION,
            )
        except StoreError as error:
            store.close()
            code = (
                "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_W08_NOT_FREE"
                if error.code == "GLOBAL_PRODUCTION_WRITER_HELD"
                else "PRODUCTION_DCS_V8_ADOPTION_W08_ACQUIRE_FAILED"
            )
            raise ProductionDcsV8AdoptionError(code, error.code, phase="SERIALIZATION") from error
        events = store.global_production_writer_events()
        if not events:
            store.close()
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_GLOBAL_WRITER_EVENT_CURSOR_MISSING",
                phase="SERIALIZATION",
            )
        latest = events[-1]
        if (
            latest["event_type"] not in {"ACQUIRE", "EXPIRED_TAKEOVER"}
            or latest["new_owner_id"] != owner_id
            or int(latest["to_fencing_token"]) != int(row["fencing_token"])
        ):
            store.close()
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_GLOBAL_WRITER_EVENT_CURSOR_INVALID",
                phase="SERIALIZATION",
            )
        return _ControlStoreHeldW08Lease(
            path=path,
            store=store,
            owner_id=owner_id,
            fencing_token=int(row["fencing_token"]),
            release_operation_key=release_key,
            event_cursor=int(latest["event_seq"]),
        )


def _inspect_exact_profile(path: Path) -> _DcsProfile:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    try:
        try:
            integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        except sqlite3.Error as error:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_INTEGRITY_FAILED") from error
        if integrity != ["ok"]:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_INTEGRITY_FAILED")
        try:
            foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        except sqlite3.Error as error:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_FOREIGN_KEY_VIOLATION") from error
        if foreign_keys:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_FOREIGN_KEY_VIOLATION")
        try:
            versions = tuple(int(row[0]) for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            ))
        except sqlite3.Error as error:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_SCHEMA_UNREADABLE") from error
        if not versions:
            raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_SCHEMA_VERSION_UNSUPPORTED", "0")
        version = versions[-1]
        if version not in _PROFILE_BY_VERSION or versions != tuple(range(1, version + 1)):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_SCHEMA_VERSION_UNSUPPORTED", str(version)
            )
        try:
            profile = schema_profile_identity(connection, version)
        except BaseException as error:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_SCHEMA_PROFILE_INVALID", str(version)
            ) from error
        if profile != _PROFILE_BY_VERSION[version]:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_SCHEMA_PROFILE_INVALID", str(version)
            )
        return _DcsProfile(version, profile, "ok", 0)
    finally:
        connection.close()


def _w08_free(path: Path) -> Mapping[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    try:
        row = connection.execute(
            "SELECT state,owner_id,writer_class,operation_class,target,fencing_token "
            "FROM global_production_writer_lease WHERE resource_key='GLOBAL_PRODUCTION'"
        ).fetchone()
    except sqlite3.Error as error:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_W08_STATE_UNREADABLE") from error
    finally:
        connection.close()
    if row is None:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_W08_STATE_UNREADABLE")
    state, owner_id, writer_class, operation_class, target, token = row
    occupied = any(value not in (None, "") for value in (owner_id, writer_class, operation_class, target))
    if state != "FREE" or occupied:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_V8_ADOPTION_BLOCKED_W08_NOT_FREE")
    return {"state": state, "fencing_token": int(token)}


def _validate_operation_id(operation_id: str) -> None:
    if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 200:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_V8_ADOPTION_OPERATION_ID_INVALID")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:/" for ch in operation_id):
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_V8_ADOPTION_OPERATION_ID_INVALID")


class _ProductionDcsV8AdoptionController:
    def __init__(
        self,
        *,
        path: Path,
        writers: _WriterAuthority,
        migrations: _MigrationAuthority,
        profile_reader: Callable[[Path], _DcsProfile] = _inspect_exact_profile,
        w08_reader: Callable[[Path], Mapping[str, Any]] = _w08_free,
        w08_authority: _W08LeaseAuthority | None = None,
    ) -> None:
        self.path = path
        self.writers = writers
        self.migrations = migrations
        self.profile_reader = profile_reader
        self.w08_reader = w08_reader
        self.w08_authority = (
            _ControlStoreW08LeaseAuthority() if w08_authority is None else w08_authority
        )

    def _compatible(self, inventory: DcsWriterInventory) -> None:
        if not inventory.all_support_v8:
            incompatible = [
                f"{entry.writer_id}:{entry.client.version}:{entry.client.classification}"
                for entry in inventory.entries
                if not entry.client.supports_v8
            ]
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_CLIENT_INCOMPATIBLE",
                ",".join(incompatible),
            )

    def run(self, request: ProductionDcsV8AdoptionRequest) -> ProductionDcsV8AdoptionResult:
        _validate_operation_id(request.operation_id)
        initial = self.writers.discover()
        # Compatibility remains the first gate.  Current Production 0.1.0
        # clients therefore fail before profile reads, quiescence or W08 acquire.
        self._compatible(initial)
        profile = self.profile_reader(self.path)
        before_version = profile.version
        # Revalidate exact writer identities immediately before any quiescence effect.
        try:
            rebound = self.writers.discover()
        except ProductionDcsV8AdoptionError as error:
            if (
                any(entry.state == "INACTIVE" for entry in initial.entries)
                and error.code
                in {
                    "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH",
                    "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED",
                }
            ):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED"
                ) from error
            raise
        if _inactive_startup_authority_changed(initial, rebound):
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED"
            )
        if rebound.fingerprint != initial.fingerprint:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_INVENTORY_CHANGED"
            )
        if profile.version == 8:
            final_w08 = self.w08_reader(self.path)
            return ProductionDcsV8AdoptionResult(
                request.operation_id, 8, 8, "ALREADY_ADOPTED_EXACT", (), initial.fingerprint,
                len(initial.entries), tuple(entry.client.build_identity for entry in initial.entries),
                True, False, str(final_w08["state"]), profile.schema_profile_identity,
            )

        token: _QuiescenceToken | None = None
        held_w08: _HeldW08LeaseAuthority | None = None
        held_w08_token: int | None = None
        migration_versions: list[int] = []
        migration_started = False
        migration8_completed = False
        committed_v8 = False
        w08_safely_released = False
        fenced_physical = callable(getattr(self.writers, "quiesce_fenced", None)) and callable(
            getattr(self.writers, "resume_fenced", None)
        )
        migrations_fence_v6 = bool(getattr(self.migrations, "handles_physical_quiescence", False))

        def _held_event_guard() -> None:
            if held_w08 is None:
                return
            guard = getattr(held_w08, "assert_event_guard", None)
            if callable(guard):
                guard()

        try:
            # Legacy/injected adapters preserve their old outer quiescence behavior.
            # The real launchd authority defers physical effects until a migration
            # GLOBAL_PRODUCTION fence has been acquired.
            if not fenced_physical:
                token = self.writers.quiesce(initial)
                self.writers.verify_quiesced(token)
                profile = self.profile_reader(self.path)
                if profile.version != before_version:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_SCHEMA_CHANGED_DURING_QUIESCENCE", phase="QUIESCENCE"
                    )

            if profile.version == 6:
                migration_started = True
                if fenced_physical and not migrations_fence_v6:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V6_TO_V7_FENCED_QUIESCENCE_AUTHORITY_MISSING",
                        phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
                    )
                self.migrations.run_v6_to_v7(self.path, initial)
                migration_versions.append(7)
                profile = self.profile_reader(self.path)
                if profile.version != 7:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V6_TO_V7_POSTCONDITION_FAILED", phase="MIGRATION"
                    )

            if profile.version == 7:
                # Real Production path: ACQUIRE -> ASSERT/EVENT -> physical A+B
                # quiesce -> stable proof -> migrate. Test doubles without the
                # fenced surface retain the previously accepted ordering.
                held_w08 = self.w08_authority.acquire(self.path, request)
                held_w08_token = held_w08.fencing_token
                if held_w08.assert_current() != held_w08_token:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_W08_FENCING_TOKEN_CHANGED",
                        phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
                    )
                _held_event_guard()
                if fenced_physical:
                    current_inventory = self.writers.discover()
                    if _stable_inventory_fingerprint(current_inventory.entries) != _stable_inventory_fingerprint(initial.entries):
                        raise ProductionDcsV8AdoptionError(
                            "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_INVENTORY_CHANGED",
                            phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
                        )
                    token = self.writers.quiesce_fenced(
                        current_inventory,
                        assert_current=held_w08.assert_current,
                        assert_event_guard=_held_event_guard,
                    )
                    self.writers.verify_quiesced(token)
                    held_w08.assert_current()
                    _held_event_guard()
                elif token is None:
                    token = self.writers.quiesce(initial)
                    self.writers.verify_quiesced(token)

                profile = self.profile_reader(self.path)
                if profile.version != 7:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_SCHEMA_CHANGED_BEFORE_V8_MIGRATION", phase="SERIALIZATION"
                    )
                if held_w08.assert_current() != held_w08_token:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_W08_FENCING_TOKEN_CHANGED",
                        phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
                    )
                _held_event_guard()
                migration_started = True
                self.migrations.run_v7_to_v8(self.path)
                migration_versions.append(8)
                migration8_completed = True
                committed_v8 = True
                profile = self.profile_reader(self.path)
                if profile.version != 8:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V7_TO_V8_POSTCONDITION_FAILED",
                        phase="POST_MIGRATION", recovery_status="RECOVERY_REQUIRED",
                    )
                rebound_token = held_w08.reopen_exact_schema(8)
                if rebound_token != held_w08_token or held_w08.assert_current() != held_w08_token:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_W08_FENCING_TOKEN_CHANGED",
                        phase="POST_MIGRATION", schema_version=8,
                        recovery_status="RECOVERY_REQUIRED",
                    )
                _held_event_guard()
                # Legacy injected paths keep their previous release-before-resume
                # contract. Real fenced physical restore must occur under same lease.
                if not fenced_physical:
                    released = held_w08.release()
                    if (
                        released.get("state") != "FREE"
                        or int(released.get("fencing_token", -1)) != held_w08_token
                    ):
                        raise ProductionDcsV8AdoptionError(
                            "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED",
                            "readback", phase="POST_MIGRATION", schema_version=8,
                            recovery_status="RECOVERY_REQUIRED",
                        )
                    held_w08.close()
                    held_w08 = None
                    final_w08 = self.w08_reader(self.path)
                    if (
                        final_w08.get("state") != "FREE"
                        or int(final_w08.get("fencing_token", -1)) != held_w08_token
                    ):
                        raise ProductionDcsV8AdoptionError(
                            "PRODUCTION_DCS_V8_ADOPTION_W08_FREE_READBACK_FAILED",
                            phase="POST_MIGRATION", schema_version=8,
                            recovery_status="RECOVERY_REQUIRED",
                        )
                    w08_safely_released = True

            if profile.version != 8:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POSTCONDITION_FAILED", phase="MIGRATION"
                )
            if token is None:
                resumed = self.writers.discover()
            else:
                if fenced_physical and held_w08 is not None:
                    held_w08.assert_current(); _held_event_guard()
                    self.writers.resume_fenced(
                        token,
                        schema_version=profile.version,
                        assert_current=held_w08.assert_current,
                        assert_event_guard=_held_event_guard,
                    )
                    held_w08.assert_current(); _held_event_guard()
                else:
                    self.writers.resume(token)
                resumed = self.writers.verify_resumed(token)

            if _stable_inventory_fingerprint(resumed.entries) != _stable_inventory_fingerprint(initial.entries):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            active_before = {entry.writer_id for entry in initial.entries if _entry_before_class(entry) == "A"}
            active_after = {entry.writer_id for entry in resumed.entries if entry.state == "ACTIVE"}
            if active_after != active_before:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )

            if fenced_physical and held_w08 is not None:
                held_w08.assert_current(); _held_event_guard()
                released = held_w08.release()
                if (
                    released.get("state") != "FREE"
                    or held_w08_token is None
                    or int(released.get("fencing_token", -1)) != held_w08_token
                ):
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED",
                        "readback", phase="POST_MIGRATION", schema_version=8,
                        recovery_status="RECOVERY_REQUIRED",
                    )
                held_w08.close(); held_w08 = None
                w08_safely_released = True

            final_w08 = self.w08_reader(self.path)
            if held_w08_token is not None and (
                final_w08.get("state") != "FREE"
                or int(final_w08.get("fencing_token", -1)) != held_w08_token
            ):
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_W08_FREE_READBACK_FAILED",
                    phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
                )
            final_profile = self.profile_reader(self.path)
            if final_profile.version != 8:
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POSTCONDITION_FAILED", phase="POST_MIGRATION"
                )
            return ProductionDcsV8AdoptionResult(
                request.operation_id,
                before_version,
                8,
                "ADOPTED_EXACT",
                tuple(migration_versions),
                initial.fingerprint,
                len(initial.entries),
                tuple(entry.client.build_identity for entry in initial.entries),
                True,
                False,
                "FREE",
                final_profile.schema_profile_identity,
            )
        except BaseException as error:
            # Before migration 8 completes we may restore only after proving our
            # held W08 lease was safely released and is FREE.  A lost/stolen or
            # unreleasable lease is an explicit recovery-required stop.
            if held_w08 is not None and not migration8_completed:
                try:
                    if fenced_physical and token is not None:
                        # Rollback/recovery before schema-8 commit restores exact A/B/C
                        # baseline while the same W08 fence is still current.
                        held_w08.assert_current(); _held_event_guard()
                        rollback_schema = self.profile_reader(self.path).version
                        self.writers.resume_fenced(
                            token,
                            schema_version=rollback_schema,
                            assert_current=held_w08.assert_current,
                            assert_event_guard=_held_event_guard,
                        )
                        self.writers.verify_resumed(token)
                        held_w08.assert_current(); _held_event_guard()
                        token = None
                    released = held_w08.release()
                    if (
                        released.get("state") != "FREE"
                        or held_w08_token is None
                        or int(released.get("fencing_token", -1)) != held_w08_token
                    ):
                        raise ProductionDcsV8AdoptionError(
                            "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED", "readback"
                        )
                    held_w08.close()
                    held_w08 = None
                    free = self.w08_reader(self.path)
                    if (
                        free.get("state") != "FREE"
                        or int(free.get("fencing_token", -1)) != held_w08_token
                    ):
                        raise ProductionDcsV8AdoptionError(
                            "PRODUCTION_DCS_V8_ADOPTION_W08_FREE_READBACK_FAILED"
                        )
                    w08_safely_released = True
                except BaseException as recovery_error:
                    try:
                        held_w08.close()
                    except BaseException:
                        pass
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_W08_RECOVERY_REQUIRED",
                        type(error).__name__,
                        phase="RECOVERY",
                        schema_version=self.profile_reader(self.path).version,
                        recovery_status="RECOVERY_REQUIRED",
                    ) from recovery_error
            elif held_w08 is not None:
                # After migration 8 completed, ambiguity in same-lease proof or
                # release is never converted into ADOPTED_EXACT or writer resume.
                try:
                    held_w08.close()
                except BaseException:
                    pass
                if isinstance(error, ProductionDcsV8AdoptionError) and error.recovery_status == "RECOVERY_REQUIRED":
                    raise
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_W08_RECOVERY_REQUIRED",
                    type(error).__name__, phase="RECOVERY", schema_version=8,
                    recovery_status="RECOVERY_REQUIRED",
                ) from error

            if token is not None and not committed_v8 and (held_w08_token is None or w08_safely_released):
                try:
                    self.writers.resume(token)
                    self.writers.verify_resumed(token)
                except BaseException as recovery_error:
                    raise ProductionDcsV8AdoptionError(
                        "PRODUCTION_DCS_V8_ADOPTION_RECOVERY_REQUIRED",
                        type(error).__name__,
                        phase="RECOVERY",
                        schema_version=self.profile_reader(self.path).version,
                        recovery_status="WRITER_RESTORE_FAILED",
                    ) from recovery_error
            if committed_v8:
                if isinstance(error, ProductionDcsV8AdoptionError) and error.recovery_status == "RECOVERY_REQUIRED":
                    raise
                raise ProductionDcsV8AdoptionError(
                    "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
                    type(error).__name__, phase="POST_MIGRATION", schema_version=8,
                    recovery_status="RECOVERY_REQUIRED",
                ) from error
            if isinstance(error, ProductionDcsV8AdoptionError):
                raise
            code = (
                "PRODUCTION_DCS_V8_ADOPTION_MIGRATION_FAILED"
                if migration_started
                else "PRODUCTION_DCS_V8_ADOPTION_QUIESCENCE_FAILED"
            )
            raise ProductionDcsV8AdoptionError(
                code,
                type(error).__name__,
                phase="MIGRATION" if migration_started else "QUIESCENCE",
                recovery_status="WRITERS_RESTORED" if token is not None else "NOT_REQUIRED",
            ) from error


def discover_production_dcs_writers() -> DcsWriterInventory:
    """Read-only exact inventory of effective launchd services bound to canonical DCS."""

    return _LaunchdWriterAuthority().discover()


def run_production_dcs_v8_adoption(
    request: ProductionDcsV8AdoptionRequest,
) -> ProductionDcsV8AdoptionResult:
    """Run only the canonical Production DCS exact-v8 adoption state machine."""

    if type(request) is not ProductionDcsV8AdoptionRequest:
        raise ProductionDcsV8AdoptionError("PRODUCTION_DCS_V8_ADOPTION_REQUEST_INVALID")
    writers = _LaunchdWriterAuthority()
    controller = _ProductionDcsV8AdoptionController(
        path=CANONICAL_DCS_PATH,
        writers=writers,
        migrations=_ExactMigrationAuthority(writers),
    )
    return controller.run(request)


__all__ = [
    "CANONICAL_DCS_PATH",
    "CHANGE_ID",
    "DcsWriterClientIdentity",
    "DcsWriterInventory",
    "DcsWriterInventoryEntry",
    "HQ_DCS_DECISION",
    "ProductionDcsV8AdoptionError",
    "ProductionDcsV8AdoptionRequest",
    "ProductionDcsV8AdoptionResult",
    "TARGET_SCHEMA_VERSION",
    "discover_production_dcs_writers",
    "run_production_dcs_v8_adoption",
]
