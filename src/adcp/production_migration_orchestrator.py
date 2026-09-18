"""Frozen schema-v6 to schema-v7 Production migration orchestration boundary.

The module deliberately contains no migration SQL, restore path, force-repair
path, or ordinary ``ControlStore`` lease.  It coordinates the accepted thin
Global Writer client and the accepted migration registry around one forward
migration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import uuid4

from adcp.store import migrations as _migrations


CHANGE_ID = "ADCP-V6V7-PRODUCTION-MIGRATION-ORCHESTRATOR-01A"
RESOURCE = "GLOBAL_PRODUCTION"
LEASE_WRITER_CLASS = "ADCP_PRODUCTION_MIGRATION_ORCHESTRATOR"
LEASE_OPERATION_CLASS = "PRODUCTION_SCHEMA_MIGRATION"
SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7)
MIGRATION_VERSION = 7
MIGRATION_NAME = "0007_evaluator_artifact_seal"
MIGRATION_CHECKSUM = "e2488288c73cfb0572430eb38bfd4279b98ddaf4b5eb81468d0b7a666c495596"
LEASE_TTL_SECONDS = 300
HEARTBEAT_TARGET_SECONDS = 15
PRE_BEGIN_MIN_REMAINING_HORIZON_SECONDS = 240
MIGRATION_TRANSACTION_BUDGET_SECONDS = 30
POST_TRANSACTION_REBIND_MAX_DELAY_SECONDS = 15
EXPECTED_WRITER_CODES = frozenset(f"W{number:02d}" for number in range(1, 10))
PROPERTYAI_WRITER_CODES = frozenset(f"W{number:02d}" for number in range(1, 8))
ADCP_WRITER_CODES = frozenset({"W08", "W09"})
_LEASE_CONTEXT_FIELDS = (
    "resource_key", "owner_id", "owner_execution_id", "change_id", "slice_id",
    "writer_class", "owner_session_role", "track", "repository_or_runtime",
    "operation_class", "target", "fencing_token", "acquired_at",
)
_LEASE_LIFECYCLE_FIELDS = frozenset({"state", "expires_at", "heartbeat_at", "updated_at"})


class _ExecutionState(str, Enum):
    NOT_YET_QUIESCED = "NOT_YET_QUIESCED"
    QUIESCED_PRE_TRANSACTION = "QUIESCED_PRE_TRANSACTION"
    MIGRATION_TRANSACTION_OR_ROLLBACK = "MIGRATION_TRANSACTION_OR_ROLLBACK"
    COMMITTED_V7 = "COMMITTED_V7"
    AMBIGUOUS_AUTHORITY = "AMBIGUOUS_AUTHORITY"


class ProductionMigrationError(RuntimeError):
    """Fail-closed error with a stable evidence code and transition phase."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        phase: str = "PREFLIGHT",
        schema_version: int | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.phase = phase
        self.schema_version = schema_version
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class ExecutionContext:
    dcs_path: Path
    evidence_root: Path
    accepted_git_head: str
    accepted_git_tree: str
    authority_ref: str
    owner_execution_id: str | None = None
    canonical_production_path: Path | None = None
    canonical_production_authorization: object | None = None
    background_heartbeat: bool = True


@dataclass(frozen=True)
class RuntimeWriter:
    """Execution-time evidence for one write-capable runtime identity."""

    service_code: str
    runtime_id: str
    classification: str
    state: str
    identity_validation: str = "MATCH"
    write_capable: bool = True
    conflicting: bool = False

    @property
    def identity(self) -> tuple[str, str]:
        return (self.service_code, self.runtime_id)


class QuiescenceAdapter(Protocol):
    def discover(self) -> Sequence[RuntimeWriter]: ...
    def quiesce(self, writer: RuntimeWriter) -> None: ...
    def inspect(self, writer: RuntimeWriter) -> RuntimeWriter: ...
    def reactivate(self, writer: RuntimeWriter) -> None: ...


class FreshAuthority(Protocol):
    def validate(self) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True)
class TableFingerprint:
    columns: tuple[str, ...]
    row_count: int
    sha256: str


@dataclass(frozen=True)
class ExactRowSet:
    """Typed SQLite rows bound to the table's complete ordinal column shape."""

    columns: tuple[str, ...]
    rows: tuple[tuple[tuple[str, str], ...], ...]


@dataclass(frozen=True)
class PreservationBaseline:
    tables: Mapping[str, TableFingerprint]
    authority: Mapping[str, Any]
    lease: Mapping[str, Any]
    schema_migration_0001_0006: ExactRowSet


@dataclass(frozen=True)
class BackupEvidence:
    evidence_directory: Path
    backup_path: Path
    manifest_path: Path
    manifest_identity: str
    source_sha256: str
    backup_sha256: str
    source_size: int
    backup_size: int


@dataclass(frozen=True)
class ProductionMigrationResult:
    owner_id: str
    owner_execution_id: str
    fencing_token: int
    previous_version: int
    version: int
    backup: BackupEvidence
    preserved_table_count: int
    quiesced_identities: tuple[tuple[str, str], ...]
    final_lease_state: str
    production_effect: int = 0


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


class _CallableAuthority:
    def __init__(self, callback: Callable[[], Mapping[str, Any] | None]) -> None:
        self._callback = callback

    def validate(self) -> Mapping[str, Any] | None:
        return self._callback()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _operation_key(label: str, owner_execution_id: str) -> str:
    return _sha256_bytes(f"{CHANGE_ID}:{owner_execution_id}:{label}".encode("utf-8"))


def _file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _fsync_file(path: Path, failure_code: str) -> None:
    """Synchronize one already-created immutable artifact without rewriting it."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as error:
        raise ProductionMigrationError(failure_code, f"{path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Durably publish create-new entries in an evidence directory."""

    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as error:
        raise ProductionMigrationError("BACKUP_DIRECTORY_FSYNC_FAILED", f"{path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _normalize_sqlite_value(value: Any) -> Mapping[str, str]:
    if value is None:
        return {"type": "null", "value": ""}
    if isinstance(value, bool):
        return {"type": "integer", "value": "1" if value else "0"}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "real", "value": value.hex()}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": "blob", "value": bytes(value).hex()}
    raise ProductionMigrationError("FINGERPRINT_SQLITE_TYPE_UNSUPPORTED", type(value).__name__)


def canonical_table_fingerprint(connection: sqlite3.Connection, table: str) -> TableFingerprint:
    """Fingerprint explicit ordinal columns and typed, order-independent rows."""

    quoted = table.replace('"', '""')
    columns = tuple(row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")'))
    if not columns:
        raise ProductionMigrationError("CANONICAL_TABLE_MISSING", table)
    column_sql = ",".join('"' + name.replace('"', '""') + '"' for name in columns)
    rows: list[str] = []
    for values in connection.execute(f'SELECT {column_sql} FROM "{quoted}"'):
        material = [
            {"column": column, **_normalize_sqlite_value(value)}
            for column, value in zip(columns, values, strict=True)
        ]
        rows.append(_canonical_json(material))
    rows.sort()
    payload = _canonical_json({"columns": list(columns), "rows": rows}).encode("utf-8")
    return TableFingerprint(columns, len(rows), _sha256_bytes(payload))


def _capture_schema_migration_0001_0006(connection: sqlite3.Connection) -> ExactRowSet:
    """Capture every physical column of canonical rows 0001 through 0006."""

    columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(schema_migration)"))
    if not columns or "version" not in columns:
        raise ProductionMigrationError("MIGRATION_REGISTRY_SHAPE_INVALID")
    column_sql = ",".join('"' + name.replace('"', '""') + '"' for name in columns)
    raw_rows = tuple(connection.execute(
        f'SELECT {column_sql} FROM "schema_migration" WHERE version BETWEEN 1 AND 6 ORDER BY version'
    ))
    version_index = columns.index("version")
    if tuple(row[version_index] for row in raw_rows) != tuple(range(1, 7)):
        raise ProductionMigrationError("MIGRATION_REGISTRY_0001_0006_INCOMPLETE")
    typed_rows = tuple(
        tuple(
            (normalized["type"], normalized["value"])
            for value in row
            for normalized in (_normalize_sqlite_value(value),)
        )
        for row in raw_rows
    )
    return ExactRowSet(columns, typed_rows)


def _thin_contract():
    try:
        from adcp_global_writer_client.schema_contract import verify_schema_contract
    except ImportError as error:  # pragma: no cover - installation evidence
        raise ProductionMigrationError("A_THIN_CLIENT_UNAVAILABLE", str(error)) from error
    contract = verify_schema_contract()
    if tuple(contract.supported_dcs_schema_versions) != SUPPORTED_DCS_SCHEMA_VERSIONS:
        raise ProductionMigrationError("A_THIN_CLIENT_SCHEMA_RANGE_MISMATCH")
    return contract


def _default_client_factory(path: Path, clock: Callable[[], datetime] | None = None):
    try:
        from adcp_global_writer_client import GlobalWriterControlClient
    except ImportError as error:  # pragma: no cover - installation evidence
        raise ProductionMigrationError("A_THIN_CLIENT_UNAVAILABLE", str(error)) from error
    return GlobalWriterControlClient(path, _clock=clock)


def _read_schema_version(path: Path) -> int:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = list(connection.execute("SELECT version FROM schema_migration ORDER BY version"))
    except sqlite3.Error as error:
        raise ProductionMigrationError("SCHEMA_VERSION_UNREADABLE", str(error)) from error
    finally:
        connection.close()
    return int(rows[-1][0]) if rows else 0


def _validate_profile_connection(connection: sqlite3.Connection, version: int) -> Any:
    profile = _thin_contract().profile_for_version(version)
    rows = tuple(tuple(row) for row in connection.execute(
        "SELECT version,name,checksum FROM schema_migration ORDER BY version"
    ))
    if rows != profile.migration_history:
        raise ProductionMigrationError("MIGRATION_REGISTRY_MISMATCH", repr(rows))
    schema_rows = list(connection.execute(
        "SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' "
        "AND type IN ('table','index','trigger','view') ORDER BY type,name"
    ))
    actual = {
        "table": frozenset(name for kind, name, _ in schema_rows if kind == "table"),
        "index": frozenset(name for kind, name, _ in schema_rows if kind == "index"),
        "trigger": frozenset(name for kind, name, _ in schema_rows if kind == "trigger"),
        "view": frozenset(name for kind, name, _ in schema_rows if kind == "view"),
    }
    if actual["table"] != profile.expected_tables or actual["index"] != profile.expected_indexes:
        raise ProductionMigrationError("SCHEMA_OBJECT_INVENTORY_MISMATCH")
    if actual["trigger"] != profile.expected_triggers or actual["view"]:
        raise ProductionMigrationError("SCHEMA_OBJECT_INVENTORY_MISMATCH")
    expected_fingerprints = {
        (kind, name): digest for kind, name, digest in profile.expected_object_fingerprints
    }
    observed_fingerprints = {}
    for kind, name, sql in schema_rows:
        if not isinstance(sql, str):
            raise ProductionMigrationError("SCHEMA_OBJECT_SQL_MISSING", f"{kind}:{name}")
        normalized = sql.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
        observed_fingerprints[(kind, name)] = _sha256_bytes(normalized.encode("utf-8"))
    if observed_fingerprints != expected_fingerprints:
        raise ProductionMigrationError("SCHEMA_OBJECT_FINGERPRINT_MISMATCH")
    integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
    foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
    if integrity != ["ok"]:
        raise ProductionMigrationError("SQLITE_INTEGRITY_FAILED", repr(integrity))
    if foreign_keys:
        raise ProductionMigrationError("SQLITE_FOREIGN_KEY_FAILED", repr(foreign_keys))
    return profile, integrity, foreign_keys


def capture_preservation_baseline(path: Path, version: int = 6) -> PreservationBaseline:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        profile, _, _ = _validate_profile_connection(connection, version)
        fingerprints = {
            table: canonical_table_fingerprint(connection, table)
            for table in sorted(profile.expected_tables)
        }
        authority_row = connection.execute(
            "SELECT * FROM control_authority_state WHERE singleton_id='GLOBAL'"
        ).fetchone()
        lease_row = connection.execute(
            "SELECT * FROM global_production_writer_lease WHERE resource_key='GLOBAL_PRODUCTION'"
        ).fetchone()
        if authority_row is None or lease_row is None:
            raise ProductionMigrationError("CANONICAL_SINGLETON_MISSING")
        authority_columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(control_authority_state)"))
        lease_columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(global_production_writer_lease)"))
        return PreservationBaseline(
            fingerprints,
            dict(zip(authority_columns, authority_row, strict=True)),
            dict(zip(lease_columns, lease_row, strict=True)),
            _capture_schema_migration_0001_0006(connection),
        )
    finally:
        connection.close()


def _manifest_payload(
    context: ExecutionContext,
    owner_id: str,
    owner_execution_id: str,
    fencing_token: int,
    timestamp_value: str,
    source_identity: Mapping[str, Any],
    source_digest: tuple[str, int],
    backup_digest: tuple[str, int],
    baseline: PreservationBaseline,
) -> dict[str, Any]:
    table_material = {
        name: asdict(value) for name, value in sorted(baseline.tables.items())
    }
    authority = baseline.authority
    return {
        "format_version": 1,
        "change_id": CHANGE_ID,
        "resource": RESOURCE,
        "canonical_dcs": dict(source_identity),
        "pre_schema_version": 6,
        "migration_registry": asdict(baseline.schema_migration_0001_0006),
        "source_sha256": source_digest[0],
        "source_size": source_digest[1],
        "backup_sha256": backup_digest[0],
        "backup_size": backup_digest[1],
        "source_integrity_check": ["ok"],
        "backup_integrity_check": ["ok"],
        "source_foreign_key_check": [],
        "backup_foreign_key_check": [],
        "table_fingerprints": table_material,
        "authority_mode": authority["mode"],
        "authority_generation": authority["authority_generation"],
        "cutover_identity": authority["cutover_id"],
        "lease_owner_id": owner_id,
        "lease_owner_execution_id": owner_execution_id,
        "lease_fencing_token": fencing_token,
        "accepted_git_head": context.accepted_git_head,
        "accepted_git_tree": context.accepted_git_tree,
        "authority_ref": context.authority_ref,
        "migration_version": MIGRATION_VERSION,
        "migration_name": MIGRATION_NAME,
        "migration_checksum": MIGRATION_CHECKSUM,
        "created_at": timestamp_value,
    }


def create_immutable_backup(
    context: ExecutionContext,
    *,
    owner_id: str,
    owner_execution_id: str,
    fencing_token: int,
    now: datetime,
) -> BackupEvidence:
    """Create and verify one create-new-only, orchestrator-owned online backup."""

    path = context.dcs_path.expanduser().resolve(strict=True)
    before = path.stat()
    timestamp_value = now.astimezone(timezone.utc).isoformat(timespec="microseconds")
    identity_seed = _canonical_json({
        "path": str(path), "device": before.st_dev, "inode": before.st_ino,
        "owner": owner_id, "execution": owner_execution_id, "fence": fencing_token,
        "timestamp": timestamp_value,
    })
    evidence_identity = _sha256_bytes(identity_seed.encode("utf-8"))
    evidence_directory = context.evidence_root / f"v6-v7-{evidence_identity}"
    try:
        evidence_directory.mkdir(parents=False, mode=0o700)
    except FileExistsError as error:
        raise ProductionMigrationError("BACKUP_EVIDENCE_COLLISION", str(evidence_directory)) from error
    except OSError as error:
        raise ProductionMigrationError("BACKUP_EVIDENCE_CREATE_FAILED", str(error)) from error
    backup_path = evidence_directory / "canonical-v6.sqlite3.bak"
    manifest_path = evidence_directory / "manifest.json"
    descriptor = os.open(backup_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    destination = sqlite3.connect(backup_path)
    try:
        source.execute("PRAGMA foreign_keys=ON")
        _validate_profile_connection(source, 6)
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    os.chmod(backup_path, stat.S_IRUSR)
    _fsync_file(backup_path, "BACKUP_FILE_FSYNC_FAILED")
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise ProductionMigrationError("SOURCE_IDENTITY_CHANGED_DURING_BACKUP")
    source_digest = _file_digest(path)
    backup_digest = _file_digest(backup_path)
    baseline = capture_preservation_baseline(path, 6)
    backup_connection = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    try:
        _validate_profile_connection(backup_connection, 6)
        backup_baseline = {
            table: canonical_table_fingerprint(backup_connection, table)
            for table in sorted(baseline.tables)
        }
    finally:
        backup_connection.close()
    if backup_baseline != baseline.tables:
        raise ProductionMigrationError("BACKUP_LOGICAL_CONTENT_MISMATCH")
    source_identity = {
        "path": str(path), "device": before.st_dev, "inode": before.st_ino,
    }
    payload = _manifest_payload(
        context, owner_id, owner_execution_id, fencing_token, timestamp_value,
        source_identity, source_digest, backup_digest, baseline,
    )
    manifest_identity = _sha256_bytes(_canonical_json(payload).encode("utf-8"))
    document = {**payload, "manifest_identity": manifest_identity}
    encoded = (_canonical_json(document) + "\n").encode("utf-8")
    descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
    os.chmod(manifest_path, stat.S_IRUSR)
    _fsync_file(manifest_path, "BACKUP_MANIFEST_FSYNC_FAILED")
    if manifest_path.read_bytes() != encoded or _file_digest(backup_path) != backup_digest:
        raise ProductionMigrationError("BACKUP_MANIFEST_VERIFICATION_FAILED")
    os.chmod(evidence_directory, stat.S_IRUSR | stat.S_IXUSR)
    # The child directory publishes both artifacts; its parent publishes the
    # create-new evidence directory itself.  Both metadata boundaries must be
    # durable before migration can begin.
    _fsync_directory(evidence_directory)
    _fsync_directory(context.evidence_root)
    return BackupEvidence(
        evidence_directory, backup_path, manifest_path, manifest_identity,
        source_digest[0], backup_digest[0], source_digest[1], backup_digest[1],
    )


def verify_immutable_backup(evidence: BackupEvidence) -> None:
    """Re-verify immutable evidence immediately before the migration gate."""

    try:
        raw = evidence.manifest_path.read_text(encoding="utf-8")
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ProductionMigrationError("BACKUP_MANIFEST_TAMPERED", str(error)) from error
    if not isinstance(document, dict) or raw != _canonical_json(document) + "\n":
        raise ProductionMigrationError("BACKUP_MANIFEST_TAMPERED")
    identity = document.get("manifest_identity")
    payload = {key: value for key, value in document.items() if key != "manifest_identity"}
    if identity != evidence.manifest_identity or identity != _sha256_bytes(_canonical_json(payload).encode("utf-8")):
        raise ProductionMigrationError("BACKUP_MANIFEST_TAMPERED")
    backup_digest = _file_digest(evidence.backup_path)
    if backup_digest != (document.get("backup_sha256"), document.get("backup_size")):
        raise ProductionMigrationError("BACKUP_FILE_TAMPERED")
    connection = sqlite3.connect(f"file:{evidence.backup_path}?mode=ro", uri=True)
    try:
        profile, _, _ = _validate_profile_connection(connection, 6)
        observed = json.loads(_canonical_json({
            table: asdict(canonical_table_fingerprint(connection, table))
            for table in sorted(profile.expected_tables)
        }))
    finally:
        connection.close()
    if observed != document.get("table_fingerprints"):
        raise ProductionMigrationError("BACKUP_FINGERPRINT_TAMPERED")
    if evidence.backup_path.stat().st_mode & 0o222 or evidence.manifest_path.stat().st_mode & 0o222:
        raise ProductionMigrationError("BACKUP_EVIDENCE_WRITABLE")


class _HeartbeatPump:
    def __init__(self, path: Path, owner_id: str, token: int, client_factory, clock) -> None:
        self._path = path
        self._owner = owner_id
        self._token = token
        self._factory = client_factory
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None

    def start(self) -> None:
        def work() -> None:
            while not self._stop.wait(HEARTBEAT_TARGET_SECONDS):
                try:
                    client = self._factory(self._path, self._clock.now)
                    try:
                        client.heartbeat(self._owner, self._token, LEASE_TTL_SECONDS)
                    finally:
                        client.close()
                except BaseException as error:
                    self.error = error
                    return
        self._thread = threading.Thread(target=work, name="v6-v7-migration-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=HEARTBEAT_TARGET_SECONDS + 1)
            if self._thread.is_alive():
                raise ProductionMigrationError("HEARTBEAT_STOP_TIMEOUT")
        if self.error is not None:
            raise ProductionMigrationError("HEARTBEAT_FAILED", str(self.error)) from self.error


def _classify_inventory(writers: Sequence[RuntimeWriter]) -> dict[tuple[str, str], RuntimeWriter]:
    inventory: dict[tuple[str, str], RuntimeWriter] = {}
    for writer in writers:
        if type(writer) is not RuntimeWriter or not writer.write_capable:
            raise ProductionMigrationError("WRITER_INVENTORY_INVALID")
        expected_classification = (
            "PROPERTYAI" if writer.service_code in PROPERTYAI_WRITER_CODES
            else "ADCP" if writer.service_code in ADCP_WRITER_CODES
            else "DYNAMIC"
        )
        if writer.classification != expected_classification:
            raise ProductionMigrationError("UNKNOWN_OR_UNCLASSIFIED_WRITER", writer.service_code)
        if writer.identity in inventory:
            raise ProductionMigrationError("DUPLICATE_WRITER_IDENTITY", repr(writer.identity))
        if writer.identity_validation != "MATCH":
            raise ProductionMigrationError("STALE_WRITER_IDENTITY", repr(writer.identity))
        if writer.conflicting:
            raise ProductionMigrationError("CONFLICTING_WRITER", repr(writer.identity))
        if writer.state not in {"ACTIVE", "QUIESCED"}:
            raise ProductionMigrationError("WRITER_STATE_INVALID", repr(writer.identity))
        inventory[writer.identity] = writer
    missing = EXPECTED_WRITER_CODES - {writer.service_code for writer in inventory.values()}
    if missing:
        raise ProductionMigrationError("EXPECTED_WRITER_MISSING", ",".join(sorted(missing)))
    return inventory


class ProductionMigrationOrchestrator:
    def __init__(
        self,
        context: ExecutionContext,
        *,
        authority: FreshAuthority | Callable[[], Mapping[str, Any] | None],
        quiescence: QuiescenceAdapter,
        clock: Any | None = None,
        client_factory: Callable[..., Any] = _default_client_factory,
        connection_factory: Callable[[Path], sqlite3.Connection] | None = None,
        migrate_primitive: Callable[..., Any] | None = None,
        owner_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.context = context
        self.authority = _CallableAuthority(authority) if callable(authority) and not hasattr(authority, "validate") else authority
        self.quiescence = quiescence
        self.clock = clock or _SystemClock()
        self.client_factory = client_factory
        self.connection_factory = connection_factory or (
            lambda path: sqlite3.connect(path, isolation_level=None, timeout=5.0)
        )
        self.migrate_primitive = migrate_primitive or _migrations.migrate_to_v7
        self.owner_id_factory = owner_id_factory or (lambda: f"v6-v7-orchestrator:{uuid4().hex}")
        self.owner_id = self.owner_id_factory()
        self.owner_execution_id = context.owner_execution_id or uuid4().hex
        self.token: int | None = None
        self.client: Any | None = None
        self.pump: _HeartbeatPump | None = None
        self.quiesced: list[RuntimeWriter] = []
        self._authority_evidence: Mapping[str, Any] | None = None
        self._execution_state = _ExecutionState.NOT_YET_QUIESCED
        self._rebind_proven = False
        self._global_writer_event_cursor: int | None = None

    def _capture_global_writer_event_cursor(self) -> int:
        """Bind immutable GPW event history immediately after our acquisition."""
        connection = sqlite3.connect(
            f"file:{self.context.dcs_path.expanduser().resolve(strict=True)}?mode=ro", uri=True
        )
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                """SELECT event_seq,event_type,to_fencing_token,new_owner_id,
                          new_owner_execution_id,new_change_id
                   FROM global_production_writer_event
                   ORDER BY event_seq DESC LIMIT 1"""
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ProductionMigrationError("GLOBAL_WRITER_EVENT_CURSOR_MISSING")
        if (
            row["event_type"] not in {"ACQUIRE", "EXPIRED_TAKEOVER"}
            or int(row["to_fencing_token"]) != self.token
            or row["new_owner_id"] != self.owner_id
            or row["new_owner_execution_id"] != self.owner_execution_id
            or row["new_change_id"] != CHANGE_ID
        ):
            raise ProductionMigrationError("GLOBAL_WRITER_EVENT_CURSOR_NOT_OWN_ACQUIRE")
        self._global_writer_event_cursor = int(row["event_seq"])
        return self._global_writer_event_cursor

    def _assert_global_writer_event_guard(self) -> None:
        """Fail closed on any post-acquire GPW authority transition before release."""
        if self._global_writer_event_cursor is None:
            raise ProductionMigrationError("GLOBAL_WRITER_EVENT_CURSOR_UNBOUND")
        connection = sqlite3.connect(
            f"file:{self.context.dcs_path.expanduser().resolve(strict=True)}?mode=ro", uri=True
        )
        connection.row_factory = sqlite3.Row
        try:
            rows = list(
                connection.execute(
                    """SELECT event_seq,event_type,from_fencing_token,to_fencing_token,
                              prior_owner_id,new_owner_id
                       FROM global_production_writer_event
                       WHERE event_seq > ? ORDER BY event_seq""",
                    (self._global_writer_event_cursor,),
                )
            )
        finally:
            connection.close()
        if rows:
            row = rows[0]
            raise ProductionMigrationError(
                "GLOBAL_WRITER_EVENT_CONFLICT",
                f"{row['event_type']}:{row['event_seq']}:{row['from_fencing_token']}->{row['to_fencing_token']}",
            )

    def _bind_quiescence_guard(self) -> None:
        binder = getattr(self.quiescence, "bind_migration_guard", None)
        if callable(binder):
            binder(
                assert_current=self._assert_current,
                assert_event_guard=self._assert_global_writer_event_guard,
                schema_version=lambda: _read_schema_version(self.context.dcs_path),
            )

    def _fresh_authority(self) -> None:
        evidence = self.authority.validate()
        normalized = dict(evidence) if evidence is not None else {}
        if self._authority_evidence is None:
            self._authority_evidence = normalized
        elif normalized != self._authority_evidence:
            raise ProductionMigrationError("AUTHORITY_SOURCE_DRIFT")

    def _assert_current(self) -> Mapping[str, Any]:
        if self.client is None or self.token is None:
            raise ProductionMigrationError("LEASE_NOT_BOUND")
        self._fresh_authority()
        if self.pump is not None and self.pump.error is not None:
            raise ProductionMigrationError("HEARTBEAT_FAILED", str(self.pump.error))
        row = self.client.assert_current(self.owner_id, self.token)
        expected_context = {
            "resource_key": RESOURCE,
            "owner_execution_id": self.owner_execution_id,
            "writer_class": LEASE_WRITER_CLASS,
            "operation_class": LEASE_OPERATION_CLASS,
            "target": str(self.context.dcs_path.expanduser().resolve(strict=True)),
        }
        for field, expected in expected_context.items():
            if row.get(field) != expected:
                raise ProductionMigrationError("LEASE_CONTEXT_MISMATCH", field)
        return row

    def _start_pump(self) -> None:
        if not self.context.background_heartbeat:
            return
        self.pump = _HeartbeatPump(
            self.context.dcs_path, self.owner_id, self.token, self.client_factory, self.clock
        )
        self.pump.start()

    def _stop_pump(self) -> None:
        if self.pump is not None:
            pump, self.pump = self.pump, None
            pump.stop()

    def _quiesce(self) -> None:
        before = _classify_inventory(tuple(self.quiescence.discover()))
        for writer in before.values():
            if writer.state == "ACTIVE":
                self._assert_current()
                self._assert_global_writer_event_guard()
                self.quiescence.quiesce(writer)
                # Once a quiesce effect has been attempted, failure handling must
                # conservatively preserve writers stopped; it never restarts them.
                self._execution_state = _ExecutionState.QUIESCED_PRE_TRANSACTION
                observed = self.quiescence.inspect(writer)
                if observed.identity != writer.identity or observed.identity_validation != "MATCH":
                    raise ProductionMigrationError("QUIESCED_WRITER_IDENTITY_MISMATCH", repr(writer.identity))
                if observed.state != "QUIESCED" or observed.conflicting:
                    raise ProductionMigrationError("WRITER_QUIESCENCE_FAILED", repr(writer.identity))
                self._assert_current()
                self._assert_global_writer_event_guard()
                self.quiesced.append(observed)
        self._assert_current()
        self._assert_global_writer_event_guard()
        after = _classify_inventory(tuple(self.quiescence.discover()))
        if set(after) != set(before):
            raise ProductionMigrationError("WRITER_INVENTORY_CHANGED_DURING_QUIESCE")
        if any(writer.state != "QUIESCED" for writer in after.values()):
            raise ProductionMigrationError("CONFLICTING_WRITER_AFTER_QUIESCE")
        self._assert_current()
        self._assert_global_writer_event_guard()

    def _reactivate(self) -> None:
        for writer in self.quiesced:
            self._assert_current()
            self._assert_global_writer_event_guard()
            current = self.quiescence.inspect(writer)
            if current.identity != writer.identity or current.identity_validation != "MATCH" or current.state != "QUIESCED":
                raise ProductionMigrationError("REACTIVATION_IDENTITY_NOT_C_VALIDATED", repr(writer.identity))
            self.quiescence.reactivate(current)
            self._assert_current()
            self._assert_global_writer_event_guard()

    def _safe_release(self) -> bool:
        if self.client is None or self.token is None:
            return False
        try:
            self.client.assert_current(self.owner_id, self.token)
        except BaseException:
            return False
        self.client.release(
            operation_key=_operation_key("release", self.owner_execution_id),
            owner_id=self.owner_id,
            fencing_token=self.token,
            reason="ADCP_PRODUCTION_MIGRATION_ORCHESTRATOR_RELEASED",
            control_decision_ref=self.context.authority_ref,
        )
        return True

    def _preflight(self) -> None:
        if _migrations.MIGRATION_7_NAME != MIGRATION_NAME or _migrations.MIGRATION_7_CHECKSUM != MIGRATION_CHECKSUM:
            raise ProductionMigrationError("FROZEN_MIGRATION_BINDING_MISMATCH")
        supplied_path = self.context.dcs_path.expanduser()
        if supplied_path.is_symlink():
            raise ProductionMigrationError("CANONICAL_DCS_PATH_INVALID")
        path = supplied_path.resolve(strict=True)
        if not path.is_file():
            raise ProductionMigrationError("CANONICAL_DCS_PATH_INVALID")
        if not self.context.evidence_root.is_dir() or self.context.evidence_root.is_symlink():
            raise ProductionMigrationError("EVIDENCE_ROOT_NOT_PRECREATED")
        for field, value, length in (
            ("accepted_git_head", self.context.accepted_git_head, 40),
            ("accepted_git_tree", self.context.accepted_git_tree, 40),
        ):
            if len(value) != length or any(character not in "0123456789abcdef" for character in value):
                raise ProductionMigrationError("EXECUTION_GIT_BINDING_INVALID", field)
        canonical = self.context.canonical_production_path
        if canonical is not None and path == canonical.expanduser().resolve(strict=False):
            if self.context.canonical_production_authorization is None:
                raise ProductionMigrationError("CANONICAL_PRODUCTION_AUTHORIZATION_REQUIRED")
        self._fresh_authority()
        if _read_schema_version(path) != 6:
            raise ProductionMigrationError("STARTING_SCHEMA_V6_REQUIRED")
        _thin_contract().profile_for_version(6)

    def _post_migration_validation(self, baseline: PreservationBaseline) -> None:
        post = capture_preservation_baseline(self.context.dcs_path, 7)
        stable_tables = set(baseline.tables) - {"schema_migration", "global_production_writer_lease"}
        for table in stable_tables:
            if post.tables[table] != baseline.tables[table]:
                raise ProductionMigrationError("AUTHORITATIVE_TABLE_CHANGED", table, phase="POST_COMMIT", schema_version=7)
        if post.schema_migration_0001_0006 != baseline.schema_migration_0001_0006:
            raise ProductionMigrationError(
                "MIGRATION_REGISTRY_0001_0006_CHANGED", phase="POST_COMMIT", schema_version=7
            )
        connection = sqlite3.connect(f"file:{self.context.dcs_path}?mode=ro", uri=True)
        try:
            lineage = tuple(connection.execute(
                "SELECT version,name,checksum FROM schema_migration ORDER BY version"
            ))
            expected = tuple(
                (migration.version, migration.name, migration.checksum)
                for migration in _migrations.MIGRATIONS
                if migration.version <= MIGRATION_VERSION
            )
            if lineage != expected:
                raise ProductionMigrationError("MIGRATION_LINEAGE_CHANGED", phase="POST_COMMIT", schema_version=7)
            if connection.execute("SELECT count(*) FROM evaluator_artifact_seal").fetchone()[0] != 0:
                raise ProductionMigrationError("MIGRATION_CREATED_ARTIFACT_SEAL_ROWS", phase="POST_COMMIT", schema_version=7)
        finally:
            connection.close()
        if post.authority != baseline.authority:
            raise ProductionMigrationError("AUTHORITY_GENERATION_OR_CUTOVER_DRIFT", phase="POST_COMMIT", schema_version=7)
        for field in _LEASE_CONTEXT_FIELDS:
            if post.lease[field] != baseline.lease[field]:
                raise ProductionMigrationError("LEASE_CONTINUITY_CHANGED", field, phase="POST_COMMIT", schema_version=7)
        if set(post.lease) - set(_LEASE_CONTEXT_FIELDS) != _LEASE_LIFECYCLE_FIELDS:
            raise ProductionMigrationError("LEASE_SHAPE_CHANGED", phase="POST_COMMIT", schema_version=7)

    def _inspect_rollback(self, baseline: PreservationBaseline) -> None:
        observed = capture_preservation_baseline(self.context.dcs_path, 6)
        if observed != baseline:
            raise ProductionMigrationError("ROLLBACK_V6_STATE_CHANGED", phase="ROLLBACK", schema_version=6)

    def run(self) -> ProductionMigrationResult:
        backup: BackupEvidence | None = None
        baseline: PreservationBaseline | None = None
        migration_error: BaseException | None = None
        try:
            self._preflight()
            self.client = self.client_factory(self.context.dcs_path, self.clock.now)
            acquired = self.client.acquire(
                operation_key=_operation_key("acquire", self.owner_execution_id),
                owner_id=self.owner_id,
                owner_execution_id=self.owner_execution_id,
                change_id=CHANGE_ID,
                slice_id=self.owner_execution_id,
                writer_class=LEASE_WRITER_CLASS,
                owner_session_role="SEPARATELY_AUTHORIZED_PRODUCTION_MIGRATION",
                track="CONTROL",
                repository_or_runtime=str(self.context.dcs_path.resolve()),
                operation_class=LEASE_OPERATION_CLASS,
                target=str(self.context.dcs_path.expanduser().resolve(strict=True)),
                ttl_seconds=LEASE_TTL_SECONDS,
                control_decision_ref=self.context.authority_ref,
            )
            self.token = int(acquired["fencing_token"])
            self._assert_current()
            self._capture_global_writer_event_cursor()
            self._assert_global_writer_event_guard()
            self._bind_quiescence_guard()
            self._start_pump()
            self._quiesce()
            self._stop_pump()
            self._assert_current()
            self._assert_global_writer_event_guard()
            backup = create_immutable_backup(
                self.context,
                owner_id=self.owner_id,
                owner_execution_id=self.owner_execution_id,
                fencing_token=self.token,
                now=self.clock.now(),
            )
            verify_immutable_backup(backup)
            # Final, non-concurrent heartbeat immediately before the transaction.
            heartbeat = self.client.heartbeat(self.owner_id, self.token, LEASE_TTL_SECONDS)
            self._assert_current()
            expires = datetime.fromisoformat(heartbeat["expires_at"])
            horizon = (expires - self.clock.now().astimezone(timezone.utc)).total_seconds()
            if horizon < PRE_BEGIN_MIN_REMAINING_HORIZON_SECONDS:
                raise ProductionMigrationError("LEASE_HORIZON_INSUFFICIENT", f"{horizon:.6f}")
            baseline = capture_preservation_baseline(self.context.dcs_path, 6)
            self.client.close()
            self.client = None

            connection = self.connection_factory(self.context.dcs_path)
            connection.execute("PRAGMA foreign_keys=ON")
            started = self.clock.monotonic()
            try:
                # This is the only schema mutation primitive in this module.
                self._execution_state = _ExecutionState.MIGRATION_TRANSACTION_OR_ROLLBACK
                self.migrate_primitive(connection, backup_root=None)
            except BaseException as error:
                migration_error = error
            finally:
                returned = self.clock.monotonic()
                connection.close()
            duration = returned - started

            # Rebind is the very first action after COMMIT/ROLLBACK return.
            rebind_started = self.clock.monotonic()
            if rebind_started - returned > POST_TRANSACTION_REBIND_MAX_DELAY_SECONDS:
                self._execution_state = _ExecutionState.AMBIGUOUS_AUTHORITY
                raise ProductionMigrationError("POST_TRANSACTION_REBIND_DELAY_EXCEEDED", phase="AMBIGUOUS")
            try:
                self.client = self.client_factory(self.context.dcs_path, self.clock.now)
                rebound = self.client.assert_current(self.owner_id, self.token)
                if rebound["owner_execution_id"] != self.owner_execution_id:
                    raise ProductionMigrationError("POST_TRANSACTION_LEASE_CONTEXT_MISMATCH")
                self._rebind_proven = True
                self._assert_global_writer_event_guard()
            except BaseException as error:
                self.client = None
                self._execution_state = _ExecutionState.AMBIGUOUS_AUTHORITY
                raise ProductionMigrationError(
                    "POST_TRANSACTION_FENCING_AMBIGUOUS", str(error), phase="AMBIGUOUS",
                    schema_version=_read_schema_version(self.context.dcs_path),
                ) from error
            observed_version = _read_schema_version(self.context.dcs_path)
            self._execution_state = (
                _ExecutionState.COMMITTED_V7
                if observed_version == 7
                else _ExecutionState.MIGRATION_TRANSACTION_OR_ROLLBACK
            )
            exact_rebind_baseline = capture_preservation_baseline(self.context.dcs_path, observed_version)
            if exact_rebind_baseline.lease != baseline.lease:
                raise ProductionMigrationError(
                    "MIGRATION_TRANSACTION_CHANGED_LEASE",
                    phase="POST_COMMIT" if self._execution_state is _ExecutionState.COMMITTED_V7 else "ROLLBACK",
                    schema_version=observed_version,
                )
            if observed_version == 7:
                self.client.heartbeat(self.owner_id, self.token, LEASE_TTL_SECONDS)
                self._start_pump()
            if duration >= MIGRATION_TRANSACTION_BUDGET_SECONDS:
                raise ProductionMigrationError(
                    "MIGRATION_TRANSACTION_BUDGET_EXCEEDED", f"{duration:.6f}",
                    phase="POST_COMMIT" if self._execution_state is _ExecutionState.COMMITTED_V7 else "ROLLBACK", schema_version=observed_version,
                )
            if migration_error is not None:
                if observed_version == 6:
                    self._inspect_rollback(baseline)
                raise ProductionMigrationError(
                    "ACCEPTED_MIGRATION_FAILED", str(migration_error),
                    phase="POST_COMMIT" if self._execution_state is _ExecutionState.COMMITTED_V7 else "ROLLBACK", schema_version=observed_version,
                ) from migration_error
            if observed_version != 7:
                self._inspect_rollback(baseline)
                raise ProductionMigrationError("MIGRATION_DID_NOT_COMMIT_V7", phase="ROLLBACK", schema_version=observed_version)
            self._post_migration_validation(baseline)
            self._fresh_authority()
            self._reactivate()
            self._assert_current()
            self._assert_global_writer_event_guard()
            self._stop_pump()
            self._assert_current()
            self._assert_global_writer_event_guard()
            if not self._safe_release():
                raise ProductionMigrationError("FINAL_RELEASE_NOT_PROVABLY_SAFE", phase="POST_COMMIT", schema_version=7)
            final = self.client.get()
            if final["state"] != "FREE" or final["fencing_token"] != self.token:
                raise ProductionMigrationError("FINAL_LEASE_NOT_FREE", phase="POST_COMMIT", schema_version=7)
            return ProductionMigrationResult(
                self.owner_id, self.owner_execution_id, self.token, 6, 7, backup,
                len(baseline.tables), tuple(writer.identity for writer in self.quiesced),
                final["state"], 0,
            )
        except BaseException as error:
            try:
                self._stop_pump()
            except BaseException:
                pass
            if isinstance(error, ProductionMigrationError):
                phase = error.phase
            else:
                phase = {
                    _ExecutionState.NOT_YET_QUIESCED: "PRE_TRANSACTION",
                    _ExecutionState.QUIESCED_PRE_TRANSACTION: "PRE_TRANSACTION",
                    _ExecutionState.MIGRATION_TRANSACTION_OR_ROLLBACK: "ROLLBACK",
                    _ExecutionState.COMMITTED_V7: "POST_COMMIT",
                    _ExecutionState.AMBIGUOUS_AUTHORITY: "AMBIGUOUS",
                }[self._execution_state]
            if phase == "AMBIGUOUS":
                self._execution_state = _ExecutionState.AMBIGUOUS_AUTHORITY
            # Failure handling never restarts writers.  Reactivation exists only on
            # the fully validated success path above; lease release is independent.
            if phase != "AMBIGUOUS" and self.client is not None:
                try:
                    self._safe_release()
                except BaseException:
                    pass
            if isinstance(error, ProductionMigrationError):
                raise
            raise ProductionMigrationError(
                "PRODUCTION_MIGRATION_FAILED", str(error), phase=phase,
                schema_version=7 if self._execution_state is _ExecutionState.COMMITTED_V7 else 6,
            ) from error
        finally:
            if self.client is not None:
                self.client.close()


def run_production_migration(
    context: ExecutionContext,
    *,
    authority: FreshAuthority | Callable[[], Mapping[str, Any] | None],
    quiescence: QuiescenceAdapter,
    **injected: Any,
) -> ProductionMigrationResult:
    return ProductionMigrationOrchestrator(
        context, authority=authority, quiescence=quiescence, **injected
    ).run()


__all__ = [
    "BackupEvidence", "CHANGE_ID", "ExecutionContext", "EXPECTED_WRITER_CODES",
    "LEASE_OPERATION_CLASS", "LEASE_WRITER_CLASS", "MIGRATION_CHECKSUM", "MIGRATION_NAME", "MIGRATION_VERSION",
    "ExactRowSet",
    "PreservationBaseline", "ProductionMigrationError",
    "ProductionMigrationOrchestrator", "ProductionMigrationResult", "RuntimeWriter",
    "TableFingerprint", "canonical_table_fingerprint", "capture_preservation_baseline",
    "create_immutable_backup", "run_production_migration", "verify_immutable_backup",
]
