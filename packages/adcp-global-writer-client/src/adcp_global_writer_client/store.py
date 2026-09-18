from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from .canonical import canonical_json, require_sha256, timestamp, utc_now
from .errors import GlobalWriterClientError
from .schema_contract import SchemaProfile, VerifiedSchemaContract, verify_client_schema_contract

DEFAULT_LEASE_TTL_SECONDS = 60
MIN_LEASE_TTL_SECONDS = 15
MAX_LEASE_TTL_SECONDS = 300
GLOBAL_PRODUCTION_RESOURCE_KEY = "GLOBAL_PRODUCTION"
GLOBAL_WRITER_CONTEXT_FIELDS = (
    "owner_id",
    "owner_execution_id",
    "change_id",
    "slice_id",
    "writer_class",
    "owner_session_role",
    "track",
    "repository_or_runtime",
    "operation_class",
    "target",
)
GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS = (
    "owner_id",
    "change_id",
    "writer_class",
    "owner_session_role",
    "track",
    "repository_or_runtime",
    "operation_class",
    "target",
)
GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS = ("owner_execution_id", "slice_id")


def _schema_invalid(detail: str) -> GlobalWriterClientError:
    return GlobalWriterClientError("GLOBAL_WRITER_CLIENT_SCHEMA_INVALID", detail)


def _schema_object_fingerprint(sql: str) -> str:
    normalized = sql.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _select_schema_profile(
    rows: tuple[tuple[int, str, str], ...], contract: VerifiedSchemaContract
) -> SchemaProfile:
    if not rows:
        raise GlobalWriterClientError("GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY", "no migrations applied")

    for profile in contract.profiles:
        if rows == profile.migration_history:
            return profile
    oldest = contract.profiles[0]
    if len(rows) < len(oldest.migration_history) and rows == oldest.migration_history[: len(rows)]:
        raise GlobalWriterClientError(
            "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY",
            "expected one of the exact supported canonical schemas "
            f"{contract.supported_dcs_schema_versions}, got canonical prefix through {rows[-1][0]}",
        )
    raise _schema_invalid("migration history/checksum mismatch")


def _validate_schema_connection(
    connection: sqlite3.Connection,
    contract: VerifiedSchemaContract | None = None,
) -> SchemaProfile:
    contract = verify_client_schema_contract() if contract is None else contract
    try:
        rows = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migration ORDER BY version"
            )
        )
    except sqlite3.Error as error:
        raise GlobalWriterClientError(
            "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY", "canonical schema_migration unavailable"
        ) from error

    profile = _select_schema_profile(rows, contract)
    try:
        schema_rows = list(
            connection.execute(
                "SELECT type,name,sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view') "
                "ORDER BY type,name"
            )
        )
        tables = frozenset(name for kind, name, _ in schema_rows if kind == "table")
        indexes = frozenset(name for kind, name, _ in schema_rows if kind == "index")
        triggers = frozenset(name for kind, name, _ in schema_rows if kind == "trigger")
        views = frozenset(name for kind, name, _ in schema_rows if kind == "view")
        if tables != profile.expected_tables:
            raise _schema_invalid("table inventory mismatch")
        if indexes != profile.expected_indexes:
            raise _schema_invalid("index inventory mismatch")
        if triggers != profile.expected_triggers:
            raise _schema_invalid("trigger inventory mismatch")
        if views:
            raise _schema_invalid("view inventory mismatch")

        actual_fingerprints: dict[tuple[str, str], str] = {}
        for kind, name, sql in schema_rows:
            if not isinstance(sql, str):
                raise _schema_invalid(f"missing SQL for {kind}:{name}")
            actual_fingerprints[(kind, name)] = _schema_object_fingerprint(sql)
        expected_fingerprints = {
            (kind, name): digest
            for kind, name, digest in profile.expected_object_fingerprints
        }
        if actual_fingerprints != expected_fingerprints:
            raise _schema_invalid("schema object definition mismatch")
        integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        if integrity != ["ok"]:
            raise _schema_invalid("integrity_check failed")
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        if foreign_keys:
            raise _schema_invalid("foreign_key_check failed")
    except GlobalWriterClientError:
        raise
    except sqlite3.Error as error:
        raise _schema_invalid(str(error)) from error
    return profile


def _schema_ready(path: Path) -> None:
    contract = verify_client_schema_contract()
    if not path.is_file():
        raise GlobalWriterClientError("GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY", "DCS does not exist")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            _validate_schema_connection(connection, contract)
        finally:
            connection.close()
    except GlobalWriterClientError:
        raise
    except sqlite3.Error as error:
        raise GlobalWriterClientError("GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY", str(error)) from error


def _connect_existing_supported_profile(path: Path) -> sqlite3.Connection:
    _schema_ready(path)
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = NORMAL")
        try:
            _validate_schema_connection(connection)
        except BaseException:
            connection.close()
            raise
        return connection
    except GlobalWriterClientError:
        raise
    except sqlite3.Error as error:
        raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error


class GlobalWriterStore:
    """Minimal exact-schema v6/v7/v8/v9/v10 Global Writer protocol; it never migrates a DCS."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.clock = clock
        self.connection = _connect_existing_supported_profile(self.database_path)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "GlobalWriterStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise GlobalWriterClientError("INVALID_TIMESTAMP", "clock must return an aware datetime")
        return value.astimezone(timezone.utc)

    def _begin(self) -> None:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error

    def _rollback(self) -> None:
        if self.connection.in_transaction:
            self.connection.execute("ROLLBACK")

    def _global_writer_timestamp(self, value: Any, field: str) -> float:
        if not isinstance(value, str):
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        try:
            row = self.connection.execute(
                """SELECT julianday(?)
                     WHERE length(?) > 0
                       AND julianday(?) IS NOT NULL
                       AND substr(?, -6) = '+00:00'""",
                (value, value, value, value),
            ).fetchone()
        except sqlite3.Error as error:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        if row is None:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        return float(row[0])

    def _validate_global_writer_row(self, row: sqlite3.Row) -> sqlite3.Row:
        if row["resource_key"] != GLOBAL_PRODUCTION_RESOURCE_KEY:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "resource_key")
        if row["state"] not in {"FREE", "HELD"}:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "state")
        token = row["fencing_token"]
        if not isinstance(token, int) or isinstance(token, bool) or token < 0:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "fencing_token")
        updated = self._global_writer_timestamp(row["updated_at"], "updated_at")
        if row["state"] == "FREE":
            for field in (*GLOBAL_WRITER_CONTEXT_FIELDS, "acquired_at", "expires_at", "heartbeat_at"):
                if row[field] is not None:
                    raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
            return row
        for field in GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS:
            if not isinstance(row[field], str) or not row[field]:
                raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        for field in GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS:
            if row[field] is not None and (not isinstance(row[field], str) or not row[field]):
                raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        acquired = self._global_writer_timestamp(row["acquired_at"], "acquired_at")
        expires = self._global_writer_timestamp(row["expires_at"], "expires_at")
        heartbeat = self._global_writer_timestamp(row["heartbeat_at"], "heartbeat_at")
        if not (acquired <= heartbeat == updated < expires):
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "lease timestamps")
        return row

    def get(self) -> sqlite3.Row:
        _validate_schema_connection(self.connection)
        try:
            row = self.connection.execute(
                "SELECT * FROM global_production_writer_lease WHERE resource_key = ?",
                (GLOBAL_PRODUCTION_RESOURCE_KEY,),
            ).fetchone()
        except sqlite3.Error as error:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        if row is None:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "singleton missing")
        return self._validate_global_writer_row(row)

    def events(self) -> list[sqlite3.Row]:
        _validate_schema_connection(self.connection)
        try:
            return list(self.connection.execute("SELECT * FROM global_production_writer_event ORDER BY event_seq"))
        except sqlite3.Error as error:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error

    def _context_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {field: row[field] for field in GLOBAL_WRITER_CONTEXT_FIELDS}

    def _validate_context(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if set(context) != set(GLOBAL_WRITER_CONTEXT_FIELDS):
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", "shape")
        normalized = dict(context)
        for field in GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS:
            if not isinstance(normalized[field], str) or not normalized[field]:
                raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", field)
        for field in GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS:
            value = normalized[field]
            if value is not None and (not isinstance(value, str) or not value):
                raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", field)
        return normalized

    def _existing_event(self, operation_key: str, allowed: set[str], request_json: str) -> sqlite3.Row | None:
        row = self.connection.execute(
            "SELECT * FROM global_production_writer_event WHERE operation_key = ?", (operation_key,)
        ).fetchone()
        if row is None:
            return None
        if row["event_type"] not in allowed or row["request_json"] != request_json:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT")
        return row

    def _insert_event(
        self,
        *,
        operation_key: str,
        event_type: str,
        from_fencing_token: int,
        to_fencing_token: int,
        prior_context: Mapping[str, Any] | None,
        new_context: Mapping[str, Any] | None,
        reason: str,
        control_decision_ref: str | None,
        request_json: str,
        created_at: str,
    ) -> None:
        prior = {field: None for field in GLOBAL_WRITER_CONTEXT_FIELDS}
        current = {field: None for field in GLOBAL_WRITER_CONTEXT_FIELDS}
        if prior_context is not None:
            prior.update(prior_context)
        if new_context is not None:
            current.update(new_context)
        self.connection.execute(
            """INSERT INTO global_production_writer_event(
                event_id, operation_key, resource_key, event_type,
                from_fencing_token, to_fencing_token,
                prior_owner_id, prior_owner_execution_id, prior_change_id, prior_slice_id,
                prior_writer_class, prior_owner_session_role, prior_track,
                prior_repository_or_runtime, prior_operation_class, prior_target,
                new_owner_id, new_owner_execution_id, new_change_id, new_slice_id,
                new_writer_class, new_owner_session_role, new_track,
                new_repository_or_runtime, new_operation_class, new_target,
                reason, control_decision_ref, request_json, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid4()), operation_key, GLOBAL_PRODUCTION_RESOURCE_KEY, event_type,
                from_fencing_token, to_fencing_token,
                prior["owner_id"], prior["owner_execution_id"], prior["change_id"], prior["slice_id"],
                prior["writer_class"], prior["owner_session_role"], prior["track"],
                prior["repository_or_runtime"], prior["operation_class"], prior["target"],
                current["owner_id"], current["owner_execution_id"], current["change_id"], current["slice_id"],
                current["writer_class"], current["owner_session_role"], current["track"],
                current["repository_or_runtime"], current["operation_class"], current["target"],
                reason, control_decision_ref, request_json, created_at,
            ),
        )

    def _require_current(self, row: sqlite3.Row, owner_id: str, fencing_token: int, now: datetime) -> sqlite3.Row:
        if row["fencing_token"] != fencing_token:
            raise GlobalWriterClientError("STALE_FENCING_TOKEN")
        if row["state"] != "HELD":
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_NOT_HELD")
        if row["owner_id"] != owner_id:
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH")
        if self._global_writer_timestamp(row["expires_at"], "expires_at") <= self._global_writer_timestamp(
            timestamp(now), "current_time"
        ):
            raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_LEASE_EXPIRED")
        return row

    def assert_current(self, owner_id: str, fencing_token: int) -> sqlite3.Row:
        if not isinstance(owner_id, str) or not owner_id:
            raise GlobalWriterClientError("INVALID_INPUT", "owner_id is required")
        if not isinstance(fencing_token, int) or isinstance(fencing_token, bool) or fencing_token < 0:
            raise GlobalWriterClientError("INVALID_INPUT", "fencing_token")
        return self._require_current(self.get(), owner_id, fencing_token, self._now())

    def acquire(
        self,
        *,
        operation_key: str,
        owner_id: str,
        change_id: str,
        writer_class: str,
        owner_session_role: str,
        track: str,
        repository_or_runtime: str,
        operation_class: str,
        target: str,
        owner_execution_id: str | None = None,
        slice_id: str | None = None,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        control_decision_ref: str | None = None,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise GlobalWriterClientError("INVALID_LEASE_TTL")
        if control_decision_ref is not None and (not isinstance(control_decision_ref, str) or not control_decision_ref):
            raise GlobalWriterClientError("INVALID_INPUT", "control_decision_ref")
        context = self._validate_context(
            {
                "owner_id": owner_id,
                "owner_execution_id": owner_execution_id,
                "change_id": change_id,
                "slice_id": slice_id,
                "writer_class": writer_class,
                "owner_session_role": owner_session_role,
                "track": track,
                "repository_or_runtime": repository_or_runtime,
                "operation_class": operation_class,
                "target": target,
            }
        )
        request_json = canonical_json(
            {"context": context, "ttl_seconds": ttl_seconds, "control_decision_ref": control_decision_ref}
        )
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin()
        try:
            existing = self._existing_event(operation_key, {"ACQUIRE", "EXPIRED_TAKEOVER"}, request_json)
            if existing is not None:
                current = self.get()
                if current["state"] != "HELD" or current["fencing_token"] != existing["to_fencing_token"] or self._context_from_row(current) != context:
                    raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return self.assert_current(owner_id, current["fencing_token"])
            prior = self.get()
            prior_context = self._context_from_row(prior) if prior["state"] == "HELD" else None
            if prior["state"] == "HELD":
                if self._global_writer_timestamp(prior["expires_at"], "expires_at") > self._global_writer_timestamp(now, "current_time"):
                    raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_HELD")
                event_type = "EXPIRED_TAKEOVER"
                reason = "GLOBAL_PRODUCTION_WRITER_EXPIRED_TAKEOVER"
            else:
                event_type = "ACQUIRE"
                reason = "GLOBAL_PRODUCTION_WRITER_ACQUIRED"
            new_token = prior["fencing_token"] + 1
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state='HELD', owner_id=?, owner_execution_id=?, change_id=?, slice_id=?,
                          writer_class=?, owner_session_role=?, track=?, repository_or_runtime=?,
                          operation_class=?, target=?, fencing_token=?, acquired_at=?, expires_at=?,
                          heartbeat_at=?, updated_at=?
                    WHERE resource_key=? AND fencing_token=?""",
                (
                    context["owner_id"], context["owner_execution_id"], context["change_id"], context["slice_id"],
                    context["writer_class"], context["owner_session_role"], context["track"],
                    context["repository_or_runtime"], context["operation_class"], context["target"],
                    new_token, now, expires, now, now, GLOBAL_PRODUCTION_RESOURCE_KEY, prior["fencing_token"],
                ),
            )
            if updated.rowcount != 1:
                raise GlobalWriterClientError("CONTROL_STORE_ERROR", "global writer singleton update lost")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_event(
                operation_key=operation_key,
                event_type=event_type,
                from_fencing_token=prior["fencing_token"],
                to_fencing_token=new_token,
                prior_context=prior_context,
                new_context=context,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except GlobalWriterClientError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        current = self.assert_current(owner_id, new_token)
        if self._context_from_row(current) != context:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", "global writer readback mismatch")
        return current

    def heartbeat(self, owner_id: str, fencing_token: int, ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS) -> sqlite3.Row:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise GlobalWriterClientError("INVALID_LEASE_TTL")
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin()
        try:
            row = self.get()
            self._require_current(row, owner_id, fencing_token, now_value)
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease SET expires_at=?, heartbeat_at=?, updated_at=?
                    WHERE resource_key=? AND state='HELD' AND owner_id=? AND fencing_token=? AND expires_at>?""",
                (expires, now, now, GLOBAL_PRODUCTION_RESOURCE_KEY, owner_id, fencing_token, now),
            )
            if updated.rowcount != 1:
                raise GlobalWriterClientError("STALE_FENCING_TOKEN")
            self.connection.execute("COMMIT")
        except GlobalWriterClientError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        return self.assert_current(owner_id, fencing_token)

    def release(
        self,
        *,
        operation_key: str,
        owner_id: str,
        fencing_token: int,
        reason: str = "GLOBAL_PRODUCTION_WRITER_RELEASED",
        control_decision_ref: str | None = None,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if not isinstance(reason, str) or not reason:
            raise GlobalWriterClientError("INVALID_INPUT", "reason")
        if control_decision_ref is not None and (not isinstance(control_decision_ref, str) or not control_decision_ref):
            raise GlobalWriterClientError("INVALID_INPUT", "control_decision_ref")
        if not isinstance(fencing_token, int) or isinstance(fencing_token, bool) or fencing_token < 0:
            raise GlobalWriterClientError("INVALID_INPUT", "fencing_token")
        request_json = canonical_json(
            {"owner_id": owner_id, "fencing_token": fencing_token, "reason": reason, "control_decision_ref": control_decision_ref}
        )
        now_value = self._now()
        now = timestamp(now_value)
        self._begin()
        try:
            existing = self._existing_event(operation_key, {"RELEASE"}, request_json)
            if existing is not None:
                current = self.get()
                if current["state"] != "FREE" or current["fencing_token"] != existing["to_fencing_token"]:
                    raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return current
            prior = self.get()
            self._require_current(prior, owner_id, fencing_token, now_value)
            prior_context = self._context_from_row(prior)
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state='FREE', owner_id=NULL, owner_execution_id=NULL, change_id=NULL,
                          slice_id=NULL, writer_class=NULL, owner_session_role=NULL, track=NULL,
                          repository_or_runtime=NULL, operation_class=NULL, target=NULL,
                          acquired_at=NULL, expires_at=NULL, heartbeat_at=NULL, updated_at=?
                    WHERE resource_key=? AND state='HELD' AND owner_id=? AND fencing_token=? AND expires_at>?""",
                (now, GLOBAL_PRODUCTION_RESOURCE_KEY, owner_id, fencing_token, now),
            )
            if updated.rowcount != 1:
                raise GlobalWriterClientError("STALE_FENCING_TOKEN")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_event(
                operation_key=operation_key,
                event_type="RELEASE",
                from_fencing_token=fencing_token,
                to_fencing_token=fencing_token,
                prior_context=prior_context,
                new_context=None,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except GlobalWriterClientError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        current = self.get()
        if current["state"] != "FREE" or current["fencing_token"] != fencing_token:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", "global writer release readback mismatch")
        return current

    def force_revoke(
        self,
        *,
        operation_key: str,
        reason: str,
        control_decision_ref: str,
        expected_owner_id: str,
        expected_fencing_token: int,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        for field, value in (("reason", reason), ("control_decision_ref", control_decision_ref), ("expected_owner_id", expected_owner_id)):
            if not isinstance(value, str) or not value:
                raise GlobalWriterClientError("INVALID_INPUT", field)
        if not isinstance(expected_fencing_token, int) or isinstance(expected_fencing_token, bool) or expected_fencing_token < 0:
            raise GlobalWriterClientError("INVALID_INPUT", "expected_fencing_token")
        request_json = canonical_json(
            {
                "reason": reason,
                "control_decision_ref": control_decision_ref,
                "expected_owner_id": expected_owner_id,
                "expected_fencing_token": expected_fencing_token,
            }
        )
        now_value = self._now()
        now = timestamp(now_value)
        self._begin()
        try:
            existing = self._existing_event(operation_key, {"FORCE_REVOKE"}, request_json)
            if existing is not None:
                current = self.get()
                if current["state"] != "FREE" or current["fencing_token"] != existing["to_fencing_token"]:
                    raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return current
            prior = self.get()
            self._require_current(prior, expected_owner_id, expected_fencing_token, now_value)
            prior_context = self._context_from_row(prior)
            new_token = expected_fencing_token + 1
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state='FREE', owner_id=NULL, owner_execution_id=NULL, change_id=NULL,
                          slice_id=NULL, writer_class=NULL, owner_session_role=NULL, track=NULL,
                          repository_or_runtime=NULL, operation_class=NULL, target=NULL,
                          fencing_token=?, acquired_at=NULL, expires_at=NULL, heartbeat_at=NULL, updated_at=?
                    WHERE resource_key=? AND state='HELD' AND owner_id=? AND fencing_token=? AND expires_at>?""",
                (new_token, now, GLOBAL_PRODUCTION_RESOURCE_KEY, expected_owner_id, expected_fencing_token, now),
            )
            if updated.rowcount != 1:
                raise GlobalWriterClientError("GLOBAL_PRODUCTION_WRITER_FORCE_REVOKE_MISMATCH")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_event(
                operation_key=operation_key,
                event_type="FORCE_REVOKE",
                from_fencing_token=expected_fencing_token,
                to_fencing_token=new_token,
                prior_context=prior_context,
                new_context=None,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except GlobalWriterClientError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        current = self.get()
        if current["state"] != "FREE" or current["fencing_token"] != new_token:
            raise GlobalWriterClientError("CONTROL_STORE_ERROR", "global writer revoke readback mismatch")
        return current
