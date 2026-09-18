"""Strict read-only Production control-surface inspection for REMOTE_MCP.

This module exposes one narrow semantic snapshot.  It never constructs a
``ControlStore`` because that path intentionally configures write-capable SQLite
PRAGMAs.  The canonical entrypoint accepts only semantic operation identity;
physical source/interpreter/DCS bindings remain Controller-owned.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from typing import Any, Mapping, TextIO

from adcp.domain import StoreError
from adcp.production_prep import CANONICAL_PRODUCTION_CONTROL_STORE, CANONICAL_SOURCE_ROOT
from adcp.store.migrations import REGISTERED_SCHEMA_VERSION, schema_profile_identity


DOCTOR_VERSION = 1
REQUEST_VERSION = 1
SUPPORTED_PRODUCTION_CONTROL_SURFACE_SCHEMAS = frozenset({9, 10})
W08_WRITER_CLASS = "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
CANONICAL_CONTROLLER_INTERPRETER = Path("/Users/kate/DKATE/adcp-controller/.venv/bin/python")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,511}$")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ProductionControlSurfaceRequest:
    request_version: int
    expected_controller_commit: str
    change_id: str
    unit_or_subchange_id: str
    operation_id: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProductionControlSurfaceRequest":
        expected = {
            "request_version",
            "expected_controller_commit",
            "change_id",
            "unit_or_subchange_id",
            "operation_id",
        }
        if set(value) != expected:
            raise ValueError("exact request fields required")
        return cls(
            request_version=value["request_version"],
            expected_controller_commit=value["expected_controller_commit"],
            change_id=value["change_id"],
            unit_or_subchange_id=value["unit_or_subchange_id"],
            operation_id=value["operation_id"],
        )


@dataclass(frozen=True)
class _ProductionControlSurfaceBindings:
    controller_root: Path
    controller_interpreter: Path
    dcs_path: Path


@dataclass(frozen=True)
class ProductionControlSurfaceResult:
    doctor_version: int
    status: str
    error_code: str | None
    controller_root: str | None
    controller_interpreter: str | None
    controller_python_version: str | None
    controller_commit: str | None
    controller_tree: str | None
    controller_source_clean: bool | None
    dcs_path: str | None
    dcs_readable: bool
    dcs_schema: int | None
    dcs_schema_supported: bool
    global_writer_state: str | None
    global_writer_owner_if_any: str | None
    current_fencing_token: int | None
    global_writer_lease: Mapping[str, Any] | None
    request_change_id: str | None
    request_unit_or_subchange_id: str | None
    request_operation_id: str | None
    exact_operation_prior_acquisition_count: int
    prior_operation_state: str
    w08_control_path_available: bool
    mutation_exercised: str
    w08_acquire_count: int
    diagnostic_detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_bindings() -> _ProductionControlSurfaceBindings:
    return _ProductionControlSurfaceBindings(
        controller_root=CANONICAL_SOURCE_ROOT,
        controller_interpreter=CANONICAL_CONTROLLER_INTERPRETER,
        dcs_path=CANONICAL_PRODUCTION_CONTROL_STORE,
    )


def _safe_detail(value: BaseException | str | None) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return text[:512] or None


def _base_result(
    request: ProductionControlSurfaceRequest | None,
    bindings: _ProductionControlSurfaceBindings,
    *,
    status: str,
    error_code: str | None = None,
    detail: BaseException | str | None = None,
    **overrides: Any,
) -> ProductionControlSurfaceResult:
    values: dict[str, Any] = {
        "doctor_version": DOCTOR_VERSION,
        "status": status,
        "error_code": error_code,
        "controller_root": str(bindings.controller_root),
        "controller_interpreter": str(bindings.controller_interpreter),
        "controller_python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "controller_commit": None,
        "controller_tree": None,
        "controller_source_clean": None,
        "dcs_path": str(bindings.dcs_path),
        "dcs_readable": False,
        "dcs_schema": None,
        "dcs_schema_supported": False,
        "global_writer_state": None,
        "global_writer_owner_if_any": None,
        "current_fencing_token": None,
        "global_writer_lease": None,
        "request_change_id": request.change_id if request is not None else None,
        "request_unit_or_subchange_id": request.unit_or_subchange_id if request is not None else None,
        "request_operation_id": request.operation_id if request is not None else None,
        "exact_operation_prior_acquisition_count": 0,
        "prior_operation_state": "UNKNOWN" if error_code else "NONE",
        "w08_control_path_available": False,
        "mutation_exercised": "NO",
        "w08_acquire_count": 0,
        "diagnostic_detail": _safe_detail(detail),
    }
    values.update(overrides)
    result = ProductionControlSurfaceResult(**values)
    if result.mutation_exercised != "NO" or result.w08_acquire_count != 0:
        return ProductionControlSurfaceResult(
            **{
                **result.as_dict(),
                "status": "ERROR",
                "error_code": "INTERNAL_MUTATION_INVARIANT_FAILURE",
                "diagnostic_detail": "read-only mutation invariant violated",
            }
        )
    return result


def _validate_request(request: ProductionControlSurfaceRequest) -> None:
    if type(request) is not ProductionControlSurfaceRequest:
        raise ValueError("request type")
    if type(request.request_version) is not int or request.request_version != REQUEST_VERSION:
        raise ValueError("request_version")
    if not isinstance(request.expected_controller_commit, str) or not _HEX40_RE.fullmatch(
        request.expected_controller_commit
    ):
        raise ValueError("expected_controller_commit")
    for name in ("change_id", "unit_or_subchange_id", "operation_id"):
        value = getattr(request, name)
        if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError(name)


def _validate_interpreter(bindings: _ProductionControlSurfaceBindings) -> str | None:
    expected = bindings.controller_interpreter
    if not expected.is_file() or not os.access(expected, os.X_OK):
        return "CONTROLLER_INTERPRETER_MISSING"
    actual = Path(sys.executable).expanduser().absolute()
    if actual != expected.expanduser().absolute():
        return "CONTROLLER_INTERPRETER_MISMATCH"
    if sys.version_info[:2] != (3, 13):
        return "CONTROLLER_PYTHON_UNSUPPORTED"
    return None


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
    )


def _inspect_source(
    bindings: _ProductionControlSurfaceBindings,
    expected_commit: str,
) -> tuple[str | None, str | None, bool | None, str | None, str | None]:
    root = bindings.controller_root.expanduser()
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        return None, None, None, "CONTROLLER_ROOT_MISMATCH", _safe_detail(error)
    top = _run_git(resolved, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return None, None, None, "CONTROLLER_ROOT_MISMATCH", _safe_detail(top.stderr)
    try:
        actual_top = Path(top.stdout.strip()).resolve(strict=True)
    except OSError as error:
        return None, None, None, "CONTROLLER_ROOT_MISMATCH", _safe_detail(error)
    if actual_top != resolved:
        return None, None, None, "CONTROLLER_ROOT_MISMATCH", "git top-level mismatch"
    head = _run_git(resolved, "rev-parse", "HEAD")
    tree = _run_git(resolved, "rev-parse", "HEAD^{tree}")
    status = _run_git(resolved, "status", "--porcelain=v1", "--untracked-files=all")
    if any(item.returncode != 0 for item in (head, tree, status)):
        return None, None, None, "CONTROLLER_ROOT_MISMATCH", "git source inspection failed"
    actual_head = head.stdout.strip()
    actual_tree = tree.stdout.strip()
    clean = not bool(status.stdout.strip())
    if actual_head != expected_commit:
        return actual_head, actual_tree, clean, "CONTROLLER_HEAD_MISMATCH", None
    if not clean:
        return actual_head, actual_tree, False, "CONTROLLER_DIRTY", None
    return actual_head, actual_tree, True, None, None


def _configure_readonly_connection(connection: sqlite3.Connection) -> sqlite3.Connection:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA query_only = ON")
    query_only = connection.execute("PRAGMA query_only").fetchone()
    if query_only is None or int(query_only[0]) != 1:
        connection.close()
        raise sqlite3.OperationalError("query_only was not enabled")
    return connection


def _readonly_connection(path: Path) -> sqlite3.Connection:
    """Immutable authority/profile snapshot; never observes uncheckpointed WAL state."""

    connection = sqlite3.connect(
        path.resolve(strict=False).as_uri() + "?mode=ro&immutable=1", uri=True
    )
    return _configure_readonly_connection(connection)


def _readonly_live_connection(path: Path) -> sqlite3.Connection:
    """Read current WAL-visible state without acquiring any write-capable handle."""

    connection = sqlite3.connect(path.resolve(strict=False).as_uri() + "?mode=ro", uri=True)
    return _configure_readonly_connection(connection)


def _schema_version(connection: sqlite3.Connection) -> int:
    table = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name='schema_migration'"
    ).fetchone()
    if table is None:
        raise StoreError("MIGRATION_SCHEMA_INVALID", "schema_migration missing")
    row = connection.execute("SELECT max(version) AS version FROM schema_migration").fetchone()
    if row is None or type(row["version"]) is not int or row["version"] <= 0:
        raise StoreError("MIGRATION_SCHEMA_INVALID", "schema version invalid")
    return int(row["version"])


def _validate_writer_row(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise ValueError("singleton missing")
    value = dict(row)
    required_columns = {
        "resource_key", "state", "owner_id", "owner_execution_id", "change_id", "slice_id",
        "writer_class", "owner_session_role", "track", "repository_or_runtime",
        "operation_class", "target", "fencing_token", "acquired_at", "expires_at",
        "heartbeat_at", "updated_at",
    }
    if set(value) != required_columns or value["resource_key"] != "GLOBAL_PRODUCTION":
        raise ValueError("writer row shape")
    if value["state"] not in {"FREE", "HELD"}:
        raise ValueError("writer state")
    if type(value["fencing_token"]) is not int or value["fencing_token"] < 0:
        raise ValueError("fencing token")
    context = (
        "owner_id", "owner_execution_id", "change_id", "slice_id", "writer_class",
        "owner_session_role", "track", "repository_or_runtime", "operation_class", "target",
        "acquired_at", "expires_at", "heartbeat_at",
    )
    if value["state"] == "FREE":
        if any(value[field] is not None for field in context):
            raise ValueError("free writer context")
    else:
        required = (
            "owner_id", "change_id", "writer_class", "owner_session_role", "track",
            "repository_or_runtime", "operation_class", "target", "acquired_at", "expires_at",
            "heartbeat_at", "updated_at",
        )
        if any(not isinstance(value[field], str) or not value[field] for field in required):
            raise ValueError("held writer context")
        for optional in ("owner_execution_id", "slice_id"):
            if value[optional] is not None and (
                not isinstance(value[optional], str) or not value[optional]
            ):
                raise ValueError("held writer optional context")
    return value


def _lease_public_view(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "resource_key", "state", "owner_id", "owner_execution_id", "change_id", "slice_id",
        "writer_class", "owner_session_role", "track", "repository_or_runtime",
        "operation_class", "target", "fencing_token", "acquired_at", "expires_at",
        "heartbeat_at", "updated_at",
    )
    return {field: value[field] for field in fields}


def _prior_w08_acquisition_count(
    connection: sqlite3.Connection,
    request: ProductionControlSurfaceRequest,
) -> int:
    # Existing W08 controlled-deployment semantics use deployment_id as the
    # global-writer ``slice_id``.  Typed PostgreSQL uses its public operation_id as
    # that deployment_id, so this is the exact durable replay identity.
    row = connection.execute(
        """SELECT count(*) AS acquisition_count
             FROM global_production_writer_event
            WHERE event_type IN ('ACQUIRE','EXPIRED_TAKEOVER')
              AND new_change_id = ?
              AND new_slice_id = ?
              AND new_writer_class = ?""",
        (request.change_id, request.operation_id, W08_WRITER_CLASS),
    ).fetchone()
    if row is None or type(row["acquisition_count"]) is not int or row["acquisition_count"] < 0:
        raise ValueError("prior acquisition count")
    return int(row["acquisition_count"])


def _inspect_production_control_surface(
    request: ProductionControlSurfaceRequest,
    bindings: _ProductionControlSurfaceBindings,
) -> ProductionControlSurfaceResult:
    try:
        _validate_request(request)
    except (TypeError, ValueError) as error:
        return _base_result(
            request if type(request) is ProductionControlSurfaceRequest else None,
            bindings,
            status="ERROR",
            error_code="OPERATION_BINDING_INVALID",
            detail=error,
        )

    interpreter_error = _validate_interpreter(bindings)
    if interpreter_error is not None:
        return _base_result(request, bindings, status="ERROR", error_code=interpreter_error)

    commit, tree, clean, source_error, source_detail = _inspect_source(
        bindings, request.expected_controller_commit
    )
    source_fields = {
        "controller_commit": commit,
        "controller_tree": tree,
        "controller_source_clean": clean,
    }
    if source_error is not None:
        return _base_result(
            request,
            bindings,
            status="ERROR",
            error_code=source_error,
            detail=source_detail,
            **source_fields,
        )

    dcs_path = bindings.dcs_path.expanduser()
    if not dcs_path.is_file():
        return _base_result(
            request, bindings, status="ERROR", error_code="DCS_MISSING", **source_fields
        )

    connection: sqlite3.Connection | None = None
    live_connection: sqlite3.Connection | None = None
    try:
        try:
            connection = _readonly_connection(dcs_path)
            # Force a basic sqlite_schema read so a random/non-SQLite file is
            # classified as unreadable rather than as a malformed ADCP profile.
            connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        except (OSError, sqlite3.DatabaseError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_UNREADABLE",
                detail=error,
                **source_fields,
            )

        try:
            schema = _schema_version(connection)
        except (sqlite3.DatabaseError, StoreError, TypeError, ValueError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_SCHEMA_MALFORMED",
                detail=error,
                dcs_readable=True,
                **source_fields,
            )

        if schema not in SUPPORTED_PRODUCTION_CONTROL_SURFACE_SCHEMAS:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_SCHEMA_UNSUPPORTED",
                detail=f"schema={schema},registered={REGISTERED_SCHEMA_VERSION}",
                dcs_readable=True,
                dcs_schema=schema,
                **source_fields,
            )

        try:
            static_profile = schema_profile_identity(connection, schema)
        except (sqlite3.DatabaseError, StoreError, TypeError, ValueError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_SCHEMA_MALFORMED",
                detail=error,
                dcs_readable=True,
                dcs_schema=schema,
                dcs_schema_supported=True,
                **source_fields,
            )

        try:
            # The immutable handle above proves the durable static authority/profile.
            # Current writer/fencing/event state can legitimately be newer in WAL, so
            # inspect it through one WAL-aware mode=ro + query_only connection.  An
            # explicit ordinary read transaction is required: the first live schema
            # SELECT establishes one SQLite snapshot and every READY-driving live read
            # below remains inside that same snapshot.
            live_connection = _readonly_live_connection(dcs_path)
            live_connection.execute("BEGIN")
            live_schema = _schema_version(live_connection)
            if live_schema != schema:
                raise StoreError(
                    "MIGRATION_SCHEMA_INVALID",
                    f"immutable={schema},live={live_schema}",
                )
            live_profile = schema_profile_identity(live_connection, live_schema)
            if live_profile != static_profile:
                raise StoreError(
                    "MIGRATION_SCHEMA_INVALID",
                    "immutable/live schema profile identity mismatch",
                )
        except (OSError, sqlite3.DatabaseError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_UNREADABLE",
                detail=error,
                dcs_readable=True,
                dcs_schema=schema,
                dcs_schema_supported=True,
                **source_fields,
            )
        except (StoreError, TypeError, ValueError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="DCS_SCHEMA_MALFORMED",
                detail=error,
                dcs_readable=True,
                dcs_schema=schema,
                dcs_schema_supported=True,
                **source_fields,
            )

        try:
            lease = _validate_writer_row(
                live_connection.execute(
                    "SELECT * FROM global_production_writer_lease WHERE resource_key='GLOBAL_PRODUCTION'"
                ).fetchone()
            )
        except (sqlite3.DatabaseError, TypeError, ValueError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="WRITER_STATE_MALFORMED",
                detail=error,
                dcs_readable=True,
                dcs_schema=schema,
                dcs_schema_supported=True,
                w08_control_path_available=True,
                **source_fields,
            )

        try:
            prior_count = _prior_w08_acquisition_count(live_connection, request)
        except (sqlite3.DatabaseError, TypeError, ValueError) as error:
            return _base_result(
                request,
                bindings,
                status="ERROR",
                error_code="OPERATION_BINDING_INVALID",
                detail=error,
                dcs_readable=True,
                dcs_schema=schema,
                dcs_schema_supported=True,
                global_writer_state=lease["state"],
                global_writer_owner_if_any=lease["owner_id"],
                current_fencing_token=lease["fencing_token"],
                global_writer_lease=_lease_public_view(lease),
                w08_control_path_available=True,
                **source_fields,
            )

        if prior_count > 0:
            status = "RECONCILIATION_REQUIRED"
            prior_state = "PRIOR_W08_ACQUISITION_PRESENT"
        elif lease["state"] == "HELD":
            status = "NOT_READY"
            prior_state = "NONE"
        else:
            status = "READY"
            prior_state = "NONE"
        return _base_result(
            request,
            bindings,
            status=status,
            dcs_readable=True,
            dcs_schema=schema,
            dcs_schema_supported=True,
            global_writer_state=lease["state"],
            global_writer_owner_if_any=lease["owner_id"],
            current_fencing_token=lease["fencing_token"],
            global_writer_lease=_lease_public_view(lease),
            exact_operation_prior_acquisition_count=prior_count,
            prior_operation_state=prior_state,
            w08_control_path_available=True,
            **source_fields,
        )
    finally:
        if live_connection is not None:
            try:
                if live_connection.in_transaction:
                    live_connection.rollback()
            except sqlite3.DatabaseError:
                # The handle is mode=ro/query_only and will be closed below.  Never
                # reopen writable merely to recover from read-transaction cleanup.
                pass
            finally:
                live_connection.close()
        if connection is not None:
            connection.close()


def inspect_production_control_surface(
    request: ProductionControlSurfaceRequest,
) -> ProductionControlSurfaceResult:
    """Inspect the canonical Production control surface without mutation."""

    return _inspect_production_control_surface(request, _canonical_bindings())


def _invalid_cli_result(detail: BaseException | str) -> ProductionControlSurfaceResult:
    return _base_result(
        None,
        _canonical_bindings(),
        status="ERROR",
        error_code="OPERATION_BINDING_INVALID",
        detail=detail,
    )


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Fixed JSON-over-stdin Controller entrypoint for the REMOTE_MCP adapter."""

    source = sys.stdin if stdin is None else stdin
    target = sys.stdout if stdout is None else stdout
    try:
        raw = json.load(source)
        if not isinstance(raw, dict):
            raise ValueError("request object required")
        request = ProductionControlSurfaceRequest.from_mapping(raw)
        result = inspect_production_control_surface(request)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        result = _invalid_cli_result(error)
    target.write(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    return 0


__all__ = [
    "DOCTOR_VERSION",
    "ProductionControlSurfaceRequest",
    "ProductionControlSurfaceResult",
    "SUPPORTED_PRODUCTION_CONTROL_SURFACE_SCHEMAS",
    "inspect_production_control_surface",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
