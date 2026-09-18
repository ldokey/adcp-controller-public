from __future__ import annotations

from dataclasses import fields
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from adcp.domain import operation_key
import adcp.production_control_surface as doctor
from adcp.production_control_surface import (
    ProductionControlSurfaceRequest,
    _ProductionControlSurfaceBindings,
    _inspect_production_control_surface,
)
from adcp.store.migrations import migrate
from adcp.store.sqlite import ControlStore, connect


class ProductionControlSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "controller"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        (self.repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.repo), "-c", "user.name=Doctor Fixture",
                "-c", "user.email=doctor@example.invalid", "commit", "-qm", "baseline",
            ],
            check=True,
        )
        self.head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.dcs = self.root / "control.sqlite3"
        connection = connect(self.dcs)
        try:
            migrate(connection, target_version=9)
        finally:
            connection.close()
        self.bindings = _ProductionControlSurfaceBindings(
            controller_root=self.repo,
            controller_interpreter=Path(sys.executable).absolute(),
            dcs_path=self.dcs,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        *,
        expected_commit: str | None = None,
        change_id: str = "P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01",
        unit_id: str = "P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01-P1R5-C2-PRODUCTION-PG-INGRESS",
        operation_id: str = "dl57-wheel-1",
    ) -> ProductionControlSurfaceRequest:
        return ProductionControlSurfaceRequest(
            request_version=1,
            expected_controller_commit=expected_commit or self.head,
            change_id=change_id,
            unit_or_subchange_id=unit_id,
            operation_id=operation_id,
        )

    def inspect(self, request: ProductionControlSurfaceRequest | None = None):
        return _inspect_production_control_surface(request or self.request(), self.bindings)

    def _writer_store(self) -> ControlStore:
        return ControlStore(
            self.dcs,
            migrate_schema=False,
            require_schema_version=9,
            global_writer_guard_required=False,
        )

    def _acquire_w08(self, operation_id: str, *, change_id: str | None = None):
        store = self._writer_store()
        row = store.acquire_global_production_writer(
            operation_key=operation_key(
                "doctor-fixture-acquire", {"operation_id": operation_id, "change_id": change_id or self.request().change_id}
            ),
            owner_id=f"doctor-owner-{operation_id}",
            owner_execution_id=f"doctor-exec-{operation_id}",
            change_id=change_id or self.request().change_id,
            slice_id=operation_id,
            writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
            owner_session_role="DOCTOR_FIXTURE",
            track="TEST",
            repository_or_runtime="DISPOSABLE_TEST",
            operation_class="CONTROLLED_PRODUCTION_DEPLOYMENT",
            target="GLOBAL_PRODUCTION",
            control_decision_ref="DOCTOR/FIXTURE",
        )
        return store, row

    def _sqlite_content_bytes(self) -> dict[str, bytes]:
        paths = (self.dcs, Path(f"{self.dcs}-wal"), Path(f"{self.dcs}-shm"))
        return {path.name: path.read_bytes() for path in paths if path.exists()}

    def test_strict_read_schema_9_success_and_fixture_bytes_unchanged(self):
        before_bytes = self.dcs.read_bytes()
        before_stat = self.dcs.stat()
        result = self.inspect()
        after_stat = self.dcs.stat()
        self.assertEqual("READY", result.status)
        self.assertIsNone(result.error_code)
        self.assertEqual(9, result.dcs_schema)
        self.assertTrue(result.dcs_schema_supported)
        self.assertEqual("FREE", result.global_writer_state)
        self.assertEqual(0, result.current_fencing_token)
        self.assertEqual("NO", result.mutation_exercised)
        self.assertEqual(0, result.w08_acquire_count)
        self.assertEqual(before_bytes, self.dcs.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, after_stat.st_mtime_ns)

    def test_strict_read_schema_10_success_and_fixture_bytes_unchanged(self):
        connection = connect(self.dcs)
        try:
            migrate(connection, target_version=10)
        finally:
            connection.close()
        before_bytes = self.dcs.read_bytes()
        before_stat = self.dcs.stat()
        result = self.inspect()
        after_stat = self.dcs.stat()
        self.assertEqual("READY", result.status)
        self.assertIsNone(result.error_code)
        self.assertEqual(10, result.dcs_schema)
        self.assertTrue(result.dcs_schema_supported)
        self.assertEqual("NO", result.mutation_exercised)
        self.assertEqual(0, result.w08_acquire_count)
        self.assertEqual(before_bytes, self.dcs.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, after_stat.st_mtime_ns)

    def test_schema_8_is_not_promoted_into_production_doctor_contract(self):
        self.assertEqual(
            frozenset({9, 10}), doctor.SUPPORTED_PRODUCTION_CONTROL_SURFACE_SCHEMAS
        )
        historical = self.root / "control-v8.sqlite3"
        connection = connect(historical)
        try:
            migrate(connection, target_version=8)
        finally:
            connection.close()
        bindings = _ProductionControlSurfaceBindings(
            controller_root=self.repo,
            controller_interpreter=Path(sys.executable).absolute(),
            dcs_path=historical,
        )
        result = _inspect_production_control_surface(self.request(), bindings)
        self.assertEqual("ERROR", result.status)
        self.assertEqual("DCS_SCHEMA_UNSUPPORTED", result.error_code)
        self.assertEqual(8, result.dcs_schema)

    def test_future_schema_fails_closed_without_mutation(self):
        connection = connect(self.dcs)
        try:
            migrate(connection, target_version=10)
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES (11,'future','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','2026-09-12T00:00:00+00:00')"
            )
        finally:
            connection.close()
        before = self.dcs.read_bytes()
        result = self.inspect()
        self.assertEqual("ERROR", result.status)
        self.assertEqual("DCS_SCHEMA_UNSUPPORTED", result.error_code)
        self.assertEqual(11, result.dcs_schema)
        self.assertEqual(before, self.dcs.read_bytes())

    def test_malformed_schema_profile_is_typed_failure(self):
        connection = sqlite3.connect(self.dcs)
        try:
            connection.execute("DROP TRIGGER global_production_writer_event_immutable_delete")
            connection.commit()
        finally:
            connection.close()
        result = self.inspect()
        self.assertEqual("ERROR", result.status)
        self.assertEqual("DCS_SCHEMA_MALFORMED", result.error_code)
        self.assertEqual(9, result.dcs_schema)

    def test_dcs_missing(self):
        missing = self.root / "missing.sqlite3"
        result = _inspect_production_control_surface(
            self.request(),
            _ProductionControlSurfaceBindings(self.repo, Path(sys.executable).absolute(), missing),
        )
        self.assertEqual("DCS_MISSING", result.error_code)
        self.assertFalse(result.dcs_readable)

    def test_invalid_unreadable_disposable_dcs(self):
        invalid = self.root / "invalid.sqlite3"
        invalid.write_bytes(b"not a sqlite database\x00\x01")
        result = _inspect_production_control_surface(
            self.request(),
            _ProductionControlSurfaceBindings(self.repo, Path(sys.executable).absolute(), invalid),
        )
        self.assertEqual("DCS_UNREADABLE", result.error_code)

    def test_writer_free_is_ready(self):
        result = self.inspect()
        self.assertEqual("READY", result.status)
        self.assertEqual("FREE", result.global_writer_state)
        self.assertIsNone(result.global_writer_owner_if_any)
        self.assertEqual(0, result.exact_operation_prior_acquisition_count)

    def test_writer_held_is_not_ready_and_never_acquired_by_doctor(self):
        store, held = self._acquire_w08("other-operation")
        try:
            before_events = len(store.global_production_writer_events())
            durable_paths = [self.dcs, Path(f"{self.dcs}-wal"), Path(f"{self.dcs}-shm")]
            before_bytes = {
                str(path): path.read_bytes() for path in durable_paths if path.exists()
            }
            result = self.inspect()
            after_events = len(store.global_production_writer_events())
            after_bytes = {
                str(path): path.read_bytes() for path in durable_paths if path.exists()
            }
            self.assertEqual("NOT_READY", result.status)
            self.assertEqual("HELD", result.global_writer_state)
            self.assertEqual(held["owner_id"], result.global_writer_owner_if_any)
            self.assertEqual(held["fencing_token"], result.current_fencing_token)
            self.assertEqual(before_events, after_events)
            self.assertEqual(before_bytes, after_bytes)
            self.assertEqual(0, result.w08_acquire_count)
        finally:
            store.close()

    def test_current_fencing_token_is_read_exactly(self):
        store, held = self._acquire_w08("fencing-operation")
        try:
            result = self.inspect()
            self.assertEqual(int(held["fencing_token"]), result.current_fencing_token)
            self.assertEqual(int(held["fencing_token"]), result.global_writer_lease["fencing_token"])
        finally:
            store.close()

    def test_exact_prior_w08_acquisition_requires_reconciliation(self):
        request = self.request(operation_id="prior-operation")
        store, held = self._acquire_w08(request.operation_id, change_id=request.change_id)
        store.release_global_production_writer(
            operation_key=operation_key("doctor-fixture-release", {"operation_id": request.operation_id}),
            owner_id=held["owner_id"],
            fencing_token=held["fencing_token"],
            control_decision_ref="DOCTOR/FIXTURE",
        )
        store.close()
        result = self.inspect(request)
        self.assertEqual("RECONCILIATION_REQUIRED", result.status)
        self.assertEqual(1, result.exact_operation_prior_acquisition_count)
        self.assertEqual("PRIOR_W08_ACQUISITION_PRESENT", result.prior_operation_state)
        self.assertEqual("FREE", result.global_writer_state)

    def test_live_read_transaction_prevents_mixed_generation_under_concurrent_w08_commit(self):
        request = self.request(operation_id="concurrent-operation")
        real_schema_version = doctor._schema_version
        schema_reads = 0
        writer_store: ControlStore | None = None
        held = None
        post_writer_bytes: dict[str, bytes] | None = None

        def schema_version_with_concurrent_commit(connection: sqlite3.Connection) -> int:
            nonlocal schema_reads, writer_store, held, post_writer_bytes
            value = real_schema_version(connection)
            schema_reads += 1
            if schema_reads == 2:
                # The live transaction's first SELECT has already established
                # generation A.  Commit generation B before any writer/event read.
                writer_store, held = self._acquire_w08(
                    request.operation_id, change_id=request.change_id
                )
                post_writer_bytes = self._sqlite_content_bytes()
            return value

        with patch(
            "adcp.production_control_surface._schema_version",
            side_effect=schema_version_with_concurrent_commit,
        ):
            result = self.inspect(request)

        self.assertEqual(2, schema_reads)
        self.assertIsNotNone(writer_store)
        self.assertIsNotNone(held)
        self.assertIsNotNone(post_writer_bytes)
        try:
            # Generation A is the coherent snapshot established before the
            # concurrent W08 fixture commit.  Generation B is visible immediately
            # to a fresh reader, but must not leak into the in-flight doctor result.
            generation_a = ("FREE", 0, 0)
            generation_b = ("HELD", int(held["fencing_token"]), 1)
            observed = (
                result.global_writer_state,
                result.current_fencing_token,
                result.exact_operation_prior_acquisition_count,
            )
            self.assertIn(observed, {generation_a, generation_b})
            self.assertEqual(generation_a, observed)
            self.assertEqual("READY", result.status)

            # The writer fixture accounts for the WAL/SHM change.  Doctor reads
            # after that commit add no persistent authority bytes of their own.
            self.assertEqual(post_writer_bytes, self._sqlite_content_bytes())

            fresh = self._writer_store()
            try:
                actual = fresh.get_global_production_writer_lease()
                matching = [
                    row
                    for row in fresh.global_production_writer_events()
                    if row["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
                    and row["new_change_id"] == request.change_id
                    and row["new_slice_id"] == request.operation_id
                    and row["new_writer_class"] == "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
                ]
                self.assertEqual("HELD", actual["state"])
                self.assertEqual(int(held["fencing_token"]), int(actual["fencing_token"]))
                self.assertEqual(1, len(matching))
                self.assertEqual(int(held["fencing_token"]), int(matching[0]["to_fencing_token"]))
            finally:
                fresh.close()
        finally:
            writer_store.close()

    def test_pre_snapshot_committed_wal_writer_state_is_visible(self):
        store, held = self._acquire_w08("pre-snapshot-wal")
        try:
            wal = Path(f"{self.dcs}-wal")
            self.assertTrue(wal.is_file())
            self.assertGreater(wal.stat().st_size, 0)
            result = self.inspect()
            self.assertEqual("NOT_READY", result.status)
            self.assertEqual("HELD", result.global_writer_state)
            self.assertEqual(held["owner_id"], result.global_writer_owner_if_any)
            self.assertEqual(int(held["fencing_token"]), result.current_fencing_token)
        finally:
            store.close()

    def test_static_live_authority_race_is_detected_before_ready(self):
        real_profile_identity = doctor.schema_profile_identity
        profile_reads = 0
        mutation_connection: sqlite3.Connection | None = None

        def profile_with_static_live_race(
            connection: sqlite3.Connection, schema: int
        ) -> str:
            nonlocal profile_reads, mutation_connection
            value = real_profile_identity(connection, schema)
            profile_reads += 1
            if profile_reads == 1:
                # Static immutable authority is already established.  Commit a
                # newer schema generation to WAL before the live snapshot begins.
                mutation_connection = sqlite3.connect(self.dcs, isolation_level=None)
                mutation_connection.execute(
                    "INSERT INTO schema_migration(version,name,checksum,applied_at) "
                    "VALUES (10,'future-race',"
                    "'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',"
                    "'2026-09-10T00:00:00+00:00')"
                )
            return value

        try:
            with patch(
                "adcp.production_control_surface.schema_profile_identity",
                side_effect=profile_with_static_live_race,
            ):
                result = self.inspect()
            self.assertEqual(1, profile_reads)
            self.assertEqual("ERROR", result.status)
            self.assertEqual("DCS_SCHEMA_MALFORMED", result.error_code)
            self.assertEqual(9, result.dcs_schema)
            self.assertNotEqual("READY", result.status)
            self.assertIn("immutable=9,live=10", result.diagnostic_detail or "")
        finally:
            if mutation_connection is not None:
                mutation_connection.close()

    def test_repeated_doctor_calls_preserve_db_wal_shm_bytes(self):
        store, _ = self._acquire_w08("unrelated-byte-holder")
        try:
            before = self._sqlite_content_bytes()
            self.assertIn(f"{self.dcs.name}-wal", before)
            self.assertIn(f"{self.dcs.name}-shm", before)
            first = self.inspect(self.request(operation_id="byte-check-1"))
            middle = self._sqlite_content_bytes()
            second = self.inspect(self.request(operation_id="byte-check-2"))
            after = self._sqlite_content_bytes()
            self.assertEqual("NOT_READY", first.status)
            self.assertEqual("NOT_READY", second.status)
            self.assertEqual(before, middle)
            self.assertEqual(before, after)
        finally:
            store.close()

    def test_live_read_transaction_rolls_back_and_closes_on_success_and_sql_error(self):
        class TrackingConnection(sqlite3.Connection):
            rollback_calls = 0
            close_calls = 0

            def rollback(self):
                self.rollback_calls += 1
                return super().rollback()

            def close(self):
                self.close_calls += 1
                return super().close()

        captured: list[TrackingConnection] = []

        def tracked_live_connection(path: Path) -> sqlite3.Connection:
            connection = sqlite3.connect(
                path.resolve(strict=False).as_uri() + "?mode=ro",
                uri=True,
                factory=TrackingConnection,
            )
            captured.append(connection)
            return doctor._configure_readonly_connection(connection)

        with patch(
            "adcp.production_control_surface._readonly_live_connection",
            side_effect=tracked_live_connection,
        ):
            success = self.inspect()
        self.assertEqual("READY", success.status)
        self.assertEqual(1, captured[-1].rollback_calls)
        self.assertEqual(1, captured[-1].close_calls)

        with patch(
            "adcp.production_control_surface._readonly_live_connection",
            side_effect=tracked_live_connection,
        ), patch(
            "adcp.production_control_surface._prior_w08_acquisition_count",
            side_effect=sqlite3.OperationalError("fixture operation read failure"),
        ):
            failure = self.inspect()
        self.assertEqual("ERROR", failure.status)
        self.assertEqual("OPERATION_BINDING_INVALID", failure.error_code)
        self.assertEqual(1, captured[-1].rollback_calls)
        self.assertEqual(1, captured[-1].close_calls)

    def test_change_subchange_operation_identity_round_trips_exactly(self):
        request = self.request(
            change_id="PARENT-CHANGE",
            unit_id="EXACT-C2-SUBCHANGE",
            operation_id="exact-operation:wheel-4",
        )
        result = self.inspect(request)
        self.assertEqual("PARENT-CHANGE", result.request_change_id)
        self.assertEqual("EXACT-C2-SUBCHANGE", result.request_unit_or_subchange_id)
        self.assertEqual("exact-operation:wheel-4", result.request_operation_id)
        self.assertNotEqual(result.request_change_id, result.request_unit_or_subchange_id)

    def test_no_parent_subchange_substitution_in_prior_match(self):
        store, held = self._acquire_w08("EXACT-C2-SUBCHANGE", change_id="PARENT-CHANGE")
        store.release_global_production_writer(
            operation_key=operation_key("doctor-fixture-release-parent-check", {"n": 1}),
            owner_id=held["owner_id"], fencing_token=held["fencing_token"],
            control_decision_ref="DOCTOR/FIXTURE",
        )
        store.close()
        result = self.inspect(
            self.request(
                change_id="PARENT-CHANGE",
                unit_id="EXACT-C2-SUBCHANGE",
                operation_id="DIFFERENT-OPERATION",
            )
        )
        self.assertEqual(0, result.exact_operation_prior_acquisition_count)
        self.assertEqual("EXACT-C2-SUBCHANGE", result.request_unit_or_subchange_id)

    def test_request_contract_has_only_semantic_fields(self):
        names = {field.name for field in fields(ProductionControlSurfaceRequest)}
        self.assertEqual(
            {
                "request_version", "expected_controller_commit", "change_id",
                "unit_or_subchange_id", "operation_id",
            },
            names,
        )
        forbidden = {
            "shell_command", "command", "argv", "python_path", "controller_root",
            "database_path", "sqlite_sql", "migration_path", "writer_class",
            "module", "working_directory",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_invalid_operation_binding_fails_closed(self):
        bad = ProductionControlSurfaceRequest(1, self.head, "PARENT", "SUB", "bad operation with spaces")
        result = self.inspect(bad)
        self.assertEqual("ERROR", result.status)
        self.assertEqual("OPERATION_BINDING_INVALID", result.error_code)

    def test_controller_head_mismatch_and_dirty_are_typed(self):
        mismatch = self.inspect(self.request(expected_commit="f" * 40))
        self.assertEqual("CONTROLLER_HEAD_MISMATCH", mismatch.error_code)
        (self.repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        dirty = self.inspect()
        self.assertEqual("CONTROLLER_DIRTY", dirty.error_code)

    def test_controller_root_and_interpreter_failures_are_typed(self):
        nested = self.repo / "nested"
        nested.mkdir()
        wrong_root = _inspect_production_control_surface(
            self.request(), _ProductionControlSurfaceBindings(nested, Path(sys.executable).absolute(), self.dcs)
        )
        self.assertEqual("CONTROLLER_ROOT_MISMATCH", wrong_root.error_code)

        missing = _inspect_production_control_surface(
            self.request(), _ProductionControlSurfaceBindings(self.repo, self.root / "missing-python", self.dcs)
        )
        self.assertEqual("CONTROLLER_INTERPRETER_MISSING", missing.error_code)

        fake = self.root / "other-python"
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o700)
        mismatch = _inspect_production_control_surface(
            self.request(), _ProductionControlSurfaceBindings(self.repo, fake, self.dcs)
        )
        self.assertEqual("CONTROLLER_INTERPRETER_MISMATCH", mismatch.error_code)

        with patch.object(doctor.sys, "version_info", (3, 14, 0)):
            unsupported = self.inspect()
        self.assertEqual("CONTROLLER_PYTHON_UNSUPPORTED", unsupported.error_code)

    def test_writer_state_malformed_maps_to_typed_error(self):
        with patch("adcp.production_control_surface._validate_writer_row", side_effect=ValueError("fixture")):
            result = self.inspect()
        self.assertEqual("WRITER_STATE_MALFORMED", result.error_code)

    def test_cli_json_contract_and_malformed_input_are_deterministic(self):
        with patch("adcp.production_control_surface._canonical_bindings", return_value=self.bindings):
            stdin = io.StringIO(json.dumps(self.request().__dict__))
            stdout = io.StringIO()
            self.assertEqual(0, doctor.main(stdin, stdout))
            payload = json.loads(stdout.getvalue())
            self.assertEqual("READY", payload["status"])
            self.assertEqual("NO", payload["mutation_exercised"])
            self.assertEqual(0, payload["w08_acquire_count"])

            malformed_out = io.StringIO()
            self.assertEqual(0, doctor.main(io.StringIO('{"command":"echo nope"}'), malformed_out))
            malformed = json.loads(malformed_out.getvalue())
            self.assertEqual("OPERATION_BINDING_INVALID", malformed["error_code"])

    def test_source_contains_no_controlstore_or_mutating_sql_path(self):
        source = Path(doctor.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ControlStore(", source)
        for sql in ("CREATE ", "INSERT ", "UPDATE ", "DELETE ", "journal_mode", "CHECKPOINT"):
            self.assertNotIn(sql, source)
        self.assertIn("mode=ro&immutable=1", source)
        self.assertIn("PRAGMA query_only = ON", source)
        self.assertIn('live_connection.execute("BEGIN")', source)
        self.assertNotIn("BEGIN IMMEDIATE", source)
        self.assertNotIn("BEGIN EXCLUSIVE", source)


if __name__ == "__main__":
    unittest.main()
