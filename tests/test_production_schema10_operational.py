from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import plistlib
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import adcp.production_dcs_v8_adoption as dcs_adoption
import adcp.production_schema10_operational as schema10
from adcp.production_dcs_v8_adoption import (
    DcsWriterInventory,
    ProductionDcsV8AdoptionError,
    _LaunchdWriterAuthority,
    _QuiescenceToken,
)
from adcp.production_schema10_operational import (
    EXPECTED_WRITERS,
    PRODUCTION_PRODUCT_COMMIT,
    SCHEMA9_PROFILE,
    SCHEMA10_PROFILE,
    V04_CLIENT_BUILD,
    V05_CLIENT_BUILD,
    ProductionSchema10OperationalError,
    Schema10HeldW08,
    Schema10WriterTransition,
    _acquire_schema9_w08,
    _authorized_document_bytes,
    _create_schema9_to10_immutable_backup,
    _inspect_schema,
    _transition_authorized_projection,
    verify_schema9_to10_immutable_backup,
)
from adcp.store import migrations


def _schema_db(path: Path, version: int) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        migrations.migrate(connection, backup_root=None, target_version=version)
    finally:
        connection.close()


def _backup(path: Path, root: Path, operation_id: str):
    return _create_schema9_to10_immutable_backup(
        path,
        root,
        operation_id,
        now=datetime(2026, 9, 13, 1, 2, 3, tzinfo=timezone.utc),
    )


def _prepared_transition_for_test(
    operation_id: str, backup
) -> Schema10WriterTransition:
    transition = Schema10WriterTransition(operation_id)
    transition._state = "BACKED_UP"
    transition._backup = backup
    transition._v05_token = object()
    transition._assert_exact_v05_quiesced = lambda: None
    return transition


def _lease(path: Path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return dict(
            connection.execute(
                "SELECT * FROM global_production_writer_lease "
                "WHERE resource_key='GLOBAL_PRODUCTION'"
            ).fetchone()
        )
    finally:
        connection.close()


def _event_rows(path: Path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM global_production_writer_event ORDER BY event_seq"
            )
        ]
    finally:
        connection.close()


def _authorized_doc(writer_id: str, build: str) -> dict[str, object]:
    source = PRODUCTION_PRODUCT_COMMIT
    artifact = f"source-commit:{source}"
    return {
        "writer_id": writer_id,
        "service_code": EXPECTED_WRITERS[writer_id],
        "product_build_commit": source,
        "product_build_identity": (
            f"product:PropertyAI@g{source[:12]}|source={source}|artifact={artifact}"
        ),
        "source_root_or_artifact_identity": artifact,
        "global_writer_client_build": build,
        "config_artifact_identity": f"cfg:{writer_id}",
    }


def _write_authorized_root(root: Path, build: str) -> dict[str, bytes]:
    root.mkdir()
    originals: dict[str, bytes] = {}
    for writer_id in EXPECTED_WRITERS:
        payload = _authorized_document_bytes(_authorized_doc(writer_id, build))
        (root / f"{writer_id}.authorized.json").write_bytes(payload)
        originals[writer_id] = payload
    return originals


class _InactiveLaunchctlRunner:
    def __init__(self) -> None:
        self.last_label = "com.propertyai.cleaning-completion"

    def __call__(self, args, **_kwargs):
        call = tuple(str(value) for value in args)
        if len(call) >= 3 and call[1] == "print":
            self.last_label = call[2].rsplit("/", 1)[-1]
            return subprocess.CompletedProcess(call, 113, "", "not loaded")
        if len(call) >= 2 and call[1] == "print-disabled":
            return subprocess.CompletedProcess(
                call, 0, f'{{ "{self.last_label}" => true }}\n', ""
            )
        return subprocess.CompletedProcess(call, 0, "", "")

    @staticmethod
    def process_probe(_pid, _arguments):
        return False, False


def _write_actual_thin_startup(site: Path, accepted) -> None:
    package = site / "adcp_global_writer_client"
    package.mkdir(parents=True, exist_ok=True)
    for old in site.glob("adcp_global_writer_client-*.dist-info"):
        for child in old.iterdir():
            child.unlink()
        old.rmdir()
    dist = site / f"adcp_global_writer_client-{accepted.version}.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: adcp-global-writer-client\nVersion: {accepted.version}\n",
        encoding="utf-8",
    )
    (package / "_build_identity.py").write_text(
        "\n".join(
            (
                "CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'",
                f"CLIENT_VERSION = '{accepted.version}'",
                f"SOURCE_COMMIT = '{accepted.source_commit}'",
                f"BUILD_ID = '{accepted.build_id}'",
                f"ARTIFACT_IDENTITY = '{accepted.artifact_identity}'",
                f"EXPECTED_THIN_CONTRACT_FORMAT_VERSION = {accepted.thin_contract_format_version}",
                f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = '{accepted.schema_contract_identity}'",
                f"EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = {accepted.supported_dcs_schema_versions!r}",
                "",
            )
        ),
        encoding="utf-8",
    )
    (package / "_schema_contract.py").write_text(
        "\n".join(
            (
                f"THIN_CONTRACT_FORMAT_VERSION = {accepted.thin_contract_format_version}",
                f"SUPPORTED_DCS_SCHEMA_VERSIONS = {accepted.supported_dcs_schema_versions!r}",
                f"SCHEMA_CONTRACT_IDENTITY = '{accepted.schema_contract_identity}'",
                "",
            )
        ),
        encoding="utf-8",
    )


def _actual_single_writer_authority(root: Path):
    runtime = root / "runtime"
    launch = root / "LaunchAgents"
    release = root / "releases" / PRODUCTION_PRODUCT_COMMIT
    venv = root / "venv"
    python = venv / "bin" / "python"
    site = venv / "lib" / "python3.13" / "site-packages"
    launch.mkdir(parents=True)
    (release / "propertyai_core").mkdir(parents=True)
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fixture-python")
    artifact = f"source-commit:{PRODUCTION_PRODUCT_COMMIT}"
    product_identity = (
        f"product:PropertyAI@g{PRODUCTION_PRODUCT_COMMIT[:12]}|source="
        f"{PRODUCTION_PRODUCT_COMMIT}|artifact={artifact}"
    )
    (release / "propertyai_core" / "_global_writer_build_identity.py").write_text(
        "\n".join(
            (
                "PRODUCT_IDENTITY_MODULE = 'propertyai_core._global_writer_build_identity'",
                "PRODUCT_NAME = 'PropertyAI'",
                f"PRODUCT_BUILD_COMMIT = '{PRODUCTION_PRODUCT_COMMIT}'",
                f"SOURCE_ARTIFACT_IDENTITY = '{artifact}'",
                f"PRODUCT_BUILD_IDENTITY = '{product_identity}'",
                "",
            )
        ),
        encoding="utf-8",
    )
    _write_actual_thin_startup(site, dcs_adoption._AUTHORIZED_THIN_STARTUP_V10)
    _write_authorized_root(runtime, V05_CLIENT_BUILD)
    dcs = root / "control.sqlite3"
    plist_path = launch / "com.propertyai.cleaning-completion.plist"
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.propertyai.cleaning-completion",
                "ProgramArguments": [str(python), "-m", "fixture.worker"],
                "WorkingDirectory": str(release),
                "EnvironmentVariables": {
                    "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT": str(release),
                    "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT": PRODUCTION_PRODUCT_COMMIT,
                    "PROPERTYAI_GLOBAL_WRITER_DCS_PATH": str(dcs),
                    "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH": str(runtime / "W05.runtime.json"),
                    "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH": str(runtime / "W05.authorized.json"),
                },
            }
        )
    )
    runner = _InactiveLaunchctlRunner()
    authority = _LaunchdWriterAuthority(
        dcs_path=dcs,
        launch_agents_root=launch,
        runtime_root=runtime,
        uid=501,
        runner=runner,
        process_probe=runner.process_probe,
    )
    return authority, runtime, site


class Schema10SharedRuntimeArtifactAttestorRegressionTests(unittest.TestCase):
    def test_w01_w06_transition_keeps_shared_provider_wiring(self) -> None:
        transition = Schema10WriterTransition("schema10-shared-attestor-regression")
        provider = transition._authority.runtime_artifact_attestation
        self.assertIsNotNone(provider)
        sentinel = object()
        entry = SimpleNamespace(writer_id="W01")
        with patch.object(
            schema10, "_attest_schema9_10_runtime_artifact", return_value=sentinel
        ) as shared:
            self.assertIs(sentinel, provider(entry, schema10.SCHEMA10))
        shared.assert_called_once_with(entry, schema10.SCHEMA10)


class Schema10OperationalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_backup_is_exact_create_new_immutable_and_no_prune(self) -> None:
        dcs = self.root / "control.sqlite3"
        evidence = self.root / "evidence"
        _schema_db(dcs, 9)
        evidence.mkdir()
        sentinel = evidence / "sentinel.keep"
        sentinel.write_text("keep", encoding="utf-8")

        backup = _backup(dcs, evidence, "DL85-BACKUP-1")
        verify_schema9_to10_immutable_backup(backup)

        self.assertEqual(SCHEMA9_PROFILE, backup.schema_profile)
        self.assertEqual(SCHEMA9_PROFILE, _inspect_schema(Path(backup.backup_path), 9).profile)
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
        self.assertEqual(0, Path(backup.backup_path).stat().st_mode & 0o222)
        self.assertEqual(0, Path(backup.manifest_path).stat().st_mode & 0o222)
        self.assertEqual(Path(backup.backup_path).stat().st_size, backup.backup_size)

        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _backup(dcs, evidence, "DL85-BACKUP-1")
        self.assertEqual("SCHEMA10_BACKUP_CREATE_NEW_COLLISION", caught.exception.code)
        self.assertTrue(sentinel.exists())

    def test_schema9_w08_crosses_to_schema10_same_identity_without_reacquire(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-W08-1")
        held = _acquire_schema9_w08(dcs, "DL85-W08-1", backup)
        original = (
            held.owner_id,
            held.owner_execution_id,
            held.fencing_token,
            held.acquire_event_seq,
        )
        self.assertEqual(held.fencing_token, held.assert_current())
        self.assertEqual(1, len(_event_rows(dcs)))

        transition = _prepared_transition_for_test("DL85-W08-1", backup)
        migrated = transition.apply_exact_migration10(held)
        self.assertEqual(SCHEMA10_PROFILE, migrated.profile)
        rebound = held.rebind_schema10()
        heartbeat = held.heartbeat()

        self.assertEqual(
            original,
            (
                rebound.owner_id,
                rebound.owner_execution_id,
                rebound.fencing_token,
                rebound.acquire_event_seq,
            ),
        )
        self.assertTrue(heartbeat.heartbeat_same_identity)
        self.assertEqual(1, len(_event_rows(dcs)))
        row = _lease(dcs)
        self.assertEqual("HELD", row["state"])
        self.assertEqual(original[0], row["owner_id"])
        self.assertEqual(original[1], row["owner_execution_id"])
        self.assertEqual(original[2], row["fencing_token"])

        held.close_without_release()
        self.assertEqual("HELD", _lease(dcs)["state"])

    def test_release_is_forbidden_without_internal_writer_restore_proof(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-W08-NORELEASE")
        held = _acquire_schema9_w08(dcs, "DL85-W08-NORELEASE", backup)
        transition = _prepared_transition_for_test("DL85-W08-NORELEASE", backup)
        transition.apply_exact_migration10(held)
        held.rebind_schema10()

        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            held.release_after_schema10_writer_restore()
        self.assertEqual("SCHEMA10_RELEASE_RESTORE_PROOF_MISSING", caught.exception.code)
        self.assertEqual("HELD", _lease(dcs)["state"])
        held.close_without_release()

    def test_reacquire_substitution_and_schema_skip_fail_closed(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-ONE-W08")
        held = _acquire_schema9_w08(dcs, "DL85-ONE-W08", backup)
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _acquire_schema9_w08(dcs, "DL85-ONE-W08", backup)
        self.assertEqual("SCHEMA10_W08_NOT_FREE", caught.exception.code)
        held.close_without_release()

        schema8 = self.root / "schema8.sqlite3"
        _schema_db(schema8, 8)
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _create_schema9_to10_immutable_backup(
                schema8,
                self.root / "evidence8",
                "DL85-SKIP-8-10",
            )
        self.assertIn(
            caught.exception.code,
            {"SCHEMA10_SCHEMA_VERSION_MISMATCH", "SCHEMA10_MIGRATION_HISTORY_INVALID"},
        )
        self.assertFalse(hasattr(Schema10HeldW08, "apply_exact_migration10"))
        public = [
            inspect.signature(Schema10WriterTransition.apply_exact_migration10),
            inspect.signature(Schema10HeldW08.rebind_schema10),
        ]
        self.assertTrue(all("target_version" not in signature.parameters for signature in public))

    def test_wrong_attempt_is_rejected(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-WRONG-IDENTITY")
        held = _acquire_schema9_w08(dcs, "DL85-WRONG-IDENTITY", backup)
        connection = sqlite3.connect(dcs)
        try:
            connection.execute(
                "UPDATE global_production_writer_lease SET owner_execution_id='wrong-attempt' "
                "WHERE resource_key='GLOBAL_PRODUCTION'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            held.assert_current()
        self.assertEqual("SCHEMA10_W08_IDENTITY_MISMATCH", caught.exception.code)
        held.close_without_release()

    def test_authorized_projection_is_exact_idempotent_and_reversible(self) -> None:
        root = self.root / "runtime"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        first = _transition_authorized_projection(
            root,
            from_build=V04_CLIENT_BUILD,
            to_build=V05_CLIENT_BUILD,
            operation_id="DL85-AUTH-1",
        )
        second = _transition_authorized_projection(
            root,
            from_build=V04_CLIENT_BUILD,
            to_build=V05_CLIENT_BUILD,
            operation_id="DL85-AUTH-1",
        )
        self.assertEqual(first, second)
        for writer_id in EXPECTED_WRITERS:
            document = json.loads((root / f"{writer_id}.authorized.json").read_text())
            self.assertEqual(V05_CLIENT_BUILD, document["global_writer_client_build"])

        _transition_authorized_projection(
            root,
            from_build=V05_CLIENT_BUILD,
            to_build=V04_CLIENT_BUILD,
            operation_id="DL85-AUTH-1",
        )
        for writer_id, payload in originals.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())

    def test_authorized_projection_rejects_unknown_identity_before_any_write(self) -> None:
        root = self.root / "runtime"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        bad_path = root / "W03.authorized.json"
        bad = json.loads(bad_path.read_text())
        bad["global_writer_client_build"] = "unapproved-client"
        bad_path.write_bytes(_authorized_document_bytes(bad))

        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _transition_authorized_projection(
                root,
                from_build=V04_CLIENT_BUILD,
                to_build=V05_CLIENT_BUILD,
                operation_id="DL85-AUTH-BAD",
            )
        self.assertEqual("SCHEMA10_AUTHORIZED_CLIENT_BUILD_UNEXPECTED", caught.exception.code)
        for writer_id in set(EXPECTED_WRITERS) - {"W03"}:
            self.assertEqual(
                originals[writer_id],
                (root / f"{writer_id}.authorized.json").read_bytes(),
            )

    def test_projection_compensation_preserves_preexisting_target_and_restores_exact_source(self) -> None:
        root = self.root / "runtime"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target_path = root / "W01.authorized.json"
        target_document = json.loads(target_path.read_text())
        target_document["global_writer_client_build"] = V05_CLIENT_BUILD
        target_bytes = _authorized_document_bytes(target_document)
        target_path.write_bytes(target_bytes)
        before_mode = target_path.stat().st_mode
        calls: list[str] = []
        original_atomic = schema10._atomic_write_exact
        guard_calls = 0

        def tracked_atomic(path, payload, mode):
            calls.append(path.name)
            return original_atomic(path, payload, mode)

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls == 2:
                raise RuntimeError("post-write failure")

        with patch.object(schema10, "_atomic_write_exact", side_effect=tracked_atomic):
            with self.assertRaisesRegex(RuntimeError, "post-write failure"):
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL86-COMPENSATE-EXACT",
                    assert_effect_authority=guard,
                )
        self.assertEqual(target_bytes, target_path.read_bytes())
        self.assertEqual(before_mode, target_path.stat().st_mode)
        self.assertNotIn("W01.authorized.json", calls)
        for writer_id in set(EXPECTED_WRITERS) - {"W01"}:
            self.assertEqual(originals[writer_id], (root / f"{writer_id}.authorized.json").read_bytes())

    def test_projection_compensation_is_forbidden_when_authority_or_event_guard_is_lost(self) -> None:
        for failure_code in (
            "SCHEMA10_W08_AUTHORITY_LOST",
            "SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED",
        ):
            with self.subTest(failure_code=failure_code):
                root = self.root / failure_code
                originals = _write_authorized_root(root, V04_CLIENT_BUILD)
                atomic_calls = 0
                guard_calls = 0
                original_atomic = schema10._atomic_write_exact

                def tracked_atomic(path, payload, mode):
                    nonlocal atomic_calls
                    atomic_calls += 1
                    return original_atomic(path, payload, mode)

                def guard():
                    nonlocal guard_calls
                    guard_calls += 1
                    if guard_calls >= 2:
                        raise ProductionSchema10OperationalError(failure_code)

                with patch.object(schema10, "_atomic_write_exact", side_effect=tracked_atomic):
                    with self.assertRaises(ProductionSchema10OperationalError) as caught:
                        _transition_authorized_projection(
                            root,
                            from_build=V04_CLIENT_BUILD,
                            to_build=V05_CLIENT_BUILD,
                            operation_id=f"DL86-{failure_code[-8:]}",
                            assert_effect_authority=guard,
                        )
                self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
                self.assertEqual(1, atomic_calls)
                self.assertNotEqual(originals["W01"], (root / "W01.authorized.json").read_bytes())
                for writer_id in set(EXPECTED_WRITERS) - {"W01"}:
                    self.assertEqual(
                        originals[writer_id],
                        (root / f"{writer_id}.authorized.json").read_bytes(),
                    )

    def test_exact_entry_state_compensation_restores_absence_only_for_created_entry(self) -> None:
        path = self.root / "created.authorized.json"
        state = schema10._capture_projection_entry_state(
            writer_id="W99",
            path=path,
            source_payload=b"source\n",
            target_payload=b"target\n",
        )
        self.assertFalse(state.existed)
        schema10._atomic_write_exact(path, state.target_payload, 0o600)
        state.changed_by_invocation = True
        schema10._compensate_projection_entries([state], assert_effect_authority=lambda: 0)
        self.assertFalse(path.exists())

    def test_dl87_case_a_pre_replace_failure_is_not_classified_as_mutation(self) -> None:
        path = self.root / "case-a.authorized.json"
        original = b"before-a\n"
        target = b"after-a\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01",
            path=path,
            source_payload=original,
            target_payload=target,
        )
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1

        with patch.object(schema10.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, state.mode or 0o600)
        self.assertFalse(caught.exception.outcome.destination_replaced)
        self.assertEqual("DESTINATION_REPLACE", caught.exception.outcome.failed_operation)
        self.assertTrue(state.write_attempted)
        self.assertFalse(state.destination_replaced)
        self.assertFalse(state.changed_by_invocation)
        schema10._compensate_projection_entries([state], assert_effect_authority=guard)
        self.assertEqual(0, guard_calls)
        self.assertEqual(original, path.read_bytes())

    def test_dl87_case_b_chmod_failure_after_replace_is_compensated_exactly(self) -> None:
        path = self.root / "case-b.authorized.json"
        original = b"before-b\n"
        target = b"after-b\n"
        path.write_bytes(original)
        path.chmod(0o640)
        state = schema10._capture_projection_entry_state(
            writer_id="W01",
            path=path,
            source_payload=original,
            target_payload=target,
        )
        original_chmod = schema10.os.chmod
        calls = 0

        def fail_first_chmod(target_path, mode):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("chmod injected")
            return original_chmod(target_path, mode)

        with patch.object(schema10.os, "chmod", side_effect=fail_first_chmod):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, state.mode or 0o600)
            self.assertTrue(caught.exception.outcome.destination_replaced)
            self.assertEqual("DESTINATION_CHMOD", caught.exception.outcome.failed_operation)
            self.assertTrue(state.changed_by_invocation)
            self.assertFalse(state.post_replace_durability_complete)
            schema10._compensate_projection_entries(
                [state], assert_effect_authority=lambda: None
            )
        self.assertEqual(original, path.read_bytes())
        self.assertEqual(0o640, path.stat().st_mode & 0o777)

    def test_dl87_case_c_directory_fsync_failure_after_replace_is_compensated_exactly(self) -> None:
        path = self.root / "case-c.authorized.json"
        original = b"before-c\n"
        target = b"after-c\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01",
            path=path,
            source_payload=original,
            target_payload=target,
        )
        original_fsync = schema10._fsync_directory
        calls = 0

        def fail_first_fsync(directory):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("directory fsync injected")
            return original_fsync(directory)

        with patch.object(schema10, "_fsync_directory", side_effect=fail_first_fsync):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, state.mode or 0o600)
            self.assertTrue(caught.exception.outcome.destination_replaced)
            self.assertEqual("DIRECTORY_FSYNC", caught.exception.outcome.failed_operation)
            self.assertTrue(state.changed_by_invocation)
            schema10._compensate_projection_entries(
                [state], assert_effect_authority=lambda: None
            )
        self.assertEqual(original, path.read_bytes())

    def test_dl87_case_d_original_absence_is_restored_after_partial_success(self) -> None:
        path = self.root / "case-d.authorized.json"
        state = schema10._capture_projection_entry_state(
            writer_id="W01",
            path=path,
            source_payload=b"",
            target_payload=b"created-d\n",
        )
        original_chmod = schema10.os.chmod
        calls = 0

        def fail_first_chmod(target_path, mode):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("chmod injected")
            return original_chmod(target_path, mode)

        with patch.object(schema10.os, "chmod", side_effect=fail_first_chmod):
            with self.assertRaises(schema10._AtomicWriteFailure):
                schema10._write_projection_entry(state, 0o600)
            self.assertTrue(path.exists())
            self.assertTrue(state.changed_by_invocation)
            schema10._compensate_projection_entries(
                [state], assert_effect_authority=lambda: None
            )
        self.assertFalse(path.exists())

    def test_dl87_case_e_original_bytes_and_mode_are_restored_after_partial_success(self) -> None:
        path = self.root / "case-e.authorized.json"
        original = b"different-original-e\n"
        target = b"target-e\n"
        path.write_bytes(original)
        path.chmod(0o640)
        state = schema10._capture_projection_entry_state(
            writer_id="W01",
            path=path,
            source_payload=original,
            target_payload=target,
        )
        original_fsync = schema10._fsync_directory
        calls = 0

        def fail_first_fsync(directory):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("directory fsync injected")
            return original_fsync(directory)

        with patch.object(schema10, "_fsync_directory", side_effect=fail_first_fsync):
            with self.assertRaises(schema10._AtomicWriteFailure):
                schema10._write_projection_entry(state, state.mode or 0o600)
            schema10._compensate_projection_entries(
                [state], assert_effect_authority=lambda: None
            )
        self.assertEqual(original, path.read_bytes())
        self.assertEqual(0o640, path.stat().st_mode & 0o777)
        self.assertEqual(schema10._sha256_bytes(original), state.payload_sha256)

    def test_dl87_case_f_entry_already_at_target_causes_no_write_or_compensation(self) -> None:
        root = self.root / "case-f"
        originals = _write_authorized_root(root, V05_CLIENT_BUILD)
        with patch.object(schema10, "_atomic_write_exact", wraps=schema10._atomic_write_exact) as atomic:
            evidence = _transition_authorized_projection(
                root,
                from_build=V04_CLIENT_BUILD,
                to_build=V05_CLIENT_BUILD,
                operation_id="DL87-CASE-F",
                assert_effect_authority=lambda: None,
            )
        self.assertEqual(V05_CLIENT_BUILD, evidence.target_client_build)
        self.assertEqual(0, atomic.call_count)
        for writer_id, payload in originals.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())

    def test_dl87_case_g_post_replace_authority_loss_writes_zero_compensation(self) -> None:
        root = self.root / "case-g"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        original_chmod = schema10.os.chmod
        chmod_calls = 0
        guard_calls = 0

        def fail_first_chmod(target_path, mode):
            nonlocal chmod_calls
            chmod_calls += 1
            if chmod_calls == 1:
                raise OSError("chmod injected")
            return original_chmod(target_path, mode)

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls >= 2:
                raise ProductionSchema10OperationalError("SCHEMA10_W08_AUTHORITY_LOST")

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            patch.object(schema10.os, "chmod", side_effect=fail_first_chmod),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL87-CASE-G",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertTrue(detail["destination_replaced"])
        self.assertTrue(detail["changed_by_invocation"])
        self.assertEqual("DESTINATION_CHMOD", detail["failed_post_replace_operation"])
        self.assertEqual("SCHEMA10_W08_AUTHORITY_LOST", detail["authority_event_guard_failure"])
        self.assertEqual("NO_WRITE_MANUAL_RECONCILIATION", detail["required_reconciliation_action"])
        self.assertEqual(1, replace_call.call_count)
        self.assertNotEqual(originals["W01"], (root / "W01.authorized.json").read_bytes())

    def test_dl87_case_h_post_replace_event_guard_loss_writes_zero_compensation(self) -> None:
        root = self.root / "case-h"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        original_fsync = schema10._fsync_directory
        fsync_calls = 0
        guard_calls = 0

        def fail_first_fsync(directory):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("directory fsync injected")
            return original_fsync(directory)

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls >= 2:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED"
                )

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            patch.object(schema10, "_fsync_directory", side_effect=fail_first_fsync),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL87-CASE-H",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertTrue(detail["destination_replaced"])
        self.assertEqual("DIRECTORY_FSYNC", detail["failed_post_replace_operation"])
        self.assertEqual(
            "SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED",
            detail["authority_event_guard_failure"],
        )
        self.assertEqual(1, replace_call.call_count)
        self.assertNotEqual(originals["W01"], (root / "W01.authorized.json").read_bytes())

    def test_dl87_case_i_partial_failure_compensates_then_actual_discovery_is_exact(self) -> None:
        authority, runtime, _site = _actual_single_writer_authority(self.root / "case-i")
        with patch.object(schema10, "EXPECTED_WRITERS", {"W05": EXPECTED_WRITERS["W05"]}):
            before = authority.discover()
            self.assertEqual("0.5.0", before.entries[0].client.version)
            original_fsync = schema10._fsync_directory
            fsync_calls = 0

            def fail_first_fsync(directory):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 1:
                    raise OSError("directory fsync injected")
                return original_fsync(directory)

            with patch.object(schema10, "_fsync_directory", side_effect=fail_first_fsync):
                with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                    _transition_authorized_projection(
                        runtime,
                        from_build=V05_CLIENT_BUILD,
                        to_build=V04_CLIENT_BUILD,
                        operation_id="DL87-CASE-I",
                        assert_effect_authority=lambda: None,
                    )
            self.assertTrue(caught.exception.outcome.destination_replaced)
            self.assertEqual("DIRECTORY_FSYNC", caught.exception.outcome.failed_operation)
            observed = authority.discover()
            self.assertEqual("0.5.0", observed.entries[0].client.version)
            self.assertEqual(schema10.V05_SOURCE, observed.entries[0].client.source_commit)
            self.assertEqual(V05_CLIENT_BUILD, observed.entries[0].client.build_identity)

    def _dl88_unlink_failure(self, destination: Path, error: BaseException):
        original_unlink = Path.unlink
        remaining = {"count": 1}

        def injected_unlink(path: Path, *args, **kwargs):
            if (
                remaining["count"]
                and path.parent.resolve() == destination.parent.resolve()
                and path.name.startswith(f".{destination.name}.dl85-")
                and path.name.endswith(".tmp")
            ):
                remaining["count"] -= 1
                raise error
            return original_unlink(path, *args, **kwargs)

        return patch.object(Path, "unlink", new=injected_unlink)

    def test_dl88_case_a_replace_success_cleanup_permission_preserves_replacement(self) -> None:
        path = self.root / "dl88-a.authorized.json"
        path.write_bytes(b"before-a\n")
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"before-a\n", target_payload=b"after-a\n"
        )
        with self._dl88_unlink_failure(path, PermissionError("cleanup denied")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertTrue(caught.exception.outcome.durability_complete)
        self.assertIsNone(caught.exception.outcome.primary_failure)
        self.assertEqual("builtins.PermissionError", caught.exception.outcome.cleanup_failure.exception_type)
        self.assertEqual("ABSENT", caught.exception.outcome.temp_residual_state)
        self.assertTrue(state.changed_by_invocation)

    def test_dl88_case_b_replace_success_cleanup_oserror_preserves_replacement(self) -> None:
        path = self.root / "dl88-b.authorized.json"
        path.write_bytes(b"before-b\n")
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"before-b\n", target_payload=b"after-b\n"
        )
        with self._dl88_unlink_failure(path, OSError("cleanup io")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertEqual("TEMP_CLEANUP", caught.exception.outcome.failed_operation)
        self.assertEqual("builtins.OSError", caught.exception.outcome.cleanup_failure.exception_type)
        self.assertTrue(state.changed_by_invocation)

    def test_dl88_case_c_replace_failure_plus_cleanup_failure_is_typed_without_false_compensation(self) -> None:
        path = self.root / "dl88-c.authorized.json"
        original = b"before-c\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=b"after-c\n"
        )
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1

        with (
            patch.object(schema10.os, "replace", side_effect=OSError("replace failed")),
            self._dl88_unlink_failure(path, PermissionError("cleanup denied")),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        self.assertFalse(caught.exception.outcome.destination_replaced)
        self.assertEqual("DESTINATION_REPLACE", caught.exception.outcome.primary_failure.operation)
        self.assertEqual("TEMP_CLEANUP", caught.exception.outcome.cleanup_failure.operation)
        self.assertEqual("PRESENT", caught.exception.outcome.temp_residual_state)
        self.assertTrue(caught.exception.outcome.temp_path.endswith(".tmp"))
        self.assertFalse(state.changed_by_invocation)
        schema10._compensate_projection_entries([state], assert_effect_authority=guard)
        self.assertEqual(0, guard_calls)
        self.assertEqual(original, path.read_bytes())

    def test_dl88_case_d_chmod_and_cleanup_failures_are_both_preserved(self) -> None:
        path = self.root / "dl88-d.authorized.json"
        path.write_bytes(b"before-d\n")
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"before-d\n", target_payload=b"after-d\n"
        )
        with (
            patch.object(schema10.os, "chmod", side_effect=OSError("chmod failed")),
            self._dl88_unlink_failure(path, OSError("cleanup failed")),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertFalse(caught.exception.outcome.durability_complete)
        self.assertEqual("DESTINATION_CHMOD", caught.exception.outcome.primary_failure.operation)
        self.assertEqual("TEMP_CLEANUP", caught.exception.outcome.cleanup_failure.operation)
        self.assertTrue(state.changed_by_invocation)

    def test_dl88_case_e_directory_fsync_and_cleanup_failures_are_both_preserved(self) -> None:
        path = self.root / "dl88-e.authorized.json"
        path.write_bytes(b"before-e\n")
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"before-e\n", target_payload=b"after-e\n"
        )
        with (
            patch.object(schema10, "_fsync_directory", side_effect=OSError("fsync failed")),
            self._dl88_unlink_failure(path, OSError("cleanup failed")),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertEqual("DIRECTORY_FSYNC", caught.exception.outcome.primary_failure.operation)
        self.assertEqual("TEMP_CLEANUP", caught.exception.outcome.cleanup_failure.operation)
        self.assertTrue(state.changed_by_invocation)

    def test_dl88_case_f_cleanup_failure_enters_reconciliation_and_restores_original(self) -> None:
        root = self.root / "dl88-f"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl88_unlink_failure(target, PermissionError("cleanup denied")),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL88-CASE-F",
                    assert_effect_authority=lambda: None,
                )
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertTrue(caught.exception.outcome.durability_complete)
        self.assertEqual(originals["W01"], target.read_bytes())

    def test_dl88_case_g_cleanup_failure_guard_valid_compensation_succeeds(self) -> None:
        root = self.root / "dl88-g"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl88_unlink_failure(target, OSError("cleanup failed")),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure):
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL88-CASE-G",
                    assert_effect_authority=guard,
                )
        self.assertGreaterEqual(guard_calls, 2)
        self.assertEqual(originals["W01"], target.read_bytes())

    def test_dl88_case_h_cleanup_failure_authority_guard_lost_writes_zero_compensation(self) -> None:
        root = self.root / "dl88-h"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls >= 2:
                raise ProductionSchema10OperationalError("SCHEMA10_W08_AUTHORITY_LOST")

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl88_unlink_failure(target, PermissionError("cleanup denied")),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL88-CASE-H",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertTrue(detail["destination_state"]["replaced"])
        self.assertEqual("FAILED", detail["cleanup_state"]["status"])
        self.assertEqual("ABSENT", detail["temp_residual_state"]["state"])
        self.assertEqual("SCHEMA10_W08_AUTHORITY_LOST", detail["authority_event_guard_failure"])
        self.assertEqual(1, replace_call.call_count)
        self.assertNotEqual(originals["W01"], target.read_bytes())

    def test_dl88_case_i_cleanup_failure_event_guard_lost_writes_zero_compensation(self) -> None:
        root = self.root / "dl88-i"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls >= 2:
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED")

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl88_unlink_failure(target, OSError("cleanup failed")),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL88-CASE-I",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED", detail["authority_event_guard_failure"])
        self.assertEqual(1, replace_call.call_count)
        self.assertNotEqual(originals["W01"], target.read_bytes())

    def test_dl88_case_j_temp_already_absent_is_benign(self) -> None:
        path = self.root / "dl88-j.authorized.json"
        path.write_bytes(b"before-j\n")
        original_unlink = Path.unlink

        def benign_absent(temp: Path, *args, **kwargs):
            if temp.name.startswith(f".{path.name}.dl85-"):
                raise FileNotFoundError(temp)
            return original_unlink(temp, *args, **kwargs)

        with patch.object(Path, "unlink", new=benign_absent):
            outcome = schema10._atomic_write_exact(path, b"after-j\n", 0o600)
        self.assertTrue(outcome.destination_replaced)
        self.assertTrue(outcome.durability_complete)
        self.assertIsNone(outcome.primary_failure)
        self.assertIsNone(outcome.cleanup_failure)
        self.assertEqual("NONE", outcome.temp_residual_state)
        self.assertEqual(b"after-j\n", path.read_bytes())

    @contextmanager
    def _dl89_directory_io(
        self,
        directory: Path,
        *,
        open_error: BaseException | None = None,
        fsync_error: BaseException | None = None,
        close_error: BaseException | None = None,
        fail_count: int = 1,
    ):
        original_open = schema10.os.open
        original_fsync = schema10.os.fsync
        original_close = schema10.os.close
        target = directory.resolve()
        directory_fds: dict[int, bool] = {}
        directory_calls = 0

        def injected_open(path, flags, *args, **kwargs):
            nonlocal directory_calls
            is_directory = Path(path).resolve() == target and not (
                flags & (schema10.os.O_WRONLY | schema10.os.O_RDWR)
            )
            if not is_directory:
                return original_open(path, flags, *args, **kwargs)
            directory_calls += 1
            injected = directory_calls <= fail_count
            if injected and open_error is not None:
                raise open_error
            fd = original_open(path, flags, *args, **kwargs)
            directory_fds[fd] = injected
            return fd

        def injected_fsync(fd):
            if directory_fds.get(fd, False) and fsync_error is not None:
                raise fsync_error
            return original_fsync(fd)

        def injected_close(fd):
            injected = directory_fds.pop(fd, False)
            if injected and close_error is not None:
                # Close the real test descriptor to avoid leaking it while still
                # injecting the observed close failure into the helper.
                original_close(fd)
                raise close_error
            return original_close(fd)

        with (
            patch.object(schema10.os, "open", side_effect=injected_open),
            patch.object(schema10.os, "fsync", side_effect=injected_fsync),
            patch.object(schema10.os, "close", side_effect=injected_close),
        ):
            yield

    def test_dl89_case_a_directory_open_failure_is_exact_typed_outcome(self) -> None:
        with self._dl89_directory_io(self.root, open_error=OSError("open failed")):
            with self.assertRaises(schema10._DirectoryDurabilityFailure) as caught:
                schema10._fsync_directory(self.root)
        outcome = caught.exception.outcome
        self.assertEqual("FAIL", outcome.open_status)
        self.assertEqual("NOT_ATTEMPTED", outcome.fsync_status)
        self.assertEqual("NOT_ATTEMPTED", outcome.close_status)
        self.assertEqual("DIRECTORY_OPEN", outcome.open_failure.operation)

    def test_dl89_case_b_directory_fsync_and_close_success_are_exact(self) -> None:
        outcome = schema10._fsync_directory(self.root)
        self.assertEqual("SUCCESS", outcome.open_status)
        self.assertEqual("SUCCESS", outcome.fsync_status)
        self.assertEqual("SUCCESS", outcome.close_status)
        self.assertTrue(outcome.fsync_complete)
        self.assertTrue(outcome.operation_complete)

    def test_dl89_case_c_fsync_success_close_failure_preserves_fsync_success(self) -> None:
        with self._dl89_directory_io(self.root, close_error=OSError("close failed")):
            with self.assertRaises(schema10._DirectoryDurabilityFailure) as caught:
                schema10._fsync_directory(self.root)
        outcome = caught.exception.outcome
        self.assertEqual("SUCCESS", outcome.fsync_status)
        self.assertEqual("FAIL", outcome.close_status)
        self.assertTrue(outcome.fsync_complete)
        self.assertEqual("DIRECTORY_CLOSE", outcome.close_failure.operation)
        self.assertIsNone(outcome.fsync_failure)

    def test_dl89_case_d_fsync_failure_close_success_preserves_fsync_failure(self) -> None:
        with self._dl89_directory_io(self.root, fsync_error=OSError("fsync failed")):
            with self.assertRaises(schema10._DirectoryDurabilityFailure) as caught:
                schema10._fsync_directory(self.root)
        outcome = caught.exception.outcome
        self.assertEqual("FAIL", outcome.fsync_status)
        self.assertEqual("SUCCESS", outcome.close_status)
        self.assertEqual("DIRECTORY_FSYNC", outcome.fsync_failure.operation)
        self.assertIsNone(outcome.close_failure)

    def test_dl89_case_e_fsync_and_close_failures_are_both_preserved(self) -> None:
        with self._dl89_directory_io(
            self.root,
            fsync_error=OSError("fsync fail-a"),
            close_error=OSError("close fail-b"),
        ):
            with self.assertRaises(schema10._DirectoryDurabilityFailure) as caught:
                schema10._fsync_directory(self.root)
        outcome = caught.exception.outcome
        self.assertEqual("DIRECTORY_FSYNC", outcome.fsync_failure.operation)
        self.assertEqual("fsync fail-a", outcome.fsync_failure.detail)
        self.assertEqual("DIRECTORY_CLOSE", outcome.close_failure.operation)
        self.assertEqual("close fail-b", outcome.close_failure.detail)

    def test_dl89_case_f_close_failure_after_replace_keeps_mutation_and_durability_facts(self) -> None:
        path = self.root / "dl89-f.authorized.json"
        original = b"before-f\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=b"after-f\n"
        )
        with self._dl89_directory_io(path.parent, close_error=OSError("close failed")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, 0o600)
        outcome = caught.exception.outcome
        self.assertTrue(outcome.destination_replaced)
        self.assertTrue(outcome.durability_complete)
        self.assertEqual("DIRECTORY_CLOSE", outcome.failed_operation)
        self.assertIsNone(outcome.primary_failure)
        self.assertEqual("SUCCESS", outcome.directory_outcome.fsync_status)
        self.assertEqual("FAIL", outcome.directory_outcome.close_status)
        self.assertEqual("DIRECTORY_CLOSE", outcome.secondary_failures[0].operation)
        self.assertTrue(state.changed_by_invocation)
        self.assertTrue(state.post_replace_durability_complete)

    def test_dl89_case_g_combined_failure_reconciliation_preserves_both_directory_errors(self) -> None:
        path = self.root / "dl89-g.authorized.json"
        original = b"before-g\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=b"after-g\n"
        )
        with self._dl89_directory_io(
            path.parent,
            fsync_error=OSError("fsync g"),
            close_error=OSError("close g"),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure):
                schema10._write_projection_entry(state, 0o600)
        detail = json.loads(
            schema10._projection_reconciliation_detail(
                state, guard_failure=None, required_action="DL89_VERIFY"
            )
        )
        self.assertTrue(detail["destination_state"]["replaced"])
        self.assertEqual("FAIL", detail["directory_durability_state"]["fsync"])
        self.assertEqual("FAIL", detail["directory_durability_state"]["close"])
        self.assertEqual("DIRECTORY_FSYNC", detail["primary_write_state"]["operation"])
        self.assertEqual("DIRECTORY_CLOSE", detail["secondary_failures"][0]["operation"])

    def test_dl89_case_h_combined_failure_guard_valid_compensation_remains_exact(self) -> None:
        root = self.root / "dl89-h"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl89_directory_io(
                root,
                fsync_error=OSError("fsync h"),
                close_error=OSError("close h"),
                fail_count=1,
            ),
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL89-CASE-H",
                    assert_effect_authority=lambda: None,
                )
        self.assertEqual("DIRECTORY_FSYNC", caught.exception.outcome.primary_failure.operation)
        self.assertEqual("DIRECTORY_CLOSE", caught.exception.outcome.secondary_failures[0].operation)
        self.assertEqual(originals["W01"], target.read_bytes())

    def test_dl89_case_i_combined_failure_guard_lost_writes_zero_and_reports_both(self) -> None:
        root = self.root / "dl89-i"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls >= 2:
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED")

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            self._dl89_directory_io(
                root,
                fsync_error=OSError("fsync i"),
                close_error=OSError("close i"),
                fail_count=1,
            ),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL89-CASE-I",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("FAIL", detail["directory_durability_state"]["fsync"])
        self.assertEqual("FAIL", detail["directory_durability_state"]["close"])
        self.assertEqual("DIRECTORY_FSYNC", detail["primary_write_state"]["operation"])
        self.assertEqual("DIRECTORY_CLOSE", detail["secondary_failures"][0]["operation"])
        self.assertEqual("SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED", detail["authority_event_guard_failure"])
        self.assertEqual(1, replace_call.call_count)
        self.assertNotEqual(originals["W01"], target.read_bytes())

    @contextmanager
    def _dl90_temp_stream_io(
        self,
        *,
        write_error: BaseException | None = None,
        flush_error: BaseException | None = None,
        fsync_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ):
        original_fdopen = schema10.os.fdopen
        original_fsync = schema10.os.fsync
        temp_fds: set[int] = set()

        class InjectedStream:
            def __init__(self, fd: int, mode: str, closefd: bool) -> None:
                self.fd = fd
                self.inner = original_fdopen(fd, mode, closefd=closefd)
                temp_fds.add(fd)

            def write(self, payload):
                if write_error is not None:
                    raise write_error
                return self.inner.write(payload)

            def flush(self):
                if flush_error is not None:
                    raise flush_error
                return self.inner.flush()

            def fileno(self):
                return self.inner.fileno()

            def close(self):
                try:
                    self.inner.close()
                finally:
                    temp_fds.discard(self.fd)
                if close_error is not None:
                    raise close_error

        def injected_fdopen(fd, mode, closefd=True):
            return InjectedStream(fd, mode, closefd)

        def injected_fsync(fd):
            if fd in temp_fds and fsync_error is not None:
                raise fsync_error
            return original_fsync(fd)

        with (
            patch.object(schema10.os, "fdopen", side_effect=injected_fdopen),
            patch.object(schema10.os, "fsync", side_effect=injected_fsync),
        ):
            yield

    def _dl90_changed_state(self, name: str):
        path = self.root / f"{name}.authorized.json"
        original = f"before-{name}\n".encode()
        target = f"after-{name}\n".encode()
        path.write_bytes(original)
        path.chmod(0o640)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=target
        )
        schema10._write_projection_entry(state, state.mode or 0o600)
        self.assertTrue(state.changed_by_invocation)
        return path, original, target, state

    def test_dl90_t1_temp_write_failure_close_success_preserves_write_primary(self) -> None:
        path = self.root / "dl90-t1.authorized.json"
        path.write_bytes(b"before-t1\n")
        with self._dl90_temp_stream_io(write_error=OSError("write t1")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-t1\n", 0o600)
        stream = caught.exception.outcome.temp_stream_outcome
        self.assertEqual("SUCCESS", stream.open_status)
        self.assertEqual("FAIL", stream.write_status)
        self.assertEqual("NOT_ATTEMPTED", stream.flush_status)
        self.assertEqual("NOT_ATTEMPTED", stream.fsync_status)
        self.assertEqual("SUCCESS", stream.close_status)
        self.assertEqual("TEMP_WRITE", caught.exception.outcome.primary_failure.operation)
        self.assertEqual((), caught.exception.outcome.secondary_failures)
        self.assertEqual(b"before-t1\n", path.read_bytes())

    def test_dl90_t2_temp_write_and_close_failures_preserve_primary_and_secondary(self) -> None:
        path = self.root / "dl90-t2.authorized.json"
        path.write_bytes(b"before-t2\n")
        with self._dl90_temp_stream_io(
            write_error=OSError("write t2"), close_error=OSError("close t2")
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-t2\n", 0o600)
        outcome = caught.exception.outcome
        self.assertEqual("TEMP_WRITE", outcome.primary_failure.operation)
        self.assertEqual("write t2", outcome.primary_failure.detail)
        self.assertEqual("TEMP_STREAM_CLOSE", outcome.secondary_failures[0].operation)
        self.assertEqual("close t2", outcome.secondary_failures[0].detail)
        self.assertEqual("FAIL", outcome.temp_stream_outcome.close_status)
        self.assertEqual(b"before-t2\n", path.read_bytes())

    def test_dl90_t3_temp_flush_and_close_failures_preserve_primary_and_secondary(self) -> None:
        path = self.root / "dl90-t3.authorized.json"
        path.write_bytes(b"before-t3\n")
        with self._dl90_temp_stream_io(
            flush_error=OSError("flush t3"), close_error=OSError("close t3")
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-t3\n", 0o600)
        outcome = caught.exception.outcome
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.write_status)
        self.assertEqual("FAIL", outcome.temp_stream_outcome.flush_status)
        self.assertEqual("NOT_ATTEMPTED", outcome.temp_stream_outcome.fsync_status)
        self.assertEqual("TEMP_FLUSH", outcome.primary_failure.operation)
        self.assertEqual("TEMP_STREAM_CLOSE", outcome.secondary_failures[0].operation)

    def test_dl90_t4_temp_fsync_and_close_failures_preserve_primary_and_secondary(self) -> None:
        path = self.root / "dl90-t4.authorized.json"
        path.write_bytes(b"before-t4\n")
        with self._dl90_temp_stream_io(
            fsync_error=OSError("fsync t4"), close_error=OSError("close t4")
        ):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-t4\n", 0o600)
        outcome = caught.exception.outcome
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.write_status)
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.flush_status)
        self.assertEqual("FAIL", outcome.temp_stream_outcome.fsync_status)
        self.assertEqual("TEMP_FSYNC", outcome.primary_failure.operation)
        self.assertEqual("TEMP_STREAM_CLOSE", outcome.secondary_failures[0].operation)

    def test_dl90_t5_temp_close_only_failure_is_exact_primary(self) -> None:
        path = self.root / "dl90-t5.authorized.json"
        path.write_bytes(b"before-t5\n")
        with self._dl90_temp_stream_io(close_error=OSError("close t5")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-t5\n", 0o600)
        outcome = caught.exception.outcome
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.write_status)
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.flush_status)
        self.assertEqual("SUCCESS", outcome.temp_stream_outcome.fsync_status)
        self.assertEqual("FAIL", outcome.temp_stream_outcome.close_status)
        self.assertEqual("TEMP_STREAM_CLOSE", outcome.primary_failure.operation)
        self.assertEqual((), outcome.secondary_failures)
        self.assertFalse(outcome.destination_replaced)

    def test_dl90_t6_temp_stream_all_success_records_every_phase(self) -> None:
        path = self.root / "dl90-t6.authorized.json"
        path.write_bytes(b"before-t6\n")
        outcome = schema10._atomic_write_exact(path, b"after-t6\n", 0o600)
        stream = outcome.temp_stream_outcome
        self.assertEqual(
            ("SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS"),
            (
                stream.open_status,
                stream.write_status,
                stream.flush_status,
                stream.fsync_status,
                stream.close_status,
            ),
        )
        self.assertTrue(stream.operation_complete)
        self.assertTrue(outcome.destination_replaced)
        self.assertEqual("SUCCESS", outcome.chmod_status)
        self.assertTrue(outcome.durability_complete)
        self.assertEqual(b"after-t6\n", path.read_bytes())

    def test_dl90_c1_compensation_restore_success_records_exact_restore_outcome(self) -> None:
        path, original, _target, state = self._dl90_changed_state("c1")
        schema10._compensate_projection_entries(
            [state],
            assert_effect_authority=lambda: None,
            original_operation_error=RuntimeError("original c1"),
        )
        restore = schema10._compensation_restoration_payload(state)
        self.assertEqual(original, path.read_bytes())
        self.assertTrue(restore["restore_attempted"])
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("SUCCESS", restore["restore_file_content_synced"])
        self.assertEqual("SUCCESS", restore["restore_chmod_outcome"])
        self.assertEqual("SUCCESS", restore["restore_directory_fsync_outcome"])
        self.assertEqual("SUCCESS", restore["restore_directory_close_outcome"])
        self.assertEqual("SUCCESS", restore["restore_temp_cleanup_outcome"])
        self.assertTrue(restore["restore_durability_complete"])
        self.assertIsNone(restore["restore_primary_failure"])
        self.assertEqual([], restore["restore_secondary_failures"])
        self.assertEqual(schema10._sha256_bytes(original), restore["restore_readback_state"]["sha256"])

    def test_dl90_c2_restore_replace_then_directory_fsync_failure_uses_restore_outcome(self) -> None:
        path, original, _target, state = self._dl90_changed_state("c2")
        self.assertIsNone(state.last_write_outcome.primary_failure)
        with self._dl89_directory_io(path.parent, fsync_error=OSError("restore fsync c2")):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("original c2"),
                )
        detail = json.loads(caught.exception.detail)
        restore = detail["compensation_restoration"]
        self.assertEqual("COMPLETE", detail["primary_write_state"]["status"])
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("FAIL", restore["restore_directory_fsync_outcome"])
        self.assertEqual("SUCCESS", restore["restore_directory_close_outcome"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual(schema10._sha256_bytes(original), restore["restore_readback_state"]["sha256"])

    def test_dl90_c3_restore_directory_fsync_and_close_failures_preserves_both(self) -> None:
        path, original, _target, state = self._dl90_changed_state("c3")
        with self._dl89_directory_io(
            path.parent,
            fsync_error=OSError("restore fsync c3"),
            close_error=OSError("restore close c3"),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("original c3"),
                )
        restore = json.loads(caught.exception.detail)["compensation_restoration"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("FAIL", restore["restore_directory_fsync_outcome"])
        self.assertEqual("FAIL", restore["restore_directory_close_outcome"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("DIRECTORY_CLOSE", restore["restore_secondary_failures"][0]["operation"])
        self.assertEqual(schema10._sha256_bytes(original), restore["restore_readback_state"]["sha256"])

    def test_dl90_c4_restore_temp_cleanup_failure_preserves_restore_and_cleanup_evidence(self) -> None:
        path, original, _target, state = self._dl90_changed_state("c4")
        with self._dl88_unlink_failure(path, OSError("restore cleanup c4")):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("original c4"),
                )
        restore = json.loads(caught.exception.detail)["compensation_restoration"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertTrue(restore["restore_durability_complete"])
        self.assertEqual("FAIL", restore["restore_temp_cleanup_outcome"])
        self.assertIsNone(restore["restore_primary_failure"])
        self.assertEqual("TEMP_CLEANUP", restore["restore_secondary_failures"][0]["operation"])
        self.assertEqual(schema10._sha256_bytes(original), restore["restore_readback_state"]["sha256"])

    def _dl90_transition_with_restore_failure(self, operation_id: str, original_message: str):
        root = self.root / operation_id.lower()
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        original_atomic = schema10._atomic_write_exact
        calls = 0

        def atomic_with_restore_failure(path, payload, mode):
            nonlocal calls
            calls += 1
            if calls == 2:
                with self._dl89_directory_io(
                    path.parent, fsync_error=OSError(f"restore fsync {operation_id}")
                ):
                    return original_atomic(path, payload, mode)
            return original_atomic(path, payload, mode)

        def original_transition_failure():
            raise RuntimeError(original_message)

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            patch.object(schema10, "_atomic_write_exact", side_effect=atomic_with_restore_failure),
        ):
            try:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id=operation_id,
                    assert_effect_authority=lambda: None,
                    validate_after_transition=original_transition_failure,
                )
            except ProductionSchema10OperationalError as error:
                return error, originals, target
        self.fail("expected compensation restoration failure")

    def test_dl90_c5_original_transition_and_restore_failure_are_both_preserved(self) -> None:
        error, originals, target = self._dl90_transition_with_restore_failure(
            "DL90-C5", "original transition c5"
        )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        detail = json.loads(error.detail)
        self.assertEqual("builtins.RuntimeError", detail["original_operation_error"]["exception_type"])
        self.assertIn("original transition c5", detail["original_operation_error"]["detail"])
        self.assertEqual("SCHEMA10_ATOMIC_WRITE_FAILED", detail["compensation_error"]["code"])
        self.assertEqual(
            "DIRECTORY_FSYNC",
            detail["compensation_restoration"]["restore_primary_failure"]["operation"],
        )
        self.assertEqual(originals["W01"], target.read_bytes())

    def test_dl90_c6_outer_reraise_keeps_restoration_evidence_queryable(self) -> None:
        error, _originals, _target = self._dl90_transition_with_restore_failure(
            "DL90-C6", "original transition c6"
        )
        self.assertIsInstance(error.__cause__, RuntimeError)
        self.assertEqual("original transition c6", str(error.__cause__))
        detail = json.loads(error.detail)
        restore = detail["compensation_restoration"]
        self.assertTrue(restore["restore_attempted"])
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("FAIL", restore["restore_directory_fsync_outcome"])
        self.assertEqual("SCHEMA10_ATOMIC_WRITE_FAILED", detail["compensation_error"]["code"])
        self.assertEqual("builtins.RuntimeError", detail["original_operation_error"]["exception_type"])

    def test_dl90_c7_guard_loss_before_compensation_writes_zero_and_is_exact(self) -> None:
        path, _original, target, state = self._dl90_changed_state("c7")

        def guard():
            raise ProductionSchema10OperationalError("SCHEMA10_W08_AUTHORITY_LOST")

        with patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call:
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=guard,
                    original_operation_error=RuntimeError("original c7"),
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual(0, replace_call.call_count)
        self.assertFalse(detail["compensation_restoration"]["restore_attempted"])
        self.assertEqual("SCHEMA10_W08_AUTHORITY_LOST", detail["authority_event_guard_failure"])
        self.assertEqual("SCHEMA10_W08_AUTHORITY_LOST", detail["compensation_error"]["code"])
        self.assertEqual("builtins.RuntimeError", detail["original_operation_error"]["exception_type"])
        self.assertEqual(target, path.read_bytes())

    @contextmanager
    def _dl91_observation_io(
        self,
        target: Path,
        *,
        read_error: BaseException | None = None,
        stat_error: BaseException | None = None,
        only_when_payload: bytes | None = None,
        enabled=None,
    ):
        original_read = Path.read_bytes
        original_stat = Path.stat

        def should_inject(path: Path) -> bool:
            if path != target or (enabled is not None and not enabled()):
                return False
            if only_when_payload is None:
                return True
            try:
                return original_read(path) == only_when_payload
            except BaseException:
                return False

        def injected_read(path: Path):
            if read_error is not None and should_inject(path):
                raise read_error
            return original_read(path)

        def injected_stat(path: Path, *args, **kwargs):
            if stat_error is not None and should_inject(path):
                raise stat_error
            return original_stat(path, *args, **kwargs)

        with (
            patch.object(Path, "read_bytes", new=injected_read),
            patch.object(Path, "stat", new=injected_stat),
        ):
            yield

    def _dl91_restore_failure_detail(
        self,
        name: str,
        *,
        read_error: BaseException | None = None,
        stat_error: BaseException | None = None,
        fsync_error: BaseException | None = None,
        close_error: BaseException | None = None,
        cleanup_error: BaseException | None = None,
    ):
        path, original, _target, state = self._dl90_changed_state(name)
        contexts = []
        if cleanup_error is not None:
            contexts.append(self._dl88_unlink_failure(path, cleanup_error))
        contexts.append(
            self._dl89_directory_io(
                path.parent,
                fsync_error=fsync_error,
                close_error=close_error,
            )
        )
        contexts.append(
            self._dl91_observation_io(
                path,
                read_error=read_error,
                stat_error=stat_error,
                only_when_payload=original,
            )
        )

        @contextmanager
        def entered_all(index=0):
            if index == len(contexts):
                yield
                return
            with contexts[index]:
                with entered_all(index + 1):
                    yield

        with entered_all():
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError(f"original transition {name}"),
                )
        return path, original, state, caught.exception, caught.exception.evidence_payload

    def test_dl91_r1_restore_partial_success_read_bytes_eio_is_additive(self) -> None:
        _path, _original, _state, error, detail = self._dl91_restore_failure_detail(
            "dl91-r1",
            fsync_error=OSError("restore fsync r1"),
            read_error=OSError("readback eio r1"),
        )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        restore = detail["compensation_restoration"]
        observation = restore["restore_readback_state"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("SUCCESS", observation["stat"])
        self.assertEqual("OBSERVATION_UNKNOWN", observation["state"])
        self.assertEqual("readback eio r1", observation["read_failure"]["detail"])
        self.assertIn("original transition dl91-r1", detail["original_operation_error"]["detail"])

    def test_dl91_r2_restore_partial_success_stat_eio_is_additive(self) -> None:
        _path, original, _state, _error, detail = self._dl91_restore_failure_detail(
            "dl91-r2",
            fsync_error=OSError("restore fsync r2"),
            stat_error=OSError("stat eio r2"),
        )
        restore = detail["compensation_restoration"]
        observation = restore["restore_readback_state"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("FAIL", observation["stat"])
        self.assertEqual("SUCCESS", observation["read_bytes"])
        self.assertEqual(schema10._sha256_bytes(original), observation["sha256"])
        self.assertEqual("OBSERVATION_UNKNOWN", observation["state"])
        self.assertEqual("stat eio r2", observation["stat_failure"]["detail"])

    def test_dl91_r3_restore_fsync_close_and_readback_failures_all_survive(self) -> None:
        _path, _original, _state, _error, detail = self._dl91_restore_failure_detail(
            "dl91-r3",
            fsync_error=OSError("restore fsync r3"),
            close_error=OSError("restore close r3"),
            read_error=OSError("readback eio r3"),
        )
        restore = detail["compensation_restoration"]
        observation = restore["restore_readback_state"]
        self.assertEqual("FAIL", restore["restore_directory_fsync_outcome"])
        self.assertEqual("FAIL", restore["restore_directory_close_outcome"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertIn(
            "DIRECTORY_CLOSE",
            [item["operation"] for item in restore["restore_secondary_failures"]],
        )
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("readback eio r3", observation["read_failure"]["detail"])

    def test_dl91_r4_cleanup_failure_and_reconciliation_stat_failure_both_survive(self) -> None:
        _path, _original, _state, _error, detail = self._dl91_restore_failure_detail(
            "dl91-r4",
            cleanup_error=OSError("cleanup r4"),
            stat_error=PermissionError("stat denied r4"),
        )
        restore = detail["compensation_restoration"]
        observation = restore["restore_readback_state"]
        self.assertEqual("FAIL", restore["restore_temp_cleanup_outcome"])
        self.assertIn(
            "TEMP_CLEANUP",
            [item["operation"] for item in restore["restore_secondary_failures"]],
        )
        self.assertEqual("FAIL", observation["stat"])
        self.assertEqual("stat denied r4", observation["stat_failure"]["detail"])

    def test_dl91_r5_original_restore_and_readback_three_causal_layers_survive(self) -> None:
        _path, _original, _state, error, detail = self._dl91_restore_failure_detail(
            "dl91-r5",
            fsync_error=OSError("restore fsync r5"),
            read_error=OSError("readback eio r5"),
        )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        restore = detail["compensation_restoration"]
        observation = restore["restore_readback_state"]
        self.assertIn("original transition dl91-r5", detail["original_operation_error"]["detail"])
        self.assertEqual("SCHEMA10_ATOMIC_WRITE_FAILED", detail["compensation_error"]["code"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("readback eio r5", observation["read_failure"]["detail"])

    def test_dl91_r6_successful_readback_preserves_exact_behavior(self) -> None:
        path = self.root / "dl91-r6.authorized.json"
        payload = b"dl91-r6\n"
        path.write_bytes(payload)
        path.chmod(0o640)
        observation = schema10._observed_projection_state(path)
        self.assertEqual("YES", observation["observation_attempted"])
        self.assertEqual("YES", observation["path_exists"])
        self.assertEqual("SUCCESS", observation["read_bytes"])
        self.assertEqual("SUCCESS", observation["stat"])
        self.assertEqual("SUCCESS", observation["hash"])
        self.assertEqual("YES", observation["observation_complete"])
        self.assertEqual("PRESENT", observation["state"])
        self.assertEqual(schema10._sha256_bytes(payload), observation["sha256"])
        self.assertEqual(0o640, observation["mode"])
        self.assertEqual(len(payload), observation["size"])

    def test_dl91_r7_genuine_absence_is_exact_not_unknown(self) -> None:
        path = self.root / "dl91-r7-absent.authorized.json"
        observation = schema10._observed_projection_state(path)
        self.assertEqual("NO", observation["path_exists"])
        self.assertEqual("SUCCESS", observation["stat"])
        self.assertEqual("NOT_ATTEMPTED", observation["read_bytes"])
        self.assertEqual("YES", observation["observation_complete"])
        self.assertEqual("ABSENT", observation["state"])
        self.assertFalse(observation["exists"])
        self.assertIsNone(observation["sha256"])

    def test_dl91_r8_unprovable_existence_is_unknown_not_absent(self) -> None:
        path = self.root / "dl91-r8.authorized.json"
        path.write_bytes(b"r8\n")
        with self._dl91_observation_io(
            path,
            read_error=OSError("read eio r8"),
            stat_error=PermissionError("stat denied r8"),
        ):
            observation = schema10._observed_projection_state(path)
        self.assertEqual("UNKNOWN", observation["path_exists"])
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("FAIL", observation["stat"])
        self.assertEqual("NO", observation["observation_complete"])
        self.assertEqual("OBSERVATION_UNKNOWN", observation["state"])
        self.assertIsNone(observation["exists"])
        self.assertEqual("UNKNOWN", observation["sha256"])

    def test_dl91_r9_generic_outer_recovery_retains_prior_structured_observation(self) -> None:
        root = self.root / "dl91-r9"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        target = root / "W01.authorized.json"
        original_atomic = schema10._atomic_write_exact

        def unexpected_after_readback(
            states,
            *,
            assert_effect_authority,
            original_operation_error=None,
        ):
            state = states[0]
            state.compensation_attempted = True
            state.restoration_write_outcome = original_atomic(
                state.path, state.payload, state.mode
            )
            with self._dl91_observation_io(
                state.path,
                read_error=OSError("readback eio r9"),
                only_when_payload=state.payload,
            ):
                observation = schema10._capture_projection_observation(state)
            self.assertEqual("FAIL", observation["read_bytes"])
            raise RuntimeError("unexpected after readback r9")

        def original_transition_failure():
            raise RuntimeError("original transition r9")

        with (
            patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}),
            patch.object(
                schema10,
                "_compensate_projection_entries",
                side_effect=unexpected_after_readback,
            ),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL91-R9",
                    assert_effect_authority=lambda: None,
                    validate_after_transition=original_transition_failure,
                )
        detail = json.loads(caught.exception.detail)
        self.assertIn("original transition r9", detail["original_operation_error"]["detail"])
        self.assertIn("unexpected after readback r9", detail["unexpected_compensation_error"]["detail"])
        structured = detail["structured_reconciliation"][0]
        restore = structured["compensation_restoration"]
        history = structured["reconciliation_observation_history"]
        self.assertTrue(restore["restore_attempted"])
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("FAIL", history[-1]["read_bytes"])
        self.assertEqual("readback eio r9", history[-1]["read_failure"]["detail"])
        self.assertEqual(originals["W01"], target.read_bytes())

    def test_dl91_r10_raw_oserror_cannot_bypass_typed_reconciliation(self) -> None:
        path, _original, target, state = self._dl90_changed_state("dl91-r10")
        with self._dl91_observation_io(
            path,
            read_error=OSError("pre-restore read eio r10"),
            only_when_payload=target,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("original transition r10"),
                )
        self.assertNotIsInstance(caught.exception, OSError)
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        observation = detail["current_observed_state"]
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("pre-restore read eio r10", observation["read_failure"]["detail"])
        self.assertEqual("RECONCILE_CHANGED_ENTRY_OBSERVATION_UNKNOWN", detail["required_reconciliation_action"])
        self.assertIn("original transition r10", detail["original_operation_error"]["detail"])

    def test_dl91_absence_compensation_observation_failure_is_unknown(self) -> None:
        path = self.root / "dl91-absence-unknown.authorized.json"
        source = b"before-absence\n"
        target = b"after-absence\n"
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=source, target_payload=target
        )
        self.assertFalse(state.existed)
        schema10._write_projection_entry(state, 0o600)
        self.assertTrue(state.changed_by_invocation)
        with self._dl91_observation_io(
            path,
            stat_error=PermissionError("absence stat denied dl91"),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("original absence dl91"),
                )
        detail = json.loads(caught.exception.detail)
        observation = detail["current_observed_state"]
        self.assertEqual("RECONCILE_ABSENCE_RESTORE_OBSERVATION_UNKNOWN", detail["required_reconciliation_action"])
        self.assertEqual("UNKNOWN", observation["path_exists"])
        self.assertEqual("FAIL", observation["stat"])
        self.assertEqual("FAIL", observation["read_bytes"])
        self.assertEqual("OBSERVATION_UNKNOWN", observation["state"])
        self.assertEqual("absence stat denied dl91", observation["stat_failure"]["detail"])

    def test_dl91_hash_failure_is_typed_and_additive(self) -> None:
        path = self.root / "dl91-hash.authorized.json"
        path.write_bytes(b"hash-source\n")
        with patch.object(schema10, "_sha256_bytes", side_effect=OSError("hash eio dl91")):
            observation = schema10._observed_projection_state(path)
        self.assertEqual("SUCCESS", observation["read_bytes"])
        self.assertEqual("SUCCESS", observation["stat"])
        self.assertEqual("FAIL", observation["hash"])
        self.assertEqual("hash eio dl91", observation["hash_failure"]["detail"])
        self.assertEqual("OBSERVATION_UNKNOWN", observation["state"])
        self.assertEqual("UNKNOWN", observation["sha256"])

    def test_dl92_fdopen_failure_records_descriptor_close_success_and_safe_error_text(self) -> None:
        temp = self.root / "dl92-fdopen.tmp"
        fd = schema10.os.open(temp, schema10.os.O_WRONLY | schema10.os.O_CREAT, 0o600)

        class BrokenStrError(OSError):
            def __str__(self):
                raise RuntimeError("broken str")

        with patch.object(schema10.os, "fdopen", side_effect=BrokenStrError()):
            outcome, primary_error, close_error = schema10._write_temp_stream(fd, b"payload")
        self.assertEqual("FAIL", outcome.open_status)
        self.assertEqual("SUCCESS", outcome.close_status)
        self.assertIsNone(close_error)
        self.assertIsInstance(primary_error, BrokenStrError)
        self.assertEqual("TEMP_STREAM_OPEN", outcome.open_failure.operation)
        self.assertIn("exception-detail-unavailable", outcome.open_failure.detail)

    def test_dl92_short_temp_write_is_failure_not_false_success(self) -> None:
        path = self.root / "dl92-short-write.authorized.json"
        before = b"before-short-write\n"
        path.write_bytes(before)
        original_fdopen = schema10.os.fdopen

        class ShortWriteStream:
            def __init__(self, fd, mode, closefd=True):
                self.inner = original_fdopen(fd, mode, closefd=closefd)

            def write(self, payload):
                self.inner.write(payload)
                return max(0, len(payload) - 1)

            def flush(self):
                return self.inner.flush()

            def fileno(self):
                return self.inner.fileno()

            def close(self):
                return self.inner.close()

        with patch.object(schema10.os, "fdopen", side_effect=ShortWriteStream):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-short-write\n", 0o600)
        self.assertEqual("TEMP_WRITE", caught.exception.outcome.failed_operation)
        self.assertEqual("FAIL", caught.exception.outcome.temp_stream_outcome.write_status)
        self.assertFalse(caught.exception.outcome.destination_replaced)
        self.assertEqual(before, path.read_bytes())

    def test_dl92_reconciliation_serialization_failure_is_additive(self) -> None:
        _path, original, _target, state = self._dl90_changed_state("dl92-serialize-additive")
        schema10._compensate_projection_entries(
            [state],
            assert_effect_authority=lambda: None,
            original_operation_error=RuntimeError("primary dl92 serialize"),
        )
        with patch.object(
            schema10, "_canonical_json", side_effect=OSError("canonical serialize dl92")
        ):
            detail = schema10._projection_reconciliation_detail(
                state,
                guard_failure=None,
                required_action="DL92_SERIALIZATION_AUDIT",
                original_operation_error=RuntimeError("primary dl92 serialize"),
            )
        payload = detail.evidence_payload
        self.assertEqual("W01", payload["writer_id"])
        self.assertEqual("RECONCILIATION_SERIALIZATION", payload["serialization_failure"]["operation"])
        restore = payload["compensation_restoration"]
        self.assertTrue(restore["restore_attempted"])
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual(schema10._sha256_bytes(original), restore["restore_readback_state"]["sha256"])

    def test_dl92_reconciliation_double_serialization_failure_uses_independent_failsafe(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl92-double-serialize")
        schema10._compensate_projection_entries(
            [state],
            assert_effect_authority=lambda: None,
            original_operation_error=RuntimeError("primary double serialize"),
        )
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("canonical down")),
            patch.object(schema10.json, "dumps", side_effect=OSError("unused same-serializer fallback")) as legacy_json,
        ):
            detail = schema10._projection_reconciliation_detail(
                state,
                guard_failure=None,
                required_action="DL92_DOUBLE_SERIALIZATION_AUDIT",
                original_operation_error=RuntimeError("primary double serialize"),
            )
        self.assertTrue(str(detail).startswith("DL93_TERMINAL_EVIDENCE_V1"))
        self.assertEqual(0, legacy_json.call_count)
        payload = detail.evidence_payload
        self.assertIn("serialization_failure", payload)
        self.assertNotIn("serialization_fallback_failure", payload)
        self.assertTrue(payload["compensation_restoration"]["restore_attempted"])
        self.assertTrue(payload["compensation_restoration"]["restore_durability_complete"])

    def test_dl92_existing_entry_compensation_serialization_failure_keeps_restore_evidence(self) -> None:
        path, original, _target, state = self._dl90_changed_state("dl92-existing-serialize")
        with (
            self._dl89_directory_io(path.parent, fsync_error=OSError("restore fsync dl92")),
            patch.object(schema10, "_canonical_json", side_effect=OSError("serialize existing dl92")),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("primary existing dl92"),
                )
        payload = caught.exception.evidence_payload
        self.assertEqual("DIRECTORY_DURABILITY_SERIALIZATION", payload["serialization_failure"]["operation"])
        restore = payload["compensation_restoration"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("FAIL", restore["restore_directory_fsync_outcome"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual(original, path.read_bytes())

    def test_dl92_absent_entry_compensation_serialization_failure_keeps_unlink_and_directory_evidence(self) -> None:
        path = self.root / "dl92-absent-serialize.authorized.json"
        target = b"created-by-transition\n"
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"source\n", target_payload=target
        )
        schema10._write_projection_entry(state, 0o600)
        with (
            self._dl91_observation_io(
                path, stat_error=PermissionError("absence readback unknown dl92")
            ),
            patch.object(schema10, "_canonical_json", side_effect=OSError("serialize absence dl92")),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                schema10._compensate_projection_entries(
                    [state],
                    assert_effect_authority=lambda: None,
                    original_operation_error=RuntimeError("primary absence dl92"),
                )
        payload = caught.exception.evidence_payload
        restore = payload["compensation_restoration"]
        absence = restore["restore_absence_outcome"]
        self.assertEqual("SUCCESS", absence["unlink"])
        self.assertEqual("SUCCESS", absence["directory_durability"]["fsync"])
        self.assertEqual("SUCCESS", absence["directory_durability"]["close"])
        self.assertTrue(absence["durability_complete"])
        self.assertEqual("FAIL", restore["restore_readback_state"]["stat"])
        self.assertEqual("RECONCILIATION_SERIALIZATION", payload["serialization_failure"]["operation"])
        self.assertFalse(path.exists())

    def test_dl92_primary_secondary_readback_and_serialization_failures_all_survive(self) -> None:
        with patch.object(
            schema10, "_canonical_json", side_effect=OSError("serialize combined dl92")
        ):
            _path, _original, _state, error, detail = self._dl91_restore_failure_detail(
                "dl92-combined",
                fsync_error=OSError("restore fsync combined dl92"),
                close_error=OSError("restore close combined dl92"),
                read_error=OSError("readback combined dl92"),
            )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        self.assertEqual("DIRECTORY_DURABILITY_SERIALIZATION", detail["serialization_failure"]["operation"])
        restore = detail["compensation_restoration"]
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertIn(
            "DIRECTORY_CLOSE",
            [failure["operation"] for failure in restore["restore_secondary_failures"]],
        )
        self.assertEqual("FAIL", restore["restore_readback_state"]["read_bytes"])
        self.assertEqual("readback combined dl92", restore["restore_readback_state"]["read_failure"]["detail"])

    def test_dl92_generic_recovery_serialization_failure_is_non_recursive_and_monotonic(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl92-generic-serialize")
        schema10._compensate_projection_entries(
            [state],
            assert_effect_authority=lambda: None,
            original_operation_error=RuntimeError("primary generic dl92"),
        )
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("generic canonical down")),
            patch.object(schema10.json, "dumps", side_effect=OSError("unused generic json fallback")) as legacy_json,
        ):
            detail = schema10._generic_projection_recovery_detail(
                [state],
                original_operation_error=RuntimeError("primary generic dl92"),
                compensation_error=RuntimeError("secondary generic dl92"),
                compensation_status="FAILED",
            )
        self.assertTrue(str(detail).startswith("DL93_TERMINAL_EVIDENCE_V1"))
        self.assertEqual(0, legacy_json.call_count)
        payload = detail.evidence_payload
        self.assertTrue(payload["accumulated_evidence_is_monotonic"])
        self.assertFalse(payload["generic_recovery_recursive"])
        self.assertIn("serialization_failure", payload)
        self.assertNotIn("serialization_fallback_failure", payload)
        structured = payload["structured_reconciliation"][0]
        self.assertTrue(structured["compensation_restoration"]["restore_attempted"])
        self.assertTrue(structured["compensation_restoration"]["restore_durability_complete"])

    def test_dl92_successful_compensation_is_attached_to_outer_typed_boundary(self) -> None:
        root = self.root / "dl92-outer-success"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        guard_calls = 0

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if guard_calls == 2:
                raise RuntimeError("post-write primary dl92")

        with patch.object(schema10, "EXPECTED_WRITERS", {"W01": EXPECTED_WRITERS["W01"]}):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL92-OUTER-SUCCESS",
                    assert_effect_authority=guard,
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", caught.exception.code)
        payload = caught.exception.evidence_payload
        self.assertEqual("SUCCEEDED", payload["compensation_status"])
        self.assertTrue(payload["accumulated_evidence_is_monotonic"])
        restore = payload["structured_reconciliation"][0]["compensation_restoration"]
        self.assertTrue(restore["restore_attempted"])
        self.assertTrue(restore["restore_durability_complete"])
        self.assertEqual(originals["W01"], (root / "W01.authorized.json").read_bytes())

    def test_dl92_multi_entry_later_failure_preserves_earlier_successful_restore(self) -> None:
        path1, _original1, _target1, state1 = self._dl90_changed_state("dl92-multi-1")
        _path2, _original2, _target2, state2 = self._dl90_changed_state("dl92-multi-2")
        state2.writer_id = "W02"
        path1.write_bytes(b"external-drift\n")
        original_error = RuntimeError("multi primary dl92")
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            schema10._compensate_projection_entries(
                [state1, state2],
                assert_effect_authority=lambda: None,
                original_operation_error=original_error,
            )
        payload = schema10._generic_projection_recovery_payload(
            [state1, state2],
            original_operation_error=original_error,
            compensation_error=caught.exception,
            compensation_status="FAILED",
        )
        by_writer = {entry["writer_id"]: entry for entry in payload["structured_reconciliation"]}
        self.assertEqual({"W01", "W02"}, set(by_writer))
        by_path = {entry["path"]: entry for entry in payload["structured_reconciliation"]}
        self.assertTrue(by_path[str(state2.path)]["compensation_restoration"]["restore_attempted"])
        self.assertTrue(by_path[str(state2.path)]["compensation_restoration"]["restore_durability_complete"])
        self.assertEqual(
            "RECONCILE_CHANGED_ENTRY_DRIFT",
            by_path[str(state1.path)]["required_reconciliation_action"],
        )
        self.assertTrue(payload["accumulated_evidence_is_monotonic"])

    def test_dl92_projection_identity_serialization_fails_before_any_replace(self) -> None:
        root = self.root / "dl92-identity-serialize"
        originals = _write_authorized_root(root, V04_CLIENT_BUILD)
        original_canonical = schema10._canonical_json

        def fail_identity_only(value):
            if isinstance(value, dict) and set(value) == {"operation_id", "to_build", "files"}:
                raise OSError("identity serialization dl92")
            return original_canonical(value)

        with (
            patch.object(schema10, "_canonical_json", side_effect=fail_identity_only),
            patch.object(schema10.os, "replace", wraps=schema10.os.replace) as replace_call,
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                _transition_authorized_projection(
                    root,
                    from_build=V04_CLIENT_BUILD,
                    to_build=V05_CLIENT_BUILD,
                    operation_id="DL92-IDENTITY-SERIALIZE",
                )
        self.assertEqual("SCHEMA10_AUTHORIZED_EVIDENCE_SERIALIZATION_FAILED", caught.exception.code)
        self.assertEqual(0, replace_call.call_count)
        self.assertTrue(caught.exception.detail.startswith("DL93_TERMINAL_EVIDENCE_V1"))
        self.assertEqual(
            "PROJECTION_IDENTITY_SERIALIZATION",
            caught.exception.evidence_payload["serialization_failure"]["operation"],
        )
        for writer_id, original in originals.items():
            self.assertEqual(original, (root / f"{writer_id}.authorized.json").read_bytes())

    # DL-93 terminal recovery evidence adversarial matrix.  These cases are
    # intentionally concentrated here so the whole meta-failure surface is
    # exercised as one control rather than finding-by-finding micro rework.
    def test_dl93_m1_directory_failure_chaining_never_truth_tests_exception(self) -> None:
        class BoolBomb(OSError):
            def __bool__(self):
                raise AssertionError("directory exception truthiness forbidden")

        fsync_error = BoolBomb("directory fsync bool bomb")
        close_error = BoolBomb("directory close bool bomb")
        with self._dl89_directory_io(
            self.root, fsync_error=fsync_error, close_error=close_error
        ):
            with self.assertRaises(schema10._DirectoryDurabilityFailure) as caught:
                schema10._fsync_directory(self.root)
        self.assertIs(caught.exception.__cause__, fsync_error)
        self.assertIs(caught.exception.primary_cause, fsync_error)
        self.assertIs(caught.exception.close_cause, close_error)
        self.assertEqual("FAIL", caught.exception.outcome.fsync_status)
        self.assertEqual("FAIL", caught.exception.outcome.close_status)

    def test_dl93_m1_truthiness_bomb_after_destination_replace_keeps_bookkeeping(self) -> None:
        class BoolBomb(OSError):
            def __bool__(self):
                raise RuntimeError("__bool__ must never run")

        path = self.root / "dl93-m1.authorized.json"
        original = b"before-dl93-m1\n"
        target = b"after-dl93-m1\n"
        path.write_bytes(original)
        path.chmod(0o640)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=target
        )
        with patch.object(schema10.os, "chmod", side_effect=BoolBomb("chmod bool bomb")):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._write_projection_entry(state, state.mode or 0o600)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertEqual("DESTINATION_CHMOD", caught.exception.outcome.failed_operation)
        self.assertTrue(state.write_attempted)
        self.assertTrue(state.destination_replaced)
        self.assertTrue(state.changed_by_invocation)
        self.assertEqual(target, path.read_bytes())

    def test_dl93_m3_property_getter_failure_becomes_typed_evidence(self) -> None:
        class GetterBomb(RuntimeError):
            @property
            def code(self):
                raise OSError("code getter dl93")

            @property
            def evidence_payload(self):
                raise OSError("payload getter dl93")

        _path, _original, _target, state = self._dl90_changed_state("dl93-m3")
        error = GetterBomb("getter bomb")
        payload = schema10._generic_projection_recovery_payload(
            [state],
            original_operation_error=RuntimeError("primary dl93 m3"),
            compensation_error=error,
            compensation_status="FAILED",
        )
        self.assertIn("evidence_attribute_failures", payload)
        self.assertIn(
            "ATTRIBUTE_GET:evidence_payload",
            [item["operation"] for item in payload["evidence_attribute_failures"]],
        )
        outer = payload["outer_compensation_error"]
        self.assertIn("attribute_access_failures", outer)
        self.assertEqual("ATTRIBUTE_GET:code", outer["attribute_access_failures"][0]["operation"])

    def test_dl93_m4_str_repr_and_str_subclass_encode_hooks_are_contained(self) -> None:
        class StrBomb(RuntimeError):
            def __str__(self):
                raise OSError("str dl93")

        class ReprBomb:
            def __repr__(self):
                raise OSError("repr dl93")

        class EncodeBomb(str):
            def encode(self, *args, **kwargs):
                raise OSError("encode dl93")

        error_payload = schema10._exception_evidence_payload(StrBomb("boom"))
        self.assertIn("exception-detail-unavailable", error_payload["detail"])
        detail = schema10._serialize_evidence_payload(
            {"repr": ReprBomb(), "string_subclass": EncodeBomb("unsafe")},
            operation="DL93_M4",
        )
        self.assertLessEqual(
            len(str.__str__(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )
        self.assertIn("<opaque:", detail.evidence_payload["repr"])
        self.assertIn("<opaque:", detail.evidence_payload["string_subclass"])

    def test_dl93_m2_canonical_serializer_failure_uses_independent_terminal_fallback(self) -> None:
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("canonical dl93")),
            patch.object(schema10.json, "dumps", side_effect=AssertionError("same serializer re-entry")) as legacy,
        ):
            detail = schema10._serialize_evidence_payload(
                {"critical": "DL93-CANONICAL-FAIL"}, operation="DL93_CANONICAL"
            )
        self.assertTrue(str(detail).startswith("DL93_TERMINAL_EVIDENCE_V1"))
        self.assertEqual(0, legacy.call_count)
        self.assertEqual("DL93_CANONICAL", detail.evidence_payload["serialization_failure"]["operation"])

    def test_dl93_m2_recovery_builder_failure_uses_acyclic_state_snapshot(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl93-builder")
        with patch.object(
            schema10,
            "_generic_projection_recovery_payload",
            side_effect=OSError("recovery constructor dl93"),
        ):
            surfaced = schema10._surface_projection_recovery(
                [state],
                original_operation_error=RuntimeError("original dl93 builder"),
                compensation_error=RuntimeError("compensation dl93 builder"),
                compensation_status="FAILED",
            )
        self.assertIsInstance(surfaced, ProductionSchema10OperationalError)
        payload = surfaced.evidence_payload
        self.assertFalse(payload["generic_recovery_recursive"])
        self.assertIn("terminal_recovery_builder_failure", payload)
        self.assertTrue(payload["structured_reconciliation"][0]["destination_replaced"])

    def test_dl93_generic_recovery_never_reenters_reconciliation_after_serialization_failure(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl93-no-recursion")
        with patch.object(schema10, "_canonical_json", side_effect=OSError("prior serialize dl93")):
            prior_detail = schema10._serialize_evidence_payload(
                {"phase": "prior"}, operation="DL93_PRIOR_SERIALIZATION"
            )
        prior = ProductionSchema10OperationalError("DL93_PRIOR", prior_detail)
        with (
            patch.object(schema10, "_projection_reconciliation_payload", side_effect=AssertionError("recursive reconciliation")) as recursive,
            patch.object(schema10, "_canonical_json", side_effect=OSError("later serialize dl93")),
        ):
            detail = schema10._generic_projection_recovery_detail(
                [state],
                original_operation_error=RuntimeError("original dl93 recursion"),
                compensation_error=prior,
                compensation_status="FAILED",
            )
        self.assertEqual(0, recursive.call_count)
        self.assertFalse(detail.evidence_payload["generic_recovery_recursive"])
        operations = [item["operation"] for item in detail.serialization_failures]
        self.assertIn("DL93_PRIOR_SERIALIZATION", operations)

    def test_dl93_fallback_renderer_failure_reaches_last_resort_without_raw_escape(self) -> None:
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("canonical dl93 fallback")),
            patch.object(schema10, "_terminal_fallback_text", side_effect=OSError("renderer dl93 fallback")),
        ):
            detail = schema10._serialize_evidence_payload(
                {"critical": "DL93-FALLBACK-IDENTITY"}, operation="DL93_FALLBACK"
            )
        self.assertTrue(str(detail).startswith("DL93_TERMINAL_LAST_RESORT_V1"))
        self.assertIn("serialization_failure", detail.evidence_payload)
        self.assertIn("serialization_fallback_failure", detail.evidence_payload)
        self.assertLessEqual(len(str(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)

    def test_dl93_m5_prior_and_later_serialization_failures_are_monotonic(self) -> None:
        with patch.object(schema10, "_canonical_json", side_effect=OSError("first dl93")):
            first = schema10._serialize_evidence_payload(
                {"phase": "first"}, operation="DL93_SERIALIZE_FIRST"
            )
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("second dl93")),
            patch.object(schema10, "_terminal_fallback_text", side_effect=OSError("third dl93")),
        ):
            later = schema10._serialize_evidence_payload(
                {"phase": "later"},
                operation="DL93_SERIALIZE_SECOND",
                prior_failures=first.serialization_failures,
            )
        operations = [item["operation"] for item in later.serialization_failures]
        self.assertEqual("DL93_SERIALIZE_FIRST", operations[0])
        self.assertIn("DL93_SERIALIZE_SECOND", operations)
        self.assertIn("DL93_SERIALIZE_SECOND_TERMINAL_FALLBACK", operations)
        self.assertEqual(
            "DL93_SERIALIZE_FIRST",
            later.evidence_payload["serialization_failure"]["operation"],
        )

    def test_dl93_existing_entry_restore_readback_serialization_failure_survives(self) -> None:
        with patch.object(schema10, "_canonical_json", side_effect=OSError("existing serialize dl93")):
            _path, _original, _state, error, payload = self._dl91_restore_failure_detail(
                "dl93-existing-combined",
                fsync_error=OSError("restore fsync dl93"),
                close_error=OSError("restore close dl93"),
                read_error=OSError("readback dl93"),
            )
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        restore = payload["compensation_restoration"]
        self.assertTrue(restore["restore_destination_replaced"])
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("FAIL", restore["restore_readback_state"]["read_bytes"])
        operations = [item["operation"] for item in error.serialization_failures]
        self.assertEqual("DIRECTORY_DURABILITY_SERIALIZATION", operations[0])
        self.assertEqual(["DIRECTORY_DURABILITY_SERIALIZATION"], operations)

    def test_dl93_absent_entry_unlink_directory_and_serialization_evidence_survives(self) -> None:
        path = self.root / "dl93-absent.authorized.json"
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=b"source\n", target_payload=b"target\n"
        )
        schema10._write_projection_entry(state, 0o600)
        with patch.object(schema10, "_canonical_json", side_effect=OSError("absent serialize dl93")):
            schema10._compensate_projection_entries(
                [state],
                assert_effect_authority=lambda: None,
                original_operation_error=RuntimeError("absent original dl93"),
            )
        detail = schema10._projection_reconciliation_detail(
            state,
            guard_failure=None,
            required_action="DL93_ABSENT_REVIEW",
            original_operation_error=RuntimeError("absent original dl93"),
        )
        restore = detail.evidence_payload["compensation_restoration"]
        self.assertEqual("SUCCESS", restore["restore_absence_outcome"]["unlink"])
        self.assertEqual("SUCCESS", restore["restore_absence_outcome"]["directory_durability"]["fsync"])
        self.assertFalse(path.exists())

    def test_dl93_combined_transition_compensation_readback_serialization_fallback_failure_is_typed(self) -> None:
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("canonical combined dl93")),
            patch.object(schema10, "_terminal_fallback_text", side_effect=OSError("fallback combined dl93")),
        ):
            _path, _original, _state, error, payload = self._dl91_restore_failure_detail(
                "dl93-total-combined",
                fsync_error=OSError("restore fsync total dl93"),
                close_error=OSError("restore close total dl93"),
                read_error=OSError("readback total dl93"),
            )
        self.assertIsInstance(error, ProductionSchema10OperationalError)
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", error.code)
        self.assertIn("serialization_failure", payload)
        self.assertIn("serialization_fallback_failure", payload)
        restore = payload["compensation_restoration"]
        self.assertEqual("DIRECTORY_FSYNC", restore["restore_primary_failure"]["operation"])
        self.assertEqual("FAIL", restore["restore_readback_state"]["read_bytes"])
        self.assertTrue(error.detail.startswith("DL93_TERMINAL_LAST_RESORT_V1"))

    def test_dl93_reporting_constructor_failure_after_replace_keeps_factual_state(self) -> None:
        path = self.root / "dl93-reporting-after-replace.authorized.json"
        original = b"before-reporting-failure\n"
        target = b"after-reporting-failure\n"
        path.write_bytes(original)
        path.chmod(0o640)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=target
        )
        with (
            patch.object(schema10.os, "chmod", side_effect=OSError("chmod after replace")),
            patch.object(
                schema10._AtomicWriteFailure,
                "__init__",
                side_effect=OSError("reporting constructor failed"),
            ),
        ):
            with self.assertRaises(schema10._AtomicWriteReportingFailure) as caught:
                schema10._write_projection_entry(state, state.mode or 0o600)
        self.assertTrue(state.write_attempted)
        self.assertTrue(state.destination_replaced)
        self.assertTrue(state.changed_by_invocation)
        self.assertIsNotNone(state.last_write_outcome)
        self.assertTrue(caught.exception.outcome.destination_replaced)
        self.assertEqual("DESTINATION_CHMOD", caught.exception.outcome.failed_operation)
        self.assertEqual(target, path.read_bytes())
        self.assertIsInstance(caught.exception.reporting_error, OSError)

    def test_dl93_huge_exact_int_repr_failure_cannot_escape_terminal_renderer(self) -> None:
        huge = 10 ** 5000
        detail = schema10._serialize_evidence_payload(
            {
                "original_operation_error": {
                    "exception_type": "builtins.RuntimeError",
                    "code": huge,
                    "detail": "huge-int-identity",
                }
            },
            operation="DL93_HUGE_INT",
        )
        text = str(detail)
        self.assertIn("<int-unrenderable bits=", text)
        self.assertLessEqual(len(text.encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)
        error = ProductionSchema10OperationalError(huge, detail)
        self.assertLessEqual(
            len(str(error).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_evidence_detail_constructor_failure_uses_distinct_fallback_carrier(self) -> None:
        with patch.object(
            schema10, "_EvidenceDetail", side_effect=OSError("detail constructor dl93")
        ):
            detail = schema10._serialize_evidence_payload(
                {"critical_error_identity": "DL93-CONSTRUCTOR-FALLBACK"},
                operation="DL93_DETAIL_CONSTRUCTOR",
            )
        self.assertIsInstance(detail, schema10._TerminalEvidenceFallback)
        self.assertIn(
            "EVIDENCE_DETAIL_CONSTRUCTION",
            [item["operation"] for item in detail.serialization_failures],
        )
        error = ProductionSchema10OperationalError("DL93_TYPED", detail)
        self.assertEqual(
            "DL93-CONSTRUCTOR-FALLBACK",
            error.evidence_payload["critical_error_identity"],
        )
        self.assertLessEqual(
            len(str(error).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_hostile_dict_key_equality_is_never_used_for_priority_lookup(self) -> None:
        class EqualityBomb:
            def __hash__(self):
                return hash("code")

            def __eq__(self, other):
                raise AssertionError("custom key equality must not run")

        detail = schema10._serialize_evidence_payload(
            {EqualityBomb(): "opaque-key", "critical_error_identity": "DL93-KEY-SAFE"},
            operation="DL93_HOSTILE_KEY",
        )
        self.assertEqual(
            "DL93-KEY-SAFE", detail.evidence_payload["critical_error_identity"]
        )
        self.assertLessEqual(
            len(str(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_identity_budget_precedes_large_competing_priority_noise(self) -> None:
        payload = {
            "a": [{"code": "N" * 8192} for _ in range(8)],
            "original_operation_error": {
                "exception_type": "builtins.RuntimeError",
                "code": "DL93-ORIGINAL-IDENTITY",
                "detail": "original-detail",
            },
        }
        detail = schema10._serialize_evidence_payload(
            payload, operation="DL93_IDENTITY_RESERVATION"
        )
        text = str(detail)
        self.assertIn("builtins.RuntimeError", text)
        self.assertIn("DL93-ORIGINAL-IDENTITY", text)
        self.assertLessEqual(len(text.encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)

    def test_dl93_complete_typed_error_message_is_bounded_not_only_detail(self) -> None:
        code = "DL93-LONG-CODE"
        detail = "x" * schema10.TERMINAL_EVIDENCE_MAX_BYTES
        error = ProductionSchema10OperationalError(code, detail)
        encoded = str(error).encode("utf-8")
        self.assertLessEqual(len(encoded), schema10.TERMINAL_EVIDENCE_MAX_BYTES)
        self.assertTrue(str(error).startswith(code + ": "))
        self.assertLess(
            len(error.detail.encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_directory_wrapper_serialization_failure_survives_atomic_layer(self) -> None:
        path = self.root / "dl93-directory-wrapper.authorized.json"
        path.write_bytes(b"before-directory-wrapper\n")
        path.chmod(0o640)
        cause = OSError("directory fsync causal failure")
        directory_outcome = schema10._DirectoryDurabilityOutcome(
            open_status="SUCCESS",
            fsync_status="FAIL",
            close_status="SUCCESS",
            fsync_failure=schema10._atomic_failure_evidence("DIRECTORY_FSYNC", cause),
        )
        with patch.object(
            schema10, "_canonical_json", side_effect=OSError("directory serialization failed")
        ):
            directory_error = schema10._DirectoryDurabilityFailure(
                directory_outcome, primary_cause=cause
            )
        self.assertEqual(
            "DIRECTORY_DURABILITY_SERIALIZATION",
            directory_error.serialization_failures[0]["operation"],
        )
        with patch.object(schema10, "_fsync_directory", side_effect=directory_error):
            with self.assertRaises(schema10._AtomicWriteFailure) as caught:
                schema10._atomic_write_exact(path, b"after-directory-wrapper\n", 0o640)
        operations = [item["operation"] for item in caught.exception.serialization_failures]
        self.assertEqual("DIRECTORY_DURABILITY_SERIALIZATION", operations[0])
        self.assertIn("DIRECTORY_DURABILITY_SERIALIZATION", operations)
        self.assertTrue(caught.exception.outcome.destination_replaced)

    def test_dl93_primary_and_fallback_detail_constructor_failure_uses_third_carrier(self) -> None:
        with (
            patch.object(schema10, "_EvidenceDetail", side_effect=OSError("primary detail failed")),
            patch.object(
                schema10, "_TerminalEvidenceFallback", side_effect=OSError("fallback detail failed")
            ),
        ):
            detail = schema10._serialize_evidence_payload(
                {"critical_error_identity": "DL93-THIRD-CARRIER"},
                operation="DL93_THIRD_CARRIER",
            )
        self.assertIsInstance(detail, schema10._TerminalEvidenceEmergency)
        operations = [item["operation"] for item in detail.serialization_failures]
        self.assertIn("EVIDENCE_DETAIL_CONSTRUCTION", operations)
        self.assertIn("TERMINAL_FALLBACK_CONSTRUCTION", operations)
        self.assertEqual(
            "DL93-THIRD-CARRIER", detail.evidence_payload["critical_error_identity"]
        )
        self.assertIn("DL93-THIRD-CARRIER", str.__str__(detail))

    def test_dl93_persistent_snapshot_failure_uses_independent_terminal_surface(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl93-persistent-snapshot")
        with (
            patch.object(
                schema10, "_terminal_payload_dict", side_effect=OSError("persistent snapshot failure")
            ),
            patch.object(
                schema10._TerminalRecoverySurfaceError,
                "__init__",
                side_effect=OSError("surface constructor failure"),
            ),
        ):
            surfaced = schema10._surface_projection_recovery(
                [state],
                original_operation_error=ProductionSchema10OperationalError(
                    "DL93-PERSISTENT-ORIGINAL", "original persistent snapshot"
                ),
                compensation_error=RuntimeError("compensation persistent snapshot"),
                compensation_status="FAILED",
            )
        self.assertIsInstance(surfaced, ProductionSchema10OperationalError)
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", surfaced.code)
        self.assertEqual(
            "DL93_INDEPENDENT_TERMINAL_SURFACE_V1",
            surfaced.evidence_payload["terminal_surface"],
        )
        self.assertIn("terminal_attach_failure", surfaced.evidence_payload)
        self.assertFalse(surfaced.evidence_payload["generic_recovery_recursive"])
        self.assertLessEqual(
            len(str(surfaced).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )
        self.assertIn("DL93-PERSISTENT-ORIGINAL", str(surfaced))

    def test_dl93_all_renderers_failing_preserves_monotonic_evidence_and_identity(self) -> None:
        with (
            patch.object(schema10, "_canonical_json", side_effect=OSError("canonical all failed")),
            patch.object(schema10, "_terminal_fallback_text", side_effect=OSError("fallback all failed")),
            patch.object(schema10, "_terminal_last_resort_text", side_effect=OSError("last resort all failed")),
        ):
            detail = schema10._serialize_evidence_payload(
                {"critical_error_identity": "DL93-ALL-RENDERERS-IDENTITY"},
                operation="DL93_ALL_RENDERERS",
            )
        self.assertIsInstance(detail, schema10._TerminalEvidenceEmergency)
        operations = [item["operation"] for item in detail.serialization_failures]
        self.assertEqual("DL93_ALL_RENDERERS", operations[0])
        self.assertEqual(
            [
                "DL93_ALL_RENDERERS",
                "DL93_ALL_RENDERERS_TERMINAL_FALLBACK",
                "DL93_ALL_RENDERERS_TERMINAL_LAST_RESORT",
            ],
            operations,
        )
        self.assertEqual(
            "DL93-ALL-RENDERERS-IDENTITY",
            detail.evidence_payload["critical_error_identity"],
        )
        self.assertIn("DL93-ALL-RENDERERS-IDENTITY", str.__str__(detail))
        self.assertLessEqual(
            len(str.__str__(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_independent_surface_hostile_failure_dict_key_cannot_escape(self) -> None:
        class EqualityBomb:
            def __hash__(self):
                return hash("operation")

            def __eq__(self, other):
                raise AssertionError("emergency lookup must not invoke hostile equality")

        _path, _original, _target, state = self._dl90_changed_state("dl93-emergency-key")
        original = RuntimeError("original hostile emergency key")
        original.serialization_failures = ({EqualityBomb(): "hostile"},)
        with patch.object(
            schema10, "_attach_projection_recovery_evidence", side_effect=OSError("attach failed")
        ):
            surfaced = schema10._surface_projection_recovery(
                [state],
                original_operation_error=original,
                compensation_error=None,
                compensation_status="FAILED",
            )
        self.assertIsInstance(surfaced, ProductionSchema10OperationalError)
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", surfaced.code)
        self.assertIn("builtins.RuntimeError", str(surfaced))
        self.assertLessEqual(
            len(str(surfaced).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_independent_surface_preserves_reconciliation_and_prior_failures(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl93-emergency-monotonic")
        with patch.object(schema10, "_canonical_json", side_effect=OSError("prior emergency serialize")):
            prior_detail = schema10._serialize_evidence_payload(
                {"phase": "prior-emergency"}, operation="DL93_PRIOR_EMERGENCY"
            )
        prior = ProductionSchema10OperationalError("DL93_PRIOR_EMERGENCY_ERROR", prior_detail)
        with patch.object(
            schema10, "_attach_projection_recovery_evidence", side_effect=OSError("attach emergency failure")
        ):
            surfaced = schema10._surface_projection_recovery(
                [state],
                original_operation_error=RuntimeError("original emergency monotonic"),
                compensation_error=prior,
                compensation_status="FAILED",
            )
        payload = surfaced.evidence_payload
        self.assertTrue(payload["structured_reconciliation"][0]["destination_replaced"])
        operations = [item["operation"] for item in surfaced.serialization_failures]
        self.assertEqual("DL93_PRIOR_EMERGENCY", operations[0])
        self.assertIn("TERMINAL_ATTACH", operations)
        self.assertTrue(payload["accumulated_evidence_is_monotonic"])

    def test_dl93_independent_surface_preserves_full_original_evidence_and_message_detail(self) -> None:
        preserved_original = {
            "exception_type": "builtins.RuntimeError",
            "code": "DL93-PRESERVED-ORIGINAL-CODE",
            "detail": "DL93-UNIQUE-BOUNDED-ORIGINAL-DETAIL",
            "attribute_access_failures": [{"operation": "ORIGINAL_CODE_GETTER"}],
        }
        preserved_compensation = {
            "exception_type": "builtins.OSError",
            "code": "DL93-PRESERVED-COMPENSATION-CODE",
            "detail": "preserved compensation detail",
        }
        surfaced = schema10._independent_terminal_surface(
            original_operation_error=RuntimeError("reduced original identity"),
            compensation_error=OSError("reduced compensation identity"),
            terminal_error=OSError("terminal attach failed"),
            operation="TERMINAL_ATTACH",
            recovery_payload={
                "original_operation_error": preserved_original,
                "outer_compensation_error": preserved_compensation,
                "structured_reconciliation": [{"writer_id": "W01", "destination_replaced": True}],
                "accumulated_evidence_is_monotonic": True,
            },
        )
        payload = surfaced.evidence_payload
        self.assertEqual(preserved_original, payload["original_operation_error"])
        self.assertEqual(preserved_compensation, payload["outer_compensation_error"])
        self.assertIn("terminal_original_operation_identity", payload)
        self.assertIn("terminal_outer_compensation_identity", payload)
        self.assertIn("DL93-UNIQUE-BOUNDED-ORIGINAL-DETAIL", str(surfaced))
        self.assertLessEqual(
            len(str(surfaced).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_absolute_surface_carries_recovery_and_all_prior_failures(self) -> None:
        class EqualityBomb:
            def __eq__(self, other):
                raise OSError("independent operation comparison failed")

        prior_failures = [
            {
                "operation": operation,
                "exception_type": "builtins.OSError",
                "detail": operation + " detail",
            }
            for operation in (
                "DL93_CANONICAL_SERIALIZATION",
                "DL93_FALLBACK_SERIALIZATION",
                "DL93_LAST_RESORT_SERIALIZATION",
            )
        ]
        preserved_original = {
            "exception_type": "builtins.RuntimeError",
            "code": "DL93-ABSOLUTE-ORIGINAL-CODE",
            "detail": "DL93-ABSOLUTE-UNIQUE-ORIGINAL-DETAIL",
        }
        reconciliation = [{"writer_id": "W01", "destination_replaced": True}]
        surfaced = schema10._independent_terminal_surface(
            original_operation_error=RuntimeError("reduced absolute original"),
            compensation_error=OSError("reduced absolute compensation"),
            terminal_error=OSError("terminal failure before absolute"),
            operation=EqualityBomb(),
            recovery_payload={
                "original_operation_error": preserved_original,
                "outer_compensation_error": {
                    "exception_type": "builtins.OSError",
                    "detail": "full absolute compensation detail",
                },
                "structured_reconciliation": reconciliation,
                "serialization_failures": prior_failures,
                "serialization_failure": prior_failures[0],
                "serialization_fallback_failure": prior_failures[1],
                "last_resort_serialization_failure": prior_failures[2],
            },
        )
        payload = surfaced.evidence_payload
        self.assertEqual("DL93_ABSOLUTE_TERMINAL_SURFACE_V1", payload["terminal_surface"])
        self.assertEqual(preserved_original, payload["original_operation_error"])
        self.assertEqual(reconciliation, payload["structured_reconciliation"])
        self.assertEqual(prior_failures[1], payload["serialization_fallback_failure"])
        self.assertEqual(prior_failures[2], payload["last_resort_serialization_failure"])
        operations = [item["operation"] for item in surfaced.serialization_failures]
        for failure in prior_failures:
            self.assertIn(failure["operation"], operations)
        self.assertIn("INDEPENDENT_TERMINAL_SURFACE_INTERNAL", operations)
        self.assertIn("DL93-ABSOLUTE-UNIQUE-ORIGINAL-DETAIL", str(surfaced))
        self.assertFalse(payload["generic_recovery_recursive"])
        self.assertLessEqual(
            len(str(surfaced).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_identity_reserve_survives_snapshot_node_starvation_and_message_contraction(self) -> None:
        noisy_exception_type = [list(range(256)) for _ in range(16)]
        payload = {
            "exception_type": noisy_exception_type,
            "original_operation_error": {
                "exception_type": "builtins.RuntimeError",
                "code": "DL93-RESERVED-ORIGINAL",
                "detail": "critical original detail",
            },
            "noise": "x" * 30000,
        }
        detail = schema10._serialize_evidence_payload(
            payload, operation="DL93_IDENTITY_NODE_RESERVE"
        )
        reserve = detail.evidence_payload[schema10._TERMINAL_IDENTITY_RESERVE_KEY]
        self.assertEqual(
            "DL93-RESERVED-ORIGINAL", reserve["$.original_operation_error.code"]
        )
        self.assertIn("DL93-RESERVED-ORIGINAL", str(detail))
        error = ProductionSchema10OperationalError("C" * 8192, detail)
        self.assertIn("DL93-RESERVED-ORIGINAL", str(error))
        self.assertLessEqual(
            len(str(error).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES
        )

    def test_dl93_m6_million_character_scalar_is_bounded_deterministically(self) -> None:
        detail = schema10._serialize_evidence_payload(
            {"critical_error_identity": "DL93-MILLION", "noise": "x" * 1_000_000},
            operation="DL93_MILLION",
        )
        self.assertLessEqual(len(str(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)
        self.assertEqual("DL93-MILLION", detail.evidence_payload["critical_error_identity"])
        self.assertIn("<DL93_TRUNCATED>", detail.evidence_payload["noise"])

    def test_dl93_deep_and_numerous_evidence_is_snapshot_bounded(self) -> None:
        deep = "leaf"
        for index in range(100):
            deep = {"level": index, "next": deep}
        detail = schema10._serialize_evidence_payload(
            {"deep": deep, "many": list(range(6000)), "critical": "DL93-DEEP"},
            operation="DL93_DEEP",
        )
        self.assertLessEqual(len(str(detail).encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)
        rendered_payload = schema10._canonical_json(detail.evidence_payload)
        self.assertIn("DL93_TRUNCATED", rendered_payload)
        self.assertEqual("DL93-DEEP", detail.evidence_payload["critical"])

    def test_dl93_m6_exact_encoded_byte_bound_below_equal_and_above(self) -> None:
        cap = schema10.TERMINAL_EVIDENCE_MAX_BYTES
        below = schema10._bounded_terminal_text("x" * (cap - 1))
        equal = schema10._bounded_terminal_text("x" * cap)
        above = schema10._bounded_terminal_text("x" * (cap + 1))
        self.assertEqual(cap - 1, len(below.encode("utf-8")))
        self.assertEqual(cap, len(equal.encode("utf-8")))
        self.assertEqual(cap, len(above.encode("utf-8")))
        self.assertTrue(above.endswith("$.__truncated__=true"))

    def test_dl93_truncation_preserves_critical_error_identity(self) -> None:
        payload = {f"noise_{index:02d}": "x" * 8000 for index in range(12)}
        payload["original_operation_error"] = {
            "exception_type": "builtins.RuntimeError",
            "code": "DL93-CRITICAL-CODE",
            "detail": "DL93-CRITICAL-DETAIL",
        }
        detail = schema10._serialize_evidence_payload(payload, operation="DL93_TRUNCATION")
        text = str(detail)
        self.assertLessEqual(len(text.encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)
        self.assertIn("builtins.RuntimeError", text)
        self.assertIn("DL93-CRITICAL-CODE", text)
        self.assertIn("$.__truncated__=true", text)

    def test_dl93_terminal_boundary_never_lets_builder_or_attach_failure_escape_raw(self) -> None:
        _path, _original, _target, state = self._dl90_changed_state("dl93-last-boundary")
        with (
            patch.object(schema10, "_generic_projection_recovery_payload", side_effect=OSError("builder raw dl93")),
            patch.object(schema10, "_attach_projection_recovery_evidence", side_effect=OSError("attach raw dl93")),
        ):
            surfaced = schema10._surface_projection_recovery(
                [state],
                original_operation_error=RuntimeError("original last boundary dl93"),
                compensation_error=RuntimeError("compensation last boundary dl93"),
                compensation_status="FAILED",
            )
        self.assertIsInstance(surfaced, ProductionSchema10OperationalError)
        self.assertEqual("SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED", surfaced.code)
        self.assertIn("terminal_attach_failure", surfaced.evidence_payload)
        self.assertLessEqual(len(surfaced.detail.encode("utf-8")), schema10.TERMINAL_EVIDENCE_MAX_BYTES)

    def test_dl93_destination_mutation_bookkeeping_remains_exact_under_hostile_exception(self) -> None:
        class Hostile(OSError):
            def __bool__(self):
                raise AssertionError("truthiness forbidden")
            def __repr__(self):
                raise AssertionError("repr forbidden")

        path = self.root / "dl93-bookkeeping.authorized.json"
        original = b"dl93-bookkeeping-before\n"
        target = b"dl93-bookkeeping-after\n"
        path.write_bytes(original)
        state = schema10._capture_projection_entry_state(
            writer_id="W01", path=path, source_payload=original, target_payload=target
        )
        with patch.object(schema10.os, "chmod", side_effect=Hostile("hostile chmod")):
            with self.assertRaises(schema10._AtomicWriteFailure):
                schema10._write_projection_entry(state, state.mode or 0o600)
        self.assertTrue(state.write_attempted)
        self.assertTrue(state.destination_replaced)
        self.assertTrue(state.changed_by_invocation)
        self.assertEqual("DESTINATION_CHMOD", state.failed_post_replace_operation)
        self.assertEqual(target, path.read_bytes())

    def test_actual_discovery_runs_only_after_v04_projection_restore_and_mixed_identity_fails_closed(self) -> None:
        authority, runtime, site = _actual_single_writer_authority(self.root / "actual-discovery")
        with patch.object(schema10, "EXPECTED_WRITERS", {"W05": EXPECTED_WRITERS["W05"]}):
            initial = authority.discover()
            self.assertEqual("0.5.0", initial.entries[0].client.version)
            transition = Schema10WriterTransition("DL86-ACTUAL-DISCOVERY")
            transition._authority = authority
            transition._original_token = _QuiescenceToken(
                before=initial,
                quiesced_stable_identities=tuple(entry.stable_identity for entry in initial.entries),
                before_classes=tuple((entry.writer_id, entry.before_class or "C") for entry in initial.entries),
            )

            # Simulate the exact external v0.4 runtime-byte restore first. The
            # projection still names v0.5, so actual discovery must fail closed.
            _write_actual_thin_startup(site, dcs_adoption._AUTHORIZED_THIN_STARTUP_V9)
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority.discover()
            self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)

            entry_projection = transition._capture_exact_v04_rollback_entry_state()
            _transition_authorized_projection(
                runtime,
                from_build=V05_CLIENT_BUILD,
                to_build=V04_CLIENT_BUILD,
                operation_id="DL86-ACTUAL-DISCOVERY",
                assert_effect_authority=lambda: 0,
                expected_entry_payloads=entry_projection,
            )
            observed = authority.discover()
            self.assertEqual("0.4.0", observed.entries[0].client.version)
            self.assertEqual(schema10.V04_SOURCE, observed.entries[0].client.source_commit)
            self.assertEqual(V04_CLIENT_BUILD, observed.entries[0].client.build_identity)

    def test_post_schema10_restore_failure_retains_w08_and_retry_can_release(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-RESTORE-RETRY")
        held = _acquire_schema9_w08(dcs, "DL85-RESTORE-RETRY", backup)
        transition = _prepared_transition_for_test("DL85-RESTORE-RETRY", backup)
        transition.apply_exact_migration10(held)
        held.rebind_schema10()

        class FailingAuthority:
            def resume_fenced(self, *args, **kwargs):
                raise RuntimeError("restore failed")

        transition._authority = FailingAuthority()
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            transition.restore_schema10_same_fence(held)
        self.assertEqual(
            "SCHEMA10_WRITER_RESTORE_FAILED_W08_RETAINED", caught.exception.code
        )
        self.assertEqual("HELD", _lease(dcs)["state"])
        with self.assertRaises(ProductionSchema10OperationalError):
            held.release_after_schema10_writer_restore()

        class SuccessfulAuthority:
            def resume_fenced(self, *args, **kwargs):
                return None

        transition._authority = SuccessfulAuthority()
        transition._validate_restored = lambda _token, _schema: DcsWriterInventory(
            (), "sha256:test"
        )
        evidence = transition.restore_schema10_same_fence(held)
        self.assertEqual(held.fencing_token, evidence.fencing_token)
        released = held.release_after_schema10_writer_restore()
        self.assertEqual("FREE", released["state"])
        self.assertEqual("FREE", _lease(dcs)["state"])
        self.assertEqual(
            ["ACQUIRE", "RELEASE"],
            [event["event_type"] for event in _event_rows(dcs)],
        )

    def test_migration_requires_exact_writer_preparation_binding(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-MIGRATION-GATE")
        held = _acquire_schema9_w08(dcs, "DL85-MIGRATION-GATE", backup)

        transition = Schema10WriterTransition("DL85-MIGRATION-GATE")
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            transition.apply_exact_migration10(held)
        self.assertEqual("SCHEMA10_MIGRATION_PREPARATION_REQUIRED", caught.exception.code)
        self.assertEqual(9, _inspect_schema(dcs, 9).version)

        other = replace(backup, backup_identity="sha256:not-the-bound-backup")
        transition._state = "BACKED_UP"
        transition._backup = other
        transition._v05_token = object()
        transition._assert_exact_v05_quiesced = lambda: None
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            transition.apply_exact_migration10(held)
        self.assertEqual(
            "SCHEMA10_MIGRATION_PREPARATION_BINDING_MISMATCH", caught.exception.code
        )
        self.assertEqual(9, _inspect_schema(dcs, 9).version)
        held.close_without_release()

    def test_partial_schema10_restore_effect_is_never_blindly_replayed(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-PARTIAL-RESTORE")
        held = _acquire_schema9_w08(dcs, "DL85-PARTIAL-RESTORE", backup)
        transition = _prepared_transition_for_test("DL85-PARTIAL-RESTORE", backup)
        transition.apply_exact_migration10(held)
        held.rebind_schema10()

        class FirstFailureAuthority:
            def resume_fenced(self, *args, **kwargs):
                raise RuntimeError("effect became ambiguous")

        transition._authority = FirstFailureAuthority()
        with self.assertRaises(ProductionSchema10OperationalError):
            transition.restore_schema10_same_fence(held)
        self.assertEqual("SCHEMA10_RESTORE_RECONCILIATION_REQUIRED", transition._state)
        self.assertEqual("HELD", _lease(dcs)["state"])

        class NeverReplayAuthority:
            def __init__(self):
                self.resume_calls = 0

            def resume_fenced(self, *args, **kwargs):
                self.resume_calls += 1

        authority = NeverReplayAuthority()
        transition._authority = authority

        def unresolved(*_args, **_kwargs):
            raise RuntimeError("partial loaded/enabled state")

        transition._validate_restored = unresolved
        transition._is_exact_quiesced_v05_baseline = lambda: False
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            transition.restore_schema10_same_fence(held)
        self.assertEqual(
            "SCHEMA10_WRITER_RESTORE_PARTIAL_EFFECT_RECONCILIATION_REQUIRED",
            caught.exception.code,
        )
        self.assertEqual(0, authority.resume_calls)
        self.assertEqual("HELD", _lease(dcs)["state"])
        held.close_without_release()

    def test_schema10_restore_retry_is_allowed_only_from_exact_quiesced_baseline(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-CLEAN-RETRY")
        held = _acquire_schema9_w08(dcs, "DL85-CLEAN-RETRY", backup)
        transition = _prepared_transition_for_test("DL85-CLEAN-RETRY", backup)
        transition.apply_exact_migration10(held)
        held.rebind_schema10()
        transition._state = "SCHEMA10_RESTORE_RECONCILIATION_REQUIRED"

        class CountingAuthority:
            def __init__(self):
                self.resume_calls = 0

            def resume_fenced(self, *args, **kwargs):
                self.resume_calls += 1

        authority = CountingAuthority()
        transition._authority = authority
        validations = iter([RuntimeError("not restored"), DcsWriterInventory((), "sha256:test")])

        def validate(*_args, **_kwargs):
            result = next(validations)
            if isinstance(result, BaseException):
                raise result
            return result

        transition._validate_restored = validate
        transition._is_exact_quiesced_v05_baseline = lambda: True
        evidence = transition.restore_schema10_same_fence(held)
        self.assertEqual(1, authority.resume_calls)
        self.assertEqual(held.fencing_token, evidence.fencing_token)
        self.assertEqual("RESTORED_SCHEMA10", transition._state)
        held.close_without_release()

    def test_backup_evidence_and_source_identity_cannot_drift_before_w08(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-BINDING")

        forged = replace(backup, operation_id="DL85-FORGED")
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            verify_schema9_to10_immutable_backup(forged)
        self.assertEqual("SCHEMA10_BACKUP_EVIDENCE_BINDING_MISMATCH", caught.exception.code)

        connection = sqlite3.connect(dcs)
        try:
            connection.execute("PRAGMA user_version=85")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _acquire_schema9_w08(dcs, "DL85-BINDING", backup)
        self.assertEqual("SCHEMA10_W08_BACKUP_SOURCE_IDENTITY_STALE", caught.exception.code)

    def test_symlink_sources_and_authorized_roots_are_rejected(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        dcs_link = self.root / "dcs-link.sqlite3"
        dcs_link.symlink_to(dcs)
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _create_schema9_to10_immutable_backup(
                dcs_link, self.root / "evidence", "DL85-SYMLINK-DCS"
            )
        self.assertEqual("SCHEMA10_DCS_PATH_INVALID", caught.exception.code)

        root = self.root / "runtime"
        _write_authorized_root(root, V04_CLIENT_BUILD)
        root_link = self.root / "runtime-link"
        root_link.symlink_to(root, target_is_directory=True)
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            _transition_authorized_projection(
                root_link,
                from_build=V04_CLIENT_BUILD,
                to_build=V05_CLIENT_BUILD,
                operation_id="DL85-SYMLINK-AUTH",
            )
        self.assertEqual("SCHEMA10_AUTHORIZED_ROOT_INVALID", caught.exception.code)

    def test_wrong_fence_is_rejected(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 9)
        backup = _backup(dcs, self.root / "evidence", "DL85-WRONG-FENCE")
        held = _acquire_schema9_w08(dcs, "DL85-WRONG-FENCE", backup)
        connection = sqlite3.connect(dcs)
        try:
            connection.execute(
                "UPDATE global_production_writer_lease SET fencing_token=fencing_token+1 "
                "WHERE resource_key='GLOBAL_PRODUCTION'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            held.assert_current()
        self.assertEqual("SCHEMA10_W08_AUTHORITY_LOST", caught.exception.code)
        held.close_without_release()

    def _rollback_transition(self, operation_id: str, authority, *, state: str = "AUTHORIZED_V05"):
        transition = Schema10WriterTransition(operation_id)
        transition._state = state
        transition._original_token = object()
        transition._authority = authority
        transition._require_exact_inventory = lambda *_args: None
        transition._capture_exact_v04_rollback_entry_state = lambda: None
        transition._validate_restored = lambda *_args: DcsWriterInventory((), "sha256:restored")
        return transition

    def test_rollback_without_held_fails_before_projection_when_global_writer_occupied(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        before = _write_authorized_root(root, V05_CLIENT_BUILD)
        backup = _backup(dcs, self.root / "evidence", "DL85-RB-OCCUPIED")
        held = _acquire_schema9_w08(dcs, "DL85-RB-OCCUPIED", backup)

        class Authority:
            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                return None

        transition = self._rollback_transition("DL85-RB-OCCUPIED", Authority())
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
        ):
            with self.assertRaises(ProductionSchema10OperationalError):
                transition.rollback_to_v04_before_schema10()
        for writer_id, payload in before.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())
        held.close_without_release()

    def test_rollback_stale_held_fails_before_projection(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        before = _write_authorized_root(root, V05_CLIENT_BUILD)
        backup = _backup(dcs, self.root / "evidence", "DL85-RB-STALE")
        held = _acquire_schema9_w08(dcs, "DL85-RB-STALE", backup)
        connection = sqlite3.connect(dcs)
        try:
            connection.execute(
                "UPDATE global_production_writer_lease SET owner_execution_id='stale-attempt' "
                "WHERE resource_key='GLOBAL_PRODUCTION'"
            )
            connection.commit()
        finally:
            connection.close()

        class Authority:
            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                return None

        transition = self._rollback_transition("DL85-RB-STALE", Authority())
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                transition.rollback_to_v04_before_schema10(held)
        self.assertEqual("SCHEMA10_W08_IDENTITY_MISMATCH", caught.exception.code)
        for writer_id, payload in before.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())
        held.close_without_release()

    def test_rollback_quiescence_failure_changes_zero_authorized_bytes(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        before = _write_authorized_root(root, V05_CLIENT_BUILD)

        class Authority:
            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                raise RuntimeError("not quiesced")

        transition = self._rollback_transition("DL85-RB-QUIESCENCE", Authority())
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
        ):
            with self.assertRaisesRegex(RuntimeError, "not quiesced"):
                transition.rollback_to_v04_before_schema10()
        for writer_id, payload in before.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())

    def test_rollback_inventory_failure_changes_zero_authorized_bytes(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        before = _write_authorized_root(root, V05_CLIENT_BUILD)

        class Authority:
            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                return None

        transition = Schema10WriterTransition("DL85-RB-INVENTORY")
        transition._state = "AUTHORIZED_V05"
        transition._original_token = object()
        transition._authority = Authority()
        transition._capture_exact_v04_rollback_entry_state = lambda: None
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                transition.rollback_to_v04_before_schema10()
        self.assertEqual("SCHEMA10_WRITER_SET_INVALID", caught.exception.code)
        for writer_id, payload in before.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())

    def test_valid_free_rollback_guards_projection_before_any_write(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        _write_authorized_root(root, V05_CLIENT_BUILD)

        class Authority:
            def __init__(self):
                self.resume_calls = 0

            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                return None

            def resume_fenced(self, _token, *, schema_version, assert_current, assert_event_guard):
                self.resume_calls += 1
                self.assert_schema = schema_version
                assert_current()
                assert_event_guard()

        authority = Authority()
        transition = self._rollback_transition("DL85-RB-FREE", authority)
        original_cursor = transition._global_event_cursor_free
        original_projection = _transition_authorized_projection
        cursor_calls = 0

        def tracked_cursor():
            nonlocal cursor_calls
            cursor_calls += 1
            self.assertEqual("FREE", _lease(dcs)["state"])
            return original_cursor()

        def tracked_projection(*args, **kwargs):
            self.assertGreaterEqual(cursor_calls, 2)
            self.assertEqual("FREE", _lease(dcs)["state"])
            return original_projection(*args, **kwargs)

        transition._global_event_cursor_free = tracked_cursor
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
            patch(
                "adcp.production_schema10_operational._transition_authorized_projection",
                side_effect=tracked_projection,
            ),
        ):
            evidence = transition.rollback_to_v04_before_schema10()
        self.assertIsNone(evidence.owner_id)
        self.assertIsNone(evidence.fencing_token)
        self.assertEqual(1, authority.resume_calls)
        self.assertEqual(9, authority.assert_schema)
        self.assertEqual("ROLLED_BACK_V04_SCHEMA9", transition._state)
        for writer_id in EXPECTED_WRITERS:
            document = json.loads((root / f"{writer_id}.authorized.json").read_text())
            self.assertEqual(V04_CLIENT_BUILD, document["global_writer_client_build"])

    def test_valid_same_fence_rollback_guards_projection_under_exact_held_w08(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        _write_authorized_root(root, V05_CLIENT_BUILD)
        backup = _backup(dcs, self.root / "evidence", "DL85-RB-HELD")
        held = _acquire_schema9_w08(dcs, "DL85-RB-HELD", backup)

        class Authority:
            def __init__(self):
                self.resume_calls = 0

            def discover(self):
                return DcsWriterInventory((), "sha256:rollback")

            def verify_quiesced(self, _token):
                return None

            def resume_fenced(self, _token, *, schema_version, assert_current, assert_event_guard):
                self.resume_calls += 1
                self.assert_schema = schema_version
                assert_current()
                assert_event_guard()

        authority = Authority()
        transition = self._rollback_transition("DL85-RB-HELD", authority, state="BACKED_UP")
        original_projection = _transition_authorized_projection
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
            patch.object(held, "assert_current", wraps=held.assert_current) as current_guard,
            patch.object(held, "assert_event_guard", wraps=held.assert_event_guard) as event_guard,
        ):
            def tracked_projection(*args, **kwargs):
                self.assertGreaterEqual(current_guard.call_count, 1)
                self.assertGreaterEqual(event_guard.call_count, 1)
                row = _lease(dcs)
                self.assertEqual("HELD", row["state"])
                self.assertEqual(held.owner_id, row["owner_id"])
                self.assertEqual(held.owner_execution_id, row["owner_execution_id"])
                self.assertEqual(held.fencing_token, row["fencing_token"])
                return original_projection(*args, **kwargs)

            with patch(
                "adcp.production_schema10_operational._transition_authorized_projection",
                side_effect=tracked_projection,
            ):
                evidence = transition.rollback_to_v04_before_schema10(held)
        self.assertEqual(held.owner_id, evidence.owner_id)
        self.assertEqual(held.owner_execution_id, evidence.owner_execution_id)
        self.assertEqual(held.fencing_token, evidence.fencing_token)
        self.assertGreater(current_guard.call_count, 2)
        self.assertGreater(event_guard.call_count, 2)
        self.assertEqual(1, authority.resume_calls)
        self.assertEqual("ROLLED_BACK_V04_SCHEMA9", transition._state)
        for writer_id in EXPECTED_WRITERS:
            document = json.loads((root / f"{writer_id}.authorized.json").read_text())
            self.assertEqual(V04_CLIENT_BUILD, document["global_writer_client_build"])
        held.close_without_release()

    def test_rollback_invalid_phase_fails_before_projection(self) -> None:
        dcs = self.root / "control.sqlite3"
        root = self.root / "runtime"
        _schema_db(dcs, 9)
        before = _write_authorized_root(root, V05_CLIENT_BUILD)
        transition = Schema10WriterTransition("DL85-RB-PHASE")
        transition._original_token = object()
        with (
            patch("adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs),
            patch("adcp.production_schema10_operational.CANONICAL_RUNTIME_IDENTITY_ROOT", root),
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                transition.rollback_to_v04_before_schema10()
        self.assertEqual("SCHEMA10_WRITER_PHASE_INVALID", caught.exception.code)
        for writer_id, payload in before.items():
            self.assertEqual(payload, (root / f"{writer_id}.authorized.json").read_bytes())

    def test_v04_rollback_is_forbidden_when_dcs_is_schema10(self) -> None:
        dcs = self.root / "control.sqlite3"
        _schema_db(dcs, 10)
        transition = Schema10WriterTransition("DL85-NO-V04-SCHEMA10")
        transition._original_token = object()
        with patch(
            "adcp.production_schema10_operational.CANONICAL_DCS_PATH", dcs
        ):
            with self.assertRaises(ProductionSchema10OperationalError) as caught:
                transition.rollback_to_v04_before_schema10()
        self.assertEqual("SCHEMA10_V04_ROLLBACK_REQUIRES_SCHEMA9", caught.exception.code)

    def test_direct_w08_construction_is_forbidden(self) -> None:
        signature = inspect.signature(Schema10HeldW08)
        self.assertIn("_seal", signature.parameters)
        with self.assertRaises(ProductionSchema10OperationalError) as caught:
            Schema10HeldW08(
                _seal=object(),
                path=Path("/tmp/nope"),
                operation_id="DL85",
                backup=SimpleNamespace(),
                store=SimpleNamespace(),
                owner_id="owner",
                owner_execution_id="attempt",
                fencing_token=1,
                acquire_event_seq=1,
                release_operation_key="key",
            )
        self.assertEqual(
            "SCHEMA10_W08_DIRECT_CONSTRUCTION_FORBIDDEN", caught.exception.code
        )


if __name__ == "__main__":
    unittest.main()
