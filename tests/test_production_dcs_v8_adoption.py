from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from adcp.dcs_v7_v8_adoption import run_v7_to_v8_adoption
import adcp.production_dcs_v8_adoption as subject
from adcp.production_dcs_v8_adoption import (
    DcsWriterInventory,
    DcsWriterInventoryEntry,
    ProductionDcsV8AdoptionError,
    ProductionDcsV8AdoptionRequest,
    _DcsProfile,
    _ProductionDcsV8AdoptionController,
    _QuiescenceToken,
    _inspect_exact_profile,
    _inventory_fingerprint,
    _parse_client_identity,
)
from adcp.store import migrations
from adcp.runtime_artifact_attestation import RuntimeArtifactAttestation


def create_v6(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(migrations.SCHEMA_MIGRATION_SQL)
        for migration in migrations.MIGRATIONS[:6]:
            migrations._execute_statements(connection, migration.sql)
            connection.execute(
                "INSERT INTO schema_migration VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, "2026-09-06T00:00:00+00:00"),
            )
        connection.commit()
    finally:
        connection.close()


def migrate_to(path: Path, version: int) -> None:
    if not path.exists():
        create_v6(path)
    if version == 6:
        return
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        migrations.migrate(connection, target_version=version)
    finally:
        connection.close()


def build(version: str = "0.3.0", source: str = "a" * 40) -> str:
    return (
        f"adcp-global-writer-client@{version}+g{source[:12]}|source={source}|"
        f"artifact=source-commit:{source}"
    )


def inventory(*versions: str, state: str = "ACTIVE", suffix: str = "") -> DcsWriterInventory:
    entries = []
    for index, version in enumerate(versions, start=1):
        writer_id = f"W{index:02d}"
        client = _parse_client_identity(build(version, chr(96 + index) * 40))
        entry = DcsWriterInventoryEntry(
            writer_id=writer_id,
            launchd_label=f"com.propertyai.fixture-{writer_id.lower()}{suffix}",
            service_code=f"PROPERTYAI_{writer_id}_FIXTURE",
            runtime_identity_path=Path(f"/{writer_id}.runtime.json"),
            authorized_identity_path=Path(f"/{writer_id}.authorized.json"),
            pid=1000 + index if state == "ACTIVE" else None,
            process_incarnation_id=(str(index) * 64)[:64],
            product_build_commit="f" * 40,
            product_build_identity="product:PropertyAI@gffffffffffff|source=" + "f" * 40 + "|artifact=source-commit:" + "f" * 40,
            source_root_or_artifact_identity="source-commit:" + "f" * 40,
            client=client,
            state=state,
        )
        entries.append(entry)
    ordered = tuple(entries)
    return DcsWriterInventory(ordered, _inventory_fingerprint(ordered))

def inventory_states(*states: str) -> DcsWriterInventory:
    base = inventory(*("0.3.0" for _ in states))
    entries = tuple(
        replace(
            entry,
            state=state,
            pid=(1000 + index if state == "ACTIVE" else None),
        )
        for index, (entry, state) in enumerate(zip(base.entries, states), start=1)
    )
    return DcsWriterInventory(entries, _inventory_fingerprint(entries))



class FakeWriters:
    def __init__(self, initial: DcsWriterInventory) -> None:
        self.current = initial
        self.discoveries: list[DcsWriterInventory] = []
        self.events: list[str] = []
        self.quiesce_error: BaseException | None = None
        self.verify_quiesced_error: BaseException | None = None
        self.resume_error: BaseException | None = None
        self.health_error: BaseException | None = None

    def discover(self) -> DcsWriterInventory:
        self.events.append("discover")
        if self.discoveries:
            self.current = self.discoveries.pop(0)
        return self.current

    def quiesce(self, value: DcsWriterInventory) -> _QuiescenceToken:
        self.events.append("quiesce")
        if self.quiesce_error:
            raise self.quiesce_error
        return _QuiescenceToken(value, tuple(entry.stable_identity for entry in value.entries))

    def verify_quiesced(self, token: _QuiescenceToken) -> None:
        self.events.append("verify_quiesced")
        if self.verify_quiesced_error:
            raise self.verify_quiesced_error

    def resume(self, token: _QuiescenceToken) -> None:
        self.events.append("resume")
        if self.resume_error:
            raise self.resume_error

    def verify_resumed(self, token: _QuiescenceToken) -> DcsWriterInventory:
        self.events.append("verify_resumed")
        if self.health_error:
            raise self.health_error
        return self.current


class DisposableMigrations:
    def __init__(self) -> None:
        self.calls: list[int] = []
        self.fail_at: int | None = None

    def run_v6_to_v7(self, path: Path, _inventory: DcsWriterInventory) -> None:
        self.calls.append(7)
        if self.fail_at == 7:
            raise RuntimeError("fixture-v7-failure")
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            migrations.migrate(connection, target_version=7)
        finally:
            connection.close()

    def run_v7_to_v8(self, path: Path) -> None:
        self.calls.append(8)
        if self.fail_at == 8:
            raise RuntimeError("fixture-v8-failure")
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            run_v7_to_v8_adoption(connection)
        finally:
            connection.close()


def w08_free(_path: Path):
    return {"state": "FREE", "fencing_token": 1}


class RecordingHeldW08:
    def __init__(
        self,
        events: list[str],
        *,
        fencing_token: int = 1,
        fail_assert_at: int | None = None,
        fail_reopen: bool = False,
        fail_release: bool = False,
        replacement_token: int | None = None,
    ) -> None:
        self.events = events
        self.fencing_token = fencing_token
        self.fail_assert_at = fail_assert_at
        self.fail_reopen = fail_reopen
        self.fail_release = fail_release
        self.replacement_token = replacement_token
        self.assert_count = 0
        self.closed = False

    def assert_current(self) -> int:
        self.assert_count += 1
        self.events.append("W08_ASSERT_CURRENT")
        if self.fail_assert_at == self.assert_count:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_AUTHORITY_LOST",
                phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
            )
        return self.fencing_token

    def reopen_exact_schema(self, version: int) -> int:
        self.events.append("SAME_W08_LEASE_VERIFIED")
        if self.fail_reopen:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_SCHEMA_REBIND_FAILED",
                phase="POST_MIGRATION", schema_version=version,
                recovery_status="RECOVERY_REQUIRED",
            )
        return self.fencing_token if self.replacement_token is None else self.replacement_token

    def release(self):
        self.events.append("W08_RELEASED")
        if self.fail_release:
            raise ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED",
                phase="SERIALIZATION", recovery_status="RECOVERY_REQUIRED",
            )
        return {"state": "FREE", "fencing_token": self.fencing_token}

    def close(self) -> None:
        self.closed = True


class RecordingW08Authority:
    def __init__(
        self, events: list[str], *, lease: RecordingHeldW08 | None = None,
        acquire_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.lease = RecordingHeldW08(events) if lease is None else lease
        self.acquire_error = acquire_error
        self.acquire_count = 0

    def acquire(self, _path: Path, _request: ProductionDcsV8AdoptionRequest):
        self.acquire_count += 1
        self.events.append("W08_ACQUIRED")
        if self.acquire_error is not None:
            raise self.acquire_error
        return self.lease


class ProductionDcsV8AdoptionControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "control.sqlite3"
        self.good = inventory("0.3.0", "0.3.0")
        self.writers = FakeWriters(self.good)
        self.migrations = DisposableMigrations()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def controller(self, *, w08_reader=w08_free, w08_authority=None, profile_reader=_inspect_exact_profile):
        return _ProductionDcsV8AdoptionController(
            path=self.path,
            writers=self.writers,
            migrations=self.migrations,
            profile_reader=profile_reader,
            w08_reader=w08_reader,
            w08_authority=w08_authority,
        )

    def test_public_surface_has_no_generic_migration_or_runtime_authority(self) -> None:
        self.assertEqual(["operation_id"], list(inspect.signature(ProductionDcsV8AdoptionRequest).parameters))
        self.assertEqual(
            ["request"], list(inspect.signature(subject.run_production_dcs_v8_adoption).parameters)
        )
        forbidden = {
            "database", "path", "target", "target_schema", "migrations", "sql", "callback",
            "quiescence", "command", "writer", "writers", "services", "service_list",
        }
        self.assertFalse(forbidden & set(inspect.signature(ProductionDcsV8AdoptionRequest).parameters))
        self.assertFalse(forbidden & set(inspect.signature(subject.run_production_dcs_v8_adoption).parameters))

    def test_client_identity_classifies_deployed_lines_and_unknown_fail_closed(self) -> None:
        v1 = _parse_client_identity(build("0.1.0", subject._LEGACY_0_1_SOURCE))
        v2 = _parse_client_identity(build("0.2.0", subject._TRANSITION_0_2_SOURCE))
        v3 = _parse_client_identity(build("0.3.0", "a" * 40))
        unknown = _parse_client_identity(build("9.9.9", "b" * 40))
        source_tree = _parse_client_identity("adcp-global-writer-client@0.3.0+source-tree")
        self.assertEqual((6,), v1.supported_dcs_schema_versions)
        self.assertEqual((6, 7), v2.supported_dcs_schema_versions)
        self.assertEqual((6, 7, 8), v3.supported_dcs_schema_versions)
        self.assertIsNone(unknown.supported_dcs_schema_versions)
        self.assertIsNone(source_tree.supported_dcs_schema_versions)


    def _v9_runtime_artifact_fixture(self):
        root = self.root / "v9-runtime-artifact"
        venv = root / "venv"
        interpreter = venv / "bin" / "python"
        interpreter.parent.mkdir(parents=True, exist_ok=True)
        interpreter.write_bytes(b"fixture-python")
        purelib = venv / "lib" / "python3.13" / "site-packages"
        dist_info = purelib / "adcp_global_writer_client-0.4.0.dist-info"
        package_root = purelib / "adcp_global_writer_client"
        dist_info.mkdir(parents=True, exist_ok=True)
        package_root.mkdir(parents=True, exist_ok=True)
        module_file = package_root / "__init__.py"
        module_file.write_text("# fixture\n", encoding="utf-8")
        wheel = root / "accepted-client.whl"
        wheel.write_bytes(b"accepted-wheel-bytes")
        wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()

        source = subject._V9_COMPAT_0_4_SOURCE
        client = _parse_client_identity(build("0.4.0", source))
        base = inventory("0.3.0", state="INACTIVE").entries[0]
        entry = replace(
            base,
            client=client,
            before_class="B",
            runtime_state="INACTIVE",
            load_state="UNLOADED",
            enabled_state="DISABLED",
            program_arguments=(str(interpreter), "-m", "fixture.worker"),
        )
        binding_facts = json.dumps(
            {
                "writer": entry.writer_id,
                "label": entry.launchd_label,
                "interpreter": str(interpreter),
                "generation_trigger": "RUNATLOAD_AFTER_BASELINE_BOOTSTRAP",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        attestation = RuntimeArtifactAttestation(
            accepted_wheel_realpath=str(wheel.resolve(strict=True)),
            accepted_wheel_sha256=wheel_sha,
            interpreter_path=str(interpreter),
            interpreter_realpath=str(interpreter.resolve(strict=True)),
            sys_executable=str(interpreter),
            sys_executable_realpath=str(interpreter.resolve(strict=True)),
            sys_prefix=str(venv),
            sys_prefix_realpath=str(venv.resolve(strict=True)),
            base_prefix=str(root / "base-python"),
            purelib_path=str(purelib),
            purelib_realpath=str(purelib.resolve(strict=True)),
            installed_distribution_root=str(purelib),
            installed_dist_info_path=str(dist_info),
            installed_package_root=str(package_root),
            installed_module_file=str(module_file),
            installed_member_manifest_sha256="1" * 64,
            installed_member_count=12,
            installed_version="0.4.0",
            installed_build_id=subject._V9_COMPAT_0_4_BUILD_ID,
            installed_source_commit=source,
            installed_supported_dcs_schemas=(6, 7, 8, 9),
            installed_thin_contract_format_version=2,
            installed_schema_contract_identity=subject._V9_COMPAT_0_4_CONTRACT,
            direct_url_provenance_status="ACCEPTED_WHEEL_MATCH",
            direct_url=None,
            binding_facts_json=binding_facts,
            binding_facts_sha256=hashlib.sha256(binding_facts.encode("utf-8")).hexdigest(),
            deterministic_attestation_sha256="2" * 64,
            attestation_generated_at="2026-09-08T00:00:00+00:00",
        )
        return entry, attestation

    def _v9_authority_with_attestation(self, attestation):
        return subject._LaunchdWriterAuthority(
            dcs_path=self.path,
            launch_agents_root=self.root,
            runtime_root=self.root,
            uid=501,
            runtime_artifact_attestation=lambda _entry, _schema: attestation,
        )

    def test_s2_exact_v05_metadata_and_pinned_wheel_attestation(self):
        import zipfile
        import ast
        wheel = Path("/tmp/tk43-dl82-v05-build-a/adcp_global_writer_client-0.5.0-py3-none-any.whl")
        self.assertEqual(subject._V10_COMPAT_0_5_WHEEL_SHA256, hashlib.sha256(wheel.read_bytes()).hexdigest())
        with zipfile.ZipFile(wheel) as archive:
            assignments = ast.parse(archive.read("adcp_global_writer_client/_build_identity.py").decode())
        facts = {node.targets[0].id: ast.literal_eval(node.value) for node in assignments.body if isinstance(node, ast.Assign)}
        accepted = subject._AUTHORIZED_THIN_STARTUP_V10
        self.assertEqual(accepted.build_id, facts["BUILD_ID"])
        self.assertEqual(accepted.source_commit, facts["SOURCE_COMMIT"])
        self.assertEqual(accepted.artifact_identity, facts["ARTIFACT_IDENTITY"])
        self.assertEqual(accepted.schema_contract_identity, facts["EXPECTED_SCHEMA_CONTRACT_IDENTITY"])
        self.assertEqual(accepted.supported_dcs_schema_versions, facts["EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS"])
        client = _parse_client_identity(build("0.5.0", accepted.source_commit))
        self.assertEqual("V10_0_5_METADATA_EXACT", client.classification)
        self.assertEqual((6, 7, 8, 9, 10), client.supported_dcs_schema_versions)
        self.assertFalse(client.supports_schema(11))
        self.assertFalse(_parse_client_identity(build("0.5.0", "f" * 40)).supports_schema(10))
        entry, old = self._v9_runtime_artifact_fixture()
        entry = replace(entry, client=client)
        attestation = replace(
            old, accepted_wheel_realpath=str(wheel.resolve()),
            accepted_wheel_sha256=subject._V10_COMPAT_0_5_WHEEL_SHA256,
            installed_version="0.5.0", installed_build_id=accepted.build_id,
            installed_source_commit=accepted.source_commit,
            installed_supported_dcs_schemas=accepted.supported_dcs_schema_versions,
            installed_schema_contract_identity=accepted.schema_contract_identity,
        )
        authority = self._v9_authority_with_attestation(attestation)
        for schema in (9, 10):
            self.assertIs(attestation, authority._require_restore_client_compatible(entry, schema))
        with self.assertRaisesRegex(ProductionDcsV8AdoptionError, "SCHEMA_CLIENT_INCOMPATIBLE"):
            authority._require_restore_client_compatible(entry, 11)
        for field, value in (
            ("accepted_wheel_sha256", "f" * 64), ("installed_build_id", old.installed_build_id),
            ("installed_source_commit", "f" * 40), ("installed_schema_contract_identity", old.installed_schema_contract_identity),
            ("installed_supported_dcs_schemas", (6, 7, 8, 9, 10, 11)),
            ("installed_thin_contract_format_version", 3),
        ):
            with self.subTest(field=field):
                wrong = self._v9_authority_with_attestation(replace(attestation, **{field: value}))
                with self.assertRaisesRegex(ProductionDcsV8AdoptionError, "ATTESTATION_MISMATCH"):
                    wrong._require_restore_client_compatible(entry, 10)
        wrong_wheel = self.root / "wrong-v05.whl"
        wrong_wheel.write_bytes(b"wrong bytes with matching self-report hash")
        wrong = self._v9_authority_with_attestation(replace(
            attestation, accepted_wheel_realpath=str(wrong_wheel),
            accepted_wheel_sha256=hashlib.sha256(wrong_wheel.read_bytes()).hexdigest(),
        ))
        with self.assertRaisesRegex(ProductionDcsV8AdoptionError, "ATTESTATION_MISMATCH"):
            wrong._require_restore_client_compatible(entry, 10)

    def test_exact_0_4_identity_is_v9_metadata_capable_but_does_not_synthesize_sha(self) -> None:
        source = subject._V9_COMPAT_0_4_SOURCE
        client = _parse_client_identity(build("0.4.0", source))
        self.assertEqual("V9_0_4_METADATA_EXACT", client.classification)
        self.assertEqual((6, 7, 8, 9), client.supported_dcs_schema_versions)
        self.assertEqual(subject._AUTHORIZED_THIN_STARTUP_V9.client_build_identity, client.build_identity)
        self.assertNotIn("package_artifact_sha256", DcsWriterInventoryEntry.__dataclass_fields__)
        self.assertNotIn("package_artifact_sha256", type(client).__dataclass_fields__)
        self.assertFalse(hasattr(subject, "_V9_COMPAT_0_4_ARTIFACT_SHA256"))
        wrong = _parse_client_identity(build("0.4.0", "f" * 40))
        self.assertFalse(wrong.supports_schema(9))

    def test_v9_restore_accepts_actual_attestation_result_for_exact_runtime(self) -> None:
        entry, attestation = self._v9_runtime_artifact_fixture()
        authority = self._v9_authority_with_attestation(attestation)
        observed = authority._require_restore_client_compatible(entry, 9)
        self.assertIs(attestation, observed)
        self.assertEqual(
            hashlib.sha256(Path(attestation.accepted_wheel_realpath).read_bytes()).hexdigest(),
            observed.accepted_wheel_sha256,
        )

    def test_v9_restore_requires_attestation_provider_even_when_metadata_is_exact(self) -> None:
        entry, _attestation = self._v9_runtime_artifact_fixture()
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root, uid=501
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority._require_restore_client_compatible(entry, 9)
        self.assertEqual(
            "PRODUCTION_DCS_WRITER_V9_RUNTIME_ARTIFACT_ATTESTATION_MISSING", caught.exception.code
        )

    def test_v9_restore_fails_closed_if_attestation_producer_rejects_byte_or_member_drift(self) -> None:
        entry, _attestation = self._v9_runtime_artifact_fixture()
        def rejected(_entry, _schema):
            raise RuntimeError("producer rejected installed bytes")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path,
            launch_agents_root=self.root,
            runtime_root=self.root,
            uid=501,
            runtime_artifact_attestation=rejected,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority._require_restore_client_compatible(entry, 9)
        self.assertEqual(
            "PRODUCTION_DCS_WRITER_V9_RUNTIME_ARTIFACT_ATTESTATION_FAILED", caught.exception.code
        )

    def test_v9_restore_rechecks_accepted_wheel_bytes_after_attestation(self) -> None:
        entry, attestation = self._v9_runtime_artifact_fixture()
        Path(attestation.accepted_wheel_realpath).write_bytes(b"same-metadata-different-wheel-bytes")
        authority = self._v9_authority_with_attestation(attestation)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority._require_restore_client_compatible(entry, 9)
        self.assertEqual(
            "PRODUCTION_DCS_WRITER_V9_RUNTIME_ARTIFACT_ATTESTATION_MISMATCH", caught.exception.code
        )

    def test_v9_restore_rejects_wrong_interpreter_venv_site_packages_and_binding(self) -> None:
        entry, attestation = self._v9_runtime_artifact_fixture()
        cases = {
            "interpreter": replace(attestation, interpreter_path=str(self.root / "other" / "bin" / "python")),
            "venv": replace(attestation, sys_prefix=str(self.root / "other-venv")),
            "site-packages": replace(
                attestation,
                purelib_path=str(self.root / "outside" / "site-packages"),
                purelib_realpath=str(self.root / "outside" / "site-packages"),
                installed_distribution_root=str(self.root / "outside" / "site-packages"),
            ),
            "binding": replace(attestation, binding_facts_json='{"writer":"WRONG"}'),
        }
        for name, value in cases.items():
            with self.subTest(name=name):
                authority = self._v9_authority_with_attestation(value)
                with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                    authority._require_restore_client_compatible(entry, 9)
                self.assertEqual(
                    "PRODUCTION_DCS_WRITER_V9_RUNTIME_ARTIFACT_ATTESTATION_MISMATCH",
                    caught.exception.code,
                )

    def test_v9_restore_rejects_incomplete_or_malformed_attestation_contract(self) -> None:
        entry, attestation = self._v9_runtime_artifact_fixture()
        bad_values = (
            None,
            replace(attestation, accepted_wheel_sha256="not-a-sha"),
            replace(attestation, installed_member_manifest_sha256="bad"),
            replace(attestation, installed_member_count=0),
            replace(attestation, installed_version="0.3.0"),
            replace(attestation, installed_build_id="wrong-build"),
            replace(attestation, installed_source_commit="f" * 40),
            replace(attestation, installed_supported_dcs_schemas=(6, 7, 8)),
            replace(attestation, installed_schema_contract_identity="sha256:wrong"),
        )
        for value in bad_values:
            with self.subTest(value=repr(value)[:80]):
                authority = self._v9_authority_with_attestation(value)
                with self.assertRaises(ProductionDcsV8AdoptionError):
                    authority._require_restore_client_compatible(entry, 9)

    def test_v9_restore_still_rejects_non_04_client_before_attestation(self) -> None:
        old = inventory("0.3.0").entries[0]
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root, uid=501
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority._require_restore_client_compatible(old, 9)
        self.assertEqual("PRODUCTION_DCS_WRITER_RESTORE_SCHEMA_CLIENT_INCOMPATIBLE", caught.exception.code)

    def test_scheduler_fingerprint_distinguishes_presence_and_values(self) -> None:
        absent = {"Label": "x", "ProgramArguments": ["/x"]}
        false_zero = {"Label": "x", "ProgramArguments": ["/x"], "RunAtLoad": False, "StartInterval": 0}
        scheduled = {"Label": "x", "ProgramArguments": ["/x"], "RunAtLoad": True, "StartInterval": 300, "KeepAlive": False}
        self.assertNotEqual(subject._scheduler_config_fingerprint(absent), subject._scheduler_config_fingerprint(false_zero))
        self.assertNotEqual(subject._scheduler_config_fingerprint(false_zero), subject._scheduler_config_fingerprint(scheduled))
        material = subject._scheduler_config_material(scheduled)
        self.assertEqual({"present": True, "value": True}, material["RunAtLoad"])
        self.assertEqual({"present": True, "value": 300}, material["StartInterval"])
        self.assertEqual({"present": True, "value": False}, material["KeepAlive"])

    def test_fenced_bridge_treats_missing_launchagent_writer_as_invocation_only_no_effect(self) -> None:
        base = inventory("0.3.0").entries[0]
        c_entry = replace(
            base, writer_id="W05", service_code="PROPERTYAI_W05_FIXTURE",
            state="INACTIVE", pid=None, before_class="C", runtime_state="INACTIVE",
            load_state="UNLOADED", enabled_state="DISABLED",
        )
        inv = DcsWriterInventory((c_entry,), _inventory_fingerprint((c_entry,)))
        class NoPhysicalEffects:
            def quiesce_fenced(self, *_args, **_kwargs):
                raise AssertionError("D/C must not cause physical quiesce")
            def resume_fenced(self, *_args, **_kwargs):
                raise AssertionError("D/C must not cause physical restore")
        bridge = subject._FencedFrozenWriterAdapter(NoPhysicalEffects(), inv)
        bridge.bind_migration_guard(assert_current=lambda: 1, assert_event_guard=lambda: None, schema_version=lambda: 8)
        d = next(writer for writer in bridge.discover() if writer.service_code == "W01")
        self.assertTrue(d.runtime_id.startswith("fenced-physical:invocation-only:"))
        self.assertEqual("QUIESCED", d.state)
        bridge.quiesce(d)
        bridge.reactivate(d)

    def test_v6_to_v7_to_v8_exact_sequence(self) -> None:
        create_v6(self.path)
        result = self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v6-v8"))
        self.assertEqual((6, 8, "ADOPTED_EXACT", (7, 8)), (
            result.previous_version, result.version, result.status, result.migration_versions
        ))
        self.assertEqual([7, 8], self.migrations.calls)
        self.assertEqual(8, _inspect_exact_profile(self.path).version)
        self.assertEqual("FREE", result.final_w08_state)

    def test_v7_to_v8_exact_sequence(self) -> None:
        create_v6(self.path)
        migrate_to(self.path, 7)
        result = self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v7-v8"))
        self.assertEqual((7, 8, (8,)), (result.previous_version, result.version, result.migration_versions))
        self.assertEqual([8], self.migrations.calls)
        connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = list(connection.execute(
                "SELECT event_type,from_fencing_token,to_fencing_token,new_change_id,prior_change_id "
                "FROM global_production_writer_event ORDER BY event_seq"
            ))
            lease = connection.execute(
                "SELECT state,fencing_token FROM global_production_writer_lease "
                "WHERE resource_key='GLOBAL_PRODUCTION'"
            ).fetchone()
        finally:
            connection.close()
        ours = [row for row in rows if row["new_change_id"] == subject.CHANGE_ID or row["prior_change_id"] == subject.CHANGE_ID]
        self.assertEqual(["ACQUIRE", "RELEASE"], [row["event_type"] for row in ours])
        self.assertEqual(1, sum(row["event_type"] == "ACQUIRE" for row in ours))
        self.assertEqual(ours[0]["to_fencing_token"], ours[1]["from_fencing_token"])
        self.assertEqual(ours[0]["to_fencing_token"], ours[1]["to_fencing_token"])
        self.assertEqual(("FREE", ours[0]["to_fencing_token"]), (lease["state"], lease["fencing_token"]))

    def test_exact_v8_is_noop_and_never_quiesces(self) -> None:
        create_v6(self.path)
        migrate_to(self.path, 7)
        self.migrations.run_v7_to_v8(self.path)
        self.migrations.calls.clear()
        result = self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v8-noop"))
        self.assertEqual("ALREADY_ADOPTED_EXACT", result.status)
        self.assertEqual((), result.migration_versions)
        self.assertEqual([], self.migrations.calls)
        self.assertNotIn("quiesce", self.writers.events)

    def test_schema_v9_rejected_before_quiescence(self) -> None:
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE schema_migration(version INTEGER PRIMARY KEY,name TEXT,checksum TEXT,applied_at TEXT)")
        for version in range(1, 10):
            connection.execute("INSERT INTO schema_migration VALUES(?,?,?,?)", (version, f"v{version}", "x", "now"))
        connection.commit(); connection.close()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v9"))
        self.assertEqual("PRODUCTION_DCS_SCHEMA_VERSION_UNSUPPORTED", caught.exception.code)
        self.assertNotIn("quiesce", self.writers.events)

    def test_partial_v7_profile_rejected_before_quiescence(self) -> None:
        create_v6(self.path)
        connection = sqlite3.connect(self.path)
        migration = migrations.MIGRATIONS[6]
        connection.execute(
            "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(7,?,?,?)",
            (migration.name, migration.checksum, "partial"),
        )
        connection.commit(); connection.close()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-partial-v7"))
        self.assertEqual("PRODUCTION_DCS_SCHEMA_PROFILE_INVALID", caught.exception.code)
        self.assertNotIn("quiesce", self.writers.events)

    def test_integrity_failure_rejected(self) -> None:
        self.path.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises((ProductionDcsV8AdoptionError, sqlite3.DatabaseError)) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-integrity"))
        if isinstance(caught.exception, ProductionDcsV8AdoptionError):
            self.assertEqual("PRODUCTION_DCS_INTEGRITY_FAILED", caught.exception.code)
        self.assertNotIn("quiesce", self.writers.events)

    def test_fk_violation_rejected(self) -> None:
        create_v6(self.path)
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO context_snapshot(context_snapshot_id,execution_id,role,capsule_version,fingerprint,canonical_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("ctx", "missing-execution", "MAKER", 1, "a" * 64, "{}", "now"),
        )
        connection.commit(); connection.close()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-fk"))
        self.assertEqual("PRODUCTION_DCS_FOREIGN_KEY_VIOLATION", caught.exception.code)
        self.assertNotIn("quiesce", self.writers.events)

    def test_v6_v7_only_writer_blocks_before_profile_or_mutation(self) -> None:
        create_v6(self.path)
        legacy = inventory("0.3.0", "0.2.0")
        self.writers.current = legacy
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-old-client"))
        self.assertEqual(
            "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_CLIENT_INCOMPATIBLE", caught.exception.code
        )
        self.assertEqual([], self.migrations.calls)
        self.assertNotIn("quiesce", self.writers.events)

    def test_unknown_writer_client_blocks_before_mutation(self) -> None:
        create_v6(self.path)
        self.writers.current = inventory("0.3.0", "9.9.9")
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-unknown-client"))
        self.assertEqual(
            "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_CLIENT_INCOMPATIBLE", caught.exception.code
        )
        self.assertEqual([], self.migrations.calls)

    def test_writer_inventory_change_after_preflight_blocks_before_quiescence(self) -> None:
        create_v6(self.path)
        changed = inventory("0.3.0", "0.3.0", suffix="-changed")
        self.writers.discoveries = [self.good, changed]
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-inventory-race"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_INVENTORY_CHANGED", caught.exception.code)
        self.assertNotIn("quiesce", self.writers.events)
        self.assertEqual([], self.migrations.calls)

    def test_writer_quiescence_failure_never_migrates(self) -> None:
        create_v6(self.path)
        self.writers.quiesce_error = ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED", phase="QUIESCENCE"
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-quiesce-fail"))
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_FAILED", caught.exception.code)
        self.assertEqual([], self.migrations.calls)

    def test_w08_not_free_never_migrates_and_restores_writers(self) -> None:
        create_v6(self.path)
        migrate_to(self.path, 7)
        events: list[str] = []
        authority = RecordingW08Authority(
            events,
            acquire_error=ProductionDcsV8AdoptionError(
                "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_W08_NOT_FREE", phase="SERIALIZATION"
            ),
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(
                ProductionDcsV8AdoptionRequest("fixture-w08-held")
            )
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_BLOCKED_W08_NOT_FREE", caught.exception.code)
        self.assertEqual([], self.migrations.calls)
        self.assertEqual(1, authority.acquire_count)
        self.assertIn("resume", self.writers.events)

    def test_w08_is_held_once_across_migration8_with_exact_required_order(self) -> None:
        create_v6(self.path)
        migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fencing_token=1)
        authority = RecordingW08Authority(events, lease=lease)

        original_profile = _inspect_exact_profile
        def recorded_profile(path: Path):
            profile = original_profile(path)
            if profile.version == 7 and "W08_ACQUIRED" in events:
                events.append("V7_VERIFIED")
            elif profile.version == 8:
                events.append("V8_VERIFIED")
            return profile

        original_run8 = self.migrations.run_v7_to_v8
        def recorded_run8(path: Path) -> None:
            events.append("MIGRATE8")
            original_run8(path)
        self.migrations.run_v7_to_v8 = recorded_run8

        result = self.controller(
            w08_authority=authority,
            profile_reader=recorded_profile,
            w08_reader=lambda _path: events.append("W08_FREE") or {"state": "FREE", "fencing_token": 1},
        ).run(ProductionDcsV8AdoptionRequest("fixture-w08-order"))
        self.assertEqual("ADOPTED_EXACT", result.status)
        self.assertEqual(1, authority.acquire_count)
        required = [
            "W08_ACQUIRED", "W08_ASSERT_CURRENT", "V7_VERIFIED",
            "W08_ASSERT_CURRENT", "MIGRATE8", "V8_VERIFIED",
            "SAME_W08_LEASE_VERIFIED", "W08_RELEASED", "W08_FREE",
        ]
        cursor = 0
        for event in events:
            if cursor < len(required) and event == required[cursor]:
                cursor += 1
        self.assertEqual(len(required), cursor, events)
        self.assertLess(events.index("W08_FREE"), len(events))
        self.assertIn("resume", self.writers.events)


    def test_w08_event_guard_is_checked_before_migration_and_before_release(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        class GuardedLease(RecordingHeldW08):
            def assert_event_guard(self) -> None:
                self.events.append("W08_EVENT_GUARD")
        lease = GuardedLease(events, fencing_token=1)
        authority = RecordingW08Authority(events, lease=lease)
        original_run8 = self.migrations.run_v7_to_v8
        def recorded_run8(path: Path) -> None:
            events.append("MIGRATE8")
            original_run8(path)
        self.migrations.run_v7_to_v8 = recorded_run8
        self.controller(w08_authority=authority).run(
            ProductionDcsV8AdoptionRequest("fixture-w08-event-guard")
        )
        guards = [i for i, event in enumerate(events) if event == "W08_EVENT_GUARD"]
        self.assertGreaterEqual(len(guards), 3, events)
        self.assertLess(guards[0], events.index("MIGRATE8"))
        self.assertLess(guards[-1], events.index("W08_RELEASED"))

    def test_w08_lease_lost_before_migration_never_runs_migration8(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fail_assert_at=1, fail_release=True)
        authority = RecordingW08Authority(events, lease=lease)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(ProductionDcsV8AdoptionRequest("fixture-lost"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_W08_RECOVERY_REQUIRED", caught.exception.code)
        self.assertEqual([], self.migrations.calls)
        self.assertNotIn("resume", self.writers.events)

    def test_w08_lease_replaced_immediately_before_migration_never_runs_migration8(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fail_assert_at=2, fail_release=True)
        authority = RecordingW08Authority(events, lease=lease)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(ProductionDcsV8AdoptionRequest("fixture-replaced"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_W08_RECOVERY_REQUIRED", caught.exception.code)
        self.assertEqual([], self.migrations.calls)
        self.assertNotIn("resume", self.writers.events)

    def test_w08_invalid_immediately_after_migration_is_recovery_required(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fail_reopen=True)
        authority = RecordingW08Authority(events, lease=lease)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(ProductionDcsV8AdoptionRequest("fixture-post-invalid"))
        self.assertEqual("RECOVERY_REQUIRED", caught.exception.recovery_status)
        self.assertEqual([8], self.migrations.calls)
        self.assertEqual(8, _inspect_exact_profile(self.path).version)
        self.assertNotIn("resume", self.writers.events)

    def test_w08_fencing_token_change_across_schema_transition_is_rejected(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fencing_token=1, replacement_token=2)
        authority = RecordingW08Authority(events, lease=lease)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(ProductionDcsV8AdoptionRequest("fixture-token-change"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_W08_FENCING_TOKEN_CHANGED", caught.exception.code)
        self.assertEqual("RECOVERY_REQUIRED", caught.exception.recovery_status)
        self.assertNotIn("resume", self.writers.events)

    def test_w08_release_failure_after_migration_is_recovery_required(self) -> None:
        create_v6(self.path); migrate_to(self.path, 7)
        events: list[str] = []
        lease = RecordingHeldW08(events, fail_release=True)
        authority = RecordingW08Authority(events, lease=lease)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller(w08_authority=authority).run(ProductionDcsV8AdoptionRequest("fixture-release-fail"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_W08_RELEASE_FAILED", caught.exception.code)
        self.assertEqual("RECOVERY_REQUIRED", caught.exception.recovery_status)
        self.assertNotIn("resume", self.writers.events)

    def test_v7_migration_failure_is_atomic_and_writers_restored(self) -> None:
        create_v6(self.path)
        self.migrations.fail_at = 7
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v7-fail"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_MIGRATION_FAILED", caught.exception.code)
        self.assertEqual(6, _inspect_exact_profile(self.path).version)
        self.assertIn("resume", self.writers.events)
        self.assertIn("verify_resumed", self.writers.events)

    def test_v8_migration_failure_leaves_exact_v7_and_restores_writers(self) -> None:
        create_v6(self.path)
        self.migrations.fail_at = 8
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-v8-fail"))
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_MIGRATION_FAILED", caught.exception.code)
        self.assertEqual([7, 8], self.migrations.calls)
        self.assertEqual(7, _inspect_exact_profile(self.path).version)
        self.assertIn("resume", self.writers.events)

    def test_post_migration_writer_health_failure_is_explicit_recovery_required(self) -> None:
        create_v6(self.path)
        self.writers.health_error = ProductionDcsV8AdoptionError(
            "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
            phase="POST_MIGRATION", schema_version=8, recovery_status="RECOVERY_REQUIRED",
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            self.controller().run(ProductionDcsV8AdoptionRequest("fixture-health-fail"))
        self.assertEqual(
            "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_HEALTH_RECOVERY_REQUIRED",
            caught.exception.code,
        )
        self.assertEqual("RECOVERY_REQUIRED", caught.exception.recovery_status)
        self.assertEqual(8, _inspect_exact_profile(self.path).version)

    def test_resume_entries_only_enables_and_starts_previously_active_writers(self) -> None:
        before = inventory_states("INACTIVE", "ACTIVE")
        commands: list[list[str]] = []
        def runner(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root,
            uid=501, runner=runner,
        )
        # This legacy unit isolates active-before selection; exact plist authority
        # is covered separately by restore-boundary tests.
        authority._service_definition_for_entry = lambda entry, **_kwargs: (
            Path(f"/tmp/{entry.writer_id}.plist"),
            entry.program_arguments or (f"/fixture/{entry.writer_id.lower()}/python", "--send"),
        )
        authority._resume_entries(before.entries)
        flattened = [" ".join(command) for command in commands]
        self.assertTrue(any("w02" in command and "enable" in command for command in flattened))
        self.assertTrue(any("w02" in command and "kickstart" in command for command in flattened))
        self.assertFalse(any("w01" in command for command in flattened))

    def test_post_resume_exact_active_set_passes_and_inactive_stays_inactive(self) -> None:
        before = inventory_states("INACTIVE", "ACTIVE")
        observed = inventory_states("INACTIVE", "ACTIVE")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root,
            uid=501, sleep=lambda _seconds: None,
        )
        authority.discover = lambda: observed
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        self.assertEqual(observed, authority.verify_resumed(token))

    def test_post_resume_extra_active_writer_is_rejected(self) -> None:
        before = inventory_states("INACTIVE", "ACTIVE")
        observed = inventory_states("ACTIVE", "ACTIVE")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root, uid=501,
        )
        authority.discover = lambda: observed
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH", caught.exception.code)

    def test_post_resume_missing_active_writer_is_rejected(self) -> None:
        before = inventory_states("INACTIVE", "ACTIVE")
        observed = inventory_states("INACTIVE", "INACTIVE")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root,
            uid=501, sleep=lambda _seconds: None,
        )
        authority.discover = lambda: observed
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        with mock.patch.object(subject.time, "monotonic", side_effect=[0.0, 16.0]):
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority.verify_resumed(token)
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH", caught.exception.code)

    def test_post_resume_before_empty_active_set_rejects_new_active_writer(self) -> None:
        before = inventory_states("INACTIVE")
        observed = inventory_states("ACTIVE")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root, uid=501,
        )
        authority.discover = lambda: observed
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_STATE_MISMATCH", caught.exception.code)

    def test_post_resume_inventory_identity_change_is_rejected(self) -> None:
        before = inventory_states("ACTIVE")
        changed = inventory("0.3.0", suffix="-new")
        authority = subject._LaunchdWriterAuthority(
            dcs_path=self.path, launch_agents_root=self.root, runtime_root=self.root, uid=501,
        )
        authority.discover = lambda: changed
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)
        self.assertEqual("PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_INVENTORY_CHANGED", caught.exception.code)

    def test_outer_quiescence_bridge_runs_actual_frozen_v6_to_v7_without_inner_service_effects(self) -> None:
        create_v6(self.path)
        evidence = self.root / "frozen-evidence"
        evidence.mkdir()
        bridge = subject._AlreadyQuiescedFrozenAdapter(self.good)
        context = subject.ExecutionContext(
            dcs_path=self.path,
            evidence_root=evidence,
            accepted_git_head="1" * 40,
            accepted_git_tree="2" * 40,
            authority_ref="FIXTURE/FROZEN-BRIDGE",
            background_heartbeat=False,
        )
        result = subject.ProductionMigrationOrchestrator(
            context, authority=lambda: {"fixture": "stable"}, quiescence=bridge
        ).run()
        self.assertEqual((6, 7, "FREE"), (
            result.previous_version, result.version, result.final_lease_state
        ))
        self.assertEqual((), result.quiesced_identities)
        self.assertEqual(7, _inspect_exact_profile(self.path).version)

    def test_frozen_bridge_exposes_all_expected_codes_as_already_quiesced(self) -> None:
        bridge = subject._AlreadyQuiescedFrozenAdapter(self.good)
        writers = tuple(bridge.discover())
        self.assertEqual(subject.EXPECTED_WRITER_CODES, frozenset(item.service_code for item in writers))
        self.assertTrue(all(item.state == "QUIESCED" for item in writers))
        with self.assertRaises(ProductionDcsV8AdoptionError):
            bridge.quiesce(writers[0])
        with self.assertRaises(ProductionDcsV8AdoptionError):
            bridge.reactivate(writers[0])


if __name__ == "__main__":
    unittest.main()
