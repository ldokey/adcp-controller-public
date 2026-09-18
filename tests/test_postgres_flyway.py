from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from adcp.domain import StoreError, operation_key
from adcp.postgres_approval_evidence import ProductionOperationApprovalEvidenceV1
from adcp.postgres_flyway import (
    EXPECTED_FLYWAY_VERSION,
    FLYWAY_CALLBACK_CONFIG_PATH,
    FLYWAY_CALLBACK_PATH,
    FLYWAY_CONFIG_PATH,
    FLYWAY_LOGIN_ROLE,
    FLYWAY_OPERATION_KIND,
    FROZEN_MIGRATIONS,
    ExecuteAuthorizedFlywayMigrationsRequest,
    FlywayControlError,
    FrozenMigration,
    _FlywayExecutionPolicy,
    _ProcessResult,
    _execute_authorized_flyway_migrations,
    _load_executable_ref,
    _migration_manifest_sha256,
    _run_migrate,
    _validate_frozen_source,
)
from adcp.postgres_control import CLEANER_DATABASE, CLEANER_TARGET_SERVICE, PROJECT_CODE, _assert_current_typed_authority
from adcp.production_control import CompositeProductionAuthority, GitSourceAuthority, ProductionControlError
from adcp.store.migrations import migrate
from adcp.store.sqlite import ControlStore, connect


CHANGE_ID = "P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01-P1R5-C3A-TEST"
CONTROL_REF = "CHAT.PROJ.HQ:APPROVAL:C3A:TEST"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repo: Path, message: str = "fixture") -> tuple[str, str]:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "-c", "user.name=C3A Fixture",
            "-c", "user.email=c3a@example.invalid", "commit", "-qm", message,
        ],
        check=True,
    )
    return _git(repo, "rev-parse", "HEAD"), _git(repo, "rev-parse", "HEAD^{tree}")


class FlywayExecutionPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="c3a-flyway-")
        self.root = Path(self.tmp.name)
        self.uid = os.getuid()

        self.controller_repo = self.root / "controller"
        self.controller_repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.controller_repo)], check=True)
        (self.controller_repo / "controller.txt").write_text("controller\n", encoding="utf-8")
        self.controller_commit, self.controller_tree = _commit(self.controller_repo, "controller")

        self.source_repo = self.root / "db-source"
        self.source_repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source_repo)], check=True)
        migrations: list[FrozenMigration] = []
        for item in FROZEN_MIGRATIONS:
            value = f"-- synthetic {item.version}\nSELECT 1;\n".encode()
            path = self.source_repo / item.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            migrations.append(FrozenMigration(item.version, item.path, _sha(value)))
        self.migrations = tuple(migrations)

        self.config_bytes = b"flyway.cleanDisabled=true\n"
        self.callback_bytes = b"-- synthetic afterConnect\nSELECT 1;\n"
        self.callback_config_bytes = b"executeInTransaction=false\n"
        for relative, value in (
            (FLYWAY_CONFIG_PATH, self.config_bytes),
            (FLYWAY_CALLBACK_PATH, self.callback_bytes),
            (FLYWAY_CALLBACK_CONFIG_PATH, self.callback_config_bytes),
        ):
            path = self.source_repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        self.source_commit, self.source_tree = _commit(self.source_repo, "db source")

        self.runtime_root = self.root / "runtime"
        self.runtime_root.mkdir(mode=0o700)
        os.chmod(self.runtime_root, 0o700)
        self.executable_path = self.runtime_root / "artifacts" / "flyway" / EXPECTED_FLYWAY_VERSION / "flyway"
        self.executable_path.parent.mkdir(parents=True)
        self.executable_bytes = b"#!/bin/sh\nexit 0\n"
        self.executable_path.write_bytes(self.executable_bytes)
        os.chmod(self.executable_path, 0o700)
        self.java_path = self.executable_path.parent / "jre" / "bin" / "java"
        self.java_path.parent.mkdir(parents=True)
        self.java_path.write_bytes(b"synthetic bundled java")
        os.chmod(self.java_path, 0o700)
        self.marker_path = (
            self.executable_path.parent / "lib" / "flyway"
            / f"flyway-commandline-{EXPECTED_FLYWAY_VERSION}.jar"
        )
        self.marker_path.parent.mkdir(parents=True)
        self.marker_bytes = b"synthetic-version-marker"
        self.marker_path.write_bytes(self.marker_bytes)
        os.chmod(self.marker_path, 0o600)
        self.executable_ref_path = self.executable_path.parent / "executable-ref.json"
        self._write_executable_ref()

        self.credential_root = self.root / "credential"
        self.credential_root.mkdir(mode=0o700)
        os.chmod(self.credential_root, 0o700)
        self.credential_path = self.credential_root / "flyway-password"
        self.credential_path.write_text("synthetic-secret\n", encoding="utf-8")
        os.chmod(self.credential_path, 0o600)

        self.approval_root = self.root / "approval"
        self.approval_root.mkdir(mode=0o700)
        os.chmod(self.approval_root, 0o700)

        self.policy = _FlywayExecutionPolicy(
            controller_source_root=self.controller_repo,
            source_root=self.source_repo,
            source_commit=self.source_commit,
            source_tree=self.source_tree,
            migrations=self.migrations,
            migration_manifest_sha256=_migration_manifest_sha256(self.migrations),
            flyway_config_path=FLYWAY_CONFIG_PATH,
            flyway_config_sha256=_sha(self.config_bytes),
            callback_path=FLYWAY_CALLBACK_PATH,
            callback_sha256=_sha(self.callback_bytes),
            callback_config_path=FLYWAY_CALLBACK_CONFIG_PATH,
            callback_config_sha256=_sha(self.callback_config_bytes),
            runtime_root=self.runtime_root,
            executable_ref_path=self.executable_ref_path,
            executable_path=self.executable_path,
            credential_root=self.credential_root,
            credential_path=self.credential_path,
            expected_owner_uid=self.uid,
            approval_evidence_root=self.approval_root,
            target_database=CLEANER_DATABASE,
            target_service=CLEANER_TARGET_SERVICE,
            host="127.0.0.1",
            port=65432,
            login_role=FLYWAY_LOGIN_ROLE,
            flyway_version=EXPECTED_FLYWAY_VERSION,
        )
        self.approved_ref = _load_executable_ref(self.policy)
        now = datetime(2026, 9, 9, 0, 0, tzinfo=timezone.utc)
        self.approval = ProductionOperationApprovalEvidenceV1(
            approval_id=CONTROL_REF,
            decision_stable_id="DL-41-TEST",
            decision_page_identity="notion-page:c3a-test",
            project_code=PROJECT_CODE,
            change_id=CHANGE_ID,
            gate_or_control_id="P1R5-C3A-TEST",
            operation_kind=FLYWAY_OPERATION_KIND,
            issued_at=(now - timedelta(minutes=1)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            evidence_sha256="a" * 64,
        )
        self.runner_calls = 0
        self.runner_secrets: list[str] = []

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_executable_ref(self, *, version: str = EXPECTED_FLYWAY_VERSION, executable_sha: str | None = None, executable_path: Path | None = None) -> None:
        payload = {
            "schema_version": 1,
            "reference_kind": "FLYWAY_EXECUTABLE_REF_V1",
            "executable_path": str(executable_path or self.executable_path),
            "executable_sha256": executable_sha or _sha(self.executable_bytes),
            "flyway_version": version,
            "version_marker_path": str(self.marker_path),
            "version_marker_sha256": _sha(self.marker_bytes),
        }
        self.executable_ref_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(self.executable_ref_path, 0o600)

    def _authority(self, policy: _FlywayExecutionPolicy | None = None) -> CompositeProductionAuthority:
        policy = policy or self.policy
        return CompositeProductionAuthority((
            GitSourceAuthority(self.controller_repo, self.controller_commit, require_clean=True),
            GitSourceAuthority(policy.source_root, policy.source_commit, require_clean=True),
        ))

    def _new_store(self, version: int) -> ControlStore:
        path = self.root / f"control-v{version}-{os.urandom(3).hex()}.sqlite3"
        connection = connect(path)
        try:
            migrate(connection, target_version=version)
        finally:
            connection.close()
        return ControlStore(
            path,
            migrate_schema=False,
            require_schema_version=version,
            global_writer_guard_required=True,
        )

    def _runner(self, _ref, _policy, secret: str) -> _ProcessResult:
        self.runner_calls += 1
        self.runner_secrets.append(secret)
        return _ProcessResult(0, "migrate ok", "")

    def _execute(
        self,
        *,
        store: ControlStore,
        policy: _FlywayExecutionPolicy | None = None,
        approval: ProductionOperationApprovalEvidenceV1 | None = None,
        request: object | None = None,
        authority: CompositeProductionAuthority | None = None,
        approved_ref=None,
    ):
        policy = policy or self.policy
        return _execute_authorized_flyway_migrations(
            store,
            change_id=CHANGE_ID,
            control_decision_ref=CONTROL_REF,
            request=request or ExecuteAuthorizedFlywayMigrationsRequest("flyway-test-op"),
            policy=policy,
            authority=authority or self._authority(policy),
            approval_evidence=self.approval if approval is None else approval,
            controller_commit=self.controller_commit,
            controller_tree=self.controller_tree,
            approved_executable_ref=approved_ref or self.approved_ref,
            migration_runner=self._runner,
            start_heartbeat=False,
        )

    def _commit_source_mutation(self, mutate) -> _FlywayExecutionPolicy:
        mutate()
        head, tree = _commit(self.source_repo, "mutated source")
        return replace(self.policy, source_commit=head, source_tree=tree)

    def test_positive_path_uses_w08_and_returns_bounded_receipt_on_dcs_8_9_and_10(self):
        for version in (8, 9, 10):
            with self.subTest(version=version):
                self.runner_calls = 0
                self.runner_secrets.clear()
                with self._new_store(version) as store:
                    receipt = self._execute(
                        store=store,
                        request=ExecuteAuthorizedFlywayMigrationsRequest(f"flyway-positive-v{version}"),
                    )
                    self.assertEqual(1, self.runner_calls)
                    self.assertEqual(["synthetic-secret"], self.runner_secrets)
                    self.assertEqual(FLYWAY_OPERATION_KIND, receipt.operation_kind)
                    self.assertEqual(CLEANER_DATABASE, receipt.target_database)
                    self.assertEqual(EXPECTED_FLYWAY_VERSION, receipt.flyway_version)
                    self.assertEqual(tuple(item.version for item in FROZEN_MIGRATIONS), receipt.attempted_versions)
                    self.assertEqual(self.policy.migration_manifest_sha256, receipt.migration_manifest_sha256)
                    self.assertEqual("a" * 64, receipt.approval_evidence_sha256)
                    self.assertGreater(receipt.writer_fencing_token, 0)
                    self.assertEqual("migrate ok", receipt.stdout_sanitized_summary)

    def test_wrong_approval_operation_kind_rejects_before_process(self):
        wrong = replace(self.approval, operation_kind="TRANSITION_DATABASE_OWNER")
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "APPROVAL_OPERATION_KIND_MISMATCH"):
                self._execute(
                    store=store,
                    approval=wrong,
                    request=ExecuteAuthorizedFlywayMigrationsRequest("wrong-approval-kind"),
                )
        self.assertEqual(0, self.runner_calls)

    def test_migrate_runner_strips_environment_injection_and_uses_only_exact_argv(self):
        hostile = {
            "FLYWAY_URL": "jdbc:postgresql://attacker/other",
            "FLYWAY_JAVA_CMD": "/tmp/evil-java",
            "CLASSPATH": "/tmp/evil.jar",
            "JAVA_ARGS": "-Dflyway.configFiles=/tmp/evil.conf",
            "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/evil.jar",
            "_JAVA_OPTIONS": "-Duser.home=/tmp/evil",
            "JDK_JAVA_OPTIONS": "--class-path /tmp/evil.jar",
            "BASH_ENV": "/tmp/evil-bash-env",
            "PGPASSWORD": "attacker",
            "PGPASSFILE": "/tmp/evil-pgpass",
            "PATH": "/tmp/evil-bin",
        }
        with patch.dict(os.environ, hostile, clear=True), patch(
            "adcp.postgres_flyway.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "ok"
            run.return_value.stderr = ""
            result = _run_migrate(self.approved_ref, self.policy, "synthetic-secret")
        self.assertEqual(0, result.exit_status)
        argv = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(
            [
                str(self.executable_path),
                f"-configFiles={FLYWAY_CONFIG_PATH}",
                f"-url=jdbc:postgresql://127.0.0.1:65432/{CLEANER_DATABASE}",
                f"-user={FLYWAY_LOGIN_ROLE}",
                "migrate",
            ],
            argv,
        )
        for key in hostile:
            if key == "PATH":
                continue
            self.assertNotIn(key, env)
        self.assertEqual("/usr/bin:/bin:/usr/sbin:/sbin", env["PATH"])
        self.assertEqual("synthetic-secret", env["FLYWAY_PASSWORD"])

    def test_missing_approval_and_unsupported_dcs_reject_before_process(self):
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "APPROVAL_EVIDENCE_REQUIRED"):
                _execute_authorized_flyway_migrations(
                    store,
                    change_id=CHANGE_ID,
                    control_decision_ref=CONTROL_REF,
                    request=ExecuteAuthorizedFlywayMigrationsRequest("no-approval"),
                    policy=self.policy,
                    authority=self._authority(),
                    approval_evidence=None,
                    controller_commit=self.controller_commit,
                    controller_tree=self.controller_tree,
                    approved_executable_ref=self.approved_ref,
                    migration_runner=self._runner,
                    start_heartbeat=False,
                )
        self.assertEqual(0, self.runner_calls)
        with self._new_store(7) as store:
            with self.assertRaisesRegex(FlywayControlError, "DCS_SCHEMA_UNSUPPORTED"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("dcs7"))
        self.assertEqual(0, self.runner_calls)
        with self._new_store(10) as store:
            store.connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) "
                "VALUES(11,'0011_future','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','2026-09-12T00:00:00+00:00')"
            )
            with self.assertRaisesRegex(FlywayControlError, "DCS_SCHEMA_UNSUPPORTED"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("dcs11"))
        self.assertEqual(0, self.runner_calls)

    def test_semantic_expansion_target_version_config_callback_and_order_reject(self):
        policies = (
            replace(self.policy, target_database="arbitrary"),
            replace(self.policy, flyway_version="13.4.0"),
            replace(self.policy, flyway_config_path="other/flyway.conf"),
            replace(self.policy, callback_path="other/afterConnect.sql"),
            replace(self.policy, migrations=tuple(reversed(self.migrations))),
        )
        for index, policy in enumerate(policies):
            with self.subTest(index=index), self._new_store(9) as store:
                with self.assertRaises(FlywayControlError):
                    self._execute(
                        store=store,
                        policy=policy,
                        request=ExecuteAuthorizedFlywayMigrationsRequest(f"semantic-{index}"),
                        authority=self._authority(self.policy),
                    )
                self.assertEqual(0, self.runner_calls)

    def test_arbitrary_command_repair_clean_baseline_undo_requests_reject(self):
        @dataclass(frozen=True)
        class ForgedRequest:
            operation_id: str
            command: str

        for command in ("repair", "clean", "baseline", "undo", "info", "-configFiles=other"):
            with self.subTest(command=command), self._new_store(9) as store:
                with self.assertRaisesRegex(FlywayControlError, "PUBLIC_REQUEST_INVALID"):
                    self._execute(store=store, request=ForgedRequest(f"forged-{command}", command))
                self.assertEqual(0, self.runner_calls)

    def test_wrong_executable_version_sha_outside_root_and_symlink_reject(self):
        # Wrong protected reference version.
        self._write_executable_ref(version="13.4.0")
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "EXECUTABLE_VERSION_MISMATCH"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("wrong-version"))
        self.assertEqual(0, self.runner_calls)

        # Restore, re-freeze ref, then mutate executable bytes under the same path.
        self._write_executable_ref()
        self.approved_ref = _load_executable_ref(self.policy)
        self.executable_path.write_bytes(b"#!/bin/sh\nexit 9\n")
        os.chmod(self.executable_path, 0o700)
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "EXECUTABLE_SHA256_MISMATCH"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("wrong-sha"))
        self.assertEqual(0, self.runner_calls)

    def test_executable_outside_protected_root_rejects_without_process(self):
        outside = self.root / "outside" / "flyway"
        outside.parent.mkdir(parents=True)
        outside.write_bytes(self.executable_bytes)
        os.chmod(outside, 0o700)
        outside_marker = outside.parent / "lib" / "flyway" / f"flyway-commandline-{EXPECTED_FLYWAY_VERSION}.jar"
        outside_marker.parent.mkdir(parents=True)
        outside_marker.write_bytes(self.marker_bytes)
        os.chmod(outside_marker, 0o600)
        payload = {
            "schema_version": 1,
            "reference_kind": "FLYWAY_EXECUTABLE_REF_V1",
            "executable_path": str(outside),
            "executable_sha256": _sha(self.executable_bytes),
            "flyway_version": EXPECTED_FLYWAY_VERSION,
            "version_marker_path": str(outside_marker),
            "version_marker_sha256": _sha(self.marker_bytes),
        }
        self.executable_ref_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(self.executable_ref_path, 0o600)
        outside_policy = replace(self.policy, executable_path=outside)
        with self.assertRaisesRegex(FlywayControlError, "OUTSIDE_ROOT"):
            _load_executable_ref(outside_policy)
        self.assertEqual(0, self.runner_calls)

    def test_executable_symlink_escape_rejects_without_process(self):
        target = self.root / "outside-target"
        target.write_bytes(self.executable_bytes)
        os.chmod(target, 0o700)
        self.executable_path.unlink()
        self.executable_path.symlink_to(target)
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "PROTECTED_PATH_UNSAFE"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("symlink"))
        self.assertEqual(0, self.runner_calls)

    def test_missing_and_unsafe_credential_reject_without_process(self):
        self.credential_path.unlink()
        with self._new_store(9) as store:
            with self.assertRaises(FlywayControlError):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("cred-missing"))
        self.assertEqual(0, self.runner_calls)

        self.credential_path.write_text("synthetic-secret\n", encoding="utf-8")
        os.chmod(self.credential_path, 0o644)
        with self._new_store(9) as store:
            with self.assertRaisesRegex(FlywayControlError, "METADATA_UNSAFE|PATH_UNSAFE"):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("cred-mode"))
        self.assertEqual(0, self.runner_calls)

    def test_existing_wrong_writer_and_stale_fencing_reject_without_process(self):
        with self._new_store(9) as store:
            holder = store.acquire_global_production_writer(
                operation_key=operation_key("c3a-holder", {"n": 1}),
                owner_id="other-owner",
                owner_execution_id="other-exec",
                change_id="OTHER-CHANGE",
                slice_id="other-slice",
                writer_class="W01",
                owner_session_role="TEST_HOLDER",
                track="TEST",
                repository_or_runtime="DISPOSABLE_TEST",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
                control_decision_ref="TEST",
            )
            with self.assertRaises((ProductionControlError, StoreError)):
                self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("writer-conflict"))
            self.assertEqual(0, self.runner_calls)
            store.release_global_production_writer(
                operation_key=operation_key("c3a-holder-release", {"n": 1}),
                owner_id=holder["owner_id"],
                fencing_token=holder["fencing_token"],
                control_decision_ref="TEST",
            )

        with self._new_store(9) as store:
            with patch.object(
                store,
                "assert_current_global_writer",
                side_effect=StoreError("GLOBAL_PRODUCTION_WRITER_FENCING_MISMATCH"),
            ):
                with self.assertRaises((ProductionControlError, StoreError)):
                    self._execute(store=store, request=ExecuteAuthorizedFlywayMigrationsRequest("stale-fence"))
        self.assertEqual(0, self.runner_calls)

    def test_absent_writer_is_rejected_by_effect_authority_guard(self):
        with self._new_store(9) as store:
            with self.assertRaisesRegex(ProductionControlError, "W08_RECEIPT_AUTHORITY_MISSING"):
                _assert_current_typed_authority(
                    store,
                    self._authority(),
                    change_id=CHANGE_ID,
                    deployment_id="no-writer",
                )
        self.assertEqual(0, self.runner_calls)

    def test_source_missing_extra_hash_config_callback_commit_tree_and_order_reject(self):
        # Reordered manifest is rejected before source access.
        reordered = replace(self.policy, migrations=tuple(reversed(self.migrations)))
        with self.assertRaisesRegex(FlywayControlError, "MANIFEST_BINDING_MISMATCH"):
            _validate_frozen_source(reordered)

        # Wrong commit/tree identity is fail-closed.
        with self.assertRaises(FlywayControlError):
            _validate_frozen_source(replace(self.policy, source_commit="0" * 40))
        with self.assertRaisesRegex(FlywayControlError, "TREE_MISMATCH"):
            _validate_frozen_source(replace(self.policy, source_tree="0" * 40))

        # One migration hash mismatch from an exact new Git object.
        first_path = self.source_repo / self.migrations[0].path
        policy = self._commit_source_mutation(lambda: first_path.write_text("tampered\n", encoding="utf-8"))
        with self.assertRaisesRegex(FlywayControlError, "MIGRATION_GIT_OBJECT_HASH_MISMATCH"):
            _validate_frozen_source(policy)

    def test_source_missing_and_extra_migrations_reject(self):
        first_path = self.source_repo / self.migrations[0].path
        policy = self._commit_source_mutation(lambda: first_path.unlink())
        with self.assertRaisesRegex(FlywayControlError, "MIGRATION_SET_MISMATCH"):
            _validate_frozen_source(policy)

    def test_source_extra_migration_rejects(self):
        extra = self.source_repo / "db/v2_2_1/migration/V20260904.109__not_approved.sql"
        policy = self._commit_source_mutation(
            lambda: (extra.parent.mkdir(parents=True, exist_ok=True), extra.write_text("SELECT 1;\n", encoding="utf-8"))
        )
        with self.assertRaisesRegex(FlywayControlError, "MIGRATION_SET_MISMATCH"):
            _validate_frozen_source(policy)

    def test_wrong_flyway_config_and_callback_bytes_reject(self):
        config = self.source_repo / FLYWAY_CONFIG_PATH
        policy = self._commit_source_mutation(lambda: config.write_text("wrong=true\n", encoding="utf-8"))
        with self.assertRaisesRegex(FlywayControlError, "CONFIG_GIT_OBJECT_HASH_MISMATCH"):
            _validate_frozen_source(policy)

    def test_wrong_callback_bytes_reject(self):
        callback = self.source_repo / FLYWAY_CALLBACK_PATH
        policy = self._commit_source_mutation(lambda: callback.write_text("SELECT false;\n", encoding="utf-8"))
        with self.assertRaisesRegex(FlywayControlError, "CALLBACK_GIT_OBJECT_HASH_MISMATCH"):
            _validate_frozen_source(policy)


if __name__ == "__main__":
    unittest.main()
