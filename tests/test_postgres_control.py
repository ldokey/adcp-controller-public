from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import inspect
import json
import os
import sqlite3
from pathlib import Path
import stat
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from adcp.domain import StoreError, operation_key
from adcp.dcs_v7_v8_adoption import run_v7_to_v8_adoption
import adcp.postgres_control as postgres_control
from adcp.postgres_control import (
    ApplyRolePasswordFromProtectedFileRequest,
    ApprovedPostgresRole,
    BOOTSTRAP_SQL_PATH,
    BOOTSTRAP_SQL_SHA256,
    CANONICAL_DATA_DIRECTORY,
    CANONICAL_FLYWAY_GROUP_ROLE,
    CANONICAL_FLYWAY_LOGIN_ROLE,
    CANONICAL_HOST,
    CANONICAL_PORT,
    CANONICAL_SERVER_VERSION,
    CLEANER_DATABASE,
    CLEANER_DBA_ROLE,
    CLEANER_APP_LOGIN_ROLE,
    CLEANER_OWNER_ROLE,
    CLEANER_TARGET_SERVICE,
    CatalogReadbackOperation,
    CatalogReadbackRequest,
    _CleanerProductionPostgresPolicy,
    _CredentialKind,
    CredentialReference,
    _CredentialSpec,
    _ExecuteAuthorizedSqlFileIntent,
    _TransitionDatabaseOwnerIntent,
    _ApplyRolePasswordFromProtectedFileIntent,
    ExecuteAuthorizedSqlFileRequest,
    PasswordCredentialOperation,
    STAGE_B_LOGIN_ROLE,
    SanitizedProcessResult,
    TransitionDatabaseOwnerRequest,
    EffectSuccessReceiptFailureReconciliationRequired,
    TypedPostgresError,
    _resolve_artifact,
    _validate_credential,
    _apply_role_password_from_protected_file,
    _canonical_cleaner_postgres_policy,
    _execute_authorized_sql_file,
    _query_postgres_catalog,
    _transition_database_owner,
)
from adcp.production_control import (
    DeploymentAuthorityLost, GitSourceAuthority, GlobalProductionControlLease, ProductionControlError
)
from adcp.postgres_control import CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA, SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS
from adcp.store.sqlite import ControlStore, connect
from adcp.store.migrations import migrate
from _helpers import StoreFixture


class TypedPostgresControlTests(StoreFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        artifact = self.repo / BOOTSTRAP_SQL_PATH
        artifact.parent.mkdir(parents=True)
        self.artifact_bytes = b"-- isolated typed-postgres fixture\nSELECT 1;\n"
        artifact.write_bytes(self.artifact_bytes)
        subprocess.run(["git", "-C", str(self.repo), "add", BOOTSTRAP_SQL_PATH], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.repo), "-c", "user.name=Typed PG Fixture",
                "-c", "user.email=typed-pg@example.invalid", "commit", "-qm", "typed pg fixture",
            ],
            check=True,
        )
        self.source_head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.fixture_sha = hashlib.sha256(self.artifact_bytes).hexdigest()

        self.secret_dir = self.root / "protected-postgres-secrets"
        self.secret_dir.mkdir(mode=0o700)
        os.chmod(self.secret_dir, 0o700)
        self.dba_pgpass = self.secret_dir / "dba.pgpass"
        self.flyway_password = self.secret_dir / "flyway-password"
        self.stage_b_pgpass = self.secret_dir / "stage-b.pgpass"
        self.app_pgpass = self.secret_dir / "app.pgpass"
        self.dba_pgpass.write_text(
            f"127.0.0.1:5432:*:{CLEANER_DBA_ROLE}:dba-fixture-secret\n"
        )
        self.flyway_password.write_text("flyway-fixture-secret\n")
        self.stage_b_pgpass.write_text(
            f"127.0.0.1:5432:*:{STAGE_B_LOGIN_ROLE}:stage-b-fixture-secret\n"
        )
        self.app_pgpass.write_text(
            f"127.0.0.1:5432:{CLEANER_DATABASE}:{CLEANER_APP_LOGIN_ROLE}:cleaner-app-fixture-secret\n"
        )
        for path in (self.dba_pgpass, self.flyway_password, self.stage_b_pgpass, self.app_pgpass):
            os.chmod(path, 0o600)

        self.psql = self.root / "psql-fixture"
        self.psql.write_text("fixture executable\n")
        os.chmod(self.psql, 0o755)
        self.socket_dir = self.root / "socket"
        self.socket_dir.mkdir()
        self.data_directory = self.root / "data"
        self.data_directory.mkdir()

        self.policy = _CleanerProductionPostgresPolicy(
            source_root=self.repo,
            expected_source_head=self.source_head,
            approved_bootstrap_path=BOOTSTRAP_SQL_PATH,
            approved_bootstrap_sha256=self.fixture_sha,
            psql_path=self.psql,
            socket_dir=self.socket_dir,
            host="127.0.0.1",
            port=5432,
            data_directory=self.data_directory,
            server_version="18.6",
            server_version_num=180006,
            secret_dir=self.secret_dir,
            expected_secret_owner_uid=os.getuid(),
            credentials={
                CredentialReference.DBA_PGPASS: _CredentialSpec(
                    CredentialReference.DBA_PGPASS, self.dba_pgpass, _CredentialKind.PGPASS, CLEANER_DBA_ROLE
                ),
                CredentialReference.FLYWAY_PASSWORD: _CredentialSpec(
                    CredentialReference.FLYWAY_PASSWORD,
                    self.flyway_password,
                    _CredentialKind.RAW_PASSWORD,
                    CANONICAL_FLYWAY_LOGIN_ROLE,
                ),
                CredentialReference.STAGE_B_PGPASS: _CredentialSpec(
                    CredentialReference.STAGE_B_PGPASS,
                    self.stage_b_pgpass,
                    _CredentialKind.PGPASS,
                    STAGE_B_LOGIN_ROLE,
                ),
                CredentialReference.APP_PGPASS: _CredentialSpec(
                    CredentialReference.APP_PGPASS,
                    self.app_pgpass,
                    _CredentialKind.PGPASS,
                    CLEANER_APP_LOGIN_ROLE,
                ),
            },
        )

        # The Production-control API must be exercised with the same guarded DCS
        # behavior as the accepted W08 suite, but only against this disposable DB.
        # Receipt authority is a schema-v8 capability, so explicitly adopt the
        # accepted v7->v8 boundary before opening the typed control store.
        database_path = self.store.database_path
        self.store.close()
        adoption = connect(database_path)
        try:
            run_v7_to_v8_adoption(adoption)
        finally:
            adoption.close()
        self.store = ControlStore(
            database_path,
            clock=self.clock,
            migrate_schema=False,
            require_schema_version=CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA,
            global_writer_guard_required=True,
        )
        self.sequence = 0

    def _authority(self):
        return GitSourceAuthority(self.repo, self.source_head, require_clean=True)

    def _bootstrap_request(self, *, sha: str | None = None, database: str = CLEANER_DATABASE, role: str = CLEANER_DBA_ROLE, path: str = BOOTSTRAP_SQL_PATH, operation_id: str | None = None):
        self.sequence += 1
        return _ExecuteAuthorizedSqlFileIntent(
            target_service=CLEANER_TARGET_SERVICE,
            database=database,
            execution_role=role,
            sql_file_path=path,
            expected_sql_sha256=sha or self.fixture_sha,
            credential_reference=CredentialReference.DBA_PGPASS,
            operation_id=operation_id or f"typed-bootstrap-{self.sequence}",
        )

    def _owner_request(self, operation_id: str = "typed-owner-1"):
        return _TransitionDatabaseOwnerIntent(
            target_service=CLEANER_TARGET_SERVICE,
            database=CLEANER_DATABASE,
            expected_current_owner=CLEANER_DBA_ROLE,
            new_owner=CLEANER_OWNER_ROLE,
            operation_id=operation_id,
        )

    def _password_request(self, role=ApprovedPostgresRole.FLYWAY, *, mode=0o600, operation_id="typed-password-1"):
        ref = {
            ApprovedPostgresRole.FLYWAY: CredentialReference.FLYWAY_PASSWORD,
            ApprovedPostgresRole.STAGE_B: CredentialReference.STAGE_B_PGPASS,
            ApprovedPostgresRole.CLEANER_APP: CredentialReference.APP_PGPASS,
        }.get(role, CredentialReference.APP_PGPASS)
        return _ApplyRolePasswordFromProtectedFileIntent(
            role=role,
            credential_file_reference=ref,
            expected_file_owner_uid=os.getuid(),
            expected_file_mode=mode,
            operation_id=operation_id,
        )

    def _hold_writer(self, writer_class="W01"):
        self.sequence += 1
        return self.store.acquire_global_production_writer(
            operation_key=operation_key("typed-pg-test-holder", {"n": self.sequence}),
            owner_id=f"typed-holder-{self.sequence}",
            owner_execution_id=f"typed-holder-exec-{self.sequence}",
            change_id="TYPED-PG-TEST",
            slice_id=writer_class,
            writer_class=writer_class,
            owner_session_role="TEST_HOLDER",
            track="TEST",
            repository_or_runtime="DISPOSABLE_TEST",
            operation_class="PRODUCTION_WRITE",
            target="GLOBAL_PRODUCTION",
            control_decision_ref="TYPED/PG/TEST",
        )

    def _release_holder(self, row):
        self.sequence += 1
        self.store.release_global_production_writer(
            operation_key=operation_key("typed-pg-test-release", {"n": self.sequence}),
            owner_id=row["owner_id"],
            fencing_token=row["fencing_token"],
            control_decision_ref="TYPED/PG/TEST",
        )

    def test_w08_heartbeat_reopens_exact_adopted_v8_schema(self):
        lease = GlobalProductionControlLease(
            self.store,
            change_id="TYPED-PG-TEST",
            unit_id="typed-v8-heartbeat",
            writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
            owner_session_role="TEST",
            operation_class="CONTROLLED_PRODUCTION_DEPLOYMENT",
            target="GLOBAL_PRODUCTION",
            authority=self._authority(),
            control_decision_ref="TYPED/PG/TEST",
            start_heartbeat=False,
        )
        self.assertEqual(CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA, lease.store_schema_version)
        with lease:
            lease._heartbeat_once()
            lease.assert_current()

    def test_canonical_policy_freezes_exact_cleaner_bindings(self):
        policy = _canonical_cleaner_postgres_policy()
        self.assertEqual(BOOTSTRAP_SQL_PATH, policy.approved_bootstrap_path)
        self.assertEqual(BOOTSTRAP_SQL_SHA256, policy.approved_bootstrap_sha256)
        self.assertEqual("propertyai_flyway", CANONICAL_FLYWAY_LOGIN_ROLE)
        self.assertEqual("propertyai_migrator", CANONICAL_FLYWAY_GROUP_ROLE)
        self.assertNotEqual("propertyai_migration", CANONICAL_FLYWAY_LOGIN_ROLE)
        self.assertEqual("propertyai_stage_b_migration", STAGE_B_LOGIN_ROLE)
        self.assertEqual("propertyai_cleaner_app", CLEANER_APP_LOGIN_ROLE)
        self.assertNotEqual(CLEANER_APP_LOGIN_ROLE, ApprovedPostgresRole.APP_RUNTIME.value)
        self.assertEqual("flyway-password", policy.credentials[CredentialReference.FLYWAY_PASSWORD].path.name)
        self.assertEqual("stage-b.pgpass", policy.credentials[CredentialReference.STAGE_B_PGPASS].path.name)
        self.assertEqual("app.pgpass", policy.credentials[CredentialReference.APP_PGPASS].path.name)
        self.assertEqual(CLEANER_APP_LOGIN_ROLE, policy.credentials[CredentialReference.APP_PGPASS].role)
        self.assertNotIn(CLEANER_APP_LOGIN_ROLE, postgres_control._CANONICAL_BOOTSTRAP_ROLES)
        self.assertEqual(6, len(postgres_control._CANONICAL_BOOTSTRAP_ROLES))
        self.assertEqual("127.0.0.1", policy.host)
        self.assertEqual(5432, policy.port)
        self.assertEqual(CANONICAL_DATA_DIRECTORY, policy.data_directory)
        self.assertEqual("18.6", policy.server_version)

    def test_request_types_have_no_raw_sql_shell_argv_or_password_escape_fields(self):
        forbidden = {
            "sql", "raw_sql", "command", "shell_command", "argv", "extra_argv", "password",
            "host", "port", "socket", "socket_path", "psql", "psql_path", "executable",
            "pgpassfile", "credential_file", "database", "principal",
        }
        for request_type in (
            ExecuteAuthorizedSqlFileRequest,
            CatalogReadbackRequest,
            TransitionDatabaseOwnerRequest,
            ApplyRolePasswordFromProtectedFileRequest,
        ):
            self.assertTrue(forbidden.isdisjoint({field.name for field in fields(request_type)}))

    def test_authorized_sql_file_exact_hash_resolves(self):
        material = _resolve_artifact(self.policy, self._bootstrap_request())
        self.assertEqual(self.fixture_sha, material.sha256)
        self.assertEqual(self.artifact_bytes, material.bytes_value)

    def test_wrong_file_hash_database_and_principal_reject(self):
        with self.assertRaises(TypedPostgresError):
            _resolve_artifact(self.policy, self._bootstrap_request(path="db/v2_2_1/bootstrap/not-approved.sql"))
        with self.assertRaises(TypedPostgresError):
            _resolve_artifact(self.policy, self._bootstrap_request(sha="0" * 64))
        with self.assertRaises(TypedPostgresError):
            _resolve_artifact(self.policy, self._bootstrap_request(database="postgres"))
        with self.assertRaises(TypedPostgresError):
            _resolve_artifact(self.policy, self._bootstrap_request(role=CANONICAL_FLYWAY_LOGIN_ROLE))

    def test_symlink_artifact_substitution_rejects(self):
        artifact = self.repo / BOOTSTRAP_SQL_PATH
        substitute = self.root / "substitute.sql"
        substitute.write_bytes(self.artifact_bytes)
        artifact.unlink()
        artifact.symlink_to(substitute)
        with patch("adcp.postgres_control.assert_git_source_binding", return_value=None):
            with self.assertRaises(TypedPostgresError) as caught:
                _resolve_artifact(self.policy, self._bootstrap_request())
        self.assertIn("SYMLINK", str(caught.exception))

    def test_file_changed_after_validation_rejects_before_process_effect(self):
        request = self._bootstrap_request(operation_id="changed-after-validation")
        fresh = {"schema_owner": None, "btree_gist": False, "roles": [], "memberships": []}
        process_calls: list[bytes] = []
        import adcp.postgres_control as pc
        original = pc._revalidate_path_fingerprint
        artifact_revalidations = 0

        def mutate_on_second_artifact_check(path, expected, *, code_prefix):
            nonlocal artifact_revalidations
            if code_prefix == "POSTGRES_SQL_ARTIFACT":
                artifact_revalidations += 1
                if artifact_revalidations == 2:
                    path.write_bytes(path.read_bytes() + b"-- mutation\n")
            return original(path, expected, code_prefix=code_prefix)

        with patch("adcp.postgres_control._bootstrap_state", return_value=fresh), patch(
            "adcp.postgres_control._revalidate_path_fingerprint", side_effect=mutate_on_second_artifact_check
        ), patch(
            "adcp.postgres_control._run_psql",
            side_effect=lambda *args, **kwargs: process_calls.append(kwargs["stdin_sql"]) or SanitizedProcessResult(0, "", ""),
        ):
            with self.assertRaises(TypedPostgresError) as caught:
                _execute_authorized_sql_file(
                    self.store,
                    change_id="TYPED-PG-TEST",
                    authority=self._authority(),
                    policy=self.policy,
                    request=request,
                    start_heartbeat=False,
                )
        self.assertIn("MUTATED_AFTER_VALIDATION", str(caught.exception))
        self.assertEqual([], process_calls)

    def test_credential_file_mode_and_secret_directory_mode_fail_closed(self):
        os.chmod(self.flyway_password, 0o644)
        with self.assertRaises(TypedPostgresError) as file_mode:
            _validate_credential(self.policy, CredentialReference.FLYWAY_PASSWORD)
        self.assertIn("MODE_INVALID", str(file_mode.exception))
        os.chmod(self.flyway_password, 0o600)
        os.chmod(self.secret_dir, 0o755)
        with self.assertRaises(TypedPostgresError) as dir_mode:
            _validate_credential(self.policy, CredentialReference.FLYWAY_PASSWORD)
        self.assertIn("DIRECTORY_MODE_INVALID", str(dir_mode.exception))

    def test_typed_catalog_readback_allowed_and_unsupported_operation_rejected(self):
        expected = {"exists": True, "owner": CLEANER_DBA_ROLE}
        with patch("adcp.postgres_control._json_query", return_value=expected) as query:
            result = _query_postgres_catalog(
                self.policy, CatalogReadbackRequest(CatalogReadbackOperation.DATABASE_OWNER)
            )
        self.assertEqual(expected, result)
        self.assertIn("pg_catalog.pg_database", query.call_args.kwargs["sql"])
        bogus = CatalogReadbackRequest("SELECT * FROM pg_roles")  # type: ignore[arg-type]
        with self.assertRaises(TypedPostgresError) as caught:
            _query_postgres_catalog(self.policy, bogus)
        self.assertIn("OPERATION_UNSUPPORTED", str(caught.exception))

    def test_all_required_catalog_readback_operations_are_typed(self):
        required = {
            "DATABASE_EXISTENCE", "DATABASE_OWNER", "SCHEMA_EXISTENCE", "ROLE_EXISTENCE",
            "ROLE_ATTRIBUTES", "ROLE_MEMBERSHIPS", "FLYWAY_MIGRATION_STATE",
            "STAGE_B_ROLE_EXISTENCE", "ACTIVE_CONNECTIONS_BY_ROLE", "AUTHORITY_EPOCH_BASELINE",
            "DOMAIN_EVENT_BASELINE", "BUSINESS_SCHEDULED_ACTION_BASELINE", "INTEGRATION_OUTBOX_BASELINE",
            "SCHEMA10_PRINCIPAL_PREFLIGHT",
        }
        self.assertEqual(required, {value.value for value in CatalogReadbackOperation})

    def test_bootstrap_exact_executes_under_w08_and_persists_secret_free_receipt(self):
        fresh = {"schema_owner": None, "btree_gist": False, "roles": [], "memberships": []}
        exact = self._exact_bootstrap_state()
        states = [fresh, exact]
        with patch("adcp.postgres_control._bootstrap_state", side_effect=lambda _policy: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "CREATE ROLE\n", "")
        ) as process:
            receipt = _execute_authorized_sql_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._bootstrap_request(operation_id="bootstrap-pass"),
                control_decision_ref="TYPED/PG/TEST", start_heartbeat=False,
            )
        self.assertEqual(1, process.call_count)
        self.assertEqual("FINAL", receipt.receipt_phase)
        self.assertEqual("APPLIED", receipt.effect_status)
        self.assertEqual("TYPED-PG-TEST", receipt.change_id)
        self.assertEqual("TYPED/PG/TEST", receipt.control_decision_ref)
        rows = self.store.typed_postgres_operation_receipt_events("bootstrap-pass")
        self.assertEqual(["PREPARED", "FINAL"], [row["receipt_phase"] for row in rows])
        self.assertEqual(rows[0]["request_fingerprint"], rows[1]["request_fingerprint"])
        self.assertEqual(rows[0]["w08_fencing_token"], rows[1]["w08_fencing_token"])
        encoded = json.dumps([dict(row) for row in rows], default=str)
        self.assertNotIn("dba-fixture-secret", encoded)
        self.assertNotIn("flyway-fixture-secret", encoded)

    def _exact_bootstrap_state(self):
        return {
            "schema_owner": CLEANER_OWNER_ROLE,
            "btree_gist": True,
            "roles": [
                {
                    "role": role,
                    "can_login": role == CANONICAL_FLYWAY_LOGIN_ROLE,
                    "inherit": False, "superuser": False, "create_db": False,
                    "create_role": False, "replication": False, "bypass_rls": False,
                }
                for role in sorted([
                    CLEANER_OWNER_ROLE, CANONICAL_FLYWAY_GROUP_ROLE, CANONICAL_FLYWAY_LOGIN_ROLE,
                    "propertyai_app_runtime", "propertyai_async_worker", "propertyai_readonly",
                ])
            ],
            "memberships": [
                {"granted_role": CLEANER_OWNER_ROLE, "member_role": CANONICAL_FLYWAY_GROUP_ROLE,
                 "inherit": False, "set": True, "admin": False, "grantor_superuser": True},
                {"granted_role": CANONICAL_FLYWAY_GROUP_ROLE, "member_role": CANONICAL_FLYWAY_LOGIN_ROLE,
                 "inherit": False, "set": True, "admin": False, "grantor_superuser": True},
            ],
        }

    def test_bootstrap_already_applied_exact_is_safe_noop(self):
        exact = self._exact_bootstrap_state()
        with patch("adcp.postgres_control._bootstrap_state", return_value=exact), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            receipt = _execute_authorized_sql_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._bootstrap_request(operation_id="already-exact"),
                control_decision_ref="TYPED/PG/TEST", start_heartbeat=False,
            )
        process.assert_not_called()
        self.assertEqual("FINAL", receipt.receipt_phase)
        self.assertEqual("NOOP_EXACT", receipt.effect_status)
        rows = self.store.typed_postgres_operation_receipt_events("already-exact")
        self.assertEqual(["PREPARED", "FINAL"], [row["receipt_phase"] for row in rows])

    def test_bootstrap_partial_state_fails_closed_without_process(self):
        partial = {"schema_owner": CLEANER_OWNER_ROLE, "btree_gist": False, "roles": [], "memberships": []}
        with patch("adcp.postgres_control._bootstrap_state", return_value=partial), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            with self.assertRaises(TypedPostgresError) as caught:
                _execute_authorized_sql_file(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._bootstrap_request(operation_id="partial-reject"),
                    start_heartbeat=False,
                )
        self.assertIn("PARTIAL_STATE_REJECTED", str(caught.exception))
        process.assert_not_called()

    def test_owner_expected_before_mismatch_rejects_and_already_exact_is_noop(self):
        with patch("adcp.postgres_control._query_postgres_catalog", return_value={"exists": True, "owner": "unexpected"}), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            with self.assertRaises(TypedPostgresError) as mismatch:
                _transition_database_owner(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._owner_request("owner-mismatch"), control_decision_ref="TYPED/PG/TEST",
                    start_heartbeat=False,
                )
        self.assertIn("COMPARE_BEFORE_MISMATCH", str(mismatch.exception))
        process.assert_not_called()

        exact = {"exists": True, "owner": CLEANER_OWNER_ROLE}
        with patch("adcp.postgres_control._query_postgres_catalog", return_value=exact), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            receipt = _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._owner_request("owner-exact"), control_decision_ref="TYPED/PG/TEST",
                start_heartbeat=False,
            )
        process.assert_not_called()
        self.assertEqual("NOOP_EXACT", receipt.effect_status)
        self.assertEqual(2, len(self.store.typed_postgres_operation_receipt_events("owner-exact")))

    def test_owner_exact_transition_passes_and_post_readback_required(self):
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_OWNER_ROLE},
        ]
        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "ALTER DATABASE\n", "")
        ) as process:
            receipt = _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._owner_request("owner-transition-pass"), control_decision_ref="TYPED/PG/TEST",
                start_heartbeat=False,
            )
        self.assertEqual(1, process.call_count)
        self.assertEqual("APPLIED", receipt.effect_status)
        self.assertEqual("FINAL", receipt.receipt_phase)
        rows = self.store.typed_postgres_operation_receipt_events("owner-transition-pass")
        self.assertEqual(["PREPARED", "FINAL"], [row["receipt_phase"] for row in rows])

    def _canonical_identity_stdout(self, **overrides):
        identity = {
            "server_version": "18.6 (Homebrew)",
            "server_version_num": 180006,
            "database": CLEANER_DATABASE,
            "server_addr": "127.0.0.1",
            "server_port": 5432,
            "data_directory": str(self.data_directory),
        }
        identity.update(overrides)
        return (json.dumps(identity) + "\n").encode("utf-8")

    def test_canonical_tcp_endpoint_and_cluster_identity_are_enforced_before_effect(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((tuple(argv), kwargs["input"], dict(kwargs["env"])))
            if len(calls) == 1:
                return subprocess.CompletedProcess(argv, 0, stdout=self._canonical_identity_stdout(), stderr=b"")
            return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n", stderr=b"")

        with patch("adcp.postgres_control.subprocess.run", side_effect=fake_run):
            result = postgres_control._run_psql(
                self.policy, database=CLEANER_DATABASE, execution_role=CLEANER_DBA_ROLE, stdin_sql=b"SELECT 1;\n"
            )
        self.assertEqual(0, result.exit_status)
        self.assertEqual(2, len(calls))
        for argv, _stdin, env in calls:
            self.assertIn("--host=127.0.0.1", argv)
            self.assertIn("--port=5432", argv)
            self.assertNotIn(str(self.socket_dir), " ".join(argv))
            self.assertEqual(str(self.dba_pgpass), env["PGPASSFILE"])
            self.assertNotIn("dba-fixture-secret", " ".join(argv))

        for field, value in (
            ("server_port", 5544),
            ("database", "wrong_db"),
            ("data_directory", str(self.root / "wrong-data")),
            ("server_addr", "127.0.0.2"),
            ("server_version_num", 180005),
        ):
            with self.subTest(field=field), patch(
                "adcp.postgres_control.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [str(self.psql)], 0, stdout=self._canonical_identity_stdout(**{field: value}), stderr=b""
                ),
            ) as process:
                with self.assertRaises(TypedPostgresError) as caught:
                    postgres_control._run_psql(
                        self.policy, database=CLEANER_DATABASE, execution_role=CLEANER_DBA_ROLE, stdin_sql=b"SELECT 1;\n"
                    )
                self.assertIn("POSTGRES_CANONICAL_AUTHORITY_INVALID", str(caught.exception))
                self.assertEqual(1, process.call_count)

    def test_canonical_tcp_secret_is_redacted_from_probe_and_effect_output(self):
        calls = 0
        def fake_run(argv, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return subprocess.CompletedProcess(argv, 0, stdout=self._canonical_identity_stdout(), stderr=b"")
            leaked = b"dba-fixture-secret from hostile output\n"
            return subprocess.CompletedProcess(argv, 2, stdout=leaked, stderr=leaked)
        with patch("adcp.postgres_control.subprocess.run", side_effect=fake_run):
            result = postgres_control._run_psql(
                self.policy, database=CLEANER_DATABASE, execution_role=CLEANER_DBA_ROLE, stdin_sql=b"SELECT 1;\n"
            )
        self.assertEqual(2, result.exit_status)
        self.assertNotIn("dba-fixture-secret", result.stdout + result.stderr)
        self.assertIn("[REDACTED]", result.stdout + result.stderr)

    def test_password_application_uses_stdin_not_argv_and_receipt_is_secret_free(self):
        captured = {}
        real_subprocess_run = subprocess.run
        role_state = {"exists": True, "role": CANONICAL_FLYWAY_LOGIN_ROLE, "can_login": True, "inherit": False}

        def fake_subprocess_run(argv, **kwargs):
            if argv and argv[0] == "git":
                return real_subprocess_run(argv, **kwargs)
            if b"server_version_num" in kwargs["input"]:
                return subprocess.CompletedProcess(
                    argv, 0, stdout=self._canonical_identity_stdout(), stderr=b""
                )
            captured["argv"] = argv
            captured["input"] = kwargs["input"]
            captured["shell"] = kwargs["shell"]
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n", stderr=b"flyway-fixture-secret leaked-by-fixture\n")

        with patch("adcp.postgres_control._query_postgres_catalog", return_value=role_state), patch(
            "adcp.postgres_control.subprocess.run", side_effect=fake_subprocess_run
        ):
            receipt = _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._password_request(operation_id="flyway-password-pass"),
                control_decision_ref="TYPED/PG/TEST", start_heartbeat=False,
            )
        self.assertNotIn("flyway-fixture-secret", " ".join(captured["argv"]))
        self.assertIn(b"flyway-fixture-secret", captured["input"])
        self.assertFalse(captured["shell"])
        self.assertNotIn("flyway-fixture-secret", json.dumps(receipt.__dict__, default=str))
        rows = self.store.typed_postgres_operation_receipt_events("flyway-password-pass")
        serialized = json.dumps([dict(row) for row in rows], default=str)
        self.assertNotIn("flyway-fixture-secret", serialized)
        self.assertNotIn("dba-fixture-secret", serialized)
        db_bytes = Path(self.store.database_path).read_bytes()
        self.assertNotIn(b"flyway-fixture-secret", db_bytes)
        self.assertNotIn(b"dba-fixture-secret", db_bytes)
        self.assertEqual("APPLIED", receipt.effect_status)

    def test_stage_b_password_binding_and_wrong_credential_reject(self):
        role_state = {"exists": True, "role": STAGE_B_LOGIN_ROLE, "can_login": True}
        request = self._password_request(ApprovedPostgresRole.STAGE_B, operation_id="stage-b-password-pass")
        with patch("adcp.postgres_control._query_postgres_catalog", return_value=role_state), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            receipt = _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=request, start_heartbeat=False,
            )
        self.assertEqual(CredentialReference.STAGE_B_PGPASS.value, receipt.credential_reference)
        wrong = _ApplyRolePasswordFromProtectedFileIntent(
            role=ApprovedPostgresRole.STAGE_B,
            credential_file_reference=CredentialReference.FLYWAY_PASSWORD,
            expected_file_owner_uid=os.getuid(), expected_file_mode=0o600, operation_id="stage-b-wrong-ref",
        )
        with self.assertRaises(TypedPostgresError):
            _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=wrong, start_heartbeat=False,
            )

    def test_cleaner_app_sealed_public_mapping_is_exact_and_authority_free(self):
        store = object()
        authority = object()
        with patch(
            "adcp.postgres_control._resolve_public_operation_approval", return_value=None
        ) as approval, patch(
            "adcp.postgres_control._canonical_typed_postgres_control_store"
        ) as store_open, patch(
            "adcp.postgres_control._canonical_typed_postgres_source_authority", return_value=authority
        ), patch(
            "adcp.postgres_control._apply_role_password_from_protected_file", return_value="SEALED"
        ) as internal:
            store_open.return_value.__enter__.return_value = store
            result = postgres_control.apply_role_password_from_protected_file(
                change_id="TK-43",
                request=ApplyRolePasswordFromProtectedFileRequest(
                    PasswordCredentialOperation.CLEANER_APP, "cleaner-app-sealed"
                ),
                control_decision_ref="DL-73",
                gate_or_control_id="DL-51",
            )
        self.assertEqual("SEALED", result)
        approval.assert_called_once_with(
            change_id="TK-43",
            gate_or_control_id="DL-51",
            control_decision_ref="DL-73",
            operation_kind="APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",
            authorized_effect_scope=("APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",),
            entrypoint="apply_role_password_from_protected_file",
            target_identity={
                "database": CLEANER_DATABASE,
                "role": CLEANER_APP_LOGIN_ROLE,
                "credential_reference": CredentialReference.APP_PGPASS.value,
            },
            operation_artifact_identity=None,
        )
        intent = internal.call_args.kwargs["request"]
        self.assertIs(ApprovedPostgresRole.CLEANER_APP, intent.role)
        self.assertIs(CredentialReference.APP_PGPASS, intent.credential_file_reference)
        self.assertEqual("cleaner-app-sealed", intent.operation_id)
        self.assertEqual(0o600, intent.expected_file_mode)
        self.assertIs(store, internal.call_args.args[0])
        self.assertIs(authority, internal.call_args.kwargs["authority"])

    def test_cleaner_app_public_approval_failures_stop_before_store_or_effect(self):
        rejection_codes = (
            "TYPED_POSTGRES_APPROVAL_BINDING_MISMATCH_TARGET",
            "TYPED_POSTGRES_APPROVAL_BINDING_MISMATCH_OPERATION",
            "TYPED_POSTGRES_APPROVAL_EVIDENCE_NOT_FOUND",
            "TYPED_POSTGRES_APPROVAL_EVIDENCE_EXPIRED",
            "TYPED_POSTGRES_APPROVAL_EVIDENCE_NOT_ACTIVE",
        )
        for code in rejection_codes:
            with self.subTest(code=code), patch(
                "adcp.postgres_control._resolve_public_operation_approval",
                side_effect=TypedPostgresError(code),
            ), patch(
                "adcp.postgres_control._canonical_typed_postgres_control_store"
            ) as store_open, patch(
                "adcp.postgres_control._apply_role_password_from_protected_file"
            ) as internal:
                with self.assertRaisesRegex(TypedPostgresError, code):
                    postgres_control.apply_role_password_from_protected_file(
                        change_id="TK-43",
                        request=ApplyRolePasswordFromProtectedFileRequest(
                            PasswordCredentialOperation.CLEANER_APP, f"approval-reject-{code[-8:]}"
                        ),
                        control_decision_ref="DL-73",
                        gate_or_control_id="DL-51",
                    )
                store_open.assert_not_called()
                internal.assert_not_called()

    def test_cleaner_app_wrong_role_credential_and_operation_reject(self):
        wrong_reference = _ApplyRolePasswordFromProtectedFileIntent(
            role=ApprovedPostgresRole.CLEANER_APP,
            credential_file_reference=CredentialReference.STAGE_B_PGPASS,
            expected_file_owner_uid=os.getuid(),
            expected_file_mode=0o600,
            operation_id="cleaner-app-wrong-ref",
        )
        with self.assertRaisesRegex(TypedPostgresError, "CREDENTIAL_BINDING_MISMATCH"):
            _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=wrong_reference, start_heartbeat=False,
            )
        wrong_role = _ApplyRolePasswordFromProtectedFileIntent(
            role=ApprovedPostgresRole.APP_RUNTIME,
            credential_file_reference=CredentialReference.APP_PGPASS,
            expected_file_owner_uid=os.getuid(),
            expected_file_mode=0o600,
            operation_id="cleaner-app-wrong-role",
        )
        with self.assertRaisesRegex(TypedPostgresError, "ROLE_NOT_APPROVED"):
            _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=wrong_role, start_heartbeat=False,
            )
        invalid_operation = ApplyRolePasswordFromProtectedFileRequest(
            "APPLY_ARBITRARY_PASSWORD", "cleaner-app-wrong-operation"  # type: ignore[arg-type]
        )
        with patch("adcp.postgres_control._resolve_public_operation_approval") as approval, patch(
            "adcp.postgres_control._canonical_typed_postgres_control_store"
        ) as store_open:
            with self.assertRaisesRegex(TypedPostgresError, "OPERATION_NOT_APPROVED"):
                postgres_control.apply_role_password_from_protected_file(
                    change_id="TK-43", request=invalid_operation,
                    control_decision_ref="DL-73", gate_or_control_id="DL-51",
                )
            approval.assert_not_called()
            store_open.assert_not_called()

    def test_cleaner_app_credential_file_owner_mode_path_and_symlink_fail_closed(self):
        os.chmod(self.app_pgpass, 0o644)
        with self.assertRaisesRegex(TypedPostgresError, "FILE_MODE_INVALID"):
            _validate_credential(self.policy, CredentialReference.APP_PGPASS)
        os.chmod(self.app_pgpass, 0o600)

        real_stat = self.app_pgpass.lstat()
        fake_stat = SimpleNamespace(st_uid=os.getuid() + 1, st_mode=real_stat.st_mode)
        with patch("adcp.postgres_control._ensure_plain_file_no_symlink", return_value=fake_stat):
            with self.assertRaisesRegex(TypedPostgresError, "FILE_OWNER_INVALID"):
                _validate_credential(self.policy, CredentialReference.APP_PGPASS)

        outside = self.root / "outside-app.pgpass"
        outside.write_text("not-authorized\n")
        os.chmod(outside, 0o600)
        bad_policy = replace(
            self.policy,
            credentials={
                **self.policy.credentials,
                CredentialReference.APP_PGPASS: _CredentialSpec(
                    CredentialReference.APP_PGPASS, outside, _CredentialKind.PGPASS, CLEANER_APP_LOGIN_ROLE
                ),
            },
        )
        with self.assertRaisesRegex(TypedPostgresError, "PATH_POLICY_INVALID"):
            _validate_credential(bad_policy, CredentialReference.APP_PGPASS)

        target = self.secret_dir / "app-target.pgpass"
        target.write_text(self.app_pgpass.read_text())
        os.chmod(target, 0o600)
        self.app_pgpass.unlink()
        self.app_pgpass.symlink_to(target)
        with self.assertRaisesRegex(TypedPostgresError, "SYMLINK"):
            _validate_credential(self.policy, CredentialReference.APP_PGPASS)

    def test_cleaner_app_password_secret_free_prepared_before_effect_and_conflicting_replay_rejects(self):
        captured = {"effects": 0}
        real_subprocess_run = subprocess.run
        role_state = {"exists": True, "role": CLEANER_APP_LOGIN_ROLE, "can_login": True, "inherit": True}

        def fake_subprocess_run(argv, **kwargs):
            if argv and argv[0] == "git":
                return real_subprocess_run(argv, **kwargs)
            if b"server_version_num" in kwargs["input"]:
                return subprocess.CompletedProcess(
                    argv, 0, stdout=self._canonical_identity_stdout(), stderr=b""
                )
            captured["effects"] += 1
            captured["argv"] = argv
            captured["input"] = kwargs["input"]
            rows = self.store.typed_postgres_operation_receipt_events("cleaner-app-secret-pass")
            self.assertEqual(["PREPARED"], [row["receipt_phase"] for row in rows])
            return subprocess.CompletedProcess(
                argv, 0,
                stdout=b"cleaner-app-fixture-secret hostile stdout\n",
                stderr=b"cleaner-app-fixture-secret hostile stderr\n",
            )

        request = self._password_request(
            ApprovedPostgresRole.CLEANER_APP, operation_id="cleaner-app-secret-pass"
        )
        with patch("adcp.postgres_control._query_postgres_catalog", return_value=role_state), patch(
            "adcp.postgres_control.subprocess.run", side_effect=fake_subprocess_run
        ):
            receipt = _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=request, control_decision_ref="TYPED/PG/TEST", start_heartbeat=False,
            )
        self.assertEqual(1, captured["effects"])
        self.assertNotIn("cleaner-app-fixture-secret", " ".join(captured["argv"]))
        self.assertIn(b"cleaner-app-fixture-secret", captured["input"])
        self.assertEqual(CredentialReference.APP_PGPASS.value, receipt.credential_reference)
        self.assertNotIn("cleaner-app-fixture-secret", json.dumps(receipt.__dict__, default=str))
        serialized = json.dumps(
            [dict(row) for row in self.store.typed_postgres_operation_receipt_events("cleaner-app-secret-pass")],
            default=str,
        )
        self.assertNotIn("cleaner-app-fixture-secret", serialized)
        self.assertNotIn(b"cleaner-app-fixture-secret", Path(self.store.database_path).read_bytes())
        self.assertEqual(["PREPARED", "FINAL"], [
            row["receipt_phase"]
            for row in self.store.typed_postgres_operation_receipt_events("cleaner-app-secret-pass")
        ])

        with patch("adcp.postgres_control._run_psql") as process:
            with self.assertRaisesRegex(TypedPostgresError, "OPERATION_REQUEST_CONFLICT"):
                _apply_role_password_from_protected_file(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=request, control_decision_ref="TYPED/PG/DIFFERENT", start_heartbeat=False,
                )
            process.assert_not_called()

    def test_password_expected_mode_not_0600_rejects(self):
        with self.assertRaises(TypedPostgresError) as caught:
            _apply_role_password_from_protected_file(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._password_request(mode=0o644, operation_id="password-mode-reject"), start_heartbeat=False,
            )
        self.assertIn("EXPECTATION_NOT_APPROVED", str(caught.exception))

    def test_no_w08_available_rejects_before_bootstrap_effect(self):
        holder = self._hold_writer("W01")
        try:
            with patch("adcp.postgres_control._run_psql") as process:
                with self.assertRaises(StoreError) as caught:
                    _execute_authorized_sql_file(
                        self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                        request=self._bootstrap_request(operation_id="no-w08"),
                        start_heartbeat=False,
                    )
                self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", caught.exception.code)
                process.assert_not_called()
        finally:
            self._release_holder(holder)

    def test_stale_w08_fencing_token_rejects_before_effect(self):
        real_assert = self.store.assert_current_global_writer
        calls = 0

        def stale_after_acquire(owner_id, fencing_token):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise StoreError("STALE_FENCING_TOKEN")
            return real_assert(owner_id, fencing_token)

        with patch.object(
            self.store, "assert_current_global_writer", side_effect=stale_after_acquire
        ), patch("adcp.postgres_control._run_psql") as process:
            with self.assertRaises(ProductionControlError) as caught:
                _execute_authorized_sql_file(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._bootstrap_request(operation_id="stale-fencing-token"), start_heartbeat=False,
                )
        self.assertEqual("STALE_FENCING_TOKEN", caught.exception.code)
        process.assert_not_called()

    def test_authority_lost_before_effect_rejects_without_process(self):
        calls = 0

        def stale_binding(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls >= 3:
                raise ProductionControlError("SOURCE_AUTHORITY_STALE")

        with patch("adcp.production_control.assert_git_source_binding", side_effect=stale_binding), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            with self.assertRaises(ProductionControlError):
                _execute_authorized_sql_file(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._bootstrap_request(operation_id="authority-lost-before"),
                    start_heartbeat=False,
                )
        process.assert_not_called()

    def test_effect_success_final_receipt_failure_requires_reconciliation_and_retry_never_reexecutes(self):
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_OWNER_ROLE},
        ]
        real_append = self.store.append_typed_postgres_operation_receipt_event
        effect_count = 0

        def append_with_final_failure(**kwargs):
            if kwargs["receipt_phase"] == "FINAL":
                raise StoreError("TEST_FINAL_RECEIPT_WRITE_FAILED")
            return real_append(**kwargs)

        def effect_once(*args, **kwargs):
            nonlocal effect_count
            effect_count += 1
            return SanitizedProcessResult(0, "ALTER DATABASE\n", "")

        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", side_effect=effect_once
        ), patch.object(
            self.store, "append_typed_postgres_operation_receipt_event", side_effect=append_with_final_failure
        ):
            with self.assertRaises(EffectSuccessReceiptFailureReconciliationRequired) as caught:
                _transition_database_owner(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._owner_request("owner-final-failure"), control_decision_ref="TYPED/PG/TEST",
                    start_heartbeat=False,
                )
        self.assertEqual(1, effect_count)
        self.assertTrue(caught.exception.metadata["effect_confirmed"])
        self.assertEqual("TEST_FINAL_RECEIPT_WRITE_FAILED", caught.exception.metadata["receipt_durability_failure"])
        rows = self.store.typed_postgres_operation_receipt_events("owner-final-failure")
        self.assertEqual(["PREPARED"], [row["receipt_phase"] for row in rows])
        path = self.store.database_path
        self.store.close()
        self.store = ControlStore(path, migrate_schema=False, require_schema_version=CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA, clock=self.clock)
        rows = self.store.typed_postgres_operation_receipt_events("owner-final-failure")
        self.assertEqual(["PREPARED"], [row["receipt_phase"] for row in rows])

        with patch("adcp.postgres_control._run_psql", side_effect=effect_once):
            with self.assertRaises(TypedPostgresError) as retry:
                _transition_database_owner(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._owner_request("owner-final-failure"), control_decision_ref="TYPED/PG/TEST",
                    start_heartbeat=False,
                )
        self.assertIn("CONTROLLED_DEPLOYMENT_RECONCILIATION_REQUIRED", str(retry.exception))
        self.assertEqual(1, effect_count)

    def test_nonzero_effect_fails_with_factual_state_and_no_success_receipt(self):
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_DBA_ROLE},
        ]
        receipts = []
        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(2, "", "typed failure")
        ):
            with self.assertRaises(TypedPostgresError) as caught:
                _transition_database_owner(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._owner_request("owner-effect-fail"),
                    start_heartbeat=False,
                )
        self.assertIn("EFFECT_FAILED_WITH_FACTUAL_STATE", str(caught.exception))
        self.assertEqual([], receipts)


    def test_prepared_write_failure_executes_no_database_effect(self):
        with patch.object(
            self.store, "append_typed_postgres_operation_receipt_event", side_effect=StoreError("TEST_PREPARED_WRITE_FAILED")
        ), patch("adcp.postgres_control._query_postgres_catalog", return_value={"exists": True, "owner": CLEANER_DBA_ROLE}), patch(
            "adcp.postgres_control._run_psql"
        ) as process:
            with self.assertRaises(TypedPostgresError) as caught:
                _transition_database_owner(
                    self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                    request=self._owner_request("prepared-write-fail"), control_decision_ref="TYPED/PG/TEST",
                    start_heartbeat=False,
                )
        self.assertIn("PRE_EFFECT_RECEIPT_DURABILITY_FAILED", str(caught.exception))
        process.assert_not_called()
        self.assertEqual([], self.store.typed_postgres_operation_receipt_events("prepared-write-fail"))

    def test_prepared_and_final_commits_survive_controlstore_reopen(self):
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_OWNER_ROLE},
        ]
        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._owner_request("durability-reopen"), control_decision_ref="TYPED/PG/TEST",
                start_heartbeat=False,
            )
        path = self.store.database_path
        self.store.close()
        self.store = ControlStore(path, migrate_schema=False, require_schema_version=CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA, clock=self.clock)
        rows = self.store.typed_postgres_operation_receipt_events("durability-reopen")
        self.assertEqual(["PREPARED", "FINAL"], [row["receipt_phase"] for row in rows])
        self.assertEqual("APPLIED", rows[-1]["effect_status"])

    def test_operation_id_conflicting_request_fingerprint_fails_closed(self):
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_OWNER_ROLE},
        ]
        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._owner_request("fingerprint-conflict"), control_decision_ref="TYPED/PG/TEST",
                start_heartbeat=False,
            )
        conflicting = self._owner_request("fingerprint-conflict")
        with self.assertRaises(TypedPostgresError) as caught:
            _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=conflicting, control_decision_ref="TYPED/PG/DIFFERENT", start_heartbeat=False,
            )
        self.assertIn("OPERATION_REQUEST_CONFLICT", str(caught.exception))

    def test_receipt_events_are_append_only_and_state_api_is_typed(self):
        absent = self.store.typed_postgres_operation_receipt_state("immutable-receipt", "a" * 64)
        self.assertEqual("ABSENT", absent["state"])
        states = [
            {"exists": True, "owner": CLEANER_DBA_ROLE},
            {"exists": True, "owner": CLEANER_OWNER_ROLE},
        ]
        with patch("adcp.postgres_control._query_postgres_catalog", side_effect=lambda *args, **kwargs: states.pop(0)), patch(
            "adcp.postgres_control._run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            receipt = _transition_database_owner(
                self.store, change_id="TYPED-PG-TEST", authority=self._authority(), policy=self.policy,
                request=self._owner_request("immutable-receipt"), control_decision_ref="TYPED/PG/TEST",
                start_heartbeat=False,
            )
        typed = self.store.typed_postgres_operation_receipt_state(
            "immutable-receipt", receipt.request_fingerprint
        )
        self.assertEqual("FINAL", typed["state"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "UPDATE typed_postgres_operation_receipt_event SET effect_status='PENDING' WHERE operation_id=? AND receipt_phase='FINAL'",
                ("immutable-receipt",),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "DELETE FROM typed_postgres_operation_receipt_event WHERE operation_id=?",
                ("immutable-receipt",),
            )

    def test_typed_pg_canonical_store_accepts_only_exact_v8_v9_v10_without_migration(self):
        self.assertEqual(frozenset({8, 9, 10}), SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS)
        for version in (8, 9, 10):
            path = self.root / f"schema-{version}.sqlite3"
            connection = connect(path)
            try:
                migrate(connection, target_version=version)
            finally:
                connection.close()
            verify = sqlite3.connect(path)
            try:
                before = verify.execute(
                    "SELECT version,name,checksum FROM schema_migration ORDER BY version"
                ).fetchall()
            finally:
                verify.close()
            with patch("adcp.postgres_control.CANONICAL_PRODUCTION_CONTROL_STORE", path), patch(
                "adcp.postgres_control.ControlStore", wraps=ControlStore
            ) as store_class:
                with postgres_control._canonical_typed_postgres_control_store() as opened:
                    current = opened.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
                    self.assertEqual(version, current)
                self.assertFalse(store_class.call_args.kwargs["migrate_schema"])
                self.assertEqual(version, store_class.call_args.kwargs["require_schema_version"])
            verify = sqlite3.connect(path)
            try:
                after = verify.execute(
                    "SELECT version,name,checksum FROM schema_migration ORDER BY version"
                ).fetchall()
            finally:
                verify.close()
            self.assertEqual(before, after)

        for version in (7, 11):
            path = self.root / f"schema-{version}.sqlite3"
            connection = connect(path)
            try:
                migrate(connection, target_version=7 if version == 7 else 10)
                if version == 11:
                    connection.execute(
                        "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES (11,'unknown','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','2026-09-12T00:00:00+00:00')"
                    )
            finally:
                connection.close()
            with patch("adcp.postgres_control.CANONICAL_PRODUCTION_CONTROL_STORE", path):
                with self.assertRaisesRegex(TypedPostgresError, "SCHEMA_UNSUPPORTED"):
                    postgres_control._canonical_typed_postgres_control_store()

        incompatible = self.root / "schema-10-incompatible.sqlite3"
        connection = connect(incompatible)
        try:
            migrate(connection, target_version=10)
            connection.execute("DROP TRIGGER typed_postgres_operation_receipt_event_immutable_delete")
        finally:
            connection.close()
        with patch("adcp.postgres_control.CANONICAL_PRODUCTION_CONTROL_STORE", incompatible):
            with self.assertRaisesRegex(TypedPostgresError, "SCHEMA_PROFILE_INVALID"):
                postgres_control._canonical_typed_postgres_control_store()

    def test_provision_principal_operation_is_publicly_exposed_in_successor2(self):
        self.assertIn(
            "PROVISION_CLEANER_APP_PRINCIPAL",
            {item.value for item in postgres_control.TypedOperationType},
        )
        self.assertTrue(hasattr(postgres_control, "provision_cleaner_app_principal"))
        self.assertTrue(hasattr(postgres_control, "ProvisionCleanerAppPrincipalRequest"))

    def test_public_api_requires_resolved_approval_before_store_or_postgres_access(self):
        requests = (
            (postgres_control.provision_cleaner_app_principal, {
                "change_id": "TYPED-PG-TEST", "request": postgres_control.ProvisionCleanerAppPrincipalRequest("approval-first-principal"),
                "control_decision_ref": "missing", "gate_or_control_id": "TEST-GATE",
            }),
            (postgres_control.execute_authorized_sql_file, {
                "change_id": "TYPED-PG-TEST", "request": ExecuteAuthorizedSqlFileRequest("approval-first-bootstrap"),
                "control_decision_ref": "missing", "gate_or_control_id": "TEST-GATE",
            }),
            (postgres_control.transition_database_owner, {
                "change_id": "TYPED-PG-TEST", "request": TransitionDatabaseOwnerRequest("approval-first-owner"),
                "control_decision_ref": "missing", "gate_or_control_id": "TEST-GATE",
            }),
            (postgres_control.apply_role_password_from_protected_file, {
                "change_id": "TYPED-PG-TEST",
                "request": ApplyRolePasswordFromProtectedFileRequest(PasswordCredentialOperation.FLYWAY, "approval-first-password"),
                "control_decision_ref": "missing", "gate_or_control_id": "TEST-GATE",
            }),
        )
        for function, kwargs in requests:
            with self.subTest(function=function.__name__), patch(
                "adcp.postgres_control._resolve_public_operation_approval",
                side_effect=TypedPostgresError("TYPED_POSTGRES_APPROVAL_EVIDENCE_NOT_FOUND"),
            ), patch("adcp.postgres_control._canonical_typed_postgres_control_store") as store_open:
                with self.assertRaisesRegex(TypedPostgresError, "APPROVAL_EVIDENCE_NOT_FOUND"):
                    function(**kwargs)
                store_open.assert_not_called()

        with patch(
            "adcp.postgres_control._resolve_public_operation_approval",
            side_effect=TypedPostgresError("TYPED_POSTGRES_APPROVAL_EVIDENCE_NOT_FOUND"),
        ), patch("adcp.postgres_control._query_postgres_catalog") as query:
            with self.assertRaisesRegex(TypedPostgresError, "APPROVAL_EVIDENCE_NOT_FOUND"):
                postgres_control.query_postgres_catalog(
                    CatalogReadbackRequest(CatalogReadbackOperation.DATABASE_EXISTENCE),
                    change_id="TYPED-PG-TEST", gate_or_control_id="TEST-GATE",
                    control_decision_ref="missing",
                )
            query.assert_not_called()

    def test_public_production_api_has_no_policy_receipt_or_fake_executor_injection(self):
        public = {
            "provision_cleaner_app_principal": postgres_control.provision_cleaner_app_principal,
            "query_postgres_catalog": postgres_control.query_postgres_catalog,
            "execute_authorized_sql_file": postgres_control.execute_authorized_sql_file,
            "transition_database_owner": postgres_control.transition_database_owner,
            "apply_role_password_from_protected_file": postgres_control.apply_role_password_from_protected_file,
        }
        forbidden_parameters = {
            "policy", "persist_receipt", "receipt_sink", "store", "authority",
            "psql", "psql_path", "source_root", "bootstrap_path", "bootstrap_sha256",
            "secret_root", "secret_dir", "credentials", "target_service", "database",
            "principal", "execution_role", "role", "host", "port", "socket", "socket_path",
            "pgpassfile", "credential_file", "executable",
        }
        for name, function in public.items():
            parameters = inspect.signature(function).parameters
            self.assertTrue(forbidden_parameters.isdisjoint(parameters), (name, parameters))
        self.assertEqual(
            ["request", "change_id", "gate_or_control_id", "control_decision_ref"],
            list(inspect.signature(postgres_control.query_postgres_catalog).parameters),
        )

        self.assertEqual({"operation_id"}, {field.name for field in fields(ExecuteAuthorizedSqlFileRequest)})
        self.assertEqual({"operation_id"}, {field.name for field in fields(TransitionDatabaseOwnerRequest)})
        self.assertEqual(
            {"operation", "operation_id"},
            {field.name for field in fields(ApplyRolePasswordFromProtectedFileRequest)},
        )
        self.assertEqual(
            {"APPLY_FLYWAY_PASSWORD", "APPLY_STAGE_B_PASSWORD", "APPLY_CLEANER_APP_PASSWORD", "APPLY_CLEANER_WORKER_PASSWORD"},
            {item.value for item in PasswordCredentialOperation},
        )
        self.assertNotIn("_CleanerProductionPostgresPolicy", postgres_control.__all__)
        self.assertNotIn("_canonical_cleaner_postgres_policy", postgres_control.__all__)
        self.assertNotIn("_ExecuteAuthorizedSqlFileIntent", postgres_control.__all__)
        self.assertNotIn("_TransitionDatabaseOwnerIntent", postgres_control.__all__)
        self.assertNotIn("_ApplyRolePasswordFromProtectedFileIntent", postgres_control.__all__)

        invoked_marker = self.root / "fake-executable-invoked"
        fake_executable = self.root / "not-psql"
        fake_executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' '{\"exists\":true}'\nprintf invoked > "
            + str(invoked_marker) + "\n",
            encoding="utf-8",
        )
        fake_executable.chmod(0o700)
        fake_policy = self.policy.__class__(
            source_root=self.policy.source_root,
            expected_source_head=self.policy.expected_source_head,
            approved_bootstrap_path=self.policy.approved_bootstrap_path,
            approved_bootstrap_sha256=self.policy.approved_bootstrap_sha256,
            psql_path=fake_executable,
            socket_dir=self.policy.socket_dir,
            host=self.policy.host,
            port=self.policy.port,
            data_directory=self.policy.data_directory,
            server_version=self.policy.server_version,
            server_version_num=self.policy.server_version_num,
            secret_dir=self.policy.secret_dir,
            expected_secret_owner_uid=self.policy.expected_secret_owner_uid,
            credentials=self.policy.credentials,
        )
        accepted_fake_json = False
        with patch("adcp.postgres_control._canonical_cleaner_postgres_policy", return_value=fake_policy), patch(
            "adcp.postgres_control._resolve_public_operation_approval", return_value=None
        ):
            try:
                postgres_control.query_postgres_catalog(
                    CatalogReadbackRequest(CatalogReadbackOperation.DATABASE_EXISTENCE),
                    change_id="TYPED-PG-TEST", gate_or_control_id="TEST-GATE",
                    control_decision_ref="TYPED/PG/TEST",
                )
                accepted_fake_json = True
            except TypedPostgresError as caught:
                self.assertIn("CANONICAL_AUTHORITY_INVALID", str(caught))
        self.assertFalse(invoked_marker.exists(), "FAKE_EXECUTABLE_INVOKED")
        self.assertFalse(accepted_fake_json, "FAKE_JSON_ACCEPTED")

        with self.assertRaises(TypeError):
            postgres_control.query_postgres_catalog(
                fake_policy, CatalogReadbackRequest(CatalogReadbackOperation.DATABASE_EXISTENCE)
            )

        safe_requests = (
            (postgres_control.execute_authorized_sql_file, ExecuteAuthorizedSqlFileRequest("public-bootstrap")),
            (postgres_control.transition_database_owner, TransitionDatabaseOwnerRequest("public-owner")),
            (
                postgres_control.apply_role_password_from_protected_file,
                ApplyRolePasswordFromProtectedFileRequest(
                    PasswordCredentialOperation.FLYWAY, "public-password"
                ),
            ),
        )
        for function, request in safe_requests:
            # Unexpected authority/sink knobs fail at Python's public call boundary,
            # before canonical store/source resolution or any process execution.
            with self.assertRaises(TypeError):
                function(
                    change_id="TYPED-PG-TEST", request=request,
                    control_decision_ref="TYPED/PG/TEST", policy=fake_policy,
                )
            with self.assertRaises(TypeError):
                function(
                    change_id="TYPED-PG-TEST", request=request,
                    control_decision_ref="TYPED/PG/TEST", persist_receipt=lambda _value: None,
                )
            with self.assertRaises(TypeError):
                function(
                    change_id="TYPED-PG-TEST", request=request,
                    control_decision_ref="TYPED/PG/TEST", store=self.store,
                )
            with self.assertRaises(TypeError):
                function(
                    change_id="TYPED-PG-TEST", request=request,
                    control_decision_ref="TYPED/PG/TEST", authority=self._authority(),
                )



    def _schema(self, version=10):
        migrate(self.store.connection, target_version=version)

    def _call(self, operation_id="s2-principal"):
        return postgres_control._provision_cleaner_app_principal(
            self.store, change_id="TYPED-PG-TEST", authority=self._authority(),
            policy=self.policy,
            request=postgres_control.ProvisionCleanerAppPrincipalRequest(operation_id),
            control_decision_ref="TYPED/PG/TEST", start_heartbeat=False,
        )

    def test_sealed_request_and_approval_binding(self):
        request_type = postgres_control.ProvisionCleanerAppPrincipalRequest
        self.assertEqual({"operation_id"}, {f.name for f in fields(request_type)})
        for field in ("role", "database", "membership", "sql", "password", "granted_role", "member_role"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                request_type(operation_id="s2", **{field: "untrusted"})
        with patch.object(postgres_control, "_resolve_public_operation_approval") as approval, patch.object(
            postgres_control, "_canonical_typed_postgres_control_store", side_effect=RuntimeError("fixture stop")
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture stop"):
                postgres_control.provision_cleaner_app_principal(
                    change_id="TK-43", request=request_type("s2"),
                    control_decision_ref="DL-35", gate_or_control_id="DL-35",
                )
        binding = approval.call_args.kwargs
        self.assertEqual("PROVISION_CLEANER_APP_PRINCIPAL", binding["operation_kind"])
        self.assertEqual("propertyai_cleaner_prod", binding["target_identity"]["database"])
        self.assertEqual("propertyai_cleaner_app", binding["target_identity"]["principal"]["role"])
        self.assertNotIn("password", json.dumps(binding).lower())
        self.assertEqual(postgres_control._cleaner_principal_expected_state()["memberships"], binding["target_identity"]["memberships"])

    def test_state_machine_exact_and_fail_closed_matrix(self):
        import copy
        expected = postgres_control._cleaner_principal_expected_state()
        self.assertEqual("NOOP_EXACT", postgres_control._validate_cleaner_principal_state(expected, final=True))
        missing = copy.deepcopy(expected)
        missing["memberships"] = []
        self.assertEqual("COMPLETE_MEMBERSHIP", postgres_control._validate_cleaner_principal_state(missing))
        missing["principal"] = None
        self.assertEqual("CREATE_EXACT", postgres_control._validate_cleaner_principal_state(missing))
        cases = []
        for key in expected["principal"]:
            bad = copy.deepcopy(expected)
            bad["principal"][key] = "wrong" if key == "role" else not bad["principal"][key]
            cases.append(("principal-" + key, bad))
        for key in expected["app_runtime"]:
            bad = copy.deepcopy(expected)
            bad["app_runtime"][key] = "wrong" if key == "role" else not bad["app_runtime"][key]
            cases.append(("runtime-" + key, bad))
        bad = copy.deepcopy(expected); bad["app_runtime"] = None; cases.append(("runtime-absent", bad))
        for key in expected["memberships"][0]:
            bad = copy.deepcopy(expected)
            value = bad["memberships"][0][key]
            bad["memberships"][0][key] = not value if isinstance(value, bool) else "wrong"
            cases.append(("membership-" + key, bad))
        bad = copy.deepcopy(expected); bad["memberships"] *= 2; cases.append(("extra-membership", bad))
        for name, state in cases:
            with self.subTest(name=name), self.assertRaises(TypedPostgresError):
                postgres_control._validate_cleaner_principal_state(state)
        with self.assertRaises(TypedPostgresError):
            postgres_control._validate_cleaner_principal_state(missing, final=True)

    def test_schema_rejection_precedes_w08_receipt_and_pg(self):
        for version in (8, 9, 11):
            if version == 9:
                self._schema(9)
            elif version == 11:
                self.store.connection.execute("INSERT INTO schema_migration VALUES (11,'fixture','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','now')")
            with self.subTest(version=version), patch.object(postgres_control, "run_controlled_deployment") as w08, patch.object(
                postgres_control, "_cleaner_principal_state"
            ) as pg, patch.object(postgres_control, "_persist_prepared_receipt") as prepared:
                with self.assertRaisesRegex(TypedPostgresError, "REQUIRES_SCHEMA_10"):
                    self._call()
                w08.assert_not_called(); pg.assert_not_called(); prepared.assert_not_called()

    def test_prepared_effect_final_and_noop_membership_completion(self):
        import copy
        self._schema()
        expected = postgres_control._cleaner_principal_expected_state()
        for mode in ("absent", "membership-missing", "exact"):
            before = copy.deepcopy(expected)
            if mode != "exact": before["memberships"] = []
            if mode == "absent": before["principal"] = None
            operation_id = "s2-" + mode
            def effect(*args, **kwargs):
                events = self.store.typed_postgres_operation_receipt_events(operation_id)
                self.assertEqual(["PREPARED"], [e["receipt_phase"] for e in events])
                sql = kwargs["stdin_sql"].decode()
                self.assertEqual(mode == "absent", "CREATE ROLE" in sql)
                self.assertEqual(mode != "exact", "GRANT propertyai_app_runtime" in sql)
                for forbidden in ("ALTER ROLE", "REVOKE", "DROP ROLE", "PASSWORD"):
                    self.assertNotIn(forbidden, sql)
                return SanitizedProcessResult(0, "", "")
            with patch.object(postgres_control, "_cleaner_principal_state", side_effect=[before, expected]), patch.object(
                postgres_control, "_run_psql", side_effect=effect
            ):
                receipt = self._call(operation_id)
            self.assertEqual("NOOP_EXACT" if mode == "exact" else "APPLIED", receipt.effect_status)
            self.assertEqual("PROVISION_CLEANER_APP_PRINCIPAL", receipt.operation_type)
            self.assertEqual(["PREPARED", "FINAL"], [e["receipt_phase"] for e in self.store.typed_postgres_operation_receipt_events(operation_id)])

    def test_failed_postcondition_and_prepared_only_replay(self):
        self._schema()
        expected = postgres_control._cleaner_principal_expected_state()
        before = dict(expected, principal=None, memberships=[])
        with patch.object(postgres_control, "_cleaner_principal_state", side_effect=[before, before]), patch.object(
            postgres_control, "_run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            with self.assertRaises(TypedPostgresError): self._call()
        self.assertEqual(["PREPARED"], [e["receipt_phase"] for e in self.store.typed_postgres_operation_receipt_events("s2-principal")])
        with patch.object(postgres_control, "_cleaner_principal_state") as readback, patch.object(postgres_control, "run_controlled_deployment") as w08:
            with self.assertRaisesRegex(TypedPostgresError, "RECONCILIATION_REQUIRED"): self._call()
            readback.assert_not_called(); w08.assert_not_called()

    def test_effect_failure_cannot_finalize_even_with_exact_readback(self):
        self._schema()
        expected = postgres_control._cleaner_principal_expected_state()
        with patch.object(postgres_control, "_cleaner_principal_state", return_value=expected), patch.object(
            postgres_control, "_run_psql", return_value=SanitizedProcessResult(1, "", "fixture failure")
        ):
            with self.assertRaisesRegex(TypedPostgresError, "EFFECT_FAILED"): self._call()
        self.assertEqual(["PREPARED"], [e["receipt_phase"] for e in self.store.typed_postgres_operation_receipt_events("s2-principal")])

    def test_s2_wrong_state_never_prepares_or_effects(self):
        self._schema()
        expected = postgres_control._cleaner_principal_expected_state()
        for index, wrong in enumerate((
            dict(expected, app_runtime=None), dict(expected, memberships=[] , principal={"role": "wrong"}),
            dict(expected, memberships=expected["memberships"] * 2),
        )):
            with patch.object(postgres_control, "_cleaner_principal_state", return_value=wrong), patch.object(
                postgres_control, "_persist_prepared_receipt"
            ) as prepared, patch.object(postgres_control, "_run_psql") as process:
                with self.assertRaises(TypedPostgresError): self._call(f"s2-wrong-{index}")
                prepared.assert_not_called(); process.assert_not_called()

    def test_s2_prepared_failure_blocks_effect_and_final_replay_is_factual(self):
        self._schema()
        expected = postgres_control._cleaner_principal_expected_state()
        with patch.object(postgres_control, "_cleaner_principal_state", return_value=expected), patch.object(
            self.store, "append_typed_postgres_operation_receipt_event", side_effect=StoreError("FIXTURE_WRITE_FAILED")
        ), patch.object(postgres_control, "_run_psql") as process:
            with self.assertRaisesRegex(TypedPostgresError, "PRE_EFFECT_RECEIPT_DURABILITY_FAILED"):
                self._call("s2-prepare-failure")
            process.assert_not_called()
        with patch.object(postgres_control, "_cleaner_principal_state", return_value=expected), patch.object(
            postgres_control, "_run_psql", return_value=SanitizedProcessResult(0, "", "")
        ):
            receipt = self._call("s2-durable")
        path = self.store.database_path
        self.store.close()
        self.store = ControlStore(path, migrate_schema=False, require_schema_version=10, clock=self.clock, global_writer_guard_required=True)
        with patch.object(postgres_control, "_cleaner_principal_state", return_value=expected), patch.object(postgres_control, "run_controlled_deployment") as w08:
            self.assertEqual(receipt, self._call("s2-durable"))
            w08.assert_not_called()
        with patch.object(postgres_control, "_cleaner_principal_state", return_value=dict(expected, principal=None)):
            with self.assertRaisesRegex(TypedPostgresError, "FINAL_FACTUAL_STATE_RECONCILIATION_REQUIRED"):
                self._call("s2-durable")



class CleanerPrincipalDisposablePostgresTests(unittest.TestCase):
    """Exercise the sealed SQL in a private, socket-only PostgreSQL 18 cluster."""

    @classmethod
    def setUpClass(cls):
        from tempfile import TemporaryDirectory
        cls.bin = Path("/opt/homebrew/Cellar/postgresql@18/18.6/bin")
        if not (cls.bin / "initdb").is_file():
            raise unittest.SkipTest("disposable PostgreSQL 18.6 binaries unavailable")
        cls.temporary = TemporaryDirectory(prefix="tk43-s2-pg-")
        cls.root = Path(cls.temporary.name)
        cls.data = cls.root / "data"
        cls.socket = cls.root / "socket"
        cls.socket.mkdir(mode=0o700)
        try:
            subprocess.run([str(cls.bin / "initdb"), "-D", str(cls.data), "-A", "trust", "-U", "s2_fixture", "--no-locale", "-c", "shared_memory_type=mmap", "-c", "dynamic_shared_memory_type=mmap"], check=True, capture_output=True)
            subprocess.run([
                str(cls.bin / "pg_ctl"), "-D", str(cls.data), "-l", str(cls.root / "server.log"),
                "-o", f"-k {cls.socket} -p 65482 -c listen_addresses='' -c unix_socket_permissions=0700", "-w", "start",
            ], check=True, capture_output=True)
            cls.psql("CREATE DATABASE propertyai_cleaner_prod", database="postgres", check=True)
        except subprocess.CalledProcessError as error:
            cls.stop()
            if b"could not create shared memory segment: Operation not permitted" in (error.stderr or b""):
                raise unittest.SkipTest("sandbox prohibits PostgreSQL shared memory; no privilege escalation") from error
            raise
        except BaseException:
            cls.stop()
            raise

    @classmethod
    def stop(cls):
        subprocess.run([str(cls.bin / "pg_ctl"), "-D", str(cls.data), "-m", "immediate", "-w", "stop"], capture_output=True)
        cls.temporary.cleanup()

    @classmethod
    def tearDownClass(cls):
        cls.stop()

    @classmethod
    def psql(cls, sql, *, database="propertyai_cleaner_prod", check=False):
        return subprocess.run([
            str(cls.bin / "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "-h", str(cls.socket), "-p", "65482", "-U", "s2_fixture", "-d", database,
        ], input=sql, text=True, capture_output=True, check=check)

    def test_real_transaction_create_noop_and_membership_only(self):
        import copy
        expected = postgres_control._cleaner_principal_expected_state()
        runtime = "CREATE ROLE propertyai_app_runtime NOLOGIN NOINHERIT;"
        principal = "CREATE ROLE propertyai_cleaner_app LOGIN NOINHERIT;"
        grant = "GRANT propertyai_app_runtime TO propertyai_cleaner_app WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
        for mode in ("absent", "membership-missing", "exact"):
            before = copy.deepcopy(expected)
            setup = runtime
            if mode == "absent": before["principal"] = None
            else: setup += principal
            if mode == "exact": setup += grant
            else: before["memberships"] = []
            sql = "BEGIN;" + setup + postgres_control._cleaner_principal_transaction(before).decode()
            sql += postgres_control._cleaner_principal_state_sql() + ";ROLLBACK;"
            with self.subTest(mode=mode):
                result = self.psql(sql)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(expected, json.loads(result.stdout.strip()))

    def test_real_transaction_rejects_catalog_conflicts(self):
        expected = postgres_control._cleaner_principal_expected_state()
        runtime = "CREATE ROLE propertyai_app_runtime NOLOGIN NOINHERIT;"
        principal = "CREATE ROLE propertyai_cleaner_app LOGIN NOINHERIT;"
        grant = "GRANT propertyai_app_runtime TO propertyai_cleaner_app WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
        cases = {
            "wrong-login": runtime + principal.replace(" LOGIN ", " NOLOGIN ") + grant,
            "wrong-inherit": runtime + principal.replace("NOINHERIT", "INHERIT") + grant,
            "unexpected-privilege": runtime + principal.replace("LOGIN NOINHERIT", "LOGIN NOINHERIT CREATEDB") + grant,
            "wrong-membership": runtime + principal + grant.replace("INHERIT FALSE", "INHERIT TRUE"),
            "extra-membership": runtime + principal + grant + "CREATE ROLE s2_extra; GRANT s2_extra TO propertyai_cleaner_app;",
            "runtime-absent": principal,
            "runtime-wrong": runtime.replace("NOLOGIN", "LOGIN") + principal + grant,
        }
        for name, setup in cases.items():
            with self.subTest(name=name):
                result = self.psql("BEGIN;" + setup + postgres_control._cleaner_principal_transaction(expected).decode() + "ROLLBACK;")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("COMPARE_BEFORE_MISMATCH", result.stderr)
                state = json.loads(self.psql(postgres_control._cleaner_principal_state_sql(), check=True).stdout)
                self.assertIsNone(state["principal"])
                self.assertIsNone(state["app_runtime"])

    def test_real_postcondition_failure_rolls_back_both_effects(self):
        expected = postgres_control._cleaner_principal_expected_state()
        before = dict(expected, principal=None, memberships=[])
        sql = postgres_control._cleaner_principal_transaction(before).decode()
        # Fault injection after both DDL statements forces the real transactional
        # postcondition failure branch. The DO statement must roll back its DDL.
        final_guard = sql.rindex("IF observed IS DISTINCT FROM")
        guard_end = sql.index(" THEN", final_guard)
        sql = sql[:final_guard] + "IF true" + sql[guard_end:]
        result = self.psql("BEGIN;CREATE ROLE propertyai_app_runtime NOLOGIN NOINHERIT;" + sql + "ROLLBACK;")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("POSTCONDITION_MISMATCH", result.stderr)
        state = json.loads(self.psql(postgres_control._cleaner_principal_state_sql(), check=True).stdout)
        self.assertIsNone(state["principal"])
        self.assertEqual([], state["memberships"])


if __name__ == "__main__":
    unittest.main()
