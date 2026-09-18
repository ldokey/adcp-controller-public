from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from adcp.postgres_approval_evidence import (
    ExpectedProductionOperationApprovalBinding,
    GrantedProductionOperationApprovalProjectionV1,
    PostgresApprovalEvidenceError,
    ProtectedApprovalEvidenceSource,
    materialize_granted_production_operation_approval_projection,
    resolve_production_operation_approval_evidence,
)


class ProductionOperationApprovalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="typed-pg-approval-")
        self.root = Path(self.tmp.name) / "protected"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.source = ProtectedApprovalEvidenceSource(self.root, os.getuid())
        self.now = datetime(2026, 9, 9, 0, 0, tzinfo=timezone.utc)
        self.ref = "CHAT.PROJ.HQ:APPROVAL:TYPED-PG:1"
        self.expected = ExpectedProductionOperationApprovalBinding(
            project_code="CHAT.PROJ.HQ",
            change_id="P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01",
            gate_or_control_id="P1R5-C3-CONTROL",
            operation_kind="EXECUTE_AUTHORIZED_SQL_FILE",
            authorized_effect_scope=("EXECUTE_EXACT_SQL_ARTIFACT",),
            controller_commit="1" * 40,
            controller_tree="2" * 40,
            controller_entrypoint="execute_authorized_sql_file",
            target_identity={
                "database": "propertyai_cleaner_prod",
                "execution_role": "propertyai_dba",
                "sql_artifact_path": "db/v2_2_1/bootstrap/001__privileged_roles_schema.sql",
            },
            operation_artifact_identity={"sha256": "3" * 64},
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def payload(self, **overrides):
        value = {
            "schema_version": 1,
            "approval_id": self.ref,
            "approval_status": "GRANTED",
            "decision_identity": {
                "stable_id": "DL-35-INSTANCE-1",
                "canonical_page_identity": "notion-page:3d53f2c8cf4781cda689c78f198d67a5",
            },
            "project_code": self.expected.project_code,
            "change_id": self.expected.change_id,
            "gate_or_control_id": self.expected.gate_or_control_id,
            "operation_kind": self.expected.operation_kind,
            "authorized_effect_scope": list(self.expected.authorized_effect_scope),
            "controller_source": {
                "commit": self.expected.controller_commit,
                "tree": self.expected.controller_tree,
                "entrypoint": self.expected.controller_entrypoint,
            },
            "target_identity": dict(self.expected.target_identity),
            "operation_artifact_identity": dict(self.expected.operation_artifact_identity or {}),
            "issued_at": (self.now - timedelta(minutes=5)).isoformat(),
            "expires_at": (self.now + timedelta(hours=1)).isoformat(),
            "supersession_or_disposition": "ACTIVE",
        }
        value.update(overrides)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        value["evidence_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return value

    def write(self, payload=None, *, reference=None, mode=0o600):
        reference = self.ref if reference is None else reference
        path = self.root / (hashlib.sha256(reference.encode()).hexdigest() + ".json")
        path.write_text(json.dumps(payload or self.payload()), encoding="utf-8")
        os.chmod(path, mode)
        return path

    def resolve(self, *, expected=None, reference=None):
        return resolve_production_operation_approval_evidence(
            self.source,
            control_decision_ref=self.ref if reference is None else reference,
            expected=expected or self.expected,
            now=self.now,
        )

    def test_s2_approval_binds_sealed_target_source_scope_freshness_and_hash(self):
        import copy
        from adcp.postgres_control import _cleaner_principal_expected_state
        target = _cleaner_principal_expected_state()
        del target["principal"]["password_unset"]
        self.expected = replace(
            self.expected, operation_kind="PROVISION_CLEANER_APP_PRINCIPAL",
            authorized_effect_scope=("CREATE_EXACT_CLEANER_APP_PRINCIPAL", "CREATE_EXACT_CLEANER_APP_MEMBERSHIP"),
            controller_entrypoint="adcp.postgres_control.provision_cleaner_app_principal",
            target_identity=target, operation_artifact_identity=None,
        )
        payload = self.payload(operation_artifact_identity=None)
        self.write(payload)
        self.assertEqual("PROVISION_CLEANER_APP_PRINCIPAL", self.resolve().operation_kind)
        targets = []
        wrong = copy.deepcopy(target); wrong["database"] = "other"; targets.append(wrong)
        for key in target["principal"]:
            wrong = copy.deepcopy(target); wrong["principal"][key] = "wrong"; targets.append(wrong)
        for key in target["memberships"][0]:
            wrong = copy.deepcopy(target); wrong["memberships"][0][key] = "wrong"; targets.append(wrong)
        for wrong in targets:
            self.write(self.payload(operation_artifact_identity=None, target_identity=wrong))
            with self.assertRaisesRegex(PostgresApprovalEvidenceError, "BINDING_MISMATCH"):
                self.resolve()
        for overrides in (
            {"operation_kind": "TRANSITION_DATABASE_OWNER"},
            {"authorized_effect_scope": ["GENERIC_ROLE_ADMIN"]},
            {"controller_source": {"commit": "f" * 40, "tree": self.expected.controller_tree, "entrypoint": self.expected.controller_entrypoint}},
            {"controller_source": {"commit": self.expected.controller_commit, "tree": "f" * 40, "entrypoint": self.expected.controller_entrypoint}},
            {"expires_at": (self.now - timedelta(seconds=1)).isoformat()},
            {"issued_at": (self.now + timedelta(seconds=1)).isoformat()},
        ):
            self.write(self.payload(operation_artifact_identity=None, **overrides))
            with self.assertRaises(PostgresApprovalEvidenceError): self.resolve()
        payload["evidence_sha256"] = "f" * 64
        self.write(payload)
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "HASH_MISMATCH"): self.resolve()

    def test_exact_valid_protected_evidence_passes(self):
        self.write()
        resolved = self.resolve()
        self.assertEqual(self.ref, resolved.approval_id)
        self.assertEqual("DL-35-INSTANCE-1", resolved.decision_stable_id)

    def test_blank_missing_and_unprotected_sources_reject(self):
        with self.assertRaises(PostgresApprovalEvidenceError):
            self.resolve(reference="")
        with self.assertRaises(PostgresApprovalEvidenceError):
            self.resolve()
        self.write(mode=0o644)
        with self.assertRaises(PostgresApprovalEvidenceError):
            self.resolve()
        os.chmod(self.root, 0o755)
        with self.assertRaises(PostgresApprovalEvidenceError):
            self.resolve()

    def test_malformed_evidence_rejects(self):
        path = self.root / (hashlib.sha256(self.ref.encode()).hexdigest() + ".json")
        path.write_bytes(b"{not-json")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "MALFORMED"):
            self.resolve()

    def test_wrong_content_hash_rejects(self):
        payload = self.payload()
        payload["target_identity"]["database"] = "forged"
        self.write(payload)
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "HASH_MISMATCH"):
            self.resolve()

    def test_wrong_operation_change_gate_controller_target_and_artifact_reject(self):
        mutations = [
            ("operation_kind", "TRANSITION_DATABASE_OWNER"),
            ("change_id", "WRONG-CHANGE"),
            ("gate_or_control_id", "WRONG-GATE"),
            ("controller_source", {"commit": "4" * 40, "tree": "2" * 40, "entrypoint": "execute_authorized_sql_file"}),
            ("controller_source", {"commit": "1" * 40, "tree": "4" * 40, "entrypoint": "execute_authorized_sql_file"}),
            ("controller_source", {"commit": "1" * 40, "tree": "2" * 40, "entrypoint": "transition_database_owner"}),
            ("target_identity", {**self.expected.target_identity, "database": "wrong"}),
            ("operation_artifact_identity", {"sha256": "4" * 64}),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                self.write(self.payload(**{field: value}))
                with self.assertRaisesRegex(PostgresApprovalEvidenceError, "BINDING_MISMATCH"):
                    self.resolve()

    def test_denied_expired_future_revoked_and_superseded_reject(self):
        cases = [
            self.payload(approval_status="DENIED"),
            self.payload(expires_at=(self.now - timedelta(seconds=1)).isoformat()),
            self.payload(issued_at=(self.now + timedelta(seconds=1)).isoformat()),
            self.payload(supersession_or_disposition="REVOKED"),
            self.payload(supersession_or_disposition="SUPERSEDED"),
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                self.write(payload)
                with self.assertRaises(PostgresApprovalEvidenceError):
                    self.resolve()

    def test_reference_must_resolve_to_exact_approval_or_decision_identity(self):
        other_ref = "WRONG-LOOKUP-REF"
        self.write(self.payload(), reference=other_ref)
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "CONTROL_DECISION_REF_MISMATCH"):
            self.resolve(reference=other_ref)

    def projection(self):
        return GrantedProductionOperationApprovalProjectionV1(
            lookup_reference=self.ref,
            approval_id=self.ref,
            decision_stable_id="DL-35-INSTANCE-1",
            decision_page_identity="notion-page:3d53f2c8cf4781cda689c78f198d67a5",
            project_code=self.expected.project_code,
            change_id=self.expected.change_id,
            gate_or_control_id=self.expected.gate_or_control_id,
            operation_kind=self.expected.operation_kind,
            authorized_effect_scope=self.expected.authorized_effect_scope,
            controller_commit=self.expected.controller_commit,
            controller_tree=self.expected.controller_tree,
            controller_entrypoint=self.expected.controller_entrypoint,
            target_identity=self.expected.target_identity,
            operation_artifact_identity=self.expected.operation_artifact_identity,
            issued_at=(self.now - timedelta(minutes=5)).isoformat(),
            expires_at=(self.now + timedelta(hours=1)).isoformat(),
        )

    def test_control_owned_projection_materializer_round_trips_and_is_idempotent(self):
        path = materialize_granted_production_operation_approval_projection(
            self.source, projection=self.projection()
        )
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        first = path.read_bytes()
        again = materialize_granted_production_operation_approval_projection(
            self.source, projection=self.projection()
        )
        self.assertEqual(path, again)
        self.assertEqual(first, again.read_bytes())
        self.assertEqual(self.ref, self.resolve().approval_id)

    def test_projection_materializer_rejects_conflict_and_unprotected_parent(self):
        materialize_granted_production_operation_approval_projection(
            self.source, projection=self.projection()
        )
        conflicting = replace(
            self.projection(),
            target_identity={**self.expected.target_identity, "database": "forged"},
        )
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "IMMUTABLE_CONFLICT"):
            materialize_granted_production_operation_approval_projection(
                self.source, projection=conflicting
            )

        unsafe_parent = Path(self.tmp.name) / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o777)
        os.chmod(unsafe_parent, 0o777)
        unsafe_source = ProtectedApprovalEvidenceSource(
            unsafe_parent / "nested" / "projection", os.getuid()
        )
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "PARENT_UNPROTECTED"):
            materialize_granted_production_operation_approval_projection(
                unsafe_source, projection=self.projection()
            )

    def test_same_approval_cannot_authorize_different_typed_pg_api(self):
        self.write()
        wrong_expected = ExpectedProductionOperationApprovalBinding(
            project_code=self.expected.project_code,
            change_id=self.expected.change_id,
            gate_or_control_id=self.expected.gate_or_control_id,
            operation_kind="TRANSITION_DATABASE_OWNER",
            authorized_effect_scope=("TRANSITION_DATABASE_OWNER",),
            controller_commit=self.expected.controller_commit,
            controller_tree=self.expected.controller_tree,
            controller_entrypoint="transition_database_owner",
            target_identity={
                "database": "propertyai_cleaner_prod",
                "from_owner": "propertyai_dba",
                "to_owner": "propertyai_owner",
            },
            operation_artifact_identity=None,
        )
        with self.assertRaisesRegex(PostgresApprovalEvidenceError, "BINDING_MISMATCH"):
            self.resolve(expected=wrong_expected)


if __name__ == "__main__":
    unittest.main()
