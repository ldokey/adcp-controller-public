from __future__ import annotations

from dataclasses import replace
import inspect
import json
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from adcp.canonical import canonical_json, canonical_sha256
from adcp.cutover import (
    AUTHORITY_MODE,
    CP_SLICE_ID,
    CutoverError,
    GitBindingEvidence,
    MigrationManifest,
    frozen_cut1_manifest,
    seed_isolated_five_slice_control_state,
)
import adcp.production_prep as production_prep
from adcp.production_prep import (
    ABSENT_STORE_MANIFEST_NAME,
    AcceptedADCPBinding,
    CANONICAL_PRODUCTION_CONTROL_STORE,
    CANONICAL_PRODUCTION_RUNTIME_ROOT,
    PRODUCTION_IMPORT_EXECUTION_ID,
    _PreparationPaths,
    _prepare_production_at,
    _require_canonical_paths,
)
from adcp.store.migrations import SCHEMA_VERSION
from adcp.store.sqlite import ControlStore
from tests._helpers import FakeClock


CP_IMPLEMENTATION_RESULT_COMMIT = "c5793b7f7ec975f581355ea8ed53a36451b55807"
CP_CURRENT_BRANCH_HEAD = "3d8491a6ce1a39c23dca0206e11d00c180276afd"


class ProductionPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "cp-source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        frozen = frozen_cut1_manifest()
        cp = replace(
            frozen.entry(CP_SLICE_ID),
            logical_source_root=str(self.repo),
            repository_toplevel=str(self.repo),
            execution_worktree=str(self.repo),
            snapshot_fingerprint="",
        ).finalized()
        self.manifest = MigrationManifest(
            tuple(cp if item.slice_id == CP_SLICE_ID else item for item in frozen.slices)
        )
        self.cp_binding = GitBindingEvidence(
            str(self.repo.resolve()),
            str(self.repo.resolve()),
            cp.branch,
            cp.current_branch_head,
            True,
            True,
            True,
            True,
        )
        self.adcp_binding = AcceptedADCPBinding(
            "/accepted/adcp-controller",
            "wcp-06-mvp-a",
            "8" * 40,
            True,
        )
        self.paths = _PreparationPaths(
            self.root / "production-like-runtime",
            self.root / "production-like-runtime" / "control.sqlite3",
        )
        self.clock = FakeClock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self):
        return _prepare_production_at(
            self.paths,
            self.manifest,
            self.cp_binding,
            self.adcp_binding,
            clock=self.clock,
        )

    def test_canonical_production_path_guard_is_exact_and_public_api_has_no_path(self) -> None:
        _require_canonical_paths(
            _PreparationPaths(
                CANONICAL_PRODUCTION_RUNTIME_ROOT,
                CANONICAL_PRODUCTION_CONTROL_STORE,
            )
        )
        with self.assertRaisesRegex(CutoverError, "CANONICAL_PRODUCTION_PATH_REQUIRED"):
            _require_canonical_paths(self.paths)
        parameters = inspect.signature(production_prep.prepare_canonical_production).parameters
        self.assertEqual(["accepted_adcp_head"], list(parameters))

    def test_unexpected_preexisting_store_fails_closed_without_overwrite(self) -> None:
        self.paths.runtime_root.mkdir()
        original = b"not-a-control-store"
        self.paths.control_store.write_bytes(original)
        with self.assertRaisesRegex(CutoverError, "UNEXPECTED_PREEXISTING_RUNTIME_STATE"):
            self.prepare()
        self.assertEqual(original, self.paths.control_store.read_bytes())

    def test_absent_store_manifest_is_durable_before_first_database_write(self) -> None:
        class StopBeforeDatabase(RuntimeError):
            pass

        def inspect_before_store(*_args, **_kwargs):
            self.assertFalse(self.paths.control_store.exists())
            manifest_path = (
                self.paths.runtime_root / "rollback" / ABSENT_STORE_MANIFEST_NAME
            )
            self.assertTrue(manifest_path.is_file())
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("ABSENT_STORE", document["evidence_type"])
            self.assertFalse(document["pre_write_runtime_exists"])
            self.assertFalse(document["pre_write_control_store_exists"])
            raise StopBeforeDatabase

        with patch(
            "adcp.production_prep._reserve_control_store",
            side_effect=inspect_before_store,
        ):
            with self.assertRaises(StopBeforeDatabase):
                self.prepare()

    def test_fresh_prepare_has_exact_production_semantics_and_integrity(self) -> None:
        result = self.prepare()
        self.assertFalse(result.replayed)
        self.assertEqual(PRODUCTION_IMPORT_EXECUTION_ID, result.execution_id)
        lowered = result.execution_id.lower()
        for forbidden in ("cut1-", "cut2-", "rehearsal", "test"):
            self.assertNotIn(forbidden, lowered)
        self.assertEqual(7, result.schema_version)
        self.assertEqual(SCHEMA_VERSION, result.schema_version)
        self.assertEqual(5, result.slice_count)
        self.assertEqual("ok", result.sqlite_integrity)
        self.assertEqual(AUTHORITY_MODE, result.authority_mode)
        self.assertEqual(1, result.authority_generation)
        self.assertIsNone(result.cutover_id)
        self.assertIsNone(result.switched_at)

        store = ControlStore(self.paths.control_store)
        try:
            execution = dict(store.get_execution(PRODUCTION_IMPORT_EXECUTION_ID))
            self.assertEqual("PRODUCTION", execution["environment"])
            rows = {row["slice_id"]: dict(row) for row in store.slice_control_states()}
            cp = rows[CP_SLICE_ID]
            self.assertEqual(PRODUCTION_IMPORT_EXECUTION_ID, cp["active_execution_id"])
            self.assertEqual(CP_IMPLEMENTATION_RESULT_COMMIT, cp["implementation_result_commit"])
            self.assertEqual(CP_CURRENT_BRANCH_HEAD, cp["current_branch_head"])
            self.assertNotEqual(cp["implementation_result_commit"], cp["current_branch_head"])
            phase1 = rows["OPENCLAW.PHASE1.OPS_BRIEFING"]
            self.assertEqual("DEFER_BINDING", phase1["migration_class"])
            self.assertEqual("INELIGIBLE_UNTIL_PREFLIGHT", phase1["execution_eligibility"])
            for field in (
                "base_commit",
                "implementation_result_commit",
                "current_branch_head",
                "active_execution_id",
            ):
                self.assertIsNone(phase1[field])
            for slice_id in (
                "OPENCLAW.PHASE2A.PHOTO_REVIEW",
                "OPENCLAW.PHASE2B.INCIDENT_DIAGNOSIS",
                "OPENCLAW.PHASE2C.WEB_RESEARCH",
            ):
                row = rows[slice_id]
                self.assertEqual("DEFER_PREREQUISITE", row["migration_class"])
                self.assertEqual("INELIGIBLE_UNTIL_PREREQUISITE", row["execution_eligibility"])
                for field in (
                    "base_commit",
                    "implementation_result_commit",
                    "current_branch_head",
                    "active_execution_id",
                ):
                    self.assertIsNone(row[field])
            self.assertEqual(5, len(store.connection.execute(
                "SELECT * FROM slice_control_event"
            ).fetchall()))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_CONTROL_EVENT"):
                store.connection.execute(
                    "UPDATE slice_control_event SET reason_code = 'changed' WHERE event_seq = 1"
                )
        finally:
            store.close()

    def test_exact_replay_is_readonly_idempotent_and_fingerprints_are_canonical(self) -> None:
        first = self.prepare()
        database_stat = self.paths.control_store.stat()
        evidence_path = self.paths.runtime_root / "rollback" / ABSENT_STORE_MANIFEST_NAME
        evidence_before = evidence_path.read_bytes()
        second = self.prepare()
        database_stat_after = self.paths.control_store.stat()
        self.assertTrue(second.replayed)
        self.assertEqual(first.slice_snapshot_fingerprint, second.slice_snapshot_fingerprint)
        self.assertEqual(first.rollback_snapshot_fingerprint, second.rollback_snapshot_fingerprint)
        self.assertEqual(database_stat.st_mtime_ns, database_stat_after.st_mtime_ns)
        self.assertEqual(evidence_before, evidence_path.read_bytes())
        document = json.loads(evidence_before)
        payload = {key: value for key, value in document.items() if key != "rollback_fingerprint"}
        self.assertEqual(canonical_sha256(payload), document["rollback_fingerprint"])
        self.assertEqual(canonical_json(document) + "\n", evidence_before.decode("utf-8"))

    def test_conflicting_replay_fails_closed_without_silent_reconcile(self) -> None:
        self.prepare()
        connection = sqlite3.connect(self.paths.control_store)
        try:
            connection.execute(
                "UPDATE slice_execution SET result_commit = ? WHERE execution_id = ?",
                ("9" * 40, PRODUCTION_IMPORT_EXECUTION_ID),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(CutoverError, "PRODUCTION_EXECUTION_BINDING_CONFLICT"):
            self.prepare()
        connection = sqlite3.connect(self.paths.control_store)
        try:
            observed = connection.execute(
                "SELECT result_commit FROM slice_execution WHERE execution_id = ?",
                (PRODUCTION_IMPORT_EXECUTION_ID,),
            ).fetchone()[0]
            self.assertEqual("9" * 40, observed)
        finally:
            connection.close()

    def test_no_authority_switch_api_is_exposed_by_e2(self) -> None:
        public_names = set(production_prep.__all__)
        self.assertFalse(any("switch" in name.lower() for name in public_names))
        source = Path(production_prep.__file__).read_text(encoding="utf-8")
        self.assertNotIn("CONTROL_STORE_AUTHORITY", source)

    def test_isolated_rehearsal_helper_still_rejects_operational_root(self) -> None:
        with self.assertRaisesRegex(CutoverError, "OPERATIONAL_STORE_FORBIDDEN"):
            seed_isolated_five_slice_control_state(
                CANONICAL_PRODUCTION_CONTROL_STORE,
                self.manifest,
                self.cp_binding,
                clock=self.clock,
            )


if __name__ == "__main__":
    unittest.main()
