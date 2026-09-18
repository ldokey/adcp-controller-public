from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest

from adcp.canonical import canonical_json
from adcp.cutover import (
    AUTHORITY_MODE,
    CP_SLICE_ID,
    CutoverError,
    GitBindingEvidence,
    MigrationManifest,
    SeedEligibility,
    classify_seed_eligibility,
    control_snapshot_material,
    control_state_target,
    frozen_cut1_manifest,
    handoff_projection,
    registry_projection,
    seed_isolated_cp,
    seed_isolated_five_slice_control_state,
    snapshot_restore_material,
)
from adcp.store.migrations import SCHEMA_VERSION
from adcp.domain import StoreError, operation_key
from adcp.store.sqlite import (
    CONTROL_STATE_INPUT_FIELDS,
    ControlStore,
    DEFAULT_RUNTIME_ROOT,
    control_state_authority_fingerprint,
)
from tests._helpers import FakeClock


class CutoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@local.invalid", "commit", "-q", "-m", "base"], check=True
        )
        self.base = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        (self.repo / "tracked.txt").write_text("result\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@local.invalid", "commit", "-q", "-m", "result"], check=True
        )
        self.result = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@local.invalid", "commit", "-q", "-m", "head"], check=True
        )
        self.head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        frozen = frozen_cut1_manifest()
        cp = frozen.entry(CP_SLICE_ID)
        cp = replace(
            cp,
            logical_source_root=str(self.repo),
            repository_toplevel=str(self.repo),
            execution_worktree=str(self.repo),
            branch="main",
            base_commit=self.base,
            implementation_result_commit=self.result,
            current_branch_head=self.head,
            snapshot_fingerprint="",
        ).finalized()
        self.manifest = MigrationManifest(tuple(cp if item.slice_id == CP_SLICE_ID else item for item in frozen.slices))
        self.binding = GitBindingEvidence(
            str(self.repo.resolve()), str(self.repo.resolve()), "main", self.head, True, True, True, True
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_manifest_round_trip(self) -> None:
        rebuilt = MigrationManifest.from_json(self.manifest.canonical_payload())
        self.assertEqual(self.manifest, rebuilt)

    def test_canonicalization_and_fingerprint_are_stable(self) -> None:
        first = self.manifest.canonical_payload()
        second = MigrationManifest.from_json(first).canonical_payload()
        self.assertEqual(first, second)
        self.assertEqual(self.manifest.fingerprint, MigrationManifest.from_json(first).fingerprint)

    def test_snapshot_fingerprint_excludes_volatile_time(self) -> None:
        payload = json.loads(self.manifest.canonical_payload())
        self.assertNotIn("time", canonical_json(payload).lower())
        self.assertEqual(64, len(self.manifest.entry(CP_SLICE_ID).snapshot_fingerprint))

    def test_implementation_result_and_current_head_are_distinct(self) -> None:
        cp = self.manifest.entry(CP_SLICE_ID)
        self.assertEqual(self.result, cp.implementation_result_commit)
        self.assertEqual(self.head, cp.current_branch_head)
        self.assertNotEqual(cp.implementation_result_commit, cp.current_branch_head)

    def test_source_repository_and_worktree_are_distinct_in_frozen_manifest(self) -> None:
        cp = frozen_cut1_manifest().entry(CP_SLICE_ID)
        self.assertNotEqual(cp.logical_source_root, cp.repository_toplevel)
        self.assertNotEqual(cp.repository_toplevel, cp.execution_worktree)

    def test_frozen_manifest_uses_public_safe_symbolic_resource_refs(self) -> None:
        manifest = frozen_cut1_manifest()
        for entry in manifest.slices:
            for value in (entry.execution_packet_url, entry.contract_url):
                self.assertNotIn("notion.com", value)
                self.assertTrue(
                    value == "NONE" or value.startswith(("packet://", "contract://")),
                    value,
                )

    def test_cp_exact_binding_is_eligible(self) -> None:
        decision = classify_seed_eligibility(self.manifest.entry(CP_SLICE_ID), self.binding)
        self.assertEqual(SeedEligibility.ELIGIBLE, decision.eligibility)

    def test_cp_binding_drift_fails_closed(self) -> None:
        drift = replace(self.binding, head="f" * 40)
        decision = classify_seed_eligibility(self.manifest.entry(CP_SLICE_ID), drift)
        self.assertEqual(SeedEligibility.DEFER_BINDING, decision.eligibility)
        self.assertEqual("IMMUTABLE_BINDING_DRIFT", decision.reason)

    def test_phase1_unresolved_binding_is_ineligible(self) -> None:
        entry = self.manifest.entry("OPENCLAW.PHASE1.OPS_BRIEFING")
        self.assertEqual(SeedEligibility.DEFER_BINDING, classify_seed_eligibility(entry).eligibility)

    def test_all_phase2_entries_are_prerequisite_deferred(self) -> None:
        for suffix in ("2A.PHOTO_REVIEW", "2B.INCIDENT_DIAGNOSIS", "2C.WEB_RESEARCH"):
            entry = self.manifest.entry(f"OPENCLAW.PHASE{suffix}")
            self.assertEqual(SeedEligibility.DEFER_PREREQUISITE, classify_seed_eligibility(entry).eligibility)

    def test_isolated_cp_seed_success(self) -> None:
        result = seed_isolated_cp(self.root / "isolated" / "control.sqlite3", self.manifest, self.binding, clock=FakeClock())
        self.assertEqual("READY", result.state)
        self.assertEqual(self.result, result.result_commit)
        self.assertEqual(AUTHORITY_MODE, result.authority_mode)
        self.assertFalse(result.replayed)

    def test_same_seed_retry_is_idempotent(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        first = seed_isolated_cp(path, self.manifest, self.binding, clock=FakeClock())
        second = seed_isolated_cp(path, self.manifest, self.binding, clock=FakeClock())
        self.assertEqual(first.execution_id, second.execution_id)
        self.assertEqual(first.state_version, second.state_version)
        self.assertTrue(second.replayed)
        store = ControlStore(path)
        try:
            self.assertEqual(1, store.connection.execute("SELECT count(*) FROM slice_execution").fetchone()[0])
        finally:
            store.close()

    def test_conflicting_fingerprint_is_detected(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        seed_isolated_cp(path, self.manifest, self.binding, clock=FakeClock())
        cp = replace(self.manifest.entry(CP_SLICE_ID), contract_url="https://example.invalid/drift", snapshot_fingerprint="").finalized()
        conflict = MigrationManifest(tuple(cp if item.slice_id == CP_SLICE_ID else item for item in self.manifest.slices))
        with self.assertRaisesRegex(CutoverError, "SEED_FINGERPRINT_CONFLICT"):
            seed_isolated_cp(path, conflict, self.binding, clock=FakeClock())

    def _seeded_row(self, path: Path) -> dict[str, object]:
        seed_isolated_cp(path, self.manifest, self.binding, clock=FakeClock())
        store = ControlStore(path)
        try:
            return dict(store.get_execution("cut2-rehearsal-cp-01a-2"))
        finally:
            store.close()

    def test_registry_projection_is_deterministic_and_preserves_commit_roles(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        row = self._seeded_row(path)
        first = registry_projection(self.manifest.entry(CP_SLICE_ID), row)
        second = registry_projection(self.manifest.entry(CP_SLICE_ID), row)
        self.assertEqual(first, second)
        self.assertEqual(self.result, first["semantic_view"]["Result Commit"])
        self.assertEqual(self.head, first["metadata"]["current_branch_head"])

    def test_handoff_projection_is_deterministic_and_non_authoritative(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        row = self._seeded_row(path)
        views = [registry_projection(item, row if item.slice_id == CP_SLICE_ID else None) for item in self.manifest.slices]
        first = handoff_projection(self.manifest, views)
        second = handoff_projection(self.manifest, reversed(views))
        self.assertEqual(first, second)
        self.assertEqual("NO", first["development_control_store_authority"])

    def test_authority_mode_remains_transitional(self) -> None:
        result = seed_isolated_cp(self.root / "isolated" / "control.sqlite3", self.manifest, self.binding, clock=FakeClock())
        self.assertEqual("TRANSITIONAL_AUTHORITY", result.authority_mode)

    def test_no_operational_write_transports_exist_in_cutover_module(self) -> None:
        source = (Path(__file__).parents[1] / "src" / "adcp" / "cutover.py").read_text(encoding="utf-8")
        for forbidden in ("notion_projection", "urllib.request", "notion_update", "handoff.write", "registry.write"):
            self.assertNotIn(forbidden, source)

    def test_snapshot_restore_material_is_deterministic(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        row = self._seeded_row(path)
        first = snapshot_restore_material(path, self.manifest, [row])
        second = snapshot_restore_material(path, self.manifest, [row])
        self.assertEqual(first, second)
        self.assertEqual(self.manifest.fingerprint, first["manifest_fingerprint"])
        self.assertEqual(1, len(first["restore_inputs"]["slice_executions"]))

    def test_explicit_isolated_path_is_required(self) -> None:
        with self.assertRaisesRegex(CutoverError, "EXPLICIT_ABSOLUTE_ISOLATED_STORE_REQUIRED"):
            seed_isolated_cp(Path("control.sqlite3"), self.manifest, self.binding)

    def test_operational_runtime_root_is_forbidden(self) -> None:
        with self.assertRaisesRegex(CutoverError, "OPERATIONAL_STORE_FORBIDDEN"):
            seed_isolated_cp(DEFAULT_RUNTIME_ROOT / "cut1.sqlite3", self.manifest, self.binding)

    def test_schema_version_is_six(self) -> None:
        path = self.root / "isolated" / "control.sqlite3"
        self._seeded_row(path)
        store = ControlStore(path)
        try:
            version = store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
            self.assertEqual(SCHEMA_VERSION, version)
            self.assertEqual(7, version)
        finally:
            store.close()

    def test_isolated_projection_equality_and_exact_null_semantics(self) -> None:
        path = self.root / "e1" / "control.sqlite3"
        result = seed_isolated_five_slice_control_state(
            path, self.manifest, self.binding, clock=FakeClock()
        )
        self.assertEqual(5, len(result.slice_rows))
        by_id = {row["slice_id"]: row for row in result.slice_rows}
        cp = by_id[CP_SLICE_ID]
        self.assertEqual(("S6_EVIDENCE", "READY_FOR_CODEX"), (cp["stage"], cp["status"]))
        self.assertEqual("MIGRATE_AS_READY_CURRENT_STATE", cp["migration_class"])
        self.assertEqual("ELIGIBLE_BOUND", cp["execution_eligibility"])
        self.assertEqual(self.result, cp["implementation_result_commit"])
        self.assertEqual(self.head, cp["current_branch_head"])
        self.assertNotEqual(cp["implementation_result_commit"], cp["current_branch_head"])
        self.assertEqual(result.execution_id, cp["active_execution_id"])
        store = ControlStore(path)
        try:
            execution = store.get_execution(result.execution_id)
            self.assertEqual(
                (cp["slice_id"], cp["branch"], cp["base_commit"], cp["implementation_result_commit"]),
                (execution["slice_id"], execution["branch"], execution["base_commit"], execution["result_commit"]),
            )
        finally:
            store.close()

        phase1 = by_id["OPENCLAW.PHASE1.OPS_BRIEFING"]
        self.assertEqual(("S4_EXECUTION_FROZEN", "READY_FOR_CODEX"), (phase1["stage"], phase1["status"]))
        self.assertEqual("DEFER_BINDING", phase1["migration_class"])
        self.assertEqual("INELIGIBLE_UNTIL_PREFLIGHT", phase1["execution_eligibility"])
        for field in ("base_commit", "implementation_result_commit", "current_branch_head", "active_execution_id"):
            self.assertIsNone(phase1[field])

        for slice_id in (
            "OPENCLAW.PHASE2A.PHOTO_REVIEW",
            "OPENCLAW.PHASE2B.INCIDENT_DIAGNOSIS",
            "OPENCLAW.PHASE2C.WEB_RESEARCH",
        ):
            row = by_id[slice_id]
            self.assertEqual(("S1_LOGICAL_CONTRACT", "WAITING_USER"), (row["stage"], row["status"]))
            self.assertEqual("DEFER_PREREQUISITE", row["migration_class"])
            self.assertEqual("INELIGIBLE_UNTIL_PREREQUISITE", row["execution_eligibility"])
            for field in ("base_commit", "implementation_result_commit", "current_branch_head", "active_execution_id"):
                self.assertIsNone(row[field])
        self.assertEqual("TRANSITIONAL_AUTHORITY", result.authority_mode)

    def test_five_slice_seed_reconcile_is_idempotent_and_events_do_not_duplicate(self) -> None:
        path = self.root / "e1" / "control.sqlite3"
        first = seed_isolated_five_slice_control_state(path, self.manifest, self.binding, clock=FakeClock())
        second = seed_isolated_five_slice_control_state(path, self.manifest, self.binding, clock=FakeClock())
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.slice_snapshot_fingerprint, second.slice_snapshot_fingerprint)
        store = ControlStore(path)
        try:
            self.assertEqual(5, store.connection.execute("SELECT count(*) FROM slice_control_event").fetchone()[0])
            self.assertEqual(5, store.connection.execute("SELECT count(*) FROM slice_control_state").fetchone()[0])
        finally:
            store.close()

    def test_control_state_cas_conflict_and_immutable_event(self) -> None:
        path = self.root / "e1" / "control.sqlite3"
        seed_isolated_five_slice_control_state(path, self.manifest, self.binding, clock=FakeClock())
        store = ControlStore(path)
        try:
            row = dict(store.get_slice_control_state(CP_SLICE_ID))
            target = {field: row[field] for field in CONTROL_STATE_INPUT_FIELDS}
            target["status"] = "RECONCILED_TEST_STATE"
            target["authority_fingerprint"] = control_state_authority_fingerprint(target)
            updated, replayed = store.reconcile_slice_control_state(
                target,
                row["state_version"],
                operation_key("e1-cas-success", {"slice_id": CP_SLICE_ID}),
                reason_code="TEST_RECONCILE",
            )
            self.assertFalse(replayed)
            self.assertEqual(row["state_version"] + 1, updated["state_version"])
            self.assertEqual([0, 1], [event["to_state_version"] for event in store.slice_control_events(CP_SLICE_ID)])
            stale_target = dict(target)
            stale_target["status"] = "SECOND_TEST_STATE"
            stale_target["authority_fingerprint"] = control_state_authority_fingerprint(stale_target)
            with self.assertRaisesRegex(StoreError, "STALE_CONTROL_STATE_VERSION"):
                store.reconcile_slice_control_state(
                    stale_target,
                    row["state_version"],
                    operation_key("e1-stale-cas", {"slice_id": CP_SLICE_ID}),
                    reason_code="TEST_RECONCILE",
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_CONTROL_EVENT"):
                store.connection.execute(
                    "UPDATE slice_control_event SET reason_code = 'MUTATED' WHERE slice_id = ?",
                    (CP_SLICE_ID,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_CONTROL_EVENT"):
                store.connection.execute(
                    "DELETE FROM slice_control_event WHERE slice_id = ?", (CP_SLICE_ID,)
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CONTROL_STATE_VERSION_MISMATCH"):
                store.connection.execute(
                    """UPDATE slice_control_state
                       SET status = 'UNRECORDED', state_version = state_version + 1
                     WHERE slice_id = ?""",
                    (CP_SLICE_ID,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CONTROL_STATE_DELETE_FORBIDDEN"):
                store.connection.execute(
                    "DELETE FROM slice_control_state WHERE slice_id = ?", (CP_SLICE_ID,)
                )
        finally:
            store.close()

    def test_deferred_execution_guard_and_cp_rebinding_protection(self) -> None:
        path = self.root / "e1" / "control.sqlite3"
        result = seed_isolated_five_slice_control_state(path, self.manifest, self.binding, clock=FakeClock())
        store = ControlStore(path)
        try:
            phase1 = control_state_target(self.manifest.entry("OPENCLAW.PHASE1.OPS_BRIEFING"))
            phase1["active_execution_id"] = result.execution_id
            phase1["authority_fingerprint"] = control_state_authority_fingerprint(phase1)
            with self.assertRaisesRegex(StoreError, "DEFERRED_EXECUTION_FORBIDDEN"):
                store.reconcile_slice_control_state(
                    phase1,
                    0,
                    operation_key("e1-deferred-execution", {"slice_id": phase1["slice_id"]}),
                    reason_code="TEST_GUARD",
                )

            cp_row = dict(store.get_slice_control_state(CP_SLICE_ID))
            cp_target = {field: cp_row[field] for field in CONTROL_STATE_INPUT_FIELDS}
            cp_target["active_execution_id"] = "different-execution"
            cp_target["authority_fingerprint"] = control_state_authority_fingerprint(cp_target)
            with self.assertRaisesRegex(StoreError, "ACTIVE_EXECUTION_REBIND_FORBIDDEN"):
                store.reconcile_slice_control_state(
                    cp_target,
                    cp_row["state_version"],
                    operation_key("e1-rebind", {"slice_id": CP_SLICE_ID}),
                    reason_code="TEST_REBIND",
                )
        finally:
            store.close()

    def test_authority_fingerprint_and_snapshot_material_are_canonical(self) -> None:
        first = control_state_target(self.manifest.entry("OPENCLAW.PHASE2A.PHOTO_REVIEW"))
        second = control_state_target(self.manifest.entry("OPENCLAW.PHASE2A.PHOTO_REVIEW"))
        self.assertEqual(first, second)
        self.assertEqual(first["authority_fingerprint"], control_state_authority_fingerprint(first))
        rows = [{**first, "state_version": 0}]
        self.assertEqual(control_snapshot_material(rows), control_snapshot_material(reversed(rows)))

    def test_v3_exposes_guarded_authority_switch_and_rejects_direct_update(self) -> None:
        path = self.root / "e1" / "control.sqlite3"
        seed_isolated_five_slice_control_state(path, self.manifest, self.binding, clock=FakeClock())
        store = ControlStore(path)
        try:
            self.assertTrue(callable(store.switch_control_authority))
            self.assertTrue(callable(store.rollback_control_authority))
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "AUTHORITY_TRANSITION_EVENT_REQUIRED"
            ):
                store.connection.execute(
                    """UPDATE control_authority_state
                       SET mode = 'CONTROL_STORE_AUTHORITY', authority_generation = authority_generation + 1,
                           cutover_id = 'unauthorized', switched_at = 'now'
                     WHERE singleton_id = 'GLOBAL'"""
                )
            self.assertEqual("TRANSITIONAL_AUTHORITY", store.get_control_authority_state()["mode"])
            with self.assertRaisesRegex(StoreError, "STALE_AUTHORITY_GENERATION"):
                store.reconcile_transitional_authority(
                    0,
                    "a" * 64,
                    "b" * 64,
                )
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
