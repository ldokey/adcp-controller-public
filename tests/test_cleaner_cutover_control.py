from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import hashlib
import plistlib
import sqlite3
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from adcp.cleaner_cutover_control import (
    CleanerAuthorityMode,
    CleanerCutbackReconciliationInventory,
    CleanerCutoverActivated,
    CleanerCutoverControlError,
    CleanerCutoverPrepared,
    CleanerCutoverReconciliationRequired,
    CleanerEmergencyCutbackRequest,
    CleanerEmergencyCutbackSourcePrepared,
    CleanerEpochTransition,
    CleanerRuntimeSnapshot,
    CleanerRuntimeTopology,
    CleanerRuntimeTuple,
    LaunchdCleanerRuntimePort,
    PrepareCleanerCutoverRequest,
    RecoverCleanerPostCasRequest,
    execute_cleaner_post_cas_recovery,
    execute_cleaner_postgres_cutover,
    prepare_cleaner_emergency_cutback_source,
    prepare_cleaner_postgres_cutover,
)

from adcp.production_dcs_v8_adoption import DcsWriterInventory, DcsWriterInventoryEntry
from unittest.mock import Mock
from adcp.cleaner_cutover_control import execute_cleaner_post_cas_quiescence


class CleanerPostCasQuiescenceTests(unittest.TestCase):
    order = ("W06", "W01", "W03", "W07", "W04", "W05")

    def test_bootout_error_for_already_absent_target_requires_factual_and_stable_stop(self):
        from adcp.production_dcs_v8_adoption import _LaunchdRuntimeEvidence
        port = object.__new__(LaunchdCleanerRuntimePort)
        entry = SimpleNamespace(writer_id="W04", launchd_label="com.propertyai.cleaning-operations")
        absent = _LaunchdRuntimeEvidence(None, None, False, False, "INACTIVE", "UNLOADED", True)
        order = []
        port.authority = SimpleNamespace(
            uid=501,
            _service_definition_for_entry=Mock(return_value=(Path("exact.plist"),("python","exact"))),
            _launchctl=Mock(side_effect=lambda *args: (order.append(args[0]) or SimpleNamespace(returncode=0 if args[0]=="disable" else 5))),
            _enabled_state=Mock(return_value="DISABLED"),
            _launch_state=Mock(return_value=absent),
            _wait_for_stable_nonrunning=Mock(side_effect=lambda *args, **kwargs: order.append("stable-readback")),
        )
        with patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease") as current:
            port._fence_one(entry)
        self.assertEqual(["disable","bootout","stable-readback"],order)
        self.assertEqual(3,current.call_count)
        port.authority._launch_state.assert_called_once_with(entry.launchd_label,("python","exact"))
        # Stable proof errors (including residual owned processes) must propagate.
        port.authority._wait_for_stable_nonrunning.side_effect=RuntimeError("residual process")
        with patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease"):
            with self.assertRaisesRegex(RuntimeError,"residual process"):
                port._fence_one(entry)

    def test_bootout_error_cannot_hide_loaded_active_ambiguous_or_stale_pid_state(self):
        from adcp.production_dcs_v8_adoption import _LaunchdRuntimeEvidence
        port = object.__new__(LaunchdCleanerRuntimePort)
        entry = SimpleNamespace(writer_id="W04",launchd_label="com.propertyai.cleaning-operations")
        port.authority = SimpleNamespace(
            uid=501,
            _service_definition_for_entry=Mock(return_value=(Path("exact.plist"),("python","exact"))),
            _launchctl=Mock(side_effect=lambda *args: SimpleNamespace(returncode=0 if args[0]=="disable" else 5)),
            _enabled_state=Mock(return_value="DISABLED"),
            _launch_state=Mock(), _wait_for_stable_nonrunning=Mock(),
        )
        states = [
            (None,None,False,False,"INACTIVE","LOADED",True),
            ("running",42,True,True,"ACTIVE","LOADED",True),
            (None,None,False,False,"UNRESOLVED","UNRESOLVED",True),
            (None,42,False,False,"INACTIVE","UNLOADED",True),
            (None,None,False,False,"INACTIVE","UNLOADED",False),
        ]
        with patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease"):
            for state in states:
                with self.subTest(state=state):
                    port.authority._launch_state.return_value=_LaunchdRuntimeEvidence(*state)
                    with self.assertRaisesRegex(CleanerCutoverControlError,"WRITER_BOOTOUT_FAILED"):
                        port._fence_one(entry)
        port.authority._wait_for_stable_nonrunning.assert_not_called()

    def test_definition_binder_rejects_arbitrary_writer_before_filesystem_access(self):
        port = object.__new__(LaunchdCleanerRuntimePort)
        with self.assertRaisesRegex(CleanerCutoverControlError, "WRITER_IDENTITY_INVALID"):
            port._bind_quiescence_definition("W99")

    def port(self):
        from adcp.cleaner_cutover_control import _FIXED_LABELS
        port = object.__new__(LaunchdCleanerRuntimePort)
        entries = {
            writer: SimpleNamespace(
                writer_id=writer, launchd_label=_FIXED_LABELS.get(writer, "com.propertyai.telegram-ops"),
                program_arguments=("python", writer), plist_sha256=writer,
                state="ACTIVE" if writer == "W02" else "INACTIVE",
                load_state="LOADED" if writer == "W02" else "UNLOADED",
                enabled_state="ENABLED" if writer == "W02" else "DISABLED",
                stable_identity=writer, pid=42 if writer == "W02" else None,
            ) for writer in (*self.order, "W02")
        }
        stopped = []
        def discover():
            if stopped != list(self.order):
                raise RuntimeError("W07 spawn scheduled: strict discovery fails before stop")
            return SimpleNamespace(entries=tuple(entries.values()))
        port.authority = SimpleNamespace(
            discover=Mock(side_effect=discover),
            _launch_state=Mock(return_value=SimpleNamespace(runtime_state="ACTIVE", load_state="LOADED", pid_field=42)),
            _enabled_state=Mock(return_value="ENABLED"),
            _service_definition_for_entry=Mock(),
        )
        port.validate_activation_binding = Mock()
        port._bind_quiescence_definition = Mock(side_effect=entries.__getitem__)
        port._fence_one = Mock(side_effect=lambda entry: stopped.append(entry.writer_id))
        return port, entries, stopped

    def test_restart_loop_stops_w06_first_without_pre_stop_discovery_and_preserves_w02(self):
        port, entries, stopped = self.port()
        result = port.quiesce_post_cas_reconciliation()
        self.assertEqual(list(self.order), stopped)
        self.assertTrue(result["w02_unchanged"])
        self.assertNotIn("W02", stopped)
        self.assertEqual(1, port.authority.discover.call_count)

    def test_failure_handler_rebinds_staged_bytes_instead_of_old_snapshot_and_includes_w07(self):
        port, entries, stopped = self.port()
        snapshot = SimpleNamespace(inventory=SimpleNamespace(entries=(entries["W02"],)))
        port.quiesce_after_failed_activation(snapshot)
        self.assertEqual(list(self.order), stopped)
        self.assertEqual(list(self.order), [call.args[0] for call in port._bind_quiescence_definition.call_args_list])

    def test_w07_still_loaded_fails_stopped_postcondition(self):
        port, entries, stopped = self.port()
        entries["W07"].load_state = "LOADED"
        with self.assertRaisesRegex(CleanerCutoverControlError, "QUIESCENCE_FAILED: W07"):
            port.quiesce_post_cas_reconciliation()

    def test_w02_process_change_fails_readback(self):
        port, entries, stopped = self.port()
        port.authority._launch_state.side_effect = [
            SimpleNamespace(runtime_state="ACTIVE", load_state="LOADED", pid=42),
            SimpleNamespace(runtime_state="ACTIVE", load_state="LOADED", pid=43),
        ]
        with self.assertRaisesRegex(CleanerCutoverControlError, "W02_UNRELATED_WRITER_CHANGED"):
            port.quiesce_post_cas_reconciliation()

    def test_definition_drift_prevents_fencing(self):
        port, entries, stopped = self.port()
        port._bind_quiescence_definition.side_effect = CleanerCutoverControlError("DEFINITION_DRIFT")
        with self.assertRaisesRegex(CleanerCutoverControlError, "DEFINITION_DRIFT"):
            port.quiesce_post_cas_reconciliation()
        self.assertEqual([], stopped)

    def test_sealed_operation_rechecks_epoch_effects_and_uses_controlled_w08(self):
        port, entries, stopped = self.port()
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE global_production_writer_event(event_seq INTEGER,event_type TEXT,new_slice_id TEXT,prior_slice_id TEXT)")
        connection.executemany("INSERT INTO global_production_writer_event VALUES(?,?,?,?)", [(1,"ACQUIRE","original",None),(2,"RELEASE",None,"original")])
        epoch = SimpleNamespace(read_current=Mock(return_value=2))
        def runner(_store, **kwargs):
            self.assertEqual("stop", kwargs["deployment_id"])
            step = kwargs["steps"][0]
            self.assertEqual("CLEANER_POST_CAS_RECONCILIATION_QUIESCE", step.name)
            result = step.effect()
            return step.readback(result)
        zero = {"receipts":0,"reservations":0,"domain_events":0,"outbox":0}
        kwargs = dict(change_id="TK-43", request=RecoverCleanerPostCasRequest("stop","original",1,2), authority=object(),runtime_port=port,epoch_port=epoch,persist_result=lambda value: value,control_decision_ref="DL-98")
        with patch("adcp.cleaner_cutover_control.run_controlled_deployment",side_effect=runner), patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease"), patch("adcp.cleaner_cutover_control._read_cleaner_business_effect_counts",return_value=zero):
            execute_cleaner_post_cas_quiescence(SimpleNamespace(connection=connection),**kwargs)
        self.assertEqual(3,epoch.read_current.call_count)
        for current, counts in ((1,zero),(2,{**zero,"receipts":1})):
            port2, _, stopped2 = self.port()
            kwargs["runtime_port"] = port2
            epoch.read_current.return_value=current
            with patch("adcp.cleaner_cutover_control.run_controlled_deployment",side_effect=runner), patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease"), patch("adcp.cleaner_cutover_control._read_cleaner_business_effect_counts",return_value=counts):
                with self.assertRaises(CleanerCutoverControlError):
                    execute_cleaner_post_cas_quiescence(SimpleNamespace(connection=connection),**kwargs)
            self.assertEqual([],stopped2)


class CleanerCutoverModelTests(unittest.TestCase):
    def test_only_valid_effective_runtime_tuples_are_accepted(self):
        legacy = CleanerRuntimeTuple(CleanerAuthorityMode.LEGACY, False, 7, CleanerRuntimeTopology.PRE_CUTOVER)
        pg = CleanerRuntimeTuple(CleanerAuthorityMode.POSTGRES, True, 8, CleanerRuntimeTopology.POST_CUTOVER_PG)
        self.assertEqual("LEGACY", legacy.authority.value)
        self.assertEqual("POSTGRES", pg.authority.value)
        for args in (
            (CleanerAuthorityMode.POSTGRES, False, 8, CleanerRuntimeTopology.POST_CUTOVER_PG),
            (CleanerAuthorityMode.LEGACY, True, 7, CleanerRuntimeTopology.PRE_CUTOVER),
            (CleanerAuthorityMode.POSTGRES, True, 8, CleanerRuntimeTopology.PRE_CUTOVER),
        ):
            with self.assertRaisesRegex(CleanerCutoverControlError, "CLEANER_RUNTIME_TUPLE_INVALID"):
                CleanerRuntimeTuple(*args)

    def test_epoch_transition_is_exact_monotonic_successor_only(self):
        self.assertEqual(12, CleanerEpochTransition(11, 12).target_epoch)
        for target in (10, 11, 13, 20):
            with self.assertRaisesRegex(CleanerCutoverControlError, "CLEANER_EPOCH_SUCCESSOR_REQUIRED"):
                CleanerEpochTransition(11, target)


class CleanerEmergencyCutbackSourceTests(unittest.TestCase):
    def _inventory(self, **overrides):
        values = {
            "postgres_business_commits_since_ponr": 3,
            "command_receipts": 4,
            "outbox_pending": 1,
            "outbox_claimed": 0,
            "outbox_completed": 7,
            "outbox_failed": 1,
            "outbox_pending_reconciliation": 2,
            "notion_effects": 3,
            "calendar_effects": 2,
            "telegram_effects": 4,
            "inventory_evidence_ref": "evidence://tk43/cutback-inventory/sha256:abc",
        }
        values.update(overrides)
        return CleanerCutbackReconciliationInventory(**values)

    def _request(self, **overrides):
        values = {
            "request_id": "TK43-FUTURE-CUTBACK-REQUEST",
            "current_epoch": 17,
            "target_epoch": 18,
            "control_authority_ref": "CHAT.PROJ.HQ:FUTURE:CUTBACK_AUTHORITY",
            "reconciliation_acceptance_ref": "CHAT.PROJ.HQ:FUTURE:CUTBACK_RECONCILIATION",
            "reconciliation_accepted": True,
            "inventory": self._inventory(),
        }
        values.update(overrides)
        return CleanerEmergencyCutbackRequest(**values)

    def test_cutback_source_accepts_only_fresh_monotonic_successor_after_reconciliation(self):
        prepared = prepare_cleaner_emergency_cutback_source(self._request())
        self.assertIsInstance(prepared, CleanerEmergencyCutbackSourcePrepared)
        self.assertEqual("CLEANER_SCHEDULING", prepared.authority_scope)
        self.assertEqual((17, 18), (prepared.current_epoch, prepared.target_epoch))
        self.assertTrue(prepared.reconciliation_accepted)
        self.assertTrue(prepared.writer_fence_required)
        self.assertFalse(prepared.legacy_reactivation_allowed)
        self.assertFalse(prepared.automatic_legacy_failback)
        self.assertTrue(prepared.separate_production_effect_gate_required)

    def test_epoch_decrement_reuse_and_skip_forward_are_rejected(self):
        for target in (16, 17, 19, 25):
            with self.subTest(target=target):
                with self.assertRaisesRegex(
                    CleanerCutoverControlError, "CLEANER_EPOCH_SUCCESSOR_REQUIRED"
                ):
                    self._request(target_epoch=target)

    def test_epoch_advance_alone_never_satisfies_cutback_eligibility(self):
        with self.assertRaisesRegex(
            CleanerCutoverControlError, "CLEANER_CUTBACK_RECONCILIATION_NOT_ACCEPTED"
        ):
            self._request(reconciliation_accepted=False)

    def test_cutback_requires_explicit_control_and_reconciliation_authority_refs(self):
        for field, code in (
            ("control_authority_ref", "CLEANER_CUTBACK_CONTROL_AUTHORITY_REQUIRED"),
            (
                "reconciliation_acceptance_ref",
                "CLEANER_CUTBACK_RECONCILIATION_ACCEPTANCE_REF_REQUIRED",
            ),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CleanerCutoverControlError, code):
                    self._request(**{field: ""})

    def test_cutback_inventory_requires_factual_all_status_summary_and_evidence_ref(self):
        fields = (
            "postgres_business_commits_since_ponr",
            "command_receipts",
            "outbox_pending",
            "outbox_claimed",
            "outbox_completed",
            "outbox_failed",
            "outbox_pending_reconciliation",
            "notion_effects",
            "calendar_effects",
            "telegram_effects",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    CleanerCutoverControlError, "CLEANER_CUTBACK_INVENTORY_COUNT_INVALID"
                ):
                    self._inventory(**{field: -1})
        with self.assertRaisesRegex(
            CleanerCutoverControlError, "CLEANER_CUTBACK_INVENTORY_EVIDENCE_REF_REQUIRED"
        ):
            self._inventory(inventory_evidence_ref="")

    def test_zero_counts_are_valid_when_inventory_factually_proves_absence(self):
        inventory = self._inventory(
            postgres_business_commits_since_ponr=0,
            command_receipts=0,
            outbox_pending=0,
            outbox_claimed=0,
            outbox_completed=0,
            outbox_failed=0,
            outbox_pending_reconciliation=0,
            notion_effects=0,
            calendar_effects=0,
            telegram_effects=0,
        )
        prepared = prepare_cleaner_emergency_cutback_source(
            self._request(inventory=inventory)
        )
        self.assertEqual(inventory.inventory_evidence_ref, prepared.inventory_evidence_ref)
        self.assertFalse(prepared.legacy_reactivation_allowed)

    def test_source_validation_has_no_epoch_runtime_dcs_or_w08_effect_seam(self):
        # The source capability is intentionally pure: its signature accepts only
        # the frozen request and cannot invoke an epoch/runtime/lease effect.
        import inspect

        parameters = tuple(
            inspect.signature(prepare_cleaner_emergency_cutback_source).parameters
        )
        self.assertEqual(("request",), parameters)
        prepared = prepare_cleaner_emergency_cutback_source(self._request())
        self.assertFalse(prepared.legacy_reactivation_allowed)



@dataclass(frozen=True)
class _Snapshot:
    selected_writer_ids: tuple[str, ...] = ("W06", "W01", "W03", "W04", "W05")
    prior_plists: tuple[tuple, ...] = ()


class _Runtime:
    def __init__(self, events): self.events=events; self.snapshot=_Snapshot(); self.restored=False; self.failed_quiesced=False
    def validate_activation_binding(self): self.events.append("binding:exact")
    def quiesce_for_cutover(self): self.events.append("quiesce:W06-first"); return self.snapshot
    def materialize_postgres_runtime(self, snapshot, runtime):
        self.events.append(f"materialize:{runtime.authority.value}:{runtime.pg_ingress_enabled}:{runtime.authority_epoch}")
        return (("W01", "a"*64),("W03", "b"*64))
    def restore_pre_cutover(self, snapshot): self.restored=True; self.events.append("restore:pre-ponr")
    def readback_prepared(self, runtime): self.events.append("readback:prepared"); return {"ok": True, "epoch": runtime.authority_epoch}
    def materialize_w07_authorized_identity(self, snapshot, runtime):
        self.events.append("authorize:W01/W03/W06/W07"); return "c"*64
    def activate_postgres_runtime(self, snapshot, runtime, w07_sha):
        self.events.append("activate:W01/W03/W06/W07"); return {"ok": True, "epoch": runtime.authority_epoch}
    def readback_effective(self, snapshot, runtime, w07_sha):
        self.events.append("readback:effective"); return {"ok": True, "epoch": runtime.authority_epoch}
    def quiesce_after_failed_activation(self, snapshot):
        self.failed_quiesced=True; self.events.append("quiesce:successor-safe")
    def reconcile_post_cas_staged(self, runtime):
        self.events.append(f"reconcile:staged:{runtime.authority_epoch}")
        return self.snapshot, "c"*64


class _Epoch:
    def __init__(self, events, current=8, fail=False): self.events=events; self.current=current; self.fail=fail
    def read_current(self): self.events.append("epoch:read"); return self.current
    def advance(self, transition):
        self.events.append(f"epoch:advance:{transition.current_epoch}->{transition.target_epoch}")
        if self.fail: raise RuntimeError("cas")
        self.current=transition.target_epoch; return self.current


class CleanerCutoverSourceBindingTests(unittest.TestCase):
    def _git_repo(self, root: Path, *, with_runtime_templates: bool = False) -> str:
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(["git", "-C", root, "config", "user.email", "dl77@example.invalid"], check=True)
        subprocess.run(["git", "-C", root, "config", "user.name", "DL77 Test"], check=True)
        (root / "README").write_text("dl77\n")
        if with_runtime_templates:
            templates = {
                "gmail_ingest/com.propertyai.gmail-readonly.plist": (
                    "com.propertyai.gmail-readonly",
                    {
                        "PROPERTYAI_CLEANER_AUTHORITY": "LEGACY",
                        "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "false",
                        "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "0",
                    },
                ),
                "telegram_approval/com.propertyai.telegram-cleaner.plist": (
                    "com.propertyai.telegram-cleaner",
                    {
                        "PROPERTYAI_CLEANER_AUTHORITY": "LEGACY",
                        "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "false",
                        "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "0",
                    },
                ),
                "health_monitor/com.propertyai.health-monitor.plist": (
                    "com.propertyai.health-monitor",
                    {"PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "PRE_CUTOVER"},
                ),
            }
            for rel, (label, env) in templates.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(plistlib.dumps({
                    "Label": label,
                    "ProgramArguments": ["/usr/bin/true"],
                    "WorkingDirectory": str(root),
                    "EnvironmentVariables": env,
                }))
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "fixture"], check=True)
        return subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

    def test_s2_cutover_schema_compatibility_is_finite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            head = self._git_repo(root)
            for schema in (8, 9, 10):
                port = LaunchdCleanerRuntimePort(
                    object(), product_release_root=root, product_commit=head,
                    runtime_environment={}, dcs_schema_version=schema,
                )
                self.assertEqual(schema, port.dcs_schema_version)
            for schema in (7, 11):
                with self.assertRaisesRegex(CleanerCutoverControlError, "SCHEMA_VERSION_UNSUPPORTED"):
                    LaunchdCleanerRuntimePort(
                        object(), product_release_root=root, product_commit=head,
                        runtime_environment={}, dcs_schema_version=schema,
                    )

    def test_product_release_source_requires_exact_clean_git_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            head = self._git_repo(root)
            LaunchdCleanerRuntimePort(
                object(), product_release_root=root, product_commit=head, runtime_environment={}, dcs_schema_version=8
            )
            (root / "README").write_text("drift\n")
            with self.assertRaisesRegex(CleanerCutoverControlError, "CLEANER_PRODUCT_SOURCE_BINDING_DRIFT"):
                LaunchdCleanerRuntimePort(
                    object(), product_release_root=root, product_commit=head, runtime_environment={}, dcs_schema_version=8
                )

    def test_startup_authority_environment_cannot_be_caller_overridden(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root, with_runtime_templates=True)
            authority = SimpleNamespace(
                dcs_path=Path(td) / "control.sqlite3",
                runtime_root=Path(td) / "runtime",
            )
            port = LaunchdCleanerRuntimePort(
                authority,
                product_release_root=root,
                product_commit=head,
                runtime_environment={
                    "W01": {"ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT": "f" * 40}
                },
                dcs_schema_version=10,
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 2, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_RUNTIME_SEALED_ENV_OVERRIDE: W01"
            ):
                port._render("W01", runtime)

    def test_pre_ponr_restore_reinstates_exact_bytes_and_physical_before_class(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root)
            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            prior_path = launch / "com.propertyai.gmail-readonly.plist"
            prior_bytes = b"prior-w01-plist"
            prior_path.write_bytes(b"postgres-staged-bytes")
            staged_w07 = launch / "com.propertyai.cleaner-pg-outbox.plist"
            staged_w07.write_bytes(b"new-w07")
            client = SimpleNamespace(build_identity="thin-client")
            w01 = DcsWriterInventoryEntry(
                writer_id="W01", launchd_label="com.propertyai.gmail-readonly", service_code="GMAIL",
                runtime_identity_path=Path(td) / "w01-runtime.json", authorized_identity_path=Path(td) / "w01-authorized.json",
                pid=123, process_incarnation_id="inc-1", product_build_commit="a" * 40,
                product_build_identity="product", source_root_or_artifact_identity="source",
                client=client, state="ACTIVE", before_class="A", runtime_state="ACTIVE",
                load_state="LOADED", enabled_state="ENABLED", plist_path=prior_path,
            )
            w02 = DcsWriterInventoryEntry(
                writer_id="W02", launchd_label="com.propertyai.telegram-ops", service_code="OPS",
                runtime_identity_path=Path(td) / "w02-runtime.json", authorized_identity_path=Path(td) / "w02-authorized.json",
                pid=None, process_incarnation_id="", product_build_commit="a" * 40,
                product_build_identity="product", source_root_or_artifact_identity="source",
                client=client, state="INACTIVE", before_class="C", runtime_state="INACTIVE",
                load_state="UNLOADED", enabled_state="DISABLED", plist_path=launch / "com.propertyai.telegram-ops.plist",
            )
            inventory = DcsWriterInventory((w01, w02), "before")
            resumed = []
            class Authority:
                launch_agents_root = launch
                def resume_fenced(self, token, **kwargs):
                    resumed.append((token, kwargs))
                def discover(self): return inventory
            port = LaunchdCleanerRuntimePort(
                Authority(), product_release_root=root, product_commit=head,
                runtime_environment={}, dcs_schema_version=8
            )
            snapshot = CleanerRuntimeSnapshot(
                inventory, ("W01",),
                (("W01", prior_path, prior_bytes, hashlib.sha256(prior_bytes).hexdigest()),),
            )
            with patch("adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease", return_value=None):
                port.restore_pre_cutover(snapshot)
            self.assertEqual(prior_bytes, prior_path.read_bytes())
            self.assertFalse(staged_w07.exists())
            self.assertEqual(1, len(resumed))
            self.assertEqual(8, resumed[0][1]["schema_version"])
            self.assertEqual(("W01",), tuple(e.writer_id for e in resumed[0][0].before.entries))

    def test_postgres_runtime_materialization_requires_w07_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root, with_runtime_templates=True)
            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            prior = []
            for writer, label in (
                ("W01", "com.propertyai.gmail-readonly"),
                ("W03", "com.propertyai.telegram-cleaner"),
                ("W06", "com.propertyai.health-monitor"),
            ):
                target = launch / f"{label}.plist"
                target.write_bytes(b"prior")
                prior.append((writer, target, b"prior", __import__("hashlib").sha256(b"prior").hexdigest()))
            runtime_root = Path(td) / "runtime"
            runtime_root.mkdir()
            authority = type("Authority", (), {
                "launch_agents_root": launch,
                "runtime_root": runtime_root,
                "dcs_path": Path(td) / "production.sqlite3",
            })()
            port = LaunchdCleanerRuntimePort(
                authority, product_release_root=root, product_commit=head, runtime_environment={}, dcs_schema_version=8
            )
            snapshot = CleanerRuntimeSnapshot(object(), ("W06", "W01", "W03"), tuple(prior))
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 2, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with patch(
                "adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease",
                return_value=None,
            ):
                with self.assertRaisesRegex(CleanerCutoverControlError, "CLEANER_W07_RUNTIME_SOURCE_MISSING"):
                    port.materialize_postgres_runtime(snapshot, runtime)

    def test_postgres_runtime_materializes_required_w07_and_readback_binds_topology(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            self._git_repo(root, with_runtime_templates=True)
            w07 = root / "propertyai_core/runtime/com.propertyai.cleaner-pg-outbox.plist"
            w07.parent.mkdir(parents=True, exist_ok=True)
            w07.write_bytes(plistlib.dumps({
                "Label": "com.propertyai.cleaner-pg-outbox",
                "ProgramArguments": ["/usr/bin/python3", "-m", "propertyai_core.runtime.cleaner_pg_outbox_service"],
                "WorkingDirectory": str(root),
                "EnvironmentVariables": {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "REPLACE_AT_CUTOVER",
                    "PROPERTYAI_CLEANER_POSTGRES_WORKER_CREDENTIAL_REF": "cleaner-prod/worker.pgpass",
                },
            }))
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "w07 fixture"], check=True)
            head = subprocess.run(
                ["git", "-C", root, "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()

            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            prior = []
            for writer, label in (
                ("W01", "com.propertyai.gmail-readonly"),
                ("W03", "com.propertyai.telegram-cleaner"),
                ("W06", "com.propertyai.health-monitor"),
            ):
                target = launch / f"{label}.plist"
                target.write_bytes(b"prior")
                prior.append((writer, target, b"prior", hashlib.sha256(b"prior").hexdigest()))

            labels = {
                "W01": "com.propertyai.gmail-readonly",
                "W03": "com.propertyai.telegram-cleaner",
                "W04": "com.propertyai.cleaning-operations",
                "W05": "com.propertyai.cleaning-completion",
                "W06": "com.propertyai.health-monitor",
            }
            class Authority:
                launch_agents_root = launch
                runtime_root = Path(td) / "runtime"
                dcs_path = Path(td) / "production.sqlite3"
                def discover(self):
                    return SimpleNamespace(entries=tuple(
                        SimpleNamespace(
                            writer_id=writer, launchd_label=label, state="INACTIVE",
                            runtime_state="INACTIVE", load_state="UNLOADED", enabled_state="DISABLED",
                        )
                        for writer, label in labels.items()
                    ))
                def _launch_state(self, label, arguments):
                    self.last_w07_physical = (label, tuple(arguments))
                    return SimpleNamespace(runtime_state="INACTIVE", load_state="UNLOADED")
                def _enabled_state(self, label):
                    assert label == "com.propertyai.cleaner-pg-outbox"
                    return "DISABLED"
                def _launchctl(self, *args):
                    assert args == ("disable", "gui/501/com.propertyai.cleaner-pg-outbox")
                    return SimpleNamespace(returncode=0)
                uid = 501
            authority = Authority()
            authority.runtime_root.mkdir()
            port = LaunchdCleanerRuntimePort(
                authority,
                product_release_root=root,
                product_commit=head,
                runtime_environment={},
                dcs_schema_version=8,
            )
            snapshot = CleanerRuntimeSnapshot(
                object(), ("W06", "W01", "W03"), tuple(prior)
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 18, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with patch(
                "adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease",
                return_value=None,
            ):
                outputs = port.materialize_postgres_runtime(snapshot, runtime)
            self.assertEqual(("W01", "W03", "W06", "W07"), tuple(item[0] for item in outputs))
            target = launch / "com.propertyai.cleaner-pg-outbox.plist"
            doc = plistlib.loads(target.read_bytes())
            env = doc["EnvironmentVariables"]
            self.assertEqual("POSTGRES", env["PROPERTYAI_CLEANER_AUTHORITY"])
            self.assertEqual("POST_CUTOVER_PG", env["PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY"])
            self.assertEqual("cleaner-prod/worker.pgpass", env["PROPERTYAI_CLEANER_POSTGRES_WORKER_CREDENTIAL_REF"])
            self.assertNotIn("PROPERTYAI_CLEANER_POSTGRES_APP_DSN_PATH", env)
            self.assertNotIn("PROPERTYAI_CLEANER_POSTGRES_APP_SESSION_USER", env)
            self.assertNotIn("PROPERTYAI_CLEANER_POSTGRES_DATABASE", env)
            self.assertEqual(str(root.resolve()), env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"])
            self.assertEqual(head, env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"])
            self.assertEqual(str(authority.dcs_path), env["PROPERTYAI_GLOBAL_WRITER_DCS_PATH"])
            self.assertEqual(
                str(authority.runtime_root / "W07.runtime.json"),
                env["PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH"],
            )
            self.assertEqual(
                str(authority.runtime_root / "W07.authorized.json"),
                env["PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH"],
            )
            self.assertNotIn("REPLACE_AT_CUTOVER", target.read_text())
            readback = port.readback_prepared(runtime)
            self.assertEqual({"W01", "W03", "W06", "W07"}, set(readback["writers"]))
            self.assertEqual({"W01", "W03", "W04", "W05", "W06", "W07"}, set(readback["physical"]))
            self.assertEqual(
                "com.propertyai.cleaner-pg-outbox", authority.last_w07_physical[0]
            )

            target.unlink()
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_PREPARED_PLIST_MISSING: W07"
            ):
                port.readback_prepared(runtime)

    def test_prepared_readback_rejects_w07_topology_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root, with_runtime_templates=True)
            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            for writer, label, env in (
                ("W01", "com.propertyai.gmail-readonly", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W03", "com.propertyai.telegram-cleaner", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W06", "com.propertyai.health-monitor", {
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "POST_CUTOVER_PG",
                }),
                ("W07", "com.propertyai.cleaner-pg-outbox", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "PRE_CUTOVER",
                }),
            ):
                (launch / f"{label}.plist").write_bytes(plistlib.dumps({
                    "Label": label,
                    "EnvironmentVariables": env,
                }))
            port = LaunchdCleanerRuntimePort(
                type("Authority", (), {"launch_agents_root": launch})(),
                product_release_root=root, product_commit=head,
                runtime_environment={}, dcs_schema_version=8,
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 18, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_PREPARED_TOPOLOGY_DRIFT: W07"
            ):
                port.readback_prepared(runtime)


    def test_prepared_readback_rejects_correct_plists_with_wrong_physical_topology(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root, with_runtime_templates=True)
            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            for writer, label, env in (
                ("W01", "com.propertyai.gmail-readonly", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W03", "com.propertyai.telegram-cleaner", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W06", "com.propertyai.health-monitor", {
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "POST_CUTOVER_PG",
                }),
                ("W07", "com.propertyai.cleaner-pg-outbox", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "POST_CUTOVER_PG",
                }),
            ):
                (launch / f"{label}.plist").write_bytes(plistlib.dumps({
                    "Label": label,
                    "ProgramArguments": ["/usr/bin/true"],
                    "EnvironmentVariables": env,
                }))

            labels = {
                "W01": "com.propertyai.gmail-readonly",
                "W03": "com.propertyai.telegram-cleaner",
                "W04": "com.propertyai.cleaning-operations",
                "W05": "com.propertyai.cleaning-completion",
                "W06": "com.propertyai.health-monitor",
                "W07": "com.propertyai.cleaner-pg-outbox",
            }
            class Authority:
                launch_agents_root = launch
                discover_calls = 0
                def discover(self):
                    self.discover_calls += 1
                    entries = []
                    for writer, label in labels.items():
                        wrong = writer == "W04"
                        entries.append(SimpleNamespace(
                            writer_id=writer, launchd_label=label,
                            state="ACTIVE" if wrong else "INACTIVE",
                            runtime_state="ACTIVE" if wrong else "INACTIVE",
                            load_state="LOADED" if wrong else "UNLOADED",
                            enabled_state="ENABLED" if wrong else "DISABLED",
                        ))
                    return SimpleNamespace(entries=tuple(entries))
            authority = Authority()
            port = LaunchdCleanerRuntimePort(
                authority, product_release_root=root, product_commit=head,
                runtime_environment={}, dcs_schema_version=8,
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 18, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_PREPARED_PHYSICAL_TOPOLOGY_DRIFT: W04"
            ):
                port.readback_prepared(runtime)
            self.assertEqual(1, authority.discover_calls)

    def test_prepared_readback_fails_closed_if_physical_discovery_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "product"
            root.mkdir()
            head = self._git_repo(root, with_runtime_templates=True)
            launch = Path(td) / "LaunchAgents"
            launch.mkdir()
            for writer, label, env in (
                ("W01", "com.propertyai.gmail-readonly", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W03", "com.propertyai.telegram-cleaner", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED": "true",
                    "PROPERTYAI_CLEANER_AUTHORITY_EPOCH": "18",
                }),
                ("W06", "com.propertyai.health-monitor", {
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "POST_CUTOVER_PG",
                }),
                ("W07", "com.propertyai.cleaner-pg-outbox", {
                    "PROPERTYAI_CLEANER_AUTHORITY": "POSTGRES",
                    "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY": "POST_CUTOVER_PG",
                }),
            ):
                (launch / f"{label}.plist").write_bytes(plistlib.dumps({
                    "Label": label, "ProgramArguments": ["/usr/bin/true"],
                    "EnvironmentVariables": env,
                }))
            class Authority:
                launch_agents_root = launch
                def discover(self):
                    raise RuntimeError("physical discovery unavailable")
            port = LaunchdCleanerRuntimePort(
                Authority(), product_release_root=root, product_commit=head,
                runtime_environment={}, dcs_schema_version=8,
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 18, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_PREPARED_PHYSICAL_DISCOVERY_FAILED"
            ):
                port.readback_prepared(runtime)


class CleanerCutoverOrchestrationTests(unittest.TestCase):
    def test_prepare_orders_quiesce_epoch_materialization_and_never_activates_business_writer(self):
        events=[]; runtime=_Runtime(events); epoch=_Epoch(events)
        prepared=[]
        result=CleanerCutoverPrepared(
            8,9,CleanerRuntimeTuple(CleanerAuthorityMode.POSTGRES,True,9,CleanerRuntimeTopology.POST_CUTOVER_PG),
            runtime.snapshot.selected_writer_ids,(("W01","a"*64),("W03","b"*64))
        )
        def fake_runner(_store, **kwargs):
            self.assertEqual("op-1", kwargs["deployment_id"])
            item=kwargs["steps"][0]
            actual=item.effect()
            self.assertEqual(result, actual)
            readback=item.readback(actual)
            self.assertEqual({"ok":True,"epoch":9}, readback)
            evidence=(type("E",(),{"effect_result":actual})(),)
            kwargs["persist_result"](evidence)
            return evidence
        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            evidence=prepare_cleaner_postgres_cutover(
                object(), change_id="TK-43", request=PrepareCleanerCutoverRequest("op-1",9),
                authority=object(), runtime_port=runtime, epoch_port=epoch,
                persist_result=lambda items: prepared.append(items), control_decision_ref="DL-77"
            )
        self.assertEqual(
            ["quiesce:W06-first","epoch:read","epoch:advance:8->9","materialize:POSTGRES:True:9","readback:prepared"],
            events,
        )
        self.assertFalse(evidence[0].effect_result.autonomous_business_execution_effective)
        self.assertEqual(1,len(prepared))

    def test_prepare_failure_restores_pre_ponr_runtime_without_epoch_regression(self):
        events=[]; runtime=_Runtime(events); epoch=_Epoch(events, fail=True)
        def fake_runner(_store, **kwargs): return kwargs["steps"][0].effect()
        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            with self.assertRaisesRegex(RuntimeError,"cas"):
                prepare_cleaner_postgres_cutover(
                    object(), change_id="TK-43", request=PrepareCleanerCutoverRequest("op-2",9),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda _items: None, control_decision_ref="DL-77"
                )
        self.assertTrue(runtime.restored)
        self.assertEqual(8, epoch.current)

    def test_skip_forward_target_fails_before_epoch_mutation(self):
        events=[]; runtime=_Runtime(events); epoch=_Epoch(events,current=8)
        def fake_runner(_store, **kwargs): return kwargs["steps"][0].effect()
        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            with self.assertRaisesRegex(CleanerCutoverControlError,"CLEANER_EPOCH_SUCCESSOR_REQUIRED"):
                prepare_cleaner_postgres_cutover(
                    object(), change_id="TK-43", request=PrepareCleanerCutoverRequest("op-3",10),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda _items: None, control_decision_ref="DL-77"
                )
        self.assertNotIn("epoch:advance:8->10", events)
        self.assertTrue(runtime.restored)


class CleanerCutoverActivationTests(unittest.TestCase):
    PRODUCT = "ebd7f756e35610c3ce5a8e33e71fc610e3c84f00"
    THIN = (
        "adcp-global-writer-client@0.5.0+g4e3bd2691b2e"
        "|source=4e3bd2691b2ed58eccb65c32ad127467c89a6ebb"
        "|artifact=source-commit:4e3bd2691b2ed58eccb65c32ad127467c89a6ebb"
    )

    def _entry(self, root: Path, writer: str, label: str):
        return DcsWriterInventoryEntry(
            writer_id=writer,
            launchd_label=label,
            service_code=f"PROPERTYAI_{writer}_TEST",
            runtime_identity_path=root / f"{writer}.runtime.json",
            authorized_identity_path=root / f"{writer}.authorized.json",
            pid=None,
            process_incarnation_id="",
            product_build_commit=self.PRODUCT,
            product_build_identity="product",
            source_root_or_artifact_identity=f"source-commit:{self.PRODUCT}",
            client=SimpleNamespace(build_identity=self.THIN),
            state="INACTIVE",
            before_class="C",
            runtime_state="INACTIVE",
            load_state="UNLOADED",
            enabled_state="DISABLED",
            plist_path=root / f"{label}.plist",
            plist_realpath=root / f"{label}.plist",
            plist_sha256="a" * 64,
            program_arguments=("/usr/bin/true",),
        )

    def test_sealed_activation_uses_exact_a_b_topology_and_leaves_w02_w04_w05_out(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            labels = {
                "W01": "com.propertyai.gmail-readonly",
                "W02": "com.propertyai.telegram-ops",
                "W03": "com.propertyai.telegram-cleaner",
                "W04": "com.propertyai.cleaning-operations",
                "W05": "com.propertyai.cleaning-completion",
                "W06": "com.propertyai.health-monitor",
                "W07": "com.propertyai.cleaner-pg-outbox",
            }
            entries = tuple(self._entry(root, writer, label) for writer, label in labels.items())
            inventory = DcsWriterInventory(entries, "prepared")
            events = []

            class Authority:
                def __init__(self): self._active_resume_pending = {}
                def discover(self): return inventory
                def _require_restore_client_compatible(self, entry, schema):
                    events.append(f"attest:{entry.writer_id}:v{schema}")
                def resume_fenced(self, token, **kwargs):
                    events.append(
                        "resume:" + ",".join(
                            f"{entry.writer_id}:{entry.before_class}" for entry in token.before.entries
                        )
                    )
                    self._active_resume_pending = {
                        entry.writer_id: entry for entry in token.before.entries if entry.before_class == "A"
                    }
                def _wait_for_stable_active_resume(self, entries, *, deadline):
                    events.append("wait:" + ",".join(entry.writer_id for entry in entries))
                    return {entry.writer_id: (100 + index, f"inc-{index}") for index, entry in enumerate(entries)}

            port = object.__new__(LaunchdCleanerRuntimePort)
            port.authority = Authority()
            port.product_commit = self.PRODUCT
            port.dcs_schema_version = 10
            port.readback_prepared = lambda runtime: {"prepared": runtime.authority_epoch}
            effective = {"physical": "exact", "first_business_command_executed": False}
            port.readback_effective = lambda snapshot, runtime, sha: effective
            snapshot = CleanerRuntimeSnapshot(
                DcsWriterInventory(tuple(entry for entry in entries if entry.writer_id != "W07"), "before"),
                ("W06", "W01", "W03", "W04", "W05"),
                (),
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 2, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with patch(
                "adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease",
                return_value=None,
            ):
                self.assertEqual(effective, port.activate_postgres_runtime(snapshot, runtime, "f" * 64))
            self.assertIn("resume:W03:A,W07:A,W01:B,W06:B", events)
            self.assertIn("wait:W03,W07", events)
            self.assertFalse(any("W02" in event or "W04" in event or "W05" in event for event in events))

    def test_authorized_identity_projection_is_exact_finite_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = object.__new__(LaunchdCleanerRuntimePort)
            port.product_commit = self.PRODUCT
            port.dcs_schema_version = 10
            port.authority = SimpleNamespace(runtime_root=root)
            prior = tuple(
                (writer, root / f"{writer}.authorized.json", None, None)
                for writer in ("W01", "W06", "W03", "W07")
            )
            snapshot = CleanerRuntimeSnapshot(
                DcsWriterInventory((), "before"), (), (),
                root / "W07.authorized.json", None, None, prior,
            )
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES, True, 2, CleanerRuntimeTopology.POST_CUTOVER_PG
            )
            with patch(
                "adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease",
                return_value=None,
            ):
                w07_sha = port.materialize_w07_authorized_identity(snapshot, runtime)
            w07 = root / "W07.authorized.json"
            doc = __import__("json").loads(w07.read_bytes())
            self.assertEqual(self.PRODUCT, doc["product_build_commit"])
            self.assertEqual("PROPERTYAI_W07_CORE_OUTBOX_REPLAY", doc["service_code"])
            self.assertEqual(self.THIN, doc["global_writer_client_build"])
            self.assertEqual(hashlib.sha256(w07.read_bytes()).hexdigest(), w07_sha)
            self.assertEqual(0o600, w07.stat().st_mode & 0o777)
            self.assertEqual({"W01", "W03", "W06", "W07"}, {path.stem.split(".")[0] for path in root.glob("*.authorized.json")})

    def test_one_shot_cutover_completes_activation_and_receipt_under_same_runner(self):
        events = []
        runtime = _Runtime(events)
        epoch = _Epoch(events, current=1)
        persisted = []

        def fake_runner(_store, **kwargs):
            step = kwargs["steps"][0]
            actual = step.effect()
            readback = step.readback(actual)
            evidence = (SimpleNamespace(effect_result=actual, readback=readback),)
            kwargs["persist_result"](evidence)
            return evidence

        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            evidence = execute_cleaner_postgres_cutover(
                object(), change_id="TK-43", request=PrepareCleanerCutoverRequest("dl98-op", 2),
                authority=object(), runtime_port=runtime, epoch_port=epoch,
                persist_result=lambda value: persisted.append(value), control_decision_ref="DL-98",
            )
        self.assertIsInstance(evidence[0].effect_result, CleanerCutoverActivated)
        self.assertFalse(evidence[0].effect_result.first_business_command_executed)
        self.assertEqual(1, len(persisted))
        self.assertEqual(
            [
                "binding:exact", "quiesce:W06-first", "epoch:read", "epoch:advance:1->2",
                "materialize:POSTGRES:True:2", "authorize:W01/W03/W06/W07",
                "readback:prepared", "activate:W01/W03/W06/W07",
                "readback:effective", "epoch:read", "readback:effective", "epoch:read",
            ],
            events,
        )

    def test_post_cas_activation_failure_never_restores_legacy_and_requires_reconciliation(self):
        events = []

        class FailedRuntime(_Runtime):
            def activate_postgres_runtime(self, snapshot, runtime, w07_sha):
                self.events.append("activate:failed")
                raise RuntimeError("activation")

        runtime = FailedRuntime(events)
        epoch = _Epoch(events, current=1)

        def fake_runner(_store, **kwargs):
            return kwargs["steps"][0].effect()

        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            with self.assertRaises(CleanerCutoverReconciliationRequired) as caught:
                execute_cleaner_postgres_cutover(
                    object(), change_id="TK-43", request=PrepareCleanerCutoverRequest("dl98-fail", 2),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda value: None, control_decision_ref="DL-98",
                )
        self.assertEqual(2, epoch.current)
        self.assertFalse(runtime.restored)
        self.assertTrue(runtime.failed_quiesced)
        self.assertTrue(caught.exception.evidence.epoch_advanced)
        self.assertEqual("RUNTIME_ACTIVATION", caught.exception.evidence.stage)

    def test_startup_binding_drift_fails_before_quiescence_or_epoch_cas(self):
        events = []

        class DriftedRuntime(_Runtime):
            def validate_activation_binding(self):
                self.events.append("binding:drift")
                raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_BINDING_DRIFT")

        runtime = DriftedRuntime(events)
        epoch = _Epoch(events, current=1)

        def fake_runner(_store, **kwargs):
            return kwargs["steps"][0].effect()

        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_PRODUCT_SOURCE_BINDING_DRIFT"
            ):
                execute_cleaner_postgres_cutover(
                    object(), change_id="TK-43",
                    request=PrepareCleanerCutoverRequest("dl98-binding-drift", 2),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda value: None, control_decision_ref="DL-98",
                )
        self.assertEqual(["binding:drift"], events)
        self.assertEqual(1, epoch.current)

    def test_cas_race_with_factual_old_epoch_restores_exact_pre_cutover_runtime(self):
        events = []
        runtime = _Runtime(events)
        epoch = _Epoch(events, current=1, fail=True)

        def fake_runner(_store, **kwargs):
            return kwargs["steps"][0].effect()

        with patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner):
            with self.assertRaisesRegex(RuntimeError, "cas"):
                execute_cleaner_postgres_cutover(
                    object(), change_id="TK-43",
                    request=PrepareCleanerCutoverRequest("dl98-cas-race", 2),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda value: None, control_decision_ref="DL-98",
                )
        self.assertEqual(1, epoch.current)
        self.assertTrue(runtime.restored)
        self.assertFalse(runtime.failed_quiesced)
        self.assertEqual(
            [
                "binding:exact", "quiesce:W06-first", "epoch:read",
                "epoch:advance:1->2", "epoch:read", "restore:pre-ponr",
            ],
            events,
        )

    def test_post_cas_recovery_activates_exact_epoch_two_without_another_cas(self):
        events = []
        runtime = _Runtime(events)
        epoch = _Epoch(events, current=2)
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE global_production_writer_event (event_seq INTEGER, event_type TEXT, new_slice_id TEXT, prior_slice_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO global_production_writer_event VALUES (?,?,?,?)",
            (
                (1, "ACQUIRE", "original", None),
                (2, "RELEASE", None, "original"),
            ),
        )
        persisted = []

        def fake_runner(_store, **kwargs):
            step = kwargs["steps"][0]
            actual = step.effect()
            readback = step.readback(actual)
            evidence = (SimpleNamespace(effect_result=actual, readback=readback),)
            kwargs["persist_result"](evidence)
            return evidence

        with (
            patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner),
            patch(
                "adcp.cleaner_cutover_control._read_cleaner_business_effect_counts",
                return_value={"receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0},
            ),
        ):
            evidence = execute_cleaner_post_cas_recovery(
                SimpleNamespace(connection=connection),
                change_id="TK-43",
                request=RecoverCleanerPostCasRequest("recovery", "original", 1, 2),
                authority=object(),
                runtime_port=runtime,
                epoch_port=epoch,
                persist_result=lambda value: persisted.append(value),
                control_decision_ref="DL-98",
            )
        self.assertIsInstance(evidence[0].effect_result, CleanerCutoverActivated)
        self.assertEqual(1, len(persisted))
        self.assertFalse(any(event.startswith("epoch:advance") for event in events))
        self.assertIn("reconcile:staged:2", events)
        self.assertEqual(2, epoch.current)

    def test_post_cas_recovery_rejects_business_effect_before_activation(self):
        events = []
        runtime = _Runtime(events)
        epoch = _Epoch(events, current=2)
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE global_production_writer_event (event_seq INTEGER, event_type TEXT, new_slice_id TEXT, prior_slice_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO global_production_writer_event VALUES (?,?,?,?)",
            ((1, "ACQUIRE", "original", None), (2, "RELEASE", None, "original")),
        )

        def fake_runner(_store, **kwargs):
            return kwargs["steps"][0].effect()

        with (
            patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner),
            patch(
                "adcp.cleaner_cutover_control._read_cleaner_business_effect_counts",
                return_value={"receipts": 1, "reservations": 0, "domain_events": 0, "outbox": 0},
            ),
        ):
            with self.assertRaises(CleanerCutoverReconciliationRequired) as caught:
                execute_cleaner_post_cas_recovery(
                    SimpleNamespace(connection=connection),
                    change_id="TK-43",
                    request=RecoverCleanerPostCasRequest("recovery", "original", 1, 2),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=lambda _value: None, control_decision_ref="DL-98",
                )
        self.assertEqual(
            "CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT",
            caught.exception.__cause__.code,
        )
        self.assertNotIn("reconcile:staged:2", events)
        self.assertFalse(any(event.startswith("activate:") for event in events))

    def test_post_cas_recovery_receipt_failure_requiesces_active_runtime(self):
        events = []
        runtime = _Runtime(events)
        epoch = _Epoch(events, current=2)
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE global_production_writer_event (event_seq INTEGER, event_type TEXT, new_slice_id TEXT, prior_slice_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO global_production_writer_event VALUES (?,?,?,?)",
            ((1, "ACQUIRE", "original", None), (2, "RELEASE", None, "original")),
        )

        def fake_runner(_store, **kwargs):
            step = kwargs["steps"][0]
            actual = step.effect()
            step.readback(actual)
            kwargs["persist_result"]((SimpleNamespace(effect_result=actual),))

        def fail_receipt(_value):
            raise OSError("durable receipt failed")

        with (
            patch("adcp.cleaner_cutover_control.run_controlled_deployment", side_effect=fake_runner),
            patch(
                "adcp.cleaner_cutover_control._read_cleaner_business_effect_counts",
                return_value={"receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0},
            ),
        ):
            with self.assertRaises(CleanerCutoverReconciliationRequired) as caught:
                execute_cleaner_post_cas_recovery(
                    SimpleNamespace(connection=connection), change_id="TK-43",
                    request=RecoverCleanerPostCasRequest("recovery", "original", 1, 2),
                    authority=object(), runtime_port=runtime, epoch_port=epoch,
                    persist_result=fail_receipt, control_decision_ref="DL-98",
                )
        self.assertEqual("DURABLE_RECOVERY_RECEIPT", caught.exception.evidence.stage)
        self.assertTrue(caught.exception.evidence.safe_quiescence_confirmed)
        self.assertTrue(runtime.failed_quiesced)

    def test_post_cas_recovery_request_is_fixed_to_original_one_to_two_transition(self):
        self.assertEqual(2, RecoverCleanerPostCasRequest("recovery", "original", 1, 2).successor_epoch)
        for epochs in ((0, 1), (2, 3), (1, 3), (2, 2)):
            with self.assertRaisesRegex(
                CleanerCutoverControlError, "CLEANER_DL98_POST_CAS_RECOVERY_EPOCH_INVALID"
            ):
                RecoverCleanerPostCasRequest("recovery", "original", *epochs)


if __name__ == "__main__":
    unittest.main()
