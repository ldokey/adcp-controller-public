from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
import json
import hashlib
import os
import plistlib
import sqlite3
import tempfile

import adcp.cleaner_cutover_control as c
import adcp.production_schema10_operational as schema10
from adcp.production_dcs_v8_adoption import ProductionDcsV8AdoptionError
from adcp.runtime_artifact_attestation import RuntimeArtifactAttestationError


ZERO = dict(receipts=0, reservations=0, domain_events=0, outbox=0)


@dataclass
class FakeEntry:
    writer_id: str
    launchd_label: str
    state: str
    load_state: str
    enabled_state: str
    pid: int | None
    stable_identity: str
    plist_sha256: str
    product_build_commit: str
    product_build_identity: str
    process_incarnation_id: str
    service_config_fingerprint: str = "fingerprint"
    program_arguments: tuple = ("python",)
    startup_resolution: object = None


def entries(active=False):
    result = []
    for w in ("W01", "W02", "W03", "W04", "W05", "W06", "W07"):
        live = w == "W02" or (w == "W07" and active)
        result.append(FakeEntry(writer_id=w,
            launchd_label=c._FIXED_LABELS.get(w, "com.propertyai.telegram-ops"),
            state="ACTIVE" if live else "INACTIVE", load_state="LOADED" if live else "UNLOADED",
            enabled_state="ENABLED" if live else "DISABLED", pid=77 if live else None,
            stable_identity=w, plist_sha256=w, product_build_commit=c._DL98_PRODUCT_COMMIT,
            product_build_identity="product", process_incarnation_id="incarnation"))
    return SimpleNamespace(entries=tuple(result))


class W07RuntimeArtifactAttestorWiringTests(TestCase):
    INTERPRETER = Path("/Users/kate/PropertyAI/openclaw-workspace/gmail_ingest/.venv/bin/python")

    def _entry(self, root: Path, *, active: bool, writer_id: str = "W07", client=None):
        label = c._FIXED_LABELS.get(writer_id, "com.propertyai.telegram-ops")
        plist = root / f"{label}.plist"
        interpreter = self.INTERPRETER if writer_id == "W07" else Path("/usr/bin/true")
        arguments = (str(interpreter), "-m", f"fixture.{writer_id.lower()}")
        plist.write_bytes(
            plistlib.dumps(
                {
                    "Label": label,
                    "ProgramArguments": list(arguments),
                    "WorkingDirectory": str(root),
                    "EnvironmentVariables": {},
                }
            )
        )
        if client is None:
            client = c._parse_client_identity(c._AUTHORIZED_THIN_STARTUP_V10.client_build_identity)
        live = active
        return c.DcsWriterInventoryEntry(
            writer_id=writer_id,
            launchd_label=label,
            service_code=(c._W07_SERVICE_CODE if writer_id == "W07" else f"SERVICE_{writer_id}"),
            runtime_identity_path=root / f"{writer_id}.runtime.json",
            authorized_identity_path=root / f"{writer_id}.authorized.json",
            pid=77 if live else None,
            process_incarnation_id="incarnation-77" if live else "",
            product_build_commit=(c._W07_CURRENT_PRODUCT_COMMIT if writer_id == "W07" else "a" * 40),
            product_build_identity="product",
            source_root_or_artifact_identity="source-commit:" + (c._W07_CURRENT_PRODUCT_COMMIT if writer_id == "W07" else "a" * 40),
            client=client,
            state="ACTIVE" if live else "INACTIVE",
            service_config_fingerprint=f"fingerprint-{writer_id}",
            runtime_state="ACTIVE" if live else "INACTIVE",
            load_state="LOADED" if live else "UNLOADED",
            enabled_state="ENABLED" if live else "DISABLED",
            plist_path=plist,
            plist_realpath=plist.resolve(strict=True),
            plist_sha256=hashlib.sha256(plist.read_bytes()).hexdigest(),
            program_arguments=arguments,
            working_directory=str(root),
        )

    def _authority(self, root: Path, *, provider=False):
        runtime = root / "runtime"
        runtime.mkdir(exist_ok=True)
        authority = c._LaunchdWriterAuthority(
            dcs_path=root / "control.sqlite3",
            launch_agents_root=root,
            runtime_root=runtime,
            uid=os.getuid(),
        )
        if provider:
            c._wire_w07_runtime_artifact_attestor(authority)
        return authority

    def _stopped_port(self, root: Path):
        authority = self._authority(root, provider=True)
        entries_ = []
        for writer in ("W01", "W02", "W03", "W04", "W05", "W06", "W07"):
            entries_.append(self._entry(root, active=(writer == "W02"), writer_id=writer))
            (authority.runtime_root / f"{writer}.authorized.json").write_text("{}")
        inventory = c.DcsWriterInventory(tuple(entries_), "inventory")
        authority.discover = Mock(return_value=inventory)
        authority._service_definition_for_entry = Mock(
            side_effect=lambda entry, **_kw: (entry.plist_path, entry.program_arguments)
        )
        authority.process_scan = Mock(
            side_effect=lambda arguments: tuple(
                entry.pid
                for entry in inventory.entries
                if entry.program_arguments == tuple(arguments) and entry.pid is not None
            )
        )
        port = object.__new__(c.LaunchdCleanerRuntimePort)
        port.authority = authority
        port.product_commit = c._TELEGRAM_T1_W07_PRODUCT_COMMIT
        port.validate_activation_binding = Mock()
        port._validate_w07_prior_definition = Mock()
        return port, inventory

    def test_runtime_port_constructor_wires_exact_accepted_provider(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root)
            head = "a" * 40
            with patch.object(
                c.subprocess,
                "run",
                side_effect=[SimpleNamespace(stdout=head + "\n"), SimpleNamespace(stdout="")],
            ):
                port = c.LaunchdCleanerRuntimePort(
                    authority,
                    product_release_root=root,
                    product_commit=head,
                    runtime_environment={},
                    dcs_schema_version=10,
                )
            self.assertIs(port.authority, authority)
            self.assertIs(
                authority.runtime_artifact_attestation,
                schema10._attest_schema9_10_runtime_artifact,
            )

    def test_real_w07_no_provider_reproduces_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root)
            entry = self._entry(root, active=True)
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority._require_restore_client_compatible(entry, 10)
            self.assertEqual(
                "PRODUCTION_DCS_WRITER_V10_RUNTIME_ARTIFACT_ATTESTATION_MISSING",
                caught.exception.code,
            )

    def test_w07_accepted_provider_active_predecessor_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root, provider=True)
            entry = self._entry(root, active=True)
            attestation = authority._require_restore_client_compatible(entry, 10)
            self.assertEqual("0.5.0", attestation.installed_version)
            self.assertEqual(schema10.V05_SOURCE, attestation.installed_source_commit)
            facts = json.loads(attestation.binding_facts_json)
            self.assertEqual("W07", facts["writer"])
            self.assertEqual(entry.launchd_label, facts["label"])
            self.assertEqual(entry.program_arguments[0], facts["interpreter"])
            self.assertEqual(entry.process_incarnation_id, facts["incarnation"])

    def test_w07_accepted_provider_stopped_staging_baseline_passes_real_gate(self):
        with tempfile.TemporaryDirectory() as td:
            port, inventory = self._stopped_port(Path(td))
            observed = port.readback_w07_staging_baseline()
            self.assertIs(observed, inventory)
            port.authority._require_restore_client_compatible(
                port._inventory_entry(observed, "W07"), 10
            )

    def test_accepted_wheel_sha_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root, provider=True)
            entry = self._entry(root, active=True)
            with patch.object(schema10, "V05_SHA256", "0" * 64):
                with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                    authority._require_restore_client_compatible(entry, 10)
            self.assertEqual(
                "PRODUCTION_DCS_WRITER_V10_RUNTIME_ARTIFACT_ATTESTATION_FAILED",
                caught.exception.code,
            )
            self.assertIsInstance(caught.exception.__cause__, RuntimeArtifactAttestationError)
            self.assertEqual(
                "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
                caught.exception.__cause__.code,
            )

    def test_interpreter_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root, provider=True)
            entry = self._entry(root, active=True)
            entry = replace(
                entry,
                program_arguments=(str(root / "missing-python"), "-m", "fixture.worker"),
            )
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority._require_restore_client_compatible(entry, 10)
            self.assertEqual(
                "PRODUCTION_DCS_WRITER_V10_RUNTIME_ARTIFACT_ATTESTATION_FAILED",
                caught.exception.code,
            )
            self.assertIsInstance(caught.exception.__cause__, RuntimeArtifactAttestationError)
            self.assertEqual(
                "ARTIFACT_ATTESTATION_INTERPRETER_MISSING",
                caught.exception.__cause__.code,
            )

    def test_wrong_thin_or_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root, provider=True)
            entry = self._entry(root, active=True)
            wrong_client = c._parse_client_identity(
                "adcp-global-writer-client@0.5.0+gffffffffffff"
                "|source=" + "f" * 40 + "|artifact=source-commit:" + "f" * 40
            )
            with self.subTest("wrong thin"):
                with self.assertRaises(ProductionDcsV8AdoptionError):
                    authority._require_restore_client_compatible(
                        replace(entry, client=wrong_client), 10
                    )
            with self.subTest("unsupported schema"):
                with self.assertRaises(ProductionDcsV8AdoptionError):
                    authority._require_restore_client_compatible(entry, 11)

    def test_w07_staging_cannot_begin_until_attestation_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port, _inventory = self._stopped_port(root)
            baseline = port.readback_w07_staging_baseline()

            def fail_attestation(_entry, _schema):
                raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_INTERPRETER_MISSING")

            port.authority.runtime_artifact_attestation = fail_attestation
            port._render = Mock()
            port._atomic_replace = Mock()
            with patch.object(c, "revalidate_current_controlled_deployment_lease"):
                with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                    port.stage_w07_only(baseline)
            self.assertEqual(
                "PRODUCTION_DCS_WRITER_V10_RUNTIME_ARTIFACT_ATTESTATION_FAILED",
                caught.exception.code,
            )
            port._render.assert_not_called()
            port._atomic_replace.assert_not_called()

    def test_w07_wiring_rejects_arbitrary_provider(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            authority = self._authority(root)
            authority.runtime_artifact_attestation = lambda _entry, _schema: object()
            with self.assertRaisesRegex(
                c.CleanerCutoverControlError, "CLEANER_W07_RUNTIME_ARTIFACT_ATTESTOR_INVALID"
            ):
                c._wire_w07_runtime_artifact_attestor(authority)


class W07PhysicalTests(TestCase):
    def port(self, active=False):
        port = object.__new__(c.LaunchdCleanerRuntimePort)
        inv = entries(active)
        port.product_commit=c._DL98_PRODUCT_COMMIT
        port.validate_activation_binding=Mock()
        port.authority=SimpleNamespace(discover=Mock(return_value=inv),
            _service_definition_for_entry=Mock(side_effect=lambda e:(None,(e.writer_id,))),
            process_scan=Mock(side_effect=lambda args: tuple(e.pid for e in inv.entries if e.writer_id==args[0] and e.pid)),
            _require_restore_client_compatible=Mock())
        return port, inv

    def test_stopped_or_only_w07_active_and_other_processes_forbidden(self):
        for active in (False,True):
            port,inv=self.port(active)
            self.assertIs(port.readback_w07_only(active=active), inv)
            inv.entries[0].pid=99
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"PROCESS_ISOLATION"):
                port.readback_w07_only(active=active)

    def test_w02_identity_and_other_cleaner_topology_drift_reject(self):
        port,inv=self.port(True)
        baseline=entries(True)
        inv.entries[1].plist_sha256="changed"
        with self.assertRaisesRegex(c.CleanerCutoverControlError,"UNRELATED_WRITER_CHANGED"):
            port.readback_w07_only(baseline,active=True)
        inv.entries[1].plist_sha256="W02"
        inv.entries[2].load_state="LOADED"
        with self.assertRaisesRegex(c.CleanerCutoverControlError,"ISOLATION_INVALID"):
            port.readback_w07_only(baseline,active=True)

    def test_active_recovery_selects_only_w07_and_checks_database_before_resume(self):
        port,_=self.port()
        stopped=entries()
        entry=stopped.entries[-1]
        order=[]
        port.readback_w07_only=Mock(side_effect=[stopped,entries(True)])
        port._postcutover_entry=Mock(return_value=entry)
        port.verify_w07_database_runtime=Mock(side_effect=lambda i:order.append("database"))
        port.authority.resume_fenced=Mock(side_effect=lambda *a,**k:order.append("resume"))
        port.authority._wait_for_stable_active_resume=Mock(return_value={"W07":entry})
        port.authority._active_resume_pending={"W07":entry}
        with patch.object(c,"revalidate_current_controlled_deployment_lease"):
            port.activate_w07_only(stopped)
        self.assertEqual(order,["database","resume"])
        token=port.authority.resume_fenced.call_args.args[0]
        self.assertEqual([e.writer_id for e in token.before.entries],["W07"])
        self.assertEqual(token.before_classes,(("W07","A"),))
        port.verify_w07_database_runtime.side_effect=ValueError("wrong worker ACL")
        port.readback_w07_only.side_effect=None
        port.readback_w07_only.return_value=stopped
        port.authority.resume_fenced.reset_mock()
        with patch.object(c,"revalidate_current_controlled_deployment_lease"):
            with self.assertRaises(ValueError):port.activate_w07_only(stopped)
        port.authority.resume_fenced.assert_not_called()

    def test_full_acl_probe_requires_exact_worker_contract_and_hides_driver_errors(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);path=root/"w07.plist"
            path.write_bytes(plistlib.dumps({"EnvironmentVariables":{c._W07_CREDENTIAL_ENV:c._W07_CREDENTIAL_REF}}))
            port,_=self.port();port.product_release_root=root
            port.authority._service_definition_for_entry.return_value=(path,("python",))
            port.authority._service_definition_for_entry.side_effect=None
            good=dict(status="PASS",session_user="propertyai_cleaner_worker",current_user="propertyai_async_worker",
                database_name="propertyai_cleaner_prod",credential_ref=c._W07_CREDENTIAL_REF,privilege_contract="W07_FROZEN_V221")
            with patch.object(c.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=json.dumps(good))) as run:
                self.assertEqual(port.verify_w07_database_runtime(entries()),good)
                run.assert_called_once()
                run.return_value=SimpleNamespace(returncode=1,stdout="",stderr="SECRET_MARKER")
                with self.assertRaises(c.CleanerCutoverControlError) as err:port.verify_w07_database_runtime(entries())
                self.assertNotIn("SECRET_MARKER",str(err.exception))
                run.return_value=SimpleNamespace(returncode=0,stdout=json.dumps({**good,"current_user":"propertyai_app_runtime"}))
                with self.assertRaises(c.CleanerCutoverControlError):port.verify_w07_database_runtime(entries())
            path.write_bytes(plistlib.dumps({"EnvironmentVariables":{c._W07_CREDENTIAL_ENV:c._W07_CREDENTIAL_REF,"PROPERTYAI_CLEANER_POSTGRES_APP_SESSION_USER":"propertyai_cleaner_app"}}))
            with patch.object(c.subprocess,"run") as run:
                with self.assertRaisesRegex(c.CleanerCutoverControlError,"CREDENTIAL_BINDING_INVALID"):port.verify_w07_database_runtime(entries())
                run.assert_not_called()


class W07F903AuthorityTests(TestCase):
    @staticmethod
    def build_identity_payload() -> bytes:
        source = c._TELEGRAM_T1_W07_PRODUCT_COMMIT
        artifact = f"source-commit:{source}"
        return (
            '"""Generated Product runtime provenance. Do not edit at runtime."""\n\n'
            "PRODUCT_IDENTITY_MODULE = 'propertyai_core._global_writer_build_identity'\n"
            "PRODUCT_NAME = 'PropertyAI'\n"
            f"PRODUCT_BUILD_COMMIT = '{source}'\n"
            f"SOURCE_ARTIFACT_IDENTITY = '{artifact}'\n"
            f"PRODUCT_BUILD_IDENTITY = 'product:PropertyAI@g{source[:12]}"
            f"|source={source}|artifact={artifact}'\n"
        ).encode("utf-8")

    def port(self, root: Path) -> c.LaunchdCleanerRuntimePort:
        port = object.__new__(c.LaunchdCleanerRuntimePort)
        port.product_release_root = root
        port.product_commit = c._TELEGRAM_T1_W07_PRODUCT_COMMIT
        port.dcs_schema_version = 10
        return port

    @staticmethod
    def git_result(commit: str, tree: str, *, dirty: str = ""):
        return [
            SimpleNamespace(stdout=f"{commit}\n{tree}\n"),
            SimpleNamespace(stdout=dirty),
        ]

    def test_exact_f903_target_tree_and_build_identity_admitted_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "propertyai_core").mkdir()
            identity = root / "propertyai_core" / "_global_writer_build_identity.py"
            payload = self.build_identity_payload()
            self.assertEqual(
                c._TELEGRAM_T1_W07_BUILD_IDENTITY_SHA256,
                hashlib.sha256(payload).hexdigest(),
            )
            identity.write_bytes(payload)
            port = self.port(root)
            exact = self.git_result(
                c._TELEGRAM_T1_W07_PRODUCT_COMMIT,
                c._TELEGRAM_T1_W07_PRODUCT_TREE,
            )
            with patch.object(c.subprocess, "run", side_effect=exact):
                port.validate_activation_binding()

            wrong_tree = self.git_result(
                c._TELEGRAM_T1_W07_PRODUCT_COMMIT,
                "f" * 40,
            )
            with patch.object(c.subprocess, "run", side_effect=wrong_tree):
                with self.assertRaisesRegex(c.CleanerCutoverControlError, "PRODUCT_TREE_DRIFT"):
                    port.validate_activation_binding()

            identity.write_bytes(b"wrong build identity")
            exact = self.git_result(
                c._TELEGRAM_T1_W07_PRODUCT_COMMIT,
                c._TELEGRAM_T1_W07_PRODUCT_TREE,
            )
            with patch.object(c.subprocess, "run", side_effect=exact):
                with self.assertRaisesRegex(c.CleanerCutoverControlError, "BUILD_IDENTITY_DRIFT"):
                    port.validate_activation_binding()

            port.product_commit = "f" * 40
            with self.assertRaisesRegex(c.CleanerCutoverControlError, "RUNTIME_AUTHORITY_REQUIRED"):
                port.validate_activation_binding()
            port.product_commit = c._TELEGRAM_T1_W07_PRODUCT_COMMIT
            port.dcs_schema_version = 9
            with self.assertRaisesRegex(c.CleanerCutoverControlError, "RUNTIME_AUTHORITY_REQUIRED"):
                port.validate_activation_binding()

    def test_f903_serializer_is_w07_only_and_preserves_exact_schema(self):
        port = object.__new__(c.LaunchdCleanerRuntimePort)
        port.product_commit = c._TELEGRAM_T1_W07_PRODUCT_COMMIT
        payload = port._authorized_identity_payload("W07")
        document = json.loads(payload)
        artifact = f"source-commit:{c._TELEGRAM_T1_W07_PRODUCT_COMMIT}"
        self.assertEqual(
            {
                "authorized_at": None,
                "config_artifact_identity": None,
                "global_writer_client_build": c._AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
                "product_build_commit": c._TELEGRAM_T1_W07_PRODUCT_COMMIT,
                "product_build_identity": (
                    f"product:PropertyAI@g{c._TELEGRAM_T1_W07_PRODUCT_COMMIT[:12]}"
                    f"|source={c._TELEGRAM_T1_W07_PRODUCT_COMMIT}|artifact={artifact}"
                ),
                "schema_version": 2,
                "service_code": c._W07_SERVICE_CODE,
                "source_root_or_artifact_identity": artifact,
            },
            document,
        )
        for writer in ("W01", "W03", "W06"):
            with self.assertRaisesRegex(c.CleanerCutoverControlError, "BINDING_INVALID"):
                port._authorized_identity_payload(writer)
        port.product_commit = c._DL98_PRODUCT_COMMIT
        self.assertEqual(
            c._W07_SERVICE_CODE,
            json.loads(port._authorized_identity_payload("W07"))["service_code"],
        )
        self.assertEqual(
            "PROPERTYAI_W01_GMAIL_INGEST_PROJECTION",
            json.loads(port._authorized_identity_payload("W01"))["service_code"],
        )



class W07PriorStagingTests(TestCase):
    port = W07PhysicalTests.port
    def fixture(self, root):
        port, initial = self.port()
        port.product_release_root = root / "releases" / c._DL98_PRODUCT_COMMIT
        port.authority.launch_agents_root = root / "launch"
        port.authority.runtime_root = root / "runtime"
        port.authority.dcs_path = root / "dcs"
        port.authority.launch_agents_root.mkdir();port.authority.runtime_root.mkdir()
        paths = {}
        for e in initial.entries:
            e.product_build_commit = c._W07_PRIOR_PRODUCT_COMMIT
            e.program_arguments = ("python", e.writer_id)
            p = port.authority.launch_agents_root / f"{e.launchd_label}.plist"
            p.write_bytes(plistlib.dumps({"Label":e.launchd_label,"ProgramArguments":list(e.program_arguments)}))
            e.plist_sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
            paths[e.writer_id]=p
            (port.authority.runtime_root/f"{e.writer_id}.authorized.json").write_bytes(b"prior")
        payload = plistlib.dumps({"Label":c._FIXED_LABELS["W07"],"ProgramArguments":["python","W07"],"WorkingDirectory":str(port.product_release_root)})
        port._render=Mock(return_value=payload)
        port._authorized_identity_payload=Mock(return_value=b"successor")
        port._validate_w07_prior_definition=Mock()
        port._fence_one=Mock()
        def definition(e):
            if hashlib.sha256(paths[e.writer_id].read_bytes()).hexdigest()!=e.plist_sha256:
                raise RuntimeError("definition bytes changed")
            return paths[e.writer_id],e.program_arguments
        port.authority._service_definition_for_entry.side_effect=definition
        def discover():
            raw=paths["W07"].read_bytes()
            auth=(port.authority.runtime_root/"W07.authorized.json").read_bytes()
            if raw==payload:
                if auth!=b"successor":raise RuntimeError("partial startup definition")
                return SimpleNamespace(entries=initial.entries[:-1]+(replace(initial.entries[-1],
                    product_build_commit=c._DL98_PRODUCT_COMMIT,plist_sha256=hashlib.sha256(raw).hexdigest()),))
            return initial
        port.authority.discover.side_effect=discover
        port.authority._launch_state=Mock(side_effect=lambda label,args:SimpleNamespace(
            runtime_state="ACTIVE" if args[-1]=="W02" else "INACTIVE",
            load_state="LOADED" if args[-1]=="W02" else "UNLOADED",pid_field=77 if args[-1]=="W02" else None))
        port.authority._enabled_state=Mock(side_effect=lambda label:"ENABLED" if label=="com.propertyai.telegram-ops" else "DISABLED")
        port.authority.process_scan.side_effect=lambda args:(77,) if args[-1]=="W02" else ()
        return port,initial,paths,payload

    def test_exact_actual_prior_can_stage_new_identity_without_other_definition_changes(self):
        with tempfile.TemporaryDirectory() as td,patch.object(c,"revalidate_current_controlled_deployment_lease"):
            port,old,paths,payload=self.fixture(Path(td))
            untouched={w:p.read_bytes() for w,p in paths.items() if w!="W07"}
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"PRODUCT_DRIFT"):
                port.readback_w07_only()
            baseline=port.readback_w07_staging_baseline()
            result=port.stage_w07_only(baseline)
            self.assertEqual(paths["W07"].read_bytes(),payload)
            self.assertEqual(result["plist_sha256"],hashlib.sha256(payload).hexdigest())
            self.assertEqual(port.readback_w07_only(baseline).entries[-1].product_build_commit,c._DL98_PRODUCT_COMMIT)
            self.assertEqual(untouched,{w:paths[w].read_bytes() for w in untouched})
            self.assertEqual(port.stop_w07_only(baseline)["configuration_status"],"SUCCESSOR_EXACT_STOPPED")
            self.assertEqual(port._fence_one.call_args.args[0].writer_id,"W07")

    def test_unknown_prior_rejected_before_staging_and_prior_can_stop_before_stage(self):
        with tempfile.TemporaryDirectory() as td,patch.object(c,"revalidate_current_controlled_deployment_lease"):
            port,old,paths,payload=self.fixture(Path(td))
            baseline=port.readback_w07_staging_baseline()
            self.assertEqual(port.stop_w07_only(baseline)["configuration_status"],"PRIOR_EXACT_STOPPED")
            old.entries[-1].product_build_commit="f"*40
            before=paths["W07"].read_bytes()
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"PRODUCT_DRIFT"):
                port.stage_w07_only(baseline)
            self.assertEqual(paths["W07"].read_bytes(),before)
            port._render.assert_not_called()

    def test_current_1ab_predecessor_is_additively_admitted_with_exact_tree(self):
        with tempfile.TemporaryDirectory() as td, patch.object(
            c, "revalidate_current_controlled_deployment_lease"
        ):
            port, old, paths, _payload = self.fixture(Path(td))
            old.entries[-1].product_build_commit = c._W07_CURRENT_PRODUCT_COMMIT
            baseline = port.readback_w07_staging_baseline()
            self.assertEqual(c._W07_CURRENT_PRODUCT_COMMIT, baseline.entries[-1].product_build_commit)

        with tempfile.TemporaryDirectory() as td:
            port, old, paths, _payload = self.fixture(Path(td))
            del port._validate_w07_prior_definition
            root = port.product_release_root.parent / c._W07_CURRENT_PRODUCT_COMMIT
            entry = old.entries[-1]
            entry.product_build_commit = c._W07_CURRENT_PRODUCT_COMMIT
            entry.startup_resolution = SimpleNamespace(
                resolved_propertyai_release=root,
                resolved_propertyai_source_commit=c._W07_CURRENT_PRODUCT_COMMIT,
            )
            env = dict(port._expected_startup_environment("W07"))
            env[c._STARTUP_PRODUCT_ROOT_ENV] = str(root)
            env[c._STARTUP_PRODUCT_COMMIT_ENV] = c._W07_CURRENT_PRODUCT_COMMIT
            env[c._AUTHORITY_ENV] = "POSTGRES"
            env[c._TOPOLOGY_ENV] = "POST_CUTOVER_PG"
            paths["W07"].write_bytes(
                plistlib.dumps({"WorkingDirectory": str(root), "EnvironmentVariables": env})
            )
            entry.plist_sha256 = hashlib.sha256(paths["W07"].read_bytes()).hexdigest()
            (port.authority.runtime_root / "W07.authorized.json").write_text("{}")
            port.authority._startup_matches_authorized = Mock(return_value=True)
            exact = [
                SimpleNamespace(
                    stdout=(
                        c._W07_CURRENT_PRODUCT_COMMIT
                        + "\n"
                        + c._W07_CURRENT_PRODUCT_TREE
                        + "\n"
                    )
                ),
                SimpleNamespace(stdout=""),
            ]
            with patch.object(c.subprocess, "run", side_effect=exact):
                port._validate_w07_prior_definition(entry)

    def test_partial_publication_fences_captured_new_definition_without_discovery_success(self):
        with tempfile.TemporaryDirectory() as td,patch.object(c,"revalidate_current_controlled_deployment_lease"):
            port,old,paths,payload=self.fixture(Path(td))
            baseline=port.readback_w07_staging_baseline()
            atomic=port._atomic_replace
            def publish(path,raw):
                if path.name=="W07.authorized.json":raise OSError("disk write failure")
                atomic(path,raw)
            port._atomic_replace=Mock(side_effect=publish)
            with self.assertRaises(OSError):port.stage_w07_only(baseline)
            with self.assertRaisesRegex(RuntimeError,"partial startup"):port.authority.discover()
            port.authority.discover.reset_mock()
            result=port.stop_w07_only(baseline)
            self.assertEqual(result["configuration_status"],"PARTIAL_STAGING_STOPPED_RECONCILIATION_REQUIRED")
            port.authority.discover.assert_not_called()
            self.assertEqual(port._fence_one.call_args.args[0].plist_sha256,hashlib.sha256(payload).hexdigest())
            paths["W07"].write_bytes(b"unknown substituted bytes")
            port._fence_one.reset_mock()
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"STOP_DEFINITION_UNRESOLVED"):
                port.stop_w07_only(baseline)
            port._fence_one.assert_not_called()

    def test_prior_release_tree_startup_and_authorization_are_exact(self):
        with tempfile.TemporaryDirectory() as td:
            port,old,paths,payload=self.fixture(Path(td))
            del port._validate_w07_prior_definition
            root=port.product_release_root.parent/c._W07_PRIOR_PRODUCT_COMMIT
            entry=old.entries[-1]
            entry.startup_resolution=SimpleNamespace(resolved_propertyai_release=root,
                resolved_propertyai_source_commit=c._W07_PRIOR_PRODUCT_COMMIT)
            env=dict(port._expected_startup_environment("W07"))
            env[c._STARTUP_PRODUCT_ROOT_ENV]=str(root);env[c._STARTUP_PRODUCT_COMMIT_ENV]=c._W07_PRIOR_PRODUCT_COMMIT
            env[c._AUTHORITY_ENV]="POSTGRES";env[c._TOPOLOGY_ENV]="POST_CUTOVER_PG"
            paths["W07"].write_bytes(plistlib.dumps({"WorkingDirectory":str(root),"EnvironmentVariables":env}))
            entry.plist_sha256=hashlib.sha256(paths["W07"].read_bytes()).hexdigest()
            (port.authority.runtime_root/"W07.authorized.json").write_text('{}')
            port.authority._startup_matches_authorized=Mock(return_value=True)
            exact=[SimpleNamespace(stdout=c._W07_PRIOR_PRODUCT_COMMIT+'\n'+c._W07_PRIOR_PRODUCT_TREE+'\n'),SimpleNamespace(stdout='')]
            with patch.object(c.subprocess,"run",side_effect=exact):port._validate_w07_prior_definition(entry)
            with patch.object(c.subprocess,"run",side_effect=[SimpleNamespace(stdout=c._W07_PRIOR_PRODUCT_COMMIT+'\n'+'f'*40+'\n'),SimpleNamespace(stdout='')]):
                with self.assertRaisesRegex(c.CleanerCutoverControlError,"SOURCE_AUTHORITY_DRIFT"):port._validate_w07_prior_definition(entry)
            port.authority._startup_matches_authorized.return_value=False
            with patch.object(c.subprocess,"run",side_effect=exact):
                with self.assertRaisesRegex(c.CleanerCutoverControlError,"SOURCE_AUTHORITY_DRIFT"):port._validate_w07_prior_definition(entry)


class W07HealthTests(TestCase):
    def test_health_requires_owner_mode_identity_role_freshness_and_counter(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700)
            port=object.__new__(c.LaunchdCleanerRuntimePort)
            port.authority=SimpleNamespace(runtime_root=root,uid=os.getuid())
            port.product_commit=c._DL98_PRODUCT_COMMIT
            entry=entries(True).entries[-1]
            good=dict(schema_version=1,pid=entry.pid,process_incarnation_id=entry.process_incarnation_id,
                product_build_commit=port.product_commit,product_build_identity=entry.product_build_identity,
                session_user="propertyai_cleaner_worker",current_user="propertyai_async_worker",
                database_name="propertyai_cleaner_prod",credential_ref="cleaner-prod/worker.pgpass",
                privilege_contract="W07_FROZEN_V221",database_health="PASS",
                observed_at=datetime.now(timezone.utc).isoformat(),idle_cycles=2,status="IDLE",writer_lease="RELEASED")
            path=root/"W07.worker-health.json"
            def write(doc):path.write_text(json.dumps(doc));path.chmod(0o600)
            write(good)
            self.assertEqual(port.read_w07_worker_health(entry)["idle_cycles"],2)
            for key,bad in (("pid",78),("session_user","propertyai_cleaner_app"),("current_user","propertyai_app_runtime"),
                ("product_build_commit","f"*40),("process_incarnation_id","old"),("idle_cycles",True),
                ("database_health","FAIL"),("observed_at",(datetime.now(timezone.utc)-timedelta(seconds=30)).isoformat())):
                with self.subTest(key=key):
                    write({**good,key:bad})
                    with self.assertRaises(c.CleanerCutoverControlError):port.read_w07_worker_health(entry)
            write(good);path.chmod(0o644)
            with self.assertRaises(c.CleanerCutoverControlError):port.read_w07_worker_health(entry)
            write(good);root.chmod(0o755)
            with self.assertRaises(c.CleanerCutoverControlError):port.read_w07_worker_health(entry)
            root.chmod(0o700);port.authority.uid=os.getuid()+1
            with self.assertRaises(c.CleanerCutoverControlError):port.read_w07_worker_health(entry)


class W07ExecutorTests(TestCase):
    def test_guards_and_receipt_failure_never_activate_other_writers_or_advance_epoch(self):
        con=sqlite3.connect(":memory:");con.row_factory=sqlite3.Row
        self.addCleanup(con.close)
        con.execute("CREATE TABLE global_production_writer_event(event_type,new_slice_id,prior_slice_id,event_seq)")
        original="CHAT.PROJ.HQ:TK43:DL98:PRODUCTION_AUTHORITY_CUTOVER:V1"
        con.executemany("INSERT INTO global_production_writer_event VALUES(?,?,?,?)",[("ACQUIRE",original,None,1),("RELEASE",None,original,2)])
        req=c.RecoverCleanerPostCasRequest("recovery",original,1,2)
        runtime=Mock();runtime.product_commit=c._DL98_PRODUCT_COMMIT
        runtime.readback_w07_only.return_value=entries()
        runtime.readback_w07_staging_baseline.return_value=entries()
        runtime.stage_w07_only.return_value=dict(plist_sha256="W07",authorized_sha256="authority")
        runtime.activate_w07_only.return_value=entries(True)
        runtime._inventory_entry.side_effect=lambda inv,w:inv.entries[-1]
        runtime.read_w07_worker_health.return_value=dict(status="WAITING_CONTROL",writer_lease="NOT_ACQUIRED")
        runtime.wait_w07_control_health.return_value=dict(status="WAITING_CONTROL",writer_lease="NOT_ACQUIRED")
        epoch=Mock();epoch.read_current.return_value=2
        def deploy(store,**kw):
            result=kw["steps"][0].effect()
            kw["persist_result"]((result,))
        with ExitStack() as stack:
            stack.enter_context(patch.object(c,"run_controlled_deployment",side_effect=deploy))
            stack.enter_context(patch.object(c,"revalidate_current_controlled_deployment_lease"))
            stack.enter_context(patch.object(c,"_verify_w07_dcs_health"))
            proof=stack.enter_context(patch.object(c,"_verify_w07_worker_login"))
            counts=stack.enter_context(patch.object(c,"_read_cleaner_business_effect_counts",return_value=ZERO))
            def execute(persist):return c.execute_cleaner_w07_recovery(SimpleNamespace(connection=con),change_id="change",request=req,authority=Mock(),runtime_port=runtime,epoch_port=epoch,persist_result=persist,control_decision_ref="DL98")
            execute(Mock())
            epoch.advance.assert_not_called()
            runtime.activate_postgres_runtime.assert_not_called()
            with self.assertRaises(c.CleanerCutoverReconciliationRequired) as caught:
                execute(Mock(side_effect=OSError("disk full")))
            self.assertTrue(caught.exception.evidence.safe_quiescence_confirmed)
            runtime.stop_w07_only.assert_called()
            runtime.activate_w07_only.reset_mock()
            counts.return_value={**ZERO,"outbox":1}
            with self.assertRaises(c.CleanerCutoverReconciliationRequired):execute(Mock())
            runtime.activate_w07_only.assert_not_called()
            counts.return_value=ZERO;proof.side_effect=ValueError("wrong identity")
            with self.assertRaises(c.CleanerCutoverReconciliationRequired):execute(Mock())
            runtime.activate_w07_only.assert_not_called()


class W07ObserverTests(TestCase):
    def test_three_idle_observations_and_exact_released_poll_pairs(self):
        con=sqlite3.connect(":memory:");con.row_factory=sqlite3.Row
        self.addCleanup(con.close)
        con.execute("CREATE TABLE global_production_writer_lease(state,owner_id,owner_execution_id,expires_at,resource_key)")
        con.execute("INSERT INTO global_production_writer_lease VALUES('FREE',NULL,NULL,NULL,'GLOBAL_PRODUCTION')")
        con.execute("CREATE TABLE global_production_writer_event(event_seq INTEGER PRIMARY KEY,event_type,new_owner_id,prior_owner_id,new_owner_execution_id,prior_owner_execution_id,from_fencing_token,to_fencing_token,new_writer_class,prior_writer_class)")
        runtime=Mock();runtime.readback_w07_only.return_value=entries(True)
        runtime._inventory_entry.side_effect=lambda inv,w:inv.entries[-1]
        epoch=Mock();epoch.read_current.return_value=2
        n=[0];owner=c._W07_SERVICE_CODE+":77:incarnation"
        def tick(_):
            n[0]+=1;i=n[0]
            con.execute("INSERT INTO global_production_writer_event VALUES(?,?,?,?,?,?,?,?,?,?)",(i*2-1,"ACQUIRE",owner,None,"incarnation",None,i-1,i,"W07",None))
            con.execute("INSERT INTO global_production_writer_event VALUES(?,?,?,?,?,?,?,?,?,?)",(i*2,"RELEASE",None,owner,None,"incarnation",i,i,None,"W07"))
        runtime.read_w07_worker_health.side_effect=lambda e:dict(status="IDLE",writer_lease="RELEASED",idle_cycles=n[0],observed_at=str(n[0]))
        with patch.object(c,"_verify_w07_dcs_health"),patch.object(c,"_read_cleaner_business_effect_counts",return_value=ZERO),patch.object(c.time,"sleep",side_effect=tick):
            result=c.observe_cleaner_w07_no_work(SimpleNamespace(connection=con),runtime_port=runtime,epoch_port=epoch)
        self.assertEqual(result["status"],"PASS_W07_STABLE_NO_WORK")
        self.assertEqual(result["successful_poll_lease_pairs"],3)
        epoch.advance.assert_not_called()
        # Stale IDLE health must not pass even while the process remains active.
        con.execute("DELETE FROM global_production_writer_event");n[0]=0
        runtime.read_w07_worker_health.side_effect=None
        runtime.read_w07_worker_health.return_value=dict(status="IDLE",writer_lease="RELEASED",idle_cycles=1,observed_at="old")
        with patch.object(c,"_verify_w07_dcs_health"),patch.object(c,"_read_cleaner_business_effect_counts",return_value=ZERO),patch.object(c.time,"sleep",side_effect=tick):
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"HEALTH_STALE"):
                c.observe_cleaner_w07_no_work(SimpleNamespace(connection=con),runtime_port=runtime,epoch_port=epoch)
        # Any W08 overlap is rejected before observation or waiting.
        con.execute("UPDATE global_production_writer_lease SET state='HELD',owner_id='W08'")
        with patch.object(c,"_verify_w07_dcs_health"),patch.object(c.time,"sleep") as sleep:
            with self.assertRaisesRegex(c.CleanerCutoverControlError,"GLOBAL_NOT_FREE"):
                c.observe_cleaner_w07_no_work(SimpleNamespace(connection=con),runtime_port=runtime,epoch_port=epoch)
            sleep.assert_not_called()
        con.execute("UPDATE global_production_writer_lease SET state='FREE',owner_id=NULL")
        for mode in ("foreign_owner","wrong_writer_class","takeover"):
            con.execute("DELETE FROM global_production_writer_event");n[0]=0
            runtime.read_w07_worker_health.side_effect=lambda e:dict(status="IDLE",writer_lease="RELEASED",idle_cycles=n[0],observed_at=str(n[0]))
            def bad_tick(value):
                tick(value)
                if mode=="foreign_owner":con.execute("UPDATE global_production_writer_event SET new_owner_id='other' WHERE event_type='ACQUIRE'")
                if mode=="wrong_writer_class":con.execute("UPDATE global_production_writer_event SET new_writer_class='W08' WHERE event_type='ACQUIRE'")
                if mode=="takeover":con.execute("UPDATE global_production_writer_event SET event_type='EXPIRED_TAKEOVER' WHERE event_type='ACQUIRE'")
            with self.subTest(mode=mode),patch.object(c,"_verify_w07_dcs_health"),patch.object(c,"_read_cleaner_business_effect_counts",return_value=ZERO),patch.object(c.time,"sleep",side_effect=bad_tick):
                with self.assertRaisesRegex(c.CleanerCutoverControlError,"LEASE_HISTORY_INVALID"):
                    c.observe_cleaner_w07_no_work(SimpleNamespace(connection=con),runtime_port=runtime,epoch_port=epoch)
