from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import plistlib
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from adcp.production_dcs_v8_adoption import (
    DcsWriterInventory,
    DcsWriterInventoryEntry,
    DcsWriterStartupResolution,
    ProductionDcsV8AdoptionError,
    ProductionDcsV8AdoptionRequest,
    _DcsProfile,
    _LaunchdWriterAuthority,
    _ProductionDcsV8AdoptionController,
    _QuiescenceToken,
    _W01_RUNTIME_CONFIG_ENV,
    _inventory_fingerprint,
    _parse_client_identity,
    _service_config_fingerprint,
    materialize_w01_startup_plist,
)


PROPERTYAI_SOURCE = "e9adb4f3635e3b13aa22f674487f589befdbbd41"
THIN_SOURCE = "eb06cb8a8c4f6a0a1534b9bd9d5c49cec54fe79c"
THIN_VERSION = "0.3.0"
THIN_BUILD_ID = "adcp-global-writer-client@0.3.0+geb06cb8a8c4f"
THIN_ARTIFACT = f"source-commit:{THIN_SOURCE}"
THIN_BUILD = f"{THIN_BUILD_ID}|source={THIN_SOURCE}|artifact={THIN_ARTIFACT}"
SCHEMA_IDENTITY = "sha256:b5601f47b0447e5ad47a7a1d5cee7d20692c96b5105b925ed71cd4ddfe98ba6b"
CURRENT_PROPERTYAI_SOURCE = "379801b5bbb68549ebdb1dbf12621c6ad38b7652"
CURRENT_THIN_SOURCE = "23ce586dd369a60ac7bbbd24b33175deb05a402d"
CURRENT_THIN_VERSION = "0.4.0"
CURRENT_THIN_BUILD_ID = "adcp-global-writer-client@0.4.0+g23ce586dd369"
CURRENT_THIN_ARTIFACT = f"source-commit:{CURRENT_THIN_SOURCE}"
CURRENT_THIN_BUILD = (
    f"{CURRENT_THIN_BUILD_ID}|source={CURRENT_THIN_SOURCE}|artifact={CURRENT_THIN_ARTIFACT}"
)
CURRENT_SCHEMA_IDENTITY = "sha256:1deb066c05c1cfec1b5945e8e2b31bfd212eb80bd4021b0696ee1ee93364a0f6"
PRODUCTION_PROPERTYAI_SOURCE = "1496d9ea5f4b91df2958d948970e859f790fa7f5"
DL95_RECOVERY_PROPERTYAI_SOURCE = "45dafdcbaecd32a929d4b2a87bc9ec3eb5548af4"
DL98_CUTOVER_PROPERTYAI_SOURCE = "9e50c7306752961f18ee4d0ef0ecb5a7f0dea6c7"
TELEGRAM_T1_W07_PREDECESSOR_SOURCE = "1ab6715b413d5befe1e93c7628efe49f9d6e76c2"
TELEGRAM_T1_W07_PROPERTYAI_SOURCE = "f90303f95cf4df772c7a89dd90cf589fa6620f27"
TARGET_THIN_SOURCE = "4e3bd2691b2ed58eccb65c32ad127467c89a6ebb"
TARGET_THIN_VERSION = "0.5.0"
TARGET_THIN_BUILD_ID = "adcp-global-writer-client@0.5.0+g4e3bd2691b2e"
TARGET_THIN_ARTIFACT = f"source-commit:{TARGET_THIN_SOURCE}"
TARGET_THIN_BUILD = (
    f"{TARGET_THIN_BUILD_ID}|source={TARGET_THIN_SOURCE}|artifact={TARGET_THIN_ARTIFACT}"
)
TARGET_SCHEMA_IDENTITY = "sha256:288a69e75d8bd4399bbac1973a8632d54a79c0052debec79636a184b715db2a5"
WRONG_SCHEMA_IDENTITY = "sha256:" + "5" * 64
LEGACY_PRODUCT = "f5083587e73728fae4a847d18c2f55433277f087"
LEGACY_THIN_SOURCE = "267d79e3122da1eae0233e462326f8d096122d07"
V6_SCHEMA_IDENTITY = "sha256:047dd3c4cb1449bd428c0c8519f2baf29e876a9a96e5427767a577f5d5be94dd"
SERVICE_CODE = "PROPERTYAI_W05_CLEANING_COMPLETION_DISPATCH"
SERVICE_LABEL = "com.propertyai.cleaning-completion"


def product_identity(source: str) -> str:
    artifact = f"source-commit:{source}"
    return f"product:PropertyAI@g{source[:12]}|source={source}|artifact={artifact}"


def client_build(version: str, source: str) -> str:
    build_id = f"adcp-global-writer-client@{version}+g{source[:12]}"
    return f"{build_id}|source={source}|artifact=source-commit:{source}"


class LaunchctlRecorder:
    def __init__(
        self,
        states: list[bool] | None = None,
        *,
        pid: int = 4242,
        declared_states: list[str] | None = None,
        include_pid: bool = True,
        pid_live: bool = True,
        pid_service_owned: bool = True,
        disabled: bool | None = None,
    ) -> None:
        self.states = list(states or [False])
        self.declared_states = list(declared_states or [])
        self.include_pid = include_pid
        self.pid_live = pid_live
        self.pid_service_owned = pid_service_owned
        self.pid = pid
        first_active = bool(self.states[0]) or bool(self.declared_states and self.declared_states[0] == "running")
        self.disabled = (not first_active) if disabled is None else disabled
        self.last_label = SERVICE_LABEL
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args, **_kwargs):
        call = tuple(str(value) for value in args)
        self.calls.append(call)
        if len(call) >= 3 and call[1] in {"print", "disable", "enable", "bootout", "kickstart"}:
            target = call[2]
            if target.startswith("gui/") and target.count("/") >= 2:
                self.last_label = target.rsplit("/", 1)[-1]
        if len(call) >= 2 and call[1] == "disable":
            self.disabled = True
        elif len(call) >= 2 and call[1] == "enable":
            self.disabled = False
        if len(call) >= 2 and call[1] == "print-disabled":
            value = "true" if self.disabled else "false"
            return subprocess.CompletedProcess(call, 0, f'{{ "{self.last_label}" => {value} }}\n', "")
        if len(call) >= 2 and call[1] == "print":
            if self.declared_states:
                declared = (
                    self.declared_states.pop(0)
                    if len(self.declared_states) > 1
                    else self.declared_states[0]
                )
                pid_line = f"    pid = {self.pid}\n" if self.include_pid else ""
                return subprocess.CompletedProcess(
                    call, 0, f"    state = {declared}\n{pid_line}", ""
                )
            active = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            if active:
                return subprocess.CompletedProcess(
                    call, 0, f"    state = running\n    pid = {self.pid}\n", ""
                )
            return subprocess.CompletedProcess(call, 113, "", "not loaded")
        return subprocess.CompletedProcess(call, 0, "", "")

    def process_probe(self, pid: int, _expected_arguments) -> tuple[bool, bool]:
        if pid != self.pid:
            return False, False
        return self.pid_live, self.pid_live and self.pid_service_owned

    @property
    def process_start_count(self) -> int:
        return sum("kickstart" in call for call in self.calls)

    @property
    def mutation_call_count(self) -> int:
        mutations = {"enable", "disable", "kickstart", "kill", "bootout", "bootstrap"}
        return sum(any(token in mutations for token in call) for call in self.calls)


class ScriptedLaunchctlRecorder:
    def __init__(
        self,
        events: list[tuple[str, int | None]],
        *,
        old_pid: int = 50001,
        ownership: dict[int, tuple[bool, bool]] | None = None,
        unresolved_pids: set[int] | None = None,
        orphan_pids_after_unload: tuple[int, ...] = (),
        restart_event: tuple[str, int | None] | None = None,
        disabled: bool | None = None,
    ) -> None:
        if not events:
            raise ValueError("events required")
        self.events = list(events)
        self.last_event = events[-1]
        self.pid = old_pid
        self.ownership = ownership or {
            50001: (True, True),
            50002: (True, True),
        }
        self.unresolved_pids = set(unresolved_pids or set())
        self.orphan_pids_after_unload = tuple(orphan_pids_after_unload)
        self.restart_event = ("running", old_pid) if restart_event is None else restart_event
        self.disabled = (events[0][0] == "unloaded") if disabled is None else disabled
        self.last_label = SERVICE_LABEL
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args, **_kwargs):
        call = tuple(str(value) for value in args)
        self.calls.append(call)
        if len(call) >= 3 and call[1] in {"print", "disable", "enable", "bootout", "kickstart"}:
            target = call[2]
            if target.startswith("gui/") and target.count("/") >= 2:
                self.last_label = target.rsplit("/", 1)[-1]
        if len(call) >= 2 and call[1] == "disable":
            self.disabled = True
        elif len(call) >= 2 and call[1] == "enable":
            self.disabled = False
        if len(call) >= 2 and call[1] == "print-disabled":
            value = "true" if self.disabled else "false"
            return subprocess.CompletedProcess(call, 0, f'{{ "{self.last_label}" => {value} }}\n', "")
        if len(call) >= 2 and call[1] == "print":
            event = self.events.pop(0) if len(self.events) > 1 else self.events[0]
            self.last_event = event
            state, pid = event
            if state == "unloaded":
                return subprocess.CompletedProcess(call, 113, "", "Could not find service; not loaded")
            pid_line = f"    pid = {pid}\n" if pid is not None else ""
            return subprocess.CompletedProcess(call, 0, f"    state = {state}\n{pid_line}", "")
        if len(call) >= 2 and call[1] == "kickstart":
            self.events = [self.restart_event]
            self.last_event = self.restart_event
        return subprocess.CompletedProcess(call, 0, "", "")

    def process_probe(self, pid: int, _expected_arguments) -> tuple[bool, bool]:
        if pid in self.unresolved_pids:
            raise RuntimeError("fixture ownership unresolved")
        live, owned = self.ownership.get(pid, (False, False))
        return live, live and owned

    def process_scan(self, _expected_arguments) -> tuple[int, ...]:
        state, pid = self.last_event
        if state == "unloaded":
            return self.orphan_pids_after_unload
        if pid is None or pid in self.unresolved_pids:
            return ()
        live, owned = self.ownership.get(pid, (False, False))
        return (pid,) if live and owned else ()

    def calls_for(self, action: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if len(call) >= 2 and call[1] == action]


class PhysicalScheduleRunner:
    """Stateful fake launchd/process model for A/B/C physical transition tests."""

    def __init__(self, entries) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.arguments: dict[str, tuple[str, ...]] = {}
        self.state: dict[str, dict[str, object]] = {}
        for index, entry in enumerate(entries, start=1):
            label = entry.launchd_label
            args = (f"/fixture/{entry.writer_id.lower()}/python", "--send")
            self.arguments[label] = args
            before = entry.before_class
            self.state[label] = {
                "disabled": before == "C",
                "loaded": before in {"A", "B"},
                "runtime": "ACTIVE" if before == "A" else "INACTIVE",
                "pid": 71000 + index if before == "A" else None,
            }

    def __call__(self, args, **_kwargs):
        call = tuple(str(value) for value in args)
        self.calls.append(call)
        action = call[1] if len(call) >= 2 else ""
        if action == "print-disabled":
            body = "\n".join(
                f'"{label}" => {"true" if bool(state["disabled"]) else "false"}'
                for label, state in sorted(self.state.items())
            )
            return subprocess.CompletedProcess(call, 0, "{\n" + body + "\n}\n", "")
        if action == "bootstrap":
            plist = Path(call[3])
            label = next(label for label in self.state if plist.stem == label or plist.stem.endswith(label))
            state = self.state[label]
            state.update(loaded=True, runtime="INACTIVE", pid=None)
            return subprocess.CompletedProcess(call, 0, "", "")
        if len(call) >= 3:
            label = call[2].rsplit("/", 1)[-1]
            if label in self.state:
                state = self.state[label]
                if action == "disable":
                    state["disabled"] = True
                elif action == "enable":
                    state["disabled"] = False
                elif action == "bootout":
                    state.update(loaded=False, runtime="INACTIVE", pid=None)
                elif action == "kickstart":
                    state.update(loaded=True, runtime="ACTIVE", pid=81000 + sorted(self.state).index(label))
                elif action == "print":
                    if not bool(state["loaded"]):
                        return subprocess.CompletedProcess(call, 113, "", "not loaded")
                    if state["runtime"] == "ACTIVE":
                        return subprocess.CompletedProcess(call, 0, f'    state = running\n    pid = {state["pid"]}\n', "")
                    return subprocess.CompletedProcess(call, 0, "    state = inactive\n", "")
        return subprocess.CompletedProcess(call, 0, "", "")

    def process_probe(self, pid: int, expected_arguments) -> tuple[bool, bool]:
        expected = tuple(expected_arguments)
        for label, state in self.state.items():
            if state["pid"] == pid and self.arguments[label] == expected and state["runtime"] == "ACTIVE":
                return True, True
        return False, False

    def process_scan(self, expected_arguments) -> tuple[int, ...]:
        expected = tuple(expected_arguments)
        result = []
        for label, state in self.state.items():
            if self.arguments[label] == expected and state["runtime"] == "ACTIVE" and state["pid"] is not None:
                result.append(int(state["pid"]))
        return tuple(sorted(result))

    def calls_for(self, action: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if len(call) >= 2 and call[1] == action]


class NoMigrationEffects:
    def __init__(self) -> None:
        self.calls: list[int] = []

    def run_v6_to_v7(self, _path: Path, _inventory: DcsWriterInventory) -> None:
        self.calls.append(7)

    def run_v7_to_v8(self, _path: Path) -> None:
        self.calls.append(8)


class NoW08Effects:
    def __init__(self) -> None:
        self.acquire_count = 0

    def acquire(self, _path: Path, _request: ProductionDcsV8AdoptionRequest):
        self.acquire_count += 1
        raise AssertionError("W08 acquire must not be reached")


class StartupAuthorityFixture:
    def __init__(self, root: Path, *, runner: LaunchctlRecorder) -> None:
        self.root = root
        self.runner = runner
        self.launch_root = root / "LaunchAgents"
        self.runtime_root = root / "runtime"
        self.release = root / "releases" / PROPERTYAI_SOURCE
        self.venv = root / "venv"
        self.dcs = root / "control.sqlite3"
        self.plist_path = self.launch_root / f"{SERVICE_LABEL}.plist"
        self.runtime_path = self.runtime_root / "W05.runtime.json"
        self.authorized_path = self.runtime_root / "W05.authorized.json"
        self.site = self.venv / "lib" / "python3.13" / "site-packages"
        self.package_root = self.site / "adcp_global_writer_client"
        self.dist_info = self.site / "adcp_global_writer_client-0.3.0.dist-info"
        self.python = self.venv / "bin" / "python"
        self.launch_root.mkdir(parents=True)
        self.runtime_root.mkdir(parents=True)
        (self.release / "propertyai_core").mkdir(parents=True)
        self.package_root.mkdir(parents=True)
        self.dist_info.mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text("", encoding="utf-8")
        self._write_product(PROPERTYAI_SOURCE)
        self.write_thin_03()
        self.write_authorized()
        self.write_runtime(stale=True)
        self.write_plist()

    def _write_product(self, source: str) -> None:
        artifact = f"source-commit:{source}"
        (self.release / "propertyai_core" / "_global_writer_build_identity.py").write_text(
            "\n".join(
                (
                    "PRODUCT_IDENTITY_MODULE = 'propertyai_core._global_writer_build_identity'",
                    "PRODUCT_NAME = 'PropertyAI'",
                    f"PRODUCT_BUILD_COMMIT = '{source}'",
                    f"SOURCE_ARTIFACT_IDENTITY = '{artifact}'",
                    f"PRODUCT_BUILD_IDENTITY = '{product_identity(source)}'",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def write_thin_03(
        self,
        *,
        schema_identity: str = SCHEMA_IDENTITY,
        supported: tuple[int, ...] = (6, 7, 8),
        thin_contract_format_version: int = 2,
    ) -> None:
        supported_literal = repr(tuple(supported))
        self.dist_info.mkdir(parents=True, exist_ok=True)
        (self.dist_info / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: adcp-global-writer-client\nVersion: 0.3.0\n",
            encoding="utf-8",
        )
        (self.package_root / "_build_identity.py").write_text(
            "\n".join(
                (
                    "CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'",
                    f"CLIENT_VERSION = '{THIN_VERSION}'",
                    f"SOURCE_COMMIT = '{THIN_SOURCE}'",
                    f"BUILD_ID = '{THIN_BUILD_ID}'",
                    f"ARTIFACT_IDENTITY = '{THIN_ARTIFACT}'",
                    f"EXPECTED_THIN_CONTRACT_FORMAT_VERSION = {thin_contract_format_version}",
                    f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = '{schema_identity}'",
                    f"EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = {supported_literal}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (self.package_root / "_schema_contract.py").write_text(
            "\n".join(
                (
                    f"THIN_CONTRACT_FORMAT_VERSION = {thin_contract_format_version}",
                    f"SUPPORTED_DCS_SCHEMA_VERSIONS = {supported_literal}",
                    f"SCHEMA_CONTRACT_IDENTITY = '{schema_identity}'",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def write_thin_04(self) -> None:
        for path in self.site.glob("adcp_global_writer_client-*.dist-info"):
            for child in path.iterdir():
                child.unlink()
            path.rmdir()
        self.dist_info = self.site / "adcp_global_writer_client-0.4.0.dist-info"
        self.dist_info.mkdir()
        (self.dist_info / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: adcp-global-writer-client\nVersion: 0.4.0\n",
            encoding="utf-8",
        )
        (self.package_root / "_build_identity.py").write_text(
            "\n".join(
                (
                    "CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'",
                    f"CLIENT_VERSION = '{CURRENT_THIN_VERSION}'",
                    f"SOURCE_COMMIT = '{CURRENT_THIN_SOURCE}'",
                    f"BUILD_ID = '{CURRENT_THIN_BUILD_ID}'",
                    f"ARTIFACT_IDENTITY = '{CURRENT_THIN_ARTIFACT}'",
                    "EXPECTED_THIN_CONTRACT_FORMAT_VERSION = 2",
                    f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = '{CURRENT_SCHEMA_IDENTITY}'",
                    "EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9)",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (self.package_root / "_schema_contract.py").write_text(
            "\n".join(
                (
                    "THIN_CONTRACT_FORMAT_VERSION = 2",
                    "SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9)",
                    f"SCHEMA_CONTRACT_IDENTITY = '{CURRENT_SCHEMA_IDENTITY}'",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def write_thin_05(self) -> None:
        for path in self.site.glob("adcp_global_writer_client-*.dist-info"):
            for child in path.iterdir():
                child.unlink()
            path.rmdir()
        self.dist_info = self.site / "adcp_global_writer_client-0.5.0.dist-info"
        self.dist_info.mkdir()
        (self.dist_info / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: adcp-global-writer-client\nVersion: 0.5.0\n",
            encoding="utf-8",
        )
        (self.package_root / "_build_identity.py").write_text(
            "\n".join(
                (
                    "CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'",
                    f"CLIENT_VERSION = '{TARGET_THIN_VERSION}'",
                    f"SOURCE_COMMIT = '{TARGET_THIN_SOURCE}'",
                    f"BUILD_ID = '{TARGET_THIN_BUILD_ID}'",
                    f"ARTIFACT_IDENTITY = '{TARGET_THIN_ARTIFACT}'",
                    "EXPECTED_THIN_CONTRACT_FORMAT_VERSION = 2",
                    f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = '{TARGET_SCHEMA_IDENTITY}'",
                    "EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9, 10)",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (self.package_root / "_schema_contract.py").write_text(
            "\n".join(
                (
                    "THIN_CONTRACT_FORMAT_VERSION = 2",
                    "SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9, 10)",
                    f"SCHEMA_CONTRACT_IDENTITY = '{TARGET_SCHEMA_IDENTITY}'",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def write_thin_01(self) -> None:
        for path in self.site.glob("adcp_global_writer_client-*.dist-info"):
            for child in path.iterdir():
                child.unlink()
            path.rmdir()
        self.dist_info = self.site / "adcp_global_writer_client-0.1.0.dist-info"
        self.dist_info.mkdir()
        (self.dist_info / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: adcp-global-writer-client\nVersion: 0.1.0\n",
            encoding="utf-8",
        )
        build_id = f"adcp-global-writer-client@0.1.0+g{LEGACY_THIN_SOURCE[:12]}"
        (self.package_root / "_build_identity.py").write_text(
            "\n".join(
                (
                    "CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'",
                    "CLIENT_VERSION = '0.1.0'",
                    f"SOURCE_COMMIT = '{LEGACY_THIN_SOURCE}'",
                    f"BUILD_ID = '{build_id}'",
                    f"ARTIFACT_IDENTITY = 'source-commit:{LEGACY_THIN_SOURCE}'",
                    f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = '{V6_SCHEMA_IDENTITY}'",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (self.package_root / "_schema_contract.py").write_text(
            f"SCHEMA_CONTRACT_VERSION = 6\nSCHEMA_CONTRACT_IDENTITY = '{V6_SCHEMA_IDENTITY}'\n",
            encoding="utf-8",
        )

    def configure_current_product_thin_authority(self) -> None:
        self.release = self.root / "releases" / CURRENT_PROPERTYAI_SOURCE
        (self.release / "propertyai_core").mkdir(parents=True)
        self._write_product(CURRENT_PROPERTYAI_SOURCE)
        self.write_thin_04()
        authorized = self.authorized_document()
        authorized["product_build_commit"] = CURRENT_PROPERTYAI_SOURCE
        authorized["product_build_identity"] = product_identity(CURRENT_PROPERTYAI_SOURCE)
        authorized["source_root_or_artifact_identity"] = f"source-commit:{CURRENT_PROPERTYAI_SOURCE}"
        authorized["global_writer_client_build"] = CURRENT_THIN_BUILD
        self.write_authorized(authorized)
        document = self.plist_document()
        document["WorkingDirectory"] = str(self.release)
        document["RunAtLoad"] = True
        document["StartInterval"] = 300
        environment = document["EnvironmentVariables"]
        assert isinstance(environment, dict)
        environment["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(self.release)
        environment["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = CURRENT_PROPERTYAI_SOURCE
        self.write_plist(document)

    def configure_production_product_thin_authority(
        self, *, target_v05: bool, product_source: str = PRODUCTION_PROPERTYAI_SOURCE
    ) -> None:
        self.release = self.root / "releases" / product_source
        (self.release / "propertyai_core").mkdir(parents=True)
        self._write_product(product_source)
        if target_v05:
            self.write_thin_05()
            thin_build = TARGET_THIN_BUILD
        else:
            self.write_thin_04()
            thin_build = CURRENT_THIN_BUILD
        authorized = self.authorized_document()
        authorized["product_build_commit"] = product_source
        authorized["product_build_identity"] = product_identity(product_source)
        authorized["source_root_or_artifact_identity"] = f"source-commit:{product_source}"
        authorized["global_writer_client_build"] = thin_build
        self.write_authorized(authorized)
        document = self.plist_document()
        document["WorkingDirectory"] = str(self.release)
        document["RunAtLoad"] = True
        document["StartInterval"] = 300
        environment = document["EnvironmentVariables"]
        assert isinstance(environment, dict)
        environment["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(self.release)
        environment["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = product_source
        self.write_plist(document)

    def authorized_document(self) -> dict[str, object]:
        artifact = f"source-commit:{PROPERTYAI_SOURCE}"
        return {
            "schema_version": 2,
            "service_code": SERVICE_CODE,
            "product_build_commit": PROPERTYAI_SOURCE,
            "product_build_identity": product_identity(PROPERTYAI_SOURCE),
            "global_writer_client_build": THIN_BUILD,
            "source_root_or_artifact_identity": artifact,
            "config_artifact_identity": None,
        }

    def write_authorized(self, document: dict[str, object] | None = None) -> None:
        self.authorized_path.write_text(
            json.dumps(document or self.authorized_document(), sort_keys=True), encoding="utf-8"
        )

    def publish_runtime_pid(self, pid: int, *, incarnation: str | None = None) -> None:
        document = json.loads(self.runtime_path.read_text(encoding="utf-8"))
        document["pid"] = pid
        if incarnation is not None:
            document["process_incarnation_id"] = incarnation
        self.runtime_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    def write_runtime(self, *, stale: bool) -> None:
        if stale:
            product_source = LEGACY_PRODUCT
            thin_source = LEGACY_THIN_SOURCE
            thin_version = "0.1.0"
        else:
            product_source = PROPERTYAI_SOURCE
            thin_source = THIN_SOURCE
            thin_version = THIN_VERSION
        document = {
            "schema_version": 3,
            "service_code": SERVICE_CODE,
            "product_build_commit": product_source,
            "product_build_identity": product_identity(product_source),
            "global_writer_client_build": client_build(thin_version, thin_source),
            "source_root_or_artifact_identity": f"source-commit:{product_source}",
            "config_artifact_identity": None,
            "pid": self.runner.pid,
            "process_incarnation_id": "a" * 64,
        }
        self.runtime_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    def plist_document(self) -> dict[str, object]:
        return {
            "Label": SERVICE_LABEL,
            "ProgramArguments": [str(self.python), "-m", "telegram_approval.send_due_completions", "--send"],
            "WorkingDirectory": str(self.release),
            "EnvironmentVariables": {
                "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT": str(self.release),
                "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT": PROPERTYAI_SOURCE,
                "PROPERTYAI_GLOBAL_WRITER_DCS_PATH": str(self.dcs),
                "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH": str(self.runtime_path),
                "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH": str(self.authorized_path),
            },
        }

    def write_plist(self, document: dict[str, object] | None = None) -> None:
        self.plist_path.write_bytes(plistlib.dumps(document or self.plist_document()))

    def authority(self) -> _LaunchdWriterAuthority:
        return _LaunchdWriterAuthority(
            dcs_path=self.dcs,
            launch_agents_root=self.launch_root,
            runtime_root=self.runtime_root,
            uid=501,
            runner=self.runner,
            process_probe=self.runner.process_probe,
        )


class W01StartupPlistMaterializationTests(unittest.TestCase):
    def fixture(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        release = root / "release"
        release.mkdir()
        config = root / "external" / "gmail-config.json"
        config.parent.mkdir()
        config.write_text("{}\n", encoding="utf-8")
        source = root / "source.plist"
        source.write_bytes(
            plistlib.dumps(
                {
                    "Label": "com.propertyai.gmail-readonly",
                    "ProgramArguments": ["/usr/bin/python3", "-m", "gmail_ingest.poll_once"],
                    "WorkingDirectory": "/source-template",
                    "EnvironmentVariables": {
                        _W01_RUNTIME_CONFIG_ENV: "/REPLACE_AT_CUTOVER/propertyai/gmail-ingest-config",
                        "PROPERTYAI_CLEANER_TELEGRAM_TOKEN_PATH": "/REPLACE_AT_CUTOVER/propertyai/cleaner-token",
                        "PROPERTYAI_OPS_ADMIN_TELEGRAM_TOKEN_PATH": "/REPLACE_AT_CUTOVER/propertyai/ops-admin-token",
                        "PROPERTYAI_OPS_BRIEFING_ALLOWED_CHAT_IDS": "REPLACE_AT_CUTOVER",
                    },
                },
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            )
        )
        environment = {
            "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT": str(release),
            "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT": PROPERTYAI_SOURCE,
            "PROPERTYAI_GLOBAL_WRITER_DCS_PATH": str(root / "control.sqlite3"),
            "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH": str(root / "runtime" / "W01.runtime.json"),
            "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH": str(root / "runtime" / "W01.authorized.json"),
            _W01_RUNTIME_CONFIG_ENV: str(config),
            "PROPERTYAI_CLEANER_TELEGRAM_TOKEN_PATH": str(root / "secrets" / "cleaner-token"),
            "PROPERTYAI_OPS_ADMIN_TELEGRAM_TOKEN_PATH": str(root / "secrets" / "ops-token"),
            "PROPERTYAI_OPS_BRIEFING_ALLOWED_CHAT_IDS": "12345",
        }
        return root, source, config, environment

    def test_materializes_deterministically_and_reads_back_exact_external_config(self) -> None:
        root, source, config, environment = self.fixture()
        first_path = root / "first.plist"
        second_path = root / "second.plist"
        first = materialize_w01_startup_plist(
            source, first_path, runtime_environment=environment
        )
        second = materialize_w01_startup_plist(
            source, second_path, runtime_environment=environment
        )
        self.assertEqual(first.staged_plist_sha256, second.staged_plist_sha256)
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        readback = plistlib.loads(first_path.read_bytes())
        readback_environment = readback["EnvironmentVariables"]
        self.assertEqual(environment[_W01_RUNTIME_CONFIG_ENV], readback_environment[_W01_RUNTIME_CONFIG_ENV])
        self.assertEqual(
            str(Path(environment["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"]).resolve()),
            readback["WorkingDirectory"],
        )
        self.assertFalse(
            any(
                "REPLACE_AT_CUTOVER" in value
                for value in readback_environment.values()
                if isinstance(value, str)
            )
        )
        self.assertEqual(config.resolve(), first.resolved_config_path)
        self.assertTrue(first.service_config_fingerprint.startswith("sha256:"))

    def test_materialization_rejects_missing_placeholder_relative_tilde_empty_malformed_and_wrong_key(self) -> None:
        root, source, config, environment = self.fixture()
        cases: list[dict[str, str]] = []
        missing = dict(environment)
        missing.pop(_W01_RUNTIME_CONFIG_ENV)
        cases.append(missing)
        placeholder = dict(environment)
        placeholder[_W01_RUNTIME_CONFIG_ENV] = "/REPLACE_AT_CUTOVER/propertyai/gmail-ingest-config"
        cases.append(placeholder)
        for raw in ("relative/config.json", "~/config.json", "", f" {config}"):
            candidate = dict(environment)
            candidate[_W01_RUNTIME_CONFIG_ENV] = raw
            cases.append(candidate)
        wrong = dict(environment)
        wrong.pop(_W01_RUNTIME_CONFIG_ENV)
        wrong["PROPERTYAI_GMAIL_INGEST_CONFIG_WRONG_FIELD"] = str(config)
        cases.append(wrong)
        for index, candidate in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                    materialize_w01_startup_plist(
                        source, root / f"invalid-{index}.plist", runtime_environment=candidate
                    )
                self.assertEqual(
                    "PRODUCTION_DCS_W01_PLIST_MATERIALIZATION_INVALID", caught.exception.code
                )

    def test_materialization_rejects_non_file_and_symlink_config_authority(self) -> None:
        root, source, config, environment = self.fixture()
        directory_env = dict(environment)
        directory_env[_W01_RUNTIME_CONFIG_ENV] = str(config.parent)
        with self.assertRaises(ProductionDcsV8AdoptionError):
            materialize_w01_startup_plist(
                source, root / "directory.plist", runtime_environment=directory_env
            )
        link = root / "config-link.json"
        link.symlink_to(config)
        symlink_env = dict(environment)
        symlink_env[_W01_RUNTIME_CONFIG_ENV] = str(link)
        with self.assertRaises(ProductionDcsV8AdoptionError):
            materialize_w01_startup_plist(
                source, root / "symlink.plist", runtime_environment=symlink_env
            )


class InactiveWriterStartupAuthorityTests(unittest.TestCase):
    def fixture(
        self,
        *,
        states: list[bool] | None = None,
        declared_states: list[str] | None = None,
        include_pid: bool = True,
        pid_live: bool = True,
        pid_service_owned: bool = True,
        disabled: bool | None = None,
    ):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        runner = LaunchctlRecorder(
            states,
            declared_states=declared_states,
            include_pid=include_pid,
            pid_live=pid_live,
            pid_service_owned=pid_service_owned,
            disabled=disabled,
        )
        return StartupAuthorityFixture(root, runner=runner), runner

    def _make_w01_fixture(self, *, include_config: bool) -> tuple[StartupAuthorityFixture, LaunchctlRecorder]:
        fixture, runner = self.fixture(states=[False])
        fixture.runtime_path = fixture.runtime_root / "W01.runtime.json"
        fixture.authorized_path = fixture.runtime_root / "W01.authorized.json"
        authorized = fixture.authorized_document()
        authorized["service_code"] = "PROPERTYAI_W01_GMAIL_INGEST_PROJECTION"
        fixture.write_authorized(authorized)
        document = fixture.plist_document()
        if include_config:
            config = fixture.root / "external" / "gmail-config.json"
            config.parent.mkdir(exist_ok=True)
            config.write_text("{}\n", encoding="utf-8")
            document["EnvironmentVariables"][_W01_RUNTIME_CONFIG_ENV] = str(config)
        fixture.write_plist(document)
        return fixture, runner

    def test_current_product_04_inactive_loaded_enabled_exact_authority_passes(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive"],
            include_pid=False,
            pid_live=False,
            pid_service_owned=False,
            disabled=False,
        )
        fixture.configure_current_product_thin_authority()
        entry = fixture.authority().discover().entries[0]
        startup = entry.startup_resolution
        self.assertIsNotNone(startup)
        assert startup is not None
        self.assertEqual("B", entry.before_class)
        self.assertEqual(("INACTIVE", "LOADED", "ENABLED"), (entry.runtime_state, entry.load_state, entry.enabled_state))
        self.assertEqual(CURRENT_PROPERTYAI_SOURCE, startup.resolved_propertyai_source_commit)
        self.assertEqual(CURRENT_THIN_VERSION, startup.thin_client_version)
        self.assertEqual(CURRENT_THIN_BUILD_ID, startup.thin_client_build_id)
        self.assertEqual(CURRENT_THIN_SOURCE, startup.thin_client_source_commit)
        self.assertEqual(CURRENT_SCHEMA_IDENTITY, startup.thin_client_schema_contract_identity)
        self.assertEqual((6, 7, 8, 9), startup.supported_dcs_schema_versions)
        self.assertEqual(0, runner.mutation_call_count)

    def test_production_1496_current_04_inactive_loaded_enabled_exact_authority_passes(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive"],
            include_pid=False,
            pid_live=False,
            pid_service_owned=False,
            disabled=False,
        )
        fixture.configure_production_product_thin_authority(target_v05=False)
        entry = fixture.authority().discover().entries[0]
        startup = entry.startup_resolution
        self.assertIsNotNone(startup)
        assert startup is not None
        self.assertEqual("B", entry.before_class)
        self.assertEqual(PRODUCTION_PROPERTYAI_SOURCE, startup.resolved_propertyai_source_commit)
        self.assertEqual(CURRENT_THIN_VERSION, startup.thin_client_version)
        self.assertEqual(CURRENT_THIN_SOURCE, startup.thin_client_source_commit)
        self.assertEqual((6, 7, 8, 9), startup.supported_dcs_schema_versions)
        self.assertEqual(0, runner.mutation_call_count)

    def test_production_1496_target_05_inactive_loaded_enabled_exact_authority_passes(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive"],
            include_pid=False,
            pid_live=False,
            pid_service_owned=False,
            disabled=False,
        )
        fixture.configure_production_product_thin_authority(target_v05=True)
        entry = fixture.authority().discover().entries[0]
        startup = entry.startup_resolution
        self.assertIsNotNone(startup)
        assert startup is not None
        self.assertEqual("B", entry.before_class)
        self.assertEqual(PRODUCTION_PROPERTYAI_SOURCE, startup.resolved_propertyai_source_commit)
        self.assertEqual(TARGET_THIN_VERSION, startup.thin_client_version)
        self.assertEqual(TARGET_THIN_BUILD_ID, startup.thin_client_build_id)
        self.assertEqual(TARGET_THIN_SOURCE, startup.thin_client_source_commit)
        self.assertEqual(TARGET_SCHEMA_IDENTITY, startup.thin_client_schema_contract_identity)
        self.assertEqual((6, 7, 8, 9, 10), startup.supported_dcs_schema_versions)
        self.assertEqual(0, runner.mutation_call_count)

    def test_dl95_recovery_product_target_05_inactive_loaded_enabled_exact_authority_passes(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive"],
            include_pid=False,
            pid_live=False,
            pid_service_owned=False,
            disabled=False,
        )
        fixture.configure_production_product_thin_authority(
            target_v05=True, product_source=DL95_RECOVERY_PROPERTYAI_SOURCE
        )
        entry = fixture.authority().discover().entries[0]
        startup = entry.startup_resolution
        self.assertIsNotNone(startup)
        assert startup is not None
        self.assertEqual("B", entry.before_class)
        self.assertEqual(DL95_RECOVERY_PROPERTYAI_SOURCE, startup.resolved_propertyai_source_commit)
        self.assertEqual(TARGET_THIN_VERSION, startup.thin_client_version)
        self.assertEqual(TARGET_THIN_BUILD_ID, startup.thin_client_build_id)
        self.assertEqual(TARGET_THIN_SOURCE, startup.thin_client_source_commit)
        self.assertEqual(TARGET_SCHEMA_IDENTITY, startup.thin_client_schema_contract_identity)
        self.assertEqual((6, 7, 8, 9, 10), startup.supported_dcs_schema_versions)
        self.assertEqual(0, runner.mutation_call_count)

    def test_dl95_recovery_product_exact_pair_only_negative_matrix_fails_closed(self) -> None:
        fixture, _runner = self.fixture(states=[False])
        fixture.configure_production_product_thin_authority(
            target_v05=True, product_source=DL95_RECOVERY_PROPERTYAI_SOURCE
        )
        document = plistlib.loads(fixture.plist_path.read_bytes())
        startup = fixture.authority()._resolve_inactive_startup_authority(
            document=document, writer_id="W05", label=SERVICE_LABEL
        )
        exact = fixture.authorized_document()
        exact["product_build_commit"] = DL95_RECOVERY_PROPERTYAI_SOURCE
        exact["product_build_identity"] = product_identity(DL95_RECOVERY_PROPERTYAI_SOURCE)
        exact["source_root_or_artifact_identity"] = f"source-commit:{DL95_RECOVERY_PROPERTYAI_SOURCE}"
        exact["global_writer_client_build"] = TARGET_THIN_BUILD
        match = _LaunchdWriterAuthority._startup_matches_authorized
        self.assertTrue(match(startup, exact, SERVICE_CODE))

        wrong_thin = dict(exact)
        wrong_thin["global_writer_client_build"] = CURRENT_THIN_BUILD
        unknown_product = "b" * 40
        unknown_startup = replace(
            startup,
            resolved_propertyai_source_commit=unknown_product,
            resolved_propertyai_release=Path("/fixture/releases") / unknown_product,
        )
        unknown_authorized = dict(exact)
        unknown_authorized["product_build_commit"] = unknown_product
        unknown_authorized["product_build_identity"] = product_identity(unknown_product)
        unknown_authorized["source_root_or_artifact_identity"] = f"source-commit:{unknown_product}"
        mixed_product = dict(exact)
        mixed_product["product_build_commit"] = PRODUCTION_PROPERTYAI_SOURCE
        mixed_product["product_build_identity"] = product_identity(PRODUCTION_PROPERTYAI_SOURCE)
        mixed_product["source_root_or_artifact_identity"] = f"source-commit:{PRODUCTION_PROPERTYAI_SOURCE}"

        self.assertFalse(match(startup, wrong_thin, SERVICE_CODE))
        self.assertFalse(match(unknown_startup, unknown_authorized, SERVICE_CODE))
        self.assertFalse(match(startup, mixed_product, SERVICE_CODE))

    def test_dl98_product_successor_is_one_finite_exact_v05_pair(self) -> None:
        self._assert_dl98_product_pair(DL98_CUTOVER_PROPERTYAI_SOURCE)

    def test_dl98_worker_product_is_one_finite_exact_v05_pair(self) -> None:
        self._assert_dl98_product_pair("ebd7f756e35610c3ce5a8e33e71fc610e3c84f00")

    def test_telegram_t1_w07_product_is_one_finite_exact_v05_pair(self) -> None:
        fixture, _runner = self.fixture(states=[False])
        fixture.configure_production_product_thin_authority(
            target_v05=True, product_source=DL95_RECOVERY_PROPERTYAI_SOURCE
        )
        document = plistlib.loads(fixture.plist_path.read_bytes())
        prior = fixture.authority()._resolve_inactive_startup_authority(
            document=document, writer_id="W07", label="com.propertyai.cleaner-pg-outbox"
        )
        startup = replace(
            prior,
            writer_id="W07",
            service_label="com.propertyai.cleaner-pg-outbox",
            resolved_propertyai_source_commit=TELEGRAM_T1_W07_PROPERTYAI_SOURCE,
            resolved_propertyai_release=(
                Path("/fixture/releases") / TELEGRAM_T1_W07_PROPERTYAI_SOURCE
            ),
        )
        exact = fixture.authorized_document()
        exact["service_code"] = "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"
        exact["product_build_commit"] = TELEGRAM_T1_W07_PROPERTYAI_SOURCE
        exact["product_build_identity"] = product_identity(TELEGRAM_T1_W07_PROPERTYAI_SOURCE)
        exact["source_root_or_artifact_identity"] = (
            f"source-commit:{TELEGRAM_T1_W07_PROPERTYAI_SOURCE}"
        )
        exact["global_writer_client_build"] = TARGET_THIN_BUILD
        exact["schema_version"] = 2
        exact["config_artifact_identity"] = None
        match = _LaunchdWriterAuthority._startup_matches_authorized
        self.assertTrue(match(startup, exact, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertIn(10, startup.supported_dcs_schema_versions)

        generic_services = {
            "W01": "PROPERTYAI_W01_GMAIL_INGEST_PROJECTION",
            "W02": "PROPERTYAI_W02_OPS_TELEGRAM_MUTATION",
            "W03": "PROPERTYAI_W03_CLEANER_TELEGRAM_MUTATION",
            "W04": "PROPERTYAI_W04_CLEANING_OPERATIONS_DISPATCH",
            "W05": "PROPERTYAI_W05_CLEANING_COMPLETION_DISPATCH",
            "W06": "PROPERTYAI_W06_HEALTH_RECOVERY_MAINTENANCE",
        }
        for writer_id, service_code in generic_services.items():
            with self.subTest(writer_id=writer_id):
                generic_startup = replace(
                    startup,
                    writer_id=writer_id,
                    service_label=f"fixture.{writer_id.lower()}",
                )
                generic_authorized = dict(exact)
                generic_authorized["service_code"] = service_code
                self.assertFalse(
                    match(generic_startup, generic_authorized, service_code)
                )

        wrong_thin = dict(exact)
        wrong_thin["global_writer_client_build"] = CURRENT_THIN_BUILD
        wrong_identity = dict(exact)
        wrong_identity["product_build_identity"] = product_identity("a" * 40)
        wrong_service = dict(exact)
        wrong_service["service_code"] = "PROPERTYAI_W06_HEALTH_RECOVERY_MAINTENANCE"
        wrong_schema = dict(exact)
        wrong_schema["schema_version"] = 3
        wrong_config = dict(exact)
        wrong_config["config_artifact_identity"] = "sha256:" + "1" * 64
        predecessor_startup = replace(
            startup,
            resolved_propertyai_source_commit=TELEGRAM_T1_W07_PREDECESSOR_SOURCE,
            resolved_propertyai_release=(
                Path("/fixture/releases") / TELEGRAM_T1_W07_PREDECESSOR_SOURCE
            ),
        )
        predecessor_authorized = dict(exact)
        predecessor_authorized["product_build_commit"] = TELEGRAM_T1_W07_PREDECESSOR_SOURCE
        predecessor_authorized["product_build_identity"] = product_identity(
            TELEGRAM_T1_W07_PREDECESSOR_SOURCE
        )
        predecessor_authorized["source_root_or_artifact_identity"] = (
            f"source-commit:{TELEGRAM_T1_W07_PREDECESSOR_SOURCE}"
        )
        future = "d" * 40
        future_startup = replace(
            startup,
            resolved_propertyai_source_commit=future,
            resolved_propertyai_release=Path("/fixture/releases") / future,
        )
        future_authorized = dict(exact)
        future_authorized["product_build_commit"] = future
        future_authorized["product_build_identity"] = product_identity(future)
        future_authorized["source_root_or_artifact_identity"] = f"source-commit:{future}"
        self.assertTrue(
            match(
                predecessor_startup,
                predecessor_authorized,
                "PROPERTYAI_W07_CORE_OUTBOX_REPLAY",
            )
        )
        self.assertFalse(match(startup, wrong_thin, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertFalse(match(startup, wrong_identity, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertFalse(match(startup, wrong_service, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertFalse(
            match(startup, wrong_service, "PROPERTYAI_W06_HEALTH_RECOVERY_MAINTENANCE")
        )
        self.assertFalse(match(startup, wrong_schema, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertFalse(match(startup, wrong_config, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))
        self.assertFalse(match(future_startup, future_authorized, "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"))

    def _assert_dl98_product_pair(self, product_source) -> None:
        fixture, _runner = self.fixture(states=[False])
        fixture.configure_production_product_thin_authority(
            target_v05=True, product_source=DL95_RECOVERY_PROPERTYAI_SOURCE
        )
        document = plistlib.loads(fixture.plist_path.read_bytes())
        prior = fixture.authority()._resolve_inactive_startup_authority(
            document=document, writer_id="W05", label=SERVICE_LABEL
        )
        startup = replace(
            prior,
            resolved_propertyai_source_commit=product_source,
            resolved_propertyai_release=Path("/fixture/releases") / product_source,
        )
        exact = fixture.authorized_document()
        exact["product_build_commit"] = product_source
        exact["product_build_identity"] = product_identity(product_source)
        exact["source_root_or_artifact_identity"] = f"source-commit:{product_source}"
        exact["global_writer_client_build"] = TARGET_THIN_BUILD
        match = _LaunchdWriterAuthority._startup_matches_authorized
        self.assertTrue(match(startup, exact, SERVICE_CODE))

        future = "d" * 40
        future_startup = replace(
            startup,
            resolved_propertyai_source_commit=future,
            resolved_propertyai_release=Path("/fixture/releases") / future,
        )
        future_authorized = dict(exact)
        future_authorized["product_build_commit"] = future
        future_authorized["product_build_identity"] = product_identity(future)
        future_authorized["source_root_or_artifact_identity"] = f"source-commit:{future}"
        wrong_thin = dict(exact)
        wrong_thin["global_writer_client_build"] = CURRENT_THIN_BUILD
        self.assertFalse(match(future_startup, future_authorized, SERVICE_CODE))
        self.assertFalse(match(startup, wrong_thin, SERVICE_CODE))

    def test_production_1496_authority_negative_matrix_fails_closed(self) -> None:
        fixture, _runner = self.fixture(states=[False])
        fixture.configure_production_product_thin_authority(target_v05=True)
        document = plistlib.loads(fixture.plist_path.read_bytes())
        startup = fixture.authority()._resolve_inactive_startup_authority(
            document=document, writer_id="W05", label=SERVICE_LABEL
        )
        exact = fixture.authorized_document()
        exact["product_build_commit"] = PRODUCTION_PROPERTYAI_SOURCE
        exact["product_build_identity"] = product_identity(PRODUCTION_PROPERTYAI_SOURCE)
        exact["source_root_or_artifact_identity"] = f"source-commit:{PRODUCTION_PROPERTYAI_SOURCE}"
        exact["global_writer_client_build"] = TARGET_THIN_BUILD
        match = _LaunchdWriterAuthority._startup_matches_authorized
        self.assertTrue(match(startup, exact, SERVICE_CODE))

        wrong_version = dict(exact)
        wrong_version["global_writer_client_build"] = CURRENT_THIN_BUILD
        wrong_artifact = dict(exact)
        wrong_artifact["global_writer_client_build"] = (
            f"{TARGET_THIN_BUILD_ID}|source={TARGET_THIN_SOURCE}|artifact=source-commit:{'f' * 40}"
        )
        unknown_product = "a" * 40
        unknown_startup = replace(
            startup,
            resolved_propertyai_source_commit=unknown_product,
            resolved_propertyai_release=Path("/fixture/releases") / unknown_product,
        )
        unknown_authorized = dict(exact)
        unknown_authorized["product_build_commit"] = unknown_product
        unknown_authorized["product_build_identity"] = product_identity(unknown_product)
        unknown_authorized["source_root_or_artifact_identity"] = f"source-commit:{unknown_product}"
        historical_wrong = dict(exact)
        historical_wrong["product_build_commit"] = PROPERTYAI_SOURCE
        historical_wrong["product_build_identity"] = product_identity(PROPERTYAI_SOURCE)
        historical_wrong["source_root_or_artifact_identity"] = f"source-commit:{PROPERTYAI_SOURCE}"
        historical_wrong["global_writer_client_build"] = CURRENT_THIN_BUILD
        historical_startup = replace(
            startup,
            resolved_propertyai_source_commit=PROPERTYAI_SOURCE,
            resolved_propertyai_release=Path("/fixture/releases") / PROPERTYAI_SOURCE,
        )
        future_client = dict(exact)
        future_source = "b" * 40
        future_client["global_writer_client_build"] = client_build("9.9.9", future_source)
        wrong_writer_class = dict(exact)
        wrong_writer_class["service_code"] = "ADCP_W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
        wrong_profile = replace(
            startup,
            thin_client_schema_contract_identity=WRONG_SCHEMA_IDENTITY,
        )

        rejected = (
            (startup, wrong_version),
            (startup, wrong_artifact),
            (unknown_startup, unknown_authorized),
            (historical_startup, historical_wrong),
            (startup, future_client),
            (startup, wrong_writer_class),
            (wrong_profile, exact),
        )
        for startup_value, authorized_value in rejected:
            with self.subTest(
                product=startup_value.resolved_propertyai_source_commit,
                build=authorized_value["global_writer_client_build"],
                service=authorized_value["service_code"],
            ):
                self.assertFalse(match(startup_value, authorized_value, SERVICE_CODE))

    def test_product_thin_authority_pairs_are_exact_and_mixed_pairs_fail_closed(self) -> None:
        def startup(product_source: str, *, current_thin: bool) -> DcsWriterStartupResolution:
            if current_thin:
                version = CURRENT_THIN_VERSION
                build_id = CURRENT_THIN_BUILD_ID
                thin_source = CURRENT_THIN_SOURCE
                thin_artifact = CURRENT_THIN_ARTIFACT
                schema_identity = CURRENT_SCHEMA_IDENTITY
                supported = (6, 7, 8, 9)
            else:
                version = THIN_VERSION
                build_id = THIN_BUILD_ID
                thin_source = THIN_SOURCE
                thin_artifact = THIN_ARTIFACT
                schema_identity = SCHEMA_IDENTITY
                supported = (6, 7, 8)
            return DcsWriterStartupResolution(
                writer_id="W05",
                service_label=SERVICE_LABEL,
                service_config_fingerprint="sha256:" + "0" * 64,
                active_state="INACTIVE",
                resolved_propertyai_release=Path("/fixture/releases") / product_source,
                resolved_propertyai_source_commit=product_source,
                python_executable=Path("/fixture/venv/bin/python"),
                environment_path=Path("/fixture/venv"),
                thin_client_version=version,
                thin_client_build_id=build_id,
                thin_client_source_commit=thin_source,
                thin_client_artifact_identity=thin_artifact,
                thin_contract_format_version=2,
                thin_client_schema_contract_identity=schema_identity,
                supported_dcs_schema_versions=supported,
            )

        def authorized(product_source: str, *, current_thin: bool) -> dict[str, object]:
            artifact = f"source-commit:{product_source}"
            return {
                "service_code": SERVICE_CODE,
                "product_build_commit": product_source,
                "product_build_identity": product_identity(product_source),
                "source_root_or_artifact_identity": artifact,
                "global_writer_client_build": CURRENT_THIN_BUILD if current_thin else THIN_BUILD,
            }

        match = _LaunchdWriterAuthority._startup_matches_authorized
        current_startup = startup(CURRENT_PROPERTYAI_SOURCE, current_thin=True)
        rollback_startup = startup(PROPERTYAI_SOURCE, current_thin=False)
        self.assertTrue(match(current_startup, authorized(CURRENT_PROPERTYAI_SOURCE, current_thin=True), SERVICE_CODE))
        self.assertTrue(match(rollback_startup, authorized(PROPERTYAI_SOURCE, current_thin=False), SERVICE_CODE))

        near_match = CURRENT_PROPERTYAI_SOURCE[:-1] + ("0" if CURRENT_PROPERTYAI_SOURCE[-1] != "0" else "1")
        unknown = "a" * 40
        rejected = (
            (rollback_startup, authorized(CURRENT_PROPERTYAI_SOURCE, current_thin=True)),
            (current_startup, authorized(PROPERTYAI_SOURCE, current_thin=False)),
            (startup(unknown, current_thin=True), authorized(unknown, current_thin=True)),
            (startup(near_match, current_thin=True), authorized(near_match, current_thin=True)),
            (startup(CURRENT_PROPERTYAI_SOURCE, current_thin=False), authorized(CURRENT_PROPERTYAI_SOURCE, current_thin=False)),
            (startup(PROPERTYAI_SOURCE, current_thin=True), authorized(PROPERTYAI_SOURCE, current_thin=True)),
        )
        for startup_value, authorized_value in rejected:
            with self.subTest(product=startup_value.resolved_propertyai_source_commit, build=authorized_value["global_writer_client_build"]):
                self.assertFalse(match(startup_value, authorized_value, SERVICE_CODE))

        missing = authorized(CURRENT_PROPERTYAI_SOURCE, current_thin=True)
        missing.pop("product_build_identity")
        malformed = authorized(CURRENT_PROPERTYAI_SOURCE, current_thin=True)
        malformed["product_build_identity"] = "malformed-product-identity"
        self.assertFalse(match(current_startup, missing, SERVICE_CODE))
        self.assertFalse(match(current_startup, malformed, SERVICE_CODE))

    def test_w01_startup_consumes_required_materialized_config_sealed_key(self) -> None:
        fixture, runner = self._make_w01_fixture(include_config=True)
        entry = fixture.authority().discover().entries[0]
        self.assertEqual("W01", entry.writer_id)
        self.assertEqual("INACTIVE", entry.state)
        self.assertEqual(0, runner.mutation_call_count)

    def test_w01_startup_rejects_missing_materialized_config_before_any_mutation(self) -> None:
        fixture, runner = self._make_w01_fixture(include_config=False)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_W01_STARTUP_CONFIG_INVALID", caught.exception.code)
        self.assertEqual(0, runner.mutation_call_count)

    def test_active_exact_live_runtime_matches_authorized(self) -> None:
        fixture, runner = self.fixture(states=[True])
        fixture.write_runtime(stale=False)
        entry = fixture.authority().discover().entries[0]
        self.assertEqual(("ACTIVE", "LIVE_RUNTIME_IDENTITY", THIN_VERSION), (entry.state, entry.authority_source, entry.client.version))
        self.assertIsNone(entry.startup_resolution)
        self.assertEqual(0, runner.process_start_count)

    def test_active_live_mismatch_rejects_even_though_startup_files_are_exact(self) -> None:
        fixture, runner = self.fixture(states=[True])
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_RUNTIME_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_incident_inactive_loaded_but_disabled_is_ambiguous_and_fails_closed(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive", "inactive"],
            pid_live=False,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_PHYSICAL_STATE_AMBIGUOUS", caught.exception.code)
        self.assertEqual(0, runner.mutation_call_count)

    def test_running_dead_pid_fails_closed_before_runtime_authority(self) -> None:
        fixture, runner = self.fixture(declared_states=["running"], pid_live=False)
        fixture.write_runtime(stale=False)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_RUNTIME_STATE_UNRESOLVED", caught.exception.code)
        self.assertEqual(0, runner.mutation_call_count)

    def test_inactive_live_service_owned_pid_fails_closed_inconsistent(self) -> None:
        fixture, runner = self.fixture(
            declared_states=["inactive"],
            pid_live=True,
            pid_service_owned=True,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_RUNTIME_STATE_INCONSISTENT", caught.exception.code)
        self.assertEqual(0, runner.mutation_call_count)

    def test_w05_inactive_stale_runtime_uses_exact_mutation_free_startup_authority(self) -> None:
        fixture, runner = self.fixture(states=[False])
        entry = fixture.authority().discover().entries[0]
        startup = entry.startup_resolution
        self.assertIsNotNone(startup)
        assert startup is not None
        self.assertEqual("INACTIVE", entry.state)
        self.assertIsNone(entry.pid)
        self.assertEqual("FRESH_STARTUP_RESOLUTION", entry.authority_source)
        self.assertIsNotNone(entry.last_runtime_identity_fingerprint)
        self.assertEqual(PROPERTYAI_SOURCE, startup.resolved_propertyai_source_commit)
        self.assertEqual(THIN_VERSION, startup.thin_client_version)
        self.assertEqual(THIN_BUILD_ID, startup.thin_client_build_id)
        self.assertEqual(THIN_SOURCE, startup.thin_client_source_commit)
        self.assertEqual(THIN_ARTIFACT, startup.thin_client_artifact_identity)
        self.assertEqual(2, startup.thin_contract_format_version)
        self.assertEqual((6, 7, 8), startup.supported_dcs_schema_versions)
        self.assertEqual(SCHEMA_IDENTITY, startup.thin_client_schema_contract_identity)
        self.assertTrue(entry.client.supports_v8)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_inactive_missing_last_runtime_is_informational_and_allowed(self) -> None:
        fixture, runner = self.fixture(states=[False])
        fixture.runtime_path.unlink()
        entry = fixture.authority().discover().entries[0]
        self.assertEqual("FRESH_STARTUP_RESOLUTION", entry.authority_source)
        self.assertIsNone(entry.last_runtime_identity_fingerprint)
        self.assertEqual(0, runner.process_start_count)

    def test_inactive_startup_source_mismatch_rejects(self) -> None:
        fixture, runner = self.fixture(states=[False])
        authorized = fixture.authorized_document()
        wrong = "1" * 40
        authorized["product_build_commit"] = wrong
        authorized["product_build_identity"] = product_identity(wrong)
        authorized["source_root_or_artifact_identity"] = f"source-commit:{wrong}"
        fixture.write_authorized(authorized)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_coherent_alternate_property_source_cannot_select_startup_authority(self) -> None:
        fixture, runner = self.fixture(states=[False])
        wrong = "2" * 40
        fixture._write_product(wrong)
        plist = fixture.plist_document()
        environment = plist["EnvironmentVariables"]
        assert isinstance(environment, dict)
        environment["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = wrong
        fixture.write_plist(plist)
        authorized = fixture.authorized_document()
        authorized["product_build_commit"] = wrong
        authorized["product_build_identity"] = product_identity(wrong)
        authorized["source_root_or_artifact_identity"] = f"source-commit:{wrong}"
        fixture.write_authorized(authorized)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_coherent_wrong_contract_identity_rejects_external_anchor(self) -> None:
        fixture, runner = self.fixture(states=[False])
        fixture.write_thin_03(schema_identity=WRONG_SCHEMA_IDENTITY)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_coherent_missing_schema_rejects_external_anchor(self) -> None:
        fixture, runner = self.fixture(states=[False])
        fixture.write_thin_03(supported=(7, 8))
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_coherent_extra_schema_rejects_external_anchor(self) -> None:
        fixture, runner = self.fixture(states=[False])
        fixture.write_thin_03(supported=(6, 7, 8, 9))
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_MISMATCH", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_inactive_thin_client_01_schema6_without_contract_format_is_unresolved(self) -> None:
        fixture, runner = self.fixture(states=[False])
        fixture.write_thin_01()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_inactive_unknown_startup_resolution_rejects(self) -> None:
        fixture, runner = self.fixture(states=[False])
        (fixture.package_root / "_build_identity.py").unlink()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            fixture.authority().discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_UNRESOLVED", caught.exception.code)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_inactive_to_active_before_mutation_invalidates_old_inactive_attestation(self) -> None:
        fixture, runner = self.fixture(states=[False, False, True])
        migrations = NoMigrationEffects()
        w08 = NoW08Effects()

        def profile_reader(_path: Path) -> _DcsProfile:
            # The external activation is modeled with the exact authorized live identity
            # and an enabled launchd override, so the second observation is a valid A.
            fixture.write_runtime(stale=False)
            runner.disabled = False
            return _DcsProfile(6, "fixture-v6", "ok", 0)

        controller = _ProductionDcsV8AdoptionController(
            path=fixture.dcs,
            writers=fixture.authority(),
            migrations=migrations,
            profile_reader=profile_reader,
            w08_authority=w08,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            controller.run(ProductionDcsV8AdoptionRequest("inactive-to-active-race"))
        self.assertEqual(
            "PRODUCTION_DCS_V8_ADOPTION_BLOCKED_WRITER_INVENTORY_CHANGED", caught.exception.code
        )
        self.assertEqual([], migrations.calls)
        self.assertEqual(0, w08.acquire_count)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_package_identity_drift_between_attestations_is_startup_authority_changed(self) -> None:
        fixture, runner = self.fixture(states=[False])
        migrations = NoMigrationEffects()
        w08 = NoW08Effects()

        def profile_reader(_path: Path) -> _DcsProfile:
            fixture.write_thin_01()
            return _DcsProfile(6, "fixture-v6", "ok", 0)

        controller = _ProductionDcsV8AdoptionController(
            path=fixture.dcs,
            writers=fixture.authority(),
            migrations=migrations,
            profile_reader=profile_reader,
            w08_authority=w08,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            controller.run(ProductionDcsV8AdoptionRequest("inactive-package-drift"))
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", caught.exception.code)
        self.assertEqual([], migrations.calls)
        self.assertEqual(0, w08.acquire_count)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)

    def test_service_config_drift_before_mutation_rejects_with_narrow_code(self) -> None:
        fixture, runner = self.fixture(states=[False, False])
        migrations = NoMigrationEffects()
        w08 = NoW08Effects()

        def profile_reader(_path: Path) -> _DcsProfile:
            changed = fixture.plist_document()
            changed["ProgramArguments"] = [*changed["ProgramArguments"], "--isolated-config-b"]
            fixture.write_plist(changed)
            return _DcsProfile(6, "fixture-v6", "ok", 0)

        controller = _ProductionDcsV8AdoptionController(
            path=fixture.dcs,
            writers=fixture.authority(),
            migrations=migrations,
            profile_reader=profile_reader,
            w08_authority=w08,
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            controller.run(ProductionDcsV8AdoptionRequest("inactive-config-drift"))
        self.assertEqual("PRODUCTION_DCS_WRITER_STARTUP_AUTHORITY_CHANGED", caught.exception.code)
        self.assertEqual([], migrations.calls)
        self.assertEqual(0, w08.acquire_count)
        self.assertEqual(0, runner.process_start_count)
        self.assertEqual(0, runner.mutation_call_count)


class RestorePlistAuthorityRevalidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        # Match the controller's canonicalized launch_agents_root identity.
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.dcs = self.root / "control.sqlite3"
        self.label = "com.propertyai.w05-fixture"
        self.arguments = ("/fixture/w05/python", "--send")
        self.document = {
            "Label": self.label,
            "ProgramArguments": list(self.arguments),
            "RunAtLoad": True,
            "StartInterval": 300,
            "KeepAlive": False,
        }
        self.plist = self.root / "com.propertyai.w05-fixture.plist"
        self._write_plist(self.plist, self.document)
        self.entry = self._freeze_entry(self.plist)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_plist(path: Path, document, *, fmt=plistlib.FMT_XML) -> None:
        path.write_bytes(plistlib.dumps(document, fmt=fmt, sort_keys=True))

    def _freeze_entry(self, lexical_path: Path) -> DcsWriterInventoryEntry:
        raw = lexical_path.read_bytes()
        return DcsWriterInventoryEntry(
            writer_id="W05",
            launchd_label=self.label,
            service_code="PROPERTYAI_W05_FIXTURE",
            runtime_identity_path=self.root / "W05.runtime.json",
            authorized_identity_path=self.root / "W05.authorized.json",
            pid=None,
            process_incarnation_id="INACTIVE",
            product_build_commit="f" * 40,
            product_build_identity="product:PropertyAI@gffffffffffff|source=" + "f" * 40,
            source_root_or_artifact_identity="source-commit:" + "f" * 40,
            client=_parse_client_identity(THIN_BUILD),
            state="INACTIVE",
            service_config_fingerprint=_service_config_fingerprint(self.document),
            before_class="B",
            autonomous_write_capable=True,
            runtime_state="INACTIVE",
            load_state="UNLOADED",
            enabled_state="DISABLED",
            plist_path=lexical_path,
            plist_realpath=lexical_path.resolve(strict=True),
            plist_sha256=hashlib.sha256(raw).hexdigest(),
            program_arguments=self.arguments,
            run_at_load_present=True,
            run_at_load_value=True,
            start_interval_present=True,
            start_interval_value=300,
            keep_alive_present=True,
            keep_alive_value=False,
            scheduler_config_fingerprint="sha256:" + "4" * 64,
            dcs_binding=str(self.dcs),
        )

    def _authority(self, effects: list[tuple[str, ...]]):
        state = {"enabled": False, "loaded": False}
        def runner(command, **_kwargs):
            call = tuple(str(value) for value in command)
            effects.append(call)
            if "enable" in call:
                state["enabled"] = True
            if "bootstrap" in call:
                state["loaded"] = True
            return subprocess.CompletedProcess(command, 0, "", "")
        authority = _LaunchdWriterAuthority(
            dcs_path=self.dcs,
            launch_agents_root=self.root,
            runtime_root=self.root,
            uid=501,
            runner=runner,
            process_scan=lambda _arguments: (),
            sleep=lambda _seconds: None,
        )
        authority._enabled_state = lambda _label: "ENABLED" if state["enabled"] else "DISABLED"
        authority._launch_state = lambda _label, _arguments: type(
            "Evidence",
            (),
            {
                "runtime_state": "INACTIVE",
                "load_state": "LOADED" if state["loaded"] else "UNLOADED",
                "pid_field": None,
                "pid_liveness": False,
                "pid_service_ownership": False,
                "launchd_declared_state": "inactive",
            },
        )()
        return authority

    def _assert_restore_drift_before_effect(self) -> None:
        effects: list[tuple[str, ...]] = []
        authority = self._authority(effects)
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority._restore_b_entries((self.entry,), schema_version=8)
        self.assertEqual("PRODUCTION_DCS_WRITER_RESTORE_PLIST_AUTHORITY_DRIFT", caught.exception.code)
        self.assertEqual([], effects)

    def test_restore_unchanged_exact_frozen_plist_enables_then_bootstraps_without_kickstart(self) -> None:
        effects: list[tuple[str, ...]] = []
        authority = self._authority(effects)
        authority._restore_b_entries((self.entry,), schema_version=8)
        physical = [call for call in effects if any(effect in call for effect in ("enable", "bootstrap", "kickstart"))]
        self.assertEqual(2, len(physical))
        self.assertIn("enable", physical[0])
        self.assertIn("bootstrap", physical[1])
        self.assertNotIn("kickstart", " ".join(" ".join(call) for call in physical))
        self.assertEqual(str(self.plist), physical[1][-1])

    def test_restore_same_label_at_different_plist_path_fails_before_effect(self) -> None:
        moved = self.root / "com.propertyai.w05-moved.plist"
        self.plist.rename(moved)
        self._assert_restore_drift_before_effect()

    def test_restore_same_lexical_path_with_symlink_retarget_fails_before_effect(self) -> None:
        self.plist.unlink()
        target_one = self.root / "frozen-target.plistdata"
        target_two = self.root / "retargeted.plistdata"
        self._write_plist(target_one, self.document)
        self._write_plist(target_two, self.document)
        self.plist.symlink_to(target_one)
        self.entry = self._freeze_entry(self.plist)
        self.plist.unlink()
        self.plist.symlink_to(target_two)
        self._assert_restore_drift_before_effect()

    def test_restore_same_config_with_different_plist_bytes_fails_before_effect(self) -> None:
        self._write_plist(self.plist, self.document, fmt=plistlib.FMT_BINARY)
        self._assert_restore_drift_before_effect()

    def test_restore_startup_config_fingerprint_drift_fails_before_effect(self) -> None:
        changed = dict(self.document)
        changed["StartInterval"] = 301
        self._write_plist(self.plist, changed)
        self._assert_restore_drift_before_effect()

    def test_restore_missing_frozen_plist_fails_before_effect(self) -> None:
        self.plist.unlink()
        self._assert_restore_drift_before_effect()

    def test_restore_duplicate_same_label_discovery_fails_before_effect(self) -> None:
        duplicate = self.root / "com.propertyai.w05-duplicate.plist"
        self._write_plist(duplicate, self.document)
        self._assert_restore_drift_before_effect()

class QuiescenceTransitionAuthorityTests(unittest.TestCase):
    def fixture(
        self,
        events: list[tuple[str, int | None]],
        *,
        ownership: dict[int, tuple[bool, bool]] | None = None,
        unresolved_pids: set[int] | None = None,
        orphan_pids_after_unload: tuple[int, ...] = (),
    ):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        runner = ScriptedLaunchctlRecorder(
            events,
            ownership=ownership,
            unresolved_pids=unresolved_pids,
            orphan_pids_after_unload=orphan_pids_after_unload,
        )
        fixture = StartupAuthorityFixture(Path(temporary.name), runner=runner)
        fixture.write_runtime(stale=False)
        authority = _LaunchdWriterAuthority(
            dcs_path=fixture.dcs,
            launch_agents_root=fixture.launch_root,
            runtime_root=fixture.runtime_root,
            uid=501,
            runner=runner,
            process_probe=runner.process_probe,
            process_scan=runner.process_scan,
            sleep=lambda _seconds: None,
        )
        return fixture, runner, authority

    def test_q1_active_disable_bootout_stable_unloaded_passes_inactive(self) -> None:
        fixture, runner, authority = self.fixture(
            [
                ("running", 50001),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
            ]
        )
        before = authority.discover()
        token = authority.quiesce(before)
        after = authority.discover()
        self.assertEqual("INACTIVE", after.entries[0].state)
        self.assertEqual("FRESH_STARTUP_RESOLUTION", after.entries[0].authority_source)
        self.assertEqual(1, len(runner.calls_for("disable")))
        self.assertEqual(1, len(runner.calls_for("bootout")))
        self.assertEqual([], runner.calls_for("kill"))
        self.assertEqual(before, token.before)
        runtime = json.loads(fixture.runtime_path.read_text(encoding="utf-8"))
        self.assertEqual(50001, runtime["pid"])

    def test_q2_retry2_race_new_pid_is_tolerated_only_until_stable_unloaded(self) -> None:
        fixture, runner, authority = self.fixture(
            [
                ("running", 50001),
                ("running", 50002),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
            ]
        )
        before = authority.discover()
        self.assertEqual(50001, before.entries[0].pid)
        token = authority.quiesce(before)
        self.assertEqual(before, token.before)
        after = authority.discover()
        self.assertEqual("INACTIVE", after.entries[0].state)
        self.assertEqual("FRESH_STARTUP_RESOLUTION", after.entries[0].authority_source)
        self.assertEqual(50001, json.loads(fixture.runtime_path.read_text())["pid"])
        self.assertIn(("/bin/launchctl", "bootout", "gui/501/com.propertyai.cleaning-completion"), runner.calls)

    def test_q3_transition_timeout_fails_closed_with_diagnostic_evidence(self) -> None:
        _fixture, _runner, authority = self.fixture(
            [("running", 50001), ("running", 50002)]
        )
        before = authority.discover()
        with mock.patch(
            "adcp.production_dcs_v8_adoption.time.monotonic", side_effect=[0.0, 16.0, 16.0, 16.0]
        ):
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority.quiesce(before)
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_TIMEOUT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("W05", detail["writer_code"])
        self.assertEqual("STABILIZE_TIMEOUT", detail["transition_stage"])
        self.assertEqual("running", detail["launchd_declared_state"])
        self.assertEqual(50002, detail["launchd_pid"])
        self.assertTrue(detail["pid_live"])
        self.assertTrue(detail["pid_service_owned"])
        self.assertEqual(50001, detail["runtime_identity_pid"])
        self.assertIn("timestamp", detail)

    def test_q4_live_wrong_service_pid_fails_closed(self) -> None:
        _fixture, _runner, authority = self.fixture(
            [("running", 50001), ("running", 50002)],
            ownership={50001: (True, True), 50002: (True, False)},
        )
        before = authority.discover()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce(before)
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual(50002, detail["launchd_pid"])
        self.assertTrue(detail["pid_live"])
        self.assertFalse(detail["pid_service_owned"])

    def test_q5_nonrunning_with_live_service_owned_pid_fails_closed(self) -> None:
        _fixture, _runner, authority = self.fixture(
            [("running", 50001), ("inactive", 50002)]
        )
        before = authority.discover()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce(before)
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("inactive", detail["launchd_declared_state"])
        self.assertEqual(50002, detail["launchd_pid"])
        self.assertTrue(detail["pid_service_owned"])

    def test_q5_unloaded_with_orphan_service_process_fails_closed(self) -> None:
        _fixture, _runner, authority = self.fixture(
            [("running", 50001), ("unloaded", None)],
            orphan_pids_after_unload=(50002,),
        )
        before = authority.discover()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce(before)
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("STABILIZE_ORPHAN_PROCESS", detail["transition_stage"])
        self.assertEqual("UNLOADED", detail["load_state"])
        self.assertEqual([50002], detail["service_owned_live_pids"])

    def test_q6_retained_runtime_pid_is_informational_after_confirmed_inactive(self) -> None:
        fixture, _runner, authority = self.fixture(
            [
                ("running", 50001),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
                ("unloaded", None),
            ]
        )
        token = authority.quiesce(authority.discover())
        authority.verify_quiesced(token)
        after = authority.discover().entries[0]
        runtime = json.loads(fixture.runtime_path.read_text(encoding="utf-8"))
        self.assertEqual(50001, runtime["pid"])
        self.assertEqual("INACTIVE", after.state)
        self.assertIsNone(after.pid)
        self.assertEqual("FRESH_STARTUP_RESOLUTION", after.authority_source)
        self.assertIsNotNone(after.last_runtime_identity_fingerprint)

    def test_q7_ordinary_active_runtime_pid_mismatch_remains_strict(self) -> None:
        _fixture, runner, authority = self.fixture([("running", 50002)])
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_PROCESS_IDENTITY_MISMATCH", caught.exception.code)
        self.assertEqual([], runner.calls_for("disable"))
        self.assertEqual([], runner.calls_for("bootout"))

    def test_pid_reuse_by_unrelated_process_fails_closed(self) -> None:
        _fixture, runner, authority = self.fixture(
            [("running", 50001)], ownership={50001: (True, False)}
        )
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.discover()
        self.assertEqual("PRODUCTION_DCS_WRITER_RUNTIME_STATE_UNRESOLVED", caught.exception.code)
        self.assertEqual([], runner.calls_for("disable"))

    def test_unknown_process_ownership_during_transition_fails_closed(self) -> None:
        _fixture, _runner, authority = self.fixture(
            [("running", 50001), ("running", 50002)], unresolved_pids={50002}
        )
        before = authority.discover()
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce(before)
        self.assertEqual("PRODUCTION_DCS_WRITER_QUIESCENCE_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual(50002, detail["launchd_pid"])
        self.assertFalse(detail["pid_live"])
        self.assertFalse(detail["pid_service_owned"])

    def _physical_entry(self, template, writer_id: str, before_class: str):
        label = f"com.propertyai.{writer_id.lower()}"
        args = (f"/fixture/{writer_id.lower()}/python", "--send")
        autonomous = before_class == "B"
        return replace(
            template,
            writer_id=writer_id,
            launchd_label=label,
            service_code=f"PROPERTYAI_{writer_id}_FIXTURE",
            state="ACTIVE" if before_class == "A" else "INACTIVE",
            pid=72000 if before_class == "A" else None,
            before_class=before_class,
            autonomous_write_capable=autonomous,
            runtime_state="ACTIVE" if before_class == "A" else "INACTIVE",
            load_state="LOADED" if before_class in {"A", "B"} else "UNLOADED",
            enabled_state="DISABLED" if before_class == "C" else "ENABLED",
            plist_path=Path(f"/tmp/{label}.plist"),
            program_arguments=args,
            run_at_load_present=autonomous,
            run_at_load_value=True if autonomous else None,
            start_interval_present=autonomous,
            start_interval_value=300 if autonomous else None,
            keep_alive_present=True,
            keep_alive_value=False,
            working_directory="/fixture/release",
            scheduler_config_fingerprint=f"sha256:{writer_id.lower():0<64}"[:71],
            dcs_binding="/tmp/fixture-dcs",
        )

    def _physical_authority(self, entries):
        runner = PhysicalScheduleRunner(entries)
        authority = _LaunchdWriterAuthority(
            dcs_path=Path("/tmp/fixture-dcs"), launch_agents_root=Path("/tmp/la"),
            runtime_root=Path("/tmp/runtime"), uid=501, runner=runner,
            process_probe=runner.process_probe, process_scan=runner.process_scan,
            sleep=lambda _seconds: None,
        )
        authority._service_definition_for_entry = lambda entry, **_kwargs: (
            entry.plist_path,
            runner.arguments[entry.launchd_label],
        )
        original = tuple(entries)
        def discover():
            observed = []
            for entry in original:
                state = runner.state[entry.launchd_label]
                if state["runtime"] == "ACTIVE":
                    current_class = "A"
                    public_state = "ACTIVE"
                elif bool(state["loaded"]) and not bool(state["disabled"]) and entry.autonomous_write_capable:
                    current_class = "B"
                    public_state = "INACTIVE"
                elif not bool(state["loaded"]) and bool(state["disabled"]):
                    current_class = "C"
                    public_state = "INACTIVE"
                else:
                    current_class = "LEGACY_UNCLASSIFIED"
                    public_state = "INACTIVE"
                observed.append(replace(
                    entry,
                    state=public_state,
                    pid=state["pid"] if public_state == "ACTIVE" else None,
                    before_class=current_class,
                    runtime_state=str(state["runtime"]),
                    load_state="LOADED" if state["loaded"] else "UNLOADED",
                    enabled_state="DISABLED" if state["disabled"] else "ENABLED",
                ))
            result = tuple(observed)
            return DcsWriterInventory(result, _inventory_fingerprint(result))
        authority.discover = discover
        return runner, authority

    def test_mixed_a_b_c_quiesces_b_first_and_restores_exact_classes(self) -> None:
        fixture, _runner, template_authority = self.fixture([("running", 50001)])
        template = template_authority.discover().entries[0]
        a = self._physical_entry(template, "W02", "A")
        b = self._physical_entry(template, "W05", "B")
        c = self._physical_entry(template, "W04", "C")
        runner, authority = self._physical_authority((a, b, c))
        before = authority.discover()
        guard_calls: list[str] = []
        token = authority.quiesce_fenced(
            before,
            assert_current=lambda: guard_calls.append("assert"),
            assert_event_guard=lambda: guard_calls.append("event"),
        )
        disabled = [call[2].rsplit("/", 1)[-1] for call in runner.calls_for("disable")]
        booted = [call[2].rsplit("/", 1)[-1] for call in runner.calls_for("bootout")]
        self.assertEqual([b.launchd_label, a.launchd_label], disabled)
        self.assertEqual([b.launchd_label, a.launchd_label], booted)
        self.assertNotIn(c.launchd_label, disabled + booted)
        after = authority.discover()
        self.assertEqual({"W02": "C", "W05": "C", "W04": "C"}, {e.writer_id: e.before_class for e in after.entries})
        self.assertTrue(guard_calls)
        authority.resume_fenced(token, schema_version=8, assert_current=lambda: guard_calls.append("assert"), assert_event_guard=lambda: guard_calls.append("event"))
        restored = authority.discover()
        self.assertEqual({"W02": "A", "W05": "B", "W04": "C"}, {e.writer_id: e.before_class for e in restored.entries})
        kick_labels = [call[2].rsplit("/", 1)[-1] for call in runner.calls_for("kickstart")]
        self.assertEqual([a.launchd_label], kick_labels)
        self.assertFalse(any(b.launchd_label in " ".join(call) for call in runner.calls_for("kickstart")))

    def test_quiesce_and_b_restore_are_idempotent(self) -> None:
        fixture, _runner, template_authority = self.fixture([("running", 50001)])
        template = template_authority.discover().entries[0]
        b = self._physical_entry(template, "W06", "B")
        runner, authority = self._physical_authority((b,))
        token = authority.quiesce_fenced(authority.discover(), assert_current=lambda: None, assert_event_guard=lambda: None)
        mutation_count = len(runner.calls_for("disable")) + len(runner.calls_for("bootout"))
        authority.quiesce(authority.discover())
        self.assertEqual(mutation_count, len(runner.calls_for("disable")) + len(runner.calls_for("bootout")))
        authority.resume_fenced(token, schema_version=8, assert_current=lambda: None, assert_event_guard=lambda: None)
        first_restore = (len(runner.calls_for("enable")), len(runner.calls_for("bootstrap")), len(runner.calls_for("kickstart")))
        authority.resume_fenced(token, schema_version=8, assert_current=lambda: None, assert_event_guard=lambda: None)
        self.assertEqual(first_restore, (len(runner.calls_for("enable")), len(runner.calls_for("bootstrap")), len(runner.calls_for("kickstart"))))
        self.assertEqual((1, 1, 0), first_restore)

    def test_lease_loss_before_disable_has_zero_physical_effect(self) -> None:
        fixture, _runner, template_authority = self.fixture([("running", 50001)])
        b = self._physical_entry(template_authority.discover().entries[0], "W05", "B")
        runner, authority = self._physical_authority((b,))
        def lost():
            raise ProductionDcsV8AdoptionError("LEASE_LOST_BEFORE_DISABLE")
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce_fenced(authority.discover(), assert_current=lost, assert_event_guard=lambda: None)
        self.assertEqual("LEASE_LOST_BEFORE_DISABLE", caught.exception.code)
        self.assertEqual([], runner.calls_for("disable"))
        self.assertEqual([], runner.calls_for("bootout"))

    def test_lease_loss_between_disable_and_bootout_stops_without_restore(self) -> None:
        fixture, _runner, template_authority = self.fixture([("running", 50001)])
        b = self._physical_entry(template_authority.discover().entries[0], "W05", "B")
        runner, authority = self._physical_authority((b,))
        calls = 0
        def fence():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ProductionDcsV8AdoptionError("LEASE_LOST_AFTER_DISABLE")
        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.quiesce_fenced(authority.discover(), assert_current=fence, assert_event_guard=lambda: None)
        self.assertEqual("LEASE_LOST_AFTER_DISABLE", caught.exception.code)
        self.assertEqual("RECOVERY_REQUIRED_UNDER_FRESH_AUTHORITY", caught.exception.recovery_status)
        self.assertEqual(1, len(runner.calls_for("disable")))
        self.assertEqual([], runner.calls_for("bootout"))
        self.assertEqual([], runner.calls_for("enable"))
        self.assertEqual([], runner.calls_for("bootstrap"))

    def test_w01_w04_w05_w06_scheduled_b_regressions_preserve_exact_baseline(self) -> None:
        fixture, _runner, template_authority = self.fixture([("running", 50001)])
        template = template_authority.discover().entries[0]
        entries = tuple(self._physical_entry(template, code, "B") for code in ("W01", "W04", "W05", "W06"))
        runner, authority = self._physical_authority(entries)
        before = authority.discover()
        token = authority.quiesce_fenced(before, assert_current=lambda: None, assert_event_guard=lambda: None)
        authority.resume_fenced(token, schema_version=8, assert_current=lambda: None, assert_event_guard=lambda: None)
        after = authority.discover()
        self.assertEqual({code: "B" for code in ("W01", "W04", "W05", "W06")}, {e.writer_id: e.before_class for e in after.entries})
        self.assertEqual([], runner.calls_for("kickstart"))
        for before_entry, after_entry in zip(before.entries, after.entries):
            self.assertEqual(before_entry.program_arguments, after_entry.program_arguments)
            self.assertEqual(before_entry.plist_path, after_entry.plist_path)
            self.assertEqual(before_entry.run_at_load_present, after_entry.run_at_load_present)
            self.assertEqual(before_entry.run_at_load_value, after_entry.run_at_load_value)
            self.assertEqual(before_entry.start_interval_value, after_entry.start_interval_value)
            self.assertEqual(before_entry.keep_alive_value, after_entry.keep_alive_value)
            self.assertEqual(before_entry.scheduler_config_fingerprint, after_entry.scheduler_config_fingerprint)

    def test_exact_resume_bootstraps_only_active_before(self) -> None:
        _fixture, _runner, template_authority = self.fixture([("running", 50001)])
        template = template_authority.discover().entries[0]
        inactive = replace(
            template,
            writer_id="W01",
            launchd_label="com.propertyai.w01",
            service_code="PROPERTYAI_W01_FIXTURE",
            state="INACTIVE",
            pid=None,
        )
        active = replace(
            template,
            writer_id="W02",
            launchd_label="com.propertyai.w02",
            service_code="PROPERTYAI_W02_FIXTURE",
        )
        before = DcsWriterInventory((inactive, active), "fixture")
        token = _QuiescenceToken(before, tuple(entry.stable_identity for entry in before.entries))
        commands: list[tuple[str, ...]] = []

        def runner(args, **_kwargs):
            call = tuple(str(value) for value in args)
            commands.append(call)
            return subprocess.CompletedProcess(call, 0, "", "")

        authority = _LaunchdWriterAuthority(
            dcs_path=Path("/tmp/fixture-dcs"),
            launch_agents_root=Path("/tmp/fixture-launch"),
            runtime_root=Path("/tmp/fixture-runtime"),
            uid=501,
            runner=runner,
        )
        authority._service_definition_for_entry = lambda entry, **_kwargs: (
            Path(f"/tmp/{entry.writer_id}.plist"),
            ("/fixture/python", "--send"),
        )
        authority.resume(token)
        flattened = [" ".join(call) for call in commands]
        self.assertTrue(any("enable" in call and "w02" in call for call in flattened))
        self.assertTrue(any("bootstrap" in call and "W02.plist" in call for call in flattened))
        self.assertTrue(any("kickstart" in call and "w02" in call for call in flattened))
        self.assertFalse(any("w01" in call.lower() for call in flattened))

    def test_w02_w03_order_reversal_does_not_change_quiescence_correctness(self) -> None:
        _fixture, _runner, template_authority = self.fixture([("running", 50001)])
        template = template_authority.discover().entries[0]
        w02 = replace(
            template,
            writer_id="W02",
            launchd_label="com.propertyai.w02",
            service_code="PROPERTYAI_W02_FIXTURE",
        )
        w03 = replace(
            template,
            writer_id="W03",
            launchd_label="com.propertyai.w03",
            service_code="PROPERTYAI_W03_FIXTURE",
        )

        outcomes: list[tuple[set[tuple[str, str]], tuple[str, ...]]] = []
        for ordered in ((w02, w03), (w03, w02)):
            commands: list[tuple[str, ...]] = []
            observed_order: list[tuple[str, ...]] = []

            disabled_labels: set[str] = set()

            def runner(args, **_kwargs):
                call = tuple(str(value) for value in args)
                commands.append(call)
                if len(call) >= 3 and call[1] == "disable":
                    disabled_labels.add(call[2].rsplit("/", 1)[-1])
                if len(call) >= 3 and call[1] == "enable":
                    disabled_labels.discard(call[2].rsplit("/", 1)[-1])
                if len(call) >= 2 and call[1] == "print-disabled":
                    body = "\n".join(
                        f'"{label}" => true' for label in sorted(disabled_labels)
                    )
                    return subprocess.CompletedProcess(call, 0, "{\n" + body + "\n}\n", "")
                return subprocess.CompletedProcess(call, 0, "", "")

            authority = _LaunchdWriterAuthority(
                dcs_path=Path("/tmp/fixture-dcs"),
                launch_agents_root=Path("/tmp/fixture-launch"),
                runtime_root=Path("/tmp/fixture-runtime"),
                uid=501,
                runner=runner,
            )
            authority._service_definition_for_entry = lambda entry, **_kwargs: (
                Path(f"/tmp/{entry.writer_id}.plist"),
                ("/fixture/python", "--send"),
            )
            authority._wait_for_stable_nonrunning = lambda transitions, deadline, **_guards: observed_order.append(
                tuple(entry.writer_id for entry, _arguments in transitions)
            )
            inactive = tuple(
                replace(
                    entry,
                    state="INACTIVE",
                    pid=None,
                    runtime_state="INACTIVE",
                    load_state="UNLOADED",
                    enabled_state="DISABLED",
                )
                for entry in ordered
            )
            authority.discover = lambda inactive=inactive: DcsWriterInventory(inactive, "fixture-after")
            token = authority.quiesce(DcsWriterInventory(tuple(ordered), "fixture-before"))
            self.assertEqual({"W02", "W03"}, {entry.writer_id for entry in token.before.entries})
            mutations = {
                (call[1], call[-1].rsplit(".", 1)[-1])
                for call in commands
                if len(call) >= 3 and call[1] in {"disable", "bootout"}
            }
            outcomes.append((mutations, observed_order[0]))

        self.assertEqual(outcomes[0][0], outcomes[1][0])
        self.assertEqual({"W02", "W03"}, set(outcomes[0][1]))
        self.assertEqual({"W02", "W03"}, set(outcomes[1][1]))


class ActiveResumeTransitionAuthorityTests(unittest.TestCase):
    def fixture(
        self,
        *,
        ownership: dict[int, tuple[bool, bool]] | None = None,
        unresolved_pids: set[int] | None = None,
        restart_event: tuple[str, int | None] = ("running", 60002),
    ):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        runner = ScriptedLaunchctlRecorder(
            [("running", 60001)],
            old_pid=60001,
            ownership=ownership or {60001: (True, True), 60002: (True, True)},
            unresolved_pids=unresolved_pids,
            restart_event=restart_event,
        )
        fixture = StartupAuthorityFixture(Path(temporary.name), runner=runner)
        fixture.write_runtime(stale=False)
        sleeps: list[float] = []
        authority = _LaunchdWriterAuthority(
            dcs_path=fixture.dcs,
            launch_agents_root=fixture.launch_root,
            runtime_root=fixture.runtime_root,
            uid=501,
            runner=runner,
            process_probe=runner.process_probe,
            process_scan=runner.process_scan,
            sleep=lambda seconds: sleeps.append(seconds),
        )
        return fixture, runner, authority, sleeps

    @staticmethod
    def resume_token(authority: _LaunchdWriterAuthority) -> tuple[DcsWriterInventory, _QuiescenceToken]:
        before = authority.discover()
        token = _QuiescenceToken(
            before,
            tuple(entry.stable_identity for entry in before.entries),
        )
        authority.resume(token)
        return before, token

    def test_r1_immediate_runtime_identity_publication_reaches_two_fresh_stable_observations(self) -> None:
        fixture, runner, authority, sleeps = self.fixture()
        before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)
        fixture.publish_runtime_pid(60002, incarnation="b" * 64)

        observed = authority.verify_resumed(token)

        self.assertEqual("ACTIVE", observed.entries[0].state)
        self.assertEqual(60002, observed.entries[0].pid)
        self.assertEqual("b" * 64, observed.entries[0].process_incarnation_id)
        self.assertEqual(1, len(sleeps))
        # before + two distinct transition polls + independent strict discover
        self.assertEqual(4, len(runner.calls_for("print")))
        self.assertEqual(before.entries[0].stable_identity, observed.entries[0].stable_identity)

    def test_r2_retry3_60001_to_60002_late_runtime_publication_converges_then_strict_discovers(self) -> None:
        fixture, runner, authority, sleeps = self.fixture()
        _before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)
        published = False

        def publish_after_first_poll(seconds: float) -> None:
            nonlocal published
            sleeps.append(seconds)
            if not published:
                fixture.publish_runtime_pid(60002, incarnation="c" * 64)
                published = True

        authority.sleep = publish_after_first_poll
        observed = authority.verify_resumed(token)

        self.assertTrue(published)
        self.assertEqual((60002, "c" * 64), (observed.entries[0].pid, observed.entries[0].process_incarnation_id))
        # transient poll + stable poll #1 + stable poll #2 + strict discover
        self.assertEqual(5, len(runner.calls_for("print")))
        self.assertEqual([0.2, 0.2], sleeps)

    def test_r3_runtime_identity_never_converges_fails_closed_timeout_with_safe_evidence(self) -> None:
        _fixture, runner, authority, sleeps = self.fixture()
        _before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)

        with mock.patch(
            "adcp.production_dcs_v8_adoption.time.monotonic",
            side_effect=[0.0, 0.0, 16.0],
        ):
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority.verify_resumed(token)

        self.assertEqual(
            "PRODUCTION_DCS_WRITER_ACTIVE_RESUME_STABILIZATION_TIMEOUT",
            caught.exception.code,
        )
        detail = json.loads(caught.exception.detail)
        self.assertEqual("ACTIVE_RESUME_STABILIZATION_TIMEOUT", detail["transition_stage"])
        self.assertEqual(60002, detail["launchd_pid"])
        self.assertEqual(60001, detail["runtime_identity_pid"])
        self.assertEqual([60002], detail["service_owned_live_pids"])
        self.assertTrue(detail["pid_live"])
        self.assertTrue(detail["pid_service_owned"])
        self.assertEqual("LOADED", detail["load_state"])
        self.assertIn("timestamp", detail)
        self.assertEqual([0.2], sleeps)

    def test_r4_new_launchd_pid_wrong_process_fails_closed_without_retry(self) -> None:
        _fixture, runner, authority, sleeps = self.fixture(
            ownership={60001: (True, True), 60002: (True, False)}
        )
        _before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)

        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)

        self.assertEqual("PRODUCTION_DCS_WRITER_ACTIVE_RESUME_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("LAUNCHD_ACTIVE_STATE_UNSAFE", detail["transition_stage"])
        self.assertEqual([], sleeps)

    def test_r5_prior_pid_reuse_by_unrelated_process_fails_closed(self) -> None:
        _fixture, runner, authority, sleeps = self.fixture()
        _before, token = self.resume_token(authority)
        # The retained runtime PID has been reused by a live unrelated process.
        runner.ownership[60001] = (True, False)

        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)

        self.assertEqual("PRODUCTION_DCS_WRITER_ACTIVE_RESUME_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("PRIOR_PID_REUSED_UNRELATED", detail["transition_stage"])
        self.assertEqual([], sleeps)

    def test_r6_unknown_process_ownership_fails_closed_without_transition_retry(self) -> None:
        _fixture, runner, authority, sleeps = self.fixture(unresolved_pids={60002})
        _before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)

        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)

        self.assertEqual("PRODUCTION_DCS_WRITER_ACTIVE_RESUME_INCONSISTENT", caught.exception.code)
        detail = json.loads(caught.exception.detail)
        self.assertEqual("PROCESS_OWNERSHIP_UNRESOLVED", detail["transition_stage"])
        self.assertEqual([], sleeps)

    def test_r7_runtime_thin_authority_mismatch_fails_closed_before_stability(self) -> None:
        fixture, runner, authority, sleeps = self.fixture()
        _before, token = self.resume_token(authority)
        runner.ownership[60001] = (False, False)
        fixture.publish_runtime_pid(60002, incarnation="d" * 64)
        transition_source = "d535e00b8997e470c45dddc9efb9e8c10e656dbe"
        wrong_build = client_build("0.2.0", transition_source)
        runtime = json.loads(fixture.runtime_path.read_text(encoding="utf-8"))
        authorized = json.loads(fixture.authorized_path.read_text(encoding="utf-8"))
        runtime["global_writer_client_build"] = wrong_build
        authorized["global_writer_client_build"] = wrong_build
        fixture.runtime_path.write_text(json.dumps(runtime, sort_keys=True), encoding="utf-8")
        fixture.authorized_path.write_text(json.dumps(authorized, sort_keys=True), encoding="utf-8")

        with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
            authority.verify_resumed(token)

        self.assertEqual(
            "PRODUCTION_DCS_V8_ADOPTION_POST_MIGRATION_WRITER_INVENTORY_CHANGED",
            caught.exception.code,
        )
        detail = json.loads(caught.exception.detail)
        self.assertEqual("RUNTIME_BUILD_OR_THIN_AUTHORITY_MISMATCH", detail["transition_stage"])
        self.assertEqual([], sleeps)

    def test_r10_quiescence_failure_recovery_uses_same_active_stabilization(self) -> None:
        fixture, runner, authority, sleeps = self.fixture()
        before = authority.discover()
        runner.ownership[60001] = (False, False)
        published = False

        def publish_after_first_poll(seconds: float) -> None:
            nonlocal published
            sleeps.append(seconds)
            if not published:
                fixture.publish_runtime_pid(60002, incarnation="e" * 64)
                published = True

        authority.sleep = publish_after_first_poll
        failure = ProductionDcsV8AdoptionError(
            "FIXTURE_QUIESCENCE_FAILURE", phase="QUIESCENCE"
        )
        with mock.patch.object(
            authority, "_wait_for_stable_nonrunning", side_effect=failure
        ):
            with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                authority.quiesce(before)

        # The original quiescence error is preserved only after recovery resume
        # itself reaches two stable observations and strict discovery.
        self.assertEqual("FIXTURE_QUIESCENCE_FAILURE", caught.exception.code)
        self.assertTrue(published)
        self.assertEqual([0.2, 0.2], sleeps)
        self.assertEqual({}, authority._active_resume_pending)
        self.assertEqual(1, len(runner.calls_for("bootstrap")))
        self.assertEqual(1, len(runner.calls_for("kickstart")))

    def test_active_resume_stabilization_is_writer_order_independent(self) -> None:
        fixture, _runner, template_authority, _sleeps = self.fixture(restart_event=("running", 60001))
        template = template_authority.discover().entries[0]
        w02 = replace(
            template,
            writer_id="W02",
            launchd_label="com.propertyai.w02",
            service_code="PROPERTYAI_W02_FIXTURE",
            pid=62002,
        )
        w03 = replace(
            template,
            writer_id="W03",
            launchd_label="com.propertyai.w03",
            service_code="PROPERTYAI_W03_FIXTURE",
            pid=62003,
        )
        outcomes: list[tuple[dict[str, tuple[int, str]], tuple[str, ...]]] = []
        for ordered in ((w02, w03), (w03, w02)):
            authority = _LaunchdWriterAuthority(
                dcs_path=fixture.dcs,
                launch_agents_root=fixture.launch_root,
                runtime_root=fixture.runtime_root,
                uid=501,
                sleep=lambda _seconds: None,
            )
            calls: list[str] = []
            authority._service_definition_for_entry = lambda entry, **_kwargs: (
                Path(f"/tmp/{entry.writer_id}.plist"),
                ("/fixture/python", "--send"),
            )

            def observe(entry, _arguments, *, prior_process_pids):
                calls.append(entry.writer_id)
                pid = 62002 if entry.writer_id == "W02" else 62003
                return True, (pid, entry.writer_id.lower() * 32), None, (pid,)

            authority._observe_active_resume_entry = observe
            result = authority._wait_for_stable_active_resume(
                ordered, deadline=10**12
            )
            outcomes.append((dict(result), tuple(calls)))

        self.assertEqual(outcomes[0][0], outcomes[1][0])
        self.assertEqual(("W02", "W03", "W02", "W03"), outcomes[0][1])
        self.assertEqual(("W02", "W03", "W02", "W03"), outcomes[1][1])


if __name__ == "__main__":
    unittest.main()
