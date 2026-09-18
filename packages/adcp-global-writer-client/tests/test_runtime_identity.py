from __future__ import annotations

import importlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from tempfile import TemporaryDirectory
from types import ModuleType
import unittest
from unittest.mock import patch

import adcp_global_writer_client as public_api
import adcp_global_writer_client.runtime_identity as runtime_module
from adcp_global_writer_client import (
    MATCH,
    MISMATCH,
    UNKNOWN,
    AuthorizedProductionIdentity,
    ProcessAuthorityIdentity,
    ProductBuildIdentity,
    RuntimeIdentity,
    RuntimeIdentityError,
    authorize_new_mutation,
    compare_runtime_identity,
    process_started_at,
    read_authorized_identity,
    read_runtime_identity,
    write_authorized_identity,
    write_runtime_identity,
)

A = "a" * 40
B = "b" * 40
SOURCE_A = "source-commit:" + A
SOURCE_B = "source-commit:" + B
CLIENT_A = f"adcp-global-writer-client@0.1.0+g{A[:12]}|source={A}|artifact={SOURCE_A}"
PRODUCT_A = f"product:PropertyAI@g{A[:12]}|source={A}|artifact={SOURCE_A}"


def product_identity_source(commit: str) -> str:
    source = "source-commit:" + commit
    return "\n".join(
        [
            "PRODUCT_IDENTITY_MODULE = 'propertyai_core._global_writer_build_identity'",
            "PRODUCT_NAME = 'PropertyAI'",
            f"PRODUCT_BUILD_COMMIT = {commit!r}",
            f"SOURCE_ARTIFACT_IDENTITY = {source!r}",
            f"PRODUCT_BUILD_IDENTITY = {f'product:PropertyAI@g{commit[:12]}|source={commit}|artifact={source}'!r}",
            "",
        ]
    )


def product(commit: str = A) -> ProductBuildIdentity:
    source = "source-commit:" + commit
    return ProductBuildIdentity(
        product_name="PropertyAI",
        product_build_commit=commit,
        product_build_identity=f"product:PropertyAI@g{commit[:12]}|source={commit}|artifact={source}",
        source_artifact_identity=source,
    )


def authorized(*, commit: str = A, client: str = CLIENT_A, config: str | None = None) -> AuthorizedProductionIdentity:
    source = "source-commit:" + commit
    return AuthorizedProductionIdentity(
        service_code="W02_OPS_TELEGRAM_MUTATION",
        product_build_commit=commit,
        product_build_identity=f"product:PropertyAI@g{commit[:12]}|source={commit}|artifact={source}",
        global_writer_client_build=client,
        source_root_or_artifact_identity=source,
        config_artifact_identity=config,
        authorized_at="2026-08-29T00:01:00.000000+00:00",
    )


def raw_runtime(
    *,
    pid: int,
    start: str,
    incarnation: str,
    generated: str,
    client: str = CLIENT_A,
    commit: str = A,
) -> dict[str, object]:
    source = "source-commit:" + commit
    return {
        "service_code": "W02_OPS_TELEGRAM_MUTATION",
        "pid": pid,
        "process_started_at": start,
        "process_incarnation_id": incarnation,
        "product_build_commit": commit,
        "product_build_identity": f"product:PropertyAI@g{commit[:12]}|source={commit}|artifact={source}",
        "global_writer_client_build": client,
        "interpreter_or_executable": sys.executable,
        "source_root_or_artifact_identity": source,
        "identity_generated_at": generated,
        "config_artifact_identity": None,
        "schema_version": 3,
    }


class RuntimeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime.json"
        self.authority = self.root / "authorized.json"
        self.pid = os.getpid()
        self.start = process_started_at(self.pid)
        self.incarnation = runtime_module._current_process_incarnation_id()

    def tearDown(self) -> None:
        for name in ("propertyai_core._global_writer_build_identity", "propertyai_core"):
            sys.modules.pop(name, None)
        self.temp.cleanup()

    def capture_internal(self, commit: str = A) -> RuntimeIdentity:
        with patch("adcp_global_writer_client.runtime_identity.installed_global_writer_client_build", return_value=CLIENT_A):
            return runtime_module._capture_runtime_identity_with_verifier(
                service_code="W02_OPS_TELEGRAM_MUTATION",
                product_build_identity=product(commit),
                verifier=runtime_module.LiveOSProcessIdentityVerifier(),
            )

    def test_live_match_and_authority_mismatch(self) -> None:
        loaded = self.capture_internal()
        write_runtime_identity(self.runtime, loaded)
        write_authorized_identity(self.authority, authorized())
        self.assertEqual(MATCH, compare_runtime_identity(loaded, authorized()))
        self.assertEqual(MATCH, authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority))
        write_authorized_identity(self.authority, authorized(commit=B))
        self.assertEqual(MISMATCH, compare_runtime_identity(loaded, authorized(commit=B)))
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_MISMATCH"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)

    def test_dead_pid_and_different_live_process_manifest_fail_stale(self) -> None:
        write_authorized_identity(self.authority, authorized())
        dead = 999999
        self.runtime.write_text(
            json.dumps(raw_runtime(pid=dead, start=self.start, incarnation="1" * 64, generated=self.start)), encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_STALE"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)

        child = subprocess.Popen(["sleep", "20"])
        try:
            child_start = process_started_at(child.pid)
            self.runtime.write_text(
                json.dumps(raw_runtime(pid=child.pid, start=child_start, incarnation="2" * 64, generated=child_start)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_STALE"):
                authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)
        finally:
            child.terminate()
            child.wait()

    def test_same_pid_same_second_different_incarnation_fails_stale(self) -> None:
        self.runtime.write_text(
            json.dumps(raw_runtime(pid=self.pid, start=self.start, incarnation="1" * 64, generated=self.start)), encoding="utf-8"
        )
        write_authorized_identity(self.authority, authorized())

        class ReusedPidVerifier:
            def current_process_identity(self) -> ProcessAuthorityIdentity:
                return ProcessAuthorityIdentity(self_pid, same_start, "2" * 64)

        self_pid = self.pid
        same_start = self.start
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_STALE"):
            runtime_module._authorize_new_mutation_with_verifier(
                runtime_identity_path=self.runtime,
                authorized_identity_path=self.authority,
                verifier=ReusedPidVerifier(),
            )

    def test_ambiguous_or_unavailable_current_process_evidence_fails_closed(self) -> None:
        loaded = self.capture_internal()
        write_runtime_identity(self.runtime, loaded)
        write_authorized_identity(self.authority, authorized())

        class AmbiguousVerifier:
            def current_process_identity(self) -> ProcessAuthorityIdentity:
                raise RuntimeIdentityError("RUNTIME_IDENTITY_STALE", "ambiguous")

        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_STALE"):
            runtime_module._authorize_new_mutation_with_verifier(
                runtime_identity_path=self.runtime,
                authorized_identity_path=self.authority,
                verifier=AmbiguousVerifier(),
            )

    def test_process_start_mismatch_fails_stale(self) -> None:
        loaded = self.capture_internal()
        write_runtime_identity(self.runtime, loaded)
        write_authorized_identity(self.authority, authorized())

        class MismatchVerifier:
            def current_process_identity(self) -> ProcessAuthorityIdentity:
                return ProcessAuthorityIdentity(os.getpid(), "2020-01-01T00:00:00.000000+00:00", self_incarnation)

        self_incarnation = self.incarnation
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_STALE"):
            runtime_module._authorize_new_mutation_with_verifier(
                runtime_identity_path=self.runtime,
                authorized_identity_path=self.authority,
                verifier=MismatchVerifier(),
            )

    def test_public_authority_apis_accept_no_pid_start_incarnation_or_provider(self) -> None:
        auth_sig = inspect.signature(authorize_new_mutation)
        capture_sig = inspect.signature(public_api.capture_runtime_identity)
        for forbidden in ("pid", "process_start", "process_started_at", "incarnation", "process_incarnation_id"):
            self.assertNotIn(forbidden, auth_sig.parameters)
            self.assertNotIn(forbidden, capture_sig.parameters)
        for forbidden in ("product_build_identity_provider", "provider", "module", "module_path", "product_build_commit"):
            self.assertNotIn(forbidden, capture_sig.parameters)
        self.assertFalse(hasattr(public_api, "ImportedModuleProductBuildIdentityProvider"))
        with self.assertRaises(TypeError):
            public_api.capture_runtime_identity(service_code="X", product_build_identity_provider=object())  # type: ignore[call-arg]

    def _install_trusted_product_package(self, commit: str, *, root: Path | None = None) -> Path:
        package = (self.root if root is None else root) / "propertyai_core"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        module = package / "_global_writer_build_identity.py"
        module.write_text(product_identity_source(commit), encoding="utf-8")
        return module

    def test_product_authority_loads_directly_from_anchored_root_and_expected_commit(self) -> None:
        module_path = self._install_trusted_product_package(A)
        loaded = runtime_module._load_product_build_identity_from_anchor(self.root, A)
        self.assertEqual(A, loaded.product_build_commit)
        self.assertEqual(SOURCE_A, loaded.source_artifact_identity)
        self.assertTrue(module_path.is_file())
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            runtime_module._load_product_build_identity_from_anchor(self.root, B)
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            runtime_module._load_product_build_identity_from_anchor(Path("relative-root"), A)

    def test_product_authority_seal_resolves_symlink_root_to_canonical_snapshot(self) -> None:
        target = self.root / "target"
        target.mkdir()
        module_path = self._install_trusted_product_package(A, root=target)
        link = self.root / "product-link"
        link.symlink_to(target)

        snapshot = runtime_module._seal_product_authority_from_anchor(link, A)

        self.assertEqual(target.resolve(), snapshot.canonical_root)
        self.assertEqual(module_path.resolve(), snapshot.identity_path)
        self.assertEqual(A, snapshot.expected_commit)
        self.assertEqual(A, snapshot.product_build_identity.product_build_commit)

    def test_startup_missing_artifact_then_directory_repair_remains_fail_closed(self) -> None:
        startup_root = self.root / "startup-missing"
        startup_root.mkdir()
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(startup_root)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = A
        env["PYTHONPATH"] = str(package_src)
        artifact_source = product_identity_source(A)
        script = "\n".join(
            [
                "from pathlib import Path",
                "import os",
                "import adcp_global_writer_client as api",
                f"root = Path({str(startup_root)!r})",
                "package = root / 'propertyai_core'",
                "package.mkdir(parents=True, exist_ok=True)",
                f"(package / '_global_writer_build_identity.py').write_text({artifact_source!r}, encoding='utf-8')",
                "for attempt in range(2):",
                "    try:",
                "        api.capture_runtime_identity(service_code='R4_DIRECTORY_REPAIR')",
                "    except api.RuntimeIdentityError as error:",
                "        print(error.code)",
                "    else:",
                "        raise SystemExit('startup failure repaired by ordinary capture')",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual(["RUNTIME_IDENTITY_UNKNOWN", "RUNTIME_IDENTITY_UNKNOWN"], completed.stdout.splitlines())

    def test_startup_invalid_symlink_then_retarget_remains_fail_closed(self) -> None:
        invalid = self.root / "invalid-target"
        valid = self.root / "valid-target"
        invalid.mkdir()
        valid.mkdir()
        self._install_trusted_product_package(A, root=valid)
        link = self.root / "startup-link"
        link.symlink_to(invalid)
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(link)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = A
        env["PYTHONPATH"] = str(package_src)
        script = "\n".join(
            [
                "from pathlib import Path",
                "import adcp_global_writer_client as api",
                f"link = Path({str(link)!r})",
                f"valid = Path({str(valid)!r})",
                "link.unlink()",
                "link.symlink_to(valid)",
                "try:",
                "    api.capture_runtime_identity(service_code='R4_SYMLINK_RETARGET')",
                "except api.RuntimeIdentityError as error:",
                "    print(error.code)",
                "else:",
                "    raise SystemExit('startup symlink failure repaired by retarget')",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual("RUNTIME_IDENTITY_UNKNOWN", completed.stdout.strip())

    def test_successful_startup_a_ignores_later_environment_b(self) -> None:
        root_a = self.root / "product-a"
        root_b = self.root / "product-b"
        root_a.mkdir()
        root_b.mkdir()
        self._install_trusted_product_package(A, root=root_a)
        self._install_trusted_product_package(B, root=root_b)
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(root_a)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = A
        env["PYTHONPATH"] = str(package_src)
        script = "\n".join(
            [
                "import os",
                "from unittest.mock import patch",
                "import adcp_global_writer_client as api",
                f"os.environ['ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT'] = {str(root_b)!r}",
                f"os.environ['ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT'] = {B!r}",
                f"with patch('adcp_global_writer_client.runtime_identity.installed_global_writer_client_build', return_value={CLIENT_A!r}):",
                "    captured = api.capture_runtime_identity(service_code='R4_ENV_REBIND')",
                "print(captured.product_build_commit)",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual(A, completed.stdout.strip())

    def test_successful_startup_a_ignores_later_filesystem_b_and_does_not_rediscover(self) -> None:
        root = self.root / "replace-after-success"
        root.mkdir()
        module_path = self._install_trusted_product_package(A, root=root)
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(root)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = A
        env["PYTHONPATH"] = str(package_src)
        b_source = product_identity_source(B)
        script = "\n".join(
            [
                "from unittest.mock import patch",
                "from pathlib import Path",
                "import adcp_global_writer_client as api",
                "import adcp_global_writer_client.runtime_identity as runtime_identity",
                f"Path({str(module_path)!r}).write_text({b_source!r}, encoding='utf-8')",
                "with patch.object(runtime_identity, '_seal_product_authority_from_anchor', side_effect=AssertionError('capture rediscovered Product authority')):",
                f"    with patch.object(runtime_identity, 'installed_global_writer_client_build', return_value={CLIENT_A!r}):",
                "        captured = api.capture_runtime_identity(service_code='R4_FILESYSTEM_REPLACE')",
                "print(captured.product_build_commit)",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual(A, completed.stdout.strip())

    def test_startup_expected_commit_mismatch_cannot_be_repaired_by_environment_change(self) -> None:
        root = self.root / "commit-mismatch"
        root.mkdir()
        self._install_trusted_product_package(A, root=root)
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(root)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = B
        env["PYTHONPATH"] = str(package_src)
        script = "\n".join(
            [
                "import os",
                "import adcp_global_writer_client as api",
                f"os.environ['ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT'] = {A!r}",
                "try:",
                "    api.capture_runtime_identity(service_code='R4_EXPECTED_COMMIT_REPAIR')",
                "except api.RuntimeIdentityError as error:",
                "    print(error.code)",
                "else:",
                "    raise SystemExit('startup expected-commit mismatch repaired late')",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual("RUNTIME_IDENTITY_UNKNOWN", completed.stdout.strip())

    def test_no_public_runtime_authority_bootstrap_or_rebind_api(self) -> None:
        for name in ("initialize_runtime_authority", "retry_runtime_authority", "rebind_runtime_authority"):
            self.assertFalse(hasattr(public_api, name))

    def test_public_capture_rejects_pythonpath_shadow_as_product_authority(self) -> None:
        trusted_root = self.root / "trusted"
        shadow_root = self.root / "shadow"
        trusted_root.mkdir()
        shadow_root.mkdir()
        original_root = self.root
        self.root = trusted_root
        self._install_trusted_product_package(A)
        self.root = shadow_root
        self._install_trusted_product_package(B)
        self.root = original_root
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env["ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"] = str(trusted_root)
        env["ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"] = A
        env["PYTHONPATH"] = os.pathsep.join((str(shadow_root), str(package_src)))
        script = "\n".join(
            [
                "from unittest.mock import patch",
                "import adcp_global_writer_client as api",
                f"with patch('adcp_global_writer_client.runtime_identity.installed_global_writer_client_build', return_value={CLIENT_A!r}):",
                "    captured = api.capture_runtime_identity(service_code='R2_B1A_REPRO')",
                "print(captured.product_build_commit)",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual(A, completed.stdout.strip())

    def test_public_capture_with_only_pythonpath_shadow_fails_closed(self) -> None:
        shadow_root = self.root / "shadow-only"
        shadow_root.mkdir()
        original_root = self.root
        self.root = shadow_root
        self._install_trusted_product_package(B)
        self.root = original_root
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env.pop("ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT", None)
        env.pop("ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT", None)
        env["PYTHONPATH"] = os.pathsep.join((str(shadow_root), str(package_src)))
        script = "\n".join(
            [
                "import adcp_global_writer_client as api",
                "try:",
                "    api.capture_runtime_identity(service_code='R2_B1A_REPRO')",
                "except api.RuntimeIdentityError as error:",
                "    print(error.code)",
                "else:",
                "    raise SystemExit('forged Product authority accepted')",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual("RUNTIME_IDENTITY_UNKNOWN", completed.stdout.strip())

    def test_post_import_environment_change_cannot_reselect_product_authority(self) -> None:
        trusted_root = self.root / "late-config"
        trusted_root.mkdir()
        original_root = self.root
        self.root = trusted_root
        self._install_trusted_product_package(A)
        self.root = original_root
        package_src = Path(__file__).resolve().parents[1] / "src"
        env = os.environ.copy()
        env.pop("ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT", None)
        env.pop("ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT", None)
        env["PYTHONPATH"] = str(package_src)
        script = "\n".join(
            [
                "import os",
                "import adcp_global_writer_client as api",
                f"os.environ['ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT'] = {str(trusted_root)!r}",
                f"os.environ['ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT'] = {A!r}",
                "try:",
                "    api.capture_runtime_identity(service_code='STARTUP_SEAL_REPRO')",
                "except api.RuntimeIdentityError as error:",
                "    print(error.code)",
                "else:",
                "    raise SystemExit('late request-level authority selection accepted')",
            ]
        )
        completed = subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
        self.assertEqual("RUNTIME_IDENTITY_UNKNOWN", completed.stdout.strip())

    def test_canonical_looking_sys_modules_forgery_is_not_product_authority(self) -> None:
        module_path = self._install_trusted_product_package(A)
        package = ModuleType("propertyai_core")
        package.__file__ = str(module_path.parent / "__init__.py")
        forged = ModuleType("propertyai_core._global_writer_build_identity")
        forged.__package__ = "propertyai_core"
        forged.__file__ = str(module_path)
        forged.__spec__ = importlib.machinery.ModuleSpec(
            "propertyai_core._global_writer_build_identity", loader=None, origin=str(module_path)
        )
        forged.PRODUCT_IDENTITY_MODULE = "propertyai_core._global_writer_build_identity"
        forged.PRODUCT_NAME = "PropertyAI"
        forged.PRODUCT_BUILD_COMMIT = B
        forged.SOURCE_ARTIFACT_IDENTITY = SOURCE_B
        forged.PRODUCT_BUILD_IDENTITY = f"product:PropertyAI@g{B[:12]}|source={B}|artifact={SOURCE_B}"
        sys.modules["propertyai_core"] = package
        sys.modules["propertyai_core._global_writer_build_identity"] = forged
        with (
            patch.object(runtime_module, "_AUTHORIZED_PRODUCT_ROOT_AT_STARTUP", None),
            patch.object(runtime_module, "_EXPECTED_PRODUCT_COMMIT_AT_STARTUP", None),
        ):
            with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
                public_api.capture_runtime_identity(service_code="R2_B1B_REPRO")
        loaded = runtime_module._load_product_build_identity_from_anchor(self.root, A)
        self.assertEqual(A, loaded.product_build_commit)

    def test_product_identity_symlink_escape_is_rejected(self) -> None:
        outside = self.root / "outside.py"
        outside.write_text(
            "\n".join(
                [
                    "PRODUCT_IDENTITY_MODULE = 'propertyai_core._global_writer_build_identity'",
                    "PRODUCT_NAME = 'PropertyAI'",
                    f"PRODUCT_BUILD_COMMIT = {A!r}",
                    f"SOURCE_ARTIFACT_IDENTITY = {SOURCE_A!r}",
                    f"PRODUCT_BUILD_IDENTITY = {PRODUCT_A!r}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        root = self.root / "authorized"
        package = root / "propertyai_core"
        package.mkdir(parents=True)
        (package / "_global_writer_build_identity.py").symlink_to(outside)
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            runtime_module._load_product_build_identity_from_anchor(root, A)

    @unittest.skipUnless(hasattr(os, "fork"), "fork required")
    def test_fork_incarnation_init_failure_is_transactional(self) -> None:
        parent_nonce = runtime_module._current_process_incarnation_id()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            original = runtime_module.secrets.token_hex
            calls = 0

            def flaky(size: int) -> str:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("CSPRNG_FAIL")
                return original(size)

            runtime_module.secrets.token_hex = flaky
            first_failed = False
            try:
                runtime_module._current_process_incarnation_id()
            except RuntimeError:
                first_failed = True
            second = runtime_module._current_process_incarnation_id()
            os.write(write_fd, json.dumps({"first_failed": first_failed, "second": second}).encode("utf-8"))
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        payload = json.loads(os.read(read_fd, 65536).decode("utf-8"))
        os.close(read_fd)
        _, status = os.waitpid(child, 0)
        self.assertEqual(0, status)
        self.assertTrue(payload["first_failed"])
        self.assertNotEqual(parent_nonce, payload["second"])

    def test_same_process_rebind_is_rejected_and_manifest_remains_a(self) -> None:
        loaded_a = self.capture_internal(A)
        write_runtime_identity(self.runtime, loaded_a)
        loaded_b = self.capture_internal(B)
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_REBIND_FORBIDDEN"):
            write_runtime_identity(self.runtime, loaded_b)
        self.assertEqual(A, read_runtime_identity(self.runtime).product_build_commit)

    def test_b2_generated_before_process_start_is_unknown(self) -> None:
        self.runtime.write_text(
            json.dumps(
                raw_runtime(
                    pid=self.pid,
                    start=self.start,
                    incarnation=self.incarnation,
                    generated="2000-01-01T00:00:00.000000+00:00",
                )
            ),
            encoding="utf-8",
        )
        write_authorized_identity(self.authority, authorized())
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)

    def test_b3_garbage_build_cannot_match(self) -> None:
        payload = raw_runtime(
            pid=self.pid, start=self.start, incarnation=self.incarnation, generated=self.start, client="garbage"
        )
        self.runtime.write_text(json.dumps(payload), encoding="utf-8")
        auth = authorized().as_dict()
        auth["global_writer_client_build"] = "garbage"
        self.authority.write_text(json.dumps(auth), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)
        malformed_loaded = RuntimeIdentity(**payload)
        malformed_authorized = AuthorizedProductionIdentity(**auth)
        self.assertEqual(UNKNOWN, compare_runtime_identity(malformed_loaded, malformed_authorized))

    def test_config_identity_is_authoritative(self) -> None:
        config_a = "sha256:" + "1" * 64
        config_b = "sha256:" + "2" * 64
        with patch("adcp_global_writer_client.runtime_identity.installed_global_writer_client_build", return_value=CLIENT_A):
            loaded = runtime_module._capture_runtime_identity_with_verifier(
                service_code="W02_OPS_TELEGRAM_MUTATION",
                product_build_identity=product(A),
                verifier=runtime_module.LiveOSProcessIdentityVerifier(),
                config_artifact_identity=config_a,
            )
        write_runtime_identity(self.runtime, loaded)
        write_authorized_identity(self.authority, authorized(config=config_b))
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_MISMATCH"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)

    def test_corrupt_or_partial_manifest_never_matches(self) -> None:
        self.runtime.write_text('{"schema_version":3', encoding="utf-8")
        write_authorized_identity(self.authority, authorized())
        with self.assertRaisesRegex(RuntimeIdentityError, "RUNTIME_IDENTITY_UNKNOWN"):
            authorize_new_mutation(runtime_identity_path=self.runtime, authorized_identity_path=self.authority)

    def test_atomic_identity_publication_reader_never_observes_partial_json(self) -> None:
        a = authorized()
        b = authorized(commit=B)
        write_authorized_identity(self.authority, a)
        failures: list[BaseException] = []

        def writer(identity: AuthorizedProductionIdentity) -> None:
            try:
                for _ in range(100):
                    write_authorized_identity(self.authority, identity)
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=writer, args=(a,)), threading.Thread(target=writer, args=(b,))]
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads):
            try:
                observed = read_authorized_identity(self.authority)
                self.assertIn(observed.product_build_commit, {A, B})
            except BaseException as error:
                failures.append(error)
                break
        for thread in threads:
            thread.join()
        self.assertEqual([], failures)

    def test_product_identity_generator_binds_exact_clean_commit_and_canonical_module(self) -> None:
        repo = self.root / "product"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        (repo / "app.py").write_text("A=1\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "A"], cwd=repo, check=True)
        commit_a = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        module_path = self.root / "product_build_identity.py"
        tool = Path(__file__).resolve().parents[3] / "tools/generate_product_build_identity_module.py"
        subprocess.run(
            [sys.executable, str(tool), "--source-root", str(repo), "--product-name", "PropertyAI", "--output", str(module_path)],
            check=True,
        )
        text = module_path.read_text(encoding="utf-8")
        self.assertIn("propertyai_core._global_writer_build_identity", text)
        self.assertIn(commit_a, text)

    def test_product_identity_generator_rejects_dirty_source(self) -> None:
        repo = self.root / "dirty-product"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        (repo / "app.py").write_text("A=1\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "A"], cwd=repo, check=True)
        (repo / "app.py").write_text("dirty\n", encoding="utf-8")
        tool = Path(__file__).resolve().parents[3] / "tools/generate_product_build_identity_module.py"
        completed = subprocess.run(
            [sys.executable, str(tool), "--source-root", str(repo), "--product-name", "PropertyAI", "--output", str(self.root / "x.py")],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("dirty", completed.stderr + completed.stdout)


if __name__ == "__main__":
    unittest.main()
