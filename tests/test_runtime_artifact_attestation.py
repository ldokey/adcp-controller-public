from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile

from adcp.runtime_artifact_attestation import (
    RuntimeArtifactAttestationError,
    attest_runtime_artifact,
)


SOURCE = "1" * 40
VERSION = "0.4.0"
BUILD = f"adcp-global-writer-client@{VERSION}+g{SOURCE[:12]}"
SCHEMAS = (6, 7, 8, 9)
SCHEMA_ID = "sha256:" + "2" * 64


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    return f"sha256={digest}"


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.venv = root / "venv"
        venv.EnvBuilder(with_pip=False, symlinks=True).create(self.venv)
        self.python = self.venv / "bin" / "python"
        self.purelib = Path(
            subprocess.run(
                [str(self.python), "-B", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        self.wheel = root / "accepted.whl"
        self.build_wheel()
        self.install()

    def build_wheel(
        self,
        *,
        version: str = VERSION,
        build: str = BUILD,
        source: str = SOURCE,
        schemas: tuple[int, ...] = SCHEMAS,
        extra_members: dict[str, bytes] | None = None,
    ) -> Path:
        dist = f"adcp_global_writer_client-{version}.dist-info"
        init = f'''from ._build_identity import BUILD_ID, SOURCE_COMMIT, EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS, EXPECTED_THIN_CONTRACT_FORMAT_VERSION, EXPECTED_SCHEMA_CONTRACT_IDENTITY\n\nclass _Identity:\n    build_id = BUILD_ID\n    source_commit = SOURCE_COMMIT\n    supported_dcs_schema_versions = EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS\n    thin_contract_format_version = EXPECTED_THIN_CONTRACT_FORMAT_VERSION\n    schema_contract_identity = EXPECTED_SCHEMA_CONTRACT_IDENTITY\n\ndef client_build_identity():\n    return _Identity()\n'''.encode()
        identity = (
            '"""fixture build identity"""\n'
            f"CLIENT_PACKAGE_NAME = 'adcp-global-writer-client'\n"
            f"CLIENT_VERSION = {version!r}\n"
            f"SOURCE_COMMIT = {source!r}\n"
            f"BUILD_ID = {build!r}\n"
            f"ARTIFACT_IDENTITY = 'source-commit:{source}'\n"
            "EXPECTED_THIN_CONTRACT_FORMAT_VERSION = 2\n"
            f"EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = {schemas!r}\n"
            f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = {SCHEMA_ID!r}\n"
        ).encode()
        members: dict[str, bytes] = {
            "adcp_global_writer_client/__init__.py": init,
            "adcp_global_writer_client/_build_identity.py": identity,
            "adcp_global_writer_client/payload.py": b"VALUE = 7\n",
            "adcp_global_writer_client/_schema_contract.py": (
                "THIN_CONTRACT_FORMAT_VERSION = 2\n"
                f"SUPPORTED_DCS_SCHEMA_VERSIONS = {schemas!r}\n"
                f"SCHEMA_CONTRACT_IDENTITY = {SCHEMA_ID!r}\n"
            ).encode(),
            f"{dist}/METADATA": (
                "Metadata-Version: 2.4\n"
                "Name: adcp-global-writer-client\n"
                f"Version: {version}\n"
                "Summary: fixture\n\n"
            ).encode(),
            f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            f"{dist}/top_level.txt": b"adcp_global_writer_client\n",
        }
        members.update(extra_members or {})
        record_name = f"{dist}/RECORD"
        record_lines = [
            f"{name},{_record_hash(data)},{len(data)}" for name, data in sorted(members.items())
        ]
        record_lines.append(f"{record_name},,")
        members[record_name] = ("\n".join(record_lines) + "\n").encode()
        with zipfile.ZipFile(self.wheel, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in sorted(members):
                archive.writestr(_zip_info(name), members[name])
        return self.wheel

    @property
    def wheel_sha(self) -> str:
        return hashlib.sha256(self.wheel.read_bytes()).hexdigest()

    @property
    def dist_info(self) -> Path:
        matches = sorted(self.purelib.glob("adcp_global_writer_client-*.dist-info"))
        if len(matches) != 1:
            raise AssertionError(matches)
        return matches[0]

    @property
    def package_root(self) -> Path:
        return self.purelib / "adcp_global_writer_client"

    def install(self) -> None:
        if self.package_root.exists():
            shutil.rmtree(self.package_root)
        for old in self.purelib.glob("adcp_global_writer_client-*.dist-info"):
            shutil.rmtree(old)
        with zipfile.ZipFile(self.wheel) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                target = self.purelib / info.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))

    def rewrite_record(self) -> None:
        record = self.dist_info / "RECORD"
        lines: list[str] = []
        for root in (self.package_root, self.dist_info):
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path == record or "__pycache__" in path.parts:
                    continue
                rel = path.relative_to(self.purelib).as_posix()
                data = path.read_bytes()
                lines.append(f"{rel},{_record_hash(data)},{len(data)}")
        lines.append(f"{record.relative_to(self.purelib).as_posix()},,")
        record.write_text("\n".join(sorted(lines[:-1])) + "\n" + lines[-1] + "\n", encoding="utf-8")

    def set_direct_url(self, payload: dict) -> None:
        (self.dist_info / "direct_url.json").write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        self.rewrite_record()

    def attest(self, **overrides):
        kwargs = {
            "accepted_wheel_path": self.wheel,
            "expected_wheel_sha256": self.wheel_sha,
            "interpreter_path": self.python,
            "expected_version": VERSION,
            "expected_build_id": BUILD,
            "expected_source_commit": SOURCE,
            "required_dcs_schema": 9,
            "startup_environment": {},
            "binding_facts": {"writer_code": "W02", "fence": 17},
        }
        kwargs.update(overrides)
        return attest_runtime_artifact(**kwargs)


def _rewrite_fixture_metadata(fx: _Fixture, transform) -> None:
    rewritten = fx.root / "metadata-rewritten.whl"
    with zipfile.ZipFile(fx.wheel) as source:
        members = {info.filename: source.read(info.filename) for info in source.infolist() if not info.is_dir()}
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    if len(metadata_names) != 1 or len(record_names) != 1:
        raise AssertionError((metadata_names, record_names))
    metadata_name = metadata_names[0]
    record_name = record_names[0]
    members[metadata_name] = transform(members[metadata_name])
    record_lines = [
        f"{name},{_record_hash(data)},{len(data)}"
        for name, data in sorted(members.items())
        if name != record_name
    ]
    record_lines.append(f"{record_name},,")
    members[record_name] = ("\n".join(record_lines) + "\n").encode()
    with zipfile.ZipFile(rewritten, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            archive.writestr(_zip_info(name), members[name])
    fx.wheel.unlink()
    rewritten.rename(fx.wheel)
    fx.install()


def _explicit_target_kwargs(fx: _Fixture) -> dict:
    return {
        "accepted_wheel_path": fx.wheel,
        "expected_wheel_sha256": fx.wheel_sha,
        "interpreter_path": fx.python,
        "expected_version": VERSION,
        "expected_build_id": BUILD,
        "expected_source_commit": SOURCE,
        "required_dcs_schema": 9,
        "startup_environment": {},
        "binding_facts": {"writer_code": "W02", "fence": 17},
    }


class RuntimeArtifactAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="adcp-runtime-attestation-")
        self.root = Path(self.temp.name)
        self.fx = _Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assertCode(self, code: str, callable_) -> RuntimeArtifactAttestationError:
        with self.assertRaises(RuntimeArtifactAttestationError) as caught:
            callable_()
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def test_01_accepted_wheel_actual_sha_mismatch_fails(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
            lambda: self.fx.attest(expected_wheel_sha256="0" * 64),
        )

    def test_02_accepted_wheel_leaf_symlink_fails(self) -> None:
        link = self.root / "accepted-link.whl"
        link.symlink_to(self.fx.wheel)
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_SYMLINK_FORBIDDEN",
            lambda: self.fx.attest(accepted_wheel_path=link),
        )

    def test_03_wheel_member_traversal_fails(self) -> None:
        self.fx.build_wheel(extra_members={"../escape.py": b"x"})
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_MEMBER_UNSAFE",
            lambda: self.fx.attest(),
        )

    def test_04_missing_installed_member_fails(self) -> None:
        (self.fx.package_root / "payload.py").unlink()
        self.assertCode(
            "ARTIFACT_ATTESTATION_INSTALLED_MEMBER_MISSING",
            lambda: self.fx.attest(),
        )

    def test_05_changed_installed_member_fails(self) -> None:
        (self.fx.package_root / "payload.py").write_text("VALUE = 8\n", encoding="utf-8")
        self.assertCode(
            "ARTIFACT_ATTESTATION_INSTALLED_MEMBER_MISMATCH",
            lambda: self.fx.attest(),
        )

    def test_06_unexpected_importable_member_fails(self) -> None:
        (self.fx.package_root / "surprise.py").write_text("X=1\n", encoding="utf-8")
        self.assertCode(
            "ARTIFACT_ATTESTATION_UNEXPECTED_PACKAGE_MEMBER",
            lambda: self.fx.attest(),
        )

    def test_07_record_hash_contradiction_fails(self) -> None:
        record = self.fx.dist_info / "RECORD"
        lines = record.read_text().splitlines()
        first = lines[0].split(",")
        first[1] = "sha256=" + base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
        lines[0] = ",".join(first)
        record.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertCode(
            "ARTIFACT_ATTESTATION_RECORD_HASH_MISMATCH",
            lambda: self.fx.attest(),
        )

    def test_08_malformed_record_fails(self) -> None:
        record = self.fx.dist_info / "RECORD"
        lines = record.read_text().splitlines()
        parts = lines[0].split(",")
        parts[1] = "md5=garbage"
        lines[0] = ",".join(parts)
        record.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertCode("ARTIFACT_ATTESTATION_RECORD_INVALID", lambda: self.fx.attest())

    def test_09_direct_url_absent_with_exact_actual_bytes_passes(self) -> None:
        result = self.fx.attest()
        self.assertEqual("ABSENT_ACTUAL_BYTE_PARITY_PRIMARY", result.direct_url_provenance_status)
        self.assertIsNone(result.direct_url)

    def test_10_direct_url_different_artifact_fails(self) -> None:
        other = self.root / "other.whl"
        other.write_bytes(self.fx.wheel.read_bytes())
        self.fx.set_direct_url({"url": other.resolve().as_uri(), "archive_info": {}})
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_CONTRADICTION",
            lambda: self.fx.attest(),
        )

    def test_11_direct_url_hash_contradiction_fails(self) -> None:
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {"hash": "sha256=" + "0" * 64},
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_MISMATCH",
            lambda: self.fx.attest(),
        )

    def test_12_editable_source_tree_install_fails(self) -> None:
        source = self.root / "editable-source"
        source.mkdir()
        self.fx.set_direct_url({"url": source.resolve().as_uri(), "dir_info": {"editable": True}})
        self.assertCode(
            "ARTIFACT_ATTESTATION_EDITABLE_INSTALL_FORBIDDEN",
            lambda: self.fx.attest(),
        )

    def test_13_different_interpreter_wrapper_fails(self) -> None:
        fake = self.root / "fake" / "bin" / "python"
        fake.parent.mkdir(parents=True)
        fake.write_text(f'#!/bin/sh\nexec "{self.fx.python}" "$@"\n', encoding="utf-8")
        fake.chmod(0o755)
        self.assertCode(
            "ARTIFACT_ATTESTATION_INTERPRETER_MISMATCH",
            lambda: self.fx.attest(interpreter_path=fake),
        )

    def test_14_purelib_outside_venv_fails(self) -> None:
        outside = self.root / "outside-site-packages"
        shutil.move(str(self.fx.purelib), str(outside))
        self.fx.purelib.symlink_to(outside, target_is_directory=True)
        self.assertCode(
            "ARTIFACT_ATTESTATION_PURELIB_OUTSIDE_VENV",
            lambda: self.fx.attest(),
        )

    def test_15_pythonpath_startup_shadow_is_forbidden(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_PYTHONPATH_FORBIDDEN",
            lambda: self.fx.attest(startup_environment={"PYTHONPATH": str(self.root)}),
        )

    def test_16_pythonhome_startup_override_is_forbidden(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_PYTHONHOME_FORBIDDEN",
            lambda: self.fx.attest(startup_environment={"PYTHONHOME": str(self.root)}),
        )

    def test_17_import_resolving_outside_distribution_fails(self) -> None:
        shadow = self.root / "shadow"
        package = shadow / "adcp_global_writer_client"
        package.mkdir(parents=True)
        package.joinpath("__init__.py").write_text(
            f'''class _Identity:\n    build_id = {BUILD!r}\n    source_commit = {SOURCE!r}\n    supported_dcs_schema_versions = {SCHEMAS!r}\n    thin_contract_format_version = 2\n    schema_contract_identity = {SCHEMA_ID!r}\n\ndef client_build_identity():\n    return _Identity()\n''',
            encoding="utf-8",
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_IMPORT_LOCATION_MISMATCH",
            lambda: self.fx.attest(startup_working_directory=shadow),
        )

    def test_18_correct_build_claim_cannot_override_wrong_wheel_bytes(self) -> None:
        expected = self.fx.wheel_sha
        with self.fx.wheel.open("ab") as handle:
            handle.write(b"modified")
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
            lambda: self.fx.attest(
                expected_wheel_sha256=expected,
                binding_facts={"runtime_build": BUILD},
            ),
        )

    def test_19_correct_source_claim_cannot_override_wrong_wheel_bytes(self) -> None:
        expected = self.fx.wheel_sha
        with self.fx.wheel.open("ab") as handle:
            handle.write(b"modified-source-case")
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
            lambda: self.fx.attest(
                expected_wheel_sha256=expected,
                binding_facts={"runtime_source": SOURCE},
            ),
        )

    def test_20_exact_wheel_bytes_with_wrong_expected_build_fails(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_BUILD_MISMATCH",
            lambda: self.fx.attest(expected_build_id="adcp-global-writer-client@0.4.0+gdeadbeefdead"),
        )

    def test_21_exact_wheel_bytes_with_wrong_expected_source_fails(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_SOURCE_MISMATCH",
            lambda: self.fx.attest(expected_source_commit="f" * 40),
        )

    def test_22_schema9_requires_installed_schema9_support(self) -> None:
        self.fx.build_wheel(schemas=(6, 7, 8))
        self.fx.install()
        self.assertCode(
            "ARTIFACT_ATTESTATION_SCHEMA_UNSUPPORTED",
            lambda: self.fx.attest(),
        )

    def test_23_runtime_self_claimed_sha_is_not_artifact_proof(self) -> None:
        expected = self.fx.wheel_sha
        with self.fx.wheel.open("ab") as handle:
            handle.write(b"bad")
        self.assertCode(
            "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
            lambda: self.fx.attest(
                expected_wheel_sha256=expected,
                binding_facts={"package_artifact_sha256": expected},
            ),
        )

    def test_24_same_venv_reinstalled_or_changed_bytes_fail_fresh_reattestation(self) -> None:
        first = self.fx.attest()
        self.assertEqual(self.fx.wheel_sha, first.accepted_wheel_sha256)
        (self.fx.package_root / "payload.py").write_text("VALUE = 99\n", encoding="utf-8")
        self.assertCode(
            "ARTIFACT_ATTESTATION_INSTALLED_MEMBER_MISMATCH",
            lambda: self.fx.attest(),
        )

    def test_25_full_exact_wheel_install_interpreter_and_identity_pass(self) -> None:
        result = self.fx.attest()
        self.assertEqual(self.fx.wheel_sha, result.accepted_wheel_sha256)
        self.assertEqual(VERSION, result.installed_version)
        self.assertEqual(BUILD, result.installed_build_id)
        self.assertEqual(SOURCE, result.installed_source_commit)
        self.assertEqual(SCHEMAS, result.installed_supported_dcs_schemas)
        self.assertEqual(7, result.installed_member_count)
        self.assertEqual(2, result.installed_thin_contract_format_version)
        self.assertEqual(SCHEMA_ID, result.installed_schema_contract_identity)
        self.assertRegex(result.installed_member_manifest_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(result.deterministic_attestation_sha256, r"^[0-9a-f]{64}$")

    def test_26_manifest_and_attestation_identity_are_deterministic(self) -> None:
        first = self.fx.attest()
        second = self.fx.attest()
        self.assertEqual(first.installed_member_manifest_sha256, second.installed_member_manifest_sha256)
        self.assertEqual(first.binding_facts_sha256, second.binding_facts_sha256)
        self.assertEqual(first.deterministic_attestation_sha256, second.deterministic_attestation_sha256)
        self.assertNotEqual(first.attestation_generated_at, second.attestation_generated_at)

    def test_27_matching_direct_url_is_supporting_not_root_authority(self) -> None:
        self.fx.set_direct_url({"url": self.fx.wheel.resolve().as_uri(), "archive_info": {}})
        result = self.fx.attest()
        self.assertEqual("PRESENT_MATCHING_SUPPORTING_PROVENANCE", result.direct_url_provenance_status)

    def test_28_binding_facts_are_frozen_into_deterministic_identity(self) -> None:
        first = self.fx.attest(binding_facts={"writer": "W02", "fence": 17})
        second = self.fx.attest(binding_facts={"fence": 18, "writer": "W02"})
        self.assertNotEqual(first.binding_facts_sha256, second.binding_facts_sha256)
        self.assertNotEqual(first.deterministic_attestation_sha256, second.deterministic_attestation_sha256)


    def test_29_duplicate_metadata_name_same_value_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Name: adcp-global-writer-client\n",
                b"Name: adcp-global-writer-client\nName: adcp-global-writer-client\n",
            ),
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_30_duplicate_metadata_name_different_value_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Name: adcp-global-writer-client\n",
                b"Name: adcp-global-writer-client\nName: other-client\n",
            ),
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_31_duplicate_metadata_version_same_value_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Version: 0.4.0\n", b"Version: 0.4.0\nVersion: 0.4.0\n"
            ),
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_32_duplicate_metadata_version_different_value_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Version: 0.4.0\n", b"Version: 0.4.0\nVersion: 9.9.9\n"
            ),
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_33_metadata_singleton_duplicate_is_case_insensitive(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Name: adcp-global-writer-client\n",
                b"Name: adcp-global-writer-client\nname: adcp-global-writer-client\n",
            ),
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_34_missing_metadata_name_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx, lambda data: data.replace(b"Name: adcp-global-writer-client\n", b"")
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_35_missing_metadata_version_fails(self) -> None:
        _rewrite_fixture_metadata(
            self.fx, lambda data: data.replace(b"Version: 0.4.0\n", b"")
        )
        self.assertCode("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", self.fx.attest)

    def test_36_repeatable_metadata_headers_remain_allowed(self) -> None:
        _rewrite_fixture_metadata(
            self.fx,
            lambda data: data.replace(
                b"Summary: fixture\n",
                b"Summary: fixture\nRequires-Dist: alpha>=1\nRequires-Dist: beta>=2\n",
            ),
        )
        result = self.fx.attest()
        self.assertEqual(VERSION, result.installed_version)

    def test_37_omitting_expected_version_is_python_signature_failure(self) -> None:
        kwargs = _explicit_target_kwargs(self.fx)
        kwargs.pop("expected_version")
        with self.assertRaises(TypeError):
            attest_runtime_artifact(**kwargs)

    def test_38_explicit_none_expected_version_fails_closed(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_EXPECTED_VERSION_INVALID",
            lambda: self.fx.attest(expected_version=None),
        )

    def test_39_omitting_expected_build_id_is_python_signature_failure(self) -> None:
        kwargs = _explicit_target_kwargs(self.fx)
        kwargs.pop("expected_build_id")
        with self.assertRaises(TypeError):
            attest_runtime_artifact(**kwargs)

    def test_40_explicit_none_expected_build_id_fails_closed(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_EXPECTED_BUILD_INVALID",
            lambda: self.fx.attest(expected_build_id=None),
        )

    def test_41_omitting_expected_source_commit_is_python_signature_failure(self) -> None:
        kwargs = _explicit_target_kwargs(self.fx)
        kwargs.pop("expected_source_commit")
        with self.assertRaises(TypeError):
            attest_runtime_artifact(**kwargs)

    def test_42_explicit_none_expected_source_commit_fails_closed(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_EXPECTED_SOURCE_INVALID",
            lambda: self.fx.attest(expected_source_commit=None),
        )

    def test_43_omitting_required_dcs_schema_is_python_signature_failure(self) -> None:
        kwargs = _explicit_target_kwargs(self.fx)
        kwargs.pop("required_dcs_schema")
        with self.assertRaises(TypeError):
            attest_runtime_artifact(**kwargs)

    def test_44_explicit_none_required_dcs_schema_fails_closed(self) -> None:
        self.assertCode(
            "ARTIFACT_ATTESTATION_REQUIRED_SCHEMA_INVALID",
            lambda: self.fx.attest(required_dcs_schema=None),
        )

    def test_45_all_target_constraints_omitted_never_issue_attestation(self) -> None:
        source = "a" * 40
        self.fx.build_wheel(
            version="9.9.9",
            build="adcp-global-writer-client@9.9.9+g" + source[:12],
            source=source,
            schemas=(9,),
        )
        self.fx.install()
        with self.assertRaises(TypeError):
            attest_runtime_artifact(
                accepted_wheel_path=self.fx.wheel,
                expected_wheel_sha256=self.fx.wheel_sha,
                interpreter_path=self.fx.python,
            )

    def test_46_wrong_declared_sha512_fails(self) -> None:
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {"hashes": {"sha512": "0" * 128}},
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_MISMATCH", self.fx.attest
        )

    def test_47_correct_declared_sha512_passes(self) -> None:
        sha512 = hashlib.sha512(self.fx.wheel.read_bytes()).hexdigest()
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {"hashes": {"sha512": sha512}},
            }
        )
        result = self.fx.attest()
        self.assertEqual("PRESENT_MATCHING_SUPPORTING_PROVENANCE", result.direct_url_provenance_status)

    def test_48_multiple_declared_hashes_all_correct_pass(self) -> None:
        data = self.fx.wheel.read_bytes()
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {
                    "hashes": {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "sha512": hashlib.sha512(data).hexdigest(),
                    }
                },
            }
        )
        self.assertEqual(
            "PRESENT_MATCHING_SUPPORTING_PROVENANCE",
            self.fx.attest().direct_url_provenance_status,
        )

    def test_49_one_of_multiple_declared_hashes_wrong_fails(self) -> None:
        data = self.fx.wheel.read_bytes()
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {
                    "hashes": {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "sha512": "0" * 128,
                    }
                },
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_MISMATCH", self.fx.attest
        )

    def test_50_unsupported_declared_hash_algorithm_fails_closed(self) -> None:
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {"hashes": {"not-a-real-hash": "00"}},
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_UNVERIFIABLE", self.fx.attest
        )

    def test_51_malformed_declared_hash_digest_fails_closed(self) -> None:
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {"hashes": {"sha512": "not-hex"}},
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_INVALID", self.fx.attest
        )

    def test_52_conflicting_hash_and_hashes_declarations_fail(self) -> None:
        data = self.fx.wheel.read_bytes()
        correct = hashlib.sha256(data).hexdigest()
        self.fx.set_direct_url(
            {
                "url": self.fx.wheel.resolve().as_uri(),
                "archive_info": {
                    "hash": "sha256=" + correct,
                    "hashes": {"sha256": "0" * 64},
                },
            }
        )
        self.assertCode(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_MISMATCH", self.fx.attest
        )


if __name__ == "__main__":
    unittest.main()
