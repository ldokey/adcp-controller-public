"""Fresh external attestation for an installed Global Writer thin-client artifact.

The trust root is the control-authorized wheel *bytes*, not package version/build
strings or runtime self-report.  The verifier is read-only: it probes an exact
interpreter and compares the installed distribution to the accepted wheel.
"""
from __future__ import annotations

import ast
import base64
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Mapping
from urllib.parse import unquote, urlparse
import zipfile


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_DISTRIBUTION_NAME = "adcp-global-writer-client"
_IMPORT_NAME = "adcp_global_writer_client"
_BUILD_IDENTITY_MEMBER = f"{_IMPORT_NAME}/_build_identity.py"
_PROBE_TIMEOUT_SECONDS = 20


class RuntimeArtifactAttestationError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class RuntimeArtifactAttestation:
    accepted_wheel_realpath: str
    accepted_wheel_sha256: str
    interpreter_path: str
    interpreter_realpath: str
    sys_executable: str
    sys_executable_realpath: str
    sys_prefix: str
    sys_prefix_realpath: str
    base_prefix: str
    purelib_path: str
    purelib_realpath: str
    installed_distribution_root: str
    installed_dist_info_path: str
    installed_package_root: str
    installed_module_file: str
    installed_member_manifest_sha256: str
    installed_member_count: int
    installed_version: str
    installed_build_id: str
    installed_source_commit: str
    installed_supported_dcs_schemas: tuple[int, ...]
    installed_thin_contract_format_version: int
    installed_schema_contract_identity: str
    direct_url_provenance_status: str
    direct_url: str | None
    binding_facts_json: str
    binding_facts_sha256: str
    deterministic_attestation_sha256: str
    attestation_generated_at: str


@dataclass(frozen=True)
class _WheelFacts:
    distribution_name: str
    version: str
    build_id: str
    source_commit: str
    supported_dcs_schemas: tuple[int, ...]
    thin_contract_format_version: int
    schema_contract_identity: str
    dist_info_dir: str
    record_member: str
    installed_members: tuple[str, ...]
    member_bytes: Mapping[str, bytes]


@dataclass(frozen=True)
class _ProbeFacts:
    sys_executable: str
    sys_prefix: str
    base_prefix: str
    purelib: str
    distribution_root: str
    dist_info_path: str
    module_file: str
    distribution_version: str
    build_id: str
    source_commit: str
    supported_dcs_schemas: tuple[int, ...]
    thin_contract_format_version: int
    schema_contract_identity: str
    sys_path: tuple[str, ...]
    user_site_enabled: bool | None


def _fail(code: str, detail: str = "") -> None:
    raise RuntimeArtifactAttestationError(code, detail)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise RuntimeArtifactAttestationError(
            "ARTIFACT_ATTESTATION_BINDING_FACTS_INVALID", type(error).__name__
        ) from error


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_zip_member(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        _fail("ARTIFACT_ATTESTATION_WHEEL_MEMBER_UNSAFE", name)
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        _fail("ARTIFACT_ATTESTATION_WHEEL_MEMBER_UNSAFE", name)
    return path


def _safe_record_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        _fail("ARTIFACT_ATTESTATION_RECORD_INVALID", name)
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        _fail("ARTIFACT_ATTESTATION_RECORD_INVALID", name)
    return path


def _regular_zip_member(info: zipfile.ZipInfo) -> None:
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode and not stat.S_ISREG(mode):
        _fail("ARTIFACT_ATTESTATION_WHEEL_MEMBER_NONREGULAR", info.filename)


def _single_metadata_header(metadata: Any, name: str) -> str:
    values = metadata.get_all(name, failobj=[])
    if not isinstance(values, list) or len(values) != 1:
        _fail("ARTIFACT_ATTESTATION_WHEEL_METADATA_AMBIGUOUS", name)
    value = values[0]
    if not isinstance(value, str) or not value.strip():
        _fail("ARTIFACT_ATTESTATION_WHEEL_METADATA_INVALID", name)
    return value.strip()


def _literal_assignments(source: bytes, member: str) -> dict[str, Any]:
    try:
        tree = ast.parse(source.decode("utf-8"), filename=member)
    except (UnicodeError, SyntaxError) as error:
        raise RuntimeArtifactAttestationError(
            "ARTIFACT_ATTESTATION_BUILD_IDENTITY_INVALID", member
        ) from error
    values: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            values[target.id] = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
    return values


def _inspect_wheel(wheel_bytes: bytes) -> _WheelFacts:
    try:
        archive = zipfile.ZipFile(io.BytesIO(wheel_bytes))
    except (zipfile.BadZipFile, OSError) as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_WHEEL_INVALID") from error
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            _fail("ARTIFACT_ATTESTATION_WHEEL_DUPLICATE_MEMBER")
        regular: dict[str, bytes] = {}
        for info in infos:
            _safe_zip_member(info.filename.rstrip("/") if info.is_dir() else info.filename)
            if info.is_dir():
                continue
            _regular_zip_member(info)
            regular[info.filename] = archive.read(info)

    metadata_members = [name for name in regular if name.endswith(".dist-info/METADATA")]
    record_members = [name for name in regular if name.endswith(".dist-info/RECORD")]
    if len(metadata_members) != 1 or len(record_members) != 1:
        _fail("ARTIFACT_ATTESTATION_WHEEL_DIST_INFO_INVALID")
    metadata_member = metadata_members[0]
    record_member = record_members[0]
    dist_info_dir = metadata_member.rsplit("/", 1)[0]
    if record_member != f"{dist_info_dir}/RECORD":
        _fail("ARTIFACT_ATTESTATION_WHEEL_DIST_INFO_INVALID")
    if any(".data/" in name for name in regular):
        _fail("ARTIFACT_ATTESTATION_WHEEL_DATA_LAYOUT_UNSUPPORTED")
    if _BUILD_IDENTITY_MEMBER not in regular:
        _fail("ARTIFACT_ATTESTATION_BUILD_IDENTITY_MISSING")
    schema_member = f"{_IMPORT_NAME}/_schema_contract.py"
    if schema_member not in regular:
        _fail("ARTIFACT_ATTESTATION_SCHEMA_CONTRACT_MISSING")

    try:
        metadata = BytesParser().parsebytes(regular[metadata_member])
    except Exception as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_WHEEL_METADATA_INVALID") from error
    distribution_name = _single_metadata_header(metadata, "Name")
    version = _single_metadata_header(metadata, "Version")
    if distribution_name != _DISTRIBUTION_NAME:
        _fail("ARTIFACT_ATTESTATION_WHEEL_METADATA_MISMATCH")

    identity = _literal_assignments(regular[_BUILD_IDENTITY_MEMBER], _BUILD_IDENTITY_MEMBER)
    build_id = identity.get("BUILD_ID")
    source_commit = identity.get("SOURCE_COMMIT")
    client_version = identity.get("CLIENT_VERSION")
    package_name = identity.get("CLIENT_PACKAGE_NAME")
    supported = identity.get("EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS")
    thin_format = identity.get("EXPECTED_THIN_CONTRACT_FORMAT_VERSION")
    schema_identity = identity.get("EXPECTED_SCHEMA_CONTRACT_IDENTITY")
    schema_values = _literal_assignments(regular[schema_member], schema_member)
    if (
        package_name != _DISTRIBUTION_NAME
        or client_version != version
        or not isinstance(build_id, str)
        or not isinstance(source_commit, str)
        or _SHA40.fullmatch(source_commit) is None
        or not isinstance(supported, tuple)
        or not supported
        or any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in supported)
        or tuple(sorted(set(supported))) != supported
        or not isinstance(thin_format, int)
        or isinstance(thin_format, bool)
        or thin_format <= 0
        or not isinstance(schema_identity, str)
        or not schema_identity.startswith("sha256:")
        or _SHA256.fullmatch(schema_identity[7:]) is None
    ):
        _fail("ARTIFACT_ATTESTATION_BUILD_IDENTITY_INVALID")
    if (
        schema_values.get("THIN_CONTRACT_FORMAT_VERSION") != thin_format
        or schema_values.get("SUPPORTED_DCS_SCHEMA_VERSIONS") != supported
        or schema_values.get("SCHEMA_CONTRACT_IDENTITY") != schema_identity
    ):
        _fail("ARTIFACT_ATTESTATION_SCHEMA_CONTRACT_IDENTITY_MISMATCH")

    installed_members = tuple(sorted(name for name in regular if name != record_member))
    return _WheelFacts(
        distribution_name=distribution_name,
        version=version,
        build_id=build_id,
        source_commit=source_commit,
        supported_dcs_schemas=supported,
        thin_contract_format_version=thin_format,
        schema_contract_identity=schema_identity,
        dist_info_dir=dist_info_dir,
        record_member=record_member,
        installed_members=installed_members,
        member_bytes=regular,
    )


_PROBE_SCRIPT = r'''
import importlib.metadata as md
import json
from pathlib import Path
import site
import sys
import sysconfig
import adcp_global_writer_client as package
from adcp_global_writer_client import client_build_identity

dist = md.distribution("adcp-global-writer-client")
metadata_members = [f for f in (dist.files or ()) if str(f).endswith(".dist-info/METADATA")]
if len(metadata_members) != 1:
    raise SystemExit("DIST_INFO_METADATA_NOT_EXACT")
identity = client_build_identity()
print(json.dumps({
    "sys_executable": sys.executable,
    "sys_prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "purelib": sysconfig.get_paths()["purelib"],
    "distribution_root": str(dist.locate_file("")),
    "dist_info_path": str(Path(dist.locate_file(metadata_members[0])).parent),
    "module_file": package.__file__,
    "distribution_version": dist.version,
    "build_id": identity.build_id,
    "source_commit": identity.source_commit,
    "supported_dcs_schemas": list(identity.supported_dcs_schema_versions),
    "thin_contract_format_version": identity.thin_contract_format_version,
    "schema_contract_identity": identity.schema_contract_identity,
    "sys_path": list(sys.path),
    "user_site_enabled": site.ENABLE_USER_SITE,
}, sort_keys=True, separators=(",", ":")))
'''


def _probe_interpreter(
    interpreter_path: Path,
    *,
    startup_environment: Mapping[str, str] | None,
    startup_working_directory: str | Path | None,
) -> _ProbeFacts:
    supplied = interpreter_path.expanduser()
    if not supplied.exists() or supplied.is_dir():
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_MISSING", str(supplied))
    try:
        supplied_real = supplied.resolve(strict=True)
    except OSError as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_INTERPRETER_MISSING") from error
    if not os.access(supplied, os.X_OK):
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_NOT_EXECUTABLE", str(supplied))

    startup = dict(startup_environment or {})
    if "PYTHONPATH" in startup:
        _fail("ARTIFACT_ATTESTATION_PYTHONPATH_FORBIDDEN")
    if "PYTHONHOME" in startup:
        _fail("ARTIFACT_ATTESTATION_PYTHONHOME_FORBIDDEN")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in startup.items()):
        _fail("ARTIFACT_ATTESTATION_STARTUP_ENV_INVALID")

    if startup_working_directory is None:
        cwd = supplied.parent.parent.resolve(strict=True)
    else:
        try:
            cwd = Path(startup_working_directory).expanduser().resolve(strict=True)
        except OSError as error:
            raise RuntimeArtifactAttestationError(
                "ARTIFACT_ATTESTATION_WORKING_DIRECTORY_INVALID"
            ) from error
        if not cwd.is_dir():
            _fail("ARTIFACT_ATTESTATION_WORKING_DIRECTORY_INVALID", str(cwd))

    env: dict[str, str] = {}
    for key in ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "PATH"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.update(startup)
    completed = subprocess.run(
        [str(supplied), "-B", "-c", _PROBE_SCRIPT],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=_PROBE_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        _fail(
            "ARTIFACT_ATTESTATION_INTERPRETER_PROBE_FAILED",
            (completed.stderr or completed.stdout).strip()[:400],
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_PROBE_INVALID")
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_INTERPRETER_PROBE_INVALID") from error
    if not isinstance(payload, dict):
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_PROBE_INVALID")
    required_text = (
        "sys_executable",
        "sys_prefix",
        "base_prefix",
        "purelib",
        "distribution_root",
        "dist_info_path",
        "module_file",
        "distribution_version",
        "build_id",
        "source_commit",
        "schema_contract_identity",
    )
    if any(not isinstance(payload.get(key), str) or not payload[key] for key in required_text):
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_PROBE_INVALID")
    schemas = payload.get("supported_dcs_schemas")
    thin_format = payload.get("thin_contract_format_version")
    sys_path = payload.get("sys_path")
    if (
        not isinstance(schemas, list)
        or any(not isinstance(item, int) or isinstance(item, bool) for item in schemas)
        or not isinstance(thin_format, int)
        or isinstance(thin_format, bool)
        or thin_format <= 0
        or not isinstance(sys_path, list)
        or any(not isinstance(item, str) for item in sys_path)
        or payload.get("user_site_enabled") not in {True, False, None}
    ):
        _fail("ARTIFACT_ATTESTATION_INTERPRETER_PROBE_INVALID")

    reported_executable = Path(payload["sys_executable"]).expanduser().resolve(strict=True)
    if reported_executable != supplied_real:
        _fail(
            "ARTIFACT_ATTESTATION_INTERPRETER_MISMATCH",
            f"reported={reported_executable} supplied={supplied_real}",
        )
    prefix = Path(payload["sys_prefix"]).expanduser().resolve(strict=True)
    expected_prefix = supplied.parent.parent.resolve(strict=True)
    if prefix != expected_prefix:
        _fail("ARTIFACT_ATTESTATION_VENV_MISMATCH", f"{prefix} != {expected_prefix}")
    purelib = Path(payload["purelib"]).expanduser().resolve(strict=True)
    if not _is_relative_to(purelib, prefix):
        _fail("ARTIFACT_ATTESTATION_PURELIB_OUTSIDE_VENV", str(purelib))
    distribution_root = Path(payload["distribution_root"]).expanduser().resolve(strict=True)
    if distribution_root != purelib:
        _fail("ARTIFACT_ATTESTATION_DISTRIBUTION_ROOT_MISMATCH", str(distribution_root))
    dist_info = Path(payload["dist_info_path"]).expanduser().resolve(strict=True)
    module_file = Path(payload["module_file"]).expanduser().resolve(strict=True)
    package_root = distribution_root / _IMPORT_NAME
    if not _is_relative_to(dist_info, distribution_root) or not _is_relative_to(module_file, package_root):
        _fail("ARTIFACT_ATTESTATION_IMPORT_LOCATION_MISMATCH", str(module_file))

    return _ProbeFacts(
        sys_executable=payload["sys_executable"],
        sys_prefix=payload["sys_prefix"],
        base_prefix=payload["base_prefix"],
        purelib=payload["purelib"],
        distribution_root=payload["distribution_root"],
        dist_info_path=payload["dist_info_path"],
        module_file=payload["module_file"],
        distribution_version=payload["distribution_version"],
        build_id=payload["build_id"],
        source_commit=payload["source_commit"],
        supported_dcs_schemas=tuple(schemas),
        thin_contract_format_version=thin_format,
        schema_contract_identity=payload["schema_contract_identity"],
        sys_path=tuple(sys_path),
        user_site_enabled=payload["user_site_enabled"],
    )


def _assert_path_no_symlink_below(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _fail("ARTIFACT_ATTESTATION_INSTALLED_SYMLINK_FORBIDDEN", str(current))
    try:
        resolved = current.resolve(strict=True)
    except OSError as error:
        raise RuntimeArtifactAttestationError(
            "ARTIFACT_ATTESTATION_INSTALLED_MEMBER_MISSING", str(current)
        ) from error
    if not _is_relative_to(resolved, root):
        _fail("ARTIFACT_ATTESTATION_INSTALLED_PATH_ESCAPE", str(resolved))
    if not resolved.is_file():
        _fail("ARTIFACT_ATTESTATION_INSTALLED_MEMBER_NONREGULAR", str(resolved))
    return resolved


def _validate_installed_members(
    *, wheel: _WheelFacts, distribution_root: Path, package_root: Path
) -> tuple[str, int]:
    rows: list[dict[str, Any]] = []
    expected_package_members: set[str] = set()
    for member in wheel.installed_members:
        relative = _safe_zip_member(member)
        installed = _assert_path_no_symlink_below(distribution_root, relative)
        actual = installed.read_bytes()
        expected = wheel.member_bytes[member]
        if actual != expected:
            _fail("ARTIFACT_ATTESTATION_INSTALLED_MEMBER_MISMATCH", member)
        digest = _sha256_bytes(actual)
        rows.append({"path": member, "bytes": len(actual), "sha256": digest})
        if member.startswith(f"{_IMPORT_NAME}/"):
            expected_package_members.add(member)

    if not package_root.is_dir() or package_root.is_symlink():
        _fail("ARTIFACT_ATTESTATION_PACKAGE_ROOT_INVALID", str(package_root))
    for path in sorted(package_root.rglob("*"), key=lambda item: str(item)):
        if path.is_symlink():
            _fail("ARTIFACT_ATTESTATION_UNEXPECTED_PACKAGE_MEMBER", str(path))
        if not path.is_file():
            continue
        relative = path.relative_to(distribution_root).as_posix()
        if relative in expected_package_members:
            continue
        rel_parts = PurePosixPath(relative).parts
        if "__pycache__" in rel_parts and path.suffix == ".pyc":
            continue
        _fail("ARTIFACT_ATTESTATION_UNEXPECTED_PACKAGE_MEMBER", relative)

    manifest = _canonical_json({"format": "ADCP_RUNTIME_ARTIFACT_INSTALLED_MEMBERS_V1", "entries": rows})
    return _sha256_bytes(manifest.encode("utf-8")), len(rows)


def _decode_record_digest(value: str) -> tuple[str, bytes]:
    if "=" not in value:
        _fail("ARTIFACT_ATTESTATION_RECORD_INVALID", value)
    algorithm, encoded = value.split("=", 1)
    if algorithm != "sha256" or not encoded:
        _fail("ARTIFACT_ATTESTATION_RECORD_INVALID", value)
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_RECORD_INVALID") from error
    if len(decoded) != hashlib.sha256().digest_size:
        _fail("ARTIFACT_ATTESTATION_RECORD_INVALID", value)
    return algorithm, decoded


def _validate_record(
    *, distribution_root: Path, dist_info: Path, wheel: _WheelFacts
) -> None:
    record = dist_info / "RECORD"
    if record.is_symlink() or not record.is_file():
        _fail("ARTIFACT_ATTESTATION_RECORD_MISSING")
    try:
        text = record.read_text(encoding="utf-8")
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except (OSError, UnicodeError, csv.Error) as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_RECORD_INVALID") from error
    seen: set[str] = set()
    record_map: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            _fail("ARTIFACT_ATTESTATION_RECORD_INVALID")
        name, digest_text, size_text = row
        relative = _safe_record_path(name)
        normalized = relative.as_posix()
        if normalized in seen:
            _fail("ARTIFACT_ATTESTATION_RECORD_DUPLICATE", normalized)
        seen.add(normalized)
        record_map[normalized] = (digest_text, size_text)
        target = distribution_root.joinpath(*relative.parts)
        try:
            resolved = target.resolve(strict=True)
        except OSError:
            _fail("ARTIFACT_ATTESTATION_RECORD_TARGET_MISSING", normalized)
        if not _is_relative_to(resolved, distribution_root) or not resolved.is_file():
            _fail("ARTIFACT_ATTESTATION_RECORD_TARGET_INVALID", normalized)
        actual = resolved.read_bytes()
        if digest_text:
            _, expected_digest = _decode_record_digest(digest_text)
            if hashlib.sha256(actual).digest() != expected_digest:
                _fail("ARTIFACT_ATTESTATION_RECORD_HASH_MISMATCH", normalized)
        if size_text:
            try:
                expected_size = int(size_text)
            except ValueError as error:
                raise RuntimeArtifactAttestationError(
                    "ARTIFACT_ATTESTATION_RECORD_INVALID", normalized
                ) from error
            if expected_size < 0 or expected_size != len(actual):
                _fail("ARTIFACT_ATTESTATION_RECORD_SIZE_MISMATCH", normalized)
        elif normalized != wheel.record_member:
            _fail("ARTIFACT_ATTESTATION_RECORD_SIZE_MISSING", normalized)

    for member in wheel.installed_members:
        digest_text, size_text = record_map.get(member, ("", ""))
        if not digest_text or not size_text:
            _fail("ARTIFACT_ATTESTATION_RECORD_WHEEL_MEMBER_MISSING", member)
    if wheel.record_member not in record_map:
        _fail("ARTIFACT_ATTESTATION_RECORD_SELF_MISSING")


def _verify_declared_archive_hash(*, algorithm: str, digest: str, wheel_bytes: bytes) -> None:
    if not isinstance(algorithm, str) or not algorithm.strip() or not isinstance(digest, str):
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_HASH_INVALID")
    algorithm = algorithm.strip()
    digest = digest.strip()
    try:
        hasher = hashlib.new(algorithm)
    except (ValueError, TypeError) as error:
        raise RuntimeArtifactAttestationError(
            "ARTIFACT_ATTESTATION_DIRECT_URL_HASH_UNVERIFIABLE", algorithm
        ) from error
    expected_length = hasher.digest_size * 2
    if len(digest) != expected_length or re.fullmatch(r"[0-9A-Fa-f]+", digest) is None:
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_HASH_INVALID", algorithm)
    hasher.update(wheel_bytes)
    if hasher.hexdigest().lower() != digest.lower():
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_HASH_MISMATCH", algorithm)


def _parse_direct_url(
    *,
    dist_info: Path,
    accepted_wheel_realpath: Path,
    accepted_wheel_sha256: str,
    accepted_wheel_bytes: bytes,
) -> tuple[str, str | None]:
    path = dist_info / "direct_url.json"
    if not path.exists():
        return "ABSENT_ACTUAL_BYTE_PARITY_PRIMARY", None
    if path.is_symlink() or not path.is_file():
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_INVALID")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_DIRECT_URL_INVALID") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str) or not payload["url"]:
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_INVALID")
    url = payload["url"]
    dir_info = payload.get("dir_info")
    if dir_info is not None:
        if not isinstance(dir_info, dict):
            _fail("ARTIFACT_ATTESTATION_DIRECT_URL_INVALID")
        if dir_info.get("editable") is True:
            _fail("ARTIFACT_ATTESTATION_EDITABLE_INSTALL_FORBIDDEN")
    parsed = urlparse(url)
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_CONTRADICTION", url)
    local_path = Path(unquote(parsed.path)).expanduser()
    try:
        local_real = local_path.resolve(strict=True)
    except OSError as error:
        raise RuntimeArtifactAttestationError(
            "ARTIFACT_ATTESTATION_DIRECT_URL_CONTRADICTION", url
        ) from error
    if local_real != accepted_wheel_realpath:
        _fail("ARTIFACT_ATTESTATION_DIRECT_URL_CONTRADICTION", str(local_real))

    archive_info = payload.get("archive_info")
    if archive_info is not None:
        if not isinstance(archive_info, dict):
            _fail("ARTIFACT_ATTESTATION_DIRECT_URL_INVALID")
        hash_value = archive_info.get("hash")
        hashes = archive_info.get("hashes")
        if hash_value is not None:
            if not isinstance(hash_value, str) or hash_value.count("=") != 1:
                _fail("ARTIFACT_ATTESTATION_DIRECT_URL_HASH_INVALID")
            algorithm, digest = hash_value.split("=", 1)
            _verify_declared_archive_hash(
                algorithm=algorithm, digest=digest, wheel_bytes=accepted_wheel_bytes
            )
        if hashes is not None:
            if not isinstance(hashes, dict) or any(
                not isinstance(algorithm, str) or not isinstance(digest, str)
                for algorithm, digest in hashes.items()
            ):
                _fail("ARTIFACT_ATTESTATION_DIRECT_URL_HASH_INVALID")
            for algorithm, digest in sorted(hashes.items(), key=lambda item: item[0]):
                _verify_declared_archive_hash(
                    algorithm=algorithm, digest=digest, wheel_bytes=accepted_wheel_bytes
                )
    return "PRESENT_MATCHING_SUPPORTING_PROVENANCE", url


def _fresh_installed_parity(
    *, wheel: _WheelFacts, distribution_root: Path
) -> None:
    for member in wheel.installed_members:
        relative = _safe_zip_member(member)
        installed = _assert_path_no_symlink_below(distribution_root, relative)
        if installed.read_bytes() != wheel.member_bytes[member]:
            _fail("ARTIFACT_ATTESTATION_INSTALLED_MEMBER_DRIFT", member)


def attest_runtime_artifact(
    *,
    accepted_wheel_path: str | Path,
    expected_wheel_sha256: str,
    interpreter_path: str | Path,
    expected_version: str,
    expected_build_id: str,
    expected_source_commit: str,
    required_dcs_schema: int,
    startup_environment: Mapping[str, str] | None = None,
    startup_working_directory: str | Path | None = None,
    binding_facts: Mapping[str, Any] | None = None,
) -> RuntimeArtifactAttestation:
    """Freshly bind accepted wheel bytes to one exact installed interpreter environment."""

    if not isinstance(expected_wheel_sha256, str) or _SHA256.fullmatch(expected_wheel_sha256) is None:
        _fail("ARTIFACT_ATTESTATION_EXPECTED_SHA_INVALID")
    if not isinstance(expected_version, str) or not expected_version.strip():
        _fail("ARTIFACT_ATTESTATION_EXPECTED_VERSION_INVALID")
    if not isinstance(expected_build_id, str) or not expected_build_id.strip():
        _fail("ARTIFACT_ATTESTATION_EXPECTED_BUILD_INVALID")
    if not isinstance(expected_source_commit, str) or _SHA40.fullmatch(expected_source_commit) is None:
        _fail("ARTIFACT_ATTESTATION_EXPECTED_SOURCE_INVALID")
    if (
        not isinstance(required_dcs_schema, int)
        or isinstance(required_dcs_schema, bool)
        or required_dcs_schema <= 0
    ):
        _fail("ARTIFACT_ATTESTATION_REQUIRED_SCHEMA_INVALID")
    wheel_path = Path(accepted_wheel_path).expanduser()
    if wheel_path.is_symlink():
        _fail("ARTIFACT_ATTESTATION_WHEEL_SYMLINK_FORBIDDEN", str(wheel_path))
    try:
        wheel_realpath = wheel_path.resolve(strict=True)
    except OSError as error:
        raise RuntimeArtifactAttestationError("ARTIFACT_ATTESTATION_WHEEL_MISSING") from error
    if not wheel_realpath.is_file() or not stat.S_ISREG(wheel_realpath.stat().st_mode):
        _fail("ARTIFACT_ATTESTATION_WHEEL_NONREGULAR", str(wheel_realpath))
    wheel_bytes = wheel_realpath.read_bytes()
    actual_wheel_sha256 = _sha256_bytes(wheel_bytes)
    if actual_wheel_sha256 != expected_wheel_sha256:
        _fail(
            "ARTIFACT_ATTESTATION_WHEEL_SHA_MISMATCH",
            f"actual={actual_wheel_sha256} expected={expected_wheel_sha256}",
        )
    wheel = _inspect_wheel(wheel_bytes)

    probe = _probe_interpreter(
        Path(interpreter_path),
        startup_environment=startup_environment,
        startup_working_directory=startup_working_directory,
    )
    distribution_root = Path(probe.distribution_root).expanduser().resolve(strict=True)
    dist_info = Path(probe.dist_info_path).expanduser().resolve(strict=True)
    package_root = distribution_root / _IMPORT_NAME
    expected_dist_info = distribution_root / wheel.dist_info_dir
    if dist_info != expected_dist_info.resolve(strict=True):
        _fail(
            "ARTIFACT_ATTESTATION_DIST_INFO_MISMATCH",
            f"observed={dist_info} expected={expected_dist_info}",
        )
    module_file = Path(probe.module_file).expanduser().resolve(strict=True)
    if not _is_relative_to(module_file, package_root.resolve(strict=True)):
        _fail("ARTIFACT_ATTESTATION_IMPORT_LOCATION_MISMATCH", str(module_file))

    member_manifest_sha256, member_count = _validate_installed_members(
        wheel=wheel, distribution_root=distribution_root, package_root=package_root
    )
    _validate_record(distribution_root=distribution_root, dist_info=dist_info, wheel=wheel)
    direct_url_status, direct_url = _parse_direct_url(
        dist_info=dist_info,
        accepted_wheel_realpath=wheel_realpath,
        accepted_wheel_sha256=actual_wheel_sha256,
        accepted_wheel_bytes=wheel_bytes,
    )

    if probe.distribution_version != wheel.version:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_VERSION_WHEEL_MISMATCH")
    if probe.build_id != wheel.build_id:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_BUILD_WHEEL_MISMATCH")
    if probe.source_commit != wheel.source_commit:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_SOURCE_WHEEL_MISMATCH")
    if probe.supported_dcs_schemas != wheel.supported_dcs_schemas:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_SCHEMA_WHEEL_MISMATCH")
    if probe.thin_contract_format_version != wheel.thin_contract_format_version:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_CONTRACT_FORMAT_WHEEL_MISMATCH")
    if probe.schema_contract_identity != wheel.schema_contract_identity:
        _fail("ARTIFACT_ATTESTATION_INSTALLED_SCHEMA_IDENTITY_WHEEL_MISMATCH")
    if probe.distribution_version != expected_version:
        _fail("ARTIFACT_ATTESTATION_VERSION_MISMATCH")
    if probe.build_id != expected_build_id:
        _fail("ARTIFACT_ATTESTATION_BUILD_MISMATCH")
    if probe.source_commit != expected_source_commit:
        _fail("ARTIFACT_ATTESTATION_SOURCE_MISMATCH")
    if required_dcs_schema not in probe.supported_dcs_schemas:
        _fail("ARTIFACT_ATTESTATION_SCHEMA_UNSUPPORTED", str(required_dcs_schema))

    facts_json = _canonical_json(dict(binding_facts or {}))
    facts_sha256 = _sha256_bytes(facts_json.encode("utf-8"))

    # Close simple TOCTOU windows: the path must still be the same regular non-symlink
    # accepted wheel and all installed wheel-owned bytes must still match before return.
    if wheel_path.is_symlink() or wheel_path.resolve(strict=True) != wheel_realpath:
        _fail("ARTIFACT_ATTESTATION_WHEEL_PATH_DRIFT")
    if _sha256_bytes(wheel_realpath.read_bytes()) != actual_wheel_sha256:
        _fail("ARTIFACT_ATTESTATION_WHEEL_BYTE_DRIFT")
    _fresh_installed_parity(wheel=wheel, distribution_root=distribution_root)

    interpreter_supplied = Path(interpreter_path).expanduser()
    interpreter_real = interpreter_supplied.resolve(strict=True)
    sys_executable_real = Path(probe.sys_executable).expanduser().resolve(strict=True)
    sys_prefix_real = Path(probe.sys_prefix).expanduser().resolve(strict=True)
    purelib_real = Path(probe.purelib).expanduser().resolve(strict=True)
    deterministic_payload = {
        "format": "ADCP_RUNTIME_ARTIFACT_ATTESTATION_V1",
        "accepted_wheel_realpath": str(wheel_realpath),
        "accepted_wheel_sha256": actual_wheel_sha256,
        "interpreter_realpath": str(interpreter_real),
        "sys_executable_realpath": str(sys_executable_real),
        "sys_prefix_realpath": str(sys_prefix_real),
        "purelib_realpath": str(purelib_real),
        "distribution_root": str(distribution_root),
        "dist_info_path": str(dist_info),
        "package_root": str(package_root.resolve(strict=True)),
        "installed_member_manifest_sha256": member_manifest_sha256,
        "installed_version": probe.distribution_version,
        "installed_build_id": probe.build_id,
        "installed_source_commit": probe.source_commit,
        "installed_supported_dcs_schemas": list(probe.supported_dcs_schemas),
        "installed_thin_contract_format_version": probe.thin_contract_format_version,
        "installed_schema_contract_identity": probe.schema_contract_identity,
        "direct_url_status": direct_url_status,
        "direct_url": direct_url,
        "binding_facts_sha256": facts_sha256,
    }
    deterministic_sha256 = _sha256_bytes(_canonical_json(deterministic_payload).encode("utf-8"))
    generated = datetime.now(timezone.utc).isoformat(timespec="microseconds")

    return RuntimeArtifactAttestation(
        accepted_wheel_realpath=str(wheel_realpath),
        accepted_wheel_sha256=actual_wheel_sha256,
        interpreter_path=str(interpreter_supplied),
        interpreter_realpath=str(interpreter_real),
        sys_executable=probe.sys_executable,
        sys_executable_realpath=str(sys_executable_real),
        sys_prefix=probe.sys_prefix,
        sys_prefix_realpath=str(sys_prefix_real),
        base_prefix=probe.base_prefix,
        purelib_path=probe.purelib,
        purelib_realpath=str(purelib_real),
        installed_distribution_root=str(distribution_root),
        installed_dist_info_path=str(dist_info),
        installed_package_root=str(package_root.resolve(strict=True)),
        installed_module_file=str(module_file),
        installed_member_manifest_sha256=member_manifest_sha256,
        installed_member_count=member_count,
        installed_version=probe.distribution_version,
        installed_build_id=probe.build_id,
        installed_source_commit=probe.source_commit,
        installed_supported_dcs_schemas=probe.supported_dcs_schemas,
        installed_thin_contract_format_version=probe.thin_contract_format_version,
        installed_schema_contract_identity=probe.schema_contract_identity,
        direct_url_provenance_status=direct_url_status,
        direct_url=direct_url,
        binding_facts_json=facts_json,
        binding_facts_sha256=facts_sha256,
        deterministic_attestation_sha256=deterministic_sha256,
        attestation_generated_at=generated,
    )


__all__ = [
    "RuntimeArtifactAttestation",
    "RuntimeArtifactAttestationError",
    "attest_runtime_artifact",
]
