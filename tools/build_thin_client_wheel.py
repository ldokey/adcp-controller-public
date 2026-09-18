from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Any

PACKAGE_RELATIVE = Path("packages/adcp-global-writer-client")
IDENTITY_RELATIVE = PACKAGE_RELATIVE / "src/adcp_global_writer_client/_build_identity.py"
SCHEMA_CONTRACT_RELATIVE = PACKAGE_RELATIVE / "src/adcp_global_writer_client/_schema_contract.py"
SCHEMA_CONTRACT_GENERATOR = Path("tools/generate_thin_schema_contract.py")
EXPECTED_PACKAGE_NAME = "adcp-global-writer-client"
EXPECTED_PACKAGE_VERSION = "0.5.0"
EXPECTED_THIN_CONTRACT_FORMAT_VERSION = 2
EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = [6, 7, 8, 9, 10]


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(list(args), cwd=cwd, env=env, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True).stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_metadata(source_root: Path) -> tuple[str, str]:
    package_project = source_root / PACKAGE_RELATIVE / "pyproject.toml"
    project = tomllib.loads(package_project.read_text(encoding="utf-8"))["project"]
    package_name = project["name"]
    version = project["version"]
    if package_name != EXPECTED_PACKAGE_NAME:
        raise SystemExit("unexpected thin-client package name")
    if version != EXPECTED_PACKAGE_VERSION:
        raise SystemExit("unexpected v6/v7/v8/v9/v10-compatible thin-client version")
    if project.get("dependencies") != []:
        raise SystemExit("thin client must have zero runtime dependencies")
    return package_name, version


def _validate_schema_contract_metadata(schema_contract: dict[str, Any]) -> tuple[int, list[int], str]:
    format_version = schema_contract["thin_contract_format_version"]
    supported_versions = schema_contract["supported_dcs_schema_versions"]
    contract_identity = schema_contract["schema_contract_identity"]
    if (
        format_version != EXPECTED_THIN_CONTRACT_FORMAT_VERSION
        or supported_versions != EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS
    ):
        raise SystemExit("generated thin schema contract metadata is not exact v6+v7+v8+v9+v10 format v2")
    if not isinstance(contract_identity, str) or not contract_identity.startswith("sha256:"):
        raise SystemExit("generated thin schema contract identity is malformed")
    return format_version, supported_versions, contract_identity


def _identity_text(
    *,
    package_name: str,
    version: str,
    source_commit: str,
    build_id: str,
    artifact_identity: str,
    format_version: int,
    supported_versions: list[int],
    contract_identity: str,
) -> str:
    return "\n".join(
        [
            '"""Generated thin-client build identity bound to an exact schema contract."""',
            "",
            f"CLIENT_PACKAGE_NAME = {package_name!r}",
            f"CLIENT_VERSION = {version!r}",
            f"SOURCE_COMMIT = {source_commit!r}",
            f"BUILD_ID = {build_id!r}",
            f"ARTIFACT_IDENTITY = {artifact_identity!r}",
            f"EXPECTED_THIN_CONTRACT_FORMAT_VERSION = {format_version!r}",
            f"EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS = {tuple(supported_versions)!r}",
            f"EXPECTED_SCHEMA_CONTRACT_IDENTITY = {contract_identity!r}",
            "",
        ]
    )


def _write_identity(
    path: Path,
    *,
    package_name: str,
    version: str,
    source_commit: str,
    build_id: str,
    artifact_identity: str,
    format_version: int,
    supported_versions: list[int],
    contract_identity: str,
) -> None:
    path.write_text(
        _identity_text(
            package_name=package_name,
            version=version,
            source_commit=source_commit,
            build_id=build_id,
            artifact_identity=artifact_identity,
            format_version=format_version,
            supported_versions=supported_versions,
            contract_identity=contract_identity,
        ),
        encoding="utf-8",
    )


def _generate_schema_contract(generator_root: Path, schema_source_root: Path, output: Path) -> dict[str, Any]:
    schema_source_root = schema_source_root.expanduser().resolve(strict=True)
    return json.loads(
        run(
            os.fspath(Path(os.sys.executable).resolve()),
            os.fspath(generator_root / SCHEMA_CONTRACT_GENERATOR),
            "--source-root",
            os.fspath(schema_source_root),
            "--output",
            os.fspath(output),
            cwd=generator_root,
        )
    )


def write_source_tree_identity(schema_source_root: Path | None = None) -> dict[str, Any]:
    """Regenerate precommit source-tree contract/identity without claiming a Git commit."""

    source_root = Path(run("git", "rev-parse", "--show-toplevel")).resolve()
    package_name, version = _project_metadata(source_root)
    schema_source = source_root if schema_source_root is None else schema_source_root
    schema_contract = _generate_schema_contract(
        source_root,
        schema_source,
        source_root / SCHEMA_CONTRACT_RELATIVE,
    )
    format_version, supported_versions, contract_identity = _validate_schema_contract_metadata(schema_contract)
    build_id = f"{package_name}@{version}+source-tree"
    artifact_identity = "source-tree:unbuilt"
    _write_identity(
        source_root / IDENTITY_RELATIVE,
        package_name=package_name,
        version=version,
        source_commit="UNBUILT_SOURCE_TREE",
        build_id=build_id,
        artifact_identity=artifact_identity,
        format_version=format_version,
        supported_versions=supported_versions,
        contract_identity=contract_identity,
    )
    result: dict[str, Any] = {
        "package_name": package_name,
        "version": version,
        "build_id": build_id,
        "source_commit": "UNBUILT_SOURCE_TREE",
        "source_artifact_identity": artifact_identity,
        "thin_contract_format_version": format_version,
        "supported_dcs_schema_versions": supported_versions,
        "schema_profile_identities": schema_contract["schema_profile_identities"],
        "schema_contract_identity": contract_identity,
        "mode": "PRECOMMIT_SOURCE_TREE_IDENTITY",
    }
    print(json.dumps(result, sort_keys=True))
    return result


def build(output_dir: Path, schema_source_root: Path | None = None) -> dict[str, Any]:
    source_root = Path(run("git", "rev-parse", "--show-toplevel")).resolve()
    if run("git", "status", "--porcelain=v1", cwd=source_root):
        raise SystemExit("refusing to build commit-bound wheel from a dirty source worktree")
    commit = run("git", "rev-parse", "HEAD", cwd=source_root)
    commit_epoch = run("git", "show", "-s", "--format=%ct", "HEAD", cwd=source_root)
    package_name, version = _project_metadata(source_root)
    build_id = f"{package_name}@{version}+g{commit[:12]}"
    artifact_identity = f"source-commit:{commit}"
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="adcp-thin-client-build-") as temp_dir:
        archive_root = Path(temp_dir) / "source"
        archive_root.mkdir()
        archive = git_bytes(source_root, "archive", "--format=tar", "HEAD")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            tar.extractall(archive_root, filter="data")
        schema_source = archive_root if schema_source_root is None else schema_source_root
        schema_contract = _generate_schema_contract(
            archive_root,
            schema_source,
            archive_root / SCHEMA_CONTRACT_RELATIVE,
        )
        format_version, supported_versions, contract_identity = _validate_schema_contract_metadata(schema_contract)

        _write_identity(
            archive_root / IDENTITY_RELATIVE,
            package_name=package_name,
            version=version,
            source_commit=commit,
            build_id=build_id,
            artifact_identity=artifact_identity,
            format_version=format_version,
            supported_versions=supported_versions,
            contract_identity=contract_identity,
        )
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = commit_epoch
        env["PYTHONHASHSEED"] = "0"
        package_dir = archive_root / PACKAGE_RELATIVE
        subprocess.run(
            [
                "uv",
                "build",
                "--wheel",
                "--clear",
                "--no-create-gitignore",
                "--python",
                os.fspath(Path(os.sys.executable).resolve()),
                "--out-dir",
                os.fspath(output_dir),
                os.fspath(package_dir),
            ],
            check=True,
            env=env,
        )

    wheels = sorted(output_dir.glob("adcp_global_writer_client-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected one thin-client wheel, found {len(wheels)}")
    wheel = wheels[0]
    wheel_sha = sha256(wheel)
    wheel.with_suffix(wheel.suffix + ".sha256").write_text(f"{wheel_sha}  {wheel.name}\n", encoding="ascii")
    result: dict[str, Any] = {
        "package_name": package_name,
        "version": version,
        "build_id": build_id,
        "source_commit": commit,
        "source_artifact_identity": artifact_identity,
        "thin_contract_format_version": format_version,
        "supported_dcs_schema_versions": supported_versions,
        "schema_profile_identities": schema_contract["schema_profile_identities"],
        "schema_contract_identity": contract_identity,
        "wheel": os.fspath(wheel),
        "wheel_sha256": wheel_sha,
    }
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or precommit-generate the independent Global Writer thin client")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument(
        "--schema-source-root",
        type=Path,
        help="Exact accepted ADCP Core schema authority root; defaults to the thin-client repository root",
    )
    parser.add_argument(
        "--write-source-tree-identity",
        action="store_true",
        help="Regenerate source-tree schema/build identities for precommit testing; does not claim a commit",
    )
    args = parser.parse_args()
    if args.write_source_tree_identity:
        if args.out_dir is not None:
            parser.error("--out-dir cannot be combined with --write-source-tree-identity")
        write_source_tree_identity(args.schema_source_root)
        return
    if args.out_dir is None:
        parser.error("--out-dir is required for a commit-bound wheel build")
    build(args.out_dir, args.schema_source_root)


if __name__ == "__main__":
    main()
