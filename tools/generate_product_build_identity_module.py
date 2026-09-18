from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

_PRODUCT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
DEFAULT_PRODUCT_IDENTITY_MODULE = "propertyai_core._global_writer_build_identity"


def run(*args: str, cwd: Path) -> str:
    return subprocess.run(list(args), cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def generate(
    source_root: Path,
    product_name: str,
    output: Path,
    module_name: str = DEFAULT_PRODUCT_IDENTITY_MODULE,
) -> None:
    source_root = source_root.expanduser().resolve(strict=True)
    git_root = Path(run("git", "rev-parse", "--show-toplevel", cwd=source_root)).resolve(strict=True)
    if git_root != source_root:
        raise SystemExit("source root must be the exact Git toplevel")
    if not _PRODUCT_NAME.fullmatch(product_name):
        raise SystemExit("invalid product name")
    if not _MODULE_NAME.fullmatch(module_name):
        raise SystemExit("invalid Product identity module name")
    if run("git", "status", "--porcelain=v1", cwd=source_root):
        raise SystemExit("refusing to generate Product build identity from dirty source")
    commit = run("git", "rev-parse", "HEAD", cwd=source_root)
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise SystemExit("Git HEAD is not a canonical 40-hex commit")
    artifact = f"source-commit:{commit}"
    identity = f"product:{product_name}@g{commit[:12]}|source={commit}|artifact={artifact}"
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    data = "\n".join(
        [
            '"""Generated Product runtime provenance. Do not edit at runtime."""',
            "",
            f"PRODUCT_IDENTITY_MODULE = {module_name!r}",
            f"PRODUCT_NAME = {product_name!r}",
            f"PRODUCT_BUILD_COMMIT = {commit!r}",
            f"SOURCE_ARTIFACT_IDENTITY = {artifact!r}",
            f"PRODUCT_BUILD_IDENTITY = {identity!r}",
            "",
        ]
    ).encode("utf-8")
    temp = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temp.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, output)
        directory_fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate immutable startup Product build provenance")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--product-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module-name", default=DEFAULT_PRODUCT_IDENTITY_MODULE)
    args = parser.parse_args()
    generate(args.source_root, args.product_name, args.output, args.module_name)


if __name__ == "__main__":
    main()
