"""Pre-import trust boundary for the strict read-only Production doctor.

This file is executed by absolute path under Python isolated mode.  Until the
Controller source identity is attested it imports standard-library modules only;
project-local ``adcp.*`` code is loaded only after the repository root, HEAD,
clean state, and exact implementation origin have been fixed.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType
from typing import Any


DOCTOR_VERSION = 1
_EXPECTED_ENTRYPOINT_RELATIVE = Path("src/adcp/production_control_surface_entrypoint.py")
_EXPECTED_IMPLEMENTATION_RELATIVE = Path("src/adcp/production_control_surface.py")
_FIXED_GIT = Path("/usr/bin/git")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_DETAIL = 512
_TRUSTED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class _BootstrapFailure(RuntimeError):
    def __init__(
        self,
        error_code: str,
        detail: str,
        *,
        controller_root: Path | None = None,
        controller_commit: str | None = None,
        controller_tree: str | None = None,
        controller_source_clean: bool | None = None,
    ) -> None:
        super().__init__(detail)
        self.error_code = error_code
        self.controller_root = controller_root
        self.controller_commit = controller_commit
        self.controller_tree = controller_tree
        self.controller_source_clean = controller_source_clean


def _safe_detail(value: object) -> str:
    text = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return (text or "bootstrap source identity failure")[:_MAX_DETAIL]


def _request_context(raw_request: str) -> tuple[str | None, str | None, str | None, str | None]:
    try:
        value = json.loads(raw_request)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, None, None, None
    if not isinstance(value, dict):
        return None, None, None, None
    expected = value.get("expected_controller_commit")
    change_id = value.get("change_id")
    unit_id = value.get("unit_or_subchange_id")
    operation_id = value.get("operation_id")
    return (
        expected if isinstance(expected, str) and _HEX40_RE.fullmatch(expected) else None,
        change_id if isinstance(change_id, str) else None,
        unit_id if isinstance(unit_id, str) else None,
        operation_id if isinstance(operation_id, str) else None,
    )


def _bootstrap_failure_result(
    failure: _BootstrapFailure,
    request_context: tuple[str | None, str | None, str | None, str | None],
) -> dict[str, Any]:
    _, change_id, unit_id, operation_id = request_context
    root = str(failure.controller_root) if failure.controller_root is not None else None
    return {
        "doctor_version": DOCTOR_VERSION,
        "status": "ERROR",
        "error_code": failure.error_code,
        "controller_root": root,
        "controller_interpreter": str(Path(sys.executable).absolute()),
        "controller_python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "controller_commit": failure.controller_commit,
        "controller_tree": failure.controller_tree,
        "controller_source_clean": failure.controller_source_clean,
        "dcs_path": "/Users/kate/DKATE/adcp-runtime/control.sqlite3",
        "dcs_readable": False,
        "dcs_schema": None,
        "dcs_schema_supported": False,
        "global_writer_state": None,
        "global_writer_owner_if_any": None,
        "current_fencing_token": None,
        "global_writer_lease": None,
        "request_change_id": change_id,
        "request_unit_or_subchange_id": unit_id,
        "request_operation_id": operation_id,
        "exact_operation_prior_acquisition_count": 0,
        "prior_operation_state": "UNKNOWN",
        "w08_control_path_available": False,
        "mutation_exercised": "NO",
        "w08_acquire_count": 0,
        "diagnostic_detail": _safe_detail(failure),
    }


def _run_git(controller_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    if not _FIXED_GIT.is_file():
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            f"fixed git executable missing: {_FIXED_GIT}",
            controller_root=controller_root,
        )
    return subprocess.run(
        [str(_FIXED_GIT), "-C", str(controller_root), *args],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": _TRUSTED_PATH,
            "LC_ALL": "C",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )


def _attest_source(expected_commit: str | None) -> tuple[Path, Path, str, str]:
    raw_entrypoint = Path(os.path.abspath(__file__))
    try:
        resolved_entrypoint = raw_entrypoint.resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure("CONTROLLER_ENTRYPOINT_IDENTITY_MISMATCH", _safe_detail(error)) from error
    if raw_entrypoint != resolved_entrypoint:
        raise _BootstrapFailure(
            "CONTROLLER_ENTRYPOINT_IDENTITY_MISMATCH",
            "entrypoint path contains a symlink or resolves outside its configured identity",
        )

    source_root = resolved_entrypoint.parents[1]
    controller_root = source_root.parent
    expected_entrypoint = controller_root / _EXPECTED_ENTRYPOINT_RELATIVE
    if resolved_entrypoint != expected_entrypoint:
        raise _BootstrapFailure(
            "CONTROLLER_ENTRYPOINT_IDENTITY_MISMATCH",
            f"unexpected entrypoint layout: {resolved_entrypoint}",
            controller_root=controller_root,
        )

    implementation = controller_root / _EXPECTED_IMPLEMENTATION_RELATIVE
    try:
        resolved_implementation = implementation.resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            _safe_detail(error),
            controller_root=controller_root,
        ) from error
    if implementation != resolved_implementation or not implementation.is_file():
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "implementation path is not the exact regular source file",
            controller_root=controller_root,
        )

    top = _run_git(controller_root, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise _BootstrapFailure(
            "CONTROLLER_ROOT_MISMATCH",
            top.stderr or "git top-level inspection failed",
            controller_root=controller_root,
        )
    try:
        git_root = Path(top.stdout.strip()).resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure(
            "CONTROLLER_ROOT_MISMATCH", _safe_detail(error), controller_root=controller_root
        ) from error
    if git_root != controller_root:
        raise _BootstrapFailure(
            "CONTROLLER_ROOT_MISMATCH",
            "bootstrap-derived root does not match git top-level",
            controller_root=controller_root,
        )

    head = _run_git(controller_root, "rev-parse", "HEAD")
    tree = _run_git(controller_root, "rev-parse", "HEAD^{tree}")
    tracked = _run_git(
        controller_root,
        "ls-files",
        "--error-unmatch",
        "--",
        str(_EXPECTED_ENTRYPOINT_RELATIVE),
        str(_EXPECTED_IMPLEMENTATION_RELATIVE),
    )
    status = _run_git(controller_root, "status", "--porcelain=v1", "--untracked-files=all")
    if any(result.returncode != 0 for result in (head, tree, tracked, status)):
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "git source identity inspection failed",
            controller_root=controller_root,
        )
    actual_head = head.stdout.strip()
    actual_tree = tree.stdout.strip()
    clean = not bool(status.stdout.strip())
    if expected_commit is not None and actual_head != expected_commit:
        raise _BootstrapFailure(
            "CONTROLLER_HEAD_MISMATCH",
            "bootstrap HEAD does not match expected_controller_commit",
            controller_root=controller_root,
            controller_commit=actual_head,
            controller_tree=actual_tree,
            controller_source_clean=clean,
        )
    if not clean:
        raise _BootstrapFailure(
            "CONTROLLER_DIRTY",
            "bootstrap source worktree is not clean",
            controller_root=controller_root,
            controller_commit=actual_head,
            controller_tree=actual_tree,
            controller_source_clean=False,
        )
    return controller_root, source_root, actual_head, actual_tree


def _load_intended_module(source_root: Path) -> ModuleType:
    expected = source_root / "adcp" / "production_control_surface.py"
    resolved_expected = expected.resolve(strict=True)
    if any(name == "adcp" or name.startswith("adcp.") for name in sys.modules):
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "project-local adcp module existed before the attestation boundary",
            controller_root=source_root.parent,
        )

    # Isolated startup already excludes caller cwd/user-site import authority.
    # Replace any residual current-directory spellings and put only the attested
    # source root first before project-local imports are allowed.
    cwd = Path.cwd().resolve(strict=False)
    retained: list[str] = []
    for item in sys.path:
        if not item:
            continue
        try:
            candidate = Path(item).resolve(strict=False)
        except OSError:
            continue
        if candidate == cwd or candidate == source_root.parent:
            continue
        retained.append(item)
    sys.path[:] = [str(source_root), *retained]
    sys.dont_write_bytecode = True

    spec = importlib.util.spec_from_file_location("adcp.production_control_surface", resolved_expected)
    if spec is None or spec.loader is None or spec.origin is None:
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "could not create exact implementation module spec",
            controller_root=source_root.parent,
        )
    try:
        spec_origin = Path(spec.origin).resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH", _safe_detail(error), controller_root=source_root.parent
        ) from error
    if spec_origin != resolved_expected:
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "implementation spec origin mismatch",
            controller_root=source_root.parent,
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    module_file = getattr(module, "__file__", None)
    if not isinstance(module_file, str) or Path(module_file).resolve(strict=True) != resolved_expected:
        raise _BootstrapFailure(
            "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
            "loaded implementation realpath mismatch",
            controller_root=source_root.parent,
        )
    return module


def main() -> int:
    raw_request = sys.stdin.read()
    context = _request_context(raw_request)
    expected_commit = context[0]
    try:
        _, source_root, _, _ = _attest_source(expected_commit)
        module = _load_intended_module(source_root)
        module_main = getattr(module, "main", None)
        if not callable(module_main):
            raise _BootstrapFailure(
                "CONTROLLER_SOURCE_ORIGIN_MISMATCH",
                "intended implementation has no callable main",
                controller_root=source_root.parent,
            )
        return int(module_main(io.StringIO(raw_request), sys.stdout))
    except _BootstrapFailure as failure:
        sys.stdout.write(
            json.dumps(
                _bootstrap_failure_result(failure, context),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
