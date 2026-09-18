"""Strict source-attesting bootstrap for the protected PG effect-surface reader.

The bootstrap executes under Python isolated mode.  It imports project-local code
only after proving the exact repository/root/HEAD/tree/clean/tracked origin for
this entrypoint and its implementation.  No caller input is part of the public
capability.
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


SCHEMA_VERSION = 1
_EXPECTED_ENTRYPOINT_RELATIVE = Path("src/adcp/protected_pg_effect_surface_entrypoint.py")
_EXPECTED_IMPLEMENTATION_RELATIVE = Path("src/adcp/protected_pg_effect_surface.py")
_FIXED_GIT = Path("/usr/bin/git")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_TRUSTED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_BOOTSTRAP_REASON_CODES = frozenset(
    {
        "SOURCE_ORIGIN_MISMATCH",
        "ENTRYPOINT_IDENTITY_MISMATCH",
        "CONTROLLER_ROOT_MISMATCH",
        "CONTROLLER_HEAD_MISMATCH",
        "CONTROLLER_DIRTY",
        "SOURCE_SHADOW_MISMATCH",
        "BOOTSTRAP_INTERNAL_FAILURE",
    }
)


class _BootstrapFailure(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        *,
        commit: str | None = None,
        tree: str | None = None,
        source_clean: bool | None = None,
    ) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.commit = commit
        self.tree = tree
        self.source_clean = source_clean


def _unknown_result(
    reason_code: str,
    *,
    commit: str | None = None,
    tree: str | None = None,
    source_clean: bool | None = None,
) -> dict[str, Any]:
    if reason_code not in _BOOTSTRAP_REASON_CODES:
        reason_code = "BOOTSTRAP_INTERNAL_FAILURE"
    return {
        "schema_version": SCHEMA_VERSION,
        "read_status": "UNKNOWN",
        "reason_code": reason_code,
        "observed_at": None,
        "claimed_running_count": None,
        "pending_outbox_effect_count": None,
        "reconciliation_required_count": None,
        "result_unknown_effect_count": None,
        "other_actionable_effect_count": None,
        "unexpected_status_count": None,
        "database_name": None,
        "session_user": None,
        "current_user": None,
        "controller_source_identity": {
            "commit": commit,
            "tree": tree,
            "source_clean": source_clean,
            "entrypoint": "protected_pg_effect_surface_entrypoint.py",
        },
        "transaction_read_only": None,
        "privilege_contract": None,
        "sensitive_payload_output": "NO",
        "mutation_exercised": "NO",
    }


def _run_git(controller_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    if not _FIXED_GIT.is_file():
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")
    return subprocess.run(
        [str(_FIXED_GIT), "-C", str(controller_root), *args],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        env={
            "PATH": _TRUSTED_PATH,
            "LC_ALL": "C",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )


def _attest_source() -> tuple[Path, str, str]:
    raw_entrypoint = Path(os.path.abspath(__file__))
    try:
        resolved_entrypoint = raw_entrypoint.resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure("ENTRYPOINT_IDENTITY_MISMATCH") from error
    if raw_entrypoint != resolved_entrypoint:
        raise _BootstrapFailure("ENTRYPOINT_IDENTITY_MISMATCH")

    source_root = resolved_entrypoint.parents[1]
    controller_root = source_root.parent
    if resolved_entrypoint != controller_root / _EXPECTED_ENTRYPOINT_RELATIVE:
        raise _BootstrapFailure("ENTRYPOINT_IDENTITY_MISMATCH")

    implementation = controller_root / _EXPECTED_IMPLEMENTATION_RELATIVE
    try:
        resolved_implementation = implementation.resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH") from error
    if implementation != resolved_implementation or not implementation.is_file():
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")

    top = _run_git(controller_root, "rev-parse", "--show-toplevel")
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
    if any(result.returncode != 0 for result in (top, head, tree, tracked, status)):
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")

    try:
        git_root = Path(top.stdout.strip()).resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure("CONTROLLER_ROOT_MISMATCH") from error
    if git_root != controller_root:
        raise _BootstrapFailure("CONTROLLER_ROOT_MISMATCH")

    actual_head = head.stdout.strip()
    actual_tree = tree.stdout.strip()
    clean = not bool(status.stdout.strip())
    if not _HEX40_RE.fullmatch(actual_head) or not _HEX40_RE.fullmatch(actual_tree):
        raise _BootstrapFailure(
            "CONTROLLER_HEAD_MISMATCH",
            commit=actual_head if _HEX40_RE.fullmatch(actual_head) else None,
            tree=actual_tree if _HEX40_RE.fullmatch(actual_tree) else None,
            source_clean=clean,
        )
    if not clean:
        raise _BootstrapFailure(
            "CONTROLLER_DIRTY",
            commit=actual_head,
            tree=actual_tree,
            source_clean=False,
        )
    return source_root, actual_head, actual_tree


def _load_intended_module(source_root: Path) -> ModuleType:
    expected = source_root / "adcp" / "protected_pg_effect_surface.py"
    resolved_expected = expected.resolve(strict=True)
    if any(name == "adcp" or name.startswith("adcp.") for name in sys.modules):
        raise _BootstrapFailure("SOURCE_SHADOW_MISMATCH")

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

    spec = importlib.util.spec_from_file_location("adcp.protected_pg_effect_surface", resolved_expected)
    if spec is None or spec.loader is None or spec.origin is None:
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")
    try:
        spec_origin = Path(spec.origin).resolve(strict=True)
    except OSError as error:
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH") from error
    if spec_origin != resolved_expected:
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    module_file = getattr(module, "__file__", None)
    if not isinstance(module_file, str) or Path(module_file).resolve(strict=True) != resolved_expected:
        raise _BootstrapFailure("SOURCE_ORIGIN_MISMATCH")
    return module


def main() -> int:
    raw_input = sys.stdin.read()
    try:
        source_root, commit, tree = _attest_source()
        module = _load_intended_module(source_root)
        identity_type = getattr(module, "ControllerSourceIdentity", None)
        module_main = getattr(module, "main", None)
        if identity_type is None or not callable(module_main):
            raise _BootstrapFailure(
                "SOURCE_ORIGIN_MISMATCH",
                commit=commit,
                tree=tree,
                source_clean=True,
            )
        identity = identity_type(commit=commit, tree=tree, source_clean=True)
        return int(module_main(io.StringIO(raw_input), sys.stdout, source_identity=identity))
    except _BootstrapFailure as failure:
        sys.stdout.write(
            json.dumps(
                _unknown_result(
                    failure.reason_code,
                    commit=failure.commit,
                    tree=failure.tree,
                    source_clean=failure.source_clean,
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0
    except BaseException:
        # No raw exception text crosses the privacy boundary.
        sys.stdout.write(
            json.dumps(
                _unknown_result("BOOTSTRAP_INTERNAL_FAILURE"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
