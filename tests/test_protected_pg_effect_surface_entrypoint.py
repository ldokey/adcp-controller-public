from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from adcp import protected_pg_effect_surface_entrypoint as bootstrap


_FIXTURE_IMPLEMENTATION = r'''
from dataclasses import dataclass
import json

@dataclass(frozen=True)
class ControllerSourceIdentity:
    commit: str
    tree: str
    source_clean: bool
    entrypoint: str = "protected_pg_effect_surface_entrypoint.py"

def main(input_stream, output_stream, *, source_identity):
    raw = input_stream.read().strip()
    result = {
        "schema_version": 1,
        "read_status": "UNKNOWN" if raw else "READ",
        "reason_code": "PUBLIC_INPUT_REJECTED" if raw else "OK",
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
            "commit": source_identity.commit,
            "tree": source_identity.tree,
            "source_clean": source_identity.source_clean,
            "entrypoint": source_identity.entrypoint,
        },
        "transaction_read_only": None,
        "privilege_contract": None,
        "sensitive_payload_output": "NO",
        "mutation_exercised": "NO",
    }
    output_stream.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0
'''


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _make_clean_fixture_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "controller"
    adcp = repo / "src" / "adcp"
    adcp.mkdir(parents=True)
    entrypoint = adcp / "protected_pg_effect_surface_entrypoint.py"
    entrypoint.write_text(Path(bootstrap.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    (adcp / "protected_pg_effect_surface.py").write_text(_FIXTURE_IMPLEMENTATION, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "p0a-test@example.invalid")
    _git(repo, "config", "user.name", "P0A Test")
    _git(repo, "add", "src/adcp/protected_pg_effect_surface_entrypoint.py", "src/adcp/protected_pg_effect_surface.py")
    _git(repo, "commit", "-qm", "fixture")
    return repo, entrypoint


def _run(entrypoint: Path, *, input_text: str = "") -> dict:
    completed = subprocess.run(
        [sys.executable, "-I", str(entrypoint)],
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
        cwd=str(entrypoint.parents[2]),
    )
    assert completed.stderr == ""
    return json.loads(completed.stdout)


def test_bootstrap_reason_codes_are_a_closed_subset_of_controller_protocol():
    from adcp import protected_pg_effect_surface as surface

    assert bootstrap._BOOTSTRAP_REASON_CODES <= set(
        surface.PROTECTED_PG_EFFECT_SURFACE_REASON_CODES
    )
    assert bootstrap._unknown_result("FUTURE_BOOTSTRAP_REASON")["reason_code"] == "BOOTSTRAP_INTERNAL_FAILURE"


def test_clean_exact_source_bootstrap_reports_commit_tree_and_clean(tmp_path):
    repo, entrypoint = _make_clean_fixture_repo(tmp_path)
    result = _run(entrypoint)
    assert result["read_status"] == "READ"
    assert result["reason_code"] == "OK"
    assert result["controller_source_identity"] == {
        "commit": _git(repo, "rev-parse", "HEAD"),
        "tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "source_clean": True,
        "entrypoint": "protected_pg_effect_surface_entrypoint.py",
    }


def test_dirty_source_is_unknown_without_path_or_diagnostic_leak(tmp_path):
    repo, entrypoint = _make_clean_fixture_repo(tmp_path)
    implementation = repo / "src" / "adcp" / "protected_pg_effect_surface.py"
    implementation.write_text(_FIXTURE_IMPLEMENTATION + "\n# dirty\n", encoding="utf-8")
    result = _run(entrypoint)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "CONTROLLER_DIRTY"
    assert result["controller_source_identity"]["source_clean"] is False
    encoded = json.dumps(result)
    assert str(repo) not in encoded
    assert "diagnostic" not in encoded.lower()


def test_entrypoint_symlink_is_fail_closed(tmp_path):
    _repo, entrypoint = _make_clean_fixture_repo(tmp_path)
    link = tmp_path / "entrypoint-link.py"
    link.symlink_to(entrypoint)
    result = _run(link)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "ENTRYPOINT_IDENTITY_MISMATCH"


def test_wrong_layout_origin_is_fail_closed(tmp_path):
    _repo, entrypoint = _make_clean_fixture_repo(tmp_path)
    wrong = tmp_path / "wrong.py"
    wrong.write_text(entrypoint.read_text(encoding="utf-8"), encoding="utf-8")
    result = _run(wrong)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "ENTRYPOINT_IDENTITY_MISMATCH"


def test_head_shape_mismatch_is_fail_closed(monkeypatch):
    root = Path(bootstrap.__file__).resolve().parents[2]

    def completed(args, stdout="", code=0):
        return subprocess.CompletedProcess(args, code, stdout, "")

    def fake_git(_root, *args):
        if args == ("rev-parse", "--show-toplevel"):
            return completed(args, str(root) + "\n")
        if args == ("rev-parse", "HEAD"):
            return completed(args, "not-a-commit\n")
        if args == ("rev-parse", "HEAD^{tree}"):
            return completed(args, "b" * 40 + "\n")
        if args and args[0] == "ls-files":
            return completed(args, "tracked\n")
        if args and args[0] == "status":
            return completed(args, "")
        raise AssertionError(args)

    monkeypatch.setattr(bootstrap, "_run_git", fake_git)
    with pytest.raises(bootstrap._BootstrapFailure) as exc:
        bootstrap._attest_source()
    assert exc.value.reason_code == "CONTROLLER_HEAD_MISMATCH"


def test_preloaded_project_shadow_is_rejected(monkeypatch):
    monkeypatch.setitem(sys.modules, "adcp.shadow_fixture", object())
    source_root = Path(bootstrap.__file__).resolve().parents[1]
    with pytest.raises(bootstrap._BootstrapFailure) as exc:
        bootstrap._load_intended_module(source_root)
    assert exc.value.reason_code == "SOURCE_SHADOW_MISMATCH"


def test_nonempty_public_input_is_rejected_after_source_attestation(tmp_path):
    _repo, entrypoint = _make_clean_fixture_repo(tmp_path)
    result = _run(entrypoint, input_text='{"sql":"select *"}')
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "PUBLIC_INPUT_REJECTED"
    assert result["claimed_running_count"] is None
