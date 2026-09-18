"""Minimal operator CLI; all semantic actions delegate to :mod:`adcp.controller`."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
from pathlib import Path
import sys
from typing import Callable, Sequence

from adcp.capsule import CapsuleRole, build_context_capsule
from adcp.controller import ApprovalBinding, Controller
from adcp.domain import Environment, ExecutionCreate, RiskLevel
from adcp.production_prep import prepare_canonical_production
from adcp.production_control import GitSourceAuthority, GlobalProductionControlLease
from adcp.store.migrations import SCHEMA_VERSION
from adcp.store.sqlite import CANONICAL_PRODUCTION_CONTROL_STORE, ControlStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adcp")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--worktree-root", type=Path, required=True)
    parser.add_argument("--controller-id", default="adcp-controller")
    parser.add_argument("--global-writer-change-id")
    parser.add_argument("--global-writer-unit-id")
    parser.add_argument("--global-writer-expected-adcp-head")
    parser.add_argument("--global-writer-control-decision-ref")
    subcommands = parser.add_subparsers(dest="command", required=True)

    create = subcommands.add_parser("create")
    create.add_argument("execution_id")
    create.add_argument("slice_id")
    create.add_argument("--risk", choices=[item.value for item in RiskLevel], required=True)
    create.add_argument("--environment", choices=[item.value for item in Environment], required=True)
    create.add_argument("--contract-fingerprint", required=True)
    create.add_argument("--authority-fingerprint", required=True)
    create.add_argument("--branch", required=True)
    create.add_argument("--base-commit", required=True)

    bind_deferred = subcommands.add_parser("bind-deferred")
    bind_deferred.add_argument("execution_id")
    bind_deferred.add_argument("slice_id")
    bind_deferred.add_argument("--expected-state-version", type=int, required=True)
    bind_deferred.add_argument(
        "--risk", choices=[item.value for item in RiskLevel], required=True
    )
    bind_deferred.add_argument(
        "--environment", choices=[item.value for item in Environment], required=True
    )
    bind_deferred.add_argument("--contract-fingerprint", required=True)
    bind_deferred.add_argument("--authority-fingerprint", required=True)
    bind_deferred.add_argument("--branch", required=True)
    bind_deferred.add_argument("--base-commit", required=True)
    bind_deferred.add_argument("--packet-ref", required=True)
    bind_deferred.add_argument("--maker-capsule", type=Path, required=True)
    bind_deferred.add_argument("--provision-branch-if-missing", action="store_true")

    release_prebound = subcommands.add_parser("release-prebound")
    release_prebound.add_argument("execution_id")
    release_prebound.add_argument("slice_id")
    release_prebound.add_argument(
        "--expected-execution-state-version", type=int, required=True
    )
    release_prebound.add_argument(
        "--expected-slice-state-version", type=int, required=True
    )
    release_prebound.add_argument(
        "--reason",
        choices=(
            "BASE_STALE",
            "CONTRACT_STALE",
            "AUTHORITY_STALE",
            "BRANCH_STALE",
            "ENVIRONMENT_STALE",
            "PREMAKER_PREREQUISITE_CHANGED",
        ),
        required=True,
    )
    release_prebound.add_argument("--authority-ref", required=True)

    register_slice = subcommands.add_parser("register-slice")
    register_slice.add_argument("slice_id")
    register_slice.add_argument("--stage", required=True)
    register_slice.add_argument("--status", required=True)
    register_slice.add_argument("--migration-class", required=True)
    register_slice.add_argument("--execution-eligibility", required=True)
    register_slice.add_argument("--defer-reason", required=True)
    register_slice.add_argument("--logical-source-root", required=True)
    register_slice.add_argument("--registration-ref", required=True)
    register_slice.add_argument("--expected-authority-generation", type=int, required=True)

    start = subcommands.add_parser("start")
    start.add_argument("execution_id")

    status = subcommands.add_parser("status")
    status.add_argument("execution_id")

    advance = subcommands.add_parser("advance")
    advance.add_argument("execution_id")
    advance.add_argument("--limit", type=int, default=1)

    approval = subcommands.add_parser("approve")
    approval.add_argument("execution_id")
    approval.add_argument("approval_id")
    approval.add_argument("authority_ref")

    cancel = subcommands.add_parser("cancel")
    cancel.add_argument("execution_id")
    return parser


def _production_prepare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adcp production-prepare")
    parser.add_argument(
        "--accepted-adcp-head",
        required=True,
        help="exact E2 revision accepted by the separate GPT/Human gate",
    )
    return parser


def _is_canonical_production_database(path: Path) -> bool:
    return path.expanduser().resolve(strict=False) == CANONICAL_PRODUCTION_CONTROL_STORE.resolve(strict=False)


def _build_controller(args: argparse.Namespace) -> Controller:
    production = _is_canonical_production_database(args.database)
    # Ordinary CLI access must never perform the 01C bootstrap migration implicitly.
    # On canonical Production, source readiness therefore requires an already-v6 store.
    store = ControlStore(
        args.database,
        backup_root=args.database.parent / "backups",
        migrate_schema=not production,
        require_schema_version=SCHEMA_VERSION if production else None,
        global_writer_guard_required=production,
    )
    return Controller(
        store,
        source_root=args.source_root,
        worktree_root=args.worktree_root,
        controller_id=args.controller_id,
    )


def _production_control_scope(args: argparse.Namespace, controller: Controller):
    if not _is_canonical_production_database(args.database) or args.command == "status":
        return nullcontext()
    required = {
        "global_writer_change_id": args.global_writer_change_id,
        "global_writer_unit_id": args.global_writer_unit_id,
        "global_writer_expected_adcp_head": args.global_writer_expected_adcp_head,
        "global_writer_control_decision_ref": args.global_writer_control_decision_ref,
    }
    missing = [name for name, value in required.items() if not isinstance(value, str) or not value.strip()]
    if missing:
        raise ValueError("PRODUCTION_GLOBAL_WRITER_METADATA_REQUIRED:" + ",".join(sorted(missing)))
    adcp_source_root = Path(__file__).resolve().parents[2]
    authority = GitSourceAuthority(
        adcp_source_root, args.global_writer_expected_adcp_head, require_clean=True
    )

    return GlobalProductionControlLease(
        controller.store,
        change_id=args.global_writer_change_id,
        unit_id=args.global_writer_unit_id,
        writer_class="W09_ORDINARY_PRODUCTION_CONTROL",
        owner_session_role="ADCP_OPERATOR_CLI",
        operation_class=f"ADCP_{args.command.upper().replace('-', '_')}",
        target="PRODUCTION_DCS",
        authority=authority,
        control_decision_ref=args.global_writer_control_decision_ref,
        repository_or_runtime=str(adcp_source_root),
    )


def _row(value) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return dict(value)


def _load_maker_capsule(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CAPSULE_CONTENT_OBJECT_REQUIRED")
    if {"capsule_version", "role", "content"}.issubset(payload):
        return build_context_capsule(
            CapsuleRole(payload["role"]),
            payload["content"],
            capsule_version=payload["capsule_version"],
        )
    return build_context_capsule(CapsuleRole.MAKER, payload)


def main(
    argv: Sequence[str] | None = None,
    *,
    controller_factory: Callable[[argparse.Namespace], Controller] = _build_controller,
) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["production-prepare"]:
        production_args = _production_prepare_parser().parse_args(raw_argv[1:])
        result = prepare_canonical_production(production_args.accepted_adcp_head)
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    args = _parser().parse_args(raw_argv)
    controller = controller_factory(args)
    try:
        with _production_control_scope(args, controller):
            if args.command == "create":
                result = controller.create_execution(
                    ExecutionCreate(
                        execution_id=args.execution_id,
                        slice_id=args.slice_id,
                        risk_level=RiskLevel(args.risk),
                        environment=Environment(args.environment),
                        contract_fingerprint=args.contract_fingerprint,
                        authority_fingerprint=args.authority_fingerprint,
                        source_root=str(args.source_root),
                        branch=args.branch,
                        base_commit=args.base_commit,
                    )
                )
            elif args.command == "bind-deferred":
                result = controller.bind_deferred_execution(
                    ExecutionCreate(
                        execution_id=args.execution_id,
                        slice_id=args.slice_id,
                        risk_level=RiskLevel(args.risk),
                        environment=Environment(args.environment),
                        contract_fingerprint=args.contract_fingerprint,
                        authority_fingerprint=args.authority_fingerprint,
                        source_root=str(args.source_root),
                        branch=args.branch,
                        base_commit=args.base_commit,
                    ),
                    expected_state_version=args.expected_state_version,
                    maker_capsule=_load_maker_capsule(args.maker_capsule),
                    packet_ref=args.packet_ref,
                    provision_branch_if_missing=args.provision_branch_if_missing,
                )
            elif args.command == "release-prebound":
                result = controller.release_prebound_execution(
                    args.execution_id,
                    args.slice_id,
                    expected_execution_state_version=args.expected_execution_state_version,
                    expected_slice_state_version=args.expected_slice_state_version,
                    release_reason=args.reason,
                    authority_ref=args.authority_ref,
                )
            elif args.command == "register-slice":
                result = controller.register_slice(
                    slice_id=args.slice_id,
                    stage=args.stage,
                    status=args.status,
                    migration_class=args.migration_class,
                    execution_eligibility=args.execution_eligibility,
                    defer_reason=args.defer_reason,
                    logical_source_root=args.logical_source_root,
                    registration_ref=args.registration_ref,
                    expected_authority_generation=args.expected_authority_generation,
                )
            elif args.command == "start":
                result = controller.acquire(args.execution_id)
            elif args.command == "status":
                result = controller.inspect(args.execution_id)
            elif args.command == "advance":
                result = controller.advance(args.execution_id, limit=args.limit)
            elif args.command == "approve":
                result = controller.resolve_approval(
                    args.execution_id,
                    ApprovalBinding(args.approval_id, args.authority_ref),
                    approved=True,
                )
            else:
                result = controller.cancel(args.execution_id)
        print(json.dumps(_row(result), sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        controller.store.close()


if __name__ == "__main__":
    raise SystemExit(main())
