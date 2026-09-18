"""Safe CLI surface for the frozen v6-to-v7 migration workflow.

The Maker-facing command can validate a store or run the complete workflow on
an explicitly created clone.  It has no canonical-Production execution,
arbitrary SQL, restore, backup pruning, or migration-selection interface.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Sequence

from adcp.production_migration_orchestrator import (
    ExecutionContext,
    EXPECTED_WRITER_CODES,
    ProductionMigrationError,
    ProductionMigrationOrchestrator,
    RuntimeWriter,
    capture_preservation_baseline,
)
from adcp.store.sqlite import CANONICAL_PRODUCTION_CONTROL_STORE


class _SimulationQuiescence:
    def __init__(self) -> None:
        self._writers = {
            (code, f"simulated-{code.lower()}"): RuntimeWriter(
                code,
                f"simulated-{code.lower()}",
                "PROPERTYAI" if code <= "W07" else "ADCP",
                "ACTIVE",
            )
            for code in sorted(EXPECTED_WRITER_CODES)
        }

    def discover(self):
        return tuple(self._writers.values())

    def quiesce(self, writer: RuntimeWriter) -> None:
        self._writers[writer.identity] = replace(writer, state="QUIESCED")

    def inspect(self, writer: RuntimeWriter) -> RuntimeWriter:
        return self._writers[writer.identity]

    def reactivate(self, writer: RuntimeWriter) -> None:
        self._writers[writer.identity] = replace(writer, state="ACTIVE")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m adcp.production_migration_cli")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="read-only exact v6/v7 validation")
    validate.add_argument("--database", required=True, type=Path)

    clone = commands.add_parser(
        "clone-dry-run",
        help="create-new-only SQLite clone and run the frozen workflow on that clone",
    )
    clone.add_argument("--source", required=True, type=Path)
    clone.add_argument("--clone", required=True, type=Path)
    clone.add_argument("--evidence-root", required=True, type=Path)
    clone.add_argument("--accepted-git-head", required=True)
    clone.add_argument("--accepted-git-tree", required=True)
    clone.add_argument("--authority-ref", required=True)
    return parser


def _canonical(path: Path) -> bool:
    return path.expanduser().resolve(strict=False) == CANONICAL_PRODUCTION_CONTROL_STORE.resolve(strict=False)


def _clone_create_new(source: Path, destination: Path) -> None:
    source = source.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve(strict=False)
    if _canonical(destination):
        raise ProductionMigrationError("CANONICAL_PRODUCTION_CLI_EXECUTION_FORBIDDEN")
    if source == destination:
        raise ProductionMigrationError("CLONE_SOURCE_TARGET_EQUAL")
    descriptor = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "validate":
            version = 0
            connection = sqlite3.connect(f"file:{args.database.expanduser().resolve(strict=True)}?mode=ro", uri=True)
            try:
                row = connection.execute("SELECT max(version) FROM schema_migration").fetchone()
                version = int(row[0]) if row and row[0] is not None else 0
            finally:
                connection.close()
            if version not in (6, 7):
                raise ProductionMigrationError("SUPPORTED_SCHEMA_V6_OR_V7_REQUIRED")
            baseline = capture_preservation_baseline(args.database, version)
            result = {
                "status": "VALID",
                "schema_version": version,
                "table_count": len(baseline.tables),
                "production_effect": 0,
            }
        else:
            if _canonical(args.source) or _canonical(args.clone):
                raise ProductionMigrationError("CANONICAL_PRODUCTION_CLI_EXECUTION_FORBIDDEN")
            _clone_create_new(args.source, args.clone)
            context = ExecutionContext(
                dcs_path=args.clone,
                evidence_root=args.evidence_root,
                accepted_git_head=args.accepted_git_head,
                accepted_git_tree=args.accepted_git_tree,
                authority_ref=args.authority_ref,
                canonical_production_path=CANONICAL_PRODUCTION_CONTROL_STORE,
                background_heartbeat=False,
            )
            migration = ProductionMigrationOrchestrator(
                context,
                authority=lambda: {"mode": "ISOLATED_CLONE_DRY_RUN"},
                quiescence=_SimulationQuiescence(),
            ).run()
            result = {
                "status": "PASS_CLONE_DRY_RUN",
                "clone": str(args.clone.resolve()),
                "schema_version": migration.version,
                "lease_state": migration.final_lease_state,
                "preserved_table_count": migration.preserved_table_count,
                "production_effect": migration.production_effect,
            }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, sqlite3.Error, ProductionMigrationError) as error:
        code = error.code if isinstance(error, ProductionMigrationError) else type(error).__name__
        print(json.dumps({"status": "FAIL", "code": code, "production_effect": 0}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
