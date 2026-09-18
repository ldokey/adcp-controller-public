from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import adcp.postgres_control as pg
from adcp.postgres_control import (
    ApprovedPostgresRole,
    CatalogReadbackOperation,
    CatalogReadbackRequest,
    SanitizedProcessResult,
    TypedPostgresError,
)


class Schema10PostgresPreflightTests(unittest.TestCase):
    def test_json_catalog_transport_is_always_read_only(self) -> None:
        with patch.object(
            pg,
            "_run_psql",
            return_value=SanitizedProcessResult(0, '{"ok":true}\n', ""),
        ) as run:
            result = pg._json_query(SimpleNamespace(), database=pg.CLEANER_DATABASE, sql="SELECT 1")
        self.assertEqual({"ok": True}, result)
        self.assertTrue(run.call_args.kwargs["read_only"])

    def test_read_only_psql_overrides_inherited_pgoptions(self) -> None:
        policy = SimpleNamespace(
            psql_path=Path("/usr/bin/psql"),
            host="127.0.0.1",
            port=5432,
        )
        credential = SimpleNamespace(
            spec=SimpleNamespace(path=Path("/tmp/test.pgpass")),
            fingerprint=object(),
        )
        completed = SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")
        with patch.dict(pg.os.environ, {"PGOPTIONS": "-c default_transaction_read_only=off"}), patch.object(
            pg, "_revalidate_path_fingerprint"
        ), patch.object(pg.subprocess, "run", return_value=completed) as run:
            pg._spawn_psql(
                policy,
                database=pg.CLEANER_DATABASE,
                execution_role=pg.CLEANER_DBA_ROLE,
                stdin_sql=b"SELECT 1;\n",
                credential=credential,
                connection_secret="redacted-fixture",
                read_only=True,
            )
        env = run.call_args.kwargs["env"]
        self.assertEqual("-c default_transaction_read_only=on", env["PGOPTIONS"])
        self.assertEqual("/tmp/test.pgpass", env["PGPASSFILE"])

    @staticmethod
    def _passing_state() -> dict[str, object]:
        return {
            "transaction_read_only": "on",
            "app_runtime": {
                "role": ApprovedPostgresRole.APP_RUNTIME.value,
                "can_login": False,
                "inherit": False,
                "superuser": False,
                "create_db": False,
                "create_role": False,
                "replication": False,
                "bypass_rls": False,
            },
            "cleaner_app_exists": False,
            "memberships": [],
        }

    def test_schema10_principal_preflight_is_one_sealed_catalog_shape(self) -> None:
        request = CatalogReadbackRequest(CatalogReadbackOperation.SCHEMA10_PRINCIPAL_PREFLIGHT)
        with patch.object(pg, "_json_query", return_value=self._passing_state()) as query:
            result = pg._query_postgres_catalog(SimpleNamespace(), request)
        self.assertEqual("PASS", result["status"])
        self.assertEqual("TK43_DL85_SCHEMA10_PRINCIPAL_PREFLIGHT_V1", result["preflight_profile"])
        self.assertEqual(pg.CLEANER_DATABASE, query.call_args.kwargs["database"])
        sql = query.call_args.kwargs["sql"]
        self.assertIn("transaction_read_only", sql)
        self.assertIn("propertyai_app_runtime", sql)
        self.assertIn("propertyai_cleaner_app", sql)
        self.assertIn("pg_auth_members", sql)

    def test_schema10_principal_preflight_fails_closed_on_each_required_fact(self) -> None:
        request = CatalogReadbackRequest(CatalogReadbackOperation.SCHEMA10_PRINCIPAL_PREFLIGHT)
        cases = [
            ("transaction_read_only", "off", "POSTGRES_SCHEMA10_PREFLIGHT_NOT_READ_ONLY"),
            ("cleaner_app_exists", True, "POSTGRES_SCHEMA10_PREFLIGHT_CLEANER_APP_PRESENT"),
            (
                "memberships",
                [{"granted_role": "x", "member_role": "y"}],
                "POSTGRES_SCHEMA10_PREFLIGHT_MEMBERSHIP_PRESENT",
            ),
        ]
        for field, value, code in cases:
            with self.subTest(field=field):
                state = self._passing_state()
                state[field] = value
                with patch.object(pg, "_json_query", return_value=state):
                    with self.assertRaises(TypedPostgresError) as caught:
                        pg._query_postgres_catalog(SimpleNamespace(), request)
                self.assertEqual(code, caught.exception.code)

        state = self._passing_state()
        state["app_runtime"] = {"role": ApprovedPostgresRole.APP_RUNTIME.value, "can_login": True}
        with patch.object(pg, "_json_query", return_value=state):
            with self.assertRaises(TypedPostgresError) as caught:
                pg._query_postgres_catalog(SimpleNamespace(), request)
        self.assertEqual("POSTGRES_SCHEMA10_PREFLIGHT_APP_RUNTIME_MISMATCH", caught.exception.code)

    def test_public_approval_binding_includes_exact_preflight_profile(self) -> None:
        request = CatalogReadbackRequest(CatalogReadbackOperation.SCHEMA10_PRINCIPAL_PREFLIGHT)
        with patch.object(pg, "_resolve_public_operation_approval") as approval, patch.object(
            pg, "_canonical_cleaner_postgres_policy", return_value=SimpleNamespace()
        ), patch.object(pg, "_validate_sealed_canonical_policy"), patch.object(
            pg, "_query_postgres_catalog", return_value={"status": "PASS"}
        ):
            result = pg.query_postgres_catalog(
                request,
                change_id="P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01",
                gate_or_control_id="DL-85",
                control_decision_ref="DL-85-EXACT-DECISION",
            )
        self.assertEqual({"status": "PASS"}, result)
        kwargs = approval.call_args.kwargs
        self.assertEqual("QUERY_POSTGRES_CATALOG", kwargs["operation_kind"])
        self.assertEqual(("READ_POSTGRES_CATALOG",), kwargs["authorized_effect_scope"])
        self.assertEqual("query_postgres_catalog", kwargs["entrypoint"])
        self.assertEqual(
            {
                "database": pg.CLEANER_DATABASE,
                "catalog_operation": "SCHEMA10_PRINCIPAL_PREFLIGHT",
                "role": None,
                "read_only": True,
                "catalog_profile": "TK43_DL85_SCHEMA10_PRINCIPAL_PREFLIGHT_V1",
            },
            kwargs["target_identity"],
        )


if __name__ == "__main__":
    unittest.main()
