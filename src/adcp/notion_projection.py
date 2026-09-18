"""Minimal stdlib transport for isolated Notion shadow projections."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from typing import Any
import urllib.error
import urllib.request

from adcp.canonical import canonical_json, canonical_sha256
from adcp.projection import ProjectionError, ProjectionTargetUnavailable


DEFAULT_NOTION_API_VERSION = "2026-03-11"
NOTION_API_BASE = "https://api.notion.com/v1"

_EXPECTED_SCHEMA = {
    "Canonical Payload": "rich_text",
    "Control Execution ID": "rich_text",
    "Evidence Manifest Hash": "rich_text",
    "Execution State": "rich_text",
    "Isolated Shadow Only": "checkbox",
    "Name": "title",
    "Projected At": "date",
    "Projection Identity": "rich_text",
    "Projection Payload Hash": "rich_text",
    "Projection Version": "number",
    "Result Commit": "rich_text",
    "State Version": "number",
    "Test Run ID": "rich_text",
    "Validation State": "select",
}


class NotionProjectionTarget:
    """ProjectionTarget bound to one C5B test identity in one data source."""

    target_type = "NOTION_ISOLATED_SHADOW"

    def __init__(
        self,
        *,
        token: str,
        data_source_id: str,
        test_run_id: str,
        api_version: str = DEFAULT_NOTION_API_VERSION,
        urlopen: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        if not token:
            raise ProjectionTargetUnavailable("credential source returned an empty token")
        if not data_source_id or not test_run_id:
            raise ProjectionError("INVALID_NOTION_TARGET_CONFIGURATION")
        self._token = token
        self.data_source_id = data_source_id
        self.test_run_id = test_run_id
        self.api_version = api_version
        self._urlopen = urlopen
        self.target_ref = f"notion-data-source://{data_source_id}/run/{test_run_id}"
        self.last_write_status: int | None = None
        self.last_page_id: str | None = None
        self.request_evidence: list[tuple[str, str, int]] = []

    def preflight(self) -> None:
        status, metadata = self._request(
            "GET", f"/data_sources/{self.data_source_id}", endpoint="data-source-read"
        )
        if metadata.get("id") != self.data_source_id:
            raise ProjectionError("NOTION_TARGET_ID_MISMATCH")
        properties = metadata.get("properties", {})
        observed_schema = {
            name: value.get("type") for name, value in properties.items()
        }
        if any(observed_schema.get(name) != kind for name, kind in _EXPECTED_SCHEMA.items()):
            raise ProjectionError("NOTION_TARGET_SCHEMA_MISMATCH")
        self._request(
            "POST",
            f"/data_sources/{self.data_source_id}/query",
            {"page_size": 1},
            endpoint="data-source-query",
        )
        if status != 200:
            raise ProjectionTargetUnavailable("data-source-read did not return HTTP 200")

    def read(self, execution_id: str) -> Mapping[str, Any] | None:
        rows = self._query_owned_rows(execution_id)
        if not rows:
            self.last_page_id = None
            return None
        if len(rows) != 1:
            raise ProjectionError("PROJECTION_DUPLICATE_DIVERGENT_ROWS")
        row = rows[0]
        self.last_page_id = row.get("id")
        properties = row.get("properties", {})
        raw_payload = self._plain_text(properties.get("Canonical Payload", {}))
        try:
            payload = json.loads(raw_payload)
        except (TypeError, json.JSONDecodeError) as error:
            raise ProjectionError("PROJECTION_CONTENT_MISMATCH") from error
        if not isinstance(payload, dict):
            raise ProjectionError("PROJECTION_CONTENT_MISMATCH")
        payload["projection_payload_hash"] = self._plain_text(
            properties.get("Projection Payload Hash", {})
        )
        return payload

    def logical_row_count(self, execution_id: str) -> int:
        return len(self._query_owned_rows(execution_id))

    def row_snapshot(self, execution_id: str) -> dict[str, Any] | None:
        rows = self._query_owned_rows(execution_id)
        if not rows:
            return None
        if len(rows) != 1:
            raise ProjectionError("PROJECTION_DUPLICATE_DIVERGENT_ROWS")
        row = rows[0]
        properties = row.get("properties", {})
        return {
            "page_id": row.get("id"),
            "test_run_id": self._plain_text(properties.get("Test Run ID", {})),
            "control_execution_id": self._plain_text(
                properties.get("Control Execution ID", {})
            ),
            "projection_identity": self._plain_text(
                properties.get("Projection Identity", {})
            ),
            "projection_payload_hash": self._plain_text(
                properties.get("Projection Payload Hash", {})
            ),
            "isolated_shadow_only": properties.get("Isolated Shadow Only", {}).get(
                "checkbox"
            ),
        }

    def write(
        self,
        execution_id: str,
        projection_identity: str,
        payload: Mapping[str, Any],
    ) -> None:
        materialized = json.loads(canonical_json(dict(payload)))
        supplied_hash = materialized.pop("projection_payload_hash", None)
        valid = (
            isinstance(supplied_hash, str)
            and canonical_sha256(materialized) == supplied_hash
            and canonical_sha256(
                {
                    "control_execution_id": execution_id,
                    "projection_payload_hash": supplied_hash,
                }
            )
            == projection_identity
        )
        if not valid:
            raise ProjectionError("PROJECTION_IDENTITY_MISMATCH")
        materialized["projection_payload_hash"] = supplied_hash
        rows = self._query_owned_rows(execution_id)
        if len(rows) > 1:
            raise ProjectionError("PROJECTION_DUPLICATE_DIVERGENT_ROWS")
        validation_state = "WRITTEN"
        if rows and self._select_name(
            rows[0].get("properties", {}).get("Validation State", {})
        ) == "DRIFT_INJECTED":
            validation_state = "RECONCILED"
        properties = self._projection_properties(
            execution_id,
            projection_identity,
            materialized,
            validation_state=validation_state,
        )
        if rows:
            page_id = rows[0].get("id")
            if not isinstance(page_id, str) or not page_id:
                raise ProjectionError("NOTION_PAGE_ID_MISSING")
            status, response = self._request(
                "PATCH",
                f"/pages/{page_id}",
                {"properties": properties},
                endpoint="page-update",
            )
        else:
            status, response = self._request(
                "POST",
                "/pages",
                {
                    "parent": {
                        "type": "data_source_id",
                        "data_source_id": self.data_source_id,
                    },
                    "properties": properties,
                },
                endpoint="page-create",
            )
        self.last_write_status = status
        self.last_page_id = response.get("id")

    def apply_controlled_drift(
        self, execution_id: str, canonical_payload: Mapping[str, Any]
    ) -> int:
        rows = self._query_owned_rows(execution_id)
        if len(rows) != 1:
            raise ProjectionError("PROJECTION_OWNED_ROW_REQUIRED")
        page_id = rows[0].get("id")
        drifted = json.loads(canonical_json(dict(canonical_payload)))
        drifted.pop("projection_payload_hash", None)
        drifted["risk"] = "C5B_SYNTHETIC_DRIFT"
        drift_hash = canonical_sha256(drifted)
        drifted["projection_payload_hash"] = drift_hash
        status, _ = self._request(
            "PATCH",
            f"/pages/{page_id}",
            {
                "properties": {
                    "Canonical Payload": self._rich_text(canonical_json(drifted)),
                    "Projection Payload Hash": self._rich_text(drift_hash),
                    "Validation State": {"select": {"name": "DRIFT_INJECTED"}},
                }
            },
            endpoint="page-controlled-drift",
        )
        self.last_write_status = status
        self.last_page_id = page_id
        return status

    def _projection_properties(
        self,
        execution_id: str,
        projection_identity: str,
        payload: Mapping[str, Any],
        *,
        validation_state: str,
    ) -> dict[str, Any]:
        payload_hash = payload["projection_payload_hash"]
        return {
            "Name": self._title(f"WCP-06C5B · {self.test_run_id}"),
            "Test Run ID": self._rich_text(self.test_run_id),
            "Control Execution ID": self._rich_text(execution_id),
            "Projection Identity": self._rich_text(projection_identity),
            "Projection Version": {"number": payload["projection_version"]},
            "State Version": {"number": payload["state_version"]},
            "Execution State": self._rich_text(str(payload["execution_state"])),
            "Result Commit": self._rich_text(str(payload.get("result_commit") or "")),
            "Evidence Manifest Hash": self._rich_text(
                str(payload.get("evidence_manifest_hash") or "")
            ),
            "Canonical Payload": self._rich_text(canonical_json(payload)),
            "Projection Payload Hash": self._rich_text(str(payload_hash)),
            "Projected At": {"date": {"start": payload["projected_at"]}},
            "Validation State": {"select": {"name": validation_state}},
            "Isolated Shadow Only": {"checkbox": True},
        }

    def _query_owned_rows(self, execution_id: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            body: dict[str, Any] = {
                "filter": {
                    "and": [
                        {
                            "property": "Test Run ID",
                            "rich_text": {"equals": self.test_run_id},
                        },
                        {
                            "property": "Control Execution ID",
                            "rich_text": {"equals": execution_id},
                        },
                        {
                            "property": "Isolated Shadow Only",
                            "checkbox": {"equals": True},
                        },
                    ]
                },
                "page_size": 100,
            }
            if cursor is not None:
                body["start_cursor"] = cursor
            _, response = self._request(
                "POST",
                f"/data_sources/{self.data_source_id}/query",
                body,
                endpoint="data-source-query",
            )
            rows.extend(response.get("results", []))
            if not response.get("has_more"):
                return rows
            cursor = response.get("next_cursor")
            if not isinstance(cursor, str) or not cursor:
                raise ProjectionTargetUnavailable("query pagination cursor missing")

    def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        endpoint: str,
    ) -> tuple[int, dict[str, Any]]:
        data = None if body is None else canonical_json(dict(body)).encode("utf-8")
        request = urllib.request.Request(
            NOTION_API_BASE + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Notion-Version": self.api_version,
                "Content-Type": "application/json",
                "User-Agent": "adcp-c5b-shadow-validator/1",
            },
        )
        try:
            with self._urlopen(request, timeout=30) as response:
                status = response.status
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            code = "UNKNOWN"
            try:
                error_payload = json.load(error)
                code = str(error_payload.get("code", code))
            except Exception:
                pass
            self.request_evidence.append((method, endpoint, error.code))
            raise ProjectionTargetUnavailable(
                f"{method} {endpoint} HTTP {error.code} code={code}"
            ) from error
        except Exception as error:
            raise ProjectionTargetUnavailable(
                f"{method} {endpoint} transport={type(error).__name__}"
            ) from error
        if not isinstance(payload, dict):
            raise ProjectionTargetUnavailable(f"{method} {endpoint} invalid JSON object")
        self.request_evidence.append((method, endpoint, status))
        return status, payload

    @staticmethod
    def _rich_text(value: str) -> dict[str, Any]:
        return {
            "rich_text": [
                {"type": "text", "text": {"content": value[index:index + 2000]}}
                for index in range(0, len(value), 2000)
            ]
        }

    @staticmethod
    def _title(value: str) -> dict[str, Any]:
        return {"title": [{"type": "text", "text": {"content": value[:2000]}}]}

    @staticmethod
    def _plain_text(prop: Mapping[str, Any]) -> str:
        kind = prop.get("type")
        fragments = prop.get(kind, []) if kind in {"rich_text", "title"} else []
        return "".join(
            str(item.get("plain_text", item.get("text", {}).get("content", "")))
            for item in fragments
        )

    @staticmethod
    def _select_name(prop: Mapping[str, Any]) -> str | None:
        selected = prop.get("select")
        return selected.get("name") if isinstance(selected, Mapping) else None


__all__ = ["DEFAULT_NOTION_API_VERSION", "NotionProjectionTarget"]
