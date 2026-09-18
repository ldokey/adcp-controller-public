from __future__ import annotations

import json
import unittest

from adcp.canonical import canonical_sha256
from adcp.notion_projection import NotionProjectionTarget
from adcp.projection import ProjectionDrift, ProjectionEnvelope, compare_projection


SCHEMA = {
    name: {"type": kind}
    for name, kind in {
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
    }.items()
}


class FakeNotionProjectionTarget(NotionProjectionTarget):
    def __init__(self) -> None:
        super().__init__(
            token="test-token",
            data_source_id="data-source-1",
            test_run_id="test-run-1",
        )
        self.pages: list[dict] = []
        self.calls: list[tuple[str, str]] = []

    @staticmethod
    def _response_properties(properties):
        response = {}
        for name, value in properties.items():
            kind = SCHEMA[name]["type"]
            response[name] = {"type": kind, **value}
        return response

    def _request(self, method, path, body=None, *, endpoint):
        self.calls.append((method, endpoint))
        if endpoint == "data-source-read":
            return 200, {"id": self.data_source_id, "properties": SCHEMA}
        if endpoint == "data-source-query":
            results = []
            for page in self.pages:
                props = page["properties"]
                if (
                    self._plain_text(props["Test Run ID"]) == self.test_run_id
                    and self._plain_text(props["Control Execution ID"]) == "execution-1"
                    and props["Isolated Shadow Only"]["checkbox"]
                ):
                    results.append(page)
            return 200, {"results": results, "has_more": False}
        if endpoint == "page-create":
            page = {
                "id": "page-1",
                "properties": self._response_properties(body["properties"]),
            }
            self.pages.append(page)
            return 200, page
        if endpoint in {"page-update", "page-controlled-drift"}:
            self.pages[0]["properties"].update(
                self._response_properties(body["properties"])
            )
            return 200, self.pages[0]
        raise AssertionError(endpoint)


def envelope() -> ProjectionEnvelope:
    payload = {
        "projection_schema_version": 1,
        "control_execution_id": "execution-1",
        "projection_version": 7,
        "execution_state": "ACCEPTED",
        "state_version": 7,
        "source_root": "/tmp/isolated",
        "base_commit": "1" * 40,
        "result_commit": "2" * 40,
        "risk": "NORMAL",
        "blocker_or_escalation": None,
        "attempt_summary": {},
        "verification_status": None,
        "evaluator_verdict": None,
        "approval_status": None,
        "evidence_manifest_hash": "a" * 64,
        "projected_at": "2026-08-12T00:00:00.000000+00:00",
    }
    payload_hash = canonical_sha256(payload)
    identity = canonical_sha256(
        {"control_execution_id": "execution-1", "projection_payload_hash": payload_hash}
    )
    return ProjectionEnvelope(payload, payload_hash, identity)


class NotionProjectionTests(unittest.TestCase):
    def test_preflight_checks_exact_schema_and_query(self) -> None:
        target = FakeNotionProjectionTarget()

        target.preflight()

        self.assertEqual(
            target.calls,
            [("GET", "data-source-read"), ("POST", "data-source-query")],
        )

    def test_write_retry_reuses_owned_row_and_reads_canonical_payload(self) -> None:
        target = FakeNotionProjectionTarget()
        expected = envelope()

        target.write("execution-1", expected.projection_identity, expected.as_dict())
        target.write("execution-1", expected.projection_identity, expected.as_dict())

        self.assertEqual(len(target.pages), 1)
        self.assertEqual(target.logical_row_count("execution-1"), 1)
        self.assertEqual(target.read("execution-1"), expected.as_dict())
        snapshot = target.row_snapshot("execution-1")
        self.assertEqual(snapshot["projection_identity"], expected.projection_identity)
        self.assertTrue(snapshot["isolated_shadow_only"])
        self.assertEqual(
            target.pages[0]["properties"]["Validation State"]["select"]["name"],
            "WRITTEN",
        )

    def test_controlled_drift_is_detected_and_canonical_write_repairs_it(self) -> None:
        target = FakeNotionProjectionTarget()
        expected = envelope()
        target.write("execution-1", expected.projection_identity, expected.as_dict())

        target.apply_controlled_drift("execution-1", expected.as_dict())
        drift = compare_projection(expected, target)
        target.write("execution-1", expected.projection_identity, expected.as_dict())
        repaired = compare_projection(expected, target)

        self.assertEqual(drift.classification, ProjectionDrift.PROJECTION_CONTENT_MISMATCH)
        self.assertEqual(repaired.classification, ProjectionDrift.NO_DRIFT)
        self.assertEqual(len(target.pages), 1)
        self.assertEqual(
            target.pages[0]["properties"]["Validation State"]["select"]["name"],
            "RECONCILED",
        )


if __name__ == "__main__":
    unittest.main()
