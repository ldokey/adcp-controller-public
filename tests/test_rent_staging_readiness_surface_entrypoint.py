from __future__ import annotations

from adcp import rent_staging_readiness_surface_entrypoint as entrypoint


def test_bootstrap_unknown_is_sanitized_and_target_fixed():
    result = entrypoint._unknown_result(
        "CONTROLLER_DIRTY",
        commit="a" * 40,
        tree="b" * 40,
        source_clean=False,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "CONTROLLER_DIRTY"
    assert result["target_id"] == "propertyai-rent-persistent-staging-pg18-55433"
    assert result["service_label"] == "com.propertyai.postgresql-rent-staging"
    assert result["secret_output"] == "NONE"
    assert result["mutation_exercised"] == "NO"
    assert result["controller_source_identity"] == {
        "commit": "a" * 40,
        "tree": "b" * 40,
        "source_clean": False,
        "entrypoint": "rent_staging_readiness_surface_entrypoint.py",
    }
    assert set(result["secret_reference_semantics"]) == {
        "flyway-secret.conf", "web.dsn", "session.dsn", "worker.dsn"
    }


def test_bootstrap_rejects_unknown_future_reason():
    result = entrypoint._unknown_result("FUTURE_REASON")
    assert result["reason_code"] == "BOOTSTRAP_INTERNAL_FAILURE"
    assert result["snapshot_status"] == "UNKNOWN"
