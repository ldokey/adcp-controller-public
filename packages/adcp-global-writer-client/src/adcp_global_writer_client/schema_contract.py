from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from . import _schema_contract as generated
from ._build_identity import (
    EXPECTED_SCHEMA_CONTRACT_IDENTITY,
    EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS,
    EXPECTED_THIN_CONTRACT_FORMAT_VERSION,
)
from .errors import GlobalWriterClientError


_EXACT_SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9, 10)
_LEGACY_V6_V7_SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7)
_LEGACY_V6_V7_SCHEMA_CONTRACT_IDENTITY = (
    "sha256:966387cc5ea17df6e6bdb89993c32f0c72d59fdaf33ebfaaba1b5e31e81a1e56"
)


@dataclass(frozen=True)
class SchemaProfile:
    schema_version: int
    profile_identity: str
    migration_history: tuple[tuple[int, str, str], ...]
    expected_tables: frozenset[str]
    expected_indexes: frozenset[str]
    expected_triggers: frozenset[str]
    expected_object_fingerprints: tuple[tuple[str, str, str], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "migration_history": [list(item) for item in self.migration_history],
            "expected_tables": sorted(self.expected_tables),
            "expected_indexes": sorted(self.expected_indexes),
            "expected_triggers": sorted(self.expected_triggers),
            "expected_object_fingerprints": [list(item) for item in self.expected_object_fingerprints],
        }

    def contract_payload(self) -> dict[str, Any]:
        return {"profile_identity": self.profile_identity, **self.payload()}


@dataclass(frozen=True)
class VerifiedSchemaContract:
    thin_contract_format_version: int
    supported_dcs_schema_versions: tuple[int, ...]
    schema_contract_identity: str
    profiles: tuple[SchemaProfile, ...]

    def profile_for_version(self, version: int) -> SchemaProfile:
        for profile in self.profiles:
            if profile.schema_version == version:
                return profile
        raise _invalid(f"unsupported generated schema profile: {version}")


def _invalid(detail: str) -> GlobalWriterClientError:
    return GlobalWriterClientError("GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID", detail)


def _canonical_identity(payload: dict[str, Any]) -> str:
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _invalid("generated schema contract cannot be canonicalized") from error
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _require_sorted_text_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or any(not isinstance(item, str) or not item for item in value):
        raise _invalid(f"{field} is malformed")
    if len(set(value)) != len(value) or value != tuple(sorted(value)):
        raise _invalid(f"{field} is not unique and ordered")
    return value


def _require_migration_history(value: Any, schema_version: int) -> tuple[tuple[int, str, str], ...]:
    if not isinstance(value, tuple) or not value:
        raise _invalid("migration history is malformed")
    history: list[tuple[int, str, str]] = []
    for item in value:
        if not isinstance(item, tuple) or len(item) != 3:
            raise _invalid("migration history entry is malformed")
        version, name, checksum = item
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or not isinstance(name, str)
            or not name
            or not isinstance(checksum, str)
            or len(checksum) != 64
        ):
            raise _invalid("migration history entry is malformed")
        history.append((version, name, checksum))
    result = tuple(history)
    if tuple(item[0] for item in result) != tuple(range(1, schema_version + 1)):
        raise _invalid("migration history versions are not canonical contiguous prefix")
    return result


def _require_fingerprints(value: Any) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, tuple):
        raise _invalid("object fingerprints are malformed")
    result: list[tuple[str, str, str]] = []
    for item in value:
        if not isinstance(item, tuple) or len(item) != 3:
            raise _invalid("object fingerprint entry is malformed")
        kind, name, digest = item
        if (
            kind not in {"table", "index", "trigger"}
            or not isinstance(name, str)
            or not name
            or not isinstance(digest, str)
            or len(digest) != 64
        ):
            raise _invalid("object fingerprint entry is malformed")
        result.append((kind, name, digest))
    fingerprints = tuple(result)
    if len({(kind, name) for kind, name, _ in fingerprints}) != len(fingerprints):
        raise _invalid("object fingerprints are not unique")
    if fingerprints != tuple(sorted(fingerprints)):
        raise _invalid("object fingerprints are not ordered")
    return fingerprints


def _profile(raw: Any) -> SchemaProfile:
    if not isinstance(raw, tuple) or len(raw) != 7:
        raise _invalid("generated schema profile is malformed")
    version, declared_identity, migrations, tables, indexes, triggers, fingerprints = raw
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise _invalid("generated schema profile version is malformed")
    if not isinstance(declared_identity, str):
        raise _invalid("generated schema profile identity is malformed")
    history = _require_migration_history(migrations, version)
    table_tuple = _require_sorted_text_tuple(tables, "expected tables")
    index_tuple = _require_sorted_text_tuple(indexes, "expected indexes")
    trigger_tuple = _require_sorted_text_tuple(triggers, "expected triggers")
    fingerprint_tuple = _require_fingerprints(fingerprints)
    expected_keys = (
        {( "table", name) for name in table_tuple}
        | {( "index", name) for name in index_tuple}
        | {( "trigger", name) for name in trigger_tuple}
    )
    if {(kind, name) for kind, name, _ in fingerprint_tuple} != expected_keys:
        raise _invalid("object fingerprints do not exactly match profile inventory")
    profile = SchemaProfile(
        schema_version=version,
        profile_identity=declared_identity,
        migration_history=history,
        expected_tables=frozenset(table_tuple),
        expected_indexes=frozenset(index_tuple),
        expected_triggers=frozenset(trigger_tuple),
        expected_object_fingerprints=fingerprint_tuple,
    )
    if _canonical_identity(profile.payload()) != declared_identity:
        raise _invalid(f"schema v{version} profile identity mismatch")
    return profile


def verify_client_schema_contract() -> VerifiedSchemaContract:
    try:
        format_version = generated.THIN_CONTRACT_FORMAT_VERSION
        supported_versions = generated.SUPPORTED_DCS_SCHEMA_VERSIONS
        declared_identity = generated.SCHEMA_CONTRACT_IDENTITY
        raw_profiles = generated.SCHEMA_PROFILES
    except Exception as error:
        raise _invalid("generated schema contract is malformed") from error

    if (
        format_version != 2
        or not isinstance(format_version, int)
        or isinstance(format_version, bool)
        or EXPECTED_THIN_CONTRACT_FORMAT_VERSION != 2
        or format_version != EXPECTED_THIN_CONTRACT_FORMAT_VERSION
    ):
        raise _invalid("thin contract format version does not match build identity")
    if (
        not isinstance(supported_versions, tuple)
        or supported_versions != _EXACT_SUPPORTED_DCS_SCHEMA_VERSIONS
        or EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS != _EXACT_SUPPORTED_DCS_SCHEMA_VERSIONS
        or supported_versions != EXPECTED_SUPPORTED_DCS_SCHEMA_VERSIONS
    ):
        raise _invalid("supported DCS schema versions do not match build identity")
    if not isinstance(raw_profiles, tuple) or len(raw_profiles) != len(_EXACT_SUPPORTED_DCS_SCHEMA_VERSIONS):
        raise _invalid("generated schema profiles are malformed")

    profiles = tuple(_profile(raw) for raw in raw_profiles)
    if tuple(profile.schema_version for profile in profiles) != supported_versions:
        raise _invalid("generated schema profile order does not match supported versions")

    payload = {
        "contract_format_version": format_version,
        "supported_dcs_schema_versions": list(supported_versions),
        "profiles": [profile.contract_payload() for profile in profiles],
    }
    computed_identity = _canonical_identity(payload)
    if (
        not isinstance(EXPECTED_SCHEMA_CONTRACT_IDENTITY, str)
        or not isinstance(declared_identity, str)
        or declared_identity != EXPECTED_SCHEMA_CONTRACT_IDENTITY
        or computed_identity != EXPECTED_SCHEMA_CONTRACT_IDENTITY
    ):
        raise _invalid("schema contract identity does not match build identity")

    return VerifiedSchemaContract(
        thin_contract_format_version=format_version,
        supported_dcs_schema_versions=supported_versions,
        schema_contract_identity=computed_identity,
        profiles=profiles,
    )


def verify_schema_contract() -> VerifiedSchemaContract:
    """Frozen v6/v7 compatibility view for the production migration orchestrator.

    The independently installable client validates the full v6/v7/v8/v9/v10 generated
    authority first.  This legacy view then re-derives the exact accepted v6/v7
    contract from the first two frozen profiles without weakening or aliasing
    either profile.
    """

    full = verify_client_schema_contract()
    profiles = full.profiles[:2]
    if tuple(profile.schema_version for profile in profiles) != _LEGACY_V6_V7_SUPPORTED_DCS_SCHEMA_VERSIONS:
        raise _invalid("legacy v6/v7 profile prefix is not exact")
    payload = {
        "contract_format_version": full.thin_contract_format_version,
        "supported_dcs_schema_versions": list(_LEGACY_V6_V7_SUPPORTED_DCS_SCHEMA_VERSIONS),
        "profiles": [profile.contract_payload() for profile in profiles],
    }
    identity = _canonical_identity(payload)
    if identity != _LEGACY_V6_V7_SCHEMA_CONTRACT_IDENTITY:
        raise _invalid("legacy v6/v7 schema contract identity drifted")
    return VerifiedSchemaContract(
        thin_contract_format_version=full.thin_contract_format_version,
        supported_dcs_schema_versions=_LEGACY_V6_V7_SUPPORTED_DCS_SCHEMA_VERSIONS,
        schema_contract_identity=identity,
        profiles=profiles,
    )
