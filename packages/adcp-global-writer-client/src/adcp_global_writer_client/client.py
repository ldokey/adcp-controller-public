from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from ._build_identity import ARTIFACT_IDENTITY, BUILD_ID, CLIENT_PACKAGE_NAME, CLIENT_VERSION, SOURCE_COMMIT
from .schema_contract import verify_client_schema_contract
from .store import DEFAULT_LEASE_TTL_SECONDS, GlobalWriterStore


@dataclass(frozen=True)
class ClientBuildIdentity:
    package_name: str
    version: str
    build_id: str
    source_commit: str
    artifact_identity: str
    thin_contract_format_version: int
    supported_dcs_schema_versions: tuple[int, ...]
    schema_contract_identity: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def client_build_identity() -> ClientBuildIdentity:
    contract = verify_client_schema_contract()
    return ClientBuildIdentity(
        CLIENT_PACKAGE_NAME,
        CLIENT_VERSION,
        BUILD_ID,
        SOURCE_COMMIT,
        ARTIFACT_IDENTITY,
        contract.thin_contract_format_version,
        contract.supported_dcs_schema_versions,
        contract.schema_contract_identity,
    )


class GlobalWriterLeaseClient:
    """Ordinary writer API for exact canonical DCS schema v6, v7, v8, or v9 only."""

    def __init__(self, dcs_path: str | Path, *, _clock: Callable[..., Any] | None = None) -> None:
        self._dcs_path = Path(dcs_path).expanduser().resolve()
        self._store = GlobalWriterStore(self._dcs_path) if _clock is None else GlobalWriterStore(self._dcs_path, clock=_clock)

    @property
    def dcs_path(self) -> Path:
        return self._dcs_path

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "GlobalWriterLeaseClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get(self) -> dict[str, Any]:
        return dict(self._store.get())

    def assert_current(self, owner_id: str, fencing_token: int) -> dict[str, Any]:
        return dict(self._store.assert_current(owner_id, fencing_token))

    def acquire(
        self,
        *,
        operation_key: str,
        owner_id: str,
        change_id: str,
        writer_class: str,
        owner_session_role: str,
        track: str,
        repository_or_runtime: str,
        operation_class: str,
        target: str,
        owner_execution_id: str | None = None,
        slice_id: str | None = None,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        control_decision_ref: str | None = None,
    ) -> dict[str, Any]:
        return dict(
            self._store.acquire(
                operation_key=operation_key,
                owner_id=owner_id,
                change_id=change_id,
                writer_class=writer_class,
                owner_session_role=owner_session_role,
                track=track,
                repository_or_runtime=repository_or_runtime,
                operation_class=operation_class,
                target=target,
                owner_execution_id=owner_execution_id,
                slice_id=slice_id,
                ttl_seconds=ttl_seconds,
                control_decision_ref=control_decision_ref,
            )
        )

    def heartbeat(self, owner_id: str, fencing_token: int, ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS) -> dict[str, Any]:
        return dict(self._store.heartbeat(owner_id, fencing_token, ttl_seconds))

    def release(
        self,
        *,
        operation_key: str,
        owner_id: str,
        fencing_token: int,
        reason: str = "GLOBAL_PRODUCTION_WRITER_RELEASED",
        control_decision_ref: str | None = None,
    ) -> dict[str, Any]:
        return dict(
            self._store.release(
                operation_key=operation_key,
                owner_id=owner_id,
                fencing_token=fencing_token,
                reason=reason,
                control_decision_ref=control_decision_ref,
            )
        )


class GlobalWriterControlClient(GlobalWriterLeaseClient):
    """Control-only extension. Ordinary clients have no force-revoke member."""

    def force_revoke(
        self,
        *,
        operation_key: str,
        reason: str,
        control_decision_ref: str,
        expected_owner_id: str,
        expected_fencing_token: int,
    ) -> dict[str, Any]:
        return dict(
            self._store.force_revoke(
                operation_key=operation_key,
                reason=reason,
                control_decision_ref=control_decision_ref,
                expected_owner_id=expected_owner_id,
                expected_fencing_token=expected_fencing_token,
            )
        )
