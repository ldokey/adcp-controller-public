"""W08/W09 Global Production Writer integration for Control-side mutations.

This module composes the accepted ControlStore Global Writer primitive.  It does
not define another authority protocol and never bootstraps/migrates Production.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
import subprocess
import threading
from time import monotonic, sleep
from typing import Any, Callable, Iterable
from uuid import uuid4

from adcp.domain import StoreError, operation_key
from adcp.store.migrations import SCHEMA_VERSION
from adcp.store.sqlite import ControlStore, DEFAULT_LEASE_TTL_SECONDS

DEFAULT_HEARTBEAT_SECONDS = 15
W08_ACQUIRE_WAIT_DEADLINE_SECONDS = 30.0
W08_ACQUIRE_RETRY_INTERVAL_SECONDS = 0.5
W08_ACQUIRE_MAX_ATTEMPTS = 61


class ProductionControlError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class DeploymentStep:
    """One irreversible deployment effect plus its factual readback."""

    name: str
    effect: Callable[[], Any]
    readback: Callable[[Any], Any]


@dataclass(frozen=True)
class DeploymentEffectEvidence:
    step: str
    operation_id: str
    effect_result: Any
    readback: Any


class DeploymentAuthorityLost(ProductionControlError):
    def __init__(self, evidence: tuple[DeploymentEffectEvidence, ...], cause: BaseException) -> None:
        super().__init__("GLOBAL_PRODUCTION_DEPLOYMENT_AUTHORITY_LOST", type(cause).__name__)
        self.evidence = evidence
        self.__cause__ = cause


def assert_git_source_binding(root: str | Path, expected_head: str, *, require_clean: bool = True) -> None:
    """Read-only exact source authority check used by Control-side mutation paths."""

    if len(expected_head) != 40 or any(ch not in "0123456789abcdef" for ch in expected_head):
        raise ProductionControlError("SOURCE_AUTHORITY_EXPECTED_HEAD_INVALID")
    source = Path(root).expanduser().resolve(strict=True)
    completed = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        check=False, capture_output=True, text=True,
    )
    if completed.returncode != 0 or Path(completed.stdout.strip()).resolve(strict=True) != source:
        raise ProductionControlError("SOURCE_AUTHORITY_ROOT_MISMATCH")
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if head != expected_head:
        raise ProductionControlError("SOURCE_AUTHORITY_HEAD_MISMATCH")
    if require_clean:
        dirty = subprocess.run(
            ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        if dirty:
            raise ProductionControlError("SOURCE_AUTHORITY_DIRTY")


@dataclass(frozen=True)
class GitSourceAuthority:
    root: str | Path
    expected_head: str
    require_clean: bool = True

    def revalidate(self) -> None:
        assert_git_source_binding(
            self.root, self.expected_head, require_clean=self.require_clean
        )


@dataclass(frozen=True)
class ThinRuntimeAuthority:
    runtime_identity_path: str | Path
    authorized_identity_path: str | Path

    def revalidate(self) -> None:
        try:
            from adcp_global_writer_client import (
                MATCH,
                RuntimeIdentityError,
                authorize_new_mutation,
            )
        except ImportError as error:
            raise ProductionControlError("RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE") from error
        try:
            result = authorize_new_mutation(
                runtime_identity_path=self.runtime_identity_path,
                authorized_identity_path=self.authorized_identity_path,
            )
        except RuntimeIdentityError as error:
            raise ProductionControlError(error.code, error.detail) from error
        if result != MATCH:
            raise ProductionControlError("RUNTIME_IDENTITY_MISMATCH")


@dataclass(frozen=True)
class CompositeProductionAuthority:
    validators: tuple[GitSourceAuthority | ThinRuntimeAuthority, ...]

    def __post_init__(self) -> None:
        if not self.validators or any(
            type(value) not in {GitSourceAuthority, ThinRuntimeAuthority}
            for value in self.validators
        ):
            raise ProductionControlError("PRODUCTION_MUTATION_AUTHORITY_INVALID")

    def revalidate(self) -> None:
        for validator in self.validators:
            validator.revalidate()


ProductionMutationAuthority = (
    GitSourceAuthority | ThinRuntimeAuthority | CompositeProductionAuthority
)


def _revalidate_authority(authority: ProductionMutationAuthority) -> None:
    # The one DL98 worker authority composes these existing Git checks with
    # the existing protected approval resolver. No generic validator is accepted.
    from adcp.cleaner_worker_control import _WorkerAuthority
    if type(authority) not in {
        GitSourceAuthority,
        ThinRuntimeAuthority,
        CompositeProductionAuthority,
        _WorkerAuthority,
    }:
        raise ProductionControlError("PRODUCTION_MUTATION_AUTHORITY_INVALID")
    authority.revalidate()


class GlobalProductionControlLease:
    """One bounded Control-side GLOBAL_PRODUCTION lease with heartbeat and revalidation."""

    def __init__(
        self,
        store: ControlStore,
        *,
        change_id: str,
        unit_id: str,
        writer_class: str,
        owner_session_role: str,
        operation_class: str,
        target: str,
        authority: ProductionMutationAuthority,
        control_decision_ref: str | None = None,
        repository_or_runtime: str = "ADCP_CONTROL",
        track: str = "CONTROL",
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        heartbeat_seconds: int = DEFAULT_HEARTBEAT_SECONDS,
        start_heartbeat: bool = True,
        _bounded_acquire_wait: bool = False,
    ) -> None:
        if not unit_id:
            raise ProductionControlError("GLOBAL_PRODUCTION_UNIT_ID_REQUIRED")
        if heartbeat_seconds <= 0 or heartbeat_seconds > 20 or heartbeat_seconds >= ttl_seconds:
            raise ProductionControlError("GLOBAL_PRODUCTION_HEARTBEAT_POLICY_INVALID")
        if type(_bounded_acquire_wait) is not bool:
            raise ProductionControlError("W08_ACQUIRE_WAIT_POLICY_INVALID")
        if _bounded_acquire_wait and writer_class != "W08_CONTROLLED_PRODUCTION_DEPLOYMENT":
            raise ProductionControlError("W08_ACQUIRE_WAIT_SCOPE_INVALID")
        self.store = store
        self.change_id = change_id
        self.unit_id = unit_id
        self.writer_class = writer_class
        self.owner_session_role = owner_session_role
        self.operation_class = operation_class
        self.target = target
        self.authority = authority
        self.control_decision_ref = control_decision_ref
        self.repository_or_runtime = repository_or_runtime
        self.track = track
        self.ttl_seconds = ttl_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.start_heartbeat = start_heartbeat
        self._bounded_acquire_wait = _bounded_acquire_wait
        try:
            schema_row = self.store.connection.execute(
                "SELECT max(version) AS version FROM schema_migration"
            ).fetchone()
            schema_version = None if schema_row is None else schema_row["version"]
        except BaseException as error:
            raise ProductionControlError("GLOBAL_PRODUCTION_STORE_SCHEMA_UNREADABLE") from error
        if not isinstance(schema_version, int) or schema_version <= 0:
            raise ProductionControlError("GLOBAL_PRODUCTION_STORE_SCHEMA_UNREADABLE")
        # Heartbeats must reopen the exact schema generation held by the active
        # control store.  This preserves v7 behavior and is additive for an
        # explicitly adopted v8 ControlStore; it never performs a migration.
        self.store_schema_version = schema_version
        self.attempt_id = uuid4().hex
        self.owner_id = f"{writer_class}:{self.attempt_id}"
        self.fencing_token: int | None = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_error: BaseException | None = None
        self._guard = None
        identity = {"change_id": change_id, "unit_id": unit_id, "attempt_id": self.attempt_id,
                    "writer_class": writer_class, "operation_class": operation_class, "target": target}
        self.acquire_operation_key = operation_key("global-production-control-acquire", identity)
        self.release_operation_key = operation_key("global-production-control-release", identity)

    def _require_token(self) -> int:
        if self.fencing_token is None:
            raise ProductionControlError("GLOBAL_PRODUCTION_NOT_ACQUIRED")
        return self.fencing_token

    def _heartbeat_once(self) -> None:
        with ControlStore(
            self.store.database_path,
            migrate_schema=False,
            require_schema_version=self.store_schema_version,
            global_writer_guard_required=False,
            clock=self.store.clock,
        ) as heartbeat_store:
            heartbeat_store.heartbeat_global_production_writer(
                self.owner_id, self._require_token(), self.ttl_seconds
            )

    def _start_heartbeat(self) -> None:
        def worker() -> None:
            while not self._heartbeat_stop.wait(self.heartbeat_seconds):
                try:
                    self._heartbeat_once()
                except BaseException as error:
                    self._heartbeat_error = error
                    return
        self._heartbeat_thread = threading.Thread(
            target=worker, name="global-production-control-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def assert_current(self) -> None:
        if self._heartbeat_error is not None:
            raise ProductionControlError("GLOBAL_PRODUCTION_HEARTBEAT_FAILED") from self._heartbeat_error
        _revalidate_authority(self.authority)
        try:
            self.store.assert_current_global_writer(self.owner_id, self._require_token())
        except StoreError as error:
            raise ProductionControlError(error.code, error.detail) from error

    def _acquire_once(self):
        return self.store.acquire_global_production_writer(
            operation_key=self.acquire_operation_key,
            owner_id=self.owner_id,
            owner_execution_id=self.attempt_id,
            change_id=self.change_id,
            slice_id=self.unit_id,
            writer_class=self.writer_class,
            owner_session_role=self.owner_session_role,
            track=self.track,
            repository_or_runtime=self.repository_or_runtime,
            operation_class=self.operation_class,
            target=self.target,
            ttl_seconds=self.ttl_seconds,
            control_decision_ref=self.control_decision_ref,
        )

    def _acquire_with_optional_wait(self):
        if not self._bounded_acquire_wait:
            return self._acquire_once()

        deadline = monotonic() + W08_ACQUIRE_WAIT_DEADLINE_SECONDS
        attempts = 0
        while attempts < W08_ACQUIRE_MAX_ATTEMPTS:
            if attempts and monotonic() >= deadline:
                raise ProductionControlError(
                    "W08_ACQUIRE_WAIT_TIMEOUT", f"attempts={attempts}"
                )
            attempts += 1
            try:
                return self._acquire_once()
            except StoreError as error:
                if error.code != "GLOBAL_PRODUCTION_WRITER_HELD":
                    raise
                now = monotonic()
                if attempts >= W08_ACQUIRE_MAX_ATTEMPTS or now >= deadline:
                    raise ProductionControlError(
                        "W08_ACQUIRE_WAIT_TIMEOUT", f"attempts={attempts}"
                    ) from error
                delay = min(W08_ACQUIRE_RETRY_INTERVAL_SECONDS, deadline - now)
                if delay <= 0:
                    raise ProductionControlError(
                        "W08_ACQUIRE_WAIT_TIMEOUT", f"attempts={attempts}"
                    ) from error
                sleep(delay)
                if monotonic() >= deadline:
                    raise ProductionControlError(
                        "W08_ACQUIRE_WAIT_TIMEOUT", f"attempts={attempts}"
                    ) from error
                # A wait never extends stale mutation authority. Revalidate before
                # each retry while preserving the exact same semantic attempt/key.
                _revalidate_authority(self.authority)

        raise ProductionControlError(
            "W08_ACQUIRE_WAIT_TIMEOUT", f"attempts={attempts}"
        )

    def __enter__(self) -> "GlobalProductionControlLease":
        _revalidate_authority(self.authority)
        try:
            row = self._acquire_with_optional_wait()
            self.fencing_token = int(row["fencing_token"])
            # Mandatory post-acquire current source/runtime + lease revalidation.
            self.assert_current()
            self._guard = self.store.ordinary_global_writer_authority(
                self.owner_id, self._require_token()
            )
            self._guard.__enter__()
            if self.start_heartbeat:
                self._start_heartbeat()
            return self
        except BaseException as primary:
            if self.fencing_token is not None:
                try:
                    self.store.release_global_production_writer(
                        operation_key=self.release_operation_key,
                        owner_id=self.owner_id,
                        fencing_token=self.fencing_token,
                        reason="GLOBAL_PRODUCTION_POST_ACQUIRE_REVALIDATION_FAILED",
                        control_decision_ref=self.control_decision_ref,
                    )
                except BaseException:
                    pass
            raise primary

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=max(1, self.heartbeat_seconds + 1))
        if self._guard is not None:
            self._guard.__exit__(exc_type, exc, tb)
            self._guard = None
        release_error: BaseException | None = None
        if self.fencing_token is not None:
            try:
                self.store.release_global_production_writer(
                    operation_key=self.release_operation_key,
                    owner_id=self.owner_id,
                    fencing_token=self.fencing_token,
                    control_decision_ref=self.control_decision_ref,
                )
            except BaseException as error:
                release_error = error
        if release_error is not None and exc_type is None:
            raise ProductionControlError("GLOBAL_PRODUCTION_RELEASE_FAILED") from release_error
        return False


_ACTIVE_CONTROLLED_DEPLOYMENT_LEASE: ContextVar[GlobalProductionControlLease | None] = ContextVar(
    "adcp_active_controlled_deployment_lease", default=None
)


def revalidate_current_controlled_deployment_lease() -> None:
    """Revalidate the exact W08 lease owned by the active controlled deployment.

    This scoped API intentionally accepts no owner, fencing token, or lease object.
    It is valid only while ``run_controlled_deployment`` owns its current lease, so
    effect implementations can fail closed after blocking pre-dispatch work without
    exposing raw fencing authority to callers.
    """

    lease = _ACTIVE_CONTROLLED_DEPLOYMENT_LEASE.get()
    if lease is None:
        raise ProductionControlError(
            "CONTROLLED_DEPLOYMENT_REVALIDATION_OUTSIDE_ACTIVE_LEASE"
        )
    lease.assert_current()


def _prior_controlled_deployment_acquire(
    store: ControlStore, *, change_id: str, deployment_id: str
):
    """Return durable prior W08 acquisition evidence for the same semantic unit."""

    for row in reversed(store.global_production_writer_events()):
        if (
            row["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
            and row["new_change_id"] == change_id
            and row["new_slice_id"] == deployment_id
            and row["new_writer_class"] == "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
        ):
            return row
    return None


def run_controlled_deployment(
    store: ControlStore,
    *,
    change_id: str,
    deployment_id: str,
    authority: ProductionMutationAuthority,
    steps: Iterable[DeploymentStep],
    persist_result: Callable[[tuple[DeploymentEffectEvidence, ...]], Any],
    control_decision_ref: str | None = None,
    start_heartbeat: bool = True,
    bounded_acquire_wait: bool = False,
) -> tuple[DeploymentEffectEvidence, ...]:
    """W08: execute exactly one bounded deployment transaction under one lease.

    A deployment_id is a durable semantic operation identity.  If an earlier
    acquisition exists for that identity, this entry point refuses to repeat any
    effect blindly; Control must first reconcile factual Production state and use
    a new bounded deployment transaction only after that explicit decision.

    ``bounded_acquire_wait`` is an explicit W08-only contention policy. It keeps
    the existing atomic store acquire unchanged and retries only transient HELD
    results under one attempt identity, a 30-second monotonic deadline, 0.5-second
    sleeps, and a 61-attempt secondary ceiling. The default remains single-shot.
    """

    if type(bounded_acquire_wait) is not bool:
        raise ProductionControlError("W08_ACQUIRE_WAIT_POLICY_INVALID")

    prior = _prior_controlled_deployment_acquire(
        store, change_id=change_id, deployment_id=deployment_id
    )
    if prior is not None:
        raise ProductionControlError(
            "CONTROLLED_DEPLOYMENT_RECONCILIATION_REQUIRED",
            f"deployment_id={deployment_id},prior_fencing_token={prior['to_fencing_token']}",
        )

    evidence: list[DeploymentEffectEvidence] = []
    with GlobalProductionControlLease(
        store,
        change_id=change_id,
        unit_id=deployment_id,
        writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
        owner_session_role="GPT_REMOTE_CONTROLLED_DEPLOYMENT",
        operation_class="CONTROLLED_PRODUCTION_DEPLOYMENT",
        target="GLOBAL_PRODUCTION",
        authority=authority,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
        _bounded_acquire_wait=bounded_acquire_wait,
    ) as lease:
        scope = _ACTIVE_CONTROLLED_DEPLOYMENT_LEASE.set(lease)
        try:
            for index, step in enumerate(steps):
                operation_id = operation_key(
                    "controlled-production-deployment-step",
                    {"deployment_id": deployment_id, "index": index, "step": step.name},
                )
                # Fresh current authority immediately before every irreversible effect.
                lease.assert_current()
                effect_result = step.effect()
                # Factual readback is deliberately allowed before the post-effect authority gate:
                # a stale owner may observe facts but may not project authoritative state from them.
                readback = step.readback(effect_result)
                evidence.append(DeploymentEffectEvidence(step.name, operation_id, effect_result, readback))
                try:
                    # SC-13: stale owner cannot project an authoritative post-effect result or
                    # proceed to the next irreversible deployment effect.
                    lease.assert_current()
                except BaseException as error:
                    raise DeploymentAuthorityLost(tuple(evidence), error) from error
            # Readback may itself be external/unbounded; reassert immediately before durable result.
            lease.assert_current()
            persist_result(tuple(evidence))
            try:
                # persist_result may block; success is not reported unless the exact same
                # runner-owned lease and authority are still current after it returns.
                lease.assert_current()
            except BaseException as error:
                raise DeploymentAuthorityLost(tuple(evidence), error) from error
            return tuple(evidence)
        finally:
            _ACTIVE_CONTROLLED_DEPLOYMENT_LEASE.reset(scope)


def run_ordinary_production_control_mutation(
    store: ControlStore,
    *,
    change_id: str,
    unit_id: str,
    operation_class: str,
    authority: ProductionMutationAuthority,
    mutation: Callable[[], Any],
    control_decision_ref: str | None = None,
    start_heartbeat: bool = True,
) -> Any:
    """W09: serialize one ordinary Production control mutation; self-primitives stay exempt."""

    with GlobalProductionControlLease(
        store,
        change_id=change_id,
        unit_id=unit_id,
        writer_class="W09_ORDINARY_PRODUCTION_CONTROL",
        owner_session_role="ADCP_PRODUCTION_CONTROL",
        operation_class=operation_class,
        target="PRODUCTION_DCS",
        authority=authority,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    ) as lease:
        lease.assert_current()
        return mutation()
