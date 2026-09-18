from __future__ import annotations

from pathlib import Path
import hashlib
import sqlite3
import subprocess
import sys
import threading
from types import ModuleType
import unittest
from unittest.mock import patch

from adcp.domain import StoreError, operation_key
from adcp.production_control import (
    CompositeProductionAuthority,
    DeploymentAuthorityLost,
    DeploymentStep,
    GitSourceAuthority,
    GlobalProductionControlLease,
    ProductionControlError,
    ThinRuntimeAuthority,
    assert_git_source_binding,
    revalidate_current_controlled_deployment_lease,
    run_controlled_deployment,
    run_ordinary_production_control_mutation,
)
from adcp.store.migrations import SCHEMA_VERSION
from adcp.store.sqlite import ControlStore
from _helpers import StoreFixture


class _AuthorityProbe:
    """Test-only sequence probe for the sealed GitSourceAuthority adapter."""

    def __init__(self, fail_at: int | None = None, error: BaseException | None = None) -> None:
        self.calls = 0
        self.fail_at = fail_at
        self.error = error or ProductionControlError("SOURCE_AUTHORITY_STALE")

    def __call__(self, *args, **kwargs) -> None:
        self.calls += 1
        if self.fail_at is not None and self.calls >= self.fail_at:
            raise self.error


class _UnsafeCallable:
    def __call__(self) -> bool:
        return True


class _ThinRuntimeIdentityError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)


def _thin_module(*, result: str = "MATCH", error_code: str | None = None) -> ModuleType:
    module = ModuleType("adcp_global_writer_client")
    module.MATCH = "MATCH"
    module.RuntimeIdentityError = _ThinRuntimeIdentityError

    def authorize_new_mutation(**kwargs):
        if error_code is not None:
            raise _ThinRuntimeIdentityError(error_code, "SC11 disposable fixture")
        return result

    module.authorize_new_mutation = authorize_new_mutation
    return module




class _FakeAcquireClock:
    def __init__(self, *, advance_on_sleep: bool = True) -> None:
        self.now = 0.0
        self.advance_on_sleep = advance_on_sleep
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.advance_on_sleep:
            self.now += seconds


class ProductionControlIntegrationTests(StoreFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        # Prepare disposable v6 first, then reopen it exactly as a guarded Production DCS.
        self.store.close()
        self.store = ControlStore(
            self.root / "control.sqlite3",
            clock=self.clock,
            migrate_schema=False,
            require_schema_version=SCHEMA_VERSION,
            global_writer_guard_required=True,
        )
        self.sequence = 0
        marker = self.repo / ".sc11-authority-baseline"
        marker.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", marker.name], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.repo),
                "-c", "user.name=SC11 Fixture",
                "-c", "user.email=sc11-fixture@example.invalid",
                "commit", "-qm", "sc11 authority baseline",
            ],
            check=True,
        )
        self.source_head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def _authority(self, *, expected_head: str | None = None) -> GitSourceAuthority:
        return GitSourceAuthority(self.repo, expected_head or self.source_head, require_clean=True)

    def _key(self, label: str) -> str:
        self.sequence += 1
        return operation_key(label, {"sequence": self.sequence})

    def _acquire(self, writer_class: str, owner_id: str | None = None):
        owner_id = owner_id or f"{writer_class}-owner-{self.sequence + 1}"
        return self.store.acquire_global_production_writer(
            operation_key=self._key("test-holder-acquire"),
            owner_id=owner_id,
            owner_execution_id=f"execution-{owner_id}",
            change_id=f"CHANGE-{writer_class}",
            slice_id=writer_class,
            writer_class=writer_class,
            owner_session_role="TEST_HOLDER",
            track="TEST",
            repository_or_runtime="DISPOSABLE_TEST",
            operation_class="PRODUCTION_WRITE",
            target="GLOBAL_PRODUCTION",
            control_decision_ref="TEST/01B-C",
        )

    def _release(self, owner_id: str, token: int) -> None:
        self.store.release_global_production_writer(
            operation_key=self._key("test-holder-release"),
            owner_id=owner_id,
            fencing_token=token,
            control_decision_ref="TEST/01B-C",
        )

    def _deploy(
        self, *, authority=None, steps=(), persist_result=lambda evidence: None, deployment_id=None,
        start_heartbeat=False, bounded_acquire_wait=False,
    ):
        return run_controlled_deployment(
            self.store,
            change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
            deployment_id=deployment_id or f"deploy-{self.sequence + 1}",
            authority=authority or self._authority(),
            steps=steps,
            persist_result=persist_result,
            control_decision_ref="TEST/01B-C",
            start_heartbeat=start_heartbeat,
            bounded_acquire_wait=bounded_acquire_wait,
        )

    # W08 bounded contention successor: exact 30s / 0.5s / 61 policy.
    def test_w08_bounded_wait_immediate_success_one_attempt_no_sleep(self) -> None:
        clock = _FakeAcquireClock()
        effects: list[str] = []
        original = self.store.acquire_global_production_writer
        with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
             patch("adcp.production_control.sleep", side_effect=clock.sleep), \
             patch.object(self.store, "acquire_global_production_writer", wraps=original) as acquire:
            before = self.store.get_global_production_writer_lease()["fencing_token"]
            self._deploy(
                deployment_id="bounded-immediate", bounded_acquire_wait=True,
                steps=[DeploymentStep("EFFECT", lambda: effects.append("effect") or "ok", lambda v: v)],
            )
        rows = [r for r in self.store.global_production_writer_events()
                if r["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
                and r["new_slice_id"] == "bounded-immediate"]
        self.assertEqual(1, acquire.call_count)
        self.assertEqual([], clock.sleeps)
        self.assertEqual(["effect"], effects)
        self.assertEqual(1, len(rows))
        self.assertEqual(before + 1, rows[0]["to_fencing_token"])

    def test_w08_bounded_wait_held_once_then_success_same_semantic_attempt(self) -> None:
        holder = self._acquire("W07", "bounded-once-holder")
        holder_token = holder["fencing_token"]
        clock = _FakeAcquireClock()
        effects: list[str] = []
        original = self.store.acquire_global_production_writer
        released = False
        def sleeper(seconds: float) -> None:
            nonlocal released
            clock.sleep(seconds)
            if not released:
                self._release("bounded-once-holder", holder_token)
                released = True
        try:
            with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
                 patch("adcp.production_control.sleep", side_effect=sleeper), \
                 patch.object(self.store, "acquire_global_production_writer", wraps=original) as acquire:
                self._deploy(
                    deployment_id="bounded-held-once", bounded_acquire_wait=True,
                    steps=[DeploymentStep("EFFECT", lambda: effects.append("effect") or "ok", lambda v: v)],
                )
            self.assertEqual(2, acquire.call_count)
            self.assertEqual(1, len(clock.sleeps))
            keys = [c.kwargs["operation_key"] for c in acquire.call_args_list]
            attempts = [c.kwargs["owner_execution_id"] for c in acquire.call_args_list]
            self.assertEqual(1, len(set(keys)))
            self.assertEqual(1, len(set(attempts)))
            rows = [r for r in self.store.global_production_writer_events()
                    if r["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
                    and r["new_slice_id"] == "bounded-held-once"]
            self.assertEqual(1, len(rows))
            self.assertEqual(holder_token + 1, rows[0]["to_fencing_token"])
            self.assertEqual(["effect"], effects)
        finally:
            current = self.store.get_global_production_writer_lease()
            if current["state"] == "HELD" and current["owner_id"] == "bounded-once-holder":
                self._release("bounded-once-holder", holder_token)

    def test_w08_bounded_wait_multiple_held_then_success_exactly_one_event_and_fence(self) -> None:
        holder = self._acquire("W07", "bounded-multi-holder")
        holder_token = holder["fencing_token"]
        clock = _FakeAcquireClock()
        original = self.store.acquire_global_production_writer
        sleeps = 0
        def sleeper(seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            clock.sleep(seconds)
            if sleeps == 3:
                self._release("bounded-multi-holder", holder_token)
        try:
            with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
                 patch("adcp.production_control.sleep", side_effect=sleeper), \
                 patch.object(self.store, "acquire_global_production_writer", wraps=original) as acquire:
                self._deploy(deployment_id="bounded-held-multi", bounded_acquire_wait=True)
            self.assertEqual(4, acquire.call_count)
            rows = [r for r in self.store.global_production_writer_events()
                    if r["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
                    and r["new_slice_id"] == "bounded-held-multi"]
            self.assertEqual(1, len(rows))
            self.assertEqual(holder_token + 1, rows[0]["to_fencing_token"])
        finally:
            current = self.store.get_global_production_writer_lease()
            if current["state"] == "HELD" and current["owner_id"] == "bounded-multi-holder":
                self._release("bounded-multi-holder", holder_token)

    def test_w08_bounded_wait_deadline_timeout_fail_closed(self) -> None:
        holder = self._acquire("W07", "bounded-deadline-holder")
        holder_token = holder["fencing_token"]
        before_events = len(self.store.global_production_writer_events())
        effects: list[str] = []
        clock = _FakeAcquireClock()
        original = self.store.acquire_global_production_writer
        try:
            with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
                 patch("adcp.production_control.sleep", side_effect=clock.sleep), \
                 patch.object(self.store, "acquire_global_production_writer", wraps=original) as acquire:
                with self.assertRaises(ProductionControlError) as caught:
                    self._deploy(
                        deployment_id="bounded-deadline", bounded_acquire_wait=True,
                        steps=[DeploymentStep("EFFECT", lambda: effects.append("bad"), lambda v: v)],
                    )
            self.assertEqual("W08_ACQUIRE_WAIT_TIMEOUT", caught.exception.code)
            self.assertLessEqual(acquire.call_count, 61)
            self.assertEqual([], effects)
            current = self.store.get_global_production_writer_lease()
            self.assertEqual(("HELD", "bounded-deadline-holder", holder_token),
                             (current["state"], current["owner_id"], current["fencing_token"]))
            self.assertEqual(before_events, len(self.store.global_production_writer_events()))
        finally:
            self._release("bounded-deadline-holder", holder_token)

    def test_w08_bounded_wait_attempt_ceiling_when_monotonic_does_not_advance(self) -> None:
        clock = _FakeAcquireClock(advance_on_sleep=False)
        calls = 0
        def always_held(**kwargs):
            nonlocal calls
            calls += 1
            raise StoreError("GLOBAL_PRODUCTION_WRITER_HELD")
        with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
             patch("adcp.production_control.sleep", side_effect=clock.sleep), \
             patch.object(self.store, "acquire_global_production_writer", side_effect=always_held):
            with self.assertRaises(ProductionControlError) as caught:
                self._deploy(deployment_id="bounded-attempt-ceiling", bounded_acquire_wait=True)
        self.assertEqual("W08_ACQUIRE_WAIT_TIMEOUT", caught.exception.code)
        self.assertEqual(61, calls)
        self.assertEqual(60, len(clock.sleeps))

    def test_w08_bounded_wait_non_held_store_error_is_not_retried(self) -> None:
        clock = _FakeAcquireClock()
        with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
             patch("adcp.production_control.sleep", side_effect=clock.sleep), \
             patch.object(self.store, "acquire_global_production_writer", side_effect=StoreError("CONTROL_STORE_ERROR", "boom")) as acquire:
            with self.assertRaises(StoreError) as caught:
                self._deploy(deployment_id="bounded-non-held", bounded_acquire_wait=True)
        self.assertEqual("CONTROL_STORE_ERROR", caught.exception.code)
        self.assertEqual(1, acquire.call_count)
        self.assertEqual([], clock.sleeps)

    def test_w08_bounded_wait_unexpected_exception_is_not_retried(self) -> None:
        clock = _FakeAcquireClock()
        with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
             patch("adcp.production_control.sleep", side_effect=clock.sleep), \
             patch.object(self.store, "acquire_global_production_writer", side_effect=RuntimeError("unexpected")) as acquire:
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                self._deploy(deployment_id="bounded-unexpected", bounded_acquire_wait=True)
        self.assertEqual(1, acquire.call_count)
        self.assertEqual([], clock.sleeps)

    def test_w08_bounded_wait_cancellation_during_sleep_has_no_effect(self) -> None:
        holder = self._acquire("W07", "bounded-cancel-holder")
        holder_token = holder["fencing_token"]
        effects: list[str] = []
        clock = _FakeAcquireClock()
        try:
            with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
                 patch("adcp.production_control.sleep", side_effect=KeyboardInterrupt("cancel")):
                with self.assertRaises(KeyboardInterrupt):
                    self._deploy(
                        deployment_id="bounded-cancel", bounded_acquire_wait=True,
                        steps=[DeploymentStep("EFFECT", lambda: effects.append("bad"), lambda v: v)],
                    )
            self.assertEqual([], effects)
            current = self.store.get_global_production_writer_lease()
            self.assertEqual(("HELD", "bounded-cancel-holder", holder_token),
                             (current["state"], current["owner_id"], current["fencing_token"]))
        finally:
            self._release("bounded-cancel-holder", holder_token)

    def test_generic_control_lease_remains_single_shot_without_wait_opt_in(self) -> None:
        holder = self._acquire("W01", "single-shot-holder")
        token = holder["fencing_token"]
        lease = GlobalProductionControlLease(
            self.store, change_id="GENERIC-SINGLE-SHOT", unit_id="generic-single-shot",
            writer_class="W09_ORDINARY_PRODUCTION_CONTROL", owner_session_role="TEST",
            operation_class="GENERIC", target="GLOBAL_PRODUCTION", authority=self._authority(),
            start_heartbeat=False,
        )
        try:
            with patch("adcp.production_control.sleep", side_effect=AssertionError("generic caller must not wait")):
                with self.assertRaises(StoreError) as caught:
                    with lease:
                        pass
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", caught.exception.code)
        finally:
            self._release("single-shot-holder", token)

    def test_bounded_wait_is_rejected_for_non_w08_direct_lease(self) -> None:
        with self.assertRaises(ProductionControlError) as caught:
            GlobalProductionControlLease(
                self.store, change_id="SCOPE", unit_id="scope", writer_class="W09_ORDINARY_PRODUCTION_CONTROL",
                owner_session_role="TEST", operation_class="GENERIC", target="GLOBAL_PRODUCTION",
                authority=self._authority(), start_heartbeat=False, _bounded_acquire_wait=True,
            )
        self.assertEqual("W08_ACQUIRE_WAIT_SCOPE_INVALID", caught.exception.code)

    def test_w08_bounded_wait_failed_held_attempt_does_not_change_event_or_fence(self) -> None:
        holder = self._acquire("W07", "bounded-no-event-holder")
        token = holder["fencing_token"]
        events_before = len(self.store.global_production_writer_events())
        times = iter((0.0, 30.0))
        try:
            with patch("adcp.production_control.monotonic", side_effect=lambda: next(times)):
                with self.assertRaises(ProductionControlError) as caught:
                    self._deploy(deployment_id="bounded-no-event", bounded_acquire_wait=True)
            self.assertEqual("W08_ACQUIRE_WAIT_TIMEOUT", caught.exception.code)
            current = self.store.get_global_production_writer_lease()
            self.assertEqual(token, current["fencing_token"])
            self.assertEqual("bounded-no-event-holder", current["owner_id"])
            self.assertEqual(events_before, len(self.store.global_production_writer_events()))
        finally:
            self._release("bounded-no-event-holder", token)

    def test_w08_bounded_wait_observed_contention_shape_succeeds_without_preemption(self) -> None:
        holder = self._acquire("W07", "contention-shape-holder")
        token = holder["fencing_token"]
        clock = _FakeAcquireClock()
        released = False
        def sleeper(seconds: float) -> None:
            nonlocal released
            clock.sleep(seconds)
            if clock.now >= 4.0 and not released:
                current = self.store.get_global_production_writer_lease()
                self.assertEqual(("HELD", "contention-shape-holder", token),
                                 (current["state"], current["owner_id"], current["fencing_token"]))
                self._release("contention-shape-holder", token)
                released = True
        try:
            with patch("adcp.production_control.monotonic", side_effect=clock.monotonic), \
                 patch("adcp.production_control.sleep", side_effect=sleeper):
                self._deploy(deployment_id="contention-shape", bounded_acquire_wait=True)
            self.assertTrue(released)
            rows = [r for r in self.store.global_production_writer_events()
                    if r["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
                    and r["new_slice_id"] == "contention-shape"]
            self.assertEqual(1, len(rows))
            self.assertEqual(token + 1, rows[0]["to_fencing_token"])
            self.assertGreaterEqual(clock.now, 4.0)
            self.assertLess(clock.now, 30.0)
        finally:
            current = self.store.get_global_production_writer_lease()
            if current["state"] == "HELD" and current["owner_id"] == "contention-shape-holder":
                self._release("contention-shape-holder", token)

    # W08_A / W08_F: a current Product writer makes deployment mutation count zero.
    def test_w08_lease_unavailable_blocks_all_deployment_effects(self) -> None:
        holder = self._acquire("W01")
        effects: list[str] = []
        try:
            with self.assertRaises(StoreError) as caught:
                self._deploy(steps=[DeploymentStep("SOURCE_PROMOTION", lambda: effects.append("x"), lambda value: value)])
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", caught.exception.code)
            self.assertEqual([], effects)
        finally:
            self._release(holder["owner_id"], holder["fencing_token"])

    # W08_B: post-acquire authority is current, but stale immediately before first effect.
    def test_w08_stale_before_first_irreversible_effect_mutates_nothing(self) -> None:
        effects: list[str] = []
        authority_probe = _AuthorityProbe(fail_at=3)
        with patch("adcp.production_control.assert_git_source_binding", side_effect=authority_probe):
            with self.assertRaises(ProductionControlError):
                self._deploy(
                    steps=[DeploymentStep("SOURCE_PROMOTION", lambda: effects.append("source"), lambda value: value)],
                )
        self.assertEqual([], effects)

    # W08_C / SC-13: factual effect + readback survive, stale authoritative result does not.
    def test_w08_post_effect_stale_preserves_facts_but_writes_no_result(self) -> None:
        effects: list[str] = []
        readbacks: list[str] = []
        results: list[object] = []
        authority_probe = _AuthorityProbe(fail_at=4)

        def effect():
            effects.append("promoted")
            return "candidate-head"

        def readback(value):
            readbacks.append(value)
            return {"head": value}

        with patch("adcp.production_control.assert_git_source_binding", side_effect=authority_probe):
            with self.assertRaises(DeploymentAuthorityLost) as caught:
                self._deploy(
                    steps=[DeploymentStep("SOURCE_PROMOTION", effect, readback)],
                    persist_result=lambda evidence: results.append(evidence),
                )
        self.assertEqual(["promoted"], effects)
        self.assertEqual(["candidate-head"], readbacks)
        self.assertEqual([], results)
        self.assertEqual(1, len(caught.exception.evidence))
        self.assertEqual("SOURCE_PROMOTION", caught.exception.evidence[0].step)

    def test_w08_ambiguous_prior_effect_requires_reconciliation_before_same_id_retry(self) -> None:
        deployment_id = "ambiguous-deployment"
        first_effects: list[str] = []
        authority_probe = _AuthorityProbe(fail_at=4)
        with patch("adcp.production_control.assert_git_source_binding", side_effect=authority_probe):
            with self.assertRaises(DeploymentAuthorityLost) as lost:
                self._deploy(
                    deployment_id=deployment_id,
                    steps=[
                        DeploymentStep(
                            "SOURCE_PROMOTION",
                            lambda: first_effects.append("promoted") or "candidate",
                            lambda value: {"head": value},
                        )
                    ],
                )
        self.assertEqual(["promoted"], first_effects)
        self.assertEqual(1, len(lost.exception.evidence))
        retry_effects: list[str] = []
        with self.assertRaises(ProductionControlError) as blocked:
            self._deploy(
                deployment_id=deployment_id,
                steps=[
                    DeploymentStep(
                        "SOURCE_PROMOTION",
                        lambda: retry_effects.append("blind-repeat"),
                        lambda value: value,
                    )
                ],
            )
        self.assertEqual("CONTROLLED_DEPLOYMENT_RECONCILIATION_REQUIRED", blocked.exception.code)
        self.assertEqual([], retry_effects)
        prior = [
            row
            for row in self.store.global_production_writer_events()
            if row["new_slice_id"] == deployment_id
            and row["new_writer_class"] == "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
        ]
        self.assertEqual(1, len(prior))

    # W08_D: heartbeat failure is a hard gate for subsequent effects.
    def test_w08_heartbeat_failure_blocks_subsequent_effect(self) -> None:
        effects: list[str] = []
        lease = GlobalProductionControlLease(
            self.store,
            change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
            unit_id="heartbeat-case",
            writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
            owner_session_role="TEST",
            operation_class="DEPLOY",
            target="GLOBAL_PRODUCTION",
            authority=self._authority(),
            start_heartbeat=False,
        )
        with lease:
            lease.assert_current()
            effects.append("first")
            lease._heartbeat_error = RuntimeError("heartbeat failed")
            with self.assertRaises(ProductionControlError) as caught:
                lease.assert_current()
            self.assertEqual("GLOBAL_PRODUCTION_HEARTBEAT_FAILED", caught.exception.code)
            if caught.exception.code != "GLOBAL_PRODUCTION_HEARTBEAT_FAILED":
                effects.append("second")
        self.assertEqual(["first"], effects)

    def test_w08_scoped_revalidation_blocks_dispatch_after_heartbeat_latches_during_blocking_io(self) -> None:
        blocking_started = threading.Event()
        heartbeat_latched = threading.Event()
        dispatches: list[str] = []

        def fake_start(lease: GlobalProductionControlLease) -> None:
            def worker() -> None:
                if blocking_started.wait(2):
                    lease._heartbeat_error = RuntimeError("heartbeat failed during blocking I/O")
                    heartbeat_latched.set()

            lease._heartbeat_thread = threading.Thread(target=worker, daemon=True)
            lease._heartbeat_thread.start()

        def effect() -> str:
            # Simulate caller-owned blocking pre-dispatch work after the runner's
            # ordinary pre-effect assertion and before the irreversible dispatch.
            blocking_started.set()
            self.assertTrue(heartbeat_latched.wait(2))
            revalidate_current_controlled_deployment_lease()
            dispatches.append("irreversible-dispatch")
            return "dispatched"

        with patch.object(GlobalProductionControlLease, "_start_heartbeat", fake_start):
            with self.assertRaises(ProductionControlError) as blocked:
                self._deploy(
                    steps=[DeploymentStep("BLOCKING_PRE_DISPATCH", effect, lambda value: value)],
                    start_heartbeat=True,
                )
        self.assertEqual("GLOBAL_PRODUCTION_HEARTBEAT_FAILED", blocked.exception.code)
        self.assertEqual([], dispatches)

    def test_w08_scoped_revalidation_blocks_dispatch_after_same_lease_fencing_changes(self) -> None:
        dispatches: list[str] = []

        def effect() -> str:
            current = self.store.get_global_production_writer_lease()
            self.store.force_revoke_global_production_writer(
                operation_key=self._key("test-same-lease-force-revoke"),
                reason="TEST_SAME_LEASE_FENCING_CHANGE",
                control_decision_ref="TEST/01B-C",
                expected_owner_id=current["owner_id"],
                expected_fencing_token=current["fencing_token"],
            )
            revalidate_current_controlled_deployment_lease()
            dispatches.append("irreversible-dispatch")
            return "dispatched"

        with self.assertRaises(ProductionControlError) as blocked:
            self._deploy(
                steps=[DeploymentStep("FENCING_CHANGE", effect, lambda value: value)],
            )
        self.assertEqual("STALE_FENCING_TOKEN", blocked.exception.code)
        self.assertEqual([], dispatches)

    def test_w08_scoped_revalidation_uses_same_runner_lease_once_without_nested_acquire(self) -> None:
        deployment_id = "same-runner-lease-success"
        before = self.store.get_global_production_writer_lease()["fencing_token"]
        dispatches: list[str] = []

        def effect() -> str:
            revalidate_current_controlled_deployment_lease()
            dispatches.append("irreversible-dispatch")
            return "done"

        evidence = self._deploy(
            deployment_id=deployment_id,
            steps=[DeploymentStep("SAME_LEASE", effect, lambda value: value)],
        )
        after = self.store.get_global_production_writer_lease()
        acquires = [
            row for row in self.store.global_production_writer_events()
            if row["event_type"] in {"ACQUIRE", "EXPIRED_TAKEOVER"}
            and row["new_slice_id"] == deployment_id
            and row["new_writer_class"] == "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
        ]
        self.assertEqual(["irreversible-dispatch"], dispatches)
        self.assertEqual(1, len(evidence))
        self.assertEqual(before + 1, after["fencing_token"])
        self.assertEqual("FREE", after["state"])
        self.assertEqual(1, len(acquires))

    def test_w08_scoped_revalidation_cannot_escape_lifetime_or_accept_substituted_identity(self) -> None:
        with self.assertRaises(ProductionControlError) as before:
            revalidate_current_controlled_deployment_lease()
        self.assertEqual(
            "CONTROLLED_DEPLOYMENT_REVALIDATION_OUTSIDE_ACTIVE_LEASE", before.exception.code
        )

        self._deploy(
            deployment_id="scope-lifetime",
            steps=[
                DeploymentStep(
                    "SCOPED",
                    lambda: revalidate_current_controlled_deployment_lease() or "ok",
                    lambda value: value,
                )
            ],
        )

        with self.assertRaises(ProductionControlError) as after:
            revalidate_current_controlled_deployment_lease()
        self.assertEqual(
            "CONTROLLED_DEPLOYMENT_REVALIDATION_OUTSIDE_ACTIVE_LEASE", after.exception.code
        )
        with self.assertRaises(TypeError):
            revalidate_current_controlled_deployment_lease("other-owner")  # type: ignore[call-arg]

    def test_w08_post_persist_revalidation_prevents_success_after_authority_drift(self) -> None:
        persisted: list[tuple] = []
        drift = self.repo / ".post-persist-authority-drift"

        def persist(evidence: tuple) -> None:
            persisted.append(evidence)
            drift.write_text("authority changed after persistence\n", encoding="utf-8")

        try:
            with self.assertRaises(DeploymentAuthorityLost) as lost:
                self._deploy(
                    deployment_id="post-persist-revalidation",
                    steps=[DeploymentStep("EFFECT", lambda: "effect", lambda value: value)],
                    persist_result=persist,
                )
            self.assertEqual(1, len(persisted))
            self.assertEqual(1, len(lost.exception.evidence))
            self.assertIsInstance(lost.exception.__cause__, ProductionControlError)
            self.assertEqual("SOURCE_AUTHORITY_DIRTY", lost.exception.__cause__.code)
        finally:
            drift.unlink(missing_ok=True)

    def test_w08_post_persist_revalidation_prevents_success_after_same_lease_revoke(self) -> None:
        persisted: list[tuple] = []

        def persist(evidence: tuple) -> None:
            persisted.append(evidence)
            current = self.store.get_global_production_writer_lease()
            self.store.force_revoke_global_production_writer(
                operation_key=self._key("test-post-persist-force-revoke"),
                reason="TEST_POST_PERSIST_SAME_LEASE_REVOKE",
                control_decision_ref="TEST/01B-C",
                expected_owner_id=current["owner_id"],
                expected_fencing_token=current["fencing_token"],
            )

        with self.assertRaises(DeploymentAuthorityLost) as lost:
            self._deploy(
                deployment_id="post-persist-same-lease-revoke",
                steps=[DeploymentStep("EFFECT", lambda: "effect", lambda value: value)],
                persist_result=persist,
            )
        self.assertEqual(1, len(persisted))
        self.assertEqual(1, len(lost.exception.evidence))
        self.assertIsInstance(lost.exception.__cause__, ProductionControlError)
        self.assertEqual("STALE_FENCING_TOKEN", lost.exception.__cause__.code)

    # W08_E / W08_G: W08 holder is the single current writer.
    def test_w08_holder_blocks_second_deployment_and_product_contender(self) -> None:
        lease = GlobalProductionControlLease(
            self.store,
            change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
            unit_id="exclusive",
            writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
            owner_session_role="TEST",
            operation_class="DEPLOY",
            target="GLOBAL_PRODUCTION",
            authority=self._authority(),
            start_heartbeat=False,
        )
        with lease:
            with self.assertRaises(StoreError) as deployment_busy:
                self._acquire("W08_CONTROLLED_PRODUCTION_DEPLOYMENT", "other-deployer")
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", deployment_busy.exception.code)
            with self.assertRaises(StoreError) as product_busy:
                self._acquire("W03", "product-w03")
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", product_busy.exception.code)

    # W08_H / W08_I: multiple bounded steps still consume one lease generation/result write.
    def test_w08_one_bounded_deployment_uses_one_generation_and_one_result(self) -> None:
        before = self.store.get_global_production_writer_lease()["fencing_token"]
        effects: list[str] = []
        readbacks: list[str] = []
        results: list[tuple] = []
        steps = [
            DeploymentStep(
                name,
                lambda name=name: effects.append(name) or name,
                lambda value: readbacks.append(value) or f"read:{value}",
            )
            for name in ("SOURCE_PROMOTION", "IDENTITY_PUBLICATION", "RUNTIME_RELOAD")
        ]
        evidence = self._deploy(steps=steps, persist_result=lambda value: results.append(value))
        after = self.store.get_global_production_writer_lease()
        self.assertEqual(before + 1, after["fencing_token"])
        self.assertEqual("FREE", after["state"])
        self.assertEqual(3, len(evidence))
        self.assertEqual(steps and [step.name for step in steps], effects)
        self.assertEqual(effects, readbacks)
        self.assertEqual(1, len(results))

    def test_w08_cross_writer_matrix_w01_w07_both_directions_14_of_14(self) -> None:
        blocked = 0
        for code in ("W01", "W02", "W03", "W04", "W05", "W06", "W07"):
            holder = self._acquire(code)
            try:
                with self.assertRaises(StoreError):
                    self._deploy()
                blocked += 1
            finally:
                self._release(holder["owner_id"], holder["fencing_token"])

            lease = GlobalProductionControlLease(
                self.store,
                change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                unit_id=f"matrix-{code}",
                writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
                owner_session_role="TEST",
                operation_class="DEPLOY",
                target="GLOBAL_PRODUCTION",
                authority=self._authority(),
                start_heartbeat=False,
            )
            with lease:
                with self.assertRaises(StoreError):
                    self._acquire(code, f"contender-{code}")
                blocked += 1
        self.assertEqual(14, blocked)


    def test_canonical_production_store_cannot_implicitly_bootstrap_or_migrate(self) -> None:
        canonical = self.root / "canonical-production.sqlite3"
        with patch("adcp.store.sqlite.CANONICAL_PRODUCTION_CONTROL_STORE", canonical):
            with self.assertRaises(StoreError) as blocked:
                ControlStore(canonical)
            self.assertEqual("CANONICAL_PRODUCTION_BOOTSTRAP_REQUIRED", blocked.exception.code)
            self.assertFalse(canonical.exists())
            with ControlStore(
                canonical,
                allow_canonical_production_bootstrap=True,
                global_writer_guard_required=False,
            ) as bootstrap_store:
                version = bootstrap_store.connection.execute(
                    "SELECT max(version) FROM schema_migration"
                ).fetchone()[0]
                self.assertEqual(SCHEMA_VERSION, version)

    def test_canonical_schema_mismatch_is_rejected_readonly_before_write_capable_connect(self) -> None:
        canonical = self.root / "canonical-schema5.sqlite3"
        connection = sqlite3.connect(canonical)
        connection.execute("CREATE TABLE schema_migration(version INTEGER NOT NULL)")
        connection.execute("INSERT INTO schema_migration(version) VALUES (5)")
        connection.commit()
        connection.close()
        before = hashlib.sha256(canonical.read_bytes()).hexdigest()
        with patch("adcp.store.sqlite.CANONICAL_PRODUCTION_CONTROL_STORE", canonical):
            with self.assertRaises(StoreError) as mismatch:
                ControlStore(canonical, migrate_schema=False, require_schema_version=SCHEMA_VERSION)
        self.assertEqual("CONTROL_STORE_SCHEMA_VERSION_MISMATCH", mismatch.exception.code)
        self.assertEqual(before, hashlib.sha256(canonical.read_bytes()).hexdigest())
        self.assertFalse(canonical.with_name(canonical.name + "-wal").exists())
        self.assertFalse(canonical.with_name(canonical.name + "-shm").exists())

    def test_control_source_authority_requires_exact_clean_git_head(self) -> None:
        tracked = self.repo / "authority.txt"
        tracked.write_text("authority\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "authority.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.invalid", "commit", "-qm", "authority"],
            check=True,
        )
        head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        assert_git_source_binding(self.repo, head)
        with self.assertRaises(ProductionControlError) as mismatch:
            assert_git_source_binding(self.repo, "0" * 40)
        self.assertEqual("SOURCE_AUTHORITY_HEAD_MISMATCH", mismatch.exception.code)
        tracked.write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(ProductionControlError) as dirty:
            assert_git_source_binding(self.repo, head)
        self.assertEqual("SOURCE_AUTHORITY_DIRTY", dirty.exception.code)

    def test_w08_body_exception_remains_primary_when_release_also_fails(self) -> None:
        lease = GlobalProductionControlLease(
            self.store,
            change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
            unit_id="primary-error",
            writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
            owner_session_role="TEST",
            operation_class="DEPLOY",
            target="GLOBAL_PRODUCTION",
            authority=self._authority(),
            start_heartbeat=False,
        )
        original_release = self.store.release_global_production_writer
        try:
            with self.assertRaisesRegex(ValueError, "body-primary"):
                with lease:
                    self.store.release_global_production_writer = lambda **kwargs: (_ for _ in ()).throw(
                        RuntimeError("release-secondary")
                    )
                    raise ValueError("body-primary")
        finally:
            self.store.release_global_production_writer = original_release
            current = self.store.get_global_production_writer_lease()
            if current["state"] == "HELD":
                original_release(
                    operation_key=self._key("cleanup-primary-error"),
                    owner_id=current["owner_id"],
                    fencing_token=current["fencing_token"],
                    control_decision_ref="TEST/CLEANUP",
                )

    # W09_A/B: primitive self-operations remain non-recursive even on a guarded store.
    def test_w09_self_primitives_acquire_assert_heartbeat_release_without_recursive_guard(self) -> None:
        row = self._acquire("W09_SELF_TEST", "self-owner")
        token = row["fencing_token"]
        self.assertEqual("self-owner", self.store.assert_current_global_writer("self-owner", token)["owner_id"])
        self.assertEqual(token, self.store.heartbeat_global_production_writer("self-owner", token)["fencing_token"])
        self._release("self-owner", token)
        self.assertEqual("FREE", self.store.get_global_production_writer_lease()["state"])

    # W09_C/D: explicit privileged revoke works without holder cooperation and permanently fences old generation.
    def test_w09_force_revoke_is_non_recursive_and_fences_old_generation(self) -> None:
        row = self._acquire("W04", "stale-owner")
        token = row["fencing_token"]
        revoked = self.store.force_revoke_global_production_writer(
            operation_key=self._key("force-revoke"),
            reason="OPERATOR_REVOKE",
            control_decision_ref="CONTROL/REVOKE",
            expected_owner_id="stale-owner",
            expected_fencing_token=token,
        )
        self.assertEqual("FREE", revoked["state"])
        self.assertEqual(token + 1, revoked["fencing_token"])
        with self.assertRaises(StoreError) as caught:
            self.store.assert_current_global_writer("stale-owner", token)
        self.assertIn(caught.exception.code, {"STALE_FENCING_TOKEN", "GLOBAL_PRODUCTION_WRITER_NOT_HELD"})
        successor = self._acquire("W02", "successor")
        self.assertGreater(successor["fencing_token"], token)
        self._release("successor", successor["fencing_token"])

    # W09_E: ordinary Production DCS write cannot bypass the guard and is blocked by Product holder.
    def test_w09_ordinary_control_mutation_requires_global_lease_and_product_holder_blocks_it(self) -> None:
        with self.assertRaises(StoreError) as no_guard:
            self.create("unguarded", "slice-unguarded")
        self.assertEqual("GLOBAL_PRODUCTION_WRITER_REQUIRED", no_guard.exception.code)
        holder = self._acquire("W05", "product-holder")
        mutations: list[str] = []
        try:
            with self.assertRaises(StoreError) as busy:
                run_ordinary_production_control_mutation(
                    self.store,
                    change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                    unit_id="control-op",
                    operation_class="CREATE_EXECUTION",
                    authority=self._authority(),
                    mutation=lambda: mutations.append("mutated"),
                    start_heartbeat=False,
                )
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", busy.exception.code)
            self.assertEqual([], mutations)
        finally:
            self._release("product-holder", holder["fencing_token"])

    # W09_F: ordinary control holder blocks Product writer contender; normal guarded mutation succeeds once.
    def test_w09_ordinary_control_holder_blocks_product_and_allows_guarded_store_write(self) -> None:
        def mutation():
            with self.assertRaises(StoreError) as busy:
                self._acquire("W07", "product-contender")
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", busy.exception.code)
            return self.create("guarded", "slice-guarded")

        row = run_ordinary_production_control_mutation(
            self.store,
            change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
            unit_id="guarded-control",
            operation_class="CREATE_EXECUTION",
            authority=self._authority(),
            mutation=mutation,
            start_heartbeat=False,
        )
        self.assertEqual("guarded", row["execution_id"])

    # W09_H / SC-06: state + audit event remain atomic under injected force-revoke failure.
    def test_w09_force_revoke_state_and_event_are_atomic_under_injected_failure(self) -> None:
        row = self._acquire("W06", "atomic-owner")
        token = row["fencing_token"]
        events_before = len(self.store.global_production_writer_events())

        def fail(stage: str) -> None:
            if stage == "after_event_insert":
                raise RuntimeError("injected")

        with self.assertRaises(RuntimeError):
            self.store.force_revoke_global_production_writer(
                operation_key=self._key("force-revoke-fault"),
                reason="FAULT_TEST",
                control_decision_ref="CONTROL/FAULT",
                expected_owner_id="atomic-owner",
                expected_fencing_token=token,
                _fault_injector=fail,
            )
        current = self.store.get_global_production_writer_lease()
        self.assertEqual("HELD", current["state"])
        self.assertEqual("atomic-owner", current["owner_id"])
        self.assertEqual(token, current["fencing_token"])
        self.assertEqual(events_before, len(self.store.global_production_writer_events()))
        self._release("atomic-owner", token)

    def test_w09_guard_reasserts_inside_write_transaction_after_authority_changes(self) -> None:
        row = self._acquire("W09", "old-control")
        token = row["fencing_token"]
        guard = self.store.ordinary_global_writer_authority("old-control", token)
        guard.__enter__()
        try:
            self.store.force_revoke_global_production_writer(
                operation_key=self._key("revoke-bound-control"),
                reason="FENCE_BOUND_SCOPE",
                control_decision_ref="CONTROL/FENCE",
                expected_owner_id="old-control",
                expected_fencing_token=token,
            )
            with self.assertRaises(StoreError):
                self.create("stale-control", "slice-stale")
        finally:
            guard.__exit__(None, None, None)

    def test_sc11_arbitrary_callback_and_noop_authority_are_rejected_before_mutation(self) -> None:
        for unsafe in (lambda: True, _UnsafeCallable(), object()):
            mutations: list[str] = []
            events_before = len(self.store.global_production_writer_events())
            with self.assertRaises(ProductionControlError) as blocked:
                run_ordinary_production_control_mutation(
                    self.store,
                    change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                    unit_id=f"unsafe-authority-{type(unsafe).__name__}",
                    operation_class="SC11_AUTHORITY_ATTACK",
                    authority=unsafe,  # type: ignore[arg-type]
                    mutation=lambda: mutations.append("mutated"),
                    start_heartbeat=False,
                )
            self.assertEqual("PRODUCTION_MUTATION_AUTHORITY_INVALID", blocked.exception.code)
            self.assertEqual([], mutations)
            self.assertEqual(events_before, len(self.store.global_production_writer_events()))

    def test_sc11_wrong_and_dirty_git_source_fail_closed_before_mutation(self) -> None:
        mutations: list[str] = []
        with self.assertRaises(ProductionControlError) as wrong:
            run_ordinary_production_control_mutation(
                self.store,
                change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                unit_id="wrong-git-source",
                operation_class="SC11_GIT_SOURCE",
                authority=self._authority(expected_head="0" * 40),
                mutation=lambda: mutations.append("wrong"),
                start_heartbeat=False,
            )
        self.assertEqual("SOURCE_AUTHORITY_HEAD_MISMATCH", wrong.exception.code)
        self.assertEqual([], mutations)

        (self.repo / ".sc11-authority-baseline").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(ProductionControlError) as dirty:
            run_ordinary_production_control_mutation(
                self.store,
                change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                unit_id="dirty-git-source",
                operation_class="SC11_GIT_SOURCE",
                authority=self._authority(),
                mutation=lambda: mutations.append("dirty"),
                start_heartbeat=False,
            )
        self.assertEqual("SOURCE_AUTHORITY_DIRTY", dirty.exception.code)
        self.assertEqual([], mutations)

    def test_sc11_thin_runtime_unknown_mismatch_stale_and_malformed_fail_closed(self) -> None:
        cases = (
            ("UNKNOWN", "RUNTIME_IDENTITY_UNKNOWN"),
            ("MISMATCH", "RUNTIME_IDENTITY_MISMATCH"),
            ("STALE", "RUNTIME_IDENTITY_STALE"),
            ("MALFORMED", "RUNTIME_IDENTITY_UNKNOWN"),
        )
        for label, code in cases:
            mutations: list[str] = []
            module = _thin_module(error_code=code)
            with patch.dict(sys.modules, {"adcp_global_writer_client": module}):
                with self.assertRaises(ProductionControlError) as blocked:
                    run_ordinary_production_control_mutation(
                        self.store,
                        change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                        unit_id=f"thin-{label.lower()}",
                        operation_class="SC11_THIN_RUNTIME",
                        authority=ThinRuntimeAuthority("runtime.json", "authorized.json"),
                        mutation=lambda: mutations.append(label),
                        start_heartbeat=False,
                    )
            self.assertEqual(code, blocked.exception.code)
            self.assertEqual([], mutations)

    def test_sc11_composite_requires_git_and_thin_and_current_match_reaches_guarded_write(self) -> None:
        match_module = _thin_module(result="MATCH")
        authority = CompositeProductionAuthority(
            (self._authority(), ThinRuntimeAuthority("runtime.json", "authorized.json"))
        )
        with patch.dict(sys.modules, {"adcp_global_writer_client": match_module}):
            row = run_ordinary_production_control_mutation(
                self.store,
                change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                unit_id="composite-current",
                operation_class="SC11_COMPOSITE",
                authority=authority,
                mutation=lambda: self.create("sc11-current", "slice-sc11-current"),
                start_heartbeat=False,
            )
        self.assertEqual("sc11-current", row["execution_id"])

        mutations: list[str] = []
        wrong_git = CompositeProductionAuthority(
            (self._authority(expected_head="0" * 40), ThinRuntimeAuthority("runtime.json", "authorized.json"))
        )
        with patch.dict(sys.modules, {"adcp_global_writer_client": match_module}):
            with self.assertRaises(ProductionControlError) as blocked_git:
                run_ordinary_production_control_mutation(
                    self.store,
                    change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                    unit_id="composite-git-mismatch",
                    operation_class="SC11_COMPOSITE",
                    authority=wrong_git,
                    mutation=lambda: mutations.append("git-mismatch"),
                    start_heartbeat=False,
                )
        self.assertEqual("SOURCE_AUTHORITY_HEAD_MISMATCH", blocked_git.exception.code)
        self.assertEqual([], mutations)

        mismatch_module = _thin_module(error_code="RUNTIME_IDENTITY_MISMATCH")
        with patch.dict(sys.modules, {"adcp_global_writer_client": mismatch_module}):
            with self.assertRaises(ProductionControlError) as blocked_thin:
                run_ordinary_production_control_mutation(
                    self.store,
                    change_id="GLOBAL-PRODUCTION-WRITER-LEASE-01B-C",
                    unit_id="composite-thin-mismatch",
                    operation_class="SC11_COMPOSITE",
                    authority=authority,
                    mutation=lambda: mutations.append("thin-mismatch"),
                    start_heartbeat=False,
                )
        self.assertEqual("RUNTIME_IDENTITY_MISMATCH", blocked_thin.exception.code)
        self.assertEqual([], mutations)

    def test_w09_no_direct_raw_write_transaction_remains_outside_canonical_store_boundary(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src" / "adcp"
        projection = (source_root / "projection.py").read_text(encoding="utf-8")
        self.assertNotIn('connection.execute("BEGIN IMMEDIATE")', projection)
        production_prep = (source_root / "production_prep.py").read_text(encoding="utf-8")
        self.assertIn("mode=ro&immutable=1", production_prep)


if __name__ == "__main__":
    unittest.main()
