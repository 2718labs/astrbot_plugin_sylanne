"""Installed V2 Authority port tests with a controlled authenticated channel."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import time

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.authority_service.v2_contract import PlatformObservationV2
from sylanne3.authority_service.v2_execution_bridge import (
    CurrentEffectReadV2, handoff_start_digest_v2,
)
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.current_dispatch_handoff_port import InstalledCurrentDispatchHandoffPort
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2

from test_astrbot_v2_sender import _decision
from test_dispatch_current_host_route import _case
from test_dispatch_final_claim_v2 import _chain
from test_installed_dispatch_route import _installation


def test_port_requires_installed_exact_rpc_and_paired_identity(tmp_path, monkeypatch):
    store, _, authority, _, _, _ = _case(tmp_path)
    try:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(store._db, authority.namespace)
            finally:
                store._db.execute("ROLLBACK")
        policy, grant = _installation(authority.namespace)
        policy = replace(policy, expected_authority_id="authority:test")
        grant = replace(grant, authority_id="authority:test")
        start = _decision(binding, claimed)._start

        class PairedFence:
            def __init__(self):
                self.installation_grant = grant

            def execution_read_current_dispatch_handoff(self, **kwargs):
                assert kwargs["namespace"] == authority.namespace
                assert kwargs["authority_namespace"] == start.namespace
                assert kwargs["claimed_receipt"] == claimed
                anchor = start.permit.pinned_anchor
                effect = CurrentEffectReadV2(
                    start.permit.authority_id, start.namespace, start.effect_id,
                    start.permit.generation, "unresolved", anchor.execution_seq,
                    anchor.execution_digest, anchor.execution_seq,
                    "append:claimed", anchor.execution_digest,
                    claimed.pending.mutation_id)
                return start.permit, anchor, effect

            def read_ingress_clock(self, clock_policy):
                instant = time.monotonic()
                sample = IngressClockSampleV2(
                    grant.authority_id, grant.installation_id,
                    clock_policy.source_id, time.time(), instant,
                    "epoch:test", 0.1)
                return VerifiedIngressClockV2(
                    sample, instant - 0.01, instant, time.time() + 0.2)

            def execution_observe_v2(self, **kwargs):
                raise AssertionError("observation must not be submitted by a read")

        monkeypatch.setattr(
            "sylanne3.host.current_dispatch_handoff_port.V2FencePort", PairedFence)
        fence = PairedFence()
        port = InstalledCurrentDispatchHandoffPort(
            fence_port=fence, policy=policy, grant=grant,
            claimed_receipt=claimed)
        current = port.read_current_dispatch_handoff(start, claimed)
        assert current.permit == start.permit
        assert current.anchor == start.permit.pinned_anchor
        assert current.effect.state == "unresolved"
        clock_policy = AdminIngressClockPolicy("clock:test", 0.2, 2.0)
        assert port.read_ingress_clock(clock_policy).sample.installation_id == grant.installation_id
        observation = PlatformObservationV2(
            binding, start.handoff_id, handoff_start_digest_v2(start),
            binding.origin.adapter_ref, binding.origin.account_ref,
            binding.origin.destination_ref, "observation:test", None, None,
            "astrbot:onebot:call_action", "unknown",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            clock_policy.source_id)
        with pytest.raises(RuntimeError, match="observation differs"):
            asyncio.run(port.record_observation(
                start, replace(observation, handoff_id="handoff:other")))
        with pytest.raises(RuntimeError, match="identity differs"):
            port.read_current_dispatch_handoff(replace(start, replay=True), claimed)
        with pytest.raises(ValueError, match="identity differs"):
            InstalledCurrentDispatchHandoffPort(
                fence_port=fence, policy=policy,
                grant=replace(grant, installation_id="wrong"),
                claimed_receipt=claimed)

        class MissingRead(PairedFence):
            execution_read_current_dispatch_handoff = None

        monkeypatch.setattr(
            "sylanne3.host.current_dispatch_handoff_port.V2FencePort", MissingRead)
        with pytest.raises(ValueError, match="unavailable"):
            InstalledCurrentDispatchHandoffPort(
                fence_port=MissingRead(), policy=policy, grant=grant,
                claimed_receipt=claimed)
    finally:
        store.close()
