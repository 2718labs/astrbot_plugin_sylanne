"""Controlled OneBot send core; these tests do not establish a live graph claim."""

import asyncio
from dataclasses import asdict, replace
from types import SimpleNamespace
import time

import pytest

from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    canonical_digest,
)
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2, HandoffStartV2
from sylanne3.dispatch_runtime import DispatchBlocked
from sylanne3.host.astrbot_dispatch import (
    AstrBotV2TextSender, CurrentDispatchHandoffReadV1, GraphTextPayloadResolver,
)
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.reverse_handoff import HandoffDecisionWindow
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime_contracts import canonical_digest as graph_digest

from test_dispatch_current_host_route import _case, _host
from test_dispatch_final_claim_v2 import _chain


def _decision(binding, claimed, *, replay=False):
    permit = replace(claimed.pending.permit,
                     revision=claimed.updated_revision,
                     pinned_anchor=claimed.after_anchor)
    context = DispatchHandoffContextV1(
        permit, canonical_digest(claimed), canonical_digest(binding),
        "handoff:one")
    graph = DispatchGraphClaimReceiptV1(
        canonical_digest(context), binding.graph_namespace,
        binding.graph_incarnation, "claim:version", 1000, 0, 0,
        "claim:one", "sha256:" + "a" * 64, "issuer:test")
    start = HandoffStartV2(
        "handoff:one", binding.operation_id, binding.origin.effect_id,
        binding.namespace, canonical_digest(claimed),
        canonical_digest(binding), graph.graph_claim_ref, permit,
        replay=replay, graph_claim_receipt=graph)
    return HandoffDecisionWindow(start, SimpleNamespace(task=object(), receipt=graph))


def _candidate(catalog, namespace):
    catalog.observe(HostIngressEnvelope(
        namespace, '["platform-1","aiocqhttp","bot-1"]',
        '["platform-1:FriendMessage:123456","conversation-1"]',
        '["platform-1","user-1"]', "message-1", "test", 1.0, 2.0,
        "private", SourceLineage("a" * 64, "reported", "onebot",
                                 "external_report", "reported_claim")))


@pytest.mark.parametrize("response,outcome", [
    ({"message_id": 42}, "accepted"),
    ({}, "unknown"),
    (RuntimeError("transport lost"), "unknown"),
    ("cancel", "unknown"),
])
def test_fresh_onebot_ack_and_unknown_never_replay(
        tmp_path, monkeypatch, response, outcome):
    store, coordinator, authority, lease, request, _ = _case(tmp_path)
    try:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(store._db, authority.namespace)
            finally:
                store._db.execute("ROLLBACK")
        context, adapter_type = _host()
        calls = []
        started = asyncio.Event()
        terminal = asyncio.Event()

        async def action(name, **kwargs):
            if name == "get_login_info":
                return {"user_id": "bot-1"}
            calls.append((name, kwargs))
            if response == "cancel":
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    terminal.set()
            if isinstance(response, Exception):
                raise response
            return response

        context.platform_manager.platform_insts[0].bot.call_action = action
        monkeypatch.setattr("sylanne3.host.astrbot_dispatch.Context", SimpleNamespace)
        monkeypatch.setattr("sylanne3.host.astrbot_dispatch.AiocqhttpAdapter", adapter_type)
        monkeypatch.setattr("sylanne3.host.current_scene.AiocqhttpAdapter", adapter_type)
        catalog = SceneCandidateCatalog()
        _candidate(catalog, authority.namespace)
        recorded = []
        policy = AdminIngressClockPolicy(binding.clock_policy_ref, 0.2, 2.0)
        binding = replace(binding, clock_policy_digest="sha256:" + graph_digest(
            asdict(policy)))
        claimed = replace(claimed, pending=replace(claimed.pending, binding=binding))

        class CurrentAuthority:
            deny = False

            def read_current_dispatch_handoff(self, start, _claimed_receipt):
                if self.deny:
                    raise RuntimeError("current P2 unavailable")
                anchor = start.permit.pinned_anchor
                effect = CurrentEffectReadV2(
                    start.permit.authority_id, start.namespace, start.effect_id,
                    start.permit.generation, "unresolved", anchor.execution_seq,
                    anchor.execution_digest, anchor.execution_seq,
                    "append:claimed", anchor.execution_digest,
                    _claimed_receipt.pending.mutation_id)
                return CurrentDispatchHandoffReadV1(start.permit, anchor, effect)

            def read_ingress_clock(self, _policy):
                monotonic = time.monotonic()
                sample = IngressClockSampleV2(
                    "authority:test", "installation:test", policy.source_id,
                    time.time(), monotonic, "epoch:test", 0.1)
                return VerifiedIngressClockV2(
                    sample, monotonic - 0.01, monotonic,
                    time.time() + 0.2)

        async def record(start, observation):
            recorded.append((start, observation))

        current_authority = CurrentAuthority()
        sender = AstrBotV2TextSender(
            context=context, candidates=catalog,
            resolver=GraphTextPayloadResolver(coordinator, authority, lease),
            authority=current_authority, clock_policy=policy,
            record_observation=record)
        with pytest.raises(RuntimeError, match="no fresh handoff"):
            asyncio.run(sender.send(
                decision=_decision(binding, claimed, replay=True), binding=binding,
                claimed_receipt=claimed, request=request))
        assert calls == []
        current_authority.deny = True
        with pytest.raises(RuntimeError, match="current P2 unavailable"):
            asyncio.run(sender.send(
                decision=_decision(binding, claimed), binding=binding,
                claimed_receipt=claimed, request=request))
        current_authority.deny = False
        assert calls == []
        expired = replace(binding, utc_deadline="2020-01-01T00:00:00Z")
        expired_claim = replace(
            claimed, pending=replace(claimed.pending, binding=expired))
        with pytest.raises(DispatchBlocked, match="deadline expired"):
            asyncio.run(sender.send(
                decision=_decision(expired, expired_claim), binding=expired,
                claimed_receipt=expired_claim, request=request))
        assert calls == []
        decision = _decision(binding, claimed)
        async def run_send():
            task = asyncio.create_task(sender.send(
                decision=decision, binding=binding, claimed_receipt=claimed,
                request=request))
            if response == "cancel":
                await started.wait()
                task.cancel()
            return await task

        observation = asyncio.run(run_send())
        assert observation.outcome == outcome
        assert observation.platform_message_id == ("42" if outcome == "accepted" else None)
        assert calls[0][0] == "send_private_msg"
        assert calls[0][1]["self_id"] == "bot-1"
        assert calls[0][1]["user_id"] == 123456
        assert len(calls) == 1
        if response == "cancel":
            assert terminal.is_set()  # No sender-owned OneBot coroutine survives.
        assert recorded == [(decision._start, observation)]
        with pytest.raises(RuntimeError, match="no fresh handoff"):
            asyncio.run(sender.send(decision=decision, binding=binding,
                                    claimed_receipt=claimed, request=request))
        assert len(calls) == 1
    finally:
        store.close()
