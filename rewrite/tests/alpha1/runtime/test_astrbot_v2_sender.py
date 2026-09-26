"""Controlled OneBot send core; these tests do not establish a live graph claim."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    canonical_digest,
)
from sylanne3.authority_service.v2_execution_bridge import HandoffStartV2
from sylanne3.host.astrbot_dispatch import (
    AstrBotV2TextSender, GraphTextPayloadResolver,
)
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.reverse_handoff import HandoffDecisionWindow
from sylanne3.host.scene_candidates import SceneCandidateCatalog

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

        async def action(name, **kwargs):
            if name == "get_login_info":
                return {"user_id": "bot-1"}
            calls.append((name, kwargs))
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

        async def record(start, observation):
            recorded.append((start, observation))

        sender = AstrBotV2TextSender(
            context=context, candidates=catalog,
            resolver=GraphTextPayloadResolver(coordinator, authority, lease),
            record_observation=record)
        with pytest.raises(RuntimeError, match="no fresh handoff"):
            asyncio.run(sender.send(
                decision=_decision(binding, claimed, replay=True), binding=binding,
                request=request))
        assert calls == []
        decision = _decision(binding, claimed)
        observation = asyncio.run(sender.send(
            decision=decision, binding=binding, request=request))
        assert observation.outcome == outcome
        assert observation.platform_message_id == ("42" if outcome == "accepted" else None)
        assert calls[0][0] == "send_private_msg"
        assert calls[0][1]["self_id"] == "bot-1"
        assert calls[0][1]["user_id"] == 123456
        assert len(calls) == 1
        assert recorded == [(decision._start, observation)]
        with pytest.raises(RuntimeError, match="no fresh handoff"):
            asyncio.run(sender.send(decision=decision, binding=binding,
                                    request=request))
        assert len(calls) == 1
    finally:
        store.close()
