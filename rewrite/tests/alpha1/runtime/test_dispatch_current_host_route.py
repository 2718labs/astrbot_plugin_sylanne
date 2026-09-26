"""Host route proof uses live AstrBot reads and remains separate from admission."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace
import time

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.dispatch_current_route import read_current_dispatch_host_route
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime.dispatch_current_segment import read_current_dispatch_segment

from test_dispatch_admission import _issuer_case


def _case(tmp_path):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True, astrbot_route=True,
    )
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading,
    )
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            frozen = read_current_dispatch_segment(
                store._db, authority.namespace, "admission:one",
                now_utc=time.time(),
            )
        finally:
            store._db.execute("ROLLBACK")
    return store, coordinator, authority, lease, issuer.request, frozen


def _host(*, login_id="bot-1", conversation_id="conversation-1",
          selected_persona="persona"):
    class Adapter:
        def meta(self):
            return SimpleNamespace(id="platform-1", name="aiocqhttp")

    adapter = Adapter()

    async def call_action(action, *, self_id):
        assert action == "get_login_info" and self_id == "bot-1"
        return {"user_id": login_id}

    async def current(_umo):
        return conversation_id

    async def conversation(_umo, _conversation_id, *, create_if_not_exists):
        assert create_if_not_exists is False
        return SimpleNamespace(persona_id="persona")

    async def selected(**_kwargs):
        return (selected_persona,)

    adapter.bot = SimpleNamespace(call_action=call_action)
    context = SimpleNamespace(
        platform_manager=SimpleNamespace(platform_insts=[adapter]),
        get_platform_inst=lambda _platform_id: adapter,
        conversation_manager=SimpleNamespace(
            get_curr_conversation_id=current, get_conversation=conversation,
        ),
        persona_manager=SimpleNamespace(resolve_selected_persona=selected),
        get_config=lambda _umo: {},
    )
    return context, Adapter


def test_live_host_route_matches_frozen_graph_without_sending(tmp_path, monkeypatch):
    store, coordinator, authority, lease, request, frozen = _case(tmp_path)
    try:
        context, adapter_type = _host()
        monkeypatch.setattr("sylanne3.host.current_scene.AiocqhttpAdapter", adapter_type)
        result = asyncio.run(read_current_dispatch_host_route(
            context, coordinator, authority, lease, request, frozen,
        ))
        assert result.status == "verified"
        assert result.route_digest == frozen.route_digest
        assert result.graph_epoch == frozen.graph_epoch
        assert not hasattr(result, "payload")
    finally:
        store.close()


@pytest.mark.parametrize("change", ("login", "conversation", "persona", "digest"))
def test_live_host_route_holds_on_changed_binding(tmp_path, monkeypatch, change):
    store, coordinator, authority, lease, request, frozen = _case(tmp_path)
    try:
        context, adapter_type = _host(
            login_id="other" if change == "login" else "bot-1",
            conversation_id="other" if change == "conversation" else "conversation-1",
            selected_persona="other" if change == "persona" else "persona",
        )
        monkeypatch.setattr("sylanne3.host.current_scene.AiocqhttpAdapter", adapter_type)
        if change == "digest":
            frozen = replace(frozen, route_digest="0" * 64)
        result = asyncio.run(read_current_dispatch_host_route(
            context, coordinator, authority, lease, request, frozen,
        ))
        assert result.status == "hold"
        assert result.route_digest is None
    finally:
        store.close()
