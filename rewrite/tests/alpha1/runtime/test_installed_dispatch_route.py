"""The installed route port reads current graph and AstrBot facts, never sends."""

import asyncio
from dataclasses import replace
import json
import time

from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import InstallationGrantV2
from sylanne3.runtime_contracts import canonical_digest

from test_dispatch_current_host_route import _case, _host


def _installation(namespace):
    lease = BudgetLease("root", None, *namespace.as_tuple, "USD",
                        {"cpu_ms": 200}, {}, {}, {}, 1, "active")
    budget = BudgetLeaseGrant("root-grant", 1, *namespace.as_tuple,
                              "root", "USD", {"cpu_ms": 100},
                              ("dispatch",), time.time() + 3600, "policy")
    policy = AdminInstallationPolicy(
        namespace, "opaque:persona", "installation", "a" * 64,
        "administrator", "authority", "b" * 64,
        "scheme", "operator", "policy", lease, budget)
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher", "2", "c" * 64)
    return policy, grant


def test_installed_route_requires_observation_and_live_host(tmp_path, monkeypatch):
    store, coordinator, authority, lease, request, frozen = _case(tmp_path)
    try:
        context, adapter_type = _host()
        monkeypatch.setattr("sylanne3.host.current_scene.AiocqhttpAdapter", adapter_type)
        policy, grant = _installation(authority.namespace)
        catalog = SceneCandidateCatalog()

        async def run():
            port = InstalledDispatchRoutePort(
                context=context, host_loop=asyncio.get_running_loop(),
                candidates=catalog, coordinator=coordinator,
                authority=authority, lease=lease, policy=policy, grant=grant)
            absent = await asyncio.to_thread(port.read, request, frozen)
            assert absent.status == "hold"
            catalog.observe(HostIngressEnvelope(
                authority.namespace,
                '["platform-1","aiocqhttp","bot-1"]',
                '["platform-1:FriendMessage:123456","conversation-1"]',
                '["platform-1","user-1"]', "message-1", "test", 1.0, 2.0,
                "private", SourceLineage("a" * 64, "reported", "onebot",
                                         "external_report", "reported_claim")))
            good = await asyncio.to_thread(port.read, request, frozen)
            assert good.status == "verified_route"
            assert good.route_digest == frozen.route_digest
            assert good.missing_guards == ("current_owner_authorization",)
            assert not hasattr(good, "payload")
            context.conversation_manager.get_curr_conversation_id = (
                lambda _umo: asyncio.sleep(0, result="other"))
            changed = await asyncio.to_thread(port.read, request, frozen)
            assert changed.status == "hold"
            assert changed.route_digest is None
            mismatch = await asyncio.to_thread(
                port.read, request, replace(frozen, route_digest="0" * 64))
            assert mismatch.status == "hold"

        asyncio.run(run())
    finally:
        store.close()


def test_p2_live_scene_only_never_reads_graph_and_holds_changed_route(
    tmp_path, monkeypatch,
):
    store, coordinator, authority, lease, request, frozen = _case(tmp_path)
    try:
        context, adapter_type = _host()
        monkeypatch.setattr("sylanne3.host.current_scene.AiocqhttpAdapter", adapter_type)
        policy, grant = _installation(authority.namespace)
        catalog = SceneCandidateCatalog()
        segment = coordinator.get_dispatch_text_segment(authority, lease, request)
        account_ref = json.dumps(
            [segment.platform_id, segment.platform_name, segment.self_id],
            ensure_ascii=True, separators=(",", ":"))
        destination_ref = json.dumps(
            [segment.umo, segment.conversation_id],
            ensure_ascii=True, separators=(",", ":"))
        scene_ref = segment.scene_ref
        digest = canonical_digest({
            "account_ref": account_ref, "destination_ref": destination_ref,
            "scene_ref": scene_ref})

        async def run():
            port = InstalledDispatchRoutePort(
                context=context, host_loop=asyncio.get_running_loop(),
                candidates=catalog, coordinator=coordinator,
                authority=authority, lease=lease, policy=policy, grant=grant)
            catalog.observe(HostIngressEnvelope(
                authority.namespace, account_ref, destination_ref,
                '["platform-1","user-1"]', "message-1", "test", 1.0, 2.0,
                "private", SourceLineage("a" * 64, "reported", "onebot",
                                         "external_report", "reported_claim")))
            def forbidden(*_args, **_kwargs):
                raise AssertionError("P2 host scene read must not enter GraphCoordinator")
            monkeypatch.setattr(coordinator, "get_dispatch_text_segment", forbidden)
            monkeypatch.setattr(coordinator, "get_dispatch_admission", forbidden)
            kwargs = dict(namespace=authority.namespace, account_ref=account_ref,
                          destination_ref=destination_ref, scene_ref=scene_ref,
                          route_digest=digest)
            current = await asyncio.to_thread(port.read_live_host_scene_only, **kwargs)
            assert current.status == "verified_route"
            assert current.route_digest == frozen.route_digest
            assert current.graph_epoch is None
            assert current.current_scene.scene_ref == scene_ref
            wrong_digest = await asyncio.to_thread(
                port.read_live_host_scene_only, **(kwargs | {"route_digest": "0" * 64}))
            assert wrong_digest.status == "hold"
            context.conversation_manager.get_curr_conversation_id = (
                lambda _umo: asyncio.sleep(0, result="other"))
            changed = await asyncio.to_thread(port.read_live_host_scene_only, **kwargs)
            assert changed.status == "hold"
            assert changed.current_scene is None

        asyncio.run(run())
    finally:
        store.close()
