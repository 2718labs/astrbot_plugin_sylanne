"""The host binds one graph-issued reply scope to one final-claim writer."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_runtime_reply_assembly_wrapper import _runtime
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.reverse_handoff import HostReverseGraphClaimServer
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.runtime_context import RuntimeHealth
from sylanne3.runtime_contracts import AuthorityContext


@pytest.mark.asyncio
@pytest.mark.parametrize("writer_fails", [False, True])
async def test_owned_reply_uses_scoped_graph_writer_and_releases_lease(
        monkeypatch, writer_fails):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        bundle = replace(bundle, ingress_clock=AdminIngressClockPolicy(
            "clock", 1.0, 1.0))
        policy = bundle.installation_policy
        scoped_lease = object()
        seen = []

        class Graph:
            def grant_owned_reply_dispatch_scope_v1(self, bootstrap, installed,
                                                    **identity):
                seen.append(("scope", installed, identity))
                assert installed is bundle
                assert identity == {
                    "ingress_operation_id": "ingress-original",
                    "handler_invocation_id": "handler:original"}
                scoped = AuthorityContext(
                    "holder", "d11", "scoped-capability", policy.namespace,
                    ("activity",), "expression", ("original-conversation",),
                    policy.root_grant.policy_ref, 1)
                return scoped, scoped_lease, object()

            def register_dispatch_final_claim_writer_v1(self, bootstrap,
                                                        *, route_port, issuer_id):
                seen.append(("writer", route_port.authority, issuer_id))
                if writer_fails:
                    raise RuntimeError("writer unavailable")
                return SimpleNamespace(issuer_id=issuer_id)

            def release_authority_lease(self, bootstrap, lease):
                assert lease is scoped_lease
                seen.append(("release",))

        graph = Graph()
        runtime = _runtime(bundle, graph)
        runtime._lock = asyncio.Lock()
        runtime._final_claim_authority = object()
        runtime._final_claim_lease = object()
        runtime._final_claim_writer = SimpleNamespace(issuer_id="issuer:paired")
        runtime.health = RuntimeHealth("ready")
        server = object.__new__(HostReverseGraphClaimServer)
        server.profile = SimpleNamespace(
            namespace=policy.authority_namespace,
            installation_id=runtime._v2_installation_grant.installation_id)
        candidates = object.__new__(SceneCandidateCatalog)

        class Route:
            def __init__(self, **kwargs):
                self.authority = kwargs["authority"]
                assert kwargs["lease"] is scoped_lease

        class Continuation:
            def __init__(self, **kwargs):
                seen.append(("continuation", kwargs["authority"],
                             kwargs["lease"], kwargs["claim_writer"]))

        class Driver:
            def __init__(self, worker, authority, lease, continuation):
                assert authority.audience == ("original-conversation",)
                assert lease is scoped_lease

            async def run_once(self, **identity):
                seen.append(("driver", identity))
                return SimpleNamespace(status="accepted")

        import sylanne3.host.installed_dispatch_route as route_module
        import sylanne3.host.private_reply_dispatch_driver as driver_module
        monkeypatch.setattr(route_module, "InstalledDispatchRoutePort", Route)
        monkeypatch.setattr(driver_module,
                            "InstalledPrivateReplyContinuationV1", Continuation)
        monkeypatch.setattr(driver_module, "PrivateReplyDispatchDriver", Driver)

        call = runtime.dispatch_owned_private_reply_v1(
            ingress_operation_id="ingress-original",
            handler_invocation_id="handler:original",
            server=server, host_context=object(), candidates=candidates)
        if writer_fails:
            with pytest.raises(RuntimeError, match="writer unavailable"):
                await call
            assert [item[0] for item in seen] == ["scope", "writer", "release"]
        else:
            result = await call
            assert result.status == "accepted"
            assert [item[0] for item in seen] == [
                "scope", "writer", "continuation", "driver", "release"]
            assert seen[1][1].audience == ("original-conversation",)
            assert seen[1][2] == "issuer:paired"
    finally:
        await host.asyncTearDown()
