"""The host keeps the graph-issued reply worker identity across egress reads."""

from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from sylanne3.host.installed_reply_model_driver import reply_model_operation_id_v1
from sylanne3.memory_types import source_key
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import InstallationGrantV2


class _Worker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, callback):
        return callback(self.graph)


class _Graph:
    def __init__(self, source_ref, audience):
        self.source_ref = source_ref
        self.audience = audience
        self.events = []

    def read_post_c02_attention_inputs_v1(self, *args):
        self.events.append("current_source")
        return (None, None, SimpleNamespace(source_refs=(self.source_ref,)),
                self.audience, None, None, None)

    def grant(self, *args, **kwargs):
        self.events.append(("grant", kwargs["operation_id"]))
        return object(), "capability"

    def acquire_post_c02_reply_model_job_v1(self, authority, lease, *args,
                                            **kwargs):
        self.events.append(("acquire", authority.worker_fence,
                            authority.audience, kwargs["lease_seconds"]))
        return SimpleNamespace(fence=7)

    def read_post_c02_reply_model_egress_preparation_v1(self, authority,
                                                         lease, *args):
        self.events.append(("draft", authority.worker_fence, args[:2]))
        return ("graph-issued",)

    def release_authority_lease(self, bootstrap, lease):
        self.events.append("release")


@pytest.mark.asyncio
async def test_post_c02_acquire_uses_one_original_worker_and_releases():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        namespace = bundle.installation_policy.namespace
        source_ref = source_key(*namespace.as_tuple, "source-1").token
        graph = _Graph(source_ref, "owner")
        runtime = object.__new__(RuntimeContext)
        runtime._worker = _Worker(graph)
        runtime._v2_bootstrap = object()
        runtime._v2_port = SimpleNamespace(current_anchor=lambda **_:
                                           SimpleNamespace(activation_generation=1))
        runtime._v2_namespace_provisioned = True
        runtime._v2_model_bundle = bundle
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_installation_grant = InstallationGrantV2(
            "authority", "mtls:sha256:" + "a" * 64, "holder", "install",
            "a" * 64, "policy", "v2", "b" * 64)

        async with runtime.acquired_post_c02_reply_model_v1(
                c02_operation_id="c02-1", source_ref=source_ref) as acquired:
            assert acquired is not None
            assert acquired.authority.worker_fence == 7
            assert await runtime.read_post_c02_reply_model_egress_v1(
                acquired) == ("graph-issued",)
            assert "release" not in graph.events
        assert graph.events == [
            "current_source",
            ("grant", reply_model_operation_id_v1("c02-1", source_ref)),
            ("acquire", None, ("owner",), 121),
            ("draft", 7, ("c02-1", source_ref)),
            "release",
        ]

        graph.audience = "other"
        graph.events.clear()
        async with runtime.acquired_post_c02_reply_model_v1(
                c02_operation_id="c02-1", source_ref=source_ref) as acquired:
            assert acquired is None
        assert graph.events == ["current_source"]
    finally:
        await host.asyncTearDown()
