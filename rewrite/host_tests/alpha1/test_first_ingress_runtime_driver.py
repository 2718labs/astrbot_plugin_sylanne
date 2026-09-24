"""The host schedules only the original committed D11 encoding job."""

from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_first_ingress_encoding_egress import frozen_case
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_context import RuntimeContext


class Worker:
    def __init__(self, graph):
        self.graph = graph
        self.calls = 0

    async def call(self, fn, *args):
        self.calls += 1
        return fn(self.graph, *args)


@pytest.mark.asyncio
async def test_committed_ingress_acquires_original_job_then_reads_preparation(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        _intent, _anchor, _permit, _admission, grant, authority = fixture_values(
            host, request)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        seen = []
        terminal = object()

        async def execute(self, *, binding, draft, expected_anchor):
            seen.append((binding, draft, expected_anchor))
            return terminal

        executor.execute_frozen_encoding_once = MethodType(execute, executor)
        source_ref = "a" * 64
        envelope = HostIngressEnvelope(
            bundle.installation_policy.namespace, "platform", "owner", "sender",
            "message", "text", None, 1.0, "private",
            SourceLineage(source_ref, "reported", "platform",
                          "external_report", "reported_claim"),
        )
        _, _, ingress_op, job_id, _, _ = ingress_ids(source_ref)
        receipt = IngressReceipt("accepted", ingress_op)

        class Graph:
            def grant(self, _bootstrap, **kwargs):
                assert kwargs["actor"] == grant.subject
                assert kwargs["issuer_domain"] == "d11"
                assert kwargs["domains"] == ("d11",)
                assert kwargs["operation_id"].startswith("job-acquire-")
                self.acquire_id = kwargs["operation_id"]
                self.lease = object()
                return self.lease, "capability"

            def release_authority_lease(self, _bootstrap, lease):
                assert lease is self.lease
                self.releases = getattr(self, "releases", 0) + 1

            def acquire_first_ingress_encoding_job_v2(
                self, auth, lease, acquired_job, acquire_id, *, lease_seconds,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert auth.actor == grant.subject and auth.worker_fence is None
                assert 120 < lease_seconds <= 420
                if getattr(self, "fail_acquire", False):
                    raise RuntimeError("original acquire outcome unknown")
                return SimpleNamespace(fence=1)

            def read_first_ingress_model_egress_preparation_v2(
                self, auth, lease, acquired_job, acquire_id,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert auth.worker_fence == 1
                return binding, draft, anchor

        graph = Graph()
        worker = Worker(graph)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = worker
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_port = SimpleNamespace(current_anchor=lambda **_: anchor)
        runtime._v2_bootstrap = object()
        runtime._v2_installation_grant = grant
        runtime._v2_model_bundle = bundle
        runtime._v2_namespace = envelope.namespace
        runtime._v2_namespace_provisioned = True

        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, receipt, executor=executor) is terminal
        assert seen == [(binding, draft, anchor)]
        assert worker.calls == 3 and graph.releases == 1
        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, IngressReceipt("duplicate", ingress_op),
            executor=executor) is None
        assert worker.calls == 3
        first_acquire_id = graph.acquire_id
        graph.fail_acquire = True
        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, receipt, executor=executor) is None
        assert graph.acquire_id == first_acquire_id
        assert seen == [(binding, draft, anchor)]
        assert graph.releases == 2
    finally:
        await host.asyncTearDown()
