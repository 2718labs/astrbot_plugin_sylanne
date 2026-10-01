"""Host GraphWorker wiring only; fake graph does not admit or dispatch text."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_installed_reply_expression_bridge import _case
from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminPrivateReplyDispatchPolicy,
)
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import InstallationGrantV2


class _Worker:
    def __init__(self, graph):
        self.graph = graph
        self.calls = 0

    async def call(self, callback):
        self.calls += 1
        return callback(self.graph)


class _Graph:
    def __init__(self, receipt, *, fail=False):
        self.receipt = receipt
        self.fail = fail
        self.grant_args = None
        self.assembly = None
        self.released = 0
        self.lease = object()

    def grant(self, bootstrap, **kwargs):
        self.grant_args = (bootstrap, kwargs)
        return self.lease, "capability"

    def assemble_post_c02_reply_v2(self, authority, lease, progress, bundle,
                                   **kwargs):
        self.assembly = (authority, lease, progress, bundle, kwargs)
        if self.fail:
            raise RuntimeError("assembly remains HOLD")
        return self.receipt

    def release_authority_lease(self, bootstrap, lease):
        assert lease is self.lease
        self.released += 1


def _runtime(bundle, graph):
    policy = bundle.installation_policy
    runtime = object.__new__(RuntimeContext)
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = object()
    runtime._v2_port = SimpleNamespace(current_anchor=lambda **_: SimpleNamespace(
        activation_generation=1))
    runtime._v2_namespace_provisioned = True
    runtime._v2_model_bundle = bundle
    runtime._v2_policy = policy
    runtime._v2_installation_grant = InstallationGrantV2(
        policy.expected_authority_id, "installed-subject", "holder",
        policy.installation_id, "a" * 64, "policy", "v2", "b" * 64)
    return runtime


@pytest.mark.asyncio
async def test_wrapper_uses_existing_installed_expression_lease_and_releases():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        bundle = replace(bundle, private_reply_dispatch=AdminPrivateReplyDispatchPolicy(
            30.0, {"output_tokens": 1}, "k03-snapshot", "k03-resource", 200, 15.0))
        queued, progress, _, _ = _case(bundle)
        prep = progress.run.preparation
        operation_id = post_c02_reply_operation_id(
            prep.c02_receipt.operation_id, prep.source.source_ref)
        receipt = replace(prep.c02_receipt, operation_id=operation_id)
        graph = _Graph(receipt)
        runtime = _runtime(bundle, graph)
        result = await runtime.assemble_post_c02_reply_v2(
            progress, handler_invocation_id="handler:one",
            handler_deadline_utc=100.0)
        assert result == receipt and runtime._worker.calls == 1
        assert graph.grant_args[1]["domains"] == ("d08", "d09", "d11")
        assert graph.grant_args[1]["operation_id"] == operation_id
        authority, lease, sent_progress, sent_bundle, kwargs = graph.assembly
        assert authority.owner_scope == ("activity",)
        assert lease is graph.lease and sent_progress is progress
        assert sent_bundle is bundle
        assert authority.purpose == "expression"
        assert authority.audience == prep.envelope.authority.audience
        assert kwargs == {"handler_invocation_id": "handler:one",
                          "handler_deadline_utc": 100.0}
        assert graph.released == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_missing_policy_or_cost_holds_and_failed_graph_releases():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        queued, progress, _, _ = _case(bundle)
        graph = _Graph(None, fail=True)
        runtime = _runtime(bundle, graph)
        assert await runtime.assemble_post_c02_reply_v2(
            progress, handler_invocation_id="handler:one",
            handler_deadline_utc=100.0) is None
        assert runtime._worker.calls == 0
        runtime._v2_model_bundle = replace(
            bundle, private_reply_dispatch=AdminPrivateReplyDispatchPolicy(
                30.0, {"output_tokens": 1}, "k03-snapshot", "k03-resource", 200, 15.0))
        assert await runtime.assemble_post_c02_reply_v2(
            replace(progress, cost=None), handler_invocation_id="handler:one",
            handler_deadline_utc=100.0) is None
        assert runtime._worker.calls == 0
        assert await runtime.assemble_post_c02_reply_v2(
            progress, handler_invocation_id="handler:one",
            handler_deadline_utc=100.0) is None
        assert runtime._worker.calls == 1 and graph.released == 1
    finally:
        await host.asyncTearDown()
