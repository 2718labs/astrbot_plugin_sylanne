"""Original model accounting uses installed Authority ports and one graph call."""

import asyncio
import hashlib
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.authority_service.v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from sylanne3.authority_service.v2_accounting_wire import to_wire as accounting_to_wire
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from sylanne3.host.model_egress_executor import FrozenEncodingEgressResult
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.runtime_context import RuntimeContext
from sylanne3.contracts import canonical_json


class Worker:
    def __init__(self, graph):
        self.graph = graph
        self.calls = 0

    async def call(self, fn, *args):
        self.calls += 1
        return fn(self.graph, *args)


@pytest.mark.asyncio
async def test_observed_original_cost_uses_signed_quote_identity_and_unknown_holds(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, _anchor, _permit, _admission, _grant, _client = (
            fixture_values(host, request))
        namespace = host.bundle.installation_policy.namespace
        expected_quote = "ingress-q-" + hashlib.sha256(canonical_json([
            *namespace.as_tuple, intent.budget_reservation_operation_id,
        ]).encode()).hexdigest()[:40]

        class Graph:
            def commit_first_ingress_model_cost_v1(
                self, bootstrap, selected_namespace, original_intent,
                *, quote_id, quote_version,
            ):
                assert bootstrap is runtime._v2_bootstrap
                assert selected_namespace == namespace
                assert original_intent == intent
                assert (quote_id, quote_version) == (expected_quote, 1)
                return "committed"

        worker = Worker(Graph())
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = worker
        runtime._v2_bootstrap = object()
        runtime._v2_namespace = namespace
        runtime._v2_policy = SimpleNamespace(
            expected_authority_id=intent.authority_id,
            authority_namespace=intent.namespace)
        runtime._v2_cost_transport = object()
        assert await runtime.commit_first_ingress_model_cost_v1(
            FrozenEncodingEgressResult(intent, None)) is None
        assert worker.calls == 0
        terminal = SimpleNamespace(call_id=intent.call_id,
                                   request_digest=intent.request_digest)
        result = FrozenEncodingEgressResult(intent, terminal)
        assert await runtime.commit_first_ingress_model_cost_v1(result) == "committed"
        assert await runtime.commit_first_ingress_model_cost_v1(result) == "committed"
        assert worker.calls == 2
        assert host.requests == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_accounting_port_bridges_worker_thread_to_paired_client():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        intent, anchor, _permit, _admission, grant, client = (
            fixture_values(host, model_fixture.call_request()))
        request = AccountingMaintenanceRequestV1("cost-fence-1", intent, anchor)
        bundle = replace(host.bundle, tls_profile=SimpleNamespace(timeout_seconds=1.0))
        port = InstalledAccountingMaintenancePort(
            client=client, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop())
        observed = []

        async def begin(self, bundle, installed_grant, *, accounting_request):
            observed.append((bundle, installed_grant, accounting_request))
            return "grant"

        client.accounting_begin_v1 = MethodType(begin, client)
        assert await asyncio.to_thread(port.begin, request) == "grant"
        assert observed == [(bundle, grant, request)]
        with pytest.raises(RuntimeError, match="graph worker"):
            port.begin(request)
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_accounting_rpc_uses_typed_wire_and_exact_original_operation():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        intent, anchor, _permit, _admission, grant, _client = (
            fixture_values(host, model_fixture.call_request()))
        request = AccountingMaintenanceRequestV1("cost-fence-1", intent, anchor)
        permit = FencePermitV2(
            intent.authority_id, intent.namespace, intent.subject, "holder", 1,
            "accounting", request.operation_id, intent.fence_token,
            intent.fence_epoch, intent.fence_revision, anchor,
            command_digest="sha256:" + "d" * 64)
        accounting_grant = AccountingMaintenanceGrantV1(
            permit, intent.call_id, "a" * 64, intent.budget_reservation_digest,
            "b" * 64, "c" * 64)
        transport = object.__new__(MtlsAuthorityTransport)
        transport._model_identity = lambda *args: None
        observed = []

        async def content_rpc(*args, **kwargs):
            method, command = args[2:4]
            observed.append((method, command))
            if method == "accounting_begin_v1":
                return {"grant": accounting_to_wire(accounting_grant),
                        "channel_binding_sha256": "bound"}
            field = "valid" if method == "accounting_validate_v1" else "finished"
            return {field: True, "channel_binding_sha256": "bound"}

        transport._content_rpc = content_rpc
        for method in ("accounting_begin_v1", "accounting_validate_v1",
                       "accounting_finish_v1", "accounting_recover_finish_v1"):
            kwargs = {"namespace": intent.namespace, "holder": "holder",
                      "accounting_request": request}
            if method in {"accounting_validate_v1", "accounting_finish_v1"}:
                kwargs["accounting_grant"] = accounting_grant
            result = await getattr(transport, method)(object(), object(), grant,
                                                      **kwargs)
            assert result == (accounting_grant if method == "accounting_begin_v1"
                              else True)
        assert [method for method, _ in observed] == [
            "accounting_begin_v1", "accounting_validate_v1",
            "accounting_finish_v1", "accounting_recover_finish_v1"]
        assert all(command["request"] == accounting_to_wire(request)
                   for _, command in observed)
        assert [set(command) for _, command in observed] == [
            {"namespace", "request"}, {"namespace", "request", "grant"},
            {"namespace", "request", "grant"}, {"namespace", "request"}]
    finally:
        await host.asyncTearDown()
