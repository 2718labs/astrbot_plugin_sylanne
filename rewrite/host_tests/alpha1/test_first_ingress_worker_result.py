"""The installed worker reads only the completed original Authority call."""

from dataclasses import replace
from types import MethodType

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_first_ingress_encoding_egress import frozen_case
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressObservationV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
    to_wire as worker_result_to_wire,
)
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


@pytest.mark.asyncio
async def test_installed_worker_read_and_unknown_response_close_original_attempt(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        old, _, _, _, grant, client = fixture_values(host, request)
        executor = HostModelEgressExecutor(
            authority=client, bundle=bundle, grant=grant, adapter=adapter)
        intent = replace(old, **{name: getattr(draft, name)
                               for name in draft.__dataclass_fields__},
                         anchor_digest=canonical_digest(anchor))
        permit = FencePermitV2(
            intent.authority_id, intent.namespace, intent.subject, "holder", 1,
            "model_egress", intent.operation_id, intent.fence_token,
            intent.fence_epoch, intent.fence_revision, anchor)
        admission = ModelAdmissionV2(
            "a" * 64, intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            intent.provider_config_digest, grant.installation_id, "b" * 64,
            "default", "c" * 64, adapter.host_incarnation)
        observation = ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", canonical_serialize({"text": "encoded"}),
            (("output_tokens", 2),), (), "provider-call-1")
        terminal = ModelTerminalReceiptV2(
            admission.admission_id, intent.call_id, intent.request_digest,
            "d" * 64, observation.digest, "sha256:" + "e" * 64,
            grant.installation_id, admission.host_incarnation)
        record = ModelEgressRecoveryV1(
            intent, "observed", observation.digest,
            observation.usage, observation.cost)
        read_request = WorkerModelResultReadRequestV1(
            intent.authority_id, intent.namespace, binding.namespace,
            grant.installation_id, intent.job_id, intent.operation_id,
            binding.budget_reservation_operation_id, intent.call_id,
            binding.binding_digest, intent.request_digest,
            "consumer-1", "worker-read-1")
        read = WorkerModelResultReadV1(read_request, observation, terminal)
        calls = []

        async def terminal_fact(self, *args, **kwargs):
            calls.append("terminal")
            assert kwargs["intent"] == intent
            return record, permit, admission, terminal

        async def worker_read(self, *args, **kwargs):
            calls.append("read")
            assert kwargs["read_request"] == read_request
            return read

        async def forbidden(self, *args, **kwargs):
            raise AssertionError("worker result read must not dispatch provider")

        client.model_terminal_fact_v2 = MethodType(terminal_fact, client)
        client.worker_model_result_read_v1 = MethodType(worker_read, client)
        client.model_prepare_fenced_v1 = MethodType(forbidden, client)
        client.model_admit_dispatch_once_v2 = MethodType(forbidden, client)
        assert await executor.read_original_for_worker(
            read_request=read_request, intent=intent, terminal=terminal) == read
        assert calls == ["terminal", "read"] and host.requests == []

        calls.clear()
        assert await executor.read_original_for_worker(
            read_request=replace(read_request, call_id="another-call"),
            intent=intent, terminal=terminal) is None
        assert calls == []

        async def lost_read(self, *args, **kwargs):
            calls.append("read-lost")
            raise ConnectionError("response unknown")

        async def recover_finish(self, *args, **kwargs):
            calls.append("recover-finish")
            assert kwargs["read_request"] == read_request
            return True

        client.worker_model_result_read_v1 = MethodType(lost_read, client)
        client.worker_model_result_recover_finish_v1 = MethodType(recover_finish, client)
        assert await executor.read_original_for_worker(
            read_request=read_request, intent=intent, terminal=terminal) is None
        assert calls == ["terminal", "read-lost", "recover-finish"]
        assert host.requests == []

        # The same installed transport sends the versioned worker DTO; its
        # Authority server counterpart tests finish only after TLS drain.
        profile = AuthorityTlsProfile(
            "default", "authority.example", 443, "authority.example",
            intent.authority_id, tmp_path / "ca.pem", tmp_path / "client.pem",
            tmp_path / "client.key")
        transport = MtlsAuthorityTransport({profile.profile_id: profile})
        rpc_methods = []

        async def wire_rpc(self, _request, _handshake, method, command, *, protocol):
            rpc_methods.append((method, command, protocol))
            if method == "worker_model_result_read_v1":
                return {"result": worker_result_to_wire(read),
                        "channel_binding_sha256": "f" * 64}
            return {"finished": True, "channel_binding_sha256": "f" * 64}

        transport._content_rpc = MethodType(wire_rpc, transport)
        try:
            assert await transport.worker_model_result_read_v1(
                object(), object(), grant, namespace=intent.namespace,
                read_request=read_request) == read
            assert await transport.worker_model_result_recover_finish_v1(
                object(), object(), grant, namespace=intent.namespace,
                read_request=read_request) is True
            assert [method for method, _, _ in rpc_methods] == [
                "worker_model_result_read_v1",
                "worker_model_result_recover_finish_v1"]
            assert all(command == {
                "namespace": intent.namespace,
                "read_request": worker_result_to_wire(read_request),
            } for _, command, _ in rpc_methods)
            assert all(protocol == "sylanne3.authority.v2"
                       for _, _, protocol in rpc_methods)
            with pytest.raises(RuntimeError, match="identity"):
                await transport.worker_model_result_read_v1(
                    object(), object(), grant, namespace=intent.namespace,
                    read_request=replace(read_request, installation_id="other-install"))
            assert len(rpc_methods) == 2
        finally:
            await transport.close()
    finally:
        await host.asyncTearDown()
