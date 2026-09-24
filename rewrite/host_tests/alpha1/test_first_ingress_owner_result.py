"""The host reads original Authority facts without another model dispatch."""

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
from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadV1
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


@pytest.mark.asyncio
async def test_original_terminal_and_owner_read_never_readmit_model():
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
            "completed", canonical_serialize({"text": "{}"}),
            (("output_tokens", 2),), (), "provider-call-1")
        terminal = ModelTerminalReceiptV2(
            admission.admission_id, intent.call_id, intent.request_digest,
            "d" * 64, observation.digest, "sha256:" + "e" * 64,
            grant.installation_id, admission.host_incarnation)
        record = ModelEgressRecoveryV1(
            intent, "observed", observation.digest, observation.usage,
            observation.cost)
        session = OwnerSessionLoginRequestV1(
            intent.authority_id, intent.namespace, grant.installation_id,
            OwnerPrincipalV1("provider", "account", "incarnation"),
            "credential", 1, "owner", "https://dashboard.example")
        calls = []

        async def terminal_fact(self, *args, **kwargs):
            calls.append("terminal")
            assert kwargs["intent"] == intent
            return record, permit, admission, terminal

        async def owner_read(self, *args, **kwargs):
            calls.append("owner-read")
            assert kwargs["owner_session_token"] == "current-owner-token"
            read_request = kwargs["read_request"]
            assert (read_request.call_id, read_request.source_purpose,
                    read_request.audience) == (intent.call_id, "consolidation", ("owner",))
            return ModelResultReadV1(intent.call_id, observation, terminal)

        async def forbidden(self, *args, **kwargs):
            raise AssertionError("original read must not dispatch the provider")

        client.model_terminal_fact_v2 = MethodType(terminal_fact, client)
        client.model_result_read_v1 = MethodType(owner_read, client)
        client.model_admit_dispatch_once_v2 = MethodType(forbidden, client)
        client.model_prepare_fenced_v1 = MethodType(forbidden, client)
        result = await executor.read_original_for_owner(
            binding=binding, draft=draft, expected_anchor=anchor,
            intent=intent, owner_actor_id="owner-actor",
            owner_session_request=session,
            owner_session_token="current-owner-token")
        assert result is not None
        assert result.record == record and result.terminal == terminal
        assert result.read.observation == observation
        assert calls == ["terminal", "owner-read"]
        assert host.requests == []

        calls.clear()

        async def unknown(self, *args, **kwargs):
            calls.append("terminal")
            return replace(record, state="dispatch_started"), permit, admission, None

        client.model_terminal_fact_v2 = MethodType(unknown, client)
        assert await executor.read_original_for_owner(
            binding=binding, draft=draft, expected_anchor=anchor,
            intent=intent, owner_actor_id="owner-actor",
            owner_session_request=session,
            owner_session_token="current-owner-token") is None
        assert calls == ["terminal"] and host.requests == []

        calls.clear()
        client.model_terminal_fact_v2 = MethodType(terminal_fact, client)

        async def lost_read(self, *args, **kwargs):
            calls.append("owner-read-lost")
            raise RuntimeError("Owner read reply lost")

        async def recover_finish(self, *args, **kwargs):
            calls.append("recover-finish")
            assert kwargs["read_request"].call_id == intent.call_id
            return True

        client.model_result_read_v1 = MethodType(lost_read, client)
        client.model_result_read_recover_finish_v1 = MethodType(recover_finish, client)
        assert await executor.read_original_for_owner(
            binding=binding, draft=draft, expected_anchor=anchor,
            intent=intent, owner_actor_id="owner-actor",
            owner_session_request=session,
            owner_session_token="current-owner-token") is None
        assert calls == ["terminal", "owner-read-lost", "recover-finish"]
        assert host.requests == []
    finally:
        await host.asyncTearDown()
