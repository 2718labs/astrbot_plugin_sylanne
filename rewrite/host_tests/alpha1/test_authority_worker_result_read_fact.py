"""The C02 committer receives only Authority's fenced original handoff fact."""

import asyncio
from dataclasses import asdict, replace
from types import MethodType

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1,
)
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactV1,
    to_wire as worker_fact_to_wire,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
from sylanne3.runtime_contracts import canonical_digest


@pytest.mark.asyncio
async def test_worker_fact_uses_original_handoff_and_installed_write_fence(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        _, anchor, _, _, grant, client = fixture_values(
            host, model_fixture.call_request())
        policy = bundle.installation_policy
        anchor = replace(anchor, namespace=policy.authority_namespace)
        profile = AuthorityTlsProfile(
            "default", "authority.example", 443, "authority.example",
            grant.authority_id, tmp_path / "ca.pem", tmp_path / "client.pem",
            tmp_path / "client.key",
        )
        bundle = replace(bundle, tls_profile=profile)
        read_request = WorkerModelResultReadRequestV1(
            grant.authority_id, policy.authority_namespace, policy.namespace,
            grant.installation_id, "job-1", "acquire-1", "reserve-1",
            "call-1", "a" * 64, "b" * 64, "consumer-1", "read-1",
        )
        write = FencePermitV2(
            grant.authority_id, policy.authority_namespace, grant.subject,
            grant.administrator_holder, 1, "write",
            read_request.consumer_operation_id, "c" * 64, 1, 1, anchor,
        )
        read = FencePermitV2(
            grant.authority_id, policy.authority_namespace, grant.subject,
            grant.administrator_holder, 1, "read",
            read_request.read_attempt_id, "d" * 64, 1, 1, anchor,
        )
        fact_request = WorkerResultReadFactRequestV1(read_request, write)
        finish_key = canonical_digest({
            "request": asdict(read_request), "permit": asdict(read),
        })
        terminal = ModelTerminalReceiptV2(
            "a" * 64, read_request.call_id,
            read_request.model_request_digest, "e" * 64, "f" * 64,
            "sha256:" + "a" * 64, grant.installation_id, "d" * 64,
        )
        fact = WorkerResultReadFactV1(
            read_request, read_request.digest, read,
            canonical_digest(asdict(read)),
            "worker-result-finish:" + finish_key,
            "sha256:" + canonical_digest({
                "action": "finish_worker_result_read",
                "request": asdict(read_request), "permit": asdict(read),
            }),
            "b" * 64, "c" * 64, terminal, write,
            canonical_digest(asdict(write)),
        )
        transport = MtlsAuthorityTransport({profile.profile_id: profile})
        sent = []

        async def rpc(self, request, handshake, method, command, *, protocol):
            sent.append((method, command, protocol))
            return {"fact": worker_fact_to_wire(fact),
                    "channel_binding_sha256": "d" * 64}

        transport._content_rpc = MethodType(rpc, transport)
        client._transport = transport

        async def installed_context(self, actual_bundle, actual_grant):
            assert (actual_bundle, actual_grant) == (bundle, grant)
            return object(), object(), policy

        client._model_installation_context = MethodType(installed_context, client)
        port = InstalledWorkerResultReadFactPort(
            client=client, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop(),
        )
        assert await asyncio.to_thread(
            port.current_worker_result_read_fact, fact_request,
        ) == fact
        assert sent == [(
            "worker_result_read_fact_v1",
            {"namespace": policy.authority_namespace,
             "fact_request": worker_fact_to_wire(fact_request)},
            "sylanne3.authority.v2",
        )]
        with pytest.raises(RuntimeError, match="installed C02 fence"):
            await client.worker_result_read_fact_v1(
                bundle, grant, fact_request=WorkerResultReadFactRequestV1(
                    read_request, replace(write, subject="other")),
            )
        assert len(sent) == 1 and host.requests == []
    finally:
        await host.asyncTearDown()
