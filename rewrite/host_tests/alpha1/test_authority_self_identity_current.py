"""The installed D03 read port sends only the original current-fence query."""

import asyncio
from dataclasses import replace
from types import MethodType

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1, SelfIdentityCurrentRequestV1,
    to_wire as self_identity_to_wire,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.self_identity_current_port import InstalledCurrentSelfIdentityPort


@pytest.mark.asyncio
async def test_current_self_identity_uses_installed_reader_and_original_permit(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        _, anchor, _, _, grant, client = fixture_values(
            host, model_fixture.call_request())
        profile = AuthorityTlsProfile(
            "default", "authority.example", 443, "authority.example",
            grant.authority_id, tmp_path / "ca.pem", tmp_path / "client.pem",
            tmp_path / "client.key",
        )
        bundle = replace(bundle, tls_profile=profile)
        policy = bundle.installation_policy
        anchor = replace(anchor, namespace=policy.authority_namespace)
        permit = FencePermitV2(
            grant.authority_id, policy.authority_namespace, grant.subject,
            grant.administrator_holder, 1, "write", "d03-op", "a" * 64,
            1, 1, anchor,
        )
        current_request = SelfIdentityCurrentRequestV1(
            grant.authority_id, policy.authority_namespace, policy.namespace,
            grant.installation_id, grant.manifest_digest, "d03-op", permit,
        )
        current = AuthorityCurrentSelfIdentityV1(
            namespace=policy.namespace,
            authority_namespace=policy.authority_namespace,
            authority_id=grant.authority_id,
            installation_id=grant.installation_id,
            manifest_digest=grant.manifest_digest,
            activation_generation=1,
            graph_incarnation="graph-1",
            role_head_id="role-head-1",
            graph_revision=1,
            graph_epoch=1,
            persona_ref="persona:" + policy.namespace.persona_id,
            self_entity_ref="entity:self-1",
            mapping_id="self-map:one",
            mapping_revision=1,
            mapping_revocation_epoch=0,
            registration_operation_id="register-1",
            registration_digest="b" * 64,
            owner_authorization_revision=1,
            owner_authorization_head="owner-head-1",
            owner_minimum_revocation_revision=0,
            owner_revocation_epoch=0,
            request_operation_id=current_request.request_operation_id,
            permit=permit,
        )
        transport = MtlsAuthorityTransport({profile.profile_id: profile})
        sent = []

        async def rpc(self, request, handshake, method, command, *, protocol):
            sent.append((method, command, protocol))
            return {"current": self_identity_to_wire(current),
                    "channel_binding_sha256": "c" * 64}

        transport._content_rpc = MethodType(rpc, transport)
        client._transport = transport
        contexts = []

        async def installed_context(self, actual_bundle, actual_grant):
            contexts.append((actual_bundle, actual_grant))
            return object(), object(), policy

        client._model_installation_context = MethodType(installed_context, client)
        port = InstalledCurrentSelfIdentityPort(
            client=client, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop(),
        )
        assert await asyncio.to_thread(
            port.current_self_identity, namespace=policy.namespace,
            authority_namespace=policy.authority_namespace,
            request_operation_id=current_request.request_operation_id,
            permit=permit,
        ) == current
        assert contexts == [(bundle, grant)]
        assert sent == [(
            "self_identity_current_v1",
            {"namespace": policy.authority_namespace,
             "current_request": self_identity_to_wire(current_request)},
            "sylanne3.authority.v2",
        )]
        with pytest.raises(RuntimeError, match="installed namespace"):
            await client.self_identity_current_v1(
                bundle, grant,
                current_request=replace(current_request, installation_id="other"),
            )
        assert len(sent) == 1
        with pytest.raises(RuntimeError, match="graph worker"):
            port.current_self_identity(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace,
                request_operation_id=current_request.request_operation_id,
                permit=permit,
            )
    finally:
        await host.asyncTearDown()
