"""Real TLS model identity RPCs remain passive, bound to one installation."""

import asyncio
from dataclasses import replace
import hashlib
import ssl

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from rewrite.tests.alpha1.model_broker.test_broker import request as broker_request
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_contract import to_wire as fence_to_wire
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_model_egress_wire import to_wire as model_to_wire
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, installed_model_config_ref,
)
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.asyncio
async def test_model_identity_rpc_real_mtls_binding_digest_and_replay(tmp_path, monkeypatch):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text('{"test":true}', encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    peers = {
        name: MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            files[f"{name}.pem"].read_text(encoding="ascii"))).hexdigest())
        for name in ("client", "second")
    }
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns:role", journal_id="execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)

    def authorize(peer, action, namespace, holder):
        return (peer in peers.values() and namespace == "ns:role"
                and action in {"install", "seal_v2_only", "current", "model_egress"}
                and (holder is None or holder == "host:one"))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True, dispatch_verifier=lambda *args: True,
        create=True)
    listener = None
    transports = []
    server = None
    host_fixture = None
    try:
        core.register_namespace(peers["client"], "ns:role", "host:one", deletion_head,
                                JournalHead("execution", 0, "genesis"))
        core.seal_v2_only(peers["client"])
        fences = AuthorityV2FenceService(
            core=core, fences=AuthorityV2FenceStore(core._db, create=True, lock=core._lock),
            deletion=deletion_guard, execution=execution, namespace="ns:role")
        verifier = object.__new__(PinnedCurrentModelEgressGraphVerifier)
        checked = []
        monkeypatch.setattr(verifier, "complete_graph_current",
                            lambda candidate: checked.append(candidate) or True)
        policy = AdminIngressModelPolicy(
            "provider-1", "model-1",
            installed_model_config_ref("provider-1", "model-1", "d" * 64),
            "d" * 64, 20.0, 256, ("text",), "private",
            ("proposal",), ("owner",), ("private",))
        model = AuthorityV2ModelEgressService(
            AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock),
            fences, graph_verifier=verifier, admin_model_policy=policy)
        server = AuthorityRpcServer(
            core, v2_fences=fences, v2_model_egress={"ns:role": model},
            model_observers_v2={"ns:role": (peers["client"].certificate_sha256, "first")},
            administrator_authorizer=lambda peer, action, namespace, holder:
                peer in peers.values() and action == "pair"
                and namespace == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={(peers["client"].certificate_sha256, "first"):
                              AdministratorInstallationV2(
                                  "installation-a", "host:one", "publisher-policy-a",
                                  "capabilities-v2", manifest_digest)},
            namespace_bindings_v2={
                (peers["client"].certificate_sha256, "first",
                 NamespaceId("bot-a", "persona-a")): "ns:role"})
        listener = await server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"]),
                timeout_seconds=2, max_message_bytes=65_536))
        port = listener.sockets[0].getsockname()[1]

        async def paired(name, profile_id):
            profile = AuthorityTlsProfile(
                profile_id, "127.0.0.1", port, "localhost", server._authority_id(),
                files["ca.pem"], files[f"{name}.pem"], files[f"{name}.key"],
                timeout_seconds=2, max_message_bytes=65_536)
            transport = MtlsAuthorityTransport({profile_id: profile})
            transports.append(transport)
            request = AuthorityProvisioningRequest(
                AUTHORITY_PROTOCOL, profile_id, "astrbot_plugin_sylanne", "4.28.1",
                tmp_path, tmp_path, PublisherPackageIdentity(manifest_digest))
            handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            return transport, request, handshake

        transport, provisioning, handshake = await paired("client", "first")
        grant = await transport.installation_grant_v2(provisioning, handshake)
        anchor = await transport.v2_current_anchor(provisioning, handshake, "ns:role")
        subject = handshake.installation_identity_ref
        base = broker_request()
        envelope = replace(
            base.envelope, identity=replace(base.identity, operation_id="job-operation"),
            authority=replace(base.envelope.authority, actor=subject,
                              issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                              worker_fence=7),
            version_guard=replace(base.envelope.version_guard,
                                  read_versions=(), query_epochs=()))
        call = replace(base, envelope=envelope, call_id="call-1",
                       provider_id="provider-1", model_id="model-1",
                       required_capabilities=frozenset({"text"}),
                       timeout_seconds=20.0, max_output_tokens=256)
        draft = ModelEgressDraftV1.from_intent(intent(
            authority_id=anchor.authority_id, namespace="ns:role", subject=subject,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
            request_digest=call.digest, budget_ceiling=(("output_tokens", 256),)))
        client = AuthorityClient(
            AuthoritySelection("first"), package_root=tmp_path, data_dir=tmp_path,
            transport=transport)
        assert (await client.status_v2()).state == "paired"
        current_grant = await client.installation_grant_v2()
        handshake = client._v2_handshake
        grant = current_grant
        installed_profile = transport.profile_for("first")
        host_fixture = model_fixture.AstrBotModelCallTests(
            methodName="test_one_http_request_on_host_loop_with_usage")
        await host_fixture.asyncSetUp()
        host_base = model_fixture.call_request()
        call2 = replace(
            host_base, call_id="call-2",
            envelope=replace(
                host_base.envelope,
                identity=replace(host_base.identity, operation_id="job-operation-2"),
                authority=replace(
                    host_base.envelope.authority, actor=subject,
                    issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                    worker_fence=7),
                version_guard=replace(host_base.envelope.version_guard,
                                      read_versions=(), query_epochs=())))
        draft2 = replace(
            draft, call_id="call-2", job_id="job-2",
            operation_id="job-operation-2", request_digest=call2.digest,
            provider_config_digest=host_fixture.admin_model.provider_config_digest,
            max_output_tokens=64, budget_ceiling=(("output_tokens", 128),))
        base_policy = host_fixture.bundle.installation_policy
        executor_policy = replace(
            base_policy, namespace=NamespaceId("bot-a", "persona-a"),
            authority_namespace="ns:role", installation_id="installation-a",
            manifest_digest=manifest_digest, administrator_holder="host:one",
            expected_authority_id=server._authority_id(),
            root_lease=replace(base_policy.root_lease,
                               bot_id="bot-a", persona_id="persona-a"),
            root_grant=replace(base_policy.root_grant,
                               bot_id="bot-a", persona_id="persona-a"))
        executor_bundle = replace(
            host_fixture.bundle, tls_profile=installed_profile,
            installation_policy=executor_policy)
        bundle = executor_bundle
        adapter = AstrBotModelProvider(
            context=host_fixture.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=model_fixture.UMO, descriptor=host_fixture.descriptor,
            admin_model=host_fixture.admin_model,
            installation_bundle=executor_bundle)
        model._admin_model_policy = host_fixture.admin_model
        prepared2, _ = await client.model_prepare_fenced_v1(
            executor_bundle, grant, draft=draft2, expected_anchor=anchor)
        with pytest.raises(RuntimeError, match="request binding"):
            await client.model_admit_dispatch_once_v2(
                executor_bundle, grant,
                intent=prepared2.intent, expected_anchor=anchor,
                model_request=replace(call2, payload={"prompt": "changed"}),
                host_incarnation="b" * 64)
        assert host_fixture.requests == []
        executor = HostModelEgressExecutor(
            authority=client, bundle=executor_bundle, grant=grant, adapter=adapter)
        receipt2 = await executor.execute_once(
            intent=prepared2.intent, expected_anchor=anchor, request=call2)
        assert receipt2 is not None
        assert len(host_fixture.requests) == 1
        assert host_fixture.requests[0][1].url.host == "mock.invalid"
        assert (await client.model_recover_fenced_v1(
            executor_bundle, grant, intent=prepared2.intent))[0].state == "observed"
        with pytest.raises(RuntimeError, match="unavailable"):
            await client.model_admit_dispatch_once_v2(
                executor_bundle, grant,
                intent=prepared2.intent, expected_anchor=anchor,
                model_request=call2, host_incarnation=adapter.host_incarnation)
        assert len(host_fixture.requests) == 1
        model._admin_model_policy = policy
        prepared, permit = await transport.model_prepare_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            draft=draft, expected_anchor=anchor)
        assert prepared.state == "prepared" and permit.subject == subject
        repeated, _ = await transport.model_prepare_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            draft=draft, expected_anchor=anchor)
        assert repeated == prepared
        forged = {"record": model_to_wire(prepared), "permit": fence_to_wire(permit),
                  "channel_binding_sha256": handshake.channel_binding_sha256}
        forged["record"]["intent"]["request_digest"] = "e" * 64
        with pytest.raises(RuntimeError, match="response binding"):
            transport._model_response(forged, grant, draft, "prepared")
        other, other_request, other_handshake = await paired("second", "second")
        with pytest.raises(RuntimeError):
            await other.model_recover_fenced_v1(
                other_request, other_handshake, grant, namespace="ns:role",
                holder="host:one", intent=prepared.intent)
        with pytest.raises(RuntimeError, match="request binding"):
            await transport.model_admit_dispatch_once_v1(
                provisioning, handshake, grant, namespace="ns:role", holder="host:one",
                intent=prepared.intent, expected_anchor=anchor,
                model_request=replace(call, payload={"input_ref": "changed"}))
        assert (await transport.model_recover_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent))[0].state == "prepared"
        admitted, _ = await transport.model_admit_dispatch_once_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent, expected_anchor=anchor, model_request=call)
        assert admitted.state == "dispatch_started" and len(checked) == 2
        with pytest.raises(RuntimeError, match="unavailable"):
            await transport.model_admit_dispatch_once_v1(
                provisioning, handshake, grant, namespace="ns:role", holder="host:one",
                intent=prepared.intent, expected_anchor=anchor, model_request=call)
        assert len(checked) == 2
        recovered, _ = await transport.model_recover_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent)
        assert recovered.state == "dispatch_started"
        assert (await client.model_recover_fenced_v1(
            bundle, current_grant, intent=prepared.intent))[0].state == "dispatch_started"
        drifted = replace(
            bundle, installation_policy=replace(
                executor_policy, manifest_digest="e" * 64))
        with pytest.raises(RuntimeError, match="installation binding"):
            await client.model_recover_fenced_v1(
                drifted, current_grant, intent=prepared.intent)
    finally:
        if host_fixture is not None:
            await host_fixture.asyncTearDown()
        for transport in transports:
            await transport.close()
        if server is not None:
            await server.aclose()
        deletion.close()
        execution.close()
        core.close()
