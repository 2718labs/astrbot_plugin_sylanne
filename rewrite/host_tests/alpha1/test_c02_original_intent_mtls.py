"""Original C02 intent lookup crosses a real paired loopback mTLS channel."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import ssl

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from rewrite.tests.alpha1.model_broker.test_broker import request as broker_request
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2, ModelEgressDraftV1, ModelEgressIntentV1,
)
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.c02_cost_settlement import C02OriginalIntentLookupV1
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.asyncio
async def test_original_c02_intent_lookup_uses_paired_mtls_and_observer(tmp_path, monkeypatch):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text('{"test":true}', encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    peers = {
        name: MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            files[f"{name}.pem"].read_text(encoding="ascii"))).hexdigest())
        for name in ("client", "second")
    }
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns:role", journal_id="execution",
        create=True)
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
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True, create=True)
    listener = None
    server = None
    host = None
    transports = []
    try:
        core.register_namespace(
            peers["client"], "ns:role", "host:one", deletion_head,
            JournalHead("execution", 0, "genesis"))
        core.seal_v2_only(peers["client"])
        fences = AuthorityV2FenceService(
            core=core, fences=AuthorityV2FenceStore(
                core._db, create=True, lock=core._lock),
            deletion=deletion_guard, execution=execution, namespace="ns:role")
        verifier = object.__new__(PinnedCurrentModelEgressGraphVerifier)
        monkeypatch.setattr(verifier, "complete_graph_current", lambda _: True)
        host = model_fixture.AstrBotModelCallTests(
            methodName="test_one_http_request_on_host_loop_with_usage")
        await host.asyncSetUp()
        model = AuthorityV2ModelEgressService(
            AuthorityV2ModelEgressStore(
                core._db, create=True, lock=core._lock),
            fences, graph_verifier=verifier,
            admin_model_policy=host.admin_model)
        installations = {
            (peers[name].certificate_sha256, profile): AdministratorInstallationV2(
                installation_id, "host:one", "publisher-policy-a",
                "capabilities-v2", manifest_digest)
            for name, profile, installation_id in (
                ("client", "first", "installation-a"),
                ("second", "second", "installation-b"),
            )
        }
        bindings = {
            (peers[name].certificate_sha256, profile,
             NamespaceId("bot-a", "persona-a")): "ns:role"
            for name, profile in (("client", "first"), ("second", "second"))
        }
        server = AuthorityRpcServer(
            core, v2_fences=fences, v2_model_egress={"ns:role": model},
            model_observers_v2={"ns:role": (
                peers["client"].certificate_sha256, "first")},
            administrator_authorizer=lambda peer, action, namespace, holder:
                peer in peers.values() and action == "pair"
                and namespace == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2=installations,
            namespace_bindings_v2=bindings)
        listener = await server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2,
                max_message_bytes=65_536))
        port = listener.sockets[0].getsockname()[1]

        def client_for(name, profile_id):
            profile = AuthorityTlsProfile(
                profile_id, "127.0.0.1", port, "localhost",
                server._authority_id(), files["ca.pem"],
                files[f"{name}.pem"], files[f"{name}.key"],
                timeout_seconds=2, max_message_bytes=65_536)
            transport = MtlsAuthorityTransport({profile_id: profile})
            transports.append(transport)
            return AuthorityClient(
                AuthoritySelection(profile_id), package_root=tmp_path,
                data_dir=tmp_path, transport=transport), profile

        client, profile = client_for("client", "first")
        assert (await client.status_v2()).state == "paired"
        grant = await client.installation_grant_v2()
        anchor = await client._transport.v2_current_anchor(
            client._v2_request, client._v2_handshake, "ns:role")
        base = broker_request()
        envelope = replace(
            base.envelope,
            identity=replace(base.identity, operation_id="job-operation"),
            authority=replace(
                base.envelope.authority, actor=grant.subject,
                issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                worker_fence=7),
            version_guard=replace(base.envelope.version_guard,
                                  read_versions=(), query_epochs=()))
        call = replace(
            base, envelope=envelope, call_id="call-1",
            provider_id=host.admin_model.provider_id,
            model_id=host.admin_model.model_id,
            required_capabilities=frozenset({"text"}),
            timeout_seconds=host.admin_model.timeout_seconds,
            max_output_tokens=host.admin_model.max_output_tokens)
        draft = ModelEgressDraftV1.from_intent(intent(
            authority_id=anchor.authority_id, namespace="ns:role",
            subject=grant.subject,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
            request_digest=call.digest,
            provider_config_digest=host.admin_model.provider_config_digest,
            max_output_tokens=host.admin_model.max_output_tokens,
            acquire_operation_id="job-operation",
            binding_digest="e" * 64,
            budget_reservation_operation_id="original-ingress-operation",
            budget_ceiling=(("output_tokens", 128),)))
        base_policy = host.bundle.installation_policy
        policy = replace(
            base_policy, namespace=NamespaceId("bot-a", "persona-a"),
            authority_namespace="ns:role", installation_id="installation-a",
            manifest_digest=manifest_digest,
            administrator_holder="host:one",
            expected_authority_id=server._authority_id(),
            root_lease=replace(base_policy.root_lease,
                               bot_id="bot-a", persona_id="persona-a"),
            root_grant=replace(base_policy.root_grant,
                               bot_id="bot-a", persona_id="persona-a"))
        bundle = replace(
            host.bundle, tls_profile=profile, installation_policy=policy)
        prepared, _ = await client.model_prepare_fenced_v1(
            bundle, grant, draft=draft, expected_anchor=anchor)
        original = prepared.intent
        admitted, _, admission = await client.model_admit_dispatch_once_v2(
            bundle, grant, intent=original, expected_anchor=anchor,
            model_request=call, host_incarnation="a" * 64)
        assert admitted.state == "dispatch_started"
        report = HostObservedModelCompletionV2(
            admission.admission_id, admission.host_incarnation,
            original.call_id, original.request_digest,
            original.provider_id, original.model_id,
            original.provider_config_digest, '{"answer":"ok"}',
            (("input_tokens", 1),), (("micro_usd", 2),), "provider-ref")
        observed, _, terminal = await client.model_complete_observed_v2(
            bundle, grant, intent=original, expected_anchor=anchor,
            admission=admission, report=report)
        assert observed.state == "observed" and terminal is not None
        lookup = C02OriginalIntentLookupV1(
            policy.namespace, grant.authority_id, policy.authority_namespace,
            grant.installation_id, original.job_id,
            original.budget_reservation_operation_id,
            original.acquire_operation_id, original.call_id,
            original.binding_digest, original.request_digest,
            "consumer-operation")
        recovered = await client.model_original_intent_lookup_v1(
            bundle, grant, lookup=lookup)
        assert type(recovered) is ModelEgressIntentV1 and recovered == original
        assert await client.model_original_intent_lookup_v1(
            bundle, grant, lookup=lookup) == original
        assert host.requests == []

        with pytest.raises(RuntimeError):
            await client.model_original_intent_lookup_v1(
                bundle, grant,
                lookup=replace(lookup, installation_id="wrong-installation"))
        with pytest.raises(RuntimeError):
            await client.model_original_intent_lookup_v1(
                bundle, grant,
                lookup=replace(lookup, authority_namespace="wrong-namespace"))
        original_command = {
            "namespace": lookup.authority_namespace,
            "installation_id": lookup.installation_id,
            "job_id": lookup.job_id,
            "acquire_operation_id": lookup.acquire_operation_id,
            "call_id": lookup.call_id,
            "original_model_operation_id": lookup.acquire_operation_id,
            "request_digest": lookup.model_request_digest,
            "binding_digest": lookup.binding_digest,
        }
        for changed in ({"installation_id": "wrong-installation"},
                        {"namespace": "wrong-namespace"}):
            with pytest.raises(RuntimeError):
                await client._transport._content_rpc(
                    client._v2_request, client._v2_handshake,
                    "model_original_intent_lookup_v1",
                    {**original_command, **changed},
                    protocol=AUTHORITY_V2_PROTOCOL)
        second, second_profile = client_for("second", "second")
        assert (await second.status_v2()).state == "paired"
        second_grant = await second.installation_grant_v2()
        second_policy = replace(policy, installation_id="installation-b")
        second_bundle = replace(
            bundle, tls_profile=second_profile,
            installation_policy=second_policy)
        with pytest.raises(RuntimeError):
            await second.model_original_intent_lookup_v1(
                second_bundle, second_grant,
                lookup=replace(lookup, installation_id="installation-b"))
    finally:
        if host is not None:
            await host.asyncTearDown()
        for transport in transports:
            await transport.close()
        if server is not None:
            await server.aclose()
        deletion.close()
        execution.close()
        core.close()
