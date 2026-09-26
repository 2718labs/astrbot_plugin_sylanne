"""Explicit C02 host composition uses one installed, paired model authority."""

import asyncio
import json
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.authority_profile import (
    AdminD06FirstIngressC02Policy, AdminIngressClockPolicy,
)
from sylanne3.host.first_ingress_c02_driver import (
    installed_first_ingress_c02_pairing_ready_v1,
    original_unacquired_handoff_v1,
    run_installed_first_ingress_c02_v1,
)
from sylanne3.host.d06_ingress import ingress_content_fingerprint
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.original_c02_cost_intent_port import InstalledOriginalC02CostIntentPort
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.runtime.c02_cost_settlement import C02OriginalIntentLookupV1
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.first_ingress_unacquired import (
    FirstIngressUnacquiredItemV1, FirstIngressUnacquiredPageV1,
)
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_contracts import CommitReceipt


@pytest.mark.asyncio
async def test_explicit_c02_driver_uses_paired_bundle_and_holds_without_it(
    tmp_path, monkeypatch,
):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        original_intent, _, _, _, grant, _ = fixture_values(
            host, model_fixture.call_request())
        profile = AuthorityTlsProfile(
            "installed", "authority.example", 443, "authority.example",
            grant.authority_id, tmp_path / "ca.pem", tmp_path / "client.pem",
            tmp_path / "client.key",
        )
        bundle = replace(
            bundle, tls_profile=profile,
            ingress_clock=AdminIngressClockPolicy("clock", 1.0, 1.0),
            d06_first_ingress_c02=AdminD06FirstIngressC02Policy(
                30.0, {"graph_write": 1}, "snapshot", "resource"),
        )
        installation = V2InstallationAssembly(
            bundle.installation_policy, grant, bundle.d11_signing_key,
            bundle.d02_signing_key, lambda: None, tmp_path, tmp_path,
            admin_bundle=bundle,
        )
        envelope = HostIngressEnvelope(
            bundle.installation_policy.namespace, "platform",
            json.dumps([model_fixture.UMO, "chat"]), "sender", "message",
            "text", None, 1.0, "private",
            SourceLineage("a" * 64, "reported", "platform",
                          "external_report", "reported_claim"),
        )
        receipt = IngressReceipt("accepted", "original-ingress")
        committed = CommitReceipt(
            "committed", "consumer", "a" * 64, "activity", None, 1,
            (), (), (), (), (),
        )
        runtime = RuntimeContext(tmp_path, dependencies=None)
        calls = []

        async def commit(self, observed_envelope, observed_receipt, *,
                         executor, original_recovery=None):
            calls.append((observed_envelope, observed_receipt))
            assert original_recovery is None
            assert type(executor) is HostModelEgressExecutor
            assert executor._bundle is bundle and executor._grant == grant
            return committed

        runtime.commit_first_ingress_c02_v1 = MethodType(commit, runtime)
        pairing = {"state": "paired"}

        async def status_v2(self):
            return SimpleNamespace(state=pairing["state"])

        async def installation_grant_v2(self):
            return grant

        monkeypatch.setattr(AuthorityClient, "status_v2", status_v2)
        monkeypatch.setattr(AuthorityClient, "installation_grant_v2",
                            installation_grant_v2)

        async def run(current_installation):
            return await run_installed_first_ingress_c02_v1(
                runtime, current_installation, context=host.context,
                trusted_umo=model_fixture.UMO, envelope=envelope,
                receipt=receipt,
            )

        assert await run(installation) == committed
        assert calls == [(envelope, receipt)]
        assert await run(replace(
            installation, admin_bundle=replace(
                bundle, d06_first_ingress_c02=None))) is None
        assert await run(replace(
            installation, admin_bundle=replace(
                bundle, tls_profile=None))) is None
        assert calls == [(envelope, receipt)]
        pairing["state"] = "unpaired"
        assert await run(installation) is None
        assert calls == [(envelope, receipt)] and host.requests == []

        # Startup discovery is read-only and remains HOLD until the graph
        # supplies a verified, original queued-job page.
        pairing["state"] = "paired"
        assert await installed_first_ingress_c02_pairing_ready_v1(installation)
        original_op, job_id = ingress_ids(envelope.lineage.source_ref)[2:4]
        item = FirstIngressUnacquiredItemV1(
            envelope.namespace, grant.installation_id, job_id, original_op,
            envelope, ingress_content_fingerprint(envelope), "b" * 64,
        )
        page = FirstIngressUnacquiredPageV1(
            envelope.namespace, grant.installation_id, "incarnation", 1, 1,
            (item,), None,
        )

        class Worker:
            async def call(self, operation):
                return operation(graph)

        graph = SimpleNamespace()
        runtime._worker = Worker()
        runtime._v2_bootstrap = object()
        runtime._v2_namespace_provisioned = True
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_namespace = envelope.namespace
        runtime._v2_installation_grant = grant
        assert await runtime.discover_first_ingress_unacquired_v1() is None
        graph.discover_first_ingress_unacquired_v1 = (
            lambda bootstrap, namespace, *, after_job_id, limit: page)
        assert await runtime.discover_first_ingress_unacquired_v1() == page
        assert original_unacquired_handoff_v1(item, installation) == (
            model_fixture.UMO, envelope, IngressReceipt("accepted", original_op))
        assert calls == [(envelope, receipt)] and host.requests == []

        authority = AuthorityClient(
            AuthoritySelection(), package_root=tmp_path,
            data_dir=tmp_path)
        lookup = C02OriginalIntentLookupV1(
            envelope.namespace, grant.authority_id,
            bundle.installation_policy.authority_namespace,
            grant.installation_id, original_intent.job_id,
            original_intent.budget_reservation_operation_id,
            original_intent.acquire_operation_id, original_intent.call_id,
            original_intent.binding_digest, original_intent.request_digest,
            "consumer-operation",
        )
        async def original_lookup(self, observed_bundle, observed_grant, *, lookup):
            assert observed_bundle is bundle and observed_grant == grant
            return original_intent

        authority.model_original_intent_lookup_v1 = MethodType(
            original_lookup, authority)
        port = InstalledOriginalC02CostIntentPort(
            client=authority, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop())
        assert await asyncio.to_thread(port, lookup) == original_intent

        transport = MtlsAuthorityTransport({profile.profile_id: profile})
        observed_command = []

        async def absent_original(*args, **kwargs):
            observed_command.append(args[3])
            return {"status": "absent", "channel_binding_sha256": "b" * 64}

        monkeypatch.setattr(transport, "_content_rpc", absent_original)
        with pytest.raises(RuntimeError, match="unresolved"):
            await transport.model_original_intent_lookup_v1(
                object(), object(), grant, lookup=lookup)
        assert observed_command[0]["acquire_operation_id"] == (
            original_intent.acquire_operation_id)
        assert observed_command[0]["original_model_operation_id"] == (
            original_intent.acquire_operation_id)
    finally:
        await host.asyncTearDown()
