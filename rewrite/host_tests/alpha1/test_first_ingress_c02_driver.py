"""Explicit C02 host composition uses one installed, paired model authority."""

import json
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.host.authority_client import AuthorityClient
from sylanne3.host.authority_profile import (
    AdminD06FirstIngressC02Policy, AdminIngressClockPolicy,
)
from sylanne3.host.first_ingress_c02_driver import run_installed_first_ingress_c02_v1
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.runtime_context import RuntimeContext
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
        _, _, _, _, grant, _ = fixture_values(host, model_fixture.call_request())
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

        async def commit(self, observed_envelope, observed_receipt, *, executor):
            calls.append((observed_envelope, observed_receipt))
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
        assert calls == [(envelope, receipt)]
        pairing["state"] = "unpaired"
        assert await run(installation) is None
        assert calls == [(envelope, receipt)] and host.requests == []
    finally:
        await host.asyncTearDown()
