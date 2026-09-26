"""Production bootstrap injects an admission issuer from one installation."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from sylanne3 import runtime_context
from sylanne3.domains.d03.context import ContextProvider
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.runtime.installed_dispatch_admission_issuer import InstalledDispatchAdmissionIssuer
from sylanne3.runtime_contracts import InstallationGrantV2
from rewrite.tests.alpha1.runtime.test_runtime_context_v2_worker import installation


def test_v2_worker_installs_exact_dispatch_admission_issuer(tmp_path, monkeypatch):
    async def scenario():
        grant = InstallationGrantV2(
            "authority", "subject", "administrator", "installation",
            "a" * 64, "publisher-trust", "2", "b" * 64)

        class Port:
            installation_grant = grant

            def close(self):
                pass

        class Store:
            def __init__(self, *_):
                pass

            def close(self):
                pass

        captured = {}

        class Coordinator:
            def __init__(self, _store, _bootstrap, **kwargs):
                captured.update(kwargs)

            def register_provider(self, *_args):
                pass

        monkeypatch.setattr(runtime_context, "verify_installed_package",
            lambda *_args, **_kwargs: InstalledPackageVerification(
                True, "verified", grant.manifest_digest, "3.0.0-alpha1", "formal-alpha1"))
        monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
        monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
        monkeypatch.setattr(runtime_context, "V2FencePort", Port)
        assembled = installation(grant, Port, tmp_path, tmp_path / "data")
        assembled = replace(assembled, ingress_clock=AdminIngressClockPolicy(
            "clock-a", 0.2, 2.0))
        d03 = ContextProvider()
        registry = SimpleNamespace(
            complete=True, type_registry=object(),
            registrations={"d03": SimpleNamespace(
                domain="d03", provider=d03,
                proposal_schema="d03.proposal.v1", proposal_schema_hash="c" * 64)})
        context = runtime_context.RuntimeContext(
            tmp_path / "data", package_root=tmp_path, dependencies=None,
            domains=registry)
        health = await context.start_v2(assembled)
        assert health.status == "limited", health
        issuer = captured["dispatch_admission_issuer"]
        assert type(issuer) is InstalledDispatchAdmissionIssuer
        assert issuer._d02 is captured["d02_issuer"]
        assert issuer._d11.current_budget_grant is not None
        assert issuer._context is context._domains.registrations["d03"].provider
        assert captured["d11_issuer"].resource_issuer is captured["d02_issuer"]
        assert (await context.stop()).status == "stopped"

    asyncio.run(scenario())
