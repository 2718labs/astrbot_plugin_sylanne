"""Pairing starts graph ownership but does not admit a namespace."""

import asyncio
from dataclasses import replace
from pathlib import Path
import sys
from threading import get_ident
import time
from types import ModuleType, SimpleNamespace

import pytest

host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[3] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package

from sylanne3 import runtime_context
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import InstallationGrantV2, NamespaceId

if installed_stub:
    del sys.modules["sylanne3.host"]


def installation(grant, port_factory, package_root, data_dir, *,
                 features=frozenset({"avx2"})):
    namespace = NamespaceId("bot", "persona")
    lease = BudgetLease(
        "root-lease", None, *namespace.as_tuple, "USD",
        {"cpu_ms": 200}, {}, {}, {}, 1, "active",
    )
    root_grant = BudgetLeaseGrant(
        "root-grant", 1, *namespace.as_tuple, lease.lease_id,
        "USD", {"cpu_ms": 100}, ("encode",), time.time() + 3600, "d11-policy",
    )
    policy = AdminInstallationPolicy(
        namespace, "opaque:persona", grant.installation_id, grant.manifest_digest,
        grant.administrator_holder, grant.authority_id, "c" * 64,
        "scheme-1", "operator-1", "policy-1", lease, root_grant,
    )
    return V2InstallationAssembly(
        policy, grant, b"k" * 32, port_factory,
        package_root, data_dir, features,
    )


@pytest.mark.parametrize("unresolved_fence", [False, True])
def test_context_owns_v2_worker_without_publishing_ready(
    tmp_path, monkeypatch, unresolved_fence,
):
    async def scenario():
        trace = []
        grant = InstallationGrantV2(
            "authority", "subject", "administrator", "installation",
            "a" * 64, "publisher-trust", "2", "b" * 64,
        )
        monkeypatch.setattr(
            runtime_context, "verify_installed_package",
            lambda root, digest, *, available_cpu_features: InstalledPackageVerification(
                True, "verified", digest, "3.0.0-alpha1", "formal-alpha1",
            ) if available_cpu_features == frozenset({"avx2"}) else pytest.fail("CPU evidence lost"),
        )

        class Store:
            def __init__(self, *_):
                trace.append(("store_open", get_ident()))

            def close(self):
                trace.append(("store_close", get_ident()))

        class Port:
            def __init__(self):
                trace.append(("port_open", get_ident()))

            @property
            def installation_grant(self):
                return grant

            def close(self):
                trace.append(("port_close", get_ident()))
                if unresolved_fence:
                    raise V2FenceOutcomeUnknown("fence result unknown")

        class Coordinator:
            def __init__(self, _store, _bootstrap, **kwargs):
                assert kwargs["holder"] == "administrator"
                assert isinstance(kwargs["content_fence_v2"], Port)
                assert isinstance(kwargs["d11_issuer"], runtime_context.D11BudgetGrantIssuer)
                self.bootstrap = _bootstrap
                trace.append(("coordinator_open", get_ident()))

            def provision_namespace_v2(self, bootstrap, policy, *, operation_id):
                assert bootstrap is self.bootstrap
                assert policy is assembled.installation_policy
                trace.append(("provision", get_ident()))
                return (policy.installation_id, operation_id)

        monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
        monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
        domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
        context = runtime_context.RuntimeContext(
            tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
        )
        assembled = installation(grant, Port, tmp_path, tmp_path / "data")
        health = await context.start_v2(assembled)
        assert health.status == "limited"
        assert health.missing_capabilities == ("namespace_activation",)
        assert (await context.start()).status == "limited"
        assert await context.provision_installed_namespace("install-persona") == (
            "installation", "install-persona")
        assert context.health.status == "limited"
        assert context.health.missing_capabilities == ("product_ingress", "dispatch")
        worker = context._worker
        if unresolved_fence:
            with pytest.raises(V2FenceOutcomeUnknown, match="fence result unknown"):
                await context.stop()
            assert context.health.status == "blocked"
            assert context.health.missing_capabilities == ("v2_fence_recovery",)
            assert (await context.start_v2(assembled)).status == "blocked"
            assert (await context.start()).status == "blocked"
            assert (await context.stop()).status == "blocked"
        else:
            assert (await context.stop()).status == "stopped"
        assert not worker._thread.is_alive()
        assert [event for event, _ in trace] == [
            "store_open", "port_open", "coordinator_open", "provision",
            "port_close", "store_close",
        ]
        assert len({thread for _, thread in trace}) == 1
        assert trace[0][1] != get_ident()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("verification", "detail"),
    [
        (InstalledPackageVerification(False, "file_mismatch", "a" * 64, failed_path="module.py"),
         "file_mismatch"),
        (InstalledPackageVerification(True, "verified", "a" * 64, "3.0.0-alpha1", "dev-probe"),
         "formal-alpha1 package required"),
    ],
)
def test_context_rejects_unverified_or_nonformal_package_before_opening_graph(
    tmp_path, monkeypatch, verification, detail,
):
    async def scenario():
        grant = InstallationGrantV2(
            "authority", "subject", "administrator", "installation",
            "a" * 64, "publisher-trust", "2", "b" * 64,
        )
        calls = []
        monkeypatch.setattr(
            runtime_context, "verify_installed_package",
            lambda root, digest, *, available_cpu_features: calls.append(
                (root, digest, available_cpu_features)) or verification,
        )
        domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
        context = runtime_context.RuntimeContext(
            tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
        )
        health = await context.start_v2(installation(
            grant, lambda: pytest.fail("port opened"), tmp_path, tmp_path / "data"))
        assert health.status == "blocked"
        assert health.missing_capabilities == ("installed_package",)
        assert health.detail == detail
        assert calls == [(tmp_path, grant.manifest_digest, frozenset({"avx2"}))]
        assert not (tmp_path / "data").exists()

    asyncio.run(scenario())


def test_context_rejects_assembly_grant_policy_mismatch_before_package_probe(
    tmp_path, monkeypatch,
):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    assembled = installation(
        grant, lambda: pytest.fail("port opened"), tmp_path, tmp_path / "data")
    assembled = replace(assembled, installation_policy=replace(
        assembled.installation_policy, manifest_digest="d" * 64))
    monkeypatch.setattr(runtime_context, "verify_installed_package",
                        lambda *_args, **_kwargs: pytest.fail("package probed"))
    domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
    context = runtime_context.RuntimeContext(
        tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
    )
    assert asyncio.run(context.start_v2(assembled)).missing_capabilities == ("v2_installation",)
    assert not (tmp_path / "data").exists()


def test_context_rejects_installed_policy_with_different_bound_affect_scheme(
    tmp_path, monkeypatch,
):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    assembled = installation(
        grant, lambda: pytest.fail("port opened"), tmp_path, tmp_path / "data",
    )
    scheme = AffectScheme(
        "d04.affect.scheme.v1", "scheme-2", "operator-1", "parameters-1",
        "coupling-1", (AffectAxis("care", "normalized", "care for another"),), (),
    )
    domains = discover_domain_registry(active_affect_scheme=scheme)
    assert domains.complete
    monkeypatch.setattr(runtime_context, "verify_installed_package",
                        lambda *_args, **_kwargs: pytest.fail("package probed"))
    context = runtime_context.RuntimeContext(
        tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
    )
    assert asyncio.run(context.start_v2(assembled)).missing_capabilities == ("affect_scheme",)
    assert not (tmp_path / "data").exists()


@pytest.mark.parametrize("mismatch", ["package_root", "data_dir"])
def test_context_rejects_assembly_path_mismatch_before_package_probe(
    tmp_path, monkeypatch, mismatch,
):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    assembled = installation(
        grant, lambda: pytest.fail("port opened"), tmp_path, tmp_path / "data")
    assembled = replace(assembled, **{mismatch: tmp_path / "different"})
    monkeypatch.setattr(runtime_context, "verify_installed_package",
                        lambda *_args, **_kwargs: pytest.fail("package probed"))
    domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
    context = runtime_context.RuntimeContext(
        tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
    )
    assert asyncio.run(context.start_v2(assembled)).missing_capabilities == ("v2_installation",)
    assert not (tmp_path / "data").exists()
