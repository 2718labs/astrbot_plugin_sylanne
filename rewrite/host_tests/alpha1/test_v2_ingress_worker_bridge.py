"""The v2 host bridge submits one typed ingress call to the graph worker."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import get_ident
from types import ModuleType, SimpleNamespace
import sys
import time

import pytest

host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[2] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package

from sylanne3 import runtime_context
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d03.context import RoleBinding
from sylanne3.graph_coordinator import (
    FirstIngressOutcomeUnknown, IngressHostFacts, ingress_host_fingerprint,
)
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminIngressClockPolicy, AdminIngressEncodingPolicy,
    AdminInstallationBundle,
)
from sylanne3.host.authority_client import AuthorityClient
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import InstallationGrantV2, NamespaceId

if installed_stub:
    del sys.modules["sylanne3.host"]


def assembly(root, grant, port_factory, *, clock, encoding, arrival=None):
    namespace = NamespaceId("bot", "persona")
    lease = BudgetLease(
        "root-lease", None, *namespace.as_tuple, "USD",
        {"cpu_ms": 200}, {}, {}, {}, 1, "active",
    )
    root_grant = BudgetLeaseGrant(
        "root-grant", 1, *namespace.as_tuple, lease.lease_id,
        "USD", {"cpu_ms": 100},
        ("encode", "d03.message_received") if arrival is not None else ("encode",),
        time.time() + 3600, "d11-policy",
    )
    policy = AdminInstallationPolicy(
        namespace, "opaque:persona", grant.installation_id, grant.manifest_digest,
        grant.administrator_holder, grant.authority_id, "c" * 64,
        "scheme-1", "operator-1", "policy-1", lease, root_grant,
    )
    return V2InstallationAssembly(
        policy, grant, b"k" * 32, b"d" * 32, port_factory,
        root, root / "data", frozenset({"avx2"}), clock, encoding,
        d03_arrival=arrival,
    )


def envelope(namespace, learned_at=11.0):
    return HostIngressEnvelope(
        namespace, "platform", "conversation", "sender", "message", "hello",
        10.0, learned_at, "private",
        SourceLineage("a" * 64, "reported", "platform", "external_report", "reported_claim"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("pairing", ("missing_bundle", "paired", "unpaired"))
async def test_v2_installs_worker_fact_port_only_from_paired_bundle(
    tmp_path, monkeypatch, pairing,
):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    installed = assembly(tmp_path, grant, object, clock=None, encoding=None)
    if pairing != "missing_bundle":
        profile = AuthorityTlsProfile(
            "profile", "authority.example", 443, "authority.example",
            grant.authority_id, tmp_path / "ca.pem", tmp_path / "client.pem",
            tmp_path / "client.key",
        )
        installed = replace(installed, admin_bundle=AdminInstallationBundle(
            profile, installed.installation_policy,
            installed.d11_signing_key, installed.d02_signing_key,
        ))

    async def status_v2(self):
        return SimpleNamespace(state="paired" if pairing == "paired" else "unpaired")

    async def installation_grant_v2(self):
        return grant

    monkeypatch.setattr(AuthorityClient, "status_v2", status_v2)
    monkeypatch.setattr(AuthorityClient, "installation_grant_v2", installation_grant_v2)
    monkeypatch.setattr(
        runtime_context, "verify_installed_package",
        lambda root, digest, *, available_cpu_features: InstalledPackageVerification(
            True, "verified", digest, "3.0.0-alpha1", "formal-alpha1"),
    )

    class Store:
        def __init__(self, *_):
            pass

        def close(self):
            pass

    class Port:
        installation_grant = grant

        def close(self):
            pass

    captured = []

    class Coordinator:
        def __init__(self, store, bootstrap, **kwargs):
            captured.append(kwargs["worker_result_fact_port"])

    monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
    monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
    installed = replace(installed, fence_port_factory=Port)
    context = runtime_context.RuntimeContext(
        installed.data_dir, package_root=tmp_path, dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    try:
        assert (await context.start_v2(installed)).status == "limited"
        assert len(captured) == 1
        if pairing == "paired":
            assert isinstance(captured[0], InstalledWorkerResultReadFactPort)
            assert captured[0]._grant == grant
            assert captured[0]._bundle is installed.admin_bundle
        else:
            assert captured[0] is None
    finally:
        await context.stop()


@pytest.mark.asyncio
async def test_v2_ingress_uses_installed_path_while_global_health_stays_limited(
    tmp_path, monkeypatch,
):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    clock = AdminIngressClockPolicy("admin:clock", 0.5, 2)
    encoding = AdminIngressEncodingPolicy(
        30, {"cpu_ms": 100}, "snapshot", "resource", "interval",
    )
    arrival = AdminD03ArrivalPolicy(
        30, {"cpu_ms": 10}, "snapshot", "resource",
    )
    trace = []
    admitted = False
    committed = False
    arrived = False

    class Store:
        def __init__(self, *_):
            pass

        def close(self):
            pass

    class Port:
        installation_grant = grant

        def close(self):
            pass

    class Coordinator:
        def __init__(self, store, bootstrap, **kwargs):
            self.bootstrap = bootstrap
            self.worker_thread = get_ident()

        def provision_namespace_v2(self, bootstrap, policy, *, operation_id):
            assert bootstrap is self.bootstrap
            trace.append("provision")
            return operation_id

        def commit_first_ingress_v2(self, bootstrap, host, policy, clock_policy, encoding_policy):
            nonlocal committed
            assert bootstrap is self.bootstrap
            assert policy is installed.installation_policy
            assert clock_policy is clock
            assert encoding_policy is encoding
            assert type(host) is IngressHostFacts
            assert get_ident() == self.worker_thread
            trace.append((host, ingress_host_fingerprint(host)))
            if not admitted:
                return SimpleNamespace(status="rejected", operation_id=None)
            status = "duplicate" if committed else "committed"
            committed = True
            return SimpleNamespace(status=status, operation_id="ingress-op")

        def commit_d03_message_arrival_v2(self, bootstrap, namespace, source_ref,
                                          policy, arrival_policy, clock_policy):
            nonlocal arrived
            assert bootstrap is self.bootstrap
            assert namespace == installed.installation_policy.namespace
            assert source_ref == "a" * 64
            assert policy is installed.installation_policy
            assert arrival_policy is arrival
            assert clock_policy is clock
            assert get_ident() == self.worker_thread
            trace.append(("arrival", source_ref))
            status = "duplicate" if arrived else "committed"
            arrived = True
            return SimpleNamespace(status=status, operation_id="arrival-op")

        def read_active_role_v2(self, *, namespace):
            assert namespace == installed.installation_policy.namespace
            assert get_ident() == self.worker_thread
            trace.append("trusted-role-read")
            plan = PersonaPlan(
                "plan", namespace, 1,
                (PersonaBlock("identity", "semantic_identity", "controlled", "read_only"),),
                (), True,
            )
            return ActiveRoleQualification(namespace, plan.head_id, plan, (), 1, 1)

        def read_active_scene_v2(self, *, namespace, scene_ref):
            assert scene_ref == "scene:conversation"
            trace.append("trusted-scene-read")
            return self.read_active_role_v2(namespace=namespace), RoleBinding(
                "binding:scene", "persona:persona", "companion", None, None,
                scene_ref, "scene", "private", ("norm:default",),
                1.0, None, 1, ("source:trusted",), 1, "active",
            )

    monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
    monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
    monkeypatch.setattr(
        runtime_context, "verify_installed_package",
        lambda root, digest, *, available_cpu_features: InstalledPackageVerification(
            True, "verified", digest, "3.0.0-alpha1", "formal-alpha1",
        ),
    )
    installed = assembly(
        tmp_path, grant, Port, clock=clock, encoding=encoding, arrival=arrival,
    )
    context = runtime_context.RuntimeContext(
        installed.data_dir, package_root=tmp_path, dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    assert (await context.start_v2(installed)).status == "limited"
    assert await context.handle_ingress(envelope(installed.installation_policy.namespace)) == IngressReceipt("unavailable")
    await context.provision_installed_namespace("provision-op")
    assert context.health.status == "limited"
    assert context.health.missing_capabilities == (
        "owner_guard", "active_role", "scene_binding", "dispatch",
    )
    assert context.v2_ingress_qualified
    assert await context.handle_ingress(envelope(installed.installation_policy.namespace)) == IngressReceipt("rejected")
    assert (await context.refresh_capabilities()).missing_capabilities == (
        "scene_binding", "dispatch",
    )
    assert (await context.refresh_capabilities(
        scene_ref="scene:conversation",
    )).missing_capabilities == ("scene_binding", "dispatch")
    assert "record exists" in context.health.detail
    admitted = True
    first = await context.handle_ingress(envelope(installed.installation_policy.namespace))
    second = await context.handle_ingress(envelope(installed.installation_policy.namespace))
    assert first == IngressReceipt("accepted", "ingress-op")
    assert second == IngressReceipt("duplicate", "ingress-op")
    assert trace.count(("arrival", "a" * 64)) == 2
    ingress_calls = [item for item in trace if isinstance(item, tuple)
                     and type(item[0]) is IngressHostFacts]
    assert len(ingress_calls) == 3
    assert ingress_calls[1] == ingress_calls[2]
    assert context.health.status == "limited"
    await context.stop()


@pytest.mark.asyncio
async def test_v2_ingress_missing_policy_stays_limited_and_unavailable(tmp_path, monkeypatch):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )

    class Store:
        def __init__(self, *_):
            pass

        def close(self):
            pass

    class Port:
        installation_grant = grant

        def close(self):
            pass

    class Coordinator:
        def __init__(self, store, bootstrap, **kwargs):
            self.bootstrap = bootstrap

        def provision_namespace_v2(self, bootstrap, policy, *, operation_id):
            assert bootstrap is self.bootstrap
            return operation_id

        def commit_first_ingress_v2(self, *_):
            pytest.fail("ingress called without administrator policies")

        def read_active_role_v2(self, *, namespace):
            raise UnavailableGuard("no Owner or active role")

    monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
    monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
    monkeypatch.setattr(
        runtime_context, "verify_installed_package",
        lambda root, digest, *, available_cpu_features: InstalledPackageVerification(
            True, "verified", digest, "3.0.0-alpha1", "formal-alpha1",
        ),
    )
    installed = assembly(tmp_path, grant, Port, clock=None, encoding=None)
    context = runtime_context.RuntimeContext(
        installed.data_dir, package_root=tmp_path, dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    await context.start_v2(installed)
    await context.provision_installed_namespace("provision-op")
    assert context.health.status == "limited"
    assert context.health.missing_capabilities == (
        "product_ingress", "owner_guard", "active_role", "scene_binding", "dispatch",
    )
    assert "ingress_clock, ingress_encoding" in context.health.detail
    assert not context.v2_ingress_qualified
    assert (await context.refresh_capabilities()).missing_capabilities == (
        "product_ingress", "owner_guard", "active_role", "scene_binding", "dispatch",
    )
    assert await context.handle_ingress(envelope(installed.installation_policy.namespace)) == IngressReceipt("unavailable")
    await context.stop()


def qualified_worker_context(tmp_path, worker):
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-trust", "2", "b" * 64,
    )
    installed = assembly(
        tmp_path, grant, object,
        clock=AdminIngressClockPolicy("admin:clock", 0.5, 2),
        encoding=AdminIngressEncodingPolicy(
            30, {"cpu_ms": 100}, "snapshot", "resource", "interval",
        ),
    )
    context = runtime_context.RuntimeContext(
        tmp_path / "data", dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    context._worker = worker
    context._v2_ingress = lambda *_: None
    context._v2_namespace_provisioned = True
    context._v2_namespace = installed.installation_policy.namespace
    context._v2_policy = installed.installation_policy
    context._v2_installation_grant = grant
    context.health = runtime_context.RuntimeHealth("limited", ("dispatch",))
    assert context.v2_ingress_qualified
    return context


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [
    "_v2_namespace_provisioned", "_v2_ingress", "_v2_policy",
    "_v2_installation_grant", "_v2_namespace", "_v2_missing_ingress_policies",
    "health",
])
async def test_v2_ingress_requires_each_installed_path_qualification(tmp_path, missing):
    class Worker:
        async def call(self, *_):
            pytest.fail("unqualified ingress reached graph worker")

    context = qualified_worker_context(tmp_path, Worker())
    invalid = {
        "_v2_namespace_provisioned": False,
        "_v2_ingress": None,
        "_v2_policy": None,
        "_v2_installation_grant": None,
        "_v2_namespace": NamespaceId("other", "persona"),
        "_v2_missing_ingress_policies": ("ingress_clock",),
        "health": runtime_context.RuntimeHealth("blocked", ("v2_fence_recovery",)),
    }
    setattr(context, missing, invalid[missing])
    assert not context.v2_ingress_qualified
    assert await context.handle_ingress(envelope(NamespaceId("bot", "persona"))) == IngressReceipt("unavailable")


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), [
    ("pending_confirmation", IngressReceipt("deferred", "ingress-op")),
    ("rejected", IngressReceipt("rejected")),
    ("conflict", IngressReceipt("unavailable")),
    ("stale", IngressReceipt("unavailable")),
    ("unexpected", IngressReceipt("unavailable")),
])
async def test_v2_receipt_mapping_preserves_uncertainty(tmp_path, status, expected):
    calls = []

    class Worker:
        async def call(self, function, host):
            calls.append((function, host))
            return SimpleNamespace(status=status, operation_id="ingress-op")

    context = qualified_worker_context(tmp_path, Worker())
    assert await context.handle_ingress(envelope(NamespaceId("bot", "persona"))) == expected
    assert len(calls) == 1
    assert type(calls[0][1]) is IngressHostFacts


@pytest.mark.asyncio
async def test_v2_worker_error_is_not_reported_as_rejection(tmp_path):
    class Worker:
        async def call(self, function, host):
            raise RuntimeError("worker outcome unknown")

    context = qualified_worker_context(tmp_path, Worker())
    with pytest.raises(RuntimeError, match="worker outcome unknown"):
        await context.handle_ingress(envelope(NamespaceId("bot", "persona")))


@pytest.mark.asyncio
async def test_v2_unknown_fence_outcome_is_deferred_with_original_operation_id(tmp_path):
    class Worker:
        async def call(self, function, host):
            raise FirstIngressOutcomeUnknown("ingress-op", "finish requires reconciliation")

    context = qualified_worker_context(tmp_path, Worker())
    assert await context.handle_ingress(envelope(NamespaceId("bot", "persona"))) == IngressReceipt(
        "deferred", "ingress-op",
    )
