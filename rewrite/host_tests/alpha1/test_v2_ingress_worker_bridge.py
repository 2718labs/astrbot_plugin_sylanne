"""The v2 host bridge submits one typed ingress call to the graph worker."""

from __future__ import annotations

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
from sylanne3.graph_coordinator import (
    FirstIngressOutcomeUnknown, IngressHostFacts, ingress_host_fingerprint,
)
from sylanne3.host.authority_profile import AdminIngressClockPolicy, AdminIngressEncodingPolicy
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import InstallationGrantV2, NamespaceId

if installed_stub:
    del sys.modules["sylanne3.host"]


def assembly(root, grant, port_factory, *, clock, encoding):
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
        policy, grant, b"k" * 32, b"d" * 32, port_factory,
        root, root / "data", frozenset({"avx2"}), clock, encoding,
    )


def envelope(namespace, learned_at=11.0):
    return HostIngressEnvelope(
        namespace, "platform", "conversation", "sender", "message", "hello",
        10.0, learned_at, "private",
        SourceLineage("a" * 64, "reported", "platform", "external_report", "reported_claim"),
    )


@pytest.mark.asyncio
async def test_v2_ingress_requires_provision_and_policies_then_uses_one_worker_call(
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
    trace = []

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
            assert bootstrap is self.bootstrap
            assert policy is installed.installation_policy
            assert clock_policy is clock
            assert encoding_policy is encoding
            assert type(host) is IngressHostFacts
            assert get_ident() == self.worker_thread
            trace.append((host, ingress_host_fingerprint(host)))
            status = "committed" if len(trace) == 2 else "duplicate"
            return SimpleNamespace(status=status, operation_id="ingress-op")

    monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
    monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
    monkeypatch.setattr(
        runtime_context, "verify_installed_package",
        lambda root, digest, *, available_cpu_features: InstalledPackageVerification(
            True, "verified", digest, "3.0.0-alpha1", "formal-alpha1",
        ),
    )
    installed = assembly(tmp_path, grant, Port, clock=clock, encoding=encoding)
    context = runtime_context.RuntimeContext(
        installed.data_dir, package_root=tmp_path, dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    assert (await context.start_v2(installed)).status == "limited"
    assert await context.handle_ingress(envelope(installed.installation_policy.namespace)) == IngressReceipt("unavailable")
    await context.provision_installed_namespace("provision-op")
    assert context.health.status == "limited"
    assert context.health.missing_capabilities == ("dispatch",)
    first = await context.handle_ingress(envelope(installed.installation_policy.namespace))
    second = await context.handle_ingress(envelope(installed.installation_policy.namespace, 12.0))
    assert first == IngressReceipt("accepted", "ingress-op")
    assert second == IngressReceipt("duplicate", "ingress-op")
    assert trace[1][1] == trace[2][1]
    assert trace[1][0].learned_at == 11.0
    assert trace[2][0].learned_at == 12.0
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
    assert context.health.missing_capabilities == ("product_ingress", "dispatch")
    assert "ingress_clock, ingress_encoding" in context.health.detail
    assert await context.handle_ingress(envelope(installed.installation_policy.namespace)) == IngressReceipt("unavailable")
    await context.stop()


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

    context = runtime_context.RuntimeContext(
        tmp_path / "data", dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    context._worker = Worker()
    context._v2_ingress = lambda *_: None
    context._v2_namespace_provisioned = True
    assert await context.handle_ingress(envelope(NamespaceId("bot", "persona"))) == expected
    assert len(calls) == 1
    assert type(calls[0][1]) is IngressHostFacts


@pytest.mark.asyncio
async def test_v2_worker_error_is_not_reported_as_rejection(tmp_path):
    class Worker:
        async def call(self, function, host):
            raise RuntimeError("worker outcome unknown")

    context = runtime_context.RuntimeContext(
        tmp_path / "data", dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    context._worker = Worker()
    context._v2_ingress = lambda *_: None
    context._v2_namespace_provisioned = True
    with pytest.raises(RuntimeError, match="worker outcome unknown"):
        await context.handle_ingress(envelope(NamespaceId("bot", "persona")))


@pytest.mark.asyncio
async def test_v2_unknown_fence_outcome_is_deferred_with_original_operation_id(tmp_path):
    class Worker:
        async def call(self, function, host):
            raise FirstIngressOutcomeUnknown("ingress-op", "finish requires reconciliation")

    context = runtime_context.RuntimeContext(
        tmp_path / "data", dependencies=None,
        domains=SimpleNamespace(complete=True, registrations={}, type_registry=object()),
    )
    context._worker = Worker()
    context._v2_ingress = lambda *_: None
    context._v2_namespace_provisioned = True
    assert await context.handle_ingress(envelope(NamespaceId("bot", "persona"))) == IngressReceipt(
        "deferred", "ingress-op",
    )
