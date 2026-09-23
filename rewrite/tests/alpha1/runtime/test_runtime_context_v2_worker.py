"""Pairing starts graph ownership but does not admit a namespace."""

import asyncio
from pathlib import Path
import sys
from threading import get_ident
from types import ModuleType, SimpleNamespace

import pytest

host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[3] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package

from sylanne3 import runtime_context
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
from sylanne3.runtime_contracts import InstallationGrantV2

if installed_stub:
    del sys.modules["sylanne3.host"]


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
            lambda root, digest: InstalledPackageVerification(
                True, "verified", digest, "3.0.0-alpha1", "formal-alpha1",
            ),
        )

        class Store:
            def __init__(self, *_):
                trace.append(("store_open", get_ident()))

            def close(self):
                trace.append(("store_close", get_ident()))

        class Port:
            def __init__(self):
                trace.append(("port_open", get_ident()))

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
                trace.append(("coordinator_open", get_ident()))

        monkeypatch.setattr(runtime_context, "ProductionGraphStore", Store)
        monkeypatch.setattr(runtime_context, "GraphCoordinator", Coordinator)
        domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
        context = runtime_context.RuntimeContext(
            tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
        )
        health = await context.start_v2(grant, Port)
        assert health.status == "limited"
        assert health.missing_capabilities == ("namespace_activation",)
        assert (await context.start()).status == "limited"
        worker = context._worker
        if unresolved_fence:
            with pytest.raises(V2FenceOutcomeUnknown, match="fence result unknown"):
                await context.stop()
            assert context.health.status == "blocked"
            assert context.health.missing_capabilities == ("v2_fence_recovery",)
            assert (await context.start_v2(grant, Port)).status == "blocked"
            assert (await context.start()).status == "blocked"
            assert (await context.stop()).status == "blocked"
        else:
            assert (await context.stop()).status == "stopped"
        assert not worker._thread.is_alive()
        assert [event for event, _ in trace] == [
            "store_open", "port_open", "coordinator_open", "port_close", "store_close",
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
            lambda root, digest: calls.append((root, digest)) or verification,
        )
        domains = SimpleNamespace(complete=True, registrations={}, type_registry=object())
        context = runtime_context.RuntimeContext(
            tmp_path / "data", package_root=tmp_path, dependencies=None, domains=domains,
        )
        health = await context.start_v2(grant, lambda: pytest.fail("port opened"))
        assert health.status == "blocked"
        assert health.missing_capabilities == ("installed_package",)
        assert health.detail == detail
        assert calls == [(tmp_path, grant.manifest_digest)]
        assert not (tmp_path / "data").exists()

    asyncio.run(scenario())
