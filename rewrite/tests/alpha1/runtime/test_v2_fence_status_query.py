"""A paired v2 client may reconcile its own durable content fence state."""

import asyncio
from dataclasses import replace
from pathlib import Path
import sys
from types import ModuleType

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import FencePermitV2, to_wire
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
)

host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[3] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package
from sylanne3.host.authority_client import (
    AuthorityHandshake, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.v2_fence_port import V2FencePort
if installed_stub:
    del sys.modules["sylanne3.host"]


PEER_A = MtlsPeerCredential("a" * 64)
PEER_B = MtlsPeerCredential("b" * 64)
SUBJECT_A = "mtls:sha256:" + PEER_A.certificate_sha256
NAMESPACE = NamespaceId("bot-a", "persona-a")
REQUEST_WIRE = {
    "protocol": AUTHORITY_V2_PROTOCOL, "profile_id": "profile-a",
    "plugin_name": "astrbot_plugin_sylanne", "host_api_version": "4.28.1",
    "manifest_sha256": "c" * 64,
}


@pytest.fixture
def service_rpc(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a", create=True)
    head = deletion.latest_head()
    denial = set()
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, action, namespace, holder:
            credential in (PEER_A, PEER_B) and action not in denial,
        deletion_verifier=lambda ns, before, current, phase:
            current == JournalHead(head.journal_id, head.seq, head.chain_digest)
            and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    core.register_namespace(
        PEER_A, "ns-a", "holder-a",
        JournalHead(head.journal_id, head.seq, head.chain_digest),
        JournalHead("execution-a", 0, "genesis"))
    core.seal_v2_only(PEER_A)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution, namespace="ns-a")
    installations = {
        (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            f"installation-{name}", "holder-a", "policy-a", "capabilities-v2", "c" * 64)
        for peer, name in ((PEER_A, "a"), (PEER_B, "b"))
    }
    bindings = {
        (peer.certificate_sha256, "profile-a", NAMESPACE): "ns-a"
        for peer in (PEER_A, PEER_B)
    }

    def server():
        return AuthorityRpcServer(
            core, administrator_authorizer=lambda credential, action, target, profile:
                credential in (PEER_A, PEER_B),
            publisher_manifest_verifier=lambda *args: True,
            v2_fences=service, installations_v2=installations,
            namespace_bindings_v2=bindings,
        )

    try:
        yield service, fences, server, denial
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def paired(server, peer, channel):
    binding = server._dispatch_for_test("handshake", REQUEST_WIRE, peer, channel)[
        "channel_binding_sha256"]

    def call(method, command):
        return server._dispatch_for_test(
            method, REQUEST_WIRE, peer, channel,
            handshake_binding=binding, command=command)

    return call


def test_status_survives_new_rpc_session_and_hides_other_subject(service_rpc):
    service, _, server_factory, denial = service_rpc
    first = paired(server_factory(), PEER_A, b"old-channel")
    anchor = first("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    permit_wire = first("begin_fence", {
        "namespace": "ns-a", "holder": "holder-a", "operation": "write",
        "operation_id": "write-a", "expected_anchor": anchor,
    })["permit"]

    restarted = server_factory()
    own = paired(restarted, PEER_A, b"new-channel")
    other = paired(restarted, PEER_B, b"other-channel")
    query = {"namespace": "ns-a", "operation_id": "write-a"}
    active = own("get_fence_operation", query)
    assert active["state"] == "active" and active["permit"] == permit_wire
    assert active["channel_binding_sha256"] != first(
        "installation_grant_v2", {})["channel_binding_sha256"]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        other("get_fence_operation", query)
    with pytest.raises(RuntimeError, match="authority unavailable"):
        own("get_fence_operation", {"namespace": "ns-other", "operation_id": "write-a"})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        own("get_fence_operation", {"namespace": "ns-a", "operation_id": "missing"})

    own("finish_fence", {
        "permit": permit_wire, "request_id": "finish-a",
        "request_digest": "sha256:" + "d" * 64,
    })
    assert own("get_fence_operation", query)["state"] == "finished"
    denial.add("write")
    with pytest.raises(RuntimeError, match="authority unavailable"):
        own("get_fence_operation", query)


def test_status_rpc_rejects_dispatch_and_caller_supplied_subject(service_rpc):
    service, fences, server_factory, _ = service_rpc
    call = paired(server_factory(), PEER_A, b"channel-a")
    anchor = service.current_anchor(credential=PEER_A, subject=SUBJECT_A)
    fences.begin_fence(
        subject=SUBJECT_A, holder="holder-a", operation="dispatch",
        operation_id="dispatch-a", current_anchor=anchor, effect_id="effect-a",
        command_digest="sha256:" + "c" * 64,
        footprint_digest="sha256:" + "f" * 64,
    )
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("get_fence_operation", {"namespace": "ns-a", "operation_id": "dispatch-a"})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("get_fence_operation", {
            "namespace": "ns-a", "operation_id": "dispatch-a", "subject": SUBJECT_A})


HANDSHAKE = AuthorityHandshake("paired", "authority-a", "subject-a", "a" * 64, True)
GRANT = InstallationGrantV2(
    "authority-a", "subject-a", "holder-a", "installation-a", "c" * 64,
    "policy-a", "capabilities-v2", "a" * 64)
ANCHOR = RestoreAnchor(
    "authority-a", "ns-a", 1, "deletion-a", 0, "genesis",
    "execution-a", 0, "genesis", 0, "proof-a")
PERMIT = FencePermitV2(
    "authority-a", "ns-a", "subject-a", "holder-a", 1,
    "write", "write-a", "a" * 32, 1, 0, ANCHOR)


def test_transport_rejects_unbound_or_malformed_status(tmp_path, monkeypatch):
    profile = AuthorityTlsProfile(
        "profile-a", "localhost", 443, "localhost", "authority-a",
        tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "key.pem")
    transport = MtlsAuthorityTransport({"profile-a": profile})
    request = AuthorityProvisioningRequest(
        "sylanne3.authority.v1", "profile-a", "astrbot_plugin_sylanne",
        "4.28.1", tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))
    response = {
        "permit": to_wire(PERMIT), "state": "active",
        "channel_binding_sha256": HANDSHAKE.channel_binding_sha256,
    }

    async def rpc(*args, **kwargs):
        assert args[2] == "get_fence_operation"
        assert args[3] == {"namespace": "ns-a", "operation_id": "write-a"}
        assert kwargs["protocol"] == AUTHORITY_V2_PROTOCOL
        return response

    monkeypatch.setattr(transport, "_content_rpc", rpc)

    def query():
        return asyncio.run(transport.v2_get_content_fence_operation(
            request, HANDSHAKE, namespace="ns-a", operation_id="write-a"))

    assert query() == (PERMIT, "active")
    for invalid in (
        {**response, "state": "pending"},
        {**response, "permit": to_wire(replace(PERMIT, operation_id="other"))},
        {**response, "permit": to_wire(replace(PERMIT, subject="other"))},
        {**response, "permit": {**to_wire(PERMIT), "operation": "dispatch"}},
        {**response, "channel_binding_sha256": "b" * 64},
        {**response, "extra": True},
    ):
        response = invalid
        with pytest.raises(RuntimeError, match="status response|binding"):
            query()


class StatusTransport:
    def __init__(self, profiles):
        self.mapping = "ns-a"
        self.answer = (PERMIT, "finished")
        self.queries = []

    async def handshake(self, request, *, protocol):
        assert protocol == AUTHORITY_V2_PROTOCOL
        return HANDSHAKE

    async def installation_grant_v2(self, request, handshake):
        return GRANT

    async def v2_namespace_bootstrap(self, request, handshake, namespace):
        return NamespaceBootstrapV2(
            "authority-a", NAMESPACE, self.mapping, "holder-a", 1,
            "active", NamespaceRuntimeState.ACTIVE,
            replace(ANCHOR, namespace=self.mapping), ())

    async def v2_get_content_fence_operation(self, request, handshake, *, namespace,
                                              operation_id):
        self.queries.append((namespace, operation_id))
        return self.answer

    async def close(self):
        pass


def test_port_queries_only_current_mapped_namespace(tmp_path):
    profile = AuthorityTlsProfile(
        "profile-a", "localhost", 443, "localhost", "authority-a",
        tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "key.pem")
    request = AuthorityProvisioningRequest(
        "sylanne3.authority.v1", "profile-a", "astrbot_plugin_sylanne",
        "4.28.1", tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))
    transport = StatusTransport({"profile-a": profile})
    with V2FencePort(request, {"profile-a": profile}, GRANT,
                     transport_factory=lambda _: transport) as port:
        assert port.get_fence_operation(
            namespace=NAMESPACE, authority_namespace="ns-a", operation_id="write-a"
        ) == (PERMIT, "finished")
        assert transport.queries == [("ns-a", "write-a")]
        transport.mapping = "ns-other"
        with pytest.raises(RuntimeError, match="not active or mapped"):
            port.get_fence_operation(
                namespace=NAMESPACE, authority_namespace="ns-a", operation_id="write-a")
        assert transport.queries == [("ns-a", "write-a")]
