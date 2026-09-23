"""RPC routing uses administrator-installed v2 services per namespace."""

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal


_ADMIN = MtlsPeerCredential("0" * 64)
_PEERS = {
    "ns-a": MtlsPeerCredential("a" * 64),
    "ns-b": MtlsPeerCredential("b" * 64),
}
_REQUEST = {
    "protocol": AUTHORITY_V2_PROTOCOL,
    "profile_id": "profile-a",
    "plugin_name": "astrbot_plugin_sylanne",
    "host_api_version": "4.28.1",
    "manifest_sha256": "c" * 64,
}


@pytest.fixture
def installed(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    deletion_head = deletion.latest_head()
    head = JournalHead(deletion_head.journal_id, deletion_head.seq,
                       deletion_head.chain_digest)
    executions = {
        namespace: AuthorityV2ExecutionJournal(
            tmp_path / f"{namespace}-execution.db", namespace=namespace,
            journal_id=f"{namespace}-execution", create=True,
        ) for namespace in _PEERS
    }

    def authorize(credential, action, namespace, holder):
        if action in {"install", "seal_v2_only"}:
            return credential == _ADMIN
        return credential == _PEERS.get(namespace)

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase:
            current == head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            executions[ns].verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    for namespace in _PEERS:
        core.register_namespace(
            _ADMIN, namespace, f"holder-{namespace[-1]}", head,
            JournalHead(f"{namespace}-execution", 0, "genesis"),
        )
    core.seal_v2_only(_ADMIN)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    services = {
        namespace: AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard,
            execution=executions[namespace], namespace=namespace,
        ) for namespace in _PEERS
    }
    routing = dict(services)
    server = AuthorityRpcServer(
        core,
        administrator_authorizer=lambda credential, action, target, profile:
            credential in _PEERS.values(),
        publisher_manifest_verifier=lambda *args: True,
        v2_fences=routing,
    )
    try:
        yield server, services, routing, core
    finally:
        core.close()
        deletion.close()
        guard.close()
        for execution in executions.values():
            execution.close()


def paired(server, namespace):
    peer = _PEERS[namespace]
    channel = f"channel-{namespace}".encode()
    binding = server._dispatch_for_test(
        "handshake", _REQUEST, peer, channel,
    )["channel_binding_sha256"]

    def call(method, command):
        return server._dispatch_for_test(
            method, _REQUEST, peer, channel,
            handshake_binding=binding, command=command,
        )

    return call


def anchor(call, namespace):
    result = call("current_anchor", {"namespace": namespace})
    result.pop("channel_binding_sha256")
    return result


def begin(call, namespace, expected_anchor, operation, operation_id):
    return call("begin_fence", {
        "namespace": namespace, "holder": f"holder-{namespace[-1]}",
        "operation": operation, "operation_id": operation_id,
        "expected_anchor": expected_anchor,
    })["permit"]


def test_distinct_services_route_and_preserve_namespace_authorization(installed):
    server, services, routing, _ = installed
    first = paired(server, "ns-a")
    second = paired(server, "ns-b")
    routing.clear()  # Constructor copied the administrator mapping.
    anchor_a = anchor(first, "ns-a")
    anchor_b = anchor(second, "ns-b")
    assert anchor_a["namespace"] == "ns-a"
    assert anchor_b["namespace"] == "ns-b"
    assert services["ns-a"] is not services["ns-b"]
    permit_a = begin(first, "ns-a", anchor_a, "read", "read-a")
    permit_b = begin(second, "ns-b", anchor_b, "write", "write-b")
    assert permit_a["subject"] == "mtls:sha256:" + _PEERS["ns-a"].certificate_sha256
    assert permit_b["subject"] == "mtls:sha256:" + _PEERS["ns-b"].certificate_sha256
    assert first("validate_fence", {"permit": permit_a})["permit"] == permit_a
    assert second("validate_fence", {"permit": permit_b})["permit"] == permit_b
    for call, own_permit, other_permit in (
        (first, permit_a, permit_b), (second, permit_b, permit_a),
    ):
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("validate_fence", {"permit": other_permit})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("finish_fence", {
                "permit": other_permit, "request_id": "wrong-finish",
                "request_digest": "sha256:" + "d" * 64,
            })
        assert call("validate_fence", {"permit": own_permit})["permit"] == own_permit
    assert first("finish_fence", {
        "permit": permit_a, "request_id": "finish-a",
        "request_digest": "sha256:" + "d" * 64,
    })["finished"] is True
    assert second("finish_fence", {
        "permit": permit_b, "request_id": "finish-b",
        "request_digest": "sha256:" + "d" * 64,
    })["finished"] is True


def test_cross_namespace_commands_and_unmapped_namespace_fail_closed(installed):
    server, services, _, core = installed
    first = paired(server, "ns-a")
    anchor_a = anchor(first, "ns-a")
    for namespace in ("ns-b", "ns-missing"):
        with pytest.raises(RuntimeError, match="authority unavailable"):
            first("current_anchor", {"namespace": namespace})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            begin(first, namespace, anchor_a, "read", f"attempt-{namespace}")
    with pytest.raises(TypeError, match="must match"):
        AuthorityRpcServer(
            core, administrator_authorizer=lambda *args: True,
            publisher_manifest_verifier=lambda *args: True,
            v2_fences={"ns-b": services["ns-a"]},
        )
