"""Keep v2 content fences separate from authenticated prepared dispatch."""

import json

import pytest

from sylanne3.authority_service.contract import CONTENT_OPERATIONS, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import from_wire
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from sylanne3.runtime_contracts import NamespaceId


_PEER_A = MtlsPeerCredential("a" * 64)
_PEER_B = MtlsPeerCredential("b" * 64)
_REQUEST = {
    "protocol": AUTHORITY_V2_PROTOCOL,
    "profile_id": "profile-a",
    "plugin_name": "astrbot_plugin_sylanne",
    "host_api_version": "4.28.1",
    "manifest_sha256": "c" * 64,
}


@pytest.fixture
def rpc(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=True,
    )
    deletion_head = deletion.latest_head()
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, action, namespace, holder:
            credential in (_PEER_A, _PEER_B),
        deletion_verifier=lambda ns, before, current, phase:
            current == JournalHead(deletion_head.journal_id, deletion_head.seq,
                                   deletion_head.chain_digest) and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    core.register_namespace(
        _PEER_A, "ns-a", "holder-a",
        JournalHead(deletion_head.journal_id, deletion_head.seq,
                    deletion_head.chain_digest),
        JournalHead("execution-a", 0, "genesis"),
    )
    core.seal_v2_only(_PEER_A)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a",
    )
    server = AuthorityRpcServer(
        core,
        administrator_authorizer=lambda credential, action, target, profile:
            credential in (_PEER_A, _PEER_B),
        publisher_manifest_verifier=lambda *args: True,
        v2_fences=service,
        installations_v2={
            (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
                f"installation-{name}", "holder-a", "policy-a",
                "capabilities-v2", "c" * 64)
            for peer, name in ((_PEER_A, "a"), (_PEER_B, "b"))
        },
        namespace_bindings_v2={
            (_PEER_A.certificate_sha256, "profile-a",
             NamespaceId("bot-a", "persona-a")): "ns-a",
        },
    )
    try:
        yield server
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def paired(server, peer, channel):
    handshake = server._dispatch_for_test("handshake", _REQUEST, peer, channel)
    binding = handshake["channel_binding_sha256"]

    def call(method, command):
        return server._dispatch_for_test(
            method, _REQUEST, peer, channel,
            handshake_binding=binding, command=command,
        )

    return call


def begin_command(anchor, operation, operation_id):
    return {
        "namespace": "ns-a", "holder": "holder-a", "operation": operation,
        "operation_id": operation_id, "expected_anchor": anchor,
    }


def test_all_contract_content_operations_except_dispatch_round_trip(rpc):
    call = paired(rpc, _PEER_A, b"channel-a")
    anchor = call("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    for operation in sorted(CONTENT_OPERATIONS - {"dispatch"}):
        permit_wire = call(
            "begin_fence", begin_command(anchor, operation, f"begin-{operation}"),
        )["permit"]
        permit = from_wire(permit_wire)
        assert permit.operation == operation
        assert permit.subject == "mtls:sha256:" + _PEER_A.certificate_sha256
        assert call("validate_fence", {"permit": permit_wire})["permit"] == permit_wire
        assert call("finish_fence", {
            "permit": permit_wire, "request_id": f"finish-{operation}",
            "request_digest": "sha256:" + "d" * 64,
        })["finished"] is True
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("validate_fence", {"permit": permit_wire})


def test_begin_rejects_dispatch_unknown_operations_and_extra_fields(rpc):
    call = paired(rpc, _PEER_A, b"channel-a")
    anchor = call("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    for operation in ("dispatch", "delete", "unknown"):
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("begin_fence", begin_command(anchor, operation, "attempt-a"))
    for extra in ({"subject": "mtls:sha256:" + _PEER_B.certificate_sha256},
                  {"effect_id": "effect-a"}, {"footprint": {}}):
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("begin_fence", {
                **begin_command(anchor, "write", "attempt-a"), **extra,
            })
    assert call("begin_fence", begin_command(anchor, "write", "attempt-a"))["permit"]


def test_other_mtls_peer_cannot_validate_or_finish_content_permit(rpc):
    first = paired(rpc, _PEER_A, b"channel-a")
    second = paired(rpc, _PEER_B, b"channel-b")
    anchor = first("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    with pytest.raises(RuntimeError, match="authority unavailable"):
        second("current_anchor", {"namespace": "ns-a"})
    permit = first("begin_fence", begin_command(anchor, "model_egress", "egress-a"))["permit"]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        second("validate_fence", {"permit": permit})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        second("finish_fence", {
            "permit": permit, "request_id": "finish-a",
            "request_digest": "sha256:" + "d" * 64,
        })
    assert first("validate_fence", {"permit": permit})["permit"] == permit
    with pytest.raises(RuntimeError, match="authority unavailable"):
        first("validate_fence", {"permit": permit, "subject": permit["subject"]})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        first("finish_fence", {
            "permit": permit, "request_id": "finish-a",
            "request_digest": "sha256:" + "d" * 64, "subject": permit["subject"],
        })


def test_dispatch_shaped_permit_is_rejected_by_remote_lifecycle(rpc):
    call = paired(rpc, _PEER_A, b"channel-a")
    anchor = call("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    content_permit = call("begin_fence", begin_command(anchor, "adopt", "adopt-a"))["permit"]
    dispatch_permit = {
        **content_permit, "operation": "dispatch", "effect_id": "effect-a",
        "command_digest": "sha256:" + "c" * 64,
        "footprint_digest": "sha256:" + "f" * 64,
    }
    assert from_wire(dispatch_permit).operation == "dispatch"
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("validate_fence", {"permit": dispatch_permit})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("finish_fence", {
            "permit": dispatch_permit, "request_id": "finish-a",
            "request_digest": "sha256:" + "d" * 64,
        })
    assert call("validate_fence", {"permit": content_permit})["permit"] == content_permit


def test_prepared_dispatch_rpc_retries_exact_mutation_and_rejects_other_peer(rpc):
    call = paired(rpc, _PEER_A, b"channel-a")
    other = paired(rpc, _PEER_B, b"channel-b")
    anchor = call("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    footprint = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",),
    )
    command = {
        "namespace": "ns-a", "holder": "holder-a", "operation_id": "dispatch-a",
        "expected_anchor": anchor, "effect_id": "effect-a",
        "command_digest": "sha256:" + "d" * 64,
        "footprint": json.loads(footprint._json()),
    }
    permit = call("begin_dispatch_fence", command)["permit"]
    assert call("begin_dispatch_fence", command)["permit"] == permit
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("begin_dispatch_fence", {
            **command, "command_digest": "sha256:" + "e" * 64,
        })
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("begin_dispatch_fence", {**command, "namespace": "ns-other"})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        other("begin_dispatch_fence", command)
    prepare = {"permit": permit, "mutation_id": "mutation-a",
               "footprint": command["footprint"]}
    first = call("execution_prepare", prepare)
    assert from_wire(first["receipt"]).durable_state == "committed"
    assert from_wire(first["permit"]).revision == 1
    assert call("execution_prepare", prepare) == first
    assert rpc._v2_fences["ns-a"].execution.verified_head().seq == 1
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("execution_prepare", {**prepare, "mutation_id": "mutation-b"})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        other("execution_prepare", prepare)


def test_dispatch_rpc_rechecks_d08_and_rejects_unshaped_footprint(rpc):
    call = paired(rpc, _PEER_A, b"channel-a")
    anchor = call("current_anchor", {"namespace": "ns-a"})
    anchor.pop("channel_binding_sha256")
    footprint = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a")
    command = {
        "namespace": "ns-a", "holder": "holder-a", "operation_id": "dispatch-a",
        "expected_anchor": anchor, "effect_id": "effect-a",
        "command_digest": "sha256:" + "d" * 64,
        "footprint": json.loads(footprint._json()),
    }
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("begin_dispatch_fence", {
            **command, "footprint": {**command["footprint"], "unknown": "field"},
        })
    rpc._core._dispatch_verifier = lambda *args: False
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call("begin_dispatch_fence", command)
    assert rpc._v2_fences["ns-a"].execution.verified_head().seq == 0
