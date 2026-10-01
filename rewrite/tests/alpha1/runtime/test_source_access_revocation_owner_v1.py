"""Owner withdrawal commits the access head and barrier as one graph operation."""

from dataclasses import asdict
from types import MethodType, SimpleNamespace
import json
import time
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.contracts import Event, Scope, canonical_json
from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphVersion, GraphWrite
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import canonical_digest
from tests.alpha1.d12.test_owner_graph_lease import (
    NAMESPACE, OWNER_REQUEST, OWNER_TOKEN, owner_graph,
)


def _case(owner_graph):
    graph, coordinator, bootstrap, port, grant_key, _ = owner_graph
    with graph._lock:
        db = graph._db
        grant = json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (grant_key.token,),
        ).fetchone()[0])
        grant["capabilities"] = ["workbench.correct", "workbench.read"]
        grant["purposes"] = ["audit"]
        proof_row = db.execute(
            "SELECT request_digest,graph_receipt_digest "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
            NAMESPACE.as_tuple,
        ).fetchone()
        proof = OwnerGraphCommitProofV1(
            NAMESPACE, "issue-1", proof_row[0], grant["grant_id"],
            "sha256:" + canonical_digest(grant), "graph-incarnation",
            1, 1, 1, proof_row[1],
        )
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (canonical_json(grant), grant_key.token))
        db.execute(
            "UPDATE graph_owner_issue_operations_v1 SET grant_digest=?,proof_json=? "
            "WHERE bot=? AND persona=?",
            (proof.grant_digest, canonical_json(asdict(proof)), *NAMESPACE.as_tuple),
        )
    port.guard = OwnerAuthorizationGuardV1(
        "authority", "installation", NAMESPACE, 1,
        owner_contract_digest(proof), 0, 0,
    )
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d06", "d11"), purpose="audit", audience="owner",
        activation_generation=1, owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST,
    )
    port.installation_grant = SimpleNamespace(
        installation_id="installation", subject="subject", authority_id="authority")
    operations = {}

    def get_fence_operation(self, *, operation_id, **_):
        self._outside_graph()
        return operations[operation_id]

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self._outside_graph()
        assert namespace == NAMESPACE and operation == "write"
        assert expected_anchor == self.anchor and self.active is None
        permit = FencePermitV2(
            self.anchor.authority_id, authority_namespace, "subject", holder,
            generation, operation, operation_id, "x" * 48, 1, 0, self.anchor)
        self.active = permit
        operations[operation_id] = (permit, "active")
        return permit

    def finish_fence(self, scope, *, request_id, request_digest):
        self._outside_graph()
        assert self.active == scope.permit
        assert request_id.startswith(("finish:", "abort:"))
        assert request_digest.startswith("sha256:")
        operations[scope.operation_id] = (scope.permit, "finished")
        self.finishes += 1
        self.active = None

    def read_ingress_clock(self, _policy):
        self._outside_graph()
        return SimpleNamespace(monotonic_after_seconds=time.monotonic(),
                               utc_upper_bound_seconds=10.0)

    port.get_fence_operation = MethodType(get_fence_operation, port)
    port.begin_fence = MethodType(begin_fence, port)
    port.finish_fence = MethodType(finish_fence, port)
    port.read_ingress_clock = MethodType(read_ingress_clock, port)
    source = source_key(*NAMESPACE.as_tuple, "source-1")
    access = access_key(*NAMESPACE.as_tuple, "source-1")
    original = SourceRecord(
        "source-1", "private", "speaker", "reported", "reported", 1.0,
        2.0, "family", ("owner",), ("context",),
    )
    snapshot = GraphStore.graph_snapshot(
        graph, (source, access), _capability=graph._coordinator_capability)
    GraphStore.graph_commit(
        graph, GraphCandidate(
            Event(Scope(*NAMESPACE.as_tuple, "seed"), "seed-source", 2.0,
                  "seed", {}), snapshot.versions,
            (GraphWrite(source, original.to_dict()),
             GraphWrite(access, {
                 "source_id": "source-1", "audiences": ["owner"],
                 "purposes": ["context"], "status": "active", "recorded_at": 2.0,
             }, (source,))), snapshot.epochs,
        ), _capability=graph._coordinator_capability,
    )
    with graph._lock:
        db = graph._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata = graph.graph_recovery_metadata(
                NAMESPACE, _capability=graph._coordinator_capability)
            graph.cas_graph_recovery_metadata(
                metadata, metadata.requirements,
                _capability=graph._coordinator_capability)
            for kind in ("scheme", "operator", "policy"):
                db.execute(
                    "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                    "VALUES(?,?,?,?,?)", (*NAMESPACE.as_tuple, kind, "current", "1"))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return graph, coordinator, port, authority, lease, source, access


def test_owner_revocation_advances_head_and_access_barrier_atomically(owner_graph):
    graph, coordinator, port, authority, lease, source, access = _case(owner_graph)
    request = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 3.0)
    before = graph._db.execute(
        "SELECT access_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
        NAMESPACE.as_tuple).fetchone()[0]
    receipt = coordinator.revoke_source_access_v1(authority, lease, request)
    assert receipt.source_id == "source-1"
    assert receipt.source_revision == 1 and receipt.access_revision == 2
    assert receipt.access_epoch == before + 1
    assert port.finishes >= 2
    assert graph._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (source.token,),
    ).fetchone()[0] == canonical_json(SourceRecord(
        "source-1", "private", "speaker", "reported", "reported", 1.0,
        2.0, "family", ("owner",), ("context",)).to_dict())
    withdrawn = json.loads(graph._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (access.token,),
    ).fetchone()[0])
    assert withdrawn["status"] == "withdrawn"
    assert coordinator.revoke_source_access_v1(authority, lease, request) == receipt


def test_owner_revocation_rejects_wrong_actor_and_missing_proof(owner_graph):
    _, coordinator, _, authority, lease, _, _ = _case(owner_graph)
    wrong = SourceAccessRevocationRequest(
        "source-1", "other-owner", str(uuid4()), 3.0)
    with pytest.raises(AuthorityDenied):
        coordinator.revoke_source_access_v1(authority, lease, wrong)
    proofs = coordinator._GraphCoordinator__owner_session_proofs
    proofs.pop(lease)
    valid = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 3.0)
    with pytest.raises(AuthorityDenied):
        coordinator.revoke_source_access_v1(authority, lease, valid)


def test_second_withdrawal_rejects_without_advancing_barrier(owner_graph):
    graph, coordinator, _, authority, lease, _, access = _case(owner_graph)
    first = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 3.0)
    coordinator.revoke_source_access_v1(authority, lease, first)
    next_request = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 4.0)
    before = graph._db.execute(
        "SELECT access_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
        NAMESPACE.as_tuple).fetchone()
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.revoke_source_access_v1(authority, lease, next_request)
    assert graph._db.execute(
        "SELECT access_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
        NAMESPACE.as_tuple).fetchone() == before
    assert graph._db.execute(
        "SELECT revision FROM graph_atoms WHERE token=?", (access.token,),
    ).fetchone() == (2,)


def test_lost_finish_ack_recovers_same_committed_receipt(owner_graph):
    graph, coordinator, port, authority, lease, _, access = _case(owner_graph)
    request = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 3.0)
    original_finish = port.finish_fence
    failed = False

    def lose_once(scope, *, request_id, request_digest):
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("finish ack lost")
        return original_finish(scope, request_id=request_id,
                               request_digest=request_digest)

    port.finish_fence = lose_once
    with pytest.raises(RuntimeError, match="finish ack lost"):
        coordinator.revoke_source_access_v1(authority, lease, request)
    receipt = coordinator.revoke_source_access_v1(authority, lease, request)
    assert receipt.access_revision == 2
    assert graph._db.execute(
        "SELECT revision FROM graph_atoms WHERE token=?", (access.token,),
    ).fetchone() == (2,)
