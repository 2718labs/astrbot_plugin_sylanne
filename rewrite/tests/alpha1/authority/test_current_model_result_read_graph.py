"""Result-read verifier against a committed Owner graph and durable source ACL."""

from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import _owner_issue_case
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent

from sylanne3.authority_service.current_model_result_read_graph_verifier import (
    PinnedCurrentModelResultReadGraphVerifier,
)
from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadRequestV1
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import owner_grant_key
from sylanne3.memory_types import SourceRecord, access_key, source_key


def test_real_owner_graph_revocation_blocks_terminal_result_read(tmp_path):
    (store, authority_db, port, coordinator, policy, operation,
     pending, value, bootstrap) = _owner_issue_case(tmp_path, return_bootstrap=True)
    try:
        port.pending_owner = pending
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=policy.namespace,
            operation_id=operation.operation_id, grant_value=value)
        anchor = port.anchors[policy.namespace]
        read_permit = port.fences.begin_fence(
            subject="subject", holder="administrator", operation="read",
            operation_id="read-1", current_anchor=anchor)
        source = SourceRecord(
            "source-1", "Original source", "speaker-1", "reported", "reported",
            None, 1.0, "root-1", ("owner",), ("audit",))
        source_atom = source_key(*policy.namespace.as_tuple, source.source_id)
        access_atom = access_key(*policy.namespace.as_tuple, source.source_id)
        access = {"source_id": source.source_id, "audiences": ["owner"],
                  "purposes": ["audit"], "status": "active", "recorded_at": 1.0}
        with store._lock:
            db = store._db
            for key, payload in ((source_atom, source.to_dict()), (access_atom, access)):
                db.execute(
                    "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                    "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
                    (key.token, *policy.namespace.as_tuple, key.owner.kind,
                     key.owner.subject, key.type_name, key.name, 1,
                     canonical_json(payload)))
            db.execute(
                "INSERT INTO graph_dependencies(dependent_token,dependency_token,"
                "dependency_revision) VALUES(?,?,1)",
                (access_atom.token, source_atom.token))
        request = ModelResultReadRequestV1(
            "authority", anchor.namespace, policy.namespace, "installation",
            "owner-actor", OwnerSessionLoginRequestV1(
                "authority", anchor.namespace, "installation", operation.principal,
                "owner-credential", 1, "owner", "https://dashboard.example"),
            "workbench_view", "audit", ("owner",), "call-1", "read-1")
        original = model_intent(
            authority_id="authority", namespace=anchor.namespace,
            source_refs=("source-1",), source_revisions=(("source-1", 1),),
            access_revisions=(("source-1", 1),), delete_epoch=0)
        guard = OwnerAuthorizationGuardV1(
            "authority", "installation", policy.namespace, 1,
            owner_digest(proof), 0, 0)
        verifier = PinnedCurrentModelResultReadGraphVerifier(
            tmp_path / "owner-business.db")
        assert verifier.current(request, original, guard, read_permit) is True

        with store._lock:
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?",
                (owner_grant_key(*policy.namespace.as_tuple).token,))
        assert verifier.current(request, original, guard, read_permit) is False

        with store._lock:
            store._db.execute(
                "UPDATE graph_atoms SET valid=1 WHERE token=?",
                (owner_grant_key(*policy.namespace.as_tuple).token,))
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?",
                (source_atom.token,))
        assert verifier.current(request, original, guard, read_permit) is False
    finally:
        store.close()
        authority_db.close()
