"""Pinned graph verifier against an actual production GraphCoordinator commit."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import _owner_issue_case
from sylanne3.authority_service.current_graph_verifier import PinnedCurrentGraphVerifier
from sylanne3.graph_coordinator import AuthorityDenied


def _committed_case(tmp_path, *, reject_wrong_first=False):
    (store, authority_db, port, coordinator, policy, operation,
     pending, value, bootstrap) = _owner_issue_case(tmp_path, return_bootstrap=True)
    port.pending_owner = pending
    if reject_wrong_first:
        wrong = dict(value, capabilities=["workbench.write"])
        with pytest.raises(AuthorityDenied, match="paired pending"):
            coordinator.commit_first_owner_grant_v2(
                bootstrap, namespace=policy.namespace,
                operation_id=operation.operation_id, grant_value=wrong)
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=value)

    def finished(permit, finish_id, finish_digest):
        observed, state = port.get_fence_operation(
            namespace=policy.namespace,
            authority_namespace=permit.namespace,
            operation_id=permit.operation_id)
        return (observed == permit and state == "finished"
                and ("write", finish_id, finish_digest) in port.finishes)

    verifier = PinnedCurrentGraphVerifier(
        tmp_path / "owner-business.db", finished_fence_verifier=finished)
    return store, authority_db, operation, proof, verifier


def test_pinned_current_graph_verifier_accepts_real_finished_issue(tmp_path):
    store, authority_db, operation, proof, verifier = _committed_case(tmp_path)
    try:
        assert verifier(operation, proof) is True
        assert verifier(operation, replace(proof, graph_receipt_digest="sha256:" + "f" * 64)) is False
    finally:
        store.close()
        authority_db.close()


def test_missing_or_tampered_current_graph_fails_closed(tmp_path):
    store, authority_db, operation, proof, verifier = _committed_case(tmp_path)
    try:
        with store._lock:
            store._db.execute(
                "DELETE FROM graph_owner_issue_fences_v1 WHERE bot=? AND persona=?",
                operation.namespace.as_tuple)
        assert verifier(operation, proof) is False
    finally:
        store.close()
        authority_db.close()


def test_graph_row_cannot_claim_authority_fence_finished(tmp_path):
    store, authority_db, operation, proof, _ = _committed_case(tmp_path)
    try:
        verifier = PinnedCurrentGraphVerifier(
            tmp_path / "owner-business.db", finished_fence_verifier=lambda *_: False)
        assert verifier(operation, proof) is False
    finally:
        store.close()
        authority_db.close()


def test_rejected_wrong_digest_intent_does_not_mask_current_issue(tmp_path):
    store, authority_db, operation, proof, verifier = _committed_case(
        tmp_path, reject_wrong_first=True)
    try:
        with store._lock:
            assert store._db.execute(
                "SELECT COUNT(*) FROM graph_owner_issue_intents_v1 "
                "WHERE bot=? AND persona=?", operation.namespace.as_tuple,
            ).fetchone() == (2,)
        assert verifier(operation, proof) is True
    finally:
        store.close()
        authority_db.close()
