"""Owner revoke stays a durable Authority barrier until graph rev2 is verified."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    ADMIN, AUTH_NS, CLAIMANT, ROLE, SUBJECT, WORKER, _installed, _owner_issue,
)
from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerGraphCommitProofV1,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def test_absent_revoke_read_requires_management_capability(tmp_path):
    (_, _, _, compose, _, _, _, resources) = _installed(tmp_path)
    try:
        _, tickets = compose()
        core = resources[1]
        authorize = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            (credential == ADMIN and action == "owner_authorization_revoke"
             and namespace == AUTH_NS)
            or authorize(credential, action, namespace, holder))
        assert tickets.get_revoke_committed(
            credential=ADMIN, authority_namespace=AUTH_NS,
            operation_id="not-yet-reserved") is None
        assert tickets.get_revoke_pending(
            credential=ADMIN, authority_namespace=AUTH_NS,
            operation_id="not-yet-reserved") is None
        with pytest.raises(AuthorityUnavailable, match="denied"):
            tickets.get_revoke_committed(
                credential=CLAIMANT, authority_namespace=AUTH_NS,
                operation_id="not-yet-reserved")
        with pytest.raises(AuthorityUnavailable, match="denied"):
            tickets.get_revoke_committed(
                credential=ADMIN, authority_namespace="wrong-namespace",
                operation_id="not-yet-reserved")
        with pytest.raises(AuthorityUnavailable, match="session"):
            tickets.get_revoke_committed(
                credential=ADMIN, authority_namespace=AUTH_NS,
                operation_id="not-yet-reserved", session_token="unpaired")
    finally:
        for resource in resources:
            resource.close()


def test_pending_revoke_survives_reopen_and_blocks_during_active_dispatch(tmp_path):
    (coordinator, bootstrap, service, compose, expected, principal,
     authority_id, resources) = _installed(tmp_path)
    try:
        policy = replace(policy_for(resources[0]), expected_authority_id=authority_id,
                         authority_namespace=AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, tickets = compose()
        ticket, issue, value = _owner_issue(creation, authority_id, principal)
        tickets.register_ticket(
            credential=ADMIN, authority_namespace=AUTH_NS, ticket=ticket)
        tickets.reserve_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS, operation=issue)
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=issue.operation_id,
            grant_value=value)
        committed_issue = tickets.finalize_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS,
            operation=issue, proof=proof)

        core = resources[1]
        authorize = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            (credential == ADMIN and action == "owner_authorization_revoke"
             and namespace == AUTH_NS)
            or (credential == WORKER and action in {"read", "dispatch"}
                and namespace == AUTH_NS and holder == "administrator")
            or authorize(credential, action, namespace, holder))
        core._dispatch_verifier = lambda *_: True
        anchor = service.current_anchor(credential=WORKER, subject=SUBJECT)
        revoke = OwnerAuthorizationOperationV1(
            "revoke", "owner-revoke-1", authority_id, "installation", ROLE,
            principal, issue.grant_id, "sha256:" + "d" * 64, 1,
            committed_issue.guard)
        read_fence = service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            operation="read", operation_id="read-before-revoke",
            expected_anchor=anchor)
        with pytest.raises(AuthorityUnavailable, match="non-dispatch"):
            tickets.reserve_revoke(
                credential=ADMIN, authority_namespace=AUTH_NS,
                operation=revoke)
        service.finish_fence(
            credential=WORKER, subject=SUBJECT, permit=read_fence,
            request_id="finish:read-before-revoke",
            request_digest="sha256:" + "a" * 64)
        anchor = service.current_anchor(credential=WORKER, subject=SUBJECT)
        footprint = RecoveryConstraintFootprint(
            AUTH_NS, "activity-1", "effect-1")
        dispatch = service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            operation="dispatch", operation_id="dispatch-before-revoke",
            expected_anchor=anchor, effect_id="effect-1",
            command_digest="sha256:" + "c" * 64, footprint=footprint)
        pending = tickets.reserve_revoke(
            credential=ADMIN, authority_namespace=AUTH_NS, operation=revoke)
        assert pending.guard.pending_revoke_operation_id == revoke.operation_id
        assert pending.guard.authorization_revision == 1
        assert pending.guard.authorization_head == committed_issue.guard.authorization_head
        assert pending.guard.minimum_revocation_revision == 0
        assert pending.guard.minimum_revocation_epoch == 0
        assert tickets.reserve_revoke(
            credential=ADMIN, authority_namespace=AUTH_NS, operation=revoke) == pending
        with pytest.raises(AuthorityUnavailable):
            tickets.reserve_revoke(
                credential=ADMIN, authority_namespace=AUTH_NS,
                operation=replace(revoke, grant_digest="sha256:" + "e" * 64,
                                  request_digest=None))
        with pytest.raises(AuthorityUnavailable):
            tickets.reserve_revoke(
                credential=ADMIN, authority_namespace=AUTH_NS,
                operation=replace(revoke, operation_id="owner-revoke-2",
                                  request_digest=None))

        reopened = AuthorityV2OwnerTicketStore(core, create=False)
        assert reopened.get_revoke_pending(
            credential=ADMIN, authority_namespace=AUTH_NS,
            operation_id=revoke.operation_id) == pending
        with core._tx() as db:
            assert reopened._checked_current_head(db, AUTH_NS) == pending.guard
            assert db.execute(
                "SELECT state FROM authority_v2_fences WHERE operation_id=?",
                (dispatch.operation_id,)).fetchone() == ("active",)
            assert db.execute(
                "SELECT 1 FROM authority_owner_issue_committed_v1 "
                "WHERE authority_namespace=?", (AUTH_NS,)).fetchone() == (1,)
        assert reopened.get_revoke_committed(
            credential=ADMIN, authority_namespace=AUTH_NS,
            operation_id=revoke.operation_id) is None
        with pytest.raises(AuthorityUnavailable, match="verifier"):
            unverified = OwnerGraphCommitProofV1(
                ROLE, revoke.operation_id, revoke.request_digest,
                revoke.grant_id, revoke.grant_digest,
                proof.graph_incarnation, 2, 2, proof.graph_epoch + 1,
                "sha256:" + "f" * 64)
            reopened.finalize_revoke(
                credential=ADMIN, authority_namespace=AUTH_NS,
                operation=revoke, proof=unverified)
        with core._tx() as db:
            assert reopened._checked_current_head(db, AUTH_NS) == pending.guard
    finally:
        for resource in resources:
            resource.close()
