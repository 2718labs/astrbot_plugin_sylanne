"""Independent rev2 Owner revoke proof over real graph and Authority stores."""

from dataclasses import replace
import sqlite3

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    AUTH_NS, PEER, ROLE, SUBJECT, WORKER,
)
from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from sylanne3.authority_service.current_owner_revoke_graph_verifier import (
    PinnedCurrentOwnerRevokeGraphVerifier,
)
from sylanne3.authority_service.v2_owner_contract import OwnerGraphCommitProofV1


def test_current_owner_revoke_requires_real_graph_and_finished_authority_fence(tmp_path):
    chain = _real_owner_chain(tmp_path)
    graph_path = tmp_path / "business.db"
    core = chain.resources[1]
    previous_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (credential == PEER and action == "owner_authorization_revoke"
         and namespace == AUTH_NS)
        or previous_authorizer(credential, action, namespace, holder)
    )
    tickets = chain.server._v2_owner_tickets

    def pending_for_graph(*, namespace, authority_namespace, operation_id, permit):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return tickets.get_revoke_pending_for_graph_write(
            credential=WORKER, authority_namespace=authority_namespace,
            operation_id=operation_id, installation_id="installation",
            subject=SUBJECT, permit=permit,
        )

    chain.port.get_pending_owner_revoke_for_graph_write = pending_for_graph
    try:
        owner_request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=owner_request)
        owner_token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        operation, tombstone = chain.coordinator.freeze_current_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id="owner-revoke-1")
        pending = tickets.reserve_revoke(
            credential=PEER, authority_namespace=AUTH_NS, operation=operation,
            session_token=owner_token, session_request=owner_request,
        )
        assert pending.guard.pending_revoke_operation_id == operation.operation_id

        verifier = tickets._revoke_graph_commit_verifier
        assert type(verifier) is PinnedCurrentOwnerRevokeGraphVerifier
        uncommitted = OwnerGraphCommitProofV1(
            ROLE, operation.operation_id, operation.request_digest,
            operation.grant_id, operation.grant_digest,
            tombstone["graph_incarnation"], 2, 2, 2,
            "sha256:" + "f" * 64,
        )
        assert verifier(operation, uncommitted) is False

        finish_fence = chain.port.finish_fence
        chain.port.finish_fence = lambda *_args, **_kwargs: None
        try:
            proof = chain.coordinator.commit_owner_revoke_v2(
                chain.bootstrap, namespace=ROLE, operation_id=operation.operation_id,
                grant_value=tombstone,
            )
        finally:
            chain.port.finish_fence = finish_fence
        assert verifier(operation, proof) is False
        assert chain.coordinator.commit_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=tombstone,
        ) == proof
        assert verifier(operation, proof) is True
        assert PinnedCurrentOwnerRevokeGraphVerifier(
            graph_path, finished_fence_verifier=lambda *_: False,
        )(operation, proof) is False
        assert verifier(operation, replace(
            proof, graph_receipt_digest="sha256:" + "e" * 64)) is False

        with sqlite3.connect(graph_path) as db:
            db.execute(
                "UPDATE graph_owner_revoke_operations_v1 "
                "SET graph_receipt_digest=? WHERE bot=? AND persona=?",
                ("sha256:" + "d" * 64,) + ROLE.as_tuple,
            )
        assert verifier(operation, proof) is False
        with sqlite3.connect(graph_path) as db:
            db.execute(
                "UPDATE graph_owner_revoke_operations_v1 "
                "SET graph_receipt_digest=? WHERE bot=? AND persona=?",
                (proof.graph_receipt_digest,) + ROLE.as_tuple,
            )
        assert verifier(operation, proof) is True
        with sqlite3.connect(graph_path) as db:
            event_key = ROLE.as_tuple + (
                "owner-authorization-revoke-v1", operation.operation_id)
            event_digest = db.execute(
                "SELECT digest FROM graph_events WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?", event_key,
            ).fetchone()[0]
            db.execute(
                "UPDATE graph_events SET digest=? WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?", ("0" * 64,) + event_key,
            )
        assert verifier(operation, proof) is False
        with sqlite3.connect(graph_path) as db:
            db.execute(
                "UPDATE graph_events SET digest=? WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?", (event_digest,) + event_key,
            )
        assert verifier(operation, proof) is True
        with sqlite3.connect(graph_path) as db:
            invalidated = db.execute(
                "SELECT invalidated FROM graph_events WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?", event_key,
            ).fetchone()[0]
            db.execute(
                "UPDATE graph_events SET invalidated=? WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?",
                ('[["forged",1]]',) + event_key,
            )
        assert verifier(operation, proof) is False
        with sqlite3.connect(graph_path) as db:
            db.execute(
                "UPDATE graph_events SET invalidated=? WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?", (invalidated,) + event_key,
            )
        assert verifier(operation, proof) is True

        committed = tickets.finalize_revoke(
            credential=PEER, authority_namespace=AUTH_NS,
            operation=operation, proof=proof,
            session_token=owner_token, session_request=owner_request,
        )
        assert committed.phase == "committed"
        assert committed.grant_revision == 2
        assert committed.graph_access_epoch == proof.graph_access_epoch
        assert verifier(operation, proof) is True
    finally:
        for resource in chain.resources:
            resource.close()
