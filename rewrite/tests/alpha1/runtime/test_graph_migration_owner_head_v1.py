"""A real revoked Owner head prevents rev1 graph-backup restoration."""

from dataclasses import replace
import sqlite3

import pytest

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    AUTH_NS, PEER, ROLE, SUBJECT, WORKER,
)
from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_store import GraphMigrationVerifiedTransferV1, GraphStore


class _PinnedHead:
    def __init__(self, receipt, proof):
        self.receipt, self.proof = receipt, proof

    def verify_local(self, receipt):
        if receipt is not self.receipt:
            raise PermissionError("unrecognized transfer")
        return self.proof


def test_rev1_backup_cannot_import_after_real_authority_rev2(tmp_path):
    chain = _real_owner_chain(tmp_path)
    graph, core = chain.resources[:2]
    tickets = chain.server._v2_owner_tickets
    old_db = tmp_path / "rev1-backup.db"
    capability = chain.coordinator._GraphCoordinator__graph_capability
    try:
        with graph._lock:
            with sqlite3.connect(old_db) as backup:
                graph._db.backup(backup)
            source = graph.graph_recovery_metadata(ROLE, _capability=capability)
        prior_authorizer = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            credential == PEER and action == "owner_authorization_revoke"
            and namespace == AUTH_NS
        ) or prior_authorizer(credential, action, namespace, holder)

        def pending_for_graph(*, namespace, authority_namespace, operation_id, permit):
            assert namespace == ROLE and authority_namespace == AUTH_NS
            return tickets.get_revoke_pending_for_graph_write(
                credential=WORKER, authority_namespace=AUTH_NS,
                operation_id=operation_id, installation_id="installation",
                subject=SUBJECT, permit=permit,
            )

        chain.port.get_pending_owner_revoke_for_graph_write = pending_for_graph
        owner_request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=owner_request)
        owner_token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        operation, tombstone = chain.coordinator.freeze_current_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id="owner-revoke-backup")
        tickets.reserve_revoke(
            credential=PEER, authority_namespace=AUTH_NS, operation=operation,
            session_token=owner_token, session_request=owner_request)
        with core._lock:
            core._db.execute("BEGIN")
            try:
                with pytest.raises(AuthorityUnavailable, match="pending Owner revoke"):
                    tickets.current_migration_head_in_tx(
                        core._db, authority_namespace=AUTH_NS)
            finally:
                core._db.execute("ROLLBACK")
        revoked_proof = chain.coordinator.commit_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE,
            operation_id=operation.operation_id, grant_value=tombstone)
        tickets.finalize_revoke(
            credential=PEER, authority_namespace=AUTH_NS,
            operation=operation, proof=revoked_proof,
            session_token=owner_token, session_request=owner_request)
        with core._lock:
            core._db.execute("BEGIN")
            try:
                head = tickets.current_migration_head_in_tx(
                    core._db, authority_namespace=AUTH_NS)
            finally:
                core._db.execute("ROLLBACK")
        assert head.state == "revoked" and head.grant_revision == 2

        target = replace(
            source.requirements, activation_generation=3,
            revocation_epoch=source.requirements.revocation_epoch + 1,
            graph_incarnation="target-after-revoke",
        )
        receipt = object()
        proof = GraphMigrationVerifiedTransferV1(
            "transfer-after-revoke", source, target,
            "target_recovering", "old-rev1-backup", head)
        restored = GraphStore(
            old_db, graph._registry,
            migration_transfer_verifier=_PinnedHead(receipt, proof))
        restored._coordinator_capability = capability
        try:
            with restored._lock:
                restored._db.execute("BEGIN IMMEDIATE")
                try:
                    with pytest.raises(PermissionError, match="behind Authority head"):
                        restored.cas_graph_migration_recovery_metadata(
                            source, target, receipt, _capability=capability)
                finally:
                    restored._db.execute("ROLLBACK")
        finally:
            restored.close()
    finally:
        for resource in chain.resources:
            resource.close()
