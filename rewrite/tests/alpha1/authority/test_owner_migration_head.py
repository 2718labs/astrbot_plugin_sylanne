"""A frozen Authority Owner head survives graph rev2 and rejects old grant facts."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    AUTH_NS, PEER, ROLE, SUBJECT, WORKER,
)
from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from rewrite.tests.alpha1.authority.test_v2_migration_local_state import (
    _close as close_migration, _open as open_migration, _plan as migration_plan,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
from sylanne3.authority_service.v2_migration_contract import MigrationPlanV2
from sylanne3.authority_service.v2_migration_rpc import (
    from_wire as migration_from_wire, to_wire as migration_to_wire,
)
from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerMigrationHeadV1, from_wire as owner_from_wire,
    to_wire as owner_to_wire,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore


def test_recover_transfer_requires_installed_owner_reader_when_schema_exists(tmp_path):
    bundle = open_migration(tmp_path, create=True)
    try:
        fences, unpaired, store, core, *_ = bundle
        tickets = AuthorityV2OwnerTicketStore(core, create=True)
        paired = AuthorityV2MigrationService(
            fences=fences, store=store, pairing_verifier=lambda *_: True,
            source_snapshot_verifier=None, target_recovery_verifier=None,
            owner_tickets=tickets)
        paired.begin_transfer(
            credential="admin", subject="subject-a",
            plan=migration_plan(fences), request_id="begin-owner-head")
        with pytest.raises(AuthorityUnavailable, match="reader is not installed"):
            unpaired.recover_transfer(
                credential="admin", subject="subject-a", transfer_id="transfer-a")
        recovery = paired.recover_transfer(
            credential="admin", subject="subject-a", transfer_id="transfer-a")
        assert recovery.owner_head is None
        assert migration_from_wire(
            migration_to_wire(recovery), type(recovery)) == recovery
    finally:
        close_migration(bundle)


def test_real_rev2_owner_migration_head_blocks_pending_and_old_grant(tmp_path):
    chain = _real_owner_chain(tmp_path)
    core = chain.resources[1]
    old_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (credential == PEER and action == "owner_authorization_revoke"
         and namespace == AUTH_NS)
        or (credential == PEER and action in {
            "migration_begin", "migration_recover"} and namespace == AUTH_NS)
        or old_authorizer(credential, action, namespace, holder))
    tickets = chain.server._v2_owner_tickets

    def pending_for_graph(*, namespace, authority_namespace, operation_id, permit):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return tickets.get_revoke_pending_for_graph_write(
            credential=WORKER, authority_namespace=authority_namespace,
            operation_id=operation_id, installation_id="installation",
            subject=SUBJECT, permit=permit)

    chain.port.get_pending_owner_revoke_for_graph_write = pending_for_graph
    try:
        with core._tx() as db:
            original = tickets.current_migration_head_in_tx(
                db, authority_namespace=AUTH_NS)
        assert original.state == "active"
        assert original.grant_revision == 1
        owner_request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=owner_request)
        owner_token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        operation, tombstone = chain.coordinator.freeze_current_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id="owner-revoke-migration")
        tickets.reserve_revoke(
            credential=PEER, authority_namespace=AUTH_NS, operation=operation,
            session_token=owner_token, session_request=owner_request)
        with core._tx() as db, pytest.raises(
                AuthorityUnavailable, match="pending Owner revoke"):
            tickets.current_migration_head_in_tx(db, authority_namespace=AUTH_NS)
        proof = chain.coordinator.commit_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=tombstone)
        tickets.finalize_revoke(
            credential=PEER, authority_namespace=AUTH_NS,
            operation=operation, proof=proof,
            session_token=owner_token, session_request=owner_request)
        with core._tx() as db:
            head = tickets.current_migration_head_in_tx(
                db, authority_namespace=AUTH_NS)
        assert head.state == "revoked"
        assert head.issue_operation == original.issue_operation
        assert head.issue_proof == original.issue_proof
        assert head.revoke_operation == operation
        assert head.revoke_proof == proof
        assert head.grant_revision == 2
        assert head.grant_digest == proof.grant_digest
        assert head.graph_access_epoch == proof.graph_access_epoch
        assert head.guard.minimum_revocation_revision == 2
        assert head.guard.minimum_revocation_epoch == proof.graph_access_epoch
        assert (original.grant_revision, original.grant_digest,
                original.graph_access_epoch) != (
                    head.grant_revision, head.grant_digest,
                    head.graph_access_epoch)
        assert owner_from_wire(owner_to_wire(head)) == head
        assert migration_from_wire(
            migration_to_wire(head), OwnerMigrationHeadV1) == head
        with pytest.raises(AuthorityUnavailable):
            migration_from_wire(
                {**migration_to_wire(head), "grant_revision": 1},
                OwnerMigrationHeadV1)
        migration = AuthorityV2MigrationService(
            fences=chain.service,
            store=AuthorityV2MigrationStore(
                core._db, lock=core._lock, create=True),
            pairing_verifier=lambda *_: True,
            source_snapshot_verifier=None,
            target_recovery_verifier=None,
            owner_tickets=tickets)
        migration.begin_transfer(
            credential=PEER, subject=SUBJECT,
            plan=MigrationPlanV2(
                "owner-migration-rev2", AUTH_NS, ROLE,
                "administrator", "installation", "target-holder",
                "target-installation",
                chain.service.current_anchor(
                    credential=WORKER, subject=SUBJECT)),
            request_id="begin-owner-migration-rev2")
        recovery = migration.recover_transfer(
            credential=PEER, subject=SUBJECT,
            transfer_id="owner-migration-rev2")
        assert recovery.owner_head == head
        assert migration_from_wire(
            migration_to_wire(recovery), type(recovery)) == recovery
    finally:
        for resource in chain.resources:
            resource.close()
