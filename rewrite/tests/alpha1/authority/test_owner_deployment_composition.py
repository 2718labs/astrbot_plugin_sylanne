"""Product Owner composition binds current installer pairing to first issue."""

import sqlite3
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_owner_identity_sqlite import (
    _core, _subjects, ADMIN, AUTH_NS, EXPIRY, NOW, PLUGIN, PRINCIPAL, NS,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.reverse_handoff import ReverseGraphClaimClient
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerGraphCommitProofV1,
)
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier, compose_owner_deployment
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime.deletion import DeletionJournal


def digest(char):
    return "sha256:" + char * 64


def test_product_composition_rechecks_creation_pairing_after_pending(tmp_path):
    core = _core(tmp_path / "authority.db", create=True)
    original_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (credential == PLUGIN and namespace == AUTH_NS and action == "owner_claim")
        or original_authorizer(credential, action, namespace, holder)
    )
    deletion_path = tmp_path / "deletion.db"
    deletion = DeletionJournal(deletion_path, create=True)
    guard = AuthorityV2DeletionGuard(deletion_path)
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=AUTH_NS,
        journal_id="execution", create=True)
    try:
        key, registration, ticket = _subjects(core)
        source = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW, create=True)
        source.pair_creation(
            administrator_credential=ADMIN, authority_namespace=AUTH_NS,
            ticket=ticket, client_certificate_sha256=PLUGIN.certificate_sha256,
            valid_until_utc=EXPIRY)
        source.pair_credential(
            administrator_credential=ADMIN, registration=registration,
            client_certificate_sha256=PLUGIN.certificate_sha256,
            valid_until_utc=EXPIRY)
        verifier = OwnerDeploymentVerifier(source, lambda: NOW)
        proofs = AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: NOW, pairing_verifier=verifier.pair_credential,
            current_pairing_source=source, create=True)
        proofs.register_credential(
            transport_credential=PLUGIN, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: NOW, current_pairing_source=source,
            create=True)
        request = OwnerSessionLoginRequestV1(
            registration.authority_id, AUTH_NS, "installation", PRINCIPAL,
            registration.credential_id, registration.credential_epoch,
            "sylanne-owner-console", "http://localhost:6185")
        challenge = sessions.begin_login(
            transport_credential=PLUGIN, request=request)
        token = sessions.accept_login(
            transport_credential=PLUGIN, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))

        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=AUTH_NS)
        graph_path = tmp_path / "business.db"
        sqlite3.connect(graph_path).close()
        options = dict(
            core=core, v2_fences={AUTH_NS: service}, graph_db_path=graph_path,
            utc_clock=lambda: NOW, administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={(PLUGIN.certificate_sha256, "installed"):
                              AdministratorInstallationV2(
                                  "installation", "holder", "policy",
                                  "capabilities-v2", "c" * 64)},
            namespace_bindings_v2={
                (PLUGIN.certificate_sha256, "installed", NS): AUTH_NS},
            owner_sessions=sessions, create_owner_schema=True,
        )
        with pytest.raises(AuthorityUnavailable, match="identity port"):
            compose_owner_deployment(identity=None, **options)
        another_source = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW)
        with pytest.raises(AuthorityUnavailable, match="current installation pairing"):
            compose_owner_deployment(identity=another_source, **options)
        client = object.__new__(ReverseGraphClaimClient)
        client.profile = SimpleNamespace(
            namespace=AUTH_NS, profile_id="installed", installation_id="installation")
        with pytest.raises(TypeError, match="graph claim issuers"):
            compose_owner_deployment(
                identity=source, v2_final_handoff_reverse={AUTH_NS: client},
                **options)
        server = compose_owner_deployment(
            identity=source, v2_final_handoff_reverse={AUTH_NS: client},
            v2_final_handoff_issuers={AUTH_NS: "graph-issuer"}, **options)
        bridge = server._v2_execution[AUTH_NS]
        assert bridge._final_handoff_authorizer.__self__ is client
        assert bridge._final_handoff_issuer_id == "graph-issuer"
        assert server._v2_owner_proofs._current_pairing_source is source
        assert server._v2_owner_tickets._creation_pairing_source is source
        assert server._v2_owner_sessions._current_pairing_source is source
        assert server._v2_owner_pairings is source
        assert server._v2_owner_pairings._core is core

        owner_tickets = server._v2_owner_tickets
        owner_tickets.register_ticket(
            credential=PLUGIN, authority_namespace=AUTH_NS, ticket=ticket)
        guard_value = OwnerAuthorizationGuardV1(
            registration.authority_id, "installation", NS, 0, "genesis", 0, 0)
        operation = OwnerAuthorizationOperationV1(
            "issue", "owner-issue", registration.authority_id, "installation",
            NS, PRINCIPAL, "owner-grant", digest("a"), 0, guard_value, ticket)
        assert owner_tickets.reserve_issue(
            credential=PLUGIN, authority_namespace=AUTH_NS,
            operation=operation, session_token=token,
            session_request=request).phase == "pending"
        source.revoke_creation(
            administrator_credential=ADMIN, authority_namespace=AUTH_NS)
        proof = OwnerGraphCommitProofV1(
            NS, operation.operation_id, operation.request_digest,
            operation.grant_id, operation.grant_digest, "graph", 1, 1, 1,
            digest("b"))
        with pytest.raises(AuthorityUnavailable, match="creation pairing is not current"):
            owner_tickets.finalize_issue(
                credential=PLUGIN, authority_namespace=AUTH_NS,
                operation=operation, proof=proof, session_token=token,
                session_request=request)
        with core._tx() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_issue_committed_v1"
            ).fetchone() == (0,)
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_authorization_heads_v1"
            ).fetchone() == (0,)
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
