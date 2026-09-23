"""A live Owner session is checked in the same transaction as first issue."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.authority_service.current_graph_verifier import PinnedCurrentGraphVerifier
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    _installed, _owner_issue, ADMIN, AUTH_NS as ROUND_TRIP_AUTH_NS,
    CLAIMANT, ROLE,
)
from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for


NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(NS)
PRINCIPAL = OwnerPrincipalV1("dashboard", "account", "incarnation")
NOW = datetime(2029, 1, 1, tzinfo=timezone.utc)


def digest(char):
    return "sha256:" + char * 64


def setup(tmp_path, *, graph_verifier):
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, action, namespace, _: (
            credential == "installed-peer" and namespace == AUTH_NS
            and action in {"owner_claim", "owner_pair", "owner_session"}
        ),
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True,
    )
    with core._tx() as db:
        db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
        db.execute(
            "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (AUTH_NS, "holder", 1, "active", None, None, 0,
             "deletion", 0, "genesis", "clear", "execution", 0, "genesis", "nonce"),
        )
        authority_id = core._id(db)
    AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    key = Ed25519PrivateKey.generate()
    owner_proofs = AuthorityV2OwnerProofStore(
        core, utc_clock=lambda: NOW, pairing_verifier=lambda *_: True, create=True,
    )
    owner_proofs.register_credential(
        transport_credential="installed-peer",
        registration=OwnerCredentialRegistrationV1(
            authority_id, AUTH_NS, "installation", PRINCIPAL, "owner-key", 1,
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll",
        ),
    )
    sessions = AuthorityV2OwnerSessionStore(core, utc_clock=lambda: NOW, create=True)
    request = OwnerSessionLoginRequestV1(
        authority_id, AUTH_NS, "installation", PRINCIPAL, "owner-key", 1,
        "sylanne-owner-console", "http://localhost:6185",
    )
    challenge = sessions.begin_login(
        transport_credential="installed-peer", request=request)
    token = sessions.accept_login(
        transport_credential="installed-peer", challenge=challenge,
        signature=key.sign(challenge.signed_bytes()),
    )
    ticket = OwnerClaimTicketV1(
        authority_id, "installation", NS, PRINCIPAL, "ticket", "create",
        digest("a"), digest("b"), "C" * 43, "2030-01-01T00:00:00Z",
    )
    guard = OwnerAuthorizationGuardV1(
        authority_id, "installation", NS, 0, "genesis", 0, 0)
    operation = OwnerAuthorizationOperationV1(
        "issue", "issue", authority_id, "installation", NS, PRINCIPAL,
        "grant", digest("c"), 0, guard, ticket,
    )
    proof = OwnerGraphCommitProofV1(
        NS, "issue", operation.request_digest, "grant", digest("c"),
        "graph-incarnation", 1, 1, 4, digest("d"),
    )
    store = AuthorityV2OwnerTicketStore(
        core, create=True, utc_clock=lambda: NOW,
        first_claim_verifier=lambda *_: True,
        claimant_verifier=None,
        graph_commit_verifier=graph_verifier,
        owner_sessions=sessions,
    )
    store.register_ticket(
        credential="installed-peer", authority_namespace=AUTH_NS, ticket=ticket)
    return core, sessions, request, token, operation, proof, store


def reserve(store, operation, request, token):
    return store.reserve_issue(
        credential="installed-peer", authority_namespace=AUTH_NS,
        operation=operation, session_token=token, session_request=request,
    )


def finalize(store, operation, proof, request, token):
    return store.finalize_issue(
        credential="installed-peer", authority_namespace=AUTH_NS,
        operation=operation, proof=proof, session_token=token,
        session_request=request,
    )


def test_live_session_can_issue_and_revoked_session_cannot_replay(tmp_path):
    core, sessions, request, token, operation, proof, store = setup(
        tmp_path, graph_verifier=lambda *_: True)
    try:
        with pytest.raises(AuthorityUnavailable, match="Owner session"):
            store.reserve_issue(
                credential="installed-peer", authority_namespace=AUTH_NS,
                operation=operation)
        pending = reserve(store, operation, request, token)
        assert store.get_pending(
            credential="installed-peer", authority_namespace=AUTH_NS,
            operation_id="issue", session_token=token, session_request=request,
        ) == pending
        committed = finalize(store, operation, proof, request, token)
        assert committed.phase == "committed"
        sessions.logout(
            transport_credential="installed-peer", token=token, request=request)
        with pytest.raises(AuthorityUnavailable, match="not current"):
            finalize(store, operation, proof, request, token)
        with pytest.raises(AuthorityUnavailable, match="not current"):
            reserve(store, operation, request, token)
    finally:
        core.close()


def test_logout_during_graph_verification_blocks_atomic_commit(tmp_path):
    state = {}

    def verified_then_revoked(*_):
        state["sessions"].logout(
            transport_credential="installed-peer", token=state["token"],
            request=state["request"])
        return True

    core, sessions, request, token, operation, proof, store = setup(
        tmp_path, graph_verifier=verified_then_revoked)
    state.update(sessions=sessions, request=request, token=token)
    try:
        reserve(store, operation, request, token)
        with pytest.raises(AuthorityUnavailable, match="not current"):
            finalize(store, operation, proof, request, token)
        with core._tx() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_issue_committed_v1"
            ).fetchone() == (0,)
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_authorization_heads_v1"
            ).fetchone() == (0,)
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_issue_pending_v1"
            ).fetchone() == (1,)
    finally:
        core.close()


def test_session_must_match_issue_identity_and_owner_audience(tmp_path):
    core, sessions, request, token, operation, _, store = setup(
        tmp_path, graph_verifier=lambda *_: True)
    try:
        for wrong in (
            replace(request, principal=OwnerPrincipalV1(
                "dashboard", "other-account", "incarnation")),
            replace(request, authority_namespace="other-namespace"),
            replace(request, audience="other-console"),
        ):
            with pytest.raises(AuthorityUnavailable, match="differs from issue"):
                reserve(store, operation, wrong, token)
        with core._tx() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM authority_owner_issue_pending_v1"
            ).fetchone() == (0,)
    finally:
        core.close()


def test_composition_installs_same_core_owner_sessions(tmp_path):
    core, sessions, request, token, operation, _, _ = setup(
        tmp_path, graph_verifier=lambda *_: True)
    deletion_path = tmp_path / "deletion.db"
    deletion = DeletionJournal(deletion_path, create=True)
    guard = AuthorityV2DeletionGuard(deletion_path)
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=AUTH_NS,
        journal_id="execution", create=True)
    try:
        service = AuthorityV2FenceService(
            core=core, fences=AuthorityV2FenceStore(core._db, lock=core._lock),
            deletion=guard, execution=execution, namespace=AUTH_NS)
        proofs = AuthorityV2OwnerProofStore(core, utc_clock=lambda: NOW)
        graph_path = tmp_path / "graph.db"
        graph_path.touch()
        server = compose_local_owner_authority(
            core=core, v2_fences={AUTH_NS: service}, graph_db_path=graph_path,
            utc_clock=lambda: NOW, first_claim_verifier=lambda *_: True,
            claimant_verifier=None, owner_proofs=proofs, owner_sessions=sessions,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={("a" * 64, "profile"): AdministratorInstallationV2(
                "installation", "holder-a", "policy", "capabilities-v2", "b" * 64)},
            namespace_bindings_v2={("a" * 64, "profile", NS): AUTH_NS},
        )
        assert server._v2_owner_tickets._owner_sessions is sessions
        assert server._v2_owner_tickets._claimant_verifier is None
        assert server._v2_owner_sessions is sessions
        assert reserve(server._v2_owner_tickets, operation, request, token).phase == "pending"
        sessions.logout(
            transport_credential="installed-peer", token=token, request=request)
        with pytest.raises(AuthorityUnavailable, match="not current"):
            reserve(server._v2_owner_tickets, operation, request, token)
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_real_graph_first_issue_uses_live_owner_session(tmp_path):
    (coordinator, bootstrap, service, compose, expected, principal,
     authority_id, resources) = _installed(tmp_path)
    core = resources[1]
    original_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (credential == CLAIMANT and action == "owner_session"
         and namespace == ROUND_TRIP_AUTH_NS)
        or original_authorizer(credential, action, namespace, holder)
    )
    try:
        policy = replace(
            policy_for(resources[0]), expected_authority_id=authority_id,
            authority_namespace=ROUND_TRIP_AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, original_tickets = compose()

        key = Ed25519PrivateKey.generate()
        proof_store = AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: NOW, pairing_verifier=lambda *_: True, create=True)
        proof_store.register_credential(
            transport_credential=ADMIN,
            registration=OwnerCredentialRegistrationV1(
                authority_id, ROUND_TRIP_AUTH_NS, "installation", principal,
                "owner-key", 1,
                key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "enroll",
            ),
        )
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: NOW, create=True)
        request = OwnerSessionLoginRequestV1(
            authority_id, ROUND_TRIP_AUTH_NS, "installation", principal,
            "owner-key", 1, "sylanne-owner-console", "http://localhost:6185",
        )
        challenge = sessions.begin_login(
            transport_credential=CLAIMANT, request=request)
        token = sessions.accept_login(
            transport_credential=CLAIMANT, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))

        server = compose_local_owner_authority(
            core=core, v2_fences={ROUND_TRIP_AUTH_NS: service},
            graph_db_path=tmp_path / "business.db",
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=original_tickets._first_claim_verifier,
            claimant_verifier=None, owner_proofs=proof_store,
            owner_sessions=sessions,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={("a" * 64, "installed"): AdministratorInstallationV2(
                "installation", "administrator", "policy", "capabilities-v2", "c" * 64)},
            namespace_bindings_v2={("a" * 64, "installed", ROLE): ROUND_TRIP_AUTH_NS},
        )
        tickets = server._v2_owner_tickets
        assert isinstance(tickets._graph_commit_verifier, PinnedCurrentGraphVerifier)
        assert tickets._claimant_verifier is None
        coordinator._GraphCoordinator__content_fence_v2.tickets = tickets
        ticket, operation, value = _owner_issue(creation, authority_id, principal)
        tickets.register_ticket(
            credential=ADMIN, authority_namespace=ROUND_TRIP_AUTH_NS,
            ticket=ticket)
        pending = tickets.reserve_issue(
            credential=CLAIMANT, authority_namespace=ROUND_TRIP_AUTH_NS,
            operation=operation, session_token=token, session_request=request)
        assert pending.phase == "pending"
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=value)
        assert tickets._graph_commit_verifier(operation, proof) is True
        committed = tickets.finalize_issue(
            credential=CLAIMANT, authority_namespace=ROUND_TRIP_AUTH_NS,
            operation=operation, proof=proof,
            session_token=token, session_request=request)
        assert committed.phase == "committed"
        sessions.logout(
            transport_credential=CLAIMANT, token=token, request=request)
        with pytest.raises(AuthorityUnavailable, match="not current"):
            tickets.finalize_issue(
                credential=CLAIMANT, authority_namespace=ROUND_TRIP_AUTH_NS,
                operation=operation, proof=proof,
                session_token=token, session_request=request)
    finally:
        for resource in resources:
            resource.close()
