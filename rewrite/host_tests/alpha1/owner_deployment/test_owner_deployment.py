"""Identity-port boundary tests for the first-Owner deployment wiring."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import MtlsPeerCredential
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1, canonical_digest,
)
from sylanne3.authority_service.v2_owner_proof import (
    OwnerCredentialRegistrationV1, OwnerProofAcceptanceV1,
    OwnerProofChallengeV1, OwnerProofRequestV1,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.owner_deployment import (
    CurrentCreationPairing, CurrentDashboardLogin, CurrentOwnerPairing,
    OwnerDeploymentVerifier, compose_owner_deployment,
)
from sylanne3.runtime_contracts import NamespaceId


NOW = datetime(2026, 9, 24, 0, 0, tzinfo=timezone.utc)
PEER = MtlsPeerCredential("a" * 64)
OTHER_PEER = MtlsPeerCredential("b" * 64)
PRINCIPAL = OwnerPrincipalV1("identity-provider", "account-1", "incarnation-1")
NAMESPACE = NamespaceId("bot-1", "persona-1")
AUTHORITY_NAMESPACE = namespace_ref(NAMESPACE)
TICKET = OwnerClaimTicketV1(
    "authority-1", "installation-1", NAMESPACE, PRINCIPAL, "ticket-1", "create-1",
    "sha256:" + "c" * 64, "sha256:" + "d" * 64, "e" * 43,
    "2026-09-24T00:05:00Z",
)
REGISTRATION = OwnerCredentialRegistrationV1(
    "authority-1", AUTHORITY_NAMESPACE, "installation-1", PRINCIPAL,
    "credential-1", 1, bytes.fromhex("11" * 32), "enrollment-1",
)
REQUEST = OwnerProofRequestV1(
    "authority-1", "issue-1", "first_owner_claim", AUTHORITY_NAMESPACE,
    "installation-1", PRINCIPAL, "credential-1", 1,
    "sha256:" + "f" * 64, "sha256:" + "0" * 64,
    "sha256:" + "1" * 64, "owner-login", "https://dashboard.example",
)


class IdentitySource:
    """Mutable independent records model revocation between Authority calls."""

    def __init__(self):
        expires = NOW + timedelta(minutes=1)
        self.creation = CurrentCreationPairing(TICKET, PEER.certificate_sha256, expires)
        self.pairing = CurrentOwnerPairing(REGISTRATION, PEER.certificate_sha256, expires)
        self.login = CurrentDashboardLogin(
            PRINCIPAL, "installation-1", AUTHORITY_NAMESPACE, "owner-login",
            REQUEST.host_login_jwt_digest, REQUEST.dashboard_origin,
            PEER.certificate_sha256, expires,
        )
        self.reads = {"creation": 0, "pairing": 0, "login": 0}

    def current_creation_pairing(self, authority_namespace):
        self.reads["creation"] += 1
        return self.creation if authority_namespace == AUTHORITY_NAMESPACE else None

    def current_owner_pairing(self, authority_namespace, principal):
        self.reads["pairing"] += 1
        return self.pairing if (authority_namespace, principal) == (
            AUTHORITY_NAMESPACE, PRINCIPAL) else None

    def current_dashboard_login(self, host_login_jwt_digest):
        self.reads["login"] += 1
        return self.login if host_login_jwt_digest == REQUEST.host_login_jwt_digest else None


def test_missing_host_identity_fails_before_authority_store_construction():
    with pytest.raises(AuthorityUnavailable, match="trusted Owner identity port"):
        compose_owner_deployment(
            core=None, v2_fences={}, graph_db_path="unused",
            utc_clock=lambda: NOW, identity=None,
            administrator_authorizer=lambda *_: True,
            publisher_manifest_verifier=lambda *_: True,
            installations_v2={}, namespace_bindings_v2={},
        )


def test_current_pairing_requires_exact_record_and_mtls_peer():
    source = IdentitySource()
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    assert verifier.first_claim(PEER, TICKET, AUTHORITY_NAMESPACE) is True
    assert verifier.pair_credential(PEER, REGISTRATION) is True
    assert verifier.first_claim(OTHER_PEER, TICKET, AUTHORITY_NAMESPACE) is False
    assert verifier.pair_credential(OTHER_PEER, REGISTRATION) is False
    source.creation = replace(source.creation, ticket=replace(TICKET, ticket_id="other"))
    source.pairing = replace(
        source.pairing, registration=replace(REGISTRATION, credential_epoch=2))
    assert verifier.first_claim(PEER, TICKET, AUTHORITY_NAMESPACE) is False
    assert verifier.pair_credential(PEER, REGISTRATION) is False
    assert source.reads == {"creation": 3, "pairing": 3, "login": 0}


def test_session_is_rechecked_and_bound_to_stable_principal_and_digest():
    source = IdentitySource()
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    assert verifier.current_session(PEER, REQUEST) is True
    source.login = replace(source.login, principal=replace(
        PRINCIPAL, account_incarnation="incarnation-2"))
    assert verifier.current_session(PEER, REQUEST) is False
    source.login = replace(source.login, principal=PRINCIPAL,
                           host_login_jwt_digest="sha256:" + "2" * 64)
    assert verifier.current_session(PEER, REQUEST) is False
    source.login = replace(source.login,
                           host_login_jwt_digest=REQUEST.host_login_jwt_digest,
                           dashboard_origin="https://different.example")
    assert verifier.current_session(PEER, REQUEST) is False
    source.login = None
    assert verifier.current_session(PEER, REQUEST) is False
    assert source.reads["login"] == 5


def test_expired_or_untrusted_record_never_authorizes():
    source = IdentitySource()
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    source.creation = replace(source.creation, valid_until_utc=NOW)
    source.pairing = replace(source.pairing, valid_until_utc=NOW)
    source.login = replace(source.login, valid_until_utc=NOW)
    assert verifier.first_claim(PEER, TICKET, AUTHORITY_NAMESPACE) is False
    assert verifier.pair_credential(PEER, REGISTRATION) is False
    assert verifier.current_session(PEER, REQUEST) is False
    assert verifier.current_session("a" * 64, REQUEST) is False
    source.login = replace(source.login, valid_until_utc=NOW + timedelta(minutes=1))
    assert OwnerDeploymentVerifier(source, lambda: NOW.replace(tzinfo=None)).current_session(
        PEER, REQUEST) is False


def test_accepted_proof_still_requires_live_pairing_and_login_at_issue():
    operation = OwnerAuthorizationOperationV1(
        "issue", "issue-1", "authority-1", "installation-1", NAMESPACE,
        PRINCIPAL, "grant-1", "sha256:" + "3" * 64, 0,
        OwnerAuthorizationGuardV1(
            "authority-1", "installation-1", NAMESPACE, 0, "genesis", 0, 0),
        TICKET,
    )
    request = replace(
        REQUEST, authorization_request_digest=operation.request_digest,
        ticket_digest=canonical_digest(TICKET),
    )
    acceptance = OwnerProofAcceptanceV1(
        OwnerProofChallengeV1(
            request, "N" * 43, "2026-09-24T00:00:00Z",
            "2026-09-24T00:05:00Z"),
        "sha256:" + "4" * 64, "2026-09-24T00:00:01Z",
    )
    source = IdentitySource()
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    assert verifier.current_claimant(PEER, operation, acceptance) is True
    source.login = None
    assert verifier.current_claimant(PEER, operation, acceptance) is False
    source.login = IdentitySource().login
    source.pairing = None
    assert verifier.current_claimant(PEER, operation, acceptance) is False
    source.pairing = IdentitySource().pairing
    source.creation = None
    assert verifier.current_claimant(PEER, operation, acceptance) is False
