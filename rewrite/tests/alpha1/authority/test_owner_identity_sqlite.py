"""Installer pairing state is durable, fresh and revocation-aware."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import MtlsPeerCredential
from sylanne3.authority_service.v2_owner_contract import OwnerClaimTicketV1, OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(NS)
PRINCIPAL = OwnerPrincipalV1("local-admin", "account-1", "incarnation-1")
ADMIN = MtlsPeerCredential("a" * 64)
PLUGIN = MtlsPeerCredential("b" * 64)
NOW = datetime(2029, 1, 1, tzinfo=timezone.utc)
EXPIRY = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _core(path, *, create):
    core = AuthorityServiceCore(
        path, create=create,
        authorizer=lambda credential, action, namespace, _: (
            type(credential) is MtlsPeerCredential and namespace == AUTH_NS and (
                credential == ADMIN and action in {"owner_identity_pair", "owner_identity_revoke"}
                or credential == PLUGIN and action in {"owner_pair", "owner_session"}
            )
        ),
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True,
    )
    if create:
        with core._tx() as db:
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
            db.execute("INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (AUTH_NS, "holder", 1, "active", None, None, 0, "deletion", 0,
                        "genesis", "clear", "execution", 0, "genesis", "nonce"))
    return core


def _subjects(core):
    with core._tx() as db:
        authority_id = core._id(db)
    key = Ed25519PrivateKey.generate()
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, "installation", PRINCIPAL, "owner-key", 1,
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw), "enroll-1",
    )
    ticket = OwnerClaimTicketV1(
        authority_id, "installation", NS, PRINCIPAL, "ticket-1", "create-1",
        "sha256:" + "1" * 64, "sha256:" + "2" * 64, "C" * 43,
        "2030-01-01T00:00:00Z",
    )
    return key, registration, ticket


def test_durable_pairing_reads_and_creation_revoke(tmp_path):
    path = tmp_path / "authority.sqlite"
    core = _core(path, create=True)
    _, registration, ticket = _subjects(core)
    source = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW, create=True)
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    source.pair_creation(administrator_credential=ADMIN, authority_namespace=AUTH_NS,
                         ticket=ticket, client_certificate_sha256=PLUGIN.certificate_sha256,
                         valid_until_utc=EXPIRY)
    source.pair_credential(administrator_credential=ADMIN, registration=registration,
                           client_certificate_sha256=PLUGIN.certificate_sha256,
                           valid_until_utc=EXPIRY)
    assert verifier.first_claim(PLUGIN, ticket, AUTH_NS)
    assert verifier.pair_credential(PLUGIN, registration)
    assert not verifier.first_claim(ADMIN, ticket, AUTH_NS)
    with core._tx() as db:
        source.require_current_creation_pairing_in_tx(
            db, authority_namespace=AUTH_NS, ticket=ticket,
            client_certificate_sha256=PLUGIN.certificate_sha256)
        source.require_current_registration_in_tx(
            db, registration, PLUGIN.certificate_sha256)
    core.close()

    core = _core(path, create=False)
    source = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW)
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    assert verifier.first_claim(PLUGIN, ticket, AUTH_NS)
    with pytest.raises(AuthorityUnavailable):
        source.revoke_creation(administrator_credential=PLUGIN,
                               authority_namespace=AUTH_NS)
    source.revoke_creation(administrator_credential=ADMIN,
                           authority_namespace=AUTH_NS)
    assert not verifier.first_claim(PLUGIN, ticket, AUTH_NS)
    with core._tx() as db, pytest.raises(AuthorityUnavailable):
        source.require_current_creation_pairing_in_tx(
            db, authority_namespace=AUTH_NS, ticket=ticket,
            client_certificate_sha256=PLUGIN.certificate_sha256)
    core.close()


def test_credential_pairing_revoke_invalidates_registered_key_and_session(tmp_path):
    core = _core(tmp_path / "authority.sqlite", create=True)
    key, registration, _ = _subjects(core)
    source = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW, create=True)
    verifier = OwnerDeploymentVerifier(source, lambda: NOW)
    source.pair_credential(administrator_credential=ADMIN, registration=registration,
                           client_certificate_sha256=PLUGIN.certificate_sha256,
                           valid_until_utc=EXPIRY)
    proofs = AuthorityV2OwnerProofStore(
        core, utc_clock=lambda: NOW, pairing_verifier=verifier.pair_credential, create=True)
    proofs.register_credential(transport_credential=PLUGIN, registration=registration)
    sessions = AuthorityV2OwnerSessionStore(
        core, utc_clock=lambda: NOW, current_pairing_source=source, create=True)
    request = OwnerSessionLoginRequestV1(
        registration.authority_id, AUTH_NS, "installation", PRINCIPAL,
        registration.credential_id, registration.credential_epoch,
        "sylanne-owner-console", "http://localhost:6185",
    )
    challenge = sessions.begin_login(transport_credential=PLUGIN, request=request)
    token = sessions.accept_login(transport_credential=PLUGIN, challenge=challenge,
                                  signature=key.sign(challenge.signed_bytes()))
    assert sessions.require_current(transport_credential=PLUGIN, token=token,
                                    request=request) == request
    source.revoke_credential(administrator_credential=ADMIN,
                             authority_namespace=AUTH_NS, principal=PRINCIPAL)
    assert not verifier.pair_credential(PLUGIN, registration)
    with core._tx() as db, pytest.raises(AuthorityUnavailable):
        source.require_current_registration_in_tx(
            db, registration, PLUGIN.certificate_sha256)
    with pytest.raises(AuthorityUnavailable):
        sessions.require_current(transport_credential=PLUGIN, token=token,
                                 request=request)
    with pytest.raises(AuthorityUnavailable):
        sessions.begin_login(transport_credential=PLUGIN, request=request)
    core.close()


def test_session_checks_pairing_expiry_and_exact_scope_inside_core_transaction(tmp_path):
    core = _core(tmp_path / "authority.sqlite", create=True)
    key, registration, _ = _subjects(core)
    current = [NOW]
    source = AuthorityOwnerPairingSource(core, utc_clock=lambda: current[0], create=True)
    verifier = OwnerDeploymentVerifier(source, lambda: current[0])
    source.pair_credential(
        administrator_credential=ADMIN, registration=registration,
        client_certificate_sha256=PLUGIN.certificate_sha256,
        valid_until_utc=NOW + timedelta(seconds=10),
    )
    proofs = AuthorityV2OwnerProofStore(
        core, utc_clock=lambda: current[0], pairing_verifier=verifier.pair_credential,
        create=True)
    proofs.register_credential(transport_credential=PLUGIN, registration=registration)
    sessions = AuthorityV2OwnerSessionStore(
        core, utc_clock=lambda: current[0], current_pairing_source=source, create=True)
    request = OwnerSessionLoginRequestV1(
        registration.authority_id, AUTH_NS, "installation", PRINCIPAL,
        registration.credential_id, registration.credential_epoch,
        "sylanne-owner-console", "http://localhost:6185",
    )
    with core._tx() as db:
        with pytest.raises(AuthorityUnavailable):
            source.require_current_owner_key_in_tx(db, request, b"x" * 32)
        with pytest.raises(AuthorityUnavailable):
            source.require_current_owner_key_in_tx(
                db, replace(request, authority_namespace="other-namespace"),
                registration.public_key)
    challenge = sessions.begin_login(transport_credential=PLUGIN, request=request)
    token = sessions.accept_login(
        transport_credential=PLUGIN, challenge=challenge,
        signature=key.sign(challenge.signed_bytes()), session_ttl_seconds=3600)
    current[0] = NOW + timedelta(seconds=11)
    with pytest.raises(AuthorityUnavailable):
        sessions.require_current(transport_credential=PLUGIN, token=token,
                                 request=request)
    with pytest.raises(AuthorityUnavailable):
        sessions.begin_login(transport_credential=PLUGIN, request=request)
    core.close()
