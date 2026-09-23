"""Durable independent Owner key possession without grant admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1, canonical_digest,
)
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    OwnerProofRequestV1,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "owner-proof")
NAMESPACE = namespace_ref(NS)
PRINCIPAL = OwnerPrincipalV1("dashboard", "account-17", "incarnation-3")
LOGIN = "sha256:" + "a" * 64
ORIGIN = "http://localhost:6185"


class Clock:
    def __init__(self):
        self.now = datetime(2029, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def core_at(path, *, initialize=False):
    core = AuthorityServiceCore(
        path, authorizer=lambda credential, action, namespace, _: (
            credential == "installed-peer" and namespace == NAMESPACE
            and action in {"owner_pair", "owner_proof"}),
        deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True,
        create=initialize,
    )
    if initialize:
        with core._tx() as db:
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
            db.execute(
                "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (NAMESPACE, "holder", 1, "active", None, None, 0,
                 "deletion", 0, "genesis", "clear", "execution", 0,
                 "genesis", "nonce"),
            )
    return core


def registration(core, key, *, epoch=1, credential_id="owner-key-1", enrollment="enroll-1"):
    with core._tx() as db:
        authority_id = core._id(db)
    return OwnerCredentialRegistrationV1(
        authority_id, NAMESPACE, "installation-a", PRINCIPAL, credential_id, epoch,
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw), enrollment,
    )


def owner_operation(reg, operation_id="claim-op-1"):
    ticket = OwnerClaimTicketV1(
        reg.authority_id, reg.installation_id, NS, reg.principal, "ticket-1",
        "create-persona-1", "sha256:" + "b" * 64, "sha256:" + "c" * 64,
        "C" * 43, "2030-01-01T00:00:00Z",
    )
    return OwnerAuthorizationOperationV1(
        "issue", operation_id, reg.authority_id, reg.installation_id, NS,
        reg.principal, "grant-1", "sha256:" + "d" * 64, 0,
        OwnerAuthorizationGuardV1(reg.authority_id, reg.installation_id,
                                  NS, 0, "genesis", 0, 0), ticket,
    )


def request(reg, *, operation="claim-op-1", digest=LOGIN,
            host_username="owner-login", origin=ORIGIN):
    owner = owner_operation(reg, operation)
    return OwnerProofRequestV1(
        reg.authority_id, operation, "first_owner_claim", reg.authority_namespace,
        reg.installation_id, reg.principal, reg.credential_id, reg.credential_epoch,
        owner.request_digest, canonical_digest(owner.ticket), digest,
        host_username, origin,
    )


def store(core, clock, *, create=False, pair=True, session=True):
    return AuthorityV2OwnerProofStore(
        core, utc_clock=clock,
        pairing_verifier=(lambda credential, _: credential == "installed-peer" and pair)
        if pair is not None else None,
        session_verifier=(lambda credential, proof: credential == "installed-peer"
                          and proof.host_login_jwt_digest == LOGIN
                          and proof.host_username == "owner-login"
                          and proof.dashboard_origin == ORIGIN and session)
        if session is not None else None,
        create=create,
    )


def test_signed_proof_acceptance_is_one_use_and_durable_across_restart(tmp_path):
    path = tmp_path / "authority.db"
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    core = core_at(path, initialize=True)
    try:
        subject = store(core, clock, create=True)
        reg = registration(core, key)
        assert subject.register_credential(
            transport_credential="installed-peer", registration=reg) == reg
        challenge = subject.begin_challenge(
            transport_credential="installed-peer", request=request(reg),
            operation=owner_operation(reg))
        assert subject.begin_challenge(
            transport_credential="installed-peer", request=request(reg),
            operation=owner_operation(reg)) == challenge
        signature = key.sign(challenge.signed_bytes())
        receipt = subject.accept_proof(
            transport_credential="installed-peer", challenge=challenge, signature=signature)
        assert receipt.challenge == challenge
        assert receipt.receipt_digest.startswith("sha256:")
        clock.now += timedelta(days=1)
        assert subject.accept_proof(
            transport_credential="installed-peer", challenge=challenge, signature=signature) == receipt
    finally:
        core.close()

    core = core_at(path)
    try:
        subject = store(core, clock, session=False)
        assert subject.get_current_acceptance(
            transport_credential="installed-peer", request=request(reg),
            operation=owner_operation(reg)) == receipt
        with pytest.raises(AuthorityUnavailable, match="host login binding denied"):
            subject.accept_proof(transport_credential="installed-peer",
                                 challenge=challenge, signature=signature)
        active = store(core, clock)
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            active.accept_proof(transport_credential="installed-peer",
                                challenge=challenge, signature=b"z" * 64)
        changed_session = AuthorityV2OwnerProofStore(
            core, utc_clock=clock, session_verifier=lambda *_: True)
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            changed_session.begin_challenge(transport_credential="installed-peer",
                                            request=request(reg, digest="sha256:" + "b" * 64),
                                            operation=owner_operation(reg))
        for altered in (
            replace(request(reg), authorization_request_digest="sha256:" + "e" * 64),
            replace(request(reg), ticket_digest="sha256:" + "e" * 64),
            replace(request(reg), dashboard_origin="https://other.example"),
        ):
            with pytest.raises(AuthorityUnavailable):
                subject.get_current_acceptance(
                    transport_credential="installed-peer", request=altered,
                    operation=owner_operation(reg))
    finally:
        core.close()


def test_signature_expiry_and_independent_pairing_are_required(tmp_path):
    core = core_at(tmp_path / "authority.db", initialize=True)
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    try:
        reg = registration(core, key)
        no_pairing = store(core, clock, create=True, pair=None)
        with pytest.raises(AuthorityUnavailable, match="pairing verifier is unavailable"):
            no_pairing.register_credential(transport_credential="installed-peer", registration=reg)
        denied = store(core, clock, pair=False)
        with pytest.raises(AuthorityUnavailable, match="pairing denied"):
            denied.register_credential(transport_credential="installed-peer", registration=reg)
        subject = store(core, clock)
        subject.register_credential(transport_credential="installed-peer", registration=reg)
        with pytest.raises(AuthorityUnavailable, match="host login binding denied"):
            subject.begin_challenge(
                transport_credential="installed-peer",
                request=request(reg, digest="sha256:" + "b" * 64),
                operation=owner_operation(reg))
        with pytest.raises(AuthorityUnavailable, match="host login binding denied"):
            subject.begin_challenge(
                transport_credential="installed-peer",
                request=request(reg, origin="https://other.example"),
                operation=owner_operation(reg))
        no_session = store(core, clock, session=None)
        with pytest.raises(AuthorityUnavailable, match="host login verifier is unavailable"):
            no_session.begin_challenge(
                transport_credential="installed-peer", request=request(reg),
                operation=owner_operation(reg))
        challenge = subject.begin_challenge(
            transport_credential="installed-peer", request=request(reg),
            operation=owner_operation(reg), ttl_seconds=2)
        forged = replace(challenge, nonce="F" * 43)
        with pytest.raises(AuthorityUnavailable, match="challenge binding differs"):
            subject.accept_proof(
                transport_credential="installed-peer", challenge=forged,
                signature=key.sign(forged.signed_bytes()))
        with pytest.raises(AuthorityUnavailable, match="signature denied"):
            subject.accept_proof(
                transport_credential="installed-peer", challenge=challenge,
                signature=Ed25519PrivateKey.generate().sign(challenge.signed_bytes()))
        clock.now += timedelta(seconds=3)
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.accept_proof(
                transport_credential="installed-peer", challenge=challenge,
                signature=key.sign(challenge.signed_bytes()))
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.begin_challenge(
                transport_credential="installed-peer", request=request(reg),
                operation=owner_operation(reg))
    finally:
        core.close()


def test_rotation_invalidates_old_accepted_proof_and_requires_new_operation(tmp_path):
    core = core_at(tmp_path / "authority.db", initialize=True)
    clock = Clock()
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    try:
        subject = store(core, clock, create=True)
        reg1 = registration(core, key1)
        subject.register_credential(transport_credential="installed-peer", registration=reg1)
        challenge1 = subject.begin_challenge(
            transport_credential="installed-peer", request=request(reg1),
            operation=owner_operation(reg1))
        subject.accept_proof(transport_credential="installed-peer", challenge=challenge1,
                             signature=key1.sign(challenge1.signed_bytes()))
        reg2 = registration(core, key2, epoch=2, credential_id="owner-key-2", enrollment="enroll-2")
        with pytest.raises(AuthorityUnavailable, match="current key or recovery proof"):
            subject.register_credential(transport_credential="installed-peer", registration=reg2)
        with pytest.raises(AuthorityUnavailable, match="previous Owner key denied rotation"):
            subject.register_credential(
                transport_credential="installed-peer", registration=reg2,
                rotation_signature=key2.sign(reg2.rotation_bytes()))
        subject.register_credential(
            transport_credential="installed-peer", registration=reg2,
            rotation_signature=key1.sign(reg2.rotation_bytes()))
        with pytest.raises(AuthorityUnavailable, match="not current"):
            subject.get_current_acceptance(
                transport_credential="installed-peer", request=request(reg1),
                operation=owner_operation(reg1))
        with pytest.raises(AuthorityUnavailable, match="not current"):
            subject.accept_proof(
                transport_credential="installed-peer", challenge=challenge1,
                signature=key1.sign(challenge1.signed_bytes()))
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            subject.begin_challenge(
                transport_credential="installed-peer", request=request(reg2),
                operation=owner_operation(reg2))
        challenge2 = subject.begin_challenge(
            transport_credential="installed-peer", request=request(reg2, operation="claim-op-2"),
            operation=owner_operation(reg2, "claim-op-2"))
        assert subject.accept_proof(
            transport_credential="installed-peer", challenge=challenge2,
            signature=key2.sign(challenge2.signed_bytes())).challenge == challenge2
        with pytest.raises(AuthorityUnavailable, match="epoch differs"):
            subject.register_credential(
                transport_credential="installed-peer",
                registration=replace(reg2, credential_id="owner-key-3",
                                     enrollment_operation_id="enroll-3"),
                rotation_signature=key2.sign(replace(reg2, credential_id="owner-key-3",
                                                     enrollment_operation_id="enroll-3").rotation_bytes()))
        reg3 = replace(reg2, credential_epoch=3, credential_id="owner-key-3",
                       enrollment_operation_id="enroll-1")
        with pytest.raises(AuthorityUnavailable, match="enrollment operation replay differs"):
            subject.register_credential(
                transport_credential="installed-peer", registration=reg3,
                rotation_signature=key2.sign(reg3.rotation_bytes()))
    finally:
        core.close()
