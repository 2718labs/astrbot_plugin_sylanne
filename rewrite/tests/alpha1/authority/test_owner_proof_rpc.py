"""Owner key proof crosses the real Authority mTLS channel without issuing a grant."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import ssl
from threading import Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.host_tests.alpha1.test_authority_mtls_loopback import AuthorityMtlsLoopbackTests
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    AUTH_NS, ROLE, _installed,
)
from rewrite.tests.alpha1.authority.test_owner_proof_store import (
    Clock, core_at, owner_operation, registration as stored_registration,
    request as stored_request, store as proof_store,
)
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import (
    AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1, canonical_digest,
)
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    OwnerProofRequestV1, from_wire, to_wire,
)
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


def _proof_values(authority_id, key):
    principal = OwnerPrincipalV1("paired-idp", "account", "incarnation-1")
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, "installation", principal, "key-1", 1,
        key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw), "enroll-1")
    ticket = OwnerClaimTicketV1(
        authority_id, "installation", ROLE, principal, "ticket-1", "create-1",
        "sha256:" + "a" * 64, "sha256:" + "b" * 64,
        "C" * 43, "2099-01-01T00:00:00Z")
    operation = OwnerAuthorizationOperationV1(
        "issue", "owner-issue-1", authority_id, "installation", ROLE,
        principal, "grant-1", "sha256:" + "c" * 64, 0,
        OwnerAuthorizationGuardV1(authority_id, "installation", ROLE,
                                  0, "genesis", 0, 0), ticket)
    request = OwnerProofRequestV1(
        authority_id, operation.operation_id, "first_owner_claim", AUTH_NS,
        "installation", principal, "key-1", 1, operation.request_digest,
        canonical_digest(ticket), "sha256:" + "d" * 64,
        "owner-login", "http://localhost:6185")
    return registration, operation, request


def test_owner_proof_wire_codec_rejects_noncanonical_shapes():
    key = Ed25519PrivateKey.generate()
    registration, operation, request = _proof_values("authority-1", key)
    for value in (registration, request):
        assert from_wire(to_wire(value)) == value
    altered = to_wire(registration)
    altered["public_key"] = altered["public_key"].upper()
    with pytest.raises(ValueError):
        from_wire(altered)
    altered = to_wire(request)
    altered["extra"] = "forbidden"
    with pytest.raises(ValueError):
        from_wire(altered)
    assert request.assert_matches_operation(operation) is None


def test_operation_only_recovery_rechecks_stored_signature(tmp_path):
    core = core_at(tmp_path / "proof.db", initialize=True)
    try:
        key = Ed25519PrivateKey.generate()
        subject = proof_store(core, Clock(), create=True)
        registration = stored_registration(core, key)
        operation = owner_operation(registration)
        request = stored_request(registration)
        subject.register_credential(
            transport_credential="installed-peer", registration=registration)
        challenge = subject.begin_challenge(
            transport_credential="installed-peer", request=request,
            operation=operation)
        acceptance = subject.accept_proof(
            transport_credential="installed-peer", challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))
        assert subject.get_accepted_for_operation(
            transport_credential="installed-peer", operation=operation) == acceptance
        with core._tx() as db:
            db.execute("UPDATE authority_owner_proof_challenges_v1 SET signature=? "
                       "WHERE operation_id=?", (b"x" * 64, operation.operation_id))
        with pytest.raises(RuntimeError, match="stored Owner signature differs"):
            subject.get_accepted_for_operation(
                transport_credential="installed-peer", operation=operation)
    finally:
        core.close()


def test_owner_proof_real_mtls_rpc_replay_and_binding(tmp_path):
    files = AuthorityMtlsLoopbackTests._certificates(tmp_path)
    der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text("ascii"))
    peer = MtlsPeerCredential(hashlib.sha256(der).hexdigest())
    (_, _, _, compose, _, _, authority_id, resources) = _installed(
        tmp_path, client_peer=peer)
    core = resources[1]
    original_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        credential == peer and namespace == AUTH_NS
        and action in {"owner_pair", "owner_proof"}) or original_authorizer(
            credential, action, namespace, holder)
    with core._tx() as db:
        db.execute(
            "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (AUTH_NS, "administrator", 1, "active", None, None, 0,
             "deletion", 0, "genesis", "clear", "execution", 0,
             "genesis", "nonce"))
    key = Ed25519PrivateKey.generate()
    registration, operation, proof_request = _proof_values(authority_id, key)
    store = AuthorityV2OwnerProofStore(
        core, utc_clock=lambda: datetime.now(timezone.utc),
        pairing_verifier=lambda credential, registration: (
            credential == peer and registration.principal == operation.principal),
        session_verifier=lambda credential, request: (
            credential == peer and request.host_login_jwt_digest
            == proof_request.host_login_jwt_digest
            and request.host_username == "owner-login"
            and request.dashboard_origin == "http://localhost:6185"),
        create=True)
    original_server, tickets = compose()
    server = compose_local_owner_authority(
        core=core, v2_fences=original_server._v2_fences,
        graph_db_path=tmp_path / "business.db",
        utc_clock=lambda: datetime.now(timezone.utc),
        first_claim_verifier=tickets._first_claim_verifier,
        claimant_verifier=None, owner_proofs=store,
        administrator_authorizer=original_server._administrator_authorizer,
        publisher_manifest_verifier=original_server._publisher_manifest_verifier,
        installations_v2=original_server._installations_v2,
        namespace_bindings_v2=original_server._namespace_bindings_v2)
    claimant = server._v2_owner_tickets._claimant_verifier
    assert claimant(peer, operation) is False
    loop = asyncio.new_event_loop()
    thread = Thread(target=lambda: (asyncio.set_event_loop(loop), loop.run_forever()),
                    name="owner-proof-rpc-loop", daemon=True)
    thread.start()
    listener = None
    try:
        listener = asyncio.run_coroutine_threadsafe(server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2)), loop).result(timeout=10)
        profile = AuthorityTlsProfile(
            "installed", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", authority_id, files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=2)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))

        async def scenario():
            transport = MtlsAuthorityTransport({"installed": profile})
            try:
                handshake = await transport.handshake(request, protocol="sylanne3.authority.v2")
                assert await transport.v2_get_owner_proof(
                    request, handshake, namespace=AUTH_NS, operation=operation) is None
                assert await transport.v2_register_owner_credential(
                    request, handshake, namespace=AUTH_NS,
                    registration=registration) == registration
                challenge = await transport.v2_begin_owner_proof(
                    request, handshake, namespace=AUTH_NS,
                    proof_request=proof_request, operation=operation)
                assert await transport.v2_begin_owner_proof(
                    request, handshake, namespace=AUTH_NS,
                    proof_request=proof_request, operation=operation) == challenge
                signature = key.sign(challenge.signed_bytes())
                acceptance = await transport.v2_accept_owner_proof(
                    request, handshake, namespace=AUTH_NS,
                    challenge=challenge, signature=signature)
                assert await transport.v2_accept_owner_proof(
                    request, handshake, namespace=AUTH_NS,
                    challenge=challenge, signature=signature) == acceptance
                assert await transport.v2_get_owner_proof(
                    request, handshake, namespace=AUTH_NS,
                    operation=operation) == acceptance
                assert claimant(peer, operation) is True
                with pytest.raises(RuntimeError):
                    await transport.v2_accept_owner_proof(
                        request, handshake, namespace=AUTH_NS,
                        challenge=challenge, signature=b"x" * 64)
                with pytest.raises(RuntimeError):
                    await transport.v2_get_owner_proof(
                        request, handshake, namespace=AUTH_NS,
                        operation=replace(operation, grant_id="wrong-grant",
                                          request_digest=None))
            finally:
                await transport.close()

        asyncio.run(scenario())
    finally:
        if listener is not None:
            listener.close()
            asyncio.run_coroutine_threadsafe(listener.wait_closed(), loop).result(timeout=10)
        asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(timeout=10)
        asyncio.run_coroutine_threadsafe(original_server.aclose(), loop).result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        loop.close()
        for resource in resources:
            resource.close()
