"""Owner sessions cross the installed Authority mTLS channel."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import ssl
from threading import Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.host_tests.alpha1.test_authority_mtls_loopback import AuthorityMtlsLoopbackTests
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import AUTH_NS, ROLE, _installed
from sylanne3.authority_service.mtls_server import (
    AuthorityRpcServer, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
    from_wire as session_from_wire, to_wire as session_to_wire,
)
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.v2_fence_port import V2FencePort


def test_session_wire_rejects_extra_fields():
    request = OwnerSessionLoginRequestV1(
        "authority-1", AUTH_NS, "installation",
        OwnerPrincipalV1("paired-idp", "account", "incarnation-1"),
        "key-1", 1, "sylanne-owner-console", "http://localhost:6185",
    )
    raw = session_to_wire(request)
    assert session_from_wire(raw) == request
    with pytest.raises((TypeError, ValueError)):
        session_from_wire({**raw, "host_jwt": "stateless"})


def test_owner_session_mtls_port_round_trip_and_missing_store_hold(tmp_path):
    files = AuthorityMtlsLoopbackTests._certificates(tmp_path)
    der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text("ascii"))
    peer = MtlsPeerCredential(hashlib.sha256(der).hexdigest())
    (_, _, _, compose, _, _, authority_id, resources) = _installed(
        tmp_path, client_peer=peer)
    core = resources[1]
    previous_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        credential == peer and namespace == AUTH_NS
        and action in {"owner_pair", "owner_session", "owner_session_revoke"}
    ) or previous_authorizer(credential, action, namespace, holder)
    key = Ed25519PrivateKey.generate()
    principal = OwnerPrincipalV1("paired-idp", "account", "incarnation-1")
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, "installation", principal, "key-1", 1,
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "enroll-1",
    )
    proofs = AuthorityV2OwnerProofStore(
        core, utc_clock=lambda: datetime.now(timezone.utc),
        pairing_verifier=lambda *_: True, create=True,
    )
    sessions = AuthorityV2OwnerSessionStore(
        core, utc_clock=lambda: datetime.now(timezone.utc), create=True,
    )
    original_server, _ = compose()

    def server_with(store):
        return AuthorityRpcServer(
            core, v2_fences=original_server._v2_fences,
            v2_owner_sessions=store,
            administrator_authorizer=original_server._administrator_authorizer,
            publisher_manifest_verifier=original_server._publisher_manifest_verifier,
            installations_v2=original_server._installations_v2,
            namespace_bindings_v2=original_server._namespace_bindings_v2,
        )

    server = server_with(sessions)
    loop = asyncio.new_event_loop()
    thread = Thread(target=lambda: (asyncio.set_event_loop(loop), loop.run_forever()),
                    name="owner-session-rpc-loop", daemon=True)
    thread.start()
    listener = None
    port = None
    try:
        listener = asyncio.run_coroutine_threadsafe(server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2)), loop).result(timeout=10)
        profile = AuthorityTlsProfile(
            "installed", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", authority_id, files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=2,
        )
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("c" * 64),
        )

        async def pair():
            transport = MtlsAuthorityTransport({"installed": profile})
            try:
                handshake = await transport.handshake(request, protocol="sylanne3.authority.v2")
                return await transport.installation_grant_v2(request, handshake)
            finally:
                await transport.close()

        grant = asyncio.run(pair())
        port = V2FencePort(request, {"installed": profile}, grant)
        port.provision_namespace(namespace=ROLE, request_id="owner-session-namespace-1")
        proofs.register_credential(transport_credential=peer, registration=registration)
        login_request = OwnerSessionLoginRequestV1(
            authority_id, AUTH_NS, "installation", principal, "key-1", 1,
            "sylanne-owner-console", "http://localhost:6185",
        )
        challenge = port.begin_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                             request=login_request)
        token = port.accept_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                          challenge=challenge,
                                          signature=key.sign(challenge.signed_bytes()))
        assert port.describe_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                           token=token) == login_request
        with pytest.raises(RuntimeError):
            server._v2_command(
                "describe_owner_session_v1", peer, "installed", "c" * 64,
                {"namespace": "unmapped-namespace", "token": token},
            )
        assert port.current_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                          request=login_request, token=token)
        port.revoke_all_owner_sessions(namespace=ROLE, authority_namespace=AUTH_NS,
                                       request=login_request, token=token)
        with pytest.raises(RuntimeError):
            port.current_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                       request=login_request, token=token)
        with pytest.raises(RuntimeError):
            port.describe_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                        token=token)
        with pytest.raises(RuntimeError):
            server._v2_command(
                "describe_owner_session_v1", peer, "installed", "c" * 64,
                {"namespace": AUTH_NS, "token": token,
                 "request": session_to_wire(login_request)},
            )
        second_challenge = port.begin_owner_session(
            namespace=ROLE, authority_namespace=AUTH_NS, request=login_request)
        second = port.accept_owner_session(
            namespace=ROLE, authority_namespace=AUTH_NS, challenge=second_challenge,
            signature=key.sign(second_challenge.signed_bytes()))
        port.logout_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                  request=login_request, token=second)
        with pytest.raises(RuntimeError):
            port.current_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                       request=login_request, token=second)
        third_challenge = port.begin_owner_session(
            namespace=ROLE, authority_namespace=AUTH_NS, request=login_request)
        third = port.accept_owner_session(
            namespace=ROLE, authority_namespace=AUTH_NS, challenge=third_challenge,
            signature=key.sign(third_challenge.signed_bytes()))
        port.revoke_owner_session_key(namespace=ROLE, authority_namespace=AUTH_NS,
                                      request=login_request, token=third)
        with pytest.raises(RuntimeError):
            port.begin_owner_session(namespace=ROLE, authority_namespace=AUTH_NS,
                                     request=login_request)
        with pytest.raises(RuntimeError):
            server._v2_command(
                "begin_owner_session_v1", peer, "installed", "c" * 64,
                {"namespace": AUTH_NS,
                 "request": {**session_to_wire(login_request), "host_jwt": "stateless"}},
            )
        missing = server_with(None)
        with pytest.raises(RuntimeError):
            missing._v2_command(
                "begin_owner_session_v1", peer, "installed", "c" * 64,
                {"namespace": AUTH_NS, "request": session_to_wire(login_request)},
            )
        asyncio.run_coroutine_threadsafe(missing.aclose(), loop).result(timeout=10)
    finally:
        if port is not None:
            port.close()
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
