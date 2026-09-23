"""Owner actor pairings cross the installed mTLS Authority channel."""

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
from sylanne3.authority_service.v2_owner_contract import (
    OwnerActorBindingV1, OwnerPrincipalV1, to_wire,
)
from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.v2_fence_port import V2FencePort


def test_owner_binding_rpc_is_installed_scoped_and_revocable(tmp_path):
    files = AuthorityMtlsLoopbackTests._certificates(tmp_path)
    der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text("ascii"))
    peer = MtlsPeerCredential(hashlib.sha256(der).hexdigest())
    (_, _, _, compose, _, _, authority_id, resources) = _installed(
        tmp_path, client_peer=peer)
    core = resources[1]
    original = core._authorize_callback
    admin = MtlsPeerCredential("a" * 64)
    core._authorize_callback = lambda credential, action, namespace, holder: (
        credential == admin and namespace == AUTH_NS
        and action in {"owner_identity_pair", "owner_identity_revoke"}
    ) or original(credential, action, namespace, holder)
    source = AuthorityOwnerPairingSource(
        core, utc_clock=lambda: datetime(2029, 1, 1, tzinfo=timezone.utc), create=True)
    principal = OwnerPrincipalV1("paired-idp", "account", "incarnation-1")
    key = Ed25519PrivateKey.generate()
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, "installation", principal, "key-1", 1,
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "enroll-1",
    )
    binding = OwnerActorBindingV1(
        authority_id, "installation", ROLE, "owner-actor", principal, 1)
    base, _ = compose()
    server = AuthorityRpcServer(
        core, v2_fences=base._v2_fences, v2_owner_pairings=source,
        administrator_authorizer=base._administrator_authorizer,
        publisher_manifest_verifier=base._publisher_manifest_verifier,
        installations_v2=base._installations_v2,
        namespace_bindings_v2=base._namespace_bindings_v2,
    )
    loop = asyncio.new_event_loop()
    thread = Thread(target=lambda: (asyncio.set_event_loop(loop), loop.run_forever()),
                    daemon=True)
    thread.start()
    listener = None
    port = None
    try:
        listener = asyncio.run_coroutine_threadsafe(server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"]),
                timeout_seconds=2)), loop).result(timeout=10)
        profile = AuthorityTlsProfile(
            "installed", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", authority_id, files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=2)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))

        async def grant():
            transport = MtlsAuthorityTransport({"installed": profile})
            try:
                handshake = await transport.handshake(request, protocol="sylanne3.authority.v2")
                return await transport.installation_grant_v2(request, handshake)
            finally:
                await transport.close()

        port = V2FencePort(request, {"installed": profile}, asyncio.run(grant()))
        port.provision_namespace(namespace=ROLE, request_id="owner-binding-namespace-1")
        source.pair_credential(
            administrator_credential=admin, registration=registration,
            client_certificate_sha256=peer.certificate_sha256,
            valid_until_utc=datetime(2030, 1, 1, tzinfo=timezone.utc))
        source.pair_actor(administrator_credential=admin, binding=binding)
        assert port.current_owner_actor_binding(
            namespace=ROLE, authority_namespace=AUTH_NS, actor_id="owner-actor") == binding
        assert port.current_owner_principal_binding(
            namespace=ROLE, authority_namespace=AUTH_NS, principal=principal) == binding
        assert port.current_owner_actor_binding(
            namespace=ROLE, authority_namespace=AUTH_NS, actor_id="other") is None
        for command in (
            {"namespace": "unmapped", "actor_id": "owner-actor"},
            {"namespace": AUTH_NS, "actor_id": "owner-actor", "installation_id": "other"},
        ):
            with pytest.raises(RuntimeError):
                server._v2_command("current_owner_actor_binding_v1", peer, "installed",
                                   "c" * 64, command)
        with pytest.raises(RuntimeError):
            server._v2_command("current_owner_principal_binding_v1", peer, "installed",
                               "0" * 64, {"namespace": AUTH_NS,
                                          "principal": to_wire(principal)})
        source.revoke_actor(administrator_credential=admin, binding=binding)
        assert port.current_owner_actor_binding(
            namespace=ROLE, authority_namespace=AUTH_NS, actor_id="owner-actor") is None
        assert port.current_owner_principal_binding(
            namespace=ROLE, authority_namespace=AUTH_NS, principal=principal) is None
    finally:
        if port is not None:
            port.close()
        if listener is not None:
            loop.call_soon_threadsafe(listener.close)
            asyncio.run_coroutine_threadsafe(listener.wait_closed(), loop).result(timeout=10)
        asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        core.close()
