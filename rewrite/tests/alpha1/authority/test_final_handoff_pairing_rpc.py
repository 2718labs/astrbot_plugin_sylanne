"""The installed reverse pairing is read through an authenticated V2 RPC."""

import asyncio
import hashlib
import ssl

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as _certificates_module
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.final_handoff_pairing import FinalHandoffPairingV1
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.reverse_handoff import (
    AdministratorReverseHandoffProfile, ReverseGraphClaimClient,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


def _fingerprint(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        path.read_text(encoding="ascii"))).hexdigest()


def test_installed_pairing_is_public_bound_and_wrong_installation_fails(tmp_path):
    files = _certificates_module.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(_fingerprint(files["client.pem"]))
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=True)
    head = deletion.latest_head()
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, *_: credential == peer,
        deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True)
    core.register_namespace(
        peer, "ns-a", "holder-a",
        JournalHead(head.journal_id, head.seq, head.chain_digest),
        JournalHead("execution-a", 0, "genesis"))
    core.seal_v2_only(peer)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a")
    reverse = ReverseGraphClaimClient(AdministratorReverseHandoffProfile(
        namespace="ns-a", profile_id="profile-a", installation_id="installation-a",
        host="127.0.0.1", port=41234, server_name="localhost",
        expected_host_certificate_sha256=_fingerprint(files["server.pem"]),
        trust_root=files["ca.pem"], client_certificate=files["client.pem"],
        client_private_key=files["client.key"]))
    server = AuthorityRpcServer(
        core,
        administrator_authorizer=lambda credential, action, *_:
            credential == peer and action == "pair",
        publisher_manifest_verifier=lambda *_: True,
        v2_fences={"ns-a": service},
        v2_final_handoff_reverse={"ns-a": reverse},
        v2_final_handoff_issuers={"ns-a": "issuer-a"},
        installations_v2={
            (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
                "installation-a", "holder-a", "policy-a", "v2", "c" * 64)},
        namespace_bindings_v2={
            (peer.certificate_sha256, "profile-a", NamespaceId("bot-a", "persona-a")):
                "ns-a"})

    async def exercise():
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2))
        transport = MtlsAuthorityTransport({"profile-a": AuthorityTlsProfile(
            "profile-a", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"],
            files["client.pem"], files["client.key"], timeout_seconds=2)})
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "profile-a", "astrbot_plugin_sylanne",
            "4.28.1", tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))
        try:
            handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            raw = await transport._content_rpc(
                request, handshake, "read_final_handoff_pairing_v1",
                {"namespace": "ns-a", "installation_id": "installation-a"},
                protocol=AUTHORITY_V2_PROTOCOL)
            assert type(raw.pop("channel_binding_sha256")) is str
            pairing = FinalHandoffPairingV1.from_wire(raw)
            assert pairing.authority_id == server._authority_id()
            assert pairing.issuer_id == "issuer-a"
            assert pairing.reverse_profile_id == "profile-a"
            assert pairing.reverse_client_certificate_sha256 == _fingerprint(files["client.pem"])
            assert pairing.reverse_expected_host_certificate_sha256 == _fingerprint(files["server.pem"])
            assert not any("key" in name or "path" in name for name in raw)
            with pytest.raises(RuntimeError, match="unavailable"):
                await transport._content_rpc(
                    request, handshake, "read_final_handoff_pairing_v1",
                    {"namespace": "ns-a", "installation_id": "wrong-installation"},
                    protocol=AUTHORITY_V2_PROTOCOL)
            other = MtlsAuthorityTransport({"profile-a": AuthorityTlsProfile(
                "profile-a", "127.0.0.1", listener.sockets[0].getsockname()[1],
                "localhost", server._authority_id(), files["ca.pem"],
                files["second.pem"], files["second.key"], timeout_seconds=2)})
            try:
                with pytest.raises(RuntimeError, match="unavailable"):
                    await other.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            finally:
                await other.close()
        finally:
            await transport.close()
            listener.close()
            await listener.wait_closed()
            await server.aclose()

    try:
        asyncio.run(exercise())
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
