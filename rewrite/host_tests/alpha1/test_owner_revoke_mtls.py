"""Real mTLS route for the separate Owner authorization-revoke capability."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import ssl

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2,
    AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


def _digest(character: str) -> str:
    return "sha256:" + character * 64


@pytest.mark.asyncio
async def test_owner_revoke_uses_own_mtls_capability_and_channel(tmp_path):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    namespace = NamespaceId("bot-revoke", "persona-revoke")
    authority_namespace = namespace_ref(namespace)
    peers = tuple(MtlsPeerCredential(hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(files[f"{name}.pem"].read_text(encoding="ascii"))
    ).hexdigest()) for name in ("client", "second"))
    revoker, claimant_only = peers
    seed = DeletionJournal(tmp_path / "seed.db", create=True)
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution-revoke-mtls", create=True)

    def authorize(peer, action, scope, holder):
        if action == "owner_authorization_revoke":
            return peer == revoker and scope == authority_namespace
        if action == "owner_claim":
            return peer in peers and scope == authority_namespace
        return peer in peers and scope in {"seed", authority_namespace}

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorize,
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True)
    server = None
    transports = []
    try:
        head = seed.latest_head()
        core.register_namespace(
            revoker, "seed", "seed-holder",
            JournalHead(head.journal_id, head.seq, head.chain_digest),
            JournalHead("seed-execution", 0, "genesis"))
        core.seal_v2_only(revoker)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=authority_namespace)
        tickets = AuthorityV2OwnerTicketStore(
            core, create=True,
            utc_clock=lambda: datetime(2029, 1, 1, tzinfo=timezone.utc),
            first_claim_verifier=lambda *_: True,
            claimant_verifier=lambda *_: True,
            graph_commit_verifier=lambda *_: True,
            revoke_graph_commit_verifier=lambda *_: True)
        installations = {
            (peer.certificate_sha256, "installed"): AdministratorInstallationV2(
                "installation-revoke", "holder-revoke", "policy-revoke",
                "capabilities-v2", "c" * 64)
            for peer in peers
        }
        rpc = AuthorityRpcServer(
            core, v2_fences=service, v2_owner_tickets=tickets,
            administrator_authorizer=lambda *_: True,
            publisher_manifest_verifier=lambda *_: True,
            installations_v2=installations,
            namespace_bindings_v2={
                (peer.certificate_sha256, "installed", namespace): authority_namespace
                for peer in peers
            })
        server = await rpc.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2,
                max_message_bytes=65_536))
        port = server.sockets[0].getsockname()[1]
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))

        async def connect(name):
            profile = AuthorityTlsProfile(
                "installed", "127.0.0.1", port, "localhost", rpc._authority_id(),
                files["ca.pem"], files[f"{name}.pem"], files[f"{name}.key"],
                timeout_seconds=2, max_message_bytes=65_536)
            transport = MtlsAuthorityTransport({"installed": profile})
            transports.append(transport)
            return transport, await transport.handshake(
                request, protocol=AUTHORITY_V2_PROTOCOL)

        transport, handshake = await connect("client")
        assert handshake.valid_pairing(), handshake
        await transport.v2_namespace_genesis(
            request, handshake, namespace, "revoke-mtls-genesis")
        authority_id = rpc._authority_id()
        principal = OwnerPrincipalV1("provider", "account", "incarnation")
        ticket = OwnerClaimTicketV1(
            authority_id, "installation-revoke", namespace, principal,
            "ticket-revoke-mtls", "creation-revoke-mtls", _digest("a"),
            _digest("b"), "C" * 43, "2030-01-01T00:00:00Z")
        genesis = OwnerAuthorizationGuardV1(
            authority_id, "installation-revoke", namespace, 0, "genesis", 0, 0)
        issue = OwnerAuthorizationOperationV1(
            "issue", "issue-revoke-mtls", authority_id, "installation-revoke",
            namespace, principal, "grant-revoke-mtls", _digest("c"), 0,
            genesis, ticket)
        issue_proof = OwnerGraphCommitProofV1(
            namespace, issue.operation_id, issue.request_digest, issue.grant_id,
            issue.grant_digest, "graph-revoke-mtls", 1, 1, 2, _digest("d"))
        await transport.v2_register_owner_ticket(
            request, handshake, namespace=authority_namespace, ticket=ticket)
        await transport.v2_reserve_owner_issue(
            request, handshake, namespace=authority_namespace, operation=issue)
        issued = await transport.v2_finalize_owner_issue(
            request, handshake, namespace=authority_namespace,
            operation=issue, proof=issue_proof)
        revoke = OwnerAuthorizationOperationV1(
            "revoke", "revoke-mtls", authority_id, "installation-revoke",
            namespace, principal, issue.grant_id, _digest("e"), 1, issued.guard)
        pending = await transport.v2_reserve_owner_revoke(
            request, handshake, namespace=authority_namespace, operation=revoke)
        assert pending.phase == "pending"
        assert (await transport.v2_get_pending_owner_revoke(
            request, handshake, namespace=authority_namespace,
            operation_id=revoke.operation_id)) == pending
        assert (await transport.v2_reserve_owner_revoke(
            request, handshake, namespace=authority_namespace,
            operation=revoke)) == pending
        proof = OwnerGraphCommitProofV1(
            namespace, revoke.operation_id, revoke.request_digest,
            revoke.grant_id, revoke.grant_digest,
            "graph-revoke-mtls", 2, 2, 3, _digest("f"))
        committed = await transport.v2_finalize_owner_revoke(
            request, handshake, namespace=authority_namespace,
            operation=revoke, proof=proof)
        assert committed.phase == "committed"
        assert (await transport.v2_get_committed_owner_revoke(
            request, handshake, namespace=authority_namespace,
            operation_id=revoke.operation_id)) == committed
        other, other_handshake = await connect("second")
        assert handshake.channel_binding_sha256 != other_handshake.channel_binding_sha256
        with pytest.raises(RuntimeError, match="handshake channel"):
            await transport.v2_get_committed_owner_revoke(
                request, other_handshake, namespace=authority_namespace,
                operation_id=revoke.operation_id)
        with pytest.raises(RuntimeError):
            await other.v2_reserve_owner_revoke(
                request, other_handshake, namespace=authority_namespace,
                operation=revoke)
        with pytest.raises(RuntimeError):
            await other.v2_get_committed_owner_revoke(
                request, other_handshake, namespace=authority_namespace,
                operation_id=revoke.operation_id)
    finally:
        for transport in transports:
            await transport.close()
        if server is not None:
            server.close()
            await server.wait_closed()
        core.close()
        seed.close()
        deletion.close()
        guard.close()
        execution.close()
