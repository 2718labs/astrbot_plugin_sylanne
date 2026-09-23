"""The claimant channel preserves Owner issue identity and verifier boundaries."""

from dataclasses import asdict, replace
from datetime import datetime, timezone

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_contract import from_wire
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
    to_wire,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


ROLE = NamespaceId("bot-owner", "persona-owner")
AUTH_NS = namespace_ref(ROLE)
CLAIMANT = MtlsPeerCredential("a" * 64)
ADMIN = MtlsPeerCredential("b" * 64)
REQUEST = {"protocol": AUTHORITY_V2_PROTOCOL, "profile_id": "installed",
           "plugin_name": "astrbot_plugin_sylanne", "host_api_version": "4.28.1",
           "manifest_sha256": "c" * 64}


def digest(ch):
    return "sha256:" + ch * 64


@pytest.fixture
def owner_rpc(tmp_path):
    seed = DeletionJournal(tmp_path / "seed.db", create=True)
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=AUTH_NS,
        journal_id="execution-owner", create=True)
    head = seed.latest_head()
    seed_head = JournalHead(head.journal_id, head.seq, head.chain_digest)

    def authorize(peer, action, namespace, holder):
        if action in {"install", "seal_v2_only"}:
            return peer == CLAIMANT
        if action == "owner_pair":
            return peer == ADMIN and namespace == AUTH_NS
        if action == "owner_claim":
            return peer == CLAIMANT and namespace == AUTH_NS
        if action == "owner_guard_read":
            return peer == CLAIMANT and namespace == AUTH_NS and holder == "holder-owner"
        return peer == CLAIMANT and namespace in {"seed", AUTH_NS}

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorize,
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True)
    try:
        core.register_namespace(CLAIMANT, "seed", "seed-holder", seed_head,
                                JournalHead("seed-execution", 0, "genesis"))
        core.seal_v2_only(CLAIMANT)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=AUTH_NS)
        verified = []
        tickets = AuthorityV2OwnerTicketStore(
            core, create=True,
            utc_clock=lambda: datetime(2029, 1, 1, tzinfo=timezone.utc),
            first_claim_verifier=lambda *_: True,
            claimant_verifier=lambda peer, operation: peer == CLAIMANT,
            graph_commit_verifier=lambda operation, proof:
                verified.append((operation, proof)) or True,
        )
        installations = {
            (peer.certificate_sha256, "installed"): AdministratorInstallationV2(
                installation, "holder-owner", "policy", "capabilities-v2",
                "c" * 64)
            for peer, installation in ((CLAIMANT, "installation-owner"),
                                       (ADMIN, "installation-admin"))
        }
        server = AuthorityRpcServer(
            core, v2_fences=service, v2_owner_tickets=tickets,
            administrator_authorizer=lambda *_: True,
            publisher_manifest_verifier=lambda *_: True,
            installations_v2=installations,
            namespace_bindings_v2={
                (CLAIMANT.certificate_sha256, "installed", ROLE): AUTH_NS,
                (ADMIN.certificate_sha256, "installed", ROLE): AUTH_NS,
            },
        )
        yield server, core, verified
    finally:
        core.close()
        seed.close()
        deletion.close()
        guard.close()
        execution.close()


def paired(server, peer):
    channel = b"channel-" + peer.certificate_sha256.encode()
    handshake = server._dispatch_for_test("handshake", REQUEST, peer, channel)
    binding = handshake["channel_binding_sha256"]

    def call(method, command):
        return server._dispatch_for_test(
            method, REQUEST, peer, channel, handshake_binding=binding,
            command=command)

    return call


def test_owner_issue_rpc_exact_replay_and_claimant_boundary(owner_rpc):
    server, core, verified = owner_rpc
    claimant = paired(server, CLAIMANT)
    admin = paired(server, ADMIN)
    genesis_result = claimant("namespace_genesis", {
        "namespace": asdict(ROLE), "request_id": "owner-genesis"})
    authority_id = server._authority_id()
    principal = OwnerPrincipalV1("provider", "account", "incarnation")
    ticket = OwnerClaimTicketV1(
        authority_id, "installation-owner", ROLE, principal, "ticket-owner",
        "creation-owner", digest("a"), digest("b"), "C" * 43,
        "2030-01-01T00:00:00Z")
    genesis = OwnerAuthorizationGuardV1(
        authority_id, "installation-owner", ROLE, 0, "genesis", 0, 0)
    operation = OwnerAuthorizationOperationV1(
        "issue", "issue-owner", authority_id, "installation-owner", ROLE,
        principal, "grant-owner", digest("c"), 0, genesis, ticket)
    proof = OwnerGraphCommitProofV1(
        ROLE, operation.operation_id, operation.request_digest,
        operation.grant_id, operation.grant_digest, "graph-owner", 1, 1, 2,
        digest("d"))
    ticket_command = {"namespace": AUTH_NS, "ticket": to_wire(ticket)}
    # Independent pairer registers the original ticket for the claimant's
    # installation; pairing never grants owner_claim.
    assert admin("register_owner_ticket", ticket_command)["ticket"] == to_wire(ticket)
    issue_command = {"namespace": AUTH_NS, "operation": to_wire(operation)}
    with pytest.raises(RuntimeError):
        admin("reserve_owner_issue", issue_command)
    pending = claimant("reserve_owner_issue", issue_command)["receipt"]
    assert pending["phase"] == "pending"
    assert claimant("reserve_owner_issue", issue_command)["receipt"] == pending
    with pytest.raises(RuntimeError):
        claimant("reserve_owner_issue", {
            **issue_command, "operation": {**to_wire(operation), "extra": 1}})
    finalize = {**issue_command, "proof": to_wire(proof)}
    trusted_verifier = server._v2_owner_tickets._graph_commit_verifier
    server._v2_owner_tickets._graph_commit_verifier = None
    with pytest.raises(RuntimeError):
        claimant("finalize_owner_issue", finalize)
    assert verified == []
    server._v2_owner_tickets._graph_commit_verifier = trusted_verifier
    assert claimant("finalize_owner_issue", finalize)["receipt"]["phase"] == "committed"
    assert len(verified) == 1
    assert claimant("finalize_owner_issue", finalize)["receipt"]["phase"] == "committed"
    assert len(verified) == 1
    with pytest.raises(RuntimeError):
        claimant("get_current_owner_guard", {"namespace": AUTH_NS})
    read_permit = claimant("begin_fence", {
        "namespace": AUTH_NS, "holder": "holder-owner", "operation": "read",
        "operation_id": "owner-guard-read", "expected_anchor": genesis_result["anchor"],
    })["permit"]
    guarded = claimant("get_current_owner_guard_for_fence", {
        "namespace": AUTH_NS, "permit": read_permit})
    assert guarded["guard"]["authorization_revision"] == 1
    assert guarded["permit"] == read_permit
    with pytest.raises(RuntimeError):
        claimant("finalize_owner_issue", {
            **finalize, "proof": to_wire(replace(proof, graph_epoch=3))})
    with pytest.raises(RuntimeError):
        admin("get_current_owner_guard_for_fence", {
            "namespace": AUTH_NS, "permit": read_permit})
    claimant("finish_fence", {
        "permit": read_permit, "request_id": "owner-guard-read-finish",
        "request_digest": digest("f")})
    with pytest.raises(RuntimeError):
        claimant("get_current_owner_guard_for_fence", {
            "namespace": AUTH_NS, "permit": read_permit})


@pytest.mark.asyncio
async def test_transport_rejects_guard_bound_to_different_permit(owner_rpc, tmp_path):
    server, _, _ = owner_rpc
    claimant = paired(server, CLAIMANT)
    genesis = claimant("namespace_genesis", {
        "namespace": asdict(ROLE), "request_id": "guard-decoder-genesis"})
    permit_wire = claimant("begin_fence", {
        "namespace": AUTH_NS, "holder": "holder-owner", "operation": "read",
        "operation_id": "guard-decoder-read", "expected_anchor": genesis["anchor"],
    })["permit"]
    permit = from_wire(permit_wire)
    handshake = AuthorityHandshake(
        "paired", server._authority_id(),
        "mtls:sha256:" + CLAIMANT.certificate_sha256, "e" * 64, True)
    profile = AuthorityTlsProfile(
        "installed", "localhost", 443, "localhost", server._authority_id(),
        tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "client.key")
    transport = MtlsAuthorityTransport({"installed": profile})
    request = AuthorityProvisioningRequest(
        AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
        tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))

    async def spoof(_request, _handshake, method, command, *, protocol):
        assert method == "get_current_owner_guard_for_fence"
        assert command == {"namespace": AUTH_NS, "permit": permit_wire}
        assert protocol == AUTHORITY_V2_PROTOCOL
        return {"guard": None, "permit": {**permit_wire, "token": "x" * 48},
                "channel_binding_sha256": handshake.channel_binding_sha256}

    transport._content_rpc = spoof
    with pytest.raises(RuntimeError, match="permit changed"):
        await transport.v2_get_current_owner_guard_for_fence(
            request, handshake, namespace=AUTH_NS, permit=permit)
