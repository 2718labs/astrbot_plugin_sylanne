"""First Owner issue across the real graph and independent local Authority DBs."""

from dataclasses import replace
from datetime import datetime, timezone
import asyncio
import hashlib
import sqlite3
import ssl
from threading import Thread

import pytest

from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for
from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1,
)
from sylanne3.graph_coordinator import GraphCoordinator, namespace_ref
from sylanne3.graph_store import ProductionGraphStore, TypeRegistry
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_types import owner_grant_policy_digest_v1, owner_grant_spec
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.host.owner_issue_orchestration import FirstOwnerIssueOrchestrator
from sylanne3.runtime_contracts import InstallationGrantV2, NamespaceId, canonical_digest


ROLE = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(ROLE)
SUBJECT = "mtls:sha256:" + "a" * 64
PEER = MtlsPeerCredential("a" * 64)
ADMIN = "paired-admin"
CLAIMANT = "paired-claimant"
WORKER = "installed-graph-worker"


class LocalFencePort:
    def __init__(self, graph, service, tickets, authority_id):
        self.graph, self.service, self.tickets = graph, service, tickets
        self.installation_grant = InstallationGrantV2(
            authority_id, SUBJECT, "administrator", "installation", "a" * 64,
            "publisher-trust", "2", "b" * 64)

    def _outside_graph(self):
        assert not self.graph._lock._is_owned()

    def provision_namespace(self, *, namespace, request_id):
        self._outside_graph()
        return self.service.activate_namespace(
            credential=ADMIN, subject=SUBJECT, holder="administrator",
            namespace_id=namespace, request_id=request_id)

    def current_anchor(self, *, namespace, authority_namespace):
        self._outside_graph()
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return self.service.current_anchor(credential=WORKER, subject=SUBJECT)

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self._outside_graph()
        assert namespace == ROLE and authority_namespace == AUTH_NS and generation == 1
        return self.service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder=holder,
            operation=operation, operation_id=operation_id,
            expected_anchor=expected_anchor)

    def validate_fence(self, scope):
        self._outside_graph()
        return self.service.validate_fence(
            credential=WORKER, subject=SUBJECT, permit=scope.permit)

    def get_fence_operation(self, *, namespace, authority_namespace, operation_id):
        self._outside_graph()
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return self.service.get_fence_operation(
            credential=WORKER, subject=SUBJECT, operation_id=operation_id)

    def get_pending_owner_issue_for_graph_write(
            self, *, namespace, authority_namespace, operation_id, permit):
        self._outside_graph()
        assert namespace == ROLE and authority_namespace == AUTH_NS
        self.service.validate_fence(
            credential=WORKER, subject=SUBJECT, permit=permit)
        return self.tickets.get_pending_for_graph_write(
            credential=WORKER, authority_namespace=AUTH_NS,
            operation_id=operation_id, installation_id="installation",
            subject=SUBJECT, permit=permit)

    def finish_fence(self, scope, *, request_id, request_digest):
        self._outside_graph()
        self.service.finish_fence(
            credential=WORKER, subject=SUBJECT, permit=scope.permit,
            request_id=request_id, request_digest=request_digest)


def _installed(tmp_path, *, client_peer=None, admin_peer=None,
               extra_specs=()):
    worker_credential = client_peer if client_peer is not None else WORKER
    claimant_credential = client_peer if client_peer is not None else CLAIMANT
    admin_credential = admin_peer if admin_peer is not None else ADMIN
    genesis_credential = client_peer if client_peer is not None else ADMIN
    graph_path = tmp_path / "business.db"
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in extra_specs:
        registry.register(spec)
    graph = ProductionGraphStore(graph_path, registry)
    seed = DeletionJournal(tmp_path / "seed-deletion.db", create=True)
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=AUTH_NS,
        journal_id="execution:persona", create=True)
    seed_head = seed.latest_head()
    seed_head = JournalHead(seed_head.journal_id, seed_head.seq, seed_head.chain_digest)

    def authorize(credential, action, namespace, holder):
        if action in {"install", "seal_v2_only"}:
            return credential == admin_credential
        if namespace != AUTH_NS:
            return False
        if action == "namespace_genesis":
            return credential == genesis_credential
        if action == "owner_pair":
            return credential == admin_credential
        if action == "current" and credential == admin_credential:
            return True
        if action == "owner_claim":
            return credential == claimant_credential
        return credential == worker_credential and action in {"current", "write"} and (
            holder is None or holder == "administrator")

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase:
            ns == "seed" and current == seed_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            ns == "seed" and current == JournalHead("seed-execution", 0, "genesis"),
        effect_verifier=lambda *_: False, dispatch_verifier=lambda *_: False)
    core.register_namespace(admin_credential, "seed", "seed-holder", seed_head,
                            JournalHead("seed-execution", 0, "genesis"))
    core.seal_v2_only(admin_credential)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace=AUTH_NS)
    with core._tx() as db:
        authority_id = core._id(db)
    expected = {}
    principal = OwnerPrincipalV1("paired-idp", "account", "incarnation-1")

    def first_claim(credential, ticket, authority_namespace):
        if (credential != admin_credential or authority_namespace != AUTH_NS
                or ticket.principal != principal or ticket.challenge != "a" * 32
                or ticket.installation_id != "installation"
                or ticket.creation_operation_id != expected.get("operation_id")
                or ticket.creation_digest != expected.get("digest")):
            return False
        with sqlite3.connect(graph_path) as db:
            row = db.execute(
                "SELECT operation_id,digest FROM graph_namespace_provisioning_v2 "
                "WHERE bot=? AND persona=?", ROLE.as_tuple).fetchone()
        return row == (ticket.creation_operation_id,
                       ticket.creation_digest.removeprefix("sha256:"))

    port = LocalFencePort(graph, service, None, authority_id)

    def compose():
        installed = {
            ((client_peer or PEER).certificate_sha256, "installed"):
                AdministratorInstallationV2(
                    "installation", "administrator", "policy",
                    "capabilities-v2", "c" * 64),
        }
        bindings = {
            ((client_peer or PEER).certificate_sha256, "installed", ROLE): AUTH_NS,
        }
        if admin_peer is not None:
            installed[(admin_peer.certificate_sha256, "installed")] = (
                AdministratorInstallationV2(
                    "installation-admin", "administrator", "policy",
                    "capabilities-v2", "c" * 64))
            bindings[(admin_peer.certificate_sha256, "installed", ROLE)] = AUTH_NS
        server = compose_local_owner_authority(
            core=core, v2_fences={AUTH_NS: service}, graph_db_path=graph_path,
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=first_claim,
            claimant_verifier=lambda credential, operation:
                credential == claimant_credential and operation.principal == principal,
            administrator_authorizer=lambda credential, action, _, profile:
                credential in {client_peer or PEER, admin_peer} and action == "pair"
                and profile == "installed",
            publisher_manifest_verifier=lambda profile, name, version, digest:
                (profile, name, version, digest) == (
                    "installed", "astrbot_plugin_sylanne", "4.28.1", "c" * 64),
            installations_v2=installed,
            namespace_bindings_v2=bindings,
            create_owner_schema=True)
        port.tickets = server._v2_owner_tickets
        return server, port.tickets
    _, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    bootstrap = object()
    coordinator = (GraphCoordinator(
        graph, bootstrap, holder="administrator", content_fence_v2=port,
        d11_issuer=d11) if client_peer is None else None)
    resources = (graph, core, seed, deletion, guard, execution)
    return coordinator, bootstrap, service, compose, expected, principal, authority_id, resources


def _owner_issue(creation, authority_id, principal):
    ticket = OwnerClaimTicketV1(
        authority_id, "installation", ROLE, principal, "ticket-1",
        creation.operation_id, "sha256:" + creation.input_digest,
        "sha256:" + creation.input_digest, "a" * 32, "2099-01-01T00:00:00Z")
    value = {
        "schema": "sylanne3.graph.owner_grant.v1",
        "authority_id": authority_id, "installation_id": "installation",
        "grant_id": "first-owner", "principal": {
            "identity_provider": principal.identity_provider,
            "account_ref": principal.account_ref,
            "account_incarnation": principal.account_incarnation,
        },
        "ticket_id": ticket.ticket_id,
        "creation_operation_id": ticket.creation_operation_id,
        "creation_digest": ticket.creation_digest,
        "issue_operation_id": "owner-issue-1",
        "grant_revision": 1, "state": "pending_authority",
        "scope": "bot/persona", "issuer_ref": "authority:paired-installation",
        "capabilities": ["workbench.read"],
        "purposes": ["workbench_view"], "audiences": ["owner"],
        "activation_generation": 1,
        "graph_incarnation": creation.graph_incarnation,
    }
    ticket = replace(ticket, policy_digest=owner_grant_policy_digest_v1(
        value, bot=ROLE.bot_id, persona=ROLE.persona_id))
    guard = OwnerAuthorizationGuardV1(
        authority_id, "installation", ROLE, 0, "genesis", 0, 0)
    operation = OwnerAuthorizationOperationV1(
        "issue", "owner-issue-1", authority_id, "installation", ROLE,
        principal, "first-owner", "sha256:" + canonical_digest(value),
        0, guard, ticket)
    return ticket, operation, value


def test_local_graph_to_authority_owner_issue_replay_and_tamper(tmp_path):
    (coordinator, bootstrap, service, compose, expected, principal,
     authority_id, resources) = _installed(tmp_path)
    try:
        policy = replace(policy_for(resources[0]), expected_authority_id=authority_id,
                         authority_namespace=AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, tickets = compose()
        ticket, operation, value = _owner_issue(creation, authority_id, principal)
        tickets.register_ticket(
            credential=ADMIN, authority_namespace=AUTH_NS, ticket=ticket)
        pending = tickets.reserve_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS, operation=operation)
        assert pending.phase == "pending"
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=value)
        # The graph write and finished Authority fence can survive while the
        # claimant-side finalization has not happened yet.
        with resources[1]._tx() as db:
            assert db.execute(
                "SELECT 1 FROM authority_owner_issue_committed_v1 "
                "WHERE authority_namespace=?", (AUTH_NS,)).fetchone() is None
        anchor = service.current_anchor(credential=WORKER, subject=SUBJECT)
        unrelated = service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            operation="write", operation_id="unrelated-write-after-owner",
            expected_anchor=anchor)
        service.finish_fence(
            credential=WORKER, subject=SUBJECT, permit=unrelated,
            request_id="finish:unrelated-write-after-owner",
            request_digest="sha256:" + "e" * 64)
        _, tickets = compose()
        assert tickets.get_pending(
            credential=CLAIMANT, authority_namespace=AUTH_NS,
            operation_id=operation.operation_id) == pending
        committed = tickets.finalize_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS,
            operation=operation, proof=proof)
        assert committed.phase == "committed"
        assert tickets.finalize_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS,
            operation=operation, proof=proof) == committed
        assert coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=value) == proof
        with pytest.raises(AuthorityUnavailable):
            tickets.finalize_issue(
                credential=CLAIMANT, authority_namespace=AUTH_NS,
                operation=operation,
                proof=replace(proof, graph_receipt_digest="sha256:" + "f" * 64))
    finally:
        for resource in resources:
            resource.close()


def test_owner_issue_round_trip_over_real_loopback_mtls(tmp_path, monkeypatch):
    from rewrite.host_tests.alpha1.test_authority_mtls_loopback import (
        AuthorityMtlsLoopbackTests,
    )

    files = AuthorityMtlsLoopbackTests._certificates(tmp_path)

    def peer(name):
        der = ssl.PEM_cert_to_DER_cert(files[f"{name}.pem"].read_text("ascii"))
        return MtlsPeerCredential(hashlib.sha256(der).hexdigest())

    client_peer, admin_peer = peer("client"), peer("second")
    (_, bootstrap, _, compose, expected, principal,
     authority_id, resources) = _installed(
        tmp_path, client_peer=client_peer, admin_peer=admin_peer)
    server = None
    listener = None
    loop = asyncio.new_event_loop()
    thread = Thread(
        target=lambda: (asyncio.set_event_loop(loop), loop.run_forever()),
        name="owner-authority-test-loop", daemon=True)
    thread.start()
    client_port = admin_port = None
    try:
        server, _ = compose()
        listener = asyncio.run_coroutine_threadsafe(server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=2,
                max_message_bytes=65_536)), loop).result(timeout=10)
        port_number = listener.sockets[0].getsockname()[1]
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("c" * 64))

        def fence_port(name, identity, installation_id):
            profile = AuthorityTlsProfile(
                "installed", "127.0.0.1", port_number, "localhost",
                authority_id, files["ca.pem"], files[f"{name}.pem"],
                files[f"{name}.key"], timeout_seconds=2,
                max_message_bytes=65_536)
            grant = InstallationGrantV2(
                authority_id, "mtls:sha256:" + identity.certificate_sha256,
                "administrator", installation_id, "c" * 64,
                "policy", "capabilities-v2", "b" * 64)
            return V2FencePort(request, {"installed": profile}, grant)

        client_port = fence_port("client", client_peer, "installation")
        admin_port = fence_port("second", admin_peer, "installation-admin")
        policy = replace(
            policy_for(resources[0]), authority_namespace=AUTH_NS,
            expected_authority_id=authority_id, manifest_digest="c" * 64)
        _, d11 = build_runtime_issuers(b"issuer-key-" * 4)

        async def scenario():
            registry = TypeRegistry()
            registry.register(owner_grant_spec())
            worker = await GraphWorker.start(
                lambda: ProductionGraphStore(tmp_path / "business.db", registry),
                lambda store, port: GraphCoordinator(
                    store, bootstrap, holder="administrator",
                    content_fence_v2=port, d11_issuer=d11),
                fence_port_factory=lambda: fence_port(
                    "client", client_peer, "installation"))
            try:
                creation = await worker.call(
                    lambda graph: graph.provision_namespace_v2(
                        bootstrap, policy, operation_id="owner-creation"))
                expected.update(operation_id=creation.operation_id,
                                digest="sha256:" + creation.input_digest)
                ticket, operation, value = _owner_issue(
                    creation, authority_id, principal)
                with pytest.raises(RuntimeError):
                    await asyncio.to_thread(
                        client_port.register_owner_ticket,
                        namespace=ROLE, authority_namespace=AUTH_NS, ticket=ticket)
                with pytest.raises(RuntimeError):
                    await asyncio.to_thread(
                        admin_port.reserve_owner_issue,
                        namespace=ROLE, authority_namespace=AUTH_NS,
                        operation=operation)

                def graph_commit(graph, operation_id, grant_value):
                    return graph.commit_first_owner_grant_v2(
                        bootstrap, namespace=ROLE, operation_id=operation_id,
                        grant_value=grant_value)

                orchestrator = FirstOwnerIssueOrchestrator(
                    namespace=ROLE, graph_worker=worker,
                    graph_commit=graph_commit, registration_port=admin_port,
                    claimant_port=client_port)
                original_finalize = client_port.finalize_owner_issue

                def lost_final_response(**kwargs):
                    original_finalize(**kwargs)
                    raise RuntimeError("simulated lost Authority response")

                monkeypatch.setattr(client_port, "finalize_owner_issue",
                                    lost_final_response)
                with pytest.raises(RuntimeError, match="simulated lost"):
                    await orchestrator.issue(ticket=ticket, operation=operation,
                                             grant_value=value)
                monkeypatch.setattr(client_port, "finalize_owner_issue",
                                    original_finalize)
                committed = await orchestrator.issue(
                    ticket=ticket, operation=operation, grant_value=value)
                assert committed.phase == "committed"
                proof = await worker.call(
                    graph_commit, operation.operation_id, value)
                assert await asyncio.to_thread(
                    client_port.finalize_owner_issue,
                    namespace=ROLE, authority_namespace=AUTH_NS,
                    operation=operation, proof=proof) == committed
                with pytest.raises(RuntimeError):
                    await asyncio.to_thread(
                        client_port.finalize_owner_issue,
                        namespace=ROLE, authority_namespace=AUTH_NS,
                        operation=operation,
                        proof=replace(proof,
                                      graph_receipt_digest="sha256:" + "f" * 64))
            finally:
                await worker.close()

        asyncio.run(scenario())
    finally:
        if admin_port is not None:
            admin_port.close()
        if client_port is not None:
            client_port.close()
        if listener is not None:
            async def shutdown():
                listener.close()
                await listener.wait_closed()
                await server.aclose()

            asyncio.run_coroutine_threadsafe(shutdown(), loop).result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        loop.close()
        for resource in resources:
            resource.close()
