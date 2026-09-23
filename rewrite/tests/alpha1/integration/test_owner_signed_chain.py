"""Real Authority and graph Owner chain, including the W11 signed session."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    ADMIN, AUTH_NS, PEER, ROLE, SUBJECT, WORKER, _installed, _owner_issue,
)
from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
    to_wire as session_to_wire,
)
from sylanne3.authority_service.v2_contract import to_wire as fence_to_wire
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import ProductionGraphStore, TypeRegistry
from sylanne3.graph_types import owner_grant_spec
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.workbench_api.owner_session_resolver import BoundOwnerSessions
from sylanne3.workbench_api.async_service import AsyncGraphWorkbenchService
from sylanne3.workbench_api.owner_grant import (
    DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort,
)
from sylanne3.workbench_api.service import RequestContext
from sylanne3.runtime.d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, D11RuntimeProvider,
)


ORIGIN = "https://dashboard.local"


class _AuthoritySessions:
    """In-process test transport to the actual Authority session store."""

    def __init__(self, sessions, credential, installation_id):
        self.sessions = sessions
        self.credential = credential
        self.installation_id = installation_id

    def begin_owner_session(self, *, namespace, authority_namespace, request):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return self.sessions.begin_login(
            transport_credential=self.credential, request=request)

    def accept_owner_session(self, *, namespace, authority_namespace, challenge, signature):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return self.sessions.accept_login(
            transport_credential=self.credential, challenge=challenge,
            signature=signature)

    def describe_owner_session(self, *, namespace, authority_namespace, token):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        return self.sessions.describe_current(
            transport_credential=self.credential, token=token,
            namespace=authority_namespace, installation_id=self.installation_id)

    def logout_owner_session(self, *, namespace, authority_namespace, request, token):
        assert namespace == ROLE and authority_namespace == AUTH_NS
        self.sessions.logout(
            transport_credential=self.credential, request=request, token=token)


class _HostRequest:
    username = "dashboard-owner"
    headers = {"origin": ORIGIN}


@pytest.mark.asyncio
async def test_paired_first_owner_issue_then_signed_w11_reads_real_graph(tmp_path):
    (coordinator, bootstrap, service, _compose, expected, principal,
     authority_id, resources) = _installed(tmp_path)
    graph, core = resources[:2]
    port = coordinator._GraphCoordinator__content_fence_v2
    worker = None
    try:
        original_authorizer = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            namespace == AUTH_NS and (
                credential == ADMIN and action in {"owner_identity_pair", "owner_identity_revoke"}
                or credential == PEER and action in {
                    "owner_pair", "owner_claim", "owner_session",
                    "owner_guard_read", "read"}
                or credential == WORKER and action in {"owner_guard_read", "read"}
            ) or original_authorizer(credential, action, namespace, holder)
        )
        now = lambda: datetime.now(timezone.utc).replace(microsecond=0)
        policy = replace(policy_for(graph), expected_authority_id=authority_id,
                         authority_namespace=AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        ticket, operation, value = _owner_issue(creation, authority_id, principal)
        source = AuthorityOwnerPairingSource(core, utc_clock=now, create=True)
        verifier = OwnerDeploymentVerifier(source, now)
        key = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(
            authority_id, AUTH_NS, "installation", principal, "owner-key", 1,
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw), "enroll",
        )
        source.pair_credential(
            administrator_credential=ADMIN, registration=registration,
            client_certificate_sha256="a" * 64,
            valid_until_utc=now() + timedelta(hours=1))
        actor_binding = OwnerActorBindingV1(
            authority_id, "installation", ROLE, "owner-actor", principal, 1)
        source.pair_actor(
            administrator_credential=ADMIN,
            binding=actor_binding)
        proofs = AuthorityV2OwnerProofStore(
            core, utc_clock=now, pairing_verifier=verifier.pair_credential,
            current_pairing_source=source, create=True)
        # The test transport is the installed peer; the pairing is held by the
        # independent Authority DB, not inferred from graph or browser fields.
        proofs.register_credential(
            transport_credential=PEER, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=now, current_pairing_source=source, create=True)
        issue_request = OwnerSessionLoginRequestV1(
            authority_id, AUTH_NS, "installation", principal, "owner-key", 1,
            "sylanne-owner-console", ORIGIN)
        challenge = sessions.begin_login(
            transport_credential=PEER, request=issue_request)
        issue_token = sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))

        source.pair_creation(
            administrator_credential=ADMIN, authority_namespace=AUTH_NS,
            ticket=ticket, client_certificate_sha256="a" * 64,
            valid_until_utc=now() + timedelta(hours=1))
        server = compose_local_owner_authority(
            core=core, v2_fences={AUTH_NS: service},
            graph_db_path=tmp_path / "business.db", utc_clock=now,
            first_claim_verifier=lambda credential, current, namespace:
                credential == PEER and verifier.first_claim(PEER, current, namespace),
            claimant_verifier=None, owner_proofs=proofs,
            owner_sessions=sessions, creation_pairing_source=source,
            create_owner_schema=True,
            administrator_authorizer=lambda *_: True,
            publisher_manifest_verifier=lambda *_: True,
            installations_v2={
                ("a" * 64, "installed"): AdministratorInstallationV2(
                    "installation", "administrator", "policy", "capabilities-v2", "c" * 64)},
            namespace_bindings_v2={("a" * 64, "installed", ROLE): AUTH_NS})
        tickets = server._v2_owner_tickets
        port.tickets = tickets
        tickets.register_ticket(
            credential=PEER, authority_namespace=AUTH_NS, ticket=ticket)
        pending = tickets.reserve_issue(
            credential=PEER, authority_namespace=AUTH_NS,
            operation=operation, session_token=issue_token,
            session_request=issue_request)
        assert pending.phase == "pending"
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=value)
        committed = tickets.finalize_issue(
            credential=PEER, authority_namespace=AUTH_NS,
            operation=operation, proof=proof, session_token=issue_token,
            session_request=issue_request)
        assert committed.phase == "committed"

        def current_principal(actor, namespace):
            binding = source.current_actor_binding(
                authority_namespace=AUTH_NS, installation_id="installation",
                actor_id=actor)
            return binding.principal if binding is not None and namespace == ROLE else None

        def current_actor(owner, namespace):
            binding = source.current_actor_binding(
                authority_namespace=AUTH_NS, installation_id="installation",
                actor_id="owner-actor")
            return binding.actor_id if binding is not None and (
                binding.principal, namespace) == (owner, ROLE) else None

        def current_guard(*, namespace, authority_namespace, permit,
                          owner_actor_id=None, owner_session_token=None,
                          owner_session_request=None):
            assert namespace == ROLE and authority_namespace == AUTH_NS
            service.validate_fence(
                credential=WORKER, subject=SUBJECT, permit=permit)
            return (tickets.get_current_guard(
                credential=WORKER, authority_namespace=AUTH_NS,
                installation_id="installation", subject=SUBJECT,
                permit=permit, owner_actor_id=owner_actor_id,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request), permit)

        port.get_current_owner_guard_for_fence = current_guard
        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        live = {}

        def make_coordinator(store):
            graph_coordinator = GraphCoordinator(
                store, bootstrap, holder="administrator", content_fence_v2=port,
                owner_principal_resolver=current_principal)
            graph_coordinator.register_provider(
                bootstrap, "d11", D11RuntimeProvider(),
                D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
            live["coordinator"] = graph_coordinator
            return graph_coordinator

        worker = await GraphWorker.start(
            lambda: ProductionGraphStore(tmp_path / "business.db", registry),
            make_coordinator)
        owner = BoundOwnerSessions(
            authority=_AuthoritySessions(sessions, PEER, "installation"),
            worker=worker, bootstrap=bootstrap, owner_actor=current_actor,
            namespace=ROLE, authority_id=authority_id,
            installation_id="installation", origin=ORIGIN)
        login_request = replace(issue_request, audience="owner")
        challenge = await owner.begin_signed_login(
            request=_HostRequest(), login_request=login_request)
        token = await owner.complete_signed_login(
            request=_HostRequest(), challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))
        resolved = await owner.resolve_current_owner_session(
            username=_HostRequest.username, owner_session_token=token)
        assert resolved is not None
        assert resolved.principal == principal
        assert resolved.session.actor_id == "owner-actor"
        assert "workbench.read" in resolved.session.scope_capabilities["bot/persona"]
        grant_port = GraphCurrentOwnerGrantPort(
            live["coordinator"], bootstrap, namespace=ROLE,
            activation_generation=1, domains=("d11",))

        class Views:
            def view_types(self, authority):
                return {"overview": (owner_grant_spec().name,)}

            def view_owner_kind(self, authority, view_type):
                return "persona"

        workbench = AsyncGraphWorkbenchService(
            worker, DurableOwnerGrantResolver(grant_port), Views())
        payload = {
            "schema_version": "d12.contract.v1", "action": "open_workspace",
            "scope": "bot/persona", "purpose": "workbench_view",
            "audience": "owner", "operation_id": str(uuid4()),
            "input": {"client_protocol": "d12.contract.v1"},
        }
        response = await workbench.handle(
            payload, session=resolved.session,
            context=RequestContext(True, True, True))
        assert response.status == "ready"
        assert len(live["coordinator"]._GraphCoordinator__owner_leases) == 0
        assert len(live["coordinator"]._GraphCoordinator__leases) == 0
        anchor = service.current_anchor(credential=WORKER, subject=SUBJECT)
        permit = service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            operation="read", operation_id="signed-owner-guard-read",
            expected_anchor=anchor)
        command = {
            "namespace": AUTH_NS, "permit": fence_to_wire(permit),
            "owner_actor_id": "owner-actor", "owner_session_token": token,
            "owner_session_request": session_to_wire(login_request),
        }
        def guard_rpc(fields):
            return server._v2_command(
                "get_current_owner_guard_for_fence", PEER, "installed",
                "c" * 64, fields)

        assert guard_rpc(command)["guard"] is not None
        for altered in (
                {**command, "owner_actor_id": "wrong-actor"},
                {**command, "owner_session_token": "X" * 43},
                {key: value for key, value in command.items()
                 if key != "owner_session_request"},
        ):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                guard_rpc(altered)
        assert await owner.resolve_current_owner_session(
            username="another-dashboard-user", owner_session_token=token) is None
        service.finish_fence(
            credential=WORKER, subject=SUBJECT, permit=permit,
            request_id="finish:signed-owner-guard-read",
            request_digest="sha256:" + "e" * 64)
        source.revoke_actor(
            administrator_credential=ADMIN, binding=actor_binding)
        anchor = service.current_anchor(credential=WORKER, subject=SUBJECT)
        revoked_permit = service.begin_fence(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            operation="read", operation_id="revoked-owner-guard-read",
            expected_anchor=anchor)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            guard_rpc({**command, "permit": fence_to_wire(revoked_permit)})
        assert await owner.resolve_current_owner_session(
            username=_HostRequest.username, owner_session_token=token) is None
        denied = await workbench.handle(
            payload, session=resolved.session,
            context=RequestContext(True, True, True))
        assert denied.status == "unavailable"
        assert denied.problem["code"] == "authority_unavailable"
        assert len(live["coordinator"]._GraphCoordinator__owner_leases) == 0
        assert len(live["coordinator"]._GraphCoordinator__leases) == 0
        service.finish_fence(
            credential=WORKER, subject=SUBJECT, permit=revoked_permit,
            request_id="finish:revoked-owner-guard-read",
            request_digest="sha256:" + "e" * 64)
    finally:
        if worker is not None:
            await worker.close()
        for resource in resources:
            resource.close()
