"""An independently checked Owner session reaches the real graph."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.tests.alpha1.authority import test_local_owner_round_trip as owner_case
from astrbot.dashboard.api.plugins import _match_registered_web_api
from astrbot.api.web import bind_request_context
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan, ValueRule
from sylanne3.domains.d03 import ContextProvider
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_types import TypeRegistry, owner_grant_policy_digest_v1
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.role_resources import role_resources_spec
from sylanne3.runtime.d11_types import graph_type_specs
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import canonical_digest
from sylanne3.workbench_api.http_transport import (
    SYLANNE_OWNER_SESSION_COOKIE, COMMAND_ROUTE, SESSION_ROUTE,
    VerifiedOwnerPairing,
)
from sylanne3.workbench_api.onboarding import TrustedCreateCharacter
from sylanne3.workbench_api.d01_onboarding import (
    CurrentOwnerIdentity, VerifiedBudgetLease, VerifiedCreationResources,
    VerifiedModelCapability,
)
from sylanne3.workbench_api.d03_onboarding import CurrentD03OnboardingResolver
from sylanne3.workbench_api.service import AuthenticatedSession


class _Context:
    def __init__(self):
        self.registered_web_apis = []

    def register_web_api(self, *entry):
        self.registered_web_apis.append(entry)


class _Request:
    def __init__(self, body=b"", *, token=None, session=False, owner_token=None):
        self.username = "dashboard-admin"
        self.content_type = "application/json"
        self.cookies = {"astrbot_dashboard_jwt": "dashboard-jwt",
                        SYLANNE_OWNER_SESSION_COOKIE: owner_token}
        self.headers = ({"referer": "https://dashboard.local/workbench"}
                        if session else {"origin": "https://dashboard.local",
                                         "x-csrf-token": token})
        self._body = body

    async def body(self):
        return self._body


@pytest.mark.asyncio
async def test_paired_owner_dashboard_create_character_reaches_dual_db_receipt(
        tmp_path, monkeypatch):
    def role_registry():
        registry = TypeRegistry()
        for spec in PersonaDomain().type_specs():
            registry.register(spec)
        registry.register(role_resources_spec())
        for spec in ContextProvider().type_specs():
            registry.register(spec)
        for spec in D06DomainProvider.type_specs() + graph_type_specs():
            registry.register(spec)
        return registry

    monkeypatch.setattr(owner_case, "TypeRegistry", role_registry)
    (coordinator, bootstrap, service, compose, expected, principal,
     authority_id, resources) = owner_case._installed(tmp_path)
    worker = None
    try:
        original_authorize = resources[1]._authorize_callback
        resources[1]._authorize_callback = lambda credential, action, namespace, holder: (
            credential == owner_case.WORKER and action in {"read", "owner_guard_read"}
            and namespace == owner_case.AUTH_NS and holder == "administrator"
        ) or (
            credential == owner_case.ADMIN and action == "owner_identity_pair"
            and namespace == owner_case.AUTH_NS
        ) or (
            credential == owner_case.PEER and action in {"owner_pair", "owner_session"}
            and namespace == owner_case.AUTH_NS
        ) or original_authorize(credential, action, namespace, holder)
        policy = replace(
            owner_case.policy_for(resources[0]), expected_authority_id=authority_id,
            authority_namespace=owner_case.AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        budget_lease = get_budget_lease(resources[0]._db, creation.root_lease_id)
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, tickets = compose()
        ticket, operation, value = owner_case._owner_issue(
            creation, authority_id, principal)
        value["capabilities"] = [
            "workbench.bind_scene", "workbench.create", "workbench.read",
        ]
        value["purposes"] = ["workbench_user_action", "workbench_view"]
        ticket = replace(ticket, policy_digest=owner_grant_policy_digest_v1(
            value, bot=owner_case.ROLE.bot_id,
            persona=owner_case.ROLE.persona_id))
        operation = replace(
            operation, ticket=ticket, grant_digest="sha256:" + canonical_digest(value),
            request_digest=None)
        tickets.register_ticket(
            credential=owner_case.ADMIN,
            authority_namespace=owner_case.AUTH_NS, ticket=ticket)
        tickets.reserve_issue(
            credential=owner_case.CLAIMANT,
            authority_namespace=owner_case.AUTH_NS, operation=operation)
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=owner_case.ROLE,
            operation_id=operation.operation_id, grant_value=value)
        committed = tickets.finalize_issue(
            credential=owner_case.CLAIMANT,
            authority_namespace=owner_case.AUTH_NS,
            operation=operation, proof=proof)
        assert committed.phase == "committed"

        now = lambda: datetime.now(timezone.utc).replace(microsecond=0)
        source = AuthorityOwnerPairingSource(resources[1], utc_clock=now, create=True)
        key = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(
            authority_id, owner_case.AUTH_NS, "installation", principal,
            "owner-key", 1,
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll")
        source.pair_credential(
            administrator_credential=owner_case.ADMIN,
            registration=registration,
            client_certificate_sha256="a" * 64,
            valid_until_utc=now() + timedelta(hours=1),
        )
        source.pair_actor(
            administrator_credential=owner_case.ADMIN,
            binding=OwnerActorBindingV1(
                authority_id, "installation", owner_case.ROLE,
                "owner:paired-account", principal, 1),
        )
        proofs = AuthorityV2OwnerProofStore(
            resources[1], utc_clock=now,
            pairing_verifier=OwnerDeploymentVerifier(source, now).pair_credential,
            current_pairing_source=source, create=True)
        proofs.register_credential(
            transport_credential=owner_case.PEER, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(
            resources[1], utc_clock=now, current_pairing_source=source, create=True)
        login_request = OwnerSessionLoginRequestV1(
            authority_id, owner_case.AUTH_NS, "installation", principal,
            "owner-key", 1, "owner", "https://dashboard.local")
        challenge = sessions.begin_login(
            transport_credential=owner_case.PEER, request=login_request)
        login_token = sessions.accept_login(
            transport_credential=owner_case.PEER, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))
        tickets._owner_sessions = sessions
        def current_owner_principal(actor, namespace):
            binding = source.current_actor_binding(
                authority_namespace=owner_case.AUTH_NS,
                installation_id="installation", actor_id=actor)
            return binding.principal if binding is not None and namespace == owner_case.ROLE else None

        coordinator._GraphCoordinator__owner_principal_resolver = current_owner_principal

        port = coordinator._GraphCoordinator__content_fence_v2

        def current_guard(*, namespace, authority_namespace, permit,
                          owner_actor_id=None, owner_session_token=None,
                          owner_session_request=None):
            assert namespace == owner_case.ROLE
            assert authority_namespace == owner_case.AUTH_NS
            service.validate_fence(
                credential=owner_case.WORKER, subject=owner_case.SUBJECT,
                permit=permit)
            guard = tickets.get_current_guard(
                credential=owner_case.WORKER,
                authority_namespace=owner_case.AUTH_NS,
                installation_id="installation", subject=owner_case.SUBJECT,
                permit=permit, owner_actor_id=owner_actor_id,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
            return guard, permit

        port.get_current_owner_guard_for_fence = current_guard
        d03 = ContextProvider()
        d03.compile_scheme({
            "schema": "d03.context.scheme.v1",
            "roles": ("scene_participant",), "norms": (),
        }, None)
        coordinator.register_provider(
            bootstrap, "d03", d03, "d03.proposal.v1",
            d03.descriptor.request_schema_hash)
        scene_ref = scene_ref_for_conversation(
            owner_case.ROLE, "platform", "conversation")
        scene = CurrentHostScene(
            owner_case.ROLE, "platform", "conversation", "private", scene_ref)
        scene_port = SimpleNamespace(verify=lambda namespace, ref, visibility: (
            scene if (namespace, ref, visibility) == (
                owner_case.ROLE, scene_ref, "private") else None))
        coordinator._GraphCoordinator__scene_identity_port = scene_port
        coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
            "scene-clock", 1.0, 1.0)
        port.read_ingress_clock = lambda _: SimpleNamespace(
            utc_upper_bound_seconds=datetime.now(timezone.utc).timestamp())
        plan = PersonaPlan(
            "plan:first", owner_case.ROLE, 1,
            (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
            (ValueRule("truth", "truthful", ("reply",), (), ("fabricate",)),), True)
        owner_session = AuthenticatedSession(
            "owner:paired-account", "paired-session",
            {"bot/persona": frozenset({
                "workbench.read", "workbench.create", "workbench.bind_scene",
            })},
            {"bot/persona": frozenset({"owner"})},
            {"bot/persona": frozenset({"workbench_user_action", "workbench_view"})},
            host_username="dashboard-admin", owner_session_token=login_token,
            owner_session_request=login_request)

        class Pairing:
            current = True

            def resolve_current_owner_session(self, *, username, owner_session_token):
                if (not self.current or username != "dashboard-admin"
                        or owner_session_token != login_token):
                    return None
                if sessions.describe_current(
                    transport_credential=owner_case.PEER, token=owner_session_token,
                    namespace=owner_case.AUTH_NS,
                    installation_id="installation") != login_request:
                    return None
                anchor = service.current_anchor(
                    credential=owner_case.WORKER, subject=owner_case.SUBJECT)
                permit = service.begin_fence(
                    credential=owner_case.WORKER, subject=owner_case.SUBJECT,
                    holder="administrator", operation="read",
                    operation_id=f"pair-read-{uuid4()}", expected_anchor=anchor)
                try:
                    guard = tickets.get_current_guard(
                        credential=owner_case.WORKER,
                        authority_namespace=owner_case.AUTH_NS,
                        installation_id="installation", subject=owner_case.SUBJECT,
                        permit=permit)
                    if guard != committed.guard:
                        return None
                    return VerifiedOwnerPairing(owner_session, principal, guard)
                finally:
                    service.finish_fence(
                        credential=owner_case.WORKER, subject=owner_case.SUBJECT,
                        permit=permit, request_id="finish:" + permit.operation_id,
                        request_digest="sha256:" + "d" * 64)

        pairing = Pairing()

        class Installed:
            def resolve_installed_namespace(self, *, scope):
                return owner_case.ROLE if scope == "bot/persona" else None

        class Owners:
            def resolve_current_owner_identity(self, *, session, scope, namespace):
                paired = pairing.resolve_current_owner_session(
                    username=session.host_username,
                    owner_session_token=session.owner_session_token)
                if paired is None or namespace != owner_case.ROLE:
                    return None
                return CurrentOwnerIdentity(
                    session.actor_id, session.session_id, scope, namespace,
                    paired.principal, paired.guard)

        d03_resolver = CurrentD03OnboardingResolver(
            namespaces=Installed(), owners=Owners(), scenes=scene_port)

        class Onboarding:
            def replay_committed_create_character(
                    self, *, coordinator, session, scope, purpose, audience,
                    operation_id, request_digest):
                if (session != owner_session or scope != "bot/persona"
                        or purpose != "workbench_user_action" or audience != "owner"):
                    return None
                return coordinator.replay_committed_role_initialization_v2(
                    namespace=owner_case.ROLE, operation_id=operation_id,
                    request_digest=request_digest, principal=principal,
                    actor_id=session.actor_id,
                    owner_session_token=session.owner_session_token,
                    owner_session_request=session.owner_session_request)

            def resolve_create_character(self, *, session, scope, purpose, audience,
                                         operation_id, request_digest, input_data):
                if (session != owner_session or scope != "bot/persona"
                        or purpose != "workbench_user_action" or audience != "owner"
                        or input_data != {
                            "display_name": "Companion", "blueprint": "blank",
                            "model_capability_ref": "model:one", "budget_ref": "budget:one",
                        }):
                    return None
                return TrustedCreateCharacter(
                    session.actor_id, session.session_id, scope, operation_id,
                    request_digest, plan, principal,
                    VerifiedCreationResources(
                        plan.namespace, "blank", "model:one", "budget:one", 1,
                        "sha256:" + "c" * 64, plan.blocks[1:], plan.values,
                        VerifiedModelCapability(plan.namespace, "model:one", "provider/model", 1,
                                                "sha256:" + "a" * 64),
                        VerifiedBudgetLease(
                            plan.namespace, "budget:one", budget_lease.lease_id,
                            budget_lease.version,
                            "sha256:" + canonical_digest(asdict(budget_lease))),
                    ))

            def replay_committed_bind_scene(self, **kwargs):
                return d03_resolver.replay_committed_bind_scene(**kwargs)

            def resolve_bind_scene(self, **kwargs):
                return d03_resolver.resolve_bind_scene(**kwargs)

        class OwnerGrants:
            def resolve_current_owner(self, **_):
                return None

        class _Store:
            def close(self):
                pass

        worker = await GraphWorker.start(_Store, lambda _: coordinator)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = worker
        runtime._v2_namespace_provisioned = True
        mount, context = WorkbenchHostMount(), _Context()
        mount.register(context)
        command, _ = _match_registered_web_api(
            context.registered_web_apis, COMMAND_ROUTE, "POST")
        with bind_request_context(_Request()):
            before = await command()
        assert before.status_code == 503
        mount.attach_transport(runtime.workbench_transport(
            pairing=pairing, owner_grants=OwnerGrants(),
            onboarding=Onboarding(), origin="https://dashboard.local"))
        session_route, _ = _match_registered_web_api(
            context.registered_web_apis, SESSION_ROUTE, "GET")
        with bind_request_context(_Request(session=True, owner_token=login_token)):
            opened = await session_route()
        token = json.loads(opened.body)["csrf_token"]
        operation_id = str(uuid4())
        body = json.dumps({
            "schema_version": "d12.contract.v1", "action": "create_character",
            "scope": "bot/persona", "purpose": "workbench_user_action",
            "audience": "owner", "operation_id": operation_id,
            "input": {"display_name": "Companion", "blueprint": "blank",
                      "model_capability_ref": "model:one", "budget_ref": "budget:one"},
        }).encode()
        with bind_request_context(_Request(body, token=token, owner_token=login_token)):
            response = await command()
        assert response.status_code == 200, response.body
        receipt = json.loads(response.body)["receipt"]
        assert receipt["operation_id"] == operation_id
        assert receipt["phase"] == "role_initialized"
        assert receipt["owner_grant_revision"] == 1
        assert resources[0]._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (1,)
        resources[0]._db.execute(
            "UPDATE runtime_budget_leases SET version=version+1 WHERE lease_id=?",
            (budget_lease.lease_id,))
        with bind_request_context(_Request(body, token=token, owner_token=login_token)):
            replayed = await command()
        assert replayed.status_code == 200
        assert json.loads(replayed.body)["receipt"] == receipt
        scene_operation_id = str(uuid4())
        scene_body = json.dumps({
            "schema_version": "d12.contract.v1", "action": "bind_scene",
            "scope": "bot/persona", "purpose": "workbench_user_action",
            "audience": "owner", "operation_id": scene_operation_id,
            "input": {"scene_ref": scene_ref, "visibility": "private",
                      "acknowledgement": True},
        }).encode()
        with bind_request_context(_Request(
                scene_body, token=token, owner_token=login_token)):
            bound = await command()
        assert bound.status_code == 200, bound.body
        scene_receipt = json.loads(bound.body)["receipt"]
        assert scene_receipt["phase"] == "scene_bound"
        assert scene_receipt["scene_ref"] == scene_ref
        assert dict(resources[0]._db.execute(
            "SELECT type_name,COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('memory.source','memory.access','d03.role_binding') "
            "GROUP BY type_name", owner_case.ROLE.as_tuple,
        )) == {"memory.source": 2, "memory.access": 2,
              "d03.role_binding": 1}
        assert resources[0]._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1"
        ).fetchone() == (1,)
        coordinator._GraphCoordinator__scene_identity_port = None
        with bind_request_context(_Request(
                scene_body, token=token, owner_token=login_token)):
            scene_replay = await command()
        assert scene_replay.status_code == 200, scene_replay.body
        assert json.loads(scene_replay.body)["receipt"] == scene_receipt
        assert resources[0]._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1"
        ).fetchone() == (1,)
        scene_digest = resources[0]._db.execute(
            "SELECT request_digest FROM graph_scene_binding_request_proofs_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            owner_case.ROLE.as_tuple + (scene_operation_id,),
        ).fetchone()[0]
        pairing.current = False
        with bind_request_context(_Request(
                scene_body, token=token, owner_token=login_token)):
            denied = await command()
        assert denied.status_code == 401
        pairing.current = True
        sessions.logout(
            transport_credential=owner_case.PEER, token=login_token,
            request=login_request)
        with pytest.raises(AuthorityUnavailable, match="Owner session is not current"):
            coordinator.replay_committed_scene_binding_v2(
                namespace=owner_case.ROLE, operation_id=scene_operation_id,
                request_digest=scene_digest, principal=principal,
                actor_id=owner_session.actor_id,
                owner_session_token=login_token,
                owner_session_request=login_request)
        assert resources[0]._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1"
        ).fetchone() == (1,)
        mount.close()
    finally:
        if worker is not None:
            await worker.close()
        for resource in resources:
            resource.close()
