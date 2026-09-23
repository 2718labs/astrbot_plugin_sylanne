"""An independently checked Owner session reaches the real graph."""

from dataclasses import replace
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from rewrite.tests.alpha1.authority import test_local_owner_round_trip as owner_case
from astrbot.dashboard.api.plugins import _match_registered_web_api
from astrbot.api.web import bind_request_context
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan, ValueRule
from sylanne3.graph_types import TypeRegistry, owner_grant_policy_digest_v1
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import canonical_digest
from sylanne3.workbench_api.http_transport import (
    SYLANNE_OWNER_SESSION_COOKIE, COMMAND_ROUTE, SESSION_ROUTE,
    VerifiedOwnerPairing,
)
from sylanne3.workbench_api.onboarding import TrustedCreateCharacter
from sylanne3.workbench_api.service import AuthenticatedSession


class _Context:
    def __init__(self):
        self.registered_web_apis = []

    def register_web_api(self, *entry):
        self.registered_web_apis.append(entry)


class _Request:
    def __init__(self, body=b"", *, token=None, session=False):
        self.username = "dashboard-admin"
        self.content_type = "application/json"
        self.cookies = {"astrbot_dashboard_jwt": "dashboard-jwt",
                        SYLANNE_OWNER_SESSION_COOKIE: "owner-token"}
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
        ) or original_authorize(credential, action, namespace, holder)
        policy = replace(
            owner_case.policy_for(resources[0]), expected_authority_id=authority_id,
            authority_namespace=owner_case.AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, tickets = compose()
        ticket, operation, value = owner_case._owner_issue(
            creation, authority_id, principal)
        value["capabilities"] = ["workbench.create", "workbench.read"]
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

        port = coordinator._GraphCoordinator__content_fence_v2

        def current_guard(*, namespace, authority_namespace, permit):
            assert namespace == owner_case.ROLE
            assert authority_namespace == owner_case.AUTH_NS
            service.validate_fence(
                credential=owner_case.WORKER, subject=owner_case.SUBJECT,
                permit=permit)
            guard = tickets.get_current_guard(
                credential=owner_case.WORKER,
                authority_namespace=owner_case.AUTH_NS,
                installation_id="installation", subject=owner_case.SUBJECT,
                permit=permit)
            return guard, permit

        port.get_current_owner_guard_for_fence = current_guard
        plan = PersonaPlan(
            "plan:first", owner_case.ROLE, 1,
            (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
            (ValueRule("truth", "truthful", ("reply",), (), ("fabricate",)),), True)
        owner_session = AuthenticatedSession(
            "owner:paired-account", "paired-session",
            {"bot/persona": frozenset({"workbench.read", "workbench.create"})},
            {"bot/persona": frozenset({"owner"})},
            {"bot/persona": frozenset({"workbench_user_action", "workbench_view"})},
            host_username="dashboard-admin")

        class Pairing:
            current = True

            def resolve_current_owner_session(self, *, username, owner_session_token):
                if (not self.current or username != "dashboard-admin"
                        or owner_session_token != "owner-token"):
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

        class Onboarding:
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
                    request_digest, plan, principal)

            def resolve_bind_scene(self, **_):
                return None

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
        mount, context, pairing = WorkbenchHostMount(), _Context(), Pairing()
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
        with bind_request_context(_Request(session=True)):
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
        with bind_request_context(_Request(body, token=token)):
            response = await command()
        assert response.status_code == 200
        receipt = json.loads(response.body)["receipt"]
        assert receipt["operation_id"] == operation_id
        assert receipt["phase"] == "role_initialized"
        assert receipt["owner_grant_revision"] == 1
        assert resources[0]._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (1,)
        pairing.current = False
        with bind_request_context(_Request(body, token=token)):
            denied = await command()
        assert denied.status_code == 401
        mount.close()
    finally:
        if worker is not None:
            await worker.close()
        for resource in resources:
            resource.close()
