from __future__ import annotations

from uuid import uuid4
from threading import get_ident

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution
from sylanne3.graph_coordinator import RoleInitializationReceiptV1, SceneBindingReceiptV1
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.graph_worker import GraphWorker
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest,
)
from sylanne3.workbench_api import (
    AsyncGraphWorkbenchService, AuthenticatedSession, GraphWorkbenchIssuer, RequestContext,
    TrustedBindScene, TrustedCreateCharacter, WorkbenchService,
)


SCOPE = "bot/persona"
SESSION = AuthenticatedSession(
    "creator", "server-session", {SCOPE: frozenset({"workbench.create"})},
    {SCOPE: frozenset({"owner"})},
    {SCOPE: frozenset({"workbench_user_action"})},
)
CONTEXT = RequestContext(True, True, True)
PLAN = PersonaPlan(
    "initial-plan", NamespaceId("bot", "persona"), 1,
    (PersonaBlock("identity", "semantic_identity", "小岚", "read_only"),), (), True,
)
PRINCIPAL = OwnerPrincipalV1("installed-account", "account:creator", "incarnation:1")


def command(operation_id: str | None = None, *, budget_ref: str = "host/budget") -> dict:
    return {
        "schema_version": "d12.contract.v1", "action": "create_character",
        "scope": SCOPE, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": operation_id or str(uuid4()),
        "input": {"display_name": "小岚", "blueprint": "d01.persona.warm-listener.v1",
                  "model_capability_ref": "host/model", "budget_ref": budget_ref},
    }


class Views:
    def view_types(self, authority):
        return {}


class Grants:
    def resolve(self, **kwargs):
        raise AssertionError("create must not resolve a dashboard read grant")


class Policy:
    def __init__(self):
        self.calls = []
        self.tamper = False

    def resolve_create_character(self, **kwargs):
        self.calls.append(kwargs)
        return TrustedCreateCharacter(
            kwargs["session"].actor_id,
            "another-session" if self.tamper else kwargs["session"].session_id,
            kwargs["scope"], kwargs["operation_id"], kwargs["request_digest"],
            PLAN, PRINCIPAL,
        )


class Graph:
    def __init__(self):
        self.calls = []
        self.tamper = False

    def query(self, *_args, **_kwargs):
        raise AssertionError("create must not read via dashboard grant")

    def commit_role_initialization_v2(self, **kwargs):
        self.calls.append(kwargs)
        return RoleInitializationReceiptV1(
            kwargs["namespace"], kwargs["operation_id"],
            "sha256:" + "0" * 64 if self.tamper else kwargs["request_digest"],
            "sha256:" + "1" * 64, PLAN.plan_id, PLAN.head_id,
            "owner-grant", 1, "sha256:" + "2" * 64, "graph-incarnation",
            2, 2, "role-write", "finish-role", "sha256:" + "3" * 64,
        )


class Store:
    def close(self):
        pass


def test_create_uses_server_policy_and_exact_graph_receipt():
    graph, policy = Graph(), Policy()
    service = WorkbenchService(GraphWorkbenchIssuer(graph, Grants(), Views(), policy))
    payload = command()
    answer = service.handle(payload, session=SESSION, context=CONTEXT)
    assert answer.status == "ready"
    assert answer.receipt["operation_id"] == payload["operation_id"]
    assert answer.receipt["phase"] == "role_initialized"
    assert answer.receipt["head_id"] == PLAN.head_id
    assert answer.receipt["owner_grant_revision"] == 1
    assert len(policy.calls) == 1 and len(graph.calls) == 1
    assert graph.calls[0]["plan"] is PLAN
    assert graph.calls[0]["principal"] is PRINCIPAL
    assert graph.calls[0]["request_digest"] == policy.calls[0]["request_digest"]


def test_unknown_well_formed_blueprint_reaches_resolver_and_holds():
    class CatalogueHold:
        def __init__(self):
            self.seen = []

        def resolve_create_character(self, **kwargs):
            self.seen.append(kwargs["input_data"]["blueprint"])
            return None

    resolver = CatalogueHold()
    service = WorkbenchService(GraphWorkbenchIssuer(Graph(), Grants(), Views(), resolver))
    payload = command()
    payload["input"]["blueprint"] = "d01.persona.uninstalled.v1"
    answer = service.handle(payload, session=SESSION, context=CONTEXT)
    assert resolver.seen == ["d01.persona.uninstalled.v1"]
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "role_initialization_policy_unavailable"


def test_create_rejects_wrong_session_resolution_and_wrong_request_receipt():
    graph, policy = Graph(), Policy()
    service = WorkbenchService(GraphWorkbenchIssuer(graph, Grants(), Views(), policy))
    policy.tamper = True
    denied = service.handle(command(), session=SESSION, context=CONTEXT)
    assert denied.status == "unavailable" and denied.receipt is None
    assert not graph.calls

    policy.tamper = False
    graph.tamper = True
    denied = service.handle(command(), session=SESSION, context=CONTEXT)
    assert denied.status == "unavailable" and denied.receipt is None
    assert denied.problem["code"] == "role_initialization_receipt_invalid"


def test_create_without_installed_server_policy_stays_unavailable():
    graph = Graph()
    service = WorkbenchService(GraphWorkbenchIssuer(graph, Grants(), Views()))
    answer = service.handle(command(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "role_initialization_unavailable"
    assert not graph.calls


def scene_command(operation_id: str | None = None) -> dict:
    payload = command(operation_id)
    payload["action"] = "bind_scene"
    payload["input"] = {"scene_ref": "scene:project", "visibility": "private",
                        "acknowledgement": True}
    return payload


class ScenePolicy:
    def resolve_bind_scene(self, **kwargs):
        namespace = PLAN.namespace
        operation_id = kwargs["operation_id"]
        source = "source:scene-authority"
        binding = RoleBinding(
            "binding:project", "persona:persona", "collaborator", None, None,
            "scene:project", "scene", "private", ("norm:project",), 1.0,
            None, 10, (source,), 1, "active",
        )
        role_reads = tuple(GraphVersion(
            AtomKey(Owner("persona", "bot", "persona"), type_name, name), 1,
        ) for type_name, name in (
            ("d01.persona_activation.v1", "current"),
            ("d01.persona_plan.v1", PLAN.plan_id),
            ("d11.owner_grant.v1", "primary"),
        ))
        active = ActiveRoleQualification(namespace, PLAN.head_id, PLAN, role_reads, 0, 1)
        guard = OwnerAuthorizationGuardV1(
            "authority", "installation", namespace, 1, "sha256:" + "a" * 64, 0, 0,
        )
        key = AtomKey(Owner("scene", "bot", "persona", binding.scene_ref),
                      "d03.role_binding", binding.role_binding_id)
        query = QueryEpoch(namespace, "d03.role_binding", 0)
        prior = RoleBindingResolution(
            "no_applicable_binding", (), (), (), (), query, None,
            RoleBindingRequest("persona:persona", None, None, binding.scene_ref,
                               "bind_scene", kwargs["purpose"], 1.0, True),
        )
        envelope = CommandEnvelope(
            "sylanne.runtime.v1",
            OperationIdentity("activity:scene", None, "attempt:scene", "prepare",
                              operation_id, canonical_digest({"input_refs": [source]})),
            AuthorityContext("creator", "d11", "capability:scene", namespace,
                             ("persona", "scene"), kwargs["purpose"],
                             ("owner",), "policy", 1),
            VersionGuard(role_reads + (GraphVersion(key, 0),), (query,), 0, 0,
                         "catalogue", "scheme", "operator", "policy", (), (), ()),
            SourceQualification((source,), "authored", None, 1.0,
                                "authored_content", "qualified", None, "not_applicable"),
            (source,), "budget:scene", 10.0, 10.0, "interval:scene", (),
        )
        d03 = ContextProvider()
        d03.compile_scheme({"schema": "d03.context.scheme.v1",
                            "roles": ("collaborator",), "norms": ("norm:project",)}, None)
        proposal = d03.build_scene_binding_proposal(envelope, binding, active, guard, prior)
        return TrustedBindScene(kwargs["session"].actor_id, kwargs["session"].session_id,
                                kwargs["scope"], operation_id, kwargs["request_digest"],
                                binding, active, proposal, prior, PRINCIPAL)


class SceneGraph(Graph):
    def commit_scene_binding_v2(self, **kwargs):
        self.calls.append(kwargs)
        return SceneBindingReceiptV1(
            kwargs["namespace"], kwargs["operation_id"], kwargs["request_digest"],
            "sha256:" + "1" * 64, "scene:project", "binding:project", PLAN.head_id,
            "owner-grant", "sha256:" + "2" * 64, "graph-incarnation",
            3, 3, "scene-write", "finish-scene", "sha256:" + "3" * 64,
        )


def test_bind_scene_uses_trusted_d03_candidate_and_graph_receipt():
    graph = SceneGraph()
    session = AuthenticatedSession(
        "creator", "server-session", {SCOPE: frozenset({"workbench.bind_scene"})},
        {SCOPE: frozenset({"owner"})},
        {SCOPE: frozenset({"workbench_user_action"})},
    )
    service = WorkbenchService(GraphWorkbenchIssuer(graph, Grants(), Views(), ScenePolicy()))
    payload = scene_command()
    answer = service.handle(payload, session=session, context=CONTEXT)
    assert answer.status == "ready"
    assert answer.receipt["scene_ref"] == "scene:project"
    assert answer.receipt["binding_id"] == "binding:project"
    assert graph.calls[0]["prior"].status == "no_applicable_binding"
    assert graph.calls[0]["proposal"].domain == "d03"


def test_bind_scene_without_graph_commit_is_unavailable():
    graph = Graph()
    session = AuthenticatedSession(
        "creator", "server-session", {SCOPE: frozenset({"workbench.bind_scene"})},
        {SCOPE: frozenset({"owner"})},
        {SCOPE: frozenset({"workbench_user_action"})},
    )
    service = WorkbenchService(GraphWorkbenchIssuer(graph, Grants(), Views(), ScenePolicy()))
    answer = service.handle(scene_command(), session=session, context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "scene_binding_unavailable"


@pytest.mark.asyncio
async def test_async_create_resolves_policy_and_commits_on_graph_worker():
    calls = []

    class WorkerPolicy(Policy):
        def resolve_create_character(self, **kwargs):
            calls.append(("policy", get_ident()))
            return super().resolve_create_character(**kwargs)

    class WorkerGraph(Graph):
        def commit_role_initialization_v2(self, **kwargs):
            calls.append(("commit", get_ident()))
            return super().commit_role_initialization_v2(**kwargs)

    worker = await GraphWorker.start(Store, lambda store: WorkerGraph())
    try:
        service = AsyncGraphWorkbenchService(worker, Grants(), Views(), WorkerPolicy())
        answer = await service.handle(command(), session=SESSION, context=CONTEXT)
        assert answer.status == "ready"
        assert [kind for kind, _ in calls] == ["policy", "commit"]
        assert calls[0][1] == calls[1][1] != get_ident()
    finally:
        await worker.close()
