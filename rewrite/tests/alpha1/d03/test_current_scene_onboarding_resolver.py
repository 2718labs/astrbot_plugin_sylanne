"""Owner binding requires a signed session, negative graph proof and current host scene."""

from dataclasses import replace
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import RoleBindingRequest, RoleBindingResolution
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch
from sylanne3.workbench_api.d01_onboarding import CurrentOwnerIdentity
from sylanne3.workbench_api.d03_onboarding import (
    CurrentD03OnboardingResolver, CurrentFirstBindingProof, CurrentGraphGuardMetadata,
)
from sylanne3.workbench_api.service import AuthenticatedSession

NAMESPACE = NamespaceId("bot", "persona")
SCOPE = "bot/persona"
SCENE = "scene:project"
PRINCIPAL = OwnerPrincipalV1("paired-key", "account", "incarnation")
GUARD = OwnerAuthorizationGuardV1("authority", "install", NAMESPACE, 1,
                                  "sha256:" + "a" * 64, 0, 0)
OWNER_REQUEST = OwnerSessionLoginRequestV1(
    "authority", "authority-ns", "install", PRINCIPAL, "credential", 1,
    "owner", "http://localhost:6185")
SESSION = AuthenticatedSession(
    "paired-actor", "dashboard-session",
    {SCOPE: frozenset({"workbench.bind_scene"})},
    {SCOPE: frozenset({"owner"})},
    {SCOPE: frozenset({"workbench_user_action"})},
    owner_session_token="x" * 43, owner_session_request=OWNER_REQUEST,
)
INPUT = {"scene_ref": SCENE, "visibility": "private", "acknowledgement": True}
DIGEST = "sha256:" + "b" * 64
HOST_SCENE = CurrentHostScene(NAMESPACE, "platform-ref", "conversation-ref", "private", SCENE)


class Namespaces:
    def resolve_installed_namespace(self, *, scope):
        return NAMESPACE if scope == SCOPE else None


class Owners:
    def resolve_current_owner_identity(self, *, session, scope, namespace):
        return CurrentOwnerIdentity(session.actor_id, session.session_id,
                                    scope, namespace, PRINCIPAL, GUARD)


def proof():
    plan = PersonaPlan("plan:one", NAMESPACE, 1,
                       (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
                       (), True)
    active = ActiveRoleQualification(NAMESPACE, plan.head_id, plan, (), 0, 1)
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (),
        QueryEpoch(NAMESPACE, "d03.role_binding", 0), None,
        RoleBindingRequest("persona:persona", None, None, SCENE, "bind_scene",
                           "workbench_user_action", 1.0, True),
    )
    return CurrentFirstBindingProof(
        active, prior, GUARD,
        CurrentGraphGuardMetadata(NAMESPACE, 0, 0, 0,
                                  "catalogue", "scheme", "operator", "policy"),
    )


class Scenes:
    def __init__(self, result=HOST_SCENE):
        self.result = result
        self.calls = []

    def verify(self, namespace, scene_ref, visibility):
        self.calls.append((namespace, scene_ref, visibility))
        return self.result


class Graph:
    def __init__(self, current):
        self.current = current
        self.calls = []

    def read_first_scene_binding_proof_v2(self, **kwargs):
        self.calls.append(kwargs)
        return self.current


def resolve(*, scenes=None, graph=None, session=SESSION, input_data=INPUT):
    scenes = scenes or Scenes()
    graph = graph or Graph(proof())
    resolver = CurrentD03OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), scenes=scenes)
    decision = resolver.resolve_bind_scene_decision(
        coordinator=graph, session=session, scope=SCOPE,
        purpose="workbench_user_action", audience="owner",
        operation_id=str(uuid4()), request_digest=DIGEST, input_data=input_data,
    )
    return decision, scenes, graph


def test_current_scene_and_negative_proof_produce_owner_inputs():
    decision, scenes, graph = resolve()
    assert decision.hold_reason is None
    assert decision.trusted.scene is HOST_SCENE
    assert decision.trusted.active_role == graph.current.active_role
    assert decision.trusted.prior == graph.current.prior
    assert decision.trusted.principal == PRINCIPAL
    assert decision.trusted.authorization_head == GUARD.authorization_head
    assert scenes.calls == [(NAMESPACE, SCENE, "private")]
    assert graph.calls[0]["owner_session_token"] == SESSION.owner_session_token


def test_signed_session_and_acknowledgement_precede_host_read():
    for session, input_data in (
        (replace(SESSION, owner_session_token=None), INPUT),
        (SESSION, {**INPUT, "acknowledgement": False}),
    ):
        decision, scenes, _ = resolve(session=session, input_data=input_data)
        assert decision.trusted is None
        assert not scenes.calls


def test_missing_or_mismatched_host_scene_holds():
    for scene in (None, replace(HOST_SCENE, scene_ref="scene:other"),
                  replace(HOST_SCENE, visibility="group")):
        decision, scenes, _ = resolve(scenes=Scenes(scene))
        assert decision.hold_reason == "current_host_scene_unavailable"
        assert scenes.calls == [(NAMESPACE, SCENE, "private")]


def test_stale_or_missing_negative_proof_holds_without_host_read():
    current = proof()
    with pytest.raises(ValueError, match="differs from read epoch"):
        replace(current, prior=replace(current.prior,
                                       query_epoch=QueryEpoch(NAMESPACE, "d03.role_binding", 1)))
    scenes = Scenes()
    decision, _, _ = resolve(scenes=scenes, graph=Graph(replace(
        current, prior=replace(current.prior, status="ready"))))
    assert decision.hold_reason == "current_graph_negative_proof_invalid"
    assert not scenes.calls


def test_committed_replay_uses_current_signed_owner_without_host_lookup():
    class ReplayGraph:
        def __init__(self):
            self.calls = []

        def replay_committed_scene_binding_v2(self, **kwargs):
            self.calls.append(kwargs)
            return "committed-receipt"

    scenes, graph = Scenes(), ReplayGraph()
    resolver = CurrentD03OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), scenes=scenes)
    args = {"coordinator": graph, "scope": SCOPE,
            "purpose": "workbench_user_action", "audience": "owner",
            "operation_id": str(uuid4()), "request_digest": DIGEST}
    assert resolver.replay_committed_bind_scene(
        **args, session=replace(SESSION, owner_session_token=None)) is None
    assert not graph.calls
    assert resolver.replay_committed_bind_scene(
        **args, session=SESSION) == "committed-receipt"
    assert graph.calls == [{
        "namespace": NAMESPACE, "operation_id": args["operation_id"],
        "request_digest": DIGEST, "principal": PRINCIPAL,
        "actor_id": SESSION.actor_id,
        "owner_session_token": SESSION.owner_session_token,
        "owner_session_request": OWNER_REQUEST,
    }]
    assert not scenes.calls
