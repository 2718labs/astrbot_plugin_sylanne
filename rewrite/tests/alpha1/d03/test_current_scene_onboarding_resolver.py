"""D12 scene selection needs a host policy and a current graph proof."""

from dataclasses import replace
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)
from sylanne3.workbench_api.d01_onboarding import CurrentOwnerIdentity
from sylanne3.workbench_api.d03_onboarding import (
    CurrentD03OnboardingResolver, CurrentFirstBindingProof,
    CurrentGraphGuardMetadata, VerifiedHostScenePolicy,
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


class Namespaces:
    def resolve_installed_namespace(self, *, scope):
        return NAMESPACE if scope == SCOPE else None


class Owners:
    def resolve_current_owner_identity(self, *, session, scope, namespace):
        return CurrentOwnerIdentity(session.actor_id, session.session_id,
                                    scope, namespace, PRINCIPAL, GUARD)


def _qualified(operation_id):
    plan = PersonaPlan("plan:one", NAMESPACE, 1,
                       (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
                       (), True)
    reads = tuple(GraphVersion(
        AtomKey(Owner("persona", "bot", "persona"), type_name, name), 1,
    ) for type_name, name in (
        ("d01.persona_activation.v1", "current"),
        ("d01.persona_plan.v1", plan.plan_id),
        ("d11.owner_grant.v1", "primary"),
    ))
    active = ActiveRoleQualification(NAMESPACE, plan.head_id, plan, reads, 0, 1)
    binding = RoleBinding("binding:project", "persona:persona", "collaborator",
                          None, None, SCENE, "scene", "private", ("norm:project",),
                          1.0, None, 10, ("source:scene",), 1, "active")
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (),
        QueryEpoch(NAMESPACE, "d03.role_binding", 0), None,
        RoleBindingRequest("persona:persona", None, None, SCENE, "bind_scene",
                           "workbench_user_action", 1.0, True),
    )
    key = AtomKey(Owner("scene", "bot", "persona", SCENE),
                  "d03.role_binding", binding.role_binding_id)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity:scene", None, "attempt:scene", "prepare",
                          operation_id, canonical_digest({"input_refs": ["source:scene"]})),
        AuthorityContext(SESSION.actor_id, "d11", "capability:scene", NAMESPACE,
                         ("persona", "scene"), "workbench_user_action",
                         ("owner",), "policy", 1),
        VersionGuard(reads + (GraphVersion(key, 0),), (prior.query_epoch,),
                     1, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification(("source:scene",), "authored", None, 1.0,
                            "authored_content", "qualified", None, "not_applicable"),
        ("source:scene",), "budget:scene", 10.0, 10.0, "interval:scene", (),
    )
    return (VerifiedHostScenePolicy(NAMESPACE, SCENE, "private", binding, envelope),
            CurrentFirstBindingProof(
                active, prior, GUARD,
                CurrentGraphGuardMetadata(
                    NAMESPACE, 0, 1, 0, "catalogue", "scheme", "operator", "policy"),
            ))


class Scenes:
    def __init__(self, policy, events=None, proof=None):
        self.policy = policy
        self.events = events
        self.proof = proof

    def resolve_current_scene(self, **kwargs):
        if self.events is not None:
            self.events.append("policy")
            assert kwargs["proof"] is self.proof
        return self.policy


class Graph:
    def __init__(self, proof, events=None):
        self.proof = proof
        self.calls = 0
        self.events = events

    def read_first_scene_binding_proof_v2(self, **kwargs):
        self.calls += 1
        if self.events is not None:
            self.events.append("graph")
        assert kwargs == {"namespace": NAMESPACE, "scene_ref": SCENE,
                          "purpose": "workbench_user_action", "principal": PRINCIPAL,
                          "actor_id": SESSION.actor_id,
                          "owner_session_token": SESSION.owner_session_token,
                          "owner_session_request": OWNER_REQUEST}
        return self.proof


def _resolver(policy, scenes=None):
    provider = ContextProvider()
    provider.compile_scheme({"schema": "d03.context.scheme.v1",
                             "roles": ("collaborator",), "norms": ("norm:project",)}, None)
    return CurrentD03OnboardingResolver(namespaces=Namespaces(), owners=Owners(),
                                        scenes=scenes or Scenes(policy), provider=provider)


def _resolve(resolver, graph, operation_id, input_data=INPUT, session=SESSION):
    return resolver.resolve_bind_scene_decision(
        coordinator=graph, session=session, scope=SCOPE,
        purpose="workbench_user_action", audience="owner",
        operation_id=operation_id, request_digest=DIGEST, input_data=input_data)


def test_host_scene_and_same_epoch_graph_proof_build_d03_candidate():
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    events = []
    graph = Graph(proof, events)
    result = _resolve(_resolver(policy, Scenes(policy, events, proof)), graph, operation_id)
    assert result.hold_reason is None
    assert result.trusted.binding == policy.binding
    assert result.trusted.active_role == proof.active_role
    assert result.trusted.prior == proof.prior
    assert result.trusted.proposal.domain == "d03"
    assert result.trusted.principal == PRINCIPAL
    assert graph.calls == 1
    assert events == ["graph", "policy"]


def test_signed_owner_session_is_required_before_graph_or_policy_read():
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    graph = Graph(proof)
    resolver = _resolver(policy)
    for session in (replace(SESSION, owner_session_token=None),
                    replace(SESSION, owner_session_request=None)):
        result = _resolve(resolver, graph, operation_id, session=session)
        assert result.trusted is None
        assert result.hold_reason == "signed_owner_session_unavailable"
    assert graph.calls == 0


def test_stock_coordinator_without_negative_proof_stays_on_hold():
    operation_id = str(uuid4())
    policy, _proof = _qualified(operation_id)
    result = _resolve(_resolver(policy), object(), operation_id)
    assert result.trusted is None
    assert result.hold_reason == "current_graph_negative_proof_uninstalled"
    assert _resolve(CurrentD03OnboardingResolver(), object(), operation_id).hold_reason == (
        "trusted_scene_ports_uninstalled")


def test_browser_acknowledgement_and_host_scene_identity_are_not_inferred():
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    graph = Graph(proof)
    resolver = _resolver(policy)
    assert _resolve(resolver, graph, operation_id,
                    {**INPUT, "acknowledgement": False}).hold_reason == (
        "scene_selection_or_acknowledgement_invalid")
    assert _resolve(_resolver(replace(policy, scene_ref="scene:other")),
                    graph, operation_id).hold_reason == (
        "host_scene_policy_unavailable")
    assert graph.calls == 1


def test_stale_graph_proof_is_rejected_and_unqualified_source_holds():
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    with pytest.raises(ValueError, match="differs from read epoch"):
        replace(proof, prior=replace(proof.prior,
                                     query_epoch=QueryEpoch(NAMESPACE, "d03.role_binding", 1)))
    unqualified = replace(policy, envelope=replace(
        policy.envelope, source_qualification=replace(
            policy.envelope.source_qualification, evidence_eligibility="ineligible")))
    assert _resolve(_resolver(unqualified), Graph(proof), operation_id).hold_reason == (
        "scene_command_policy_unavailable")


@pytest.mark.parametrize("field,value", [
    ("access_epoch", 2), ("delete_epoch", 1),
    ("catalogue_version", "old"), ("scheme_version", "old"),
    ("operator_version", "old"), ("policy_version", "old"),
])
def test_host_envelope_must_match_every_current_graph_guard_field(field, value):
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    stale_guard = replace(policy.envelope.version_guard, **{field: value})
    stale_policy = replace(policy, envelope=replace(policy.envelope, version_guard=stale_guard))
    assert _resolve(_resolver(stale_policy), Graph(proof), operation_id).hold_reason == (
        "scene_command_policy_unavailable")


def test_host_envelope_must_match_complete_graph_read_set_and_query_epoch():
    operation_id = str(uuid4())
    policy, proof = _qualified(operation_id)
    guard = policy.envelope.version_guard
    for stale_guard in (
        replace(guard, read_versions=guard.read_versions[:-1]),
        replace(guard, query_epochs=(QueryEpoch(NAMESPACE, "d03.role_binding", 1),)),
    ):
        stale_policy = replace(policy, envelope=replace(policy.envelope,
                                                       version_guard=stale_guard))
        assert _resolve(_resolver(stale_policy), Graph(proof), operation_id).hold_reason == (
            "scene_command_policy_unavailable")
