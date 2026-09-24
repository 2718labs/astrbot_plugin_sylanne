"""First scene binding uses an Owner command, not a runtime envelope."""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.domains.d01 import PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import (
    ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution,
)
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import QueryEpoch, canonical_digest

from test_graph_v2_provisioning import _owner_issue_case
from test_role_initialization_v2 import _resources


def _scene_case(tmp_path, *, owner_capabilities=None,
                enable_ingress=True, owner_command=True, extra_specs=()):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
        tmp_path, first_ingress=enable_ingress, return_bootstrap=True,
        role_types=True, scene_types=True,
        owner_capabilities=owner_capabilities, extra_specs=extra_specs)
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=grant_value)
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id,
        policy.namespace, 1, owner_contract_digest(proof), 0, 0)

    def guarded(*, namespace, authority_namespace, permit, **session_kwargs):
        port.outside_graph_lock()
        assert namespace == policy.namespace
        assert authority_namespace == "opaque:" + namespace.persona_id
        assert port.fences.validate_fence(
            permit, subject="subject", current_anchor=port.anchors[namespace]) == permit
        if session_kwargs:
            assert session_kwargs["owner_actor_id"] == "paired-owner"
            assert session_kwargs["owner_session_token"] == "A" * 43
            assert session_kwargs["owner_session_request"].principal == operation.principal
        return guard, permit

    port.get_current_owner_guard_for_fence = guarded
    coordinator._GraphCoordinator__owner_principal_resolver = (
        lambda actor, current_namespace: operation.principal
        if (actor, current_namespace) == ("paired-owner", policy.namespace) else None)
    plan = PersonaPlan(
        "plan:first", policy.namespace, 1,
        (PersonaBlock("identity", "semantic_identity", "reliable companion", "read_only"),),
        (), True,
    )
    coordinator.commit_role_initialization_v2(
        namespace=policy.namespace, operation_id="role-init-1", plan=plan,
        principal=operation.principal,
        request_digest="sha256:" + canonical_digest({"role": "first"}),
        resources=_resources(store, policy.namespace, plan),
        actor_id="paired-owner", owner_session_token="A" * 43,
        owner_session_request=OwnerSessionLoginRequestV1(
            operation.authority_id, "opaque:" + policy.namespace.persona_id,
            operation.installation_id, operation.principal,
            "credential:owner", 1, "owner", "http://localhost"),
    )
    d03 = ContextProvider()
    d03.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("scene_participant",), "norms": (),
    }, None)
    coordinator.register_provider(
        bootstrap, "d03", d03, "d03.proposal.v1",
        d03.descriptor.request_schema_hash)
    namespace = policy.namespace
    scene_ref = (scene_ref_for_conversation(namespace, "platform", "conversation")
                 if enable_ingress else "scene:private")
    request = RoleBindingRequest(
        f"persona:{namespace.persona_id}", None, None, scene_ref,
        "bind_scene", "workbench_user_action", 2.0, True)
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (),
        QueryEpoch(namespace, "d03.role_binding", 2), None, request)
    return (store, authority_db, port, coordinator, namespace,
            operation.principal, prior, policy, bootstrap)


def _session(case):
    _, _, port, _, namespace, principal, *_ = case
    anchor = port.anchors[namespace]
    return "A" * 43, OwnerSessionLoginRequestV1(
        anchor.authority_id, anchor.namespace,
        port.installation_grant.installation_id, principal,
        "credential:owner", 1, "owner", "http://localhost")


def _bind_scene(case):
    _, _, port, coordinator, namespace, principal, prior, *_ = case
    scene = CurrentHostScene(
        namespace, "platform", "conversation", "private", prior.request.scene_ref)
    coordinator._GraphCoordinator__scene_identity_port = SimpleNamespace(
        verify=lambda current, ref, visibility: scene if (
            current, ref, visibility) == (
                namespace, scene.scene_ref, scene.visibility) else None)
    coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
        "scene-clock", 1.0, 1.0)
    original_clock = port.read_ingress_clock
    port.read_ingress_clock = lambda _: SimpleNamespace(utc_upper_bound_seconds=1000.0)
    token, request = _session(case)
    try:
        return coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", scene=scene,
            prior=prior, principal=principal, actor_id="paired-owner",
            request_digest="sha256:" + "a" * 64,
            owner_session_token=token, owner_session_request=request)
    finally:
        port.read_ingress_clock = original_clock


def test_missing_current_owner_guard_rejects_without_scene_atoms(tmp_path):
    from test_scene_owner_transaction_v2 import _case, _commit

    case = _case(tmp_path)
    store, authority_db, port, *_ = case
    try:
        port.get_current_owner_guard_for_fence = lambda **_: None
        with pytest.raises(UnavailableGuard, match="current scene Owner guard"):
            _commit(case)
        assert store._db.execute(
            "SELECT status FROM graph_scene_binding_rejections_v1"
        ).fetchone() == ("rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_lost_finish_response_replays_original_five_atoms(tmp_path):
    from test_scene_owner_transaction_v2 import _case, _commit

    case = _case(tmp_path)
    store, authority_db, port, coordinator, namespace, principal, *_ = case
    try:
        port.lose_finish_after_durable = True
        with pytest.raises(RuntimeError, match="finish response lost"):
            _commit(case)
        receipt = coordinator.replay_committed_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1",
            request_digest=case[8], principal=principal,
            actor_id="paired-owner", owner_session_token=_session(case)[0],
            owner_session_request=_session(case)[1],
        )
        assert receipt is not None
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (5,)
    finally:
        store.close()
        authority_db.close()


def test_stale_negative_query_rejected_before_intent(tmp_path):
    from test_scene_owner_transaction_v2 import _case, _commit

    case = _case(tmp_path)
    store, authority_db, *_ = case
    try:
        prior = replace(case[7], query_epoch=replace(case[7].query_epoch, revision=1))
        with pytest.raises(Exception, match="negative query|scene graph stamp"):
            _commit(case, prior=prior)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_intents_v1"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_scene_owner_grant_requires_bind_scene_capability(tmp_path):
    from test_scene_owner_transaction_v2 import _commit, ScenePort
    from sylanne3.host.authority_profile import AdminIngressClockPolicy
    from sylanne3.host.current_scene import CurrentHostScene

    (store, authority_db, port, coordinator, namespace, principal,
     prior, _policy, _bootstrap) = _scene_case(
         tmp_path, owner_capabilities=("workbench.create", "workbench.read"))
    scene = CurrentHostScene(namespace, "platform", "conversation", "private",
                             prior.request.scene_ref)
    coordinator._GraphCoordinator__scene_identity_port = ScenePort(scene)
    coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
        "scene-clock", 1.0, 1.0)
    try:
        with pytest.raises(AuthorityDenied, match="lacks scene binding permission"):
            _commit((store, authority_db, port, coordinator, namespace, principal,
                     scene, prior, "sha256:" + "a" * 64))
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_intents_v1"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_existing_valid_scene_binding_prevents_second_first_binding(tmp_path):
    from test_scene_owner_transaction_v2 import _case, _commit

    case = _case(tmp_path)
    store, authority_db, _, _, namespace, _, scene, *_ = case
    try:
        existing = RoleBinding(
            "binding:prior", f"persona:{namespace.persona_id}",
            "scene_participant", None, None, scene.scene_ref, "scene", "private",
            (), 1.0, None, 0, ("source:prior",), 1, "active")
        key = AtomKey(Owner("scene", *namespace.as_tuple, scene.scene_ref),
                      "d03.role_binding", existing.role_binding_id)
        store._db.execute(
            "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
            "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (key.token, *namespace.as_tuple, "scene", scene.scene_ref,
             "d03.role_binding", existing.role_binding_id, 1,
             json.dumps(existing.__dict__), 1),
        )
        with pytest.raises(AuthorityDenied, match="already has a valid D03 binding"):
            _commit(case)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_intents_v1"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()
