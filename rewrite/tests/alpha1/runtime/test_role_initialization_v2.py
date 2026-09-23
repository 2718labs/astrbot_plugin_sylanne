"""First D01 head follows a finalized Owner issue under a live write fence."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan, ValueRule
from sylanne3.graph_coordinator import (
    AuthorityDenied, GraphCoordinator, RoleInitializationReceiptV1,
    UnavailableGuard,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, owner_grant_spec
from sylanne3.runtime_contracts import canonical_digest

from test_graph_v2_provisioning import AuthorityPort, _owner_issue_case


def _role_case(tmp_path):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
        tmp_path, return_bootstrap=True, role_types=True)
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=grant_value)
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id,
        policy.namespace, 1, owner_contract_digest(proof), 0, 0)

    def current_owner_guard_for_fence(*, namespace, authority_namespace, permit):
        port.outside_graph_lock()
        assert namespace == policy.namespace
        assert authority_namespace == "opaque:" + namespace.persona_id
        assert permit.operation in {"read", "write"}
        assert permit.namespace == authority_namespace
        assert port.fences.validate_fence(
            permit, subject="subject", current_anchor=port.anchors[namespace]) == permit
        return guard, permit

    port.get_current_owner_guard_for_fence = current_owner_guard_for_fence
    plan = PersonaPlan(
        "plan:first", policy.namespace, 1,
        (PersonaBlock("identity", "semantic_identity", "reliable companion", "read_only"),),
        (ValueRule("truth", "be truthful", ("reply",), (), ("fabricate",)),),
        True,
    )
    request_digest = "sha256:" + canonical_digest({
        "schema": "test.full_create_character.v1",
        "plan_id": plan.plan_id,
        "model_capability_ref": "model:one",
        "budget_ref": "budget:one",
    })
    return (store, authority_db, port, coordinator, policy.namespace,
            operation.principal, plan, request_digest)


@pytest.mark.parametrize("lose_finish,bad_identity", [(False, False), (True, False),
                                                      (False, True)])
def test_role_missing_guard_terminates_original_fence_without_graph_commit(
        tmp_path, lose_finish, bad_identity):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        if bad_identity:
            wrong = OwnerAuthorizationGuardV1(
                "authority", "installation", namespace, 1, "sha256:" + "0" * 64,
                0, 0)
            port.get_current_owner_guard_for_fence = lambda **kw: (wrong, kw["permit"])
        else:
            port.get_current_owner_guard_for_fence = lambda **_: None
        port.lose_finish_after_durable = lose_finish
        with pytest.raises((UnavailableGuard, AuthorityDenied, RuntimeError)):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT status FROM graph_role_init_rejections_v1").fetchone() == (
                "rejected_no_commit",)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_role_init_intents_v1").fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
        with pytest.raises(UnavailableGuard, match="terminal rejected_no_commit"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('d01.persona_plan.v1','d01.persona_activation.v1')",
            namespace.as_tuple).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_commits_plan_and_activation_once(tmp_path):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest)
        assert type(receipt) is RoleInitializationReceiptV1
        assert receipt.head_id == plan.head_id
        assert receipt.request_digest == request_digest
        assert receipt.owner_grant_revision == 1
        assert (receipt.graph_revision, receipt.graph_epoch) == (2, 2)
        assert coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest) == receipt
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (1,)
        active = coordinator.read_active_role_v2(namespace=namespace)
        assert active.head_id == plan.head_id
        assert active.authorization_revision == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('d01.persona_plan.v1','d01.persona_activation.v1')",
            namespace.as_tuple).fetchone() == (2,)
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_replay_rejects_changed_full_request(tmp_path):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest)
        changed = "sha256:" + canonical_digest({"budget_ref": "budget:two"})
        with pytest.raises(AuthorityDenied, match="identity differs"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=changed)
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_rejects_wrong_principal_before_write(tmp_path):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        wrong = replace(principal, account_incarnation="other-incarnation")
        with pytest.raises(AuthorityDenied, match="principal or grant"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=wrong, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_intents_v1").fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_requires_create_capability_in_graph_grant(tmp_path):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
        tmp_path, return_bootstrap=True, role_types=True,
        owner_capabilities=("workbench.read",))
    port.pending_owner = pending
    coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=grant_value)
    port.get_current_owner_guard_for_fence = lambda **_: None
    plan = PersonaPlan(
        "plan:first", policy.namespace, 1,
        (PersonaBlock("identity", "semantic_identity", "reliable", "read_only"),),
        (), True)
    try:
        with pytest.raises(AuthorityDenied, match="lacks role creation permission"):
            coordinator.commit_role_initialization_v2(
                namespace=policy.namespace, operation_id="role-init-1", plan=plan,
                principal=operation.principal,
                request_digest="sha256:" + canonical_digest({"full": "create"}))
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_intents_v1").fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_replays_unknown_begin_from_durable_intent(tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest)
        original = store._db.execute(
            "SELECT fence_attempt_id,anchor_json,graph_revision,graph_epoch "
            "FROM graph_role_init_intents_v1").fetchone()
        assert original is not None and original[2:] == (1, 1)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (0,)
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest)
        assert receipt.fence_attempt_id == original[0]
        assert store._db.execute(
            "SELECT fence_attempt_id,anchor_json,graph_revision,graph_epoch "
            "FROM graph_role_init_intents_v1").fetchone() == original
    finally:
        store.close()
        authority_db.close()


def test_role_initialization_recovers_lost_finish_after_cold_restart(tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        port.lose_finish_after_durable = True
        with pytest.raises(RuntimeError, match="finish response lost"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (1,)
        anchors = dict(port.anchors)
        store.close()
        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        for spec in PersonaDomain().type_specs():
            registry.register(spec)
        store = ProductionGraphStore(tmp_path / "owner-business.db", registry)
        port = AuthorityPort(store, authority_db)
        port.anchors = anchors
        port.get_current_owner_guard_for_fence = lambda **_: None
        coordinator = GraphCoordinator(
            store, object(), holder="administrator", content_fence_v2=port)
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest)
        assert receipt.head_id == plan.head_id
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=receipt.fence_attempt_id)[1] == "finished"
    finally:
        store.close()
        authority_db.close()
