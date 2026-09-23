"""First D01 head follows a finalized Owner issue under a live write fence."""

from dataclasses import asdict, replace
import json

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
from sylanne3.graph_types import GraphAtom, TypeRegistry, owner_grant_spec
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.role_resources import (
    role_resources_key, role_resources_spec, read_role_resources,
)
from sylanne3.runtime_contracts import canonical_digest
from sylanne3.workbench_api.d01_onboarding import (
    VerifiedBudgetLease, VerifiedCreationResources, VerifiedModelCapability,
)

from test_graph_v2_provisioning import AuthorityPort, _owner_issue_case


def _resources(store, namespace, plan):
    lease = get_budget_lease(store._db, "lease-" + namespace.persona_id)
    return VerifiedCreationResources(
        namespace, "blueprint:one", "model:one", "budget:one", plan.version,
        "sha256:" + "a" * 64, plan.blocks[1:], plan.values,
        VerifiedModelCapability(namespace, "model:one", "provider/model", 1,
                                "sha256:" + "b" * 64),
        VerifiedBudgetLease(namespace, "budget:one", lease.lease_id, lease.version,
                            "sha256:" + canonical_digest(asdict(lease))),
    )


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
                principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
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
                principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
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
            principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
        assert type(receipt) is RoleInitializationReceiptV1
        assert receipt.head_id == plan.head_id
        assert receipt.request_digest == request_digest
        assert receipt.owner_grant_revision == 1
        assert (receipt.graph_revision, receipt.graph_epoch) == (2, 2)
        assert coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan)) == receipt
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
            principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
        changed = "sha256:" + canonical_digest({"budget_ref": "budget:two"})
        with pytest.raises(AuthorityDenied, match="identity differs"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=changed, resources=_resources(store, namespace, plan))
    finally:
        store.close()
        authority_db.close()


@pytest.mark.parametrize("resource_change", ["model", "budget"])
def test_role_initialization_replay_rejects_changed_verified_resources(
        tmp_path, resource_change):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        resources = _resources(store, namespace, plan)
        coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest, resources=resources)
        changed = (replace(resources, model=replace(resources.model, revision=2))
                   if resource_change == "model" else
                   replace(resources, budget=replace(
                       resources.budget, version=resources.budget.version + 1)))
        with pytest.raises(AuthorityDenied, match="identity differs"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest, resources=changed)
    finally:
        store.close()
        authority_db.close()


@pytest.mark.parametrize("lease_change", [
    "missing", "closed", "other_namespace", "version",
])
def test_role_creation_budget_must_be_current_and_same_namespace(tmp_path, lease_change):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        resources = _resources(store, namespace, plan)
        if lease_change == "missing":
            resources = replace(resources, budget=replace(
                resources.budget, lease_ref="lease:missing"))
        elif lease_change == "closed":
            store._db.execute(
                "UPDATE runtime_budget_leases SET state='closed' WHERE lease_id=?",
                (resources.budget.lease_ref,))
        elif lease_change == "version":
            store._db.execute(
                "UPDATE runtime_budget_leases SET version=version+1 WHERE lease_id=?",
                (resources.budget.lease_ref,))
        else:
            store._db.execute(
                "UPDATE runtime_budget_leases SET persona_id='other' WHERE lease_id=?",
                (resources.budget.lease_ref,))
        with pytest.raises(AuthorityDenied, match="budget lease"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest, resources=resources)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_intents_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('d01.persona_plan.v1','d01.persona_activation.v1','runtime.role_resources.v1')"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_budget_change_after_fence_rejects_no_commit_and_finishes_original_fence(
        tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        resources = _resources(store, namespace, plan)
        original_validate = port.validate_fence
        changed = False

        def change_after_budget_precheck(scope):
            nonlocal changed
            result = original_validate(scope)
            if not changed and scope.operation == "write":
                changed = True
                store._db.execute(
                    "UPDATE runtime_budget_leases SET version=version+1 "
                    "WHERE lease_id=?", (resources.budget.lease_ref,))
            return result

        port.validate_fence = change_after_budget_precheck
        with pytest.raises(AuthorityDenied, match="budget lease changed"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=resources)
        assert changed
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT status FROM graph_role_init_rejections_v1").fetchone() == (
                "rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('d01.persona_plan.v1','d01.persona_activation.v1','runtime.role_resources.v1')"
        ).fetchone() == (0,)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_role_init_intents_v1").fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
        with pytest.raises(UnavailableGuard, match="terminal rejected_no_commit"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=resources)
    finally:
        store.close()
        authority_db.close()


def test_committed_role_replay_survives_later_budget_change(tmp_path):
    (store, authority_db, _port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    try:
        resources = _resources(store, namespace, plan)
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest,
            resources=resources)
        store._db.execute(
            "UPDATE runtime_budget_leases SET version=version+1 WHERE lease_id=?",
            (resources.budget.lease_ref,))
        assert coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest,
            resources=resources) == receipt
        assert coordinator.replay_committed_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1",
            request_digest=request_digest, principal=principal) == receipt
        with pytest.raises(AuthorityDenied, match="request identity differs"):
            coordinator.replay_committed_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1",
                request_digest="sha256:" + "f" * 64,
                principal=principal)
        with pytest.raises(AuthorityDenied, match="principal or grant"):
            coordinator.replay_committed_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1",
                request_digest=request_digest,
                principal=replace(principal, account_incarnation="other"))
    finally:
        store.close()
        authority_db.close()


def test_restart_with_pending_fence_and_changed_budget_records_terminal_rejection(
        tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    resources = _resources(store, namespace, plan)
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=resources)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_role_init_intents_v1").fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "active"
        store._db.execute(
            "UPDATE runtime_budget_leases SET version=version+1 WHERE lease_id=?",
            (resources.budget.lease_ref,))
        anchors = dict(port.anchors)
        store.close()
        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        for spec in PersonaDomain().type_specs():
            registry.register(spec)
        registry.register(role_resources_spec())
        store = ProductionGraphStore(tmp_path / "owner-business.db", registry)
        port = AuthorityPort(store, authority_db)
        port.anchors = anchors
        port.get_current_owner_guard_for_fence = lambda **_: None
        coordinator = GraphCoordinator(
            store, object(), holder="administrator", content_fence_v2=port)
        with pytest.raises(AuthorityDenied, match="budget lease changed"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=resources)
        assert store._db.execute(
            "SELECT status FROM graph_role_init_rejections_v1").fetchone() == (
                "rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('d01.persona_plan.v1','d01.persona_activation.v1','runtime.role_resources.v1')"
        ).fetchone() == (0,)
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
    finally:
        store.close()
        authority_db.close()


def test_restart_pending_intent_with_changed_model_receipt_finishes_original_fence(
        tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    original = _resources(store, namespace, plan)
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=original)
        intent = store._db.execute(
            "SELECT operation_id,input_digest,fence_attempt_id "
            "FROM graph_role_init_intents_v1").fetchone()
        assert store._db.execute(
            "SELECT operation_id,request_digest,input_digest "
            "FROM graph_role_init_request_proofs_v1").fetchone() == (
                intent[0], request_digest, intent[1])
        anchors = dict(port.anchors)
        store.close()
        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        for spec in PersonaDomain().type_specs():
            registry.register(spec)
        registry.register(role_resources_spec())
        store = ProductionGraphStore(tmp_path / "owner-business.db", registry)
        port = AuthorityPort(store, authority_db)
        port.anchors = anchors
        port.get_current_owner_guard_for_fence = lambda **_: None
        coordinator = GraphCoordinator(
            store, object(), holder="administrator", content_fence_v2=port)
        changed = replace(original, model=replace(
            original.model, revision=original.model.revision + 1,
            digest="sha256:" + "d" * 64))
        with pytest.raises(AuthorityDenied, match="request identity differs"):
            coordinator.reject_unresolvable_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1",
                request_digest="sha256:" + "f" * 64,
                principal=principal)
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=intent[2])[1] == "active"
        with pytest.raises(AuthorityDenied, match="identity differs"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=changed)
        assert store._db.execute(
            "SELECT status FROM graph_role_init_rejections_v1").fetchone() == (
                "rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('d01.persona_plan.v1','d01.persona_activation.v1','runtime.role_resources.v1')"
        ).fetchone() == (0,)
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=intent[2])[1] == "finished"
    finally:
        store.close()
        authority_db.close()


def test_pending_intent_without_original_request_proof_holds_fence(tmp_path):
    (store, authority_db, port, coordinator, namespace,
     principal, plan, request_digest) = _role_case(tmp_path)
    resources = _resources(store, namespace, plan)
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            coordinator.commit_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1", plan=plan,
                principal=principal, request_digest=request_digest,
                resources=resources)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_role_init_intents_v1").fetchone()[0]
        # Simulate a pre-migration pending intent whose request proof never existed.
        store._db.execute("DROP TRIGGER graph_role_init_request_proof_no_delete_v1")
        store._db.execute("DELETE FROM graph_role_init_request_proofs_v1")
        with pytest.raises(UnavailableGuard, match="no original request proof"):
            coordinator.reject_unresolvable_role_initialization_v2(
                namespace=namespace, operation_id="role-init-1",
                request_digest=request_digest, principal=principal)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_rejections_v1").fetchone() == (0,)
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "active"
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
                principal=wrong, request_digest=request_digest, resources=_resources(store, namespace, plan))
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
                request_digest="sha256:" + canonical_digest({"full": "create"}),
                resources=_resources(store, policy.namespace, plan))
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
                principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
        original = store._db.execute(
            "SELECT fence_attempt_id,anchor_json,graph_revision,graph_epoch "
            "FROM graph_role_init_intents_v1").fetchone()
        assert original is not None and original[2:] == (1, 1)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (0,)
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
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
                principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_role_init_receipts_v1").fetchone() == (1,)
        anchors = dict(port.anchors)
        store.close()
        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        for spec in PersonaDomain().type_specs():
            registry.register(spec)
        registry.register(role_resources_spec())
        store = ProductionGraphStore(tmp_path / "owner-business.db", registry)
        port = AuthorityPort(store, authority_db)
        port.anchors = anchors
        port.get_current_owner_guard_for_fence = lambda **_: None
        coordinator = GraphCoordinator(
            store, object(), holder="administrator", content_fence_v2=port)
        receipt = coordinator.commit_role_initialization_v2(
            namespace=namespace, operation_id="role-init-1", plan=plan,
            principal=principal, request_digest=request_digest, resources=_resources(store, namespace, plan))
        assert receipt.head_id == plan.head_id
        key = role_resources_key(namespace, plan.plan_id)
        row = store._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)
        ).fetchone()
        selected = read_role_resources(
            GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])),
            namespace=namespace, plan_id=plan.plan_id, head_id=plan.head_id)
        assert selected.budget_lease_ref == "lease-persona"
        assert selected.state == "selected_only"
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=receipt.fence_attempt_id)[1] == "finished"
    finally:
        store.close()
        authority_db.close()
