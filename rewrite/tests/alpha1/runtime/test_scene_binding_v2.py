"""D03 scene binding consumes one current Owner/D01/negative-query snapshot."""

from dataclasses import replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.domains.d03 import (
    ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution,
)
from sylanne3.graph_coordinator import (
    AuthorityDenied, SceneBindingReceiptV1, UnavailableGuard,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, GraphWrite,
    Owner, NamespaceEpoch,
    owner_grant_key,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest,
)

from test_graph_v2_provisioning import _owner_issue_case


def _scene_case(tmp_path, *, owner_capabilities=None):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
        tmp_path, return_bootstrap=True, role_types=True, scene_types=True,
        owner_capabilities=owner_capabilities)
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=grant_value)
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id,
        policy.namespace, 1, owner_contract_digest(proof), 0, 0)

    def guarded(*, namespace, authority_namespace, permit):
        port.outside_graph_lock()
        assert namespace == policy.namespace
        assert authority_namespace == "opaque:" + namespace.persona_id
        assert permit.operation in {"read", "write"}
        assert port.fences.validate_fence(
            permit, subject="subject", current_anchor=port.anchors[namespace]) == permit
        return guard, permit

    port.get_current_owner_guard_for_fence = guarded
    plan = PersonaPlan(
        "plan:first", policy.namespace, 1,
        (PersonaBlock("identity", "semantic_identity", "reliable companion", "read_only"),),
        (), True,
    )
    role_request_digest = "sha256:" + canonical_digest({"role": "first"})
    role_receipt = coordinator.commit_role_initialization_v2(
        namespace=policy.namespace, operation_id="role-init-1", plan=plan,
        principal=operation.principal, request_digest=role_request_digest)
    d03 = ContextProvider()
    d03.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("companion",), "norms": ("norm:care",),
    }, None)
    coordinator.register_provider(
        bootstrap, "d03", d03, "d03.proposal.v1",
        d03.descriptor.request_schema_hash)
    namespace = policy.namespace
    activation_key = AtomKey(
        Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")
    plan_key = PersonaDomain.plan_write(plan).key
    grant_key = owner_grant_key(*namespace.as_tuple)
    atoms = []
    for key in (activation_key, plan_key, grant_key):
        revision, value, valid = store._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (key.token,),
        ).fetchone()
        import json
        atoms.append(GraphAtom(key, revision, json.loads(value), bool(valid)))
    active_role = PersonaDomain.resolve_active_role(
        GraphSnapshot(tuple(atoms), (NamespaceEpoch(*namespace.as_tuple, 2),)),
        namespace=namespace, current_guard=guard)
    request = RoleBindingRequest(
        f"persona:{namespace.persona_id}", None, None, "scene:private",
        "bind_scene", "respond", 2.0, True)
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (),
        QueryEpoch(namespace, "d03.role_binding", 2), None, request)
    binding = RoleBinding(
        "binding:private", f"persona:{namespace.persona_id}", "companion",
        None, None, "scene:private", "scene", "private", ("norm:care",),
        1.0, None, 10, ("source:role",), 1, "active")
    key = AtomKey(
        Owner("scene", *namespace.as_tuple, "scene:private"),
        "d03.role_binding", binding.role_binding_id)
    version_guard = VersionGuard(
        active_role.read_versions + (GraphVersion(key, 0),),
        (prior.query_epoch,), 1, 0, store._registry.catalogue_hash,
        policy.scheme_version, policy.operator_version, policy.policy_version,
        (), (), (),
    )
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity:scene", None, "attempt:scene", "prepare", "scene-bind-1",
            canonical_digest({"input_refs": ["source:role"]})),
        AuthorityContext(
            "owner:account", "d03", "capability:scene", namespace,
            ("persona", "scene"), "respond", ("owner",), "policy:scene", 1),
        version_guard,
        SourceQualification(
            ("source:role",), "authored", None, 1.0,
            "authored_content", "qualified", 1.0, "not_applicable"),
        ("source:role",), "budget:root", 10.0, 10.0, "interval:scene", (),
    )
    proposal = d03.build_scene_binding_proposal(
        envelope, binding, active_role, guard, prior)
    request_digest = "sha256:" + canonical_digest({
        "scene_ref": binding.scene_ref, "binding_id": binding.role_binding_id,
        "model_ref": "model:one", "budget_ref": "budget:root",
    })
    assert role_receipt.graph_epoch == 2
    return (store, authority_db, port, coordinator, namespace, operation.principal,
            proposal, prior, request_digest, key)


@pytest.mark.parametrize("lose_finish,bad_identity", [(False, False), (True, False),
                                                      (False, True)])
def test_scene_missing_guard_terminates_original_fence_without_graph_commit(
        tmp_path, lose_finish, bad_identity):
    (store, authority_db, port, coordinator, namespace, principal,
     proposal, prior, request_digest, key) = _scene_case(tmp_path)
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
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=prior, principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT status FROM graph_scene_binding_rejections_v1").fetchone() == (
                "rejected_no_commit",)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_scene_binding_intents_v1").fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
        with pytest.raises(UnavailableGuard, match="terminal rejected_no_commit"):
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=prior, principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is None
    finally:
        store.close()
        authority_db.close()


def _seed_nonapplicable_binding(store, coordinator, namespace, proposal, prior,
                                *, scene_ref):
    """Commit a valid graph atom that D03 excludes because it is revoked."""
    provider = coordinator._GraphCoordinator__providers["d03"][0]
    value = dict(proposal.typed_writes[0].value)
    value.update(role_binding_id="binding:prior", scene_ref=scene_ref,
                 status="revoked")
    old = RoleBinding(**{
        **value, "norm_refs": tuple(value["norm_refs"]),
        "source_refs": tuple(value["source_refs"]),
    })
    key = AtomKey(Owner("scene", *namespace.as_tuple, scene_ref),
                  "d03.role_binding", old.role_binding_id)
    with store._lock:
        metadata, epoch = coordinator._v2_graph_stamp(namespace)
        store._db.execute("BEGIN IMMEDIATE")
        try:
            receipt = GraphStore._graph_commit_in_transaction(
                store, GraphCandidate(
                    Event(Scope(*namespace.as_tuple, "seed-d03"),
                          "prior-revoked", 0, "prior_binding", {}),
                    (GraphVersion(key, 0),), (GraphWrite(key, value),),
                    (epoch,)),
                _capability=coordinator._GraphCoordinator__graph_capability)
            store.cas_graph_recovery_metadata(
                metadata, metadata.requirements,
                _capability=coordinator._GraphCoordinator__graph_capability)
            store._db.execute("COMMIT")
        except BaseException:
            store._db.execute("ROLLBACK")
            raise
        proof_row = store._db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
    assert receipt.epoch.revision == prior.query_epoch.revision + 1
    proof = OwnerGraphCommitProofV1(namespace, *proof_row[:5], 1, *proof_row[5:])
    guard = OwnerAuthorizationGuardV1(
        "authority", "installation", namespace, 1,
        owner_contract_digest(proof), 0, 0)
    current_prior = replace(
        prior, read_versions=(GraphVersion(key, 1),),
        query_epoch=QueryEpoch(namespace, "d03.role_binding", receipt.epoch.revision))
    assert provider.resolve_role_binding(prior.request, (old,)).status == (
        "no_applicable_binding")
    with store._lock:
        role, bindings, current_epoch = coordinator._scene_binding_state_locked(
            namespace, guard, current_prior)
    assert bindings == (old,) and current_epoch == receipt.epoch
    original = proposal.envelope
    next_guard = replace(
        original.version_guard,
        read_versions=role.read_versions + current_prior.read_versions
        + (GraphVersion(proposal.typed_writes[0].key, 0),),
        query_epochs=(current_prior.query_epoch,))
    next_envelope = replace(original, version_guard=next_guard)
    new_binding = RoleBinding(**{
        **proposal.typed_writes[0].value,
        "norm_refs": tuple(proposal.typed_writes[0].value["norm_refs"]),
        "source_refs": tuple(proposal.typed_writes[0].value["source_refs"]),
    })
    next_proposal = provider.build_scene_binding_proposal(
        next_envelope, new_binding, role, guard, current_prior)
    return next_proposal, current_prior, key


def test_scene_binding_commits_d03_atom_and_replays_exact_receipt(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, request_digest, key) = _scene_case(tmp_path)
    try:
        receipt = coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
            prior=prior, principal=principal, request_digest=request_digest)
        assert type(receipt) is SceneBindingReceiptV1
        assert (receipt.scene_ref, receipt.binding_id) == (
            "scene:private", "binding:private")
        assert (receipt.graph_revision, receipt.graph_epoch) == (3, 3)
        assert coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
            prior=prior, principal=principal, request_digest=request_digest) == receipt
        assert store._db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (key.token,)).fetchone() == (1, 1)
        active, current_binding = coordinator.read_active_scene_v2(
            namespace=namespace, scene_ref="scene:private")
        assert active.head_id == receipt.role_head_id
        assert current_binding.role_binding_id == receipt.binding_id
    finally:
        store.close()
        authority_db.close()


def test_scene_binding_rejects_changed_full_command_on_replay(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, request_digest, _key) = _scene_case(tmp_path)
    try:
        coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
            prior=prior, principal=principal, request_digest=request_digest)
        changed = "sha256:" + canonical_digest({"budget_ref": "budget:changed"})
        with pytest.raises(AuthorityDenied, match="operation replay differs"):
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=prior, principal=principal, request_digest=changed)
    finally:
        store.close()
        authority_db.close()


def test_scene_binding_replays_committed_write_after_lost_finish(tmp_path):
    (store, authority_db, port, coordinator, namespace, principal,
     proposal, prior, request_digest, key) = _scene_case(tmp_path)
    try:
        port.lose_finish_after_durable = True
        with pytest.raises(RuntimeError, match="finish response lost"):
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=prior, principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1").fetchone() == (1,)
        receipt = coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
            prior=prior, principal=principal, request_digest=request_digest)
        assert receipt.binding_id == "binding:private"
        assert store._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?",
            (key.token,)).fetchone() == (1,)
    finally:
        store.close()
        authority_db.close()


def test_scene_binding_rejects_stale_negative_query_before_graph_commit(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, request_digest, key) = _scene_case(tmp_path)
    try:
        stale = replace(prior, query_epoch=QueryEpoch(namespace, "d03.role_binding", 1))
        with pytest.raises(Exception, match="negative query versions or epoch changed"):
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=stale, principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE token=?",
            (key.token,)).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_scene_binding_requires_bind_scene_capability_in_graph_grant(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, request_digest, key) = _scene_case(
        tmp_path, owner_capabilities=("workbench.create", "workbench.read"))
    try:
        with pytest.raises(AuthorityDenied, match="lacks scene binding permission"):
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
                prior=prior, principal=principal, request_digest=request_digest)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_intents_v1").fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE token=?",
            (key.token,)).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


@pytest.mark.parametrize("existing_scene", ("scene:private", "scene:other"))
def test_first_scene_binding_respects_valid_nonapplicable_atom(
        tmp_path, existing_scene):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, request_digest, new_key) = _scene_case(tmp_path)
    try:
        proposal, prior, old_key = _seed_nonapplicable_binding(
            store, coordinator, namespace, proposal, prior,
            scene_ref=existing_scene)
        assert store._db.execute(
            "SELECT valid FROM graph_atoms WHERE token=?",
            (old_key.token,)).fetchone() == (1,)
        if existing_scene == "scene:private":
            with pytest.raises(AuthorityDenied, match="already has a valid D03 binding"):
                coordinator.commit_scene_binding_v2(
                    namespace=namespace, operation_id="scene-bind-1",
                    proposal=proposal, prior=prior, principal=principal,
                    request_digest=request_digest)
            assert store._db.execute(
                "SELECT COUNT(*) FROM graph_scene_binding_intents_v1 "
                "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone() == (0,)
            assert store._db.execute(
                "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1 "
                "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone() == (0,)
            assert store._db.execute(
                "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
                "AND owner_kind='scene' AND subject=? "
                "AND type_name='d03.role_binding' AND valid=1",
                namespace.as_tuple + (existing_scene,)).fetchone() == (1,)
            assert store._db.execute(
                "SELECT COUNT(*) FROM graph_atoms WHERE token=?",
                (new_key.token,)).fetchone() == (0,)
        else:
            receipt = coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1",
                proposal=proposal, prior=prior, principal=principal,
                request_digest=request_digest)
            assert receipt.binding_id == "binding:private"
            assert store._db.execute(
                "SELECT valid FROM graph_atoms WHERE token=?",
                (new_key.token,)).fetchone() == (1,)
            assert coordinator.read_active_scene_v2(
                namespace=namespace, scene_ref="scene:private")[1].role_binding_id == (
                    "binding:private")
    finally:
        store.close()
        authority_db.close()
