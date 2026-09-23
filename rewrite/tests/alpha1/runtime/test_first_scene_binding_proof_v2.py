"""A first scene binding needs one current fenced Owner/D01/D03 graph proof."""

from dataclasses import replace

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.workbench_api.d03_onboarding import CurrentFirstBindingProof

from test_scene_binding_v2 import _scene_case


ACTOR = "paired-owner"


def _pair(coordinator, namespace, principal):
    paired = {ACTOR: principal}
    coordinator._GraphCoordinator__owner_principal_resolver = (
        lambda actor, current_namespace:
        paired.get(actor) if current_namespace == namespace else None)
    return paired


def test_current_first_binding_proof_reads_full_query_at_one_epoch(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     _proposal, _prior, _digest, _key) = _scene_case(tmp_path)
    try:
        _pair(coordinator, namespace, principal)
        proof = coordinator.read_first_scene_binding_proof_v2(
            namespace=namespace, scene_ref="scene:private",
            purpose="workbench_user_action", principal=principal, actor_id=ACTOR)
        assert type(proof) is CurrentFirstBindingProof
        assert proof.active_role.namespace == namespace
        assert proof.active_role.graph_epoch == 2
        assert proof.prior.status == "no_applicable_binding"
        assert proof.prior.query_epoch.revision == 2
        assert proof.prior.read_versions == ()
        assert proof.prior.request.scope_complete
        assert proof.prior.request.scene_ref == "scene:private"
        assert proof.owner_guard.authorization_revision == 1
    finally:
        store.close()
        authority_db.close()


def test_existing_scene_binding_denies_negative_proof(tmp_path):
    (store, authority_db, _port, coordinator, namespace, principal,
     proposal, prior, digest, _key) = _scene_case(tmp_path)
    try:
        _pair(coordinator, namespace, principal)
        coordinator.commit_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1", proposal=proposal,
            prior=prior, principal=principal, request_digest=digest)
        with pytest.raises(AuthorityDenied, match="already has"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal, actor_id=ACTOR)
    finally:
        store.close()
        authority_db.close()


def test_changed_principal_and_revoked_owner_head_deny_proof(tmp_path):
    (store, authority_db, port, coordinator, namespace, principal,
     _proposal, _prior, _digest, _key) = _scene_case(tmp_path)
    try:
        paired = _pair(coordinator, namespace, principal)
        with pytest.raises(UnavailableGuard, match="pairing"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal,
                actor_id="unpaired-owner")
        paired[ACTOR] = replace(principal, account_ref="other-account")
        with pytest.raises(AuthorityDenied, match="does not authorize"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action",
                principal=paired[ACTOR], actor_id=ACTOR)
        paired[ACTOR] = principal
        original_guard = port.get_current_owner_guard_for_fence
        port.get_current_owner_guard_for_fence = lambda **kwargs: (
            replace(original_guard(**kwargs)[0],
                    pending_revoke_operation_id="revoke-1"), kwargs["permit"])
        with pytest.raises(UnavailableGuard, match="Owner head changed"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal, actor_id=ACTOR)
    finally:
        store.close()
        authority_db.close()
