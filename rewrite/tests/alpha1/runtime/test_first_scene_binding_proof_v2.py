"""A first scene binding needs one current fenced Owner/D01/D03 graph proof."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.graph_coordinator import AuthorityDenied, StaleRead, UnavailableGuard
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
        assert proof.graph_guard.namespace == namespace
        assert proof.graph_guard.graph_epoch == proof.prior.query_epoch.revision
        assert (proof.graph_guard.access_epoch, proof.graph_guard.delete_epoch) == (1, 0)
        assert proof.graph_guard.catalogue_version == store._registry.catalogue_hash
        versions = dict(store._db.execute(
            "SELECT kind,version FROM graph_guard_versions "
            "WHERE bot=? AND persona=? AND ref='current'", namespace.as_tuple,
        ).fetchall())
        assert (proof.graph_guard.scheme_version,
                proof.graph_guard.operator_version,
                proof.graph_guard.policy_version) == (
                    versions["scheme"], versions["operator"], versions["policy"])
        with pytest.raises(ValueError, match="differs from read epoch"):
            replace(proof, graph_guard=replace(proof.graph_guard, graph_epoch=3))
    finally:
        store.close()
        authority_db.close()


def test_guard_version_change_during_read_rejects_proof(tmp_path, monkeypatch):
    (store, authority_db, port, coordinator, namespace, principal,
     _proposal, _prior, _digest, _key) = _scene_case(tmp_path)
    try:
        _pair(coordinator, namespace, principal)
        original_validate = port.validate_fence
        validation_count = 0

        def change_policy_after_validation(scope):
            nonlocal validation_count
            permit = original_validate(scope)
            validation_count += 1
            if validation_count == 2:
                with store._lock:
                    store._db.execute(
                        "UPDATE graph_guard_versions SET version=? "
                        "WHERE bot=? AND persona=? AND kind='policy' AND ref='current'",
                        ("policy:changed", *namespace.as_tuple),
                    )
            return permit

        monkeypatch.setattr(port, "validate_fence", change_policy_after_validation)
        with pytest.raises(StaleRead, match="graph guard changed after read"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal,
                actor_id=ACTOR)
        assert validation_count == 2
    finally:
        store.close()
        authority_db.close()


def test_signed_owner_session_is_rechecked_at_both_guard_reads(tmp_path, monkeypatch):
    (store, authority_db, port, coordinator, namespace, principal,
     _proposal, _prior, _digest, _key) = _scene_case(tmp_path)
    try:
        _pair(coordinator, namespace, principal)
        anchor = port.anchors[namespace]
        request = OwnerSessionLoginRequestV1(
            anchor.authority_id, anchor.namespace,
            port.installation_grant.installation_id, principal,
            "credential:owner", 1, "owner", "http://localhost",
        )
        original_guard = port.get_current_owner_guard_for_fence
        reads = 0

        def guarded(**kwargs):
            nonlocal reads
            reads += 1
            assert kwargs["owner_actor_id"] == ACTOR
            assert kwargs["owner_session_token"] == "A" * 43
            assert kwargs["owner_session_request"] is request
            if reads == 2:
                raise UnavailableGuard("Owner session revoked")
            return original_guard(**{
                key: kwargs[key] for key in
                ("namespace", "authority_namespace", "permit")
            })

        monkeypatch.setattr(port, "get_current_owner_guard_for_fence", guarded)
        with pytest.raises(UnavailableGuard, match="Owner session revoked"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal,
                actor_id=ACTOR, owner_session_token="A" * 43,
                owner_session_request=request)
        assert reads == 2
        with pytest.raises(UnavailableGuard, match="must be paired"):
            coordinator.read_first_scene_binding_proof_v2(
                namespace=namespace, scene_ref="scene:private",
                purpose="workbench_user_action", principal=principal,
                actor_id=ACTOR, owner_session_token="A" * 43)
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
