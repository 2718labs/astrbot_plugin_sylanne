"""The Owner scene command commits D06 provenance and D03 binding together."""

from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.current_scene import CurrentHostScene

from test_scene_binding_v2 import _scene_case, _session


class ScenePort:
    def __init__(self, scene):
        self.scene = scene

    def verify(self, namespace, scene_ref, visibility):
        if self.scene is None:
            return None
        if (namespace, scene_ref, visibility) == (
                self.scene.namespace, self.scene.scene_ref, self.scene.visibility):
            return self.scene
        return None


def _case(tmp_path):
    (store, authority_db, port, coordinator, namespace, principal,
     prior, _policy, _bootstrap) = _scene_case(
         tmp_path, enable_ingress=True, owner_command=True)
    request_digest = "sha256:" + "a" * 64
    scene = CurrentHostScene(namespace, "platform", "conversation", "private",
                             prior.request.scene_ref)
    prior = replace(prior, request=replace(
        prior.request, purpose="workbench_user_action"))
    coordinator._GraphCoordinator__scene_identity_port = ScenePort(scene)
    coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
        "scene-clock", 1.0, 1.0)
    port.read_ingress_clock = lambda _: SimpleNamespace(utc_upper_bound_seconds=1000.0)
    provider = coordinator._GraphCoordinator__providers["d03"][0]
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1", "roles": ("scene_participant",),
        "norms": (),
    }, None)
    return store, authority_db, port, coordinator, namespace, principal, scene, prior, request_digest


def _commit(case, **changes):
    _, _, _, coordinator, namespace, principal, scene, prior, request_digest = case
    token, request = _session(case)
    arguments = dict(namespace=namespace, operation_id="scene-bind-1",
                     scene=scene, prior=prior, principal=principal,
                     actor_id="paired-owner", request_digest=request_digest,
                     owner_session_token=token, owner_session_request=request)
    arguments.update(changes)
    return coordinator.commit_scene_binding_v2(**arguments)


def test_scene_owner_command_commits_five_atoms_and_replays_without_clock(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, coordinator, namespace, _, scene, _, _ = case
    try:
        receipt = _commit(case)
        assert receipt.scene_ref == scene.scene_ref
        rows = store._db.execute(
            "SELECT type_name,COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('memory.source','memory.access','d03.role_binding') "
            "GROUP BY type_name", namespace.as_tuple,
        ).fetchall()
        assert dict(rows) == {"memory.source": 2, "memory.access": 2,
                              "d03.role_binding": 1}
        source_rows = [json.loads(row[0]) for row in store._db.execute(
            "SELECT value FROM graph_atoms WHERE type_name='memory.source'"
        )]
        assert {(row["source_kind"], row["assertion_status"])
                for row in source_rows} == {
                    ("authored", "unknown"), ("observed", "confirmed")}
        port.read_ingress_clock = lambda _: (_ for _ in ()).throw(RuntimeError("clock gone"))
        coordinator._GraphCoordinator__scene_identity_port = None
        assert _commit(case) == receipt
        assert coordinator.replay_committed_scene_binding_v2(
            namespace=namespace, operation_id="scene-bind-1",
            request_digest=case[8], principal=case[5],
            actor_id="paired-owner", owner_session_token="A" * 43,
            owner_session_request=_session(case)[1],
        ) == receipt
        with pytest.raises(AuthorityDenied, match="request or principal differs"):
            _commit(case, request_digest="sha256:" + "b" * 64)
    finally:
        store.close()
        authority_db.close()


def test_scene_owner_command_rejects_wrong_principal_before_new_intent(tmp_path):
    case = _case(tmp_path)
    store, authority_db, *_ = case
    try:
        with pytest.raises((AuthorityDenied, UnavailableGuard, TypeError)):
            _commit(case, principal=replace(case[5], account_ref="other"))
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_scene_owner_command_rolls_back_all_five_writes_on_stamp_failure(tmp_path):
    case = _case(tmp_path)
    store, authority_db, *_ = case
    try:
        with patch.object(store, "cas_graph_recovery_metadata",
                          side_effect=RuntimeError("stamp failed")):
            with pytest.raises(RuntimeError, match="stamp failed"):
                _commit(case)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_scene_binding_receipts_v1"
        ).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_pending_scene_with_changed_host_finishes_no_commit(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, coordinator, namespace, *_ = case
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            _commit(case)
        coordinator._GraphCoordinator__scene_identity_port = ScenePort(None)
        with pytest.raises(UnavailableGuard, match="current scene identity changed"):
            _commit(case)
        assert store._db.execute(
            "SELECT status FROM graph_scene_binding_rejections_v1"
        ).fetchone() == ("rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (0,)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_scene_binding_intents_v1"
        ).fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
    finally:
        store.close()
        authority_db.close()


def test_pending_scene_with_new_query_time_finishes_original_no_commit(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, _, namespace, _, _, prior, _ = case
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            _commit(case)
        refreshed = replace(prior, request=replace(
            prior.request, at_time=prior.request.at_time + 1))
        with pytest.raises(UnavailableGuard, match="pending scene proof differs"):
            _commit(case, prior=refreshed)
        assert store._db.execute(
            "SELECT status FROM graph_scene_binding_rejections_v1"
        ).fetchone() == ("rejected_no_commit",)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (0,)
        attempt = store._db.execute(
            "SELECT fence_attempt_id FROM graph_scene_binding_intents_v1"
        ).fetchone()[0]
        assert port.get_fence_operation(
            namespace=namespace, authority_namespace="opaque:" + namespace.persona_id,
            operation_id=attempt)[1] == "finished"
    finally:
        store.close()
        authority_db.close()


def test_pending_scene_same_frozen_prior_resumes_original_intent(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, *_ = case
    try:
        port.lose_begin_after_durable = True
        with pytest.raises(RuntimeError, match="begin response lost"):
            _commit(case)
        proof = store._db.execute(
            "SELECT input_digest,frozen_json FROM graph_scene_binding_request_proofs_v1"
        ).fetchone()
        receipt = _commit(case)
        assert receipt.input_digest == proof[0]
        assert store._db.execute(
            "SELECT input_digest,frozen_json FROM graph_scene_binding_request_proofs_v1"
        ).fetchone() == proof
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (5,)
    finally:
        store.close()
        authority_db.close()


def test_signed_owner_session_revoked_after_negative_proof_blocks_final_write(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, *_ = case
    original = port.get_current_owner_guard_for_fence

    def revoked_at_final(**kwargs):
        if kwargs.get("owner_session_token"):
            raise UnavailableGuard("signed Owner session revoked")
        return original(**kwargs)

    port.get_current_owner_guard_for_fence = revoked_at_final
    try:
        with pytest.raises(UnavailableGuard, match="session revoked"):
            _commit(case)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('memory.source','memory.access','d03.role_binding')"
        ).fetchone() == (0,)
        assert store._db.execute(
            "SELECT status FROM graph_scene_binding_rejections_v1"
        ).fetchone() == ("rejected_no_commit",)
    finally:
        store.close()
        authority_db.close()
