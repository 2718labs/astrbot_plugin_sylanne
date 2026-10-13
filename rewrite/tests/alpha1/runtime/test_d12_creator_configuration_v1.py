"""W01 draft CAS against the permanent controlled Owner-fence fixture.

This is transaction/authorization regression coverage, not installed acceptance.
"""
from copy import deepcopy
from uuid import uuid4

import pytest

from sylanne3.domains.d12.scheme_command import D12SchemeHold
from sylanne3.domains.d12.types import active_scheme_head_key, character_draft_key
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.contracts import EventConflict, StaleRead
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case
from tests.alpha1.runtime.test_d12_current_compile_v1 import _setup


POLICY = {"policy_ref": "creator-visible", "policy_version": "v1",
          "max_visible_chars": 48, "schema": "d09.expression_policy.v1"}


def _read(coordinator, authority, lease):
    return coordinator.read_current_configuration_draft_v1(authority, lease)


def _arguments(current, fields, operation=None):
    return dict(operation_id=operation or str(uuid4()), draft_ref=current["draft_ref"],
        expected_draft_revision=current["draft_revision"],
        expected_draft_digest=current["draft_digest"],
        expected_graph_revision=current["graph_revision"],
        expected_access_epoch=current["access_epoch"],
        expected_delete_epoch=current["delete_epoch"], fields=deepcopy(fields))


def _atoms(graph):
    return graph._db.execute("SELECT token,revision,value,valid FROM graph_atoms ORDER BY token").fetchall()


def test_discover_and_first_save_create_only_real_draft(owner_graph):
    graph, coordinator, authority, lease = _setup(owner_graph, {"d09.expression_policy": POLICY})
    # Remove only the donor's synthetic draft/head seeds before exercising the
    # product. No existing installation or operation journal is modified.
    with graph._lock:
        graph._db.executemany("DELETE FROM graph_atoms WHERE token=?", (
            (character_draft_key(NAMESPACE).token,), (active_scheme_head_key(NAMESPACE).token,)))
    current = _read(coordinator, authority, lease)
    assert current["exists"] is False and current["draft_revision"] == 0
    assert current["draft_digest"] is None and current["fields"] == {}
    assert current["active_head_ref"] is None and current["active_head_revision"] == 0
    assert len(current["supported_fields"]) == 11
    assert [row["path"] for row in current["supported_fields"] if not row["editable"]] == ["d04.authored_root"]
    with pytest.raises(UnavailableGuard):
        coordinator.with_current_creator_draft_v1(authority, lease,
            draft_ref=current["draft_ref"], required_capability="workbench.create", project=lambda frame: frame)
    saved = coordinator.save_current_creator_draft_for_operation_v1(authority, lease,
        **_arguments(current, {"d09.expression_policy": POLICY}))
    observed = _read(coordinator, authority, lease)
    assert saved["status"] == "draft_saved_not_adopted" and saved["draft_revision"] == 1
    assert observed["draft_digest"] == saved["draft_digest"]
    assert observed["graph_revision"] == saved["graph_revision"]
    assert observed["active_head_revision"] == 0 and observed["active_head_ref"] is None
    assert observed["field_sources"] == {"d09.expression_policy": "owner"}
    assert graph._db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                            (active_scheme_head_key(NAMESPACE).token,)).fetchone() is None
    compiled = coordinator.compile_current_scheme_for_operation_v1(authority, lease,
        operation_id=str(uuid4()), draft_ref=current["draft_ref"], budget_ref="d12-budget")
    assert compiled.compiled.active_head_revision == 0


def test_save_is_durable_idempotent_and_does_not_adopt(owner_graph):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    current = _read(coordinator, authority, lease)
    head = graph._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                            (active_scheme_head_key(NAMESPACE).token,)).fetchone()
    fields = {"d09.expression_policy": {**POLICY, "max_visible_chars": 72}}
    request = _arguments(current, fields)
    first = coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    after = _atoms(graph)
    assert coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request) == first
    assert _atoms(graph) == after
    assert first["changed_fields"] == ["d09.expression_policy"]
    assert first["draft_revision"] == current["draft_revision"] + 1
    assert graph._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                            (active_scheme_head_key(NAMESPACE).token,)).fetchone() == head
    with pytest.raises(EventConflict):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease,
            **{**request, "fields": {"d09.expression_policy": POLICY}})
    assert _atoms(graph) == after


def test_all_ten_editable_typed_fields_save_in_one_cas(owner_graph):
    from tests.alpha1.runtime.test_d12_domain_scheme_compile_v1 import (
        ACTION_SCHEMAS, ACTIVITY_RECIPE, AFFECT_SCHEME, ATTENTION_POLICY,
        CONTEXT_SCHEME, ENCODING_POLICY, PERSONA_PLAN, PROFILE, RELATIONSHIP_SCHEME,
    )
    graph, coordinator, _, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    fields = {"d01.persona_plan": PERSONA_PLAN, "d02.body_profile": PROFILE,
        "d03.context_scheme": CONTEXT_SCHEME, "d04.affect_scheme": AFFECT_SCHEME,
        "d05.relationship_scheme": RELATIONSHIP_SCHEME,
        "d06.encoding_projection_policy": ENCODING_POLICY,
        "d07.attention_policy": ATTENTION_POLICY, "d08.action_schemas": ACTION_SCHEMAS,
        "d09.expression_policy": POLICY, "d10.activity_recipe": ACTIVITY_RECIPE}
    current = _read(coordinator, authority, lease)
    saved = coordinator.save_current_creator_draft_for_operation_v1(authority, lease,
        **_arguments(current, fields))
    observed = _read(coordinator, authority, lease)
    assert observed["fields"] == fields
    assert observed["field_sources"] == {name: "owner" for name in fields}
    assert observed["active_head_revision"] == current["active_head_revision"]
    assert saved["draft_revision"] == current["draft_revision"] + 1
    assert saved["graph_revision"] == current["graph_revision"] + 1
    assert saved["changed_fields"] == sorted(fields)


@pytest.mark.parametrize("field,value", [
    ("expected_draft_revision", 2), ("expected_draft_digest", "f" * 64),
    ("expected_graph_revision", 999), ("expected_access_epoch", 999),
    ("expected_delete_epoch", 999),
])
def test_each_stale_precondition_preserves_draft(owner_graph, field, value):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    request = _arguments(_read(coordinator, authority, lease),
                         {"d09.expression_policy": {**POLICY, "max_visible_chars": 72}})
    before = _atoms(graph)
    with pytest.raises(StaleRead):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease,
            **{**request, field: value})
    assert _atoms(graph) == before


@pytest.mark.parametrize("fields", [
    {}, {"d01.unknown": "value"}, {"d04.authored_root": {}},
    {"d09.expression_policy": {**POLICY, "max_visible_chars": -1}},
])
def test_invalid_or_dedicated_fields_never_write(owner_graph, fields):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    request = _arguments(_read(coordinator, authority, lease), fields)
    before = _atoms(graph)
    with pytest.raises(D12SchemeHold):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    assert _atoms(graph) == before


def test_revoked_owner_and_missing_session_proof_cannot_save(owner_graph):
    graph, coordinator, port, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    request = _arguments(_read(coordinator, authority, lease),
                         {"d09.expression_policy": {**POLICY, "max_visible_chars": 72}})
    before = _atoms(graph)
    proofs = coordinator._GraphCoordinator__owner_session_proofs
    proof = proofs.pop(lease)
    with pytest.raises(UnavailableGuard):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    proofs[lease] = proof
    port.session_current = False
    with pytest.raises(RuntimeError, match="Owner session revoked"):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    assert _atoms(graph) == before


def test_lost_finish_ack_recovers_original_without_second_save(owner_graph, monkeypatch):
    graph, coordinator, port, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    request = _arguments(_read(coordinator, authority, lease),
                         {"d09.expression_policy": {**POLICY, "max_visible_chars": 72}})
    finish = port.finish_fence

    def lost_ack(scope, **kwargs):
        finish(scope, **kwargs)
        if scope.operation == "write":
            raise RuntimeError("finish ACK lost")

    monkeypatch.setattr(port, "finish_fence", lost_ack)
    with pytest.raises(RuntimeError, match="ACK lost"):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    after = _atoms(graph)
    monkeypatch.setattr(port, "finish_fence", finish)
    saved = coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    assert saved["draft_revision"] == 2
    assert _atoms(graph) == after
    assert graph._db.execute("SELECT COUNT(*) FROM graph_owner_domain_attempts_v3 WHERE operation_id=?",
                            (request["operation_id"],)).fetchone() == (1,)
