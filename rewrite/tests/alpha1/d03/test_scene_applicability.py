from dataclasses import replace

import pytest

from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import (
    NormApplicabilityEvidenceV1,
    RoleBinding,
    SceneIngressScopeV1,
    check_current_scene_applicability,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
_DEFAULT = object()


def _inputs(*, occurred_at=150.0, learned_at=155.0):
    envelope = HostIngressEnvelope(
        NAMESPACE,
        "platform:qq",
        "conversation:group-1",
        "sender:user-1",
        "message:100",
        "hello",
        occurred_at,
        learned_at,
        "group",
        SourceLineage(
            "a" * 64,
            "reported",
            "family:100",
            "external_report",
            "reported_claim",
        ),
    )
    scope = SceneIngressScopeV1(
        NAMESPACE,
        "platform:qq",
        "conversation:group-1",
        "scene:project",
        "conversation:group-1",
        "scene",
        "persona:persona",
        None,
        "group:group-1",
        "reply",
        "respond",
        occurred_at,
        4,
        2,
    )
    plan = PersonaPlan(
        "plan:current",
        NAMESPACE,
        3,
        (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
        (),
        True,
    )
    reads = (
        GraphVersion(AtomKey(Owner("persona", "bot", "persona"), "d01.persona_activation.v1", "current"), 3),
        GraphVersion(AtomKey(Owner("persona", "bot", "persona"), "d01.persona_plan.v1", plan.plan_id), 3),
    )
    role = ActiveRoleQualification(NAMESPACE, plan.head_id, plan, reads, 9, 1)
    binding = RoleBinding(
        "binding:project",
        "persona:persona",
        "collaborator",
        None,
        None,
        "scene:project",
        "scene",
        "group",
        ("norm:reply",),
        100.0,
        200.0,
        10,
        ("source:binding",),
        7,
        "active",
    )
    norms = NormApplicabilityEvidenceV1(
        NAMESPACE,
        "scene:project",
        "binding:project",
        7,
        9,
        "complete",
        ("norm:reply",),
        ("reply",),
        ("respond",),
        ("platform:qq",),
        ("scene",),
        ("group",),
        6,
        180.0,
    )
    return envelope, scope, role, binding, norms


def _check(*, envelope=None, scope=None, role=None, binding=_DEFAULT, norms=_DEFAULT, reader=_DEFAULT):
    base = _inputs()
    envelope = envelope or base[0]
    scope = scope or base[1]
    role = role or base[2]
    binding = base[3] if binding is _DEFAULT else binding
    norms = base[4] if norms is _DEFAULT else norms
    calls = []

    def current_reader():
        calls.append((scope.namespace, scope.scene_ref))
        return role, binding

    result = check_current_scene_applicability(
        envelope,
        scope,
        current_scene_reader=current_reader if reader is _DEFAULT else reader,
        norm_evidence=norms,
    )
    return result, calls


def test_applicability_requires_fresh_scene_read_and_pins_current_versions():
    result, calls = _check()
    assert result.status == "applicable"
    assert calls == [(NAMESPACE, "scene:project")]
    assert result.role_head_id
    assert (result.binding_id, result.binding_version, result.graph_epoch) == (
        "binding:project",
        7,
        9,
    )
    assert {item.ref for item in result.input_versions} >= {
        "binding:project",
        "d03.norm_policy",
        "d03.identity_mapping",
        "d03.time_mapping",
        "d03.scene_query_epoch",
    }


@pytest.mark.parametrize(
    "reader,norms,expected_reason",
    [
        (None, None, "current_fenced_scene_read_missing"),
        (lambda: (None, None), None, "current_fenced_scene_read_invalid"),
    ],
)
def test_missing_or_invalid_current_read_never_uses_a_stored_binding(reader, norms, expected_reason):
    result, _ = _check(reader=reader, norms=norms)
    assert result.status == "unknown"
    assert expected_reason in result.reasons


def test_missing_norm_resolution_and_partial_resolution_hold():
    result, _ = _check(norms=None)
    assert result.status == "unknown"
    assert "current_norm_applicability_missing" in result.reasons
    partial = replace(_inputs()[4], status="partial")
    result, _ = _check(norms=partial)
    assert result.status == "unknown"
    assert "current_norm_applicability_incomplete" in result.reasons


@pytest.mark.parametrize(
    "scope_change,reason",
    [
        ({"platform_ref": "platform:other"}, "platform_mismatch"),
        ({"conversation_ref": "conversation:other", "scope_ref": "conversation:other"}, "conversation_scope_mismatch"),
        ({"at_time": 149.0}, "message_time_mismatch"),
    ],
)
def test_platform_conversation_and_message_time_are_bound(scope_change, reason):
    envelope, scope, *_ = _inputs()
    result, calls = _check(scope=replace(scope, **scope_change))
    assert result.status == "inapplicable"
    assert reason in result.reasons
    assert calls == []


def test_unknown_message_time_cannot_be_replaced_with_ingress_processing_time():
    envelope, scope, *_ = _inputs(occurred_at=None)
    result, calls = _check(envelope=envelope)
    assert result.status == "unknown"
    assert "message_occurrence_time_unknown" in result.reasons
    assert calls == []


@pytest.mark.parametrize(
    "binding_change,reason",
    [
        ({"status": "review"}, "binding_not_active"),
        ({"scope_selector": "conversation"}, "scope_selector_mismatch"),
        ({"visibility_scope": "private"}, "visibility_scope_mismatch"),
        ({"effective_until": 149.0}, "binding_outside_effective_interval"),
        ({"target_entity_ref": "entity:someone-else"}, "target_scope_mismatch"),
    ],
)
def test_current_binding_must_match_active_scope_visibility_and_time(binding_change, reason):
    binding = replace(_inputs()[3], **binding_change)
    result, _ = _check(binding=binding)
    assert result.status == "inapplicable"
    assert reason in result.reasons


def test_norm_must_cover_the_exact_action_purpose_platform_and_scope():
    norms = replace(_inputs()[4], action_kinds=("delete",))
    result, _ = _check(norms=norms)
    assert result.status == "inapplicable"
    assert "norm_does_not_cover_current_action" in result.reasons


def test_norm_evidence_from_another_binding_revision_or_graph_read_holds():
    stale = replace(_inputs()[4], binding_version=6)
    result, _ = _check(norms=stale)
    assert result.status == "unknown"
    assert "current_norm_read_version_mismatch" in result.reasons


def test_binding_that_expired_before_current_ingress_cannot_authorize_reply():
    envelope, scope, role, binding, norms = _inputs(occurred_at=150.0, learned_at=205.0)
    result, _ = _check(envelope=envelope)
    assert result.status == "inapplicable"
    assert "binding_outside_effective_interval" in result.reasons


def test_reader_failure_and_wrong_current_persona_return_unknown():
    envelope, scope, role, binding, norms = _inputs()
    result = check_current_scene_applicability(
        envelope,
        scope,
        current_scene_reader=lambda: (_ for _ in ()).throw(RuntimeError("offline")),
        norm_evidence=norms,
    )
    assert result.status == "unknown"
    assert "current_fenced_scene_read_unavailable" in result.reasons
    other_plan = replace(role.plan, namespace=NamespaceId("bot", "other"))
    result = check_current_scene_applicability(
        envelope,
        scope,
        current_scene_reader=lambda: (replace(role, plan=other_plan), binding),
        norm_evidence=norms,
    )
    assert result.status == "unknown"
    assert "current_role_namespace_mismatch" in result.reasons
