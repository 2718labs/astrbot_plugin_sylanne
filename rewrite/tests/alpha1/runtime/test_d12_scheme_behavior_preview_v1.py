"""The D12 behavior report runs real D07 decisions over fixed simulated inputs."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d07 import AttentionPolicy, D07DomainProvider
from sylanne3.runtime.d12_domain_scheme_compile_v1 import (
    ATTENTION_POLICY_FIELD, D12AttentionPolicyCandidateV1,
)
from sylanne3.runtime.d12_scheme_behavior_preview_v1 import (
    D12BehaviorExperimentSpecV1, run_d12_scheme_behavior_preview_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


NAMESPACE = NamespaceId("bot", "persona")
BASELINE = AttentionPolicy.default()


def _candidate(policy=BASELINE):
    field_digest = "a" * 64
    proposal_hash = D07DomainProvider().descriptor.request_schema_hash
    digest = canonical_digest({
        "schema": "d12.attention-policy-candidate.v1", "namespace": NAMESPACE,
        "field_input_digest": field_digest, "proposal_schema_hash": proposal_hash,
        "policy": asdict(policy),
    })
    return D12AttentionPolicyCandidateV1(
        NAMESPACE, "d07", (ATTENTION_POLICY_FIELD,), field_digest,
        proposal_hash, policy, digest,
    )


def _spec(candidate, **changes):
    values = dict(namespace=NAMESPACE, operation_id="preview-op",
                  compiled_digest="b" * 64,
                  current_policy_digest=canonical_digest(asdict(BASELINE)),
                  candidate_digest=candidate.candidate_digest,
                  scheme_fields=(ATTENTION_POLICY_FIELD,))
    values.update(changes)
    return D12BehaviorExperimentSpecV1(**values)


def test_real_d07_same_policy_is_an_honest_zero_difference():
    candidate = _candidate()
    report = run_d12_scheme_behavior_preview_v1(_spec(candidate), BASELINE, candidate)
    assert report.status == "isolated_behavior_only"
    assert report.hold_reason is None
    assert report.changed_probe_ids == ()
    assert report.baseline_outputs == report.candidate_outputs
    assert report.baseline_output_digest == report.candidate_output_digest
    assert report.steps_used == 52
    assert len(report.baseline_outputs) == 13
    assert report.coverage == tuple(row.probe_id for row in report.baseline_outputs)
    assert [row.probe_id for row in report.baseline_outputs[:9]] == [
        f"weight:{name}" for name in (
            "relevance_weight", "urgency_weight", "information_weight",
            "persona_weight", "emotion_weight", "waiting_weight",
            "switch_cost_weight", "fatigue_cost_weight", "served_cost_weight",
        )
    ]
    gates = next(row for row in report.baseline_outputs if row.probe_id == "gates")
    assert gates.ranked_scores == (("eligible", 0.044000000000000004),)
    assert gates.primary_ticket_ref == "eligible"
    assert next(row for row in report.baseline_outputs if row.probe_id == "empty").primary_ticket_ref is None
    assert report.report_digest


def test_changed_policy_reports_exact_scores_order_and_focus():
    policy = replace(BASELINE, relevance_weight=0.32, urgency_weight=0.12)
    candidate = _candidate(policy)
    report = run_d12_scheme_behavior_preview_v1(_spec(candidate), BASELINE, candidate)
    assert report.status == "isolated_behavior_only"
    assert "weight:relevance_weight" in report.changed_probe_ids
    assert "weight:urgency_weight" in report.changed_probe_ids
    assert "empty" not in report.changed_probe_ids
    base = next(row for row in report.baseline_outputs if row.probe_id == "weight:relevance_weight")
    changed = next(row for row in report.candidate_outputs if row.probe_id == "weight:relevance_weight")
    assert base.ranked_scores != changed.ranked_scores
    assert changed.ranked_scores[0][0] == changed.primary_ticket_ref
    assert changed.input_digest == base.input_digest
    assert report.baseline_output_digest != report.candidate_output_digest


@pytest.mark.parametrize("weight", (
    "relevance_weight", "urgency_weight", "information_weight",
    "persona_weight", "emotion_weight", "waiting_weight",
    "switch_cost_weight", "fatigue_cost_weight", "served_cost_weight",
))
def test_each_weight_has_a_visible_isolated_probe(weight):
    offset = "urgency_weight" if weight != "urgency_weight" else "relevance_weight"
    policy = replace(BASELINE, **{
        weight: getattr(BASELINE, weight) + 0.01,
        offset: getattr(BASELINE, offset) - 0.01,
    })
    candidate = _candidate(policy)
    report = run_d12_scheme_behavior_preview_v1(_spec(candidate), BASELINE, candidate)
    assert f"weight:{weight}" in report.changed_probe_ids


def test_mixed_scope_and_insufficient_budget_hold_without_execution(monkeypatch):
    candidate = _candidate()
    def fail(*args, **kwargs):
        pytest.fail("D07 must not run on HOLD")
    monkeypatch.setattr(D07DomainProvider, "rank_attention", fail)
    mixed = run_d12_scheme_behavior_preview_v1(
        _spec(candidate, scheme_fields=(ATTENTION_POLICY_FIELD, "d04.affect_scheme")),
        BASELINE, candidate)
    assert (mixed.status, mixed.hold_reason, mixed.steps_used) == (
        "HOLD", "mixed_or_unsupported_scheme", 0)
    assert mixed.baseline_outputs == mixed.candidate_outputs == ()
    assert mixed.coverage == ()
    budget = run_d12_scheme_behavior_preview_v1(
        _spec(candidate, max_steps=51), BASELINE, candidate)
    assert budget.hold_reason == "step_budget_insufficient"


def test_identity_tampering_is_rejected_before_any_run(monkeypatch):
    candidate = _candidate()
    def fail(*args, **kwargs):
        pytest.fail("D07 must not run for malformed identity")
    monkeypatch.setattr(D07DomainProvider, "rank_attention", fail)
    with pytest.raises(ValueError, match="baseline policy identity"):
        run_d12_scheme_behavior_preview_v1(
            _spec(candidate, current_policy_digest="c" * 64), BASELINE, candidate)
    with pytest.raises(ValueError, match="typed candidate identity"):
        run_d12_scheme_behavior_preview_v1(
            _spec(candidate), BASELINE, replace(candidate, candidate_digest="c" * 64))
    with pytest.raises(ValueError, match="protocol/runner"):
        run_d12_scheme_behavior_preview_v1(
            _spec(candidate, protocol_digest="c" * 64), BASELINE, candidate)
