"""D09's isolated preview must show the actual finite length-gate difference."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d09 import D09ExpressionPolicyV1, D09ExpressionProvider
from sylanne3.domains.d12.d09_preview import (
    D12D09PreviewSpecV1, d09_preview_control_digest_v1,
    run_d12_d09_preview_v1,
)
from sylanne3.runtime.d12_domain_scheme_compile_v1 import (
    D12ExpressionPolicyCandidateV1, EXPRESSION_POLICY_FIELD,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


NAMESPACE = NamespaceId("bot", "persona")


def _candidate(limit: int = 19) -> D12ExpressionPolicyCandidateV1:
    policy = D09ExpressionPolicyV1("d09:expression", "v1", limit)
    field_digest = "a" * 64
    proposal_hash = D09ExpressionProvider().descriptor.request_schema_hash
    digest = canonical_digest({
        "schema": "d12.expression-policy-candidate.v1", "namespace": NAMESPACE,
        "field_input_digest": field_digest, "proposal_schema_hash": proposal_hash,
        "policy": asdict(policy),
    })
    return D12ExpressionPolicyCandidateV1(
        NAMESPACE, "d09", (EXPRESSION_POLICY_FIELD,), field_digest,
        proposal_hash, policy, digest,
    )


def _spec(candidate, baseline=None, **changes) -> D12D09PreviewSpecV1:
    args = dict(
        namespace=NAMESPACE, operation_id="preview-op", compiled_digest="b" * 64,
        current_policy_digest=d09_preview_control_digest_v1(baseline),
        candidate_digest=candidate.candidate_digest,
        scheme_fields=(EXPRESSION_POLICY_FIELD,),
    )
    args.update(changes)
    return D12D09PreviewSpecV1(**args)


def test_default_d09_vs_19_chars_has_visible_pass_reject_and_stable_seal():
    candidate = _candidate(19)
    first = run_d12_d09_preview_v1(_spec(candidate), None, candidate)
    replay = run_d12_d09_preview_v1(_spec(candidate), None, candidate)
    assert first == replay
    assert first.status == "isolated_behavior_only"
    assert first.changed_probe_ids == ("visible_chars:20", "visible_chars:2048")
    at_20 = next(i for i, row in enumerate(first.baseline_outputs)
                 if row.visible_chars == 20)
    assert first.baseline_outputs[at_20].length_gate_passed
    assert not first.candidate_outputs[at_20].length_gate_passed
    assert first.steps_used == 6
    assert first.report_digest != first.candidate_output_digest


@pytest.mark.parametrize("limit", (1, 19, 2047))
def test_every_tightened_limit_has_a_boundary_probe(limit):
    candidate = _candidate(limit)
    report = run_d12_d09_preview_v1(_spec(candidate), None, candidate)
    assert f"visible_chars:{limit + 1}" in report.changed_probe_ids
    assert report.steps_used <= 8


def test_equal_default_limit_reports_no_behavior_difference():
    candidate = _candidate(2048)
    report = run_d12_d09_preview_v1(_spec(candidate), None, candidate)
    assert report.changed_probe_ids == ()
    assert report.baseline_outputs == report.candidate_outputs


def test_adopted_d09_control_is_independent_of_d07_default():
    current = D09ExpressionPolicyV1("d09:active", "v2", 20)
    candidate = _candidate(19)
    report = run_d12_d09_preview_v1(_spec(candidate, current), current, candidate)
    assert report.changed_probe_ids == ("visible_chars:20",)
    with pytest.raises(ValueError, match="current D09 control identity"):
        run_d12_d09_preview_v1(_spec(candidate, current), None, candidate)


def test_mixed_field_and_budget_hold_before_running_probes(monkeypatch):
    candidate = _candidate()
    import sylanne3.domains.d12.d09_preview as preview

    def fail(*_args):
        pytest.fail("HOLD must not execute probes")

    monkeypatch.setattr(preview, "_outputs", fail)
    mixed = run_d12_d09_preview_v1(
        _spec(candidate, scheme_fields=(EXPRESSION_POLICY_FIELD, "d07.attention_policy")),
        None, candidate,
    )
    budget = run_d12_d09_preview_v1(
        _spec(candidate, max_steps=5), None, candidate,
    )
    assert (mixed.status, mixed.hold_reason, mixed.steps_used) == (
        "HOLD", "mixed_or_unsupported_scheme", 0)
    assert (budget.status, budget.hold_reason, budget.steps_used) == (
        "HOLD", "step_budget_insufficient", 0)


def test_candidate_and_protocol_tamper_rejected():
    candidate = _candidate()
    with pytest.raises(ValueError, match="typed D09 candidate identity"):
        run_d12_d09_preview_v1(_spec(candidate), None,
                               replace(candidate, candidate_digest="c" * 64))
    with pytest.raises(ValueError, match="protocol/runner"):
        run_d12_d09_preview_v1(
            _spec(candidate, protocol_digest="d" * 64), None, candidate)
