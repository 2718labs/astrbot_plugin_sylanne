"""Finite D09 length-gate experiment for a D12 scheme preview.

This compares only the visible character bound used by D09's natural reply
mechanical check. It never generates a reply, verifies semantics, or sends one.
W01 owns current-head reads, D11 compute admission, durable report issuance,
and the adoption CAS; this pure runner grants none of those things.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ...runtime.d12_domain_scheme_compile_v1 import (
    D12ExpressionPolicyCandidateV1, EXPRESSION_POLICY_FIELD,
)
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d09 import (
    DEFAULT_MAX_VISIBLE_CHARS_V1, D09ExpressionPolicyV1,
    D09ExpressionProvider,
)


PROTOCOL = "d09.visible-length-boundary-probes.v1"
RUNNER = "d12.d09-expression-preview.v1"
_PROTOCOL_DIGEST = canonical_digest({
    "protocol": PROTOCOL,
    "probe_rule": "sorted-unique(1,baseline-limit+1,candidate-limit+1,2048);"
                  "each body is ASCII x repeated N times",
    "gate_rule": "len(body)<=effective_max_visible_chars",
})


@dataclass(frozen=True, slots=True)
class D12D09PreviewSpecV1:
    namespace: NamespaceId
    operation_id: str
    compiled_digest: str
    current_policy_digest: str
    candidate_digest: str
    scheme_fields: tuple[str, ...]
    protocol: str = PROTOCOL
    protocol_digest: str = _PROTOCOL_DIGEST
    runner: str = RUNNER
    max_steps: int = 8  # four probes, baseline and candidate gate once each


@dataclass(frozen=True, slots=True)
class D12D09ProbeOutputV1:
    probe_id: str
    input_digest: str
    visible_chars: int
    length_gate_passed: bool
    output_digest: str


@dataclass(frozen=True, slots=True)
class D12D09PreviewReportV1:
    spec: D12D09PreviewSpecV1
    status: str
    hold_reason: str | None
    coverage: tuple[str, ...]
    frozen_input_digest: str
    baseline_outputs: tuple[D12D09ProbeOutputV1, ...]
    candidate_outputs: tuple[D12D09ProbeOutputV1, ...]
    baseline_output_digest: str | None
    candidate_output_digest: str | None
    changed_probe_ids: tuple[str, ...]
    steps_used: int
    report_digest: str


def d09_preview_control_digest_v1(policy: D09ExpressionPolicyV1 | None) -> str:
    """Bind an adopted policy or the absence that means D09's default."""
    if policy is not None and type(policy) is not D09ExpressionPolicyV1:
        raise TypeError("typed D09 policy or absent default required")
    return canonical_digest({
        "schema": "d12.d09-preview-control.v1",
        "policy": asdict(policy) if policy is not None else None,
        "effective_max_visible_chars": (
            policy.max_visible_chars if policy is not None
            else DEFAULT_MAX_VISIBLE_CHARS_V1
        ),
    })


def _require_digest(value: str, label: str) -> None:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _candidate_digest(candidate: D12ExpressionPolicyCandidateV1) -> str:
    return canonical_digest({
        "schema": "d12.expression-policy-candidate.v1",
        "namespace": candidate.namespace,
        "field_input_digest": candidate.field_input_digest,
        "proposal_schema_hash": candidate.proposal_schema_hash,
        "policy": asdict(candidate.policy),
    })


def _outputs(lengths: tuple[int, ...], limit: int) -> tuple[D12D09ProbeOutputV1, ...]:
    rows = []
    for length in lengths:
        body = "x" * length
        result = {
            "probe_id": f"visible_chars:{length}",
            "input_digest": canonical_digest(body),
            "visible_chars": length,
            "length_gate_passed": len(body) <= limit,
        }
        rows.append(D12D09ProbeOutputV1(**result, output_digest=canonical_digest(result)))
    return tuple(rows)


def run_d12_d09_preview_v1(
    spec: D12D09PreviewSpecV1,
    current_policy: D09ExpressionPolicyV1 | None,
    candidate: D12ExpressionPolicyCandidateV1,
) -> D12D09PreviewReportV1:
    """Compare two local length gates over finite boundary strings only."""
    if type(spec) is not D12D09PreviewSpecV1 or type(spec.namespace) is not NamespaceId:
        raise TypeError("exact D09 preview spec and namespace required")
    if type(spec.operation_id) is not str or not spec.operation_id.strip():
        raise ValueError("operation_id required")
    for label in ("compiled_digest", "current_policy_digest", "candidate_digest",
                  "protocol_digest"):
        _require_digest(getattr(spec, label), label)
    if (spec.protocol != PROTOCOL or spec.protocol_digest != _PROTOCOL_DIGEST
            or spec.runner != RUNNER):
        raise ValueError("unsupported or changed D09 preview protocol/runner")
    if (type(spec.max_steps) is not int or not 0 <= spec.max_steps <= 64
            or type(spec.scheme_fields) is not tuple
            or any(type(field) is not str for field in spec.scheme_fields)):
        raise ValueError("bounded steps and exact scheme fields required")
    if d09_preview_control_digest_v1(current_policy) != spec.current_policy_digest:
        raise ValueError("current D09 control identity mismatch")
    if (type(candidate) is not D12ExpressionPolicyCandidateV1
            or type(candidate.policy) is not D09ExpressionPolicyV1
            or candidate.namespace != spec.namespace
            or candidate.domain != "d09"
            or candidate.field_names != (EXPRESSION_POLICY_FIELD,)
            or candidate.status != "typed_candidate_not_persisted"
            or candidate.candidate_digest != spec.candidate_digest
            or candidate.candidate_digest != _candidate_digest(candidate)
            or candidate.proposal_schema_hash
            != D09ExpressionProvider().descriptor.request_schema_hash):
        raise ValueError("typed D09 candidate identity mismatch")

    baseline_limit = (current_policy.max_visible_chars if current_policy is not None
                      else DEFAULT_MAX_VISIBLE_CHARS_V1)
    candidate_limit = candidate.policy.max_visible_chars
    lengths = tuple(sorted(length for length in {
        1, baseline_limit + 1, candidate_limit + 1,
        DEFAULT_MAX_VISIBLE_CHARS_V1,
    } if length <= DEFAULT_MAX_VISIBLE_CHARS_V1))
    required_steps = 2 * len(lengths)
    frozen_input_digest = canonical_digest({
        "protocol_digest": _PROTOCOL_DIGEST,
        "current_policy_digest": spec.current_policy_digest,
        "candidate_digest": spec.candidate_digest,
        "probe_lengths": lengths,
    })
    reason = None
    if spec.scheme_fields != (EXPRESSION_POLICY_FIELD,):
        reason = "mixed_or_unsupported_scheme"
    elif spec.max_steps < required_steps:
        reason = "step_budget_insufficient"
    if reason is not None:
        payload = dict(
            spec=spec, status="HOLD", hold_reason=reason, coverage=(),
            frozen_input_digest=frozen_input_digest, baseline_outputs=(),
            candidate_outputs=(), baseline_output_digest=None,
            candidate_output_digest=None, changed_probe_ids=(), steps_used=0,
        )
        return D12D09PreviewReportV1(**payload, report_digest=canonical_digest(payload))

    baseline = _outputs(lengths, baseline_limit)
    proposed = _outputs(lengths, candidate_limit)
    payload = dict(
        spec=spec, status="isolated_behavior_only", hold_reason=None,
        coverage=tuple(row.probe_id for row in baseline),
        frozen_input_digest=frozen_input_digest,
        baseline_outputs=baseline, candidate_outputs=proposed,
        baseline_output_digest=canonical_digest(baseline),
        candidate_output_digest=canonical_digest(proposed),
        changed_probe_ids=tuple(before.probe_id for before, after in zip(
            baseline, proposed) if before.output_digest != after.output_digest),
        steps_used=required_steps,
    )
    return D12D09PreviewReportV1(**payload, report_digest=canonical_digest(payload))


__all__ = (
    "D12D09PreviewSpecV1", "D12D09ProbeOutputV1", "D12D09PreviewReportV1",
    "d09_preview_control_digest_v1", "run_d12_d09_preview_v1",
)
