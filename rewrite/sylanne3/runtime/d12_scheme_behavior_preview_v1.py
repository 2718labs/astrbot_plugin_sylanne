"""Bounded, simulated D07 behavior comparison for a D12 scheme candidate.

This is low-trust evidence. W01 must bind the current baseline and read set,
settle D11 cost, and issue any durable preview or adoption certificate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..domains.d07 import AttentionPolicy, AttentionTicket, D07DomainProvider, FocusState
from ..runtime_contracts import NamespaceId, canonical_digest
from .d12_domain_scheme_compile_v1 import (
    ATTENTION_POLICY_FIELD, D12AttentionPolicyCandidateV1,
)


PROTOCOL = "d07.attention-probes.v1"
RUNNER = "d12.scheme-behavior-preview.v1"
_NOW = 100.0
_FOCUS = FocusState("preview-persona", 7, "prior-ticket", ("prior-aux",), "simulated")
_WEIGHT_FIELDS = (
    "relevance_weight", "urgency_weight", "information_weight", "persona_weight",
    "emotion_weight", "waiting_weight", "switch_cost_weight",
    "fatigue_cost_weight", "served_cost_weight",
)
_MEASURES = (
    "relevance", "urgency", "information_value", "persona_salience",
    "emotional_salience", "waiting", "switch_cost", "fatigue_cost", "served_fraction",
)


def _ticket(ticket_id: str, seq: int, category: str = "interaction", **changes) -> AttentionTicket:
    values = dict(
        ticket_id=ticket_id, question_key=f"question:{ticket_id}", concern_ref=None,
        causal_root=f"simulated:{ticket_id}", category=category,
        relevance=0.0, urgency=0.0, information_value=0.0,
        persona_salience=0.0, emotional_salience=0.0, waiting=0.0,
        switch_cost=0.0, fatigue_cost=0.0, served_fraction=0.0,
        enqueued_seq=seq, valid_until=_NOW + 1.0, eligible=True,
        resources_available=True, cancel_refs=(), source_refs=(),
    )
    values.update(changes)
    return AttentionTicket(**values)


def _probes() -> tuple[tuple[str, tuple[AttentionTicket, ...]], ...]:
    probes = []
    for index, measure in enumerate(_MEASURES):
        signal = {measure: 1.0}
        if index >= 6:
            signal["relevance"] = 1.0  # keep a cost effect above score clipping
        probes.append((f"weight:{_WEIGHT_FIELDS[index]}", (
            _ticket("signal", 1, **signal),
            _ticket("reference", 2, relevance=0.5, urgency=0.5),
        )))
    probes.extend((
        ("gates", (
            _ticket("ineligible", 1, relevance=1.0, eligible=False),
            _ticket("stale", 2, relevance=1.0, valid_until=_NOW - 1.0),
            _ticket("resource-shortage", 3, relevance=1.0, resources_available=False),
            _ticket("eligible", 4, relevance=0.2),
        )),
        ("category-order", (
            _ticket("background", 1, "background", relevance=1.0),
            _ticket("required", 2, "required"),
            _ticket("interaction", 3, "interaction", relevance=1.0),
        )),
        ("ties-and-capacity", (
            _ticket("tie-b", 1), _ticket("tie-a", 1),
            _ticket("tie-later", 2), _ticket("tie-third", 3),
            _ticket("tie-overflow", 4),
        )),
        ("empty", (_ticket("ineligible", 1, eligible=False),)),
    ))
    return tuple(probes)


_PROBES = _probes()
_COVERAGE = tuple(probe_id for probe_id, _ in _PROBES)
_PROTOCOL_DIGEST = canonical_digest({
    "protocol": PROTOCOL, "now": _NOW, "focus": _FOCUS, "probes": _PROBES,
})
_REQUIRED_STEPS = 4 * len(_PROBES)  # rank and allocate (which ranks) on both sides


@dataclass(frozen=True, slots=True)
class D12BehaviorExperimentSpecV1:
    namespace: NamespaceId
    operation_id: str
    compiled_digest: str
    current_policy_digest: str
    candidate_digest: str
    scheme_fields: tuple[str, ...]
    protocol: str = PROTOCOL
    protocol_digest: str = _PROTOCOL_DIGEST
    runner: str = RUNNER
    max_steps: int = _REQUIRED_STEPS


@dataclass(frozen=True, slots=True)
class D12AttentionProbeOutputV1:
    probe_id: str
    input_digest: str
    ranked_scores: tuple[tuple[str, float], ...]
    primary_ticket_ref: str | None
    auxiliary_ticket_refs: tuple[str, ...]
    focus_epoch: int
    switch_reason: str
    output_digest: str


@dataclass(frozen=True, slots=True)
class D12BehaviorExperimentReportV1:
    spec: D12BehaviorExperimentSpecV1
    status: str
    hold_reason: str | None
    coverage: tuple[str, ...]
    frozen_input_digest: str
    baseline_outputs: tuple[D12AttentionProbeOutputV1, ...]
    candidate_outputs: tuple[D12AttentionProbeOutputV1, ...]
    baseline_output_digest: str | None
    candidate_output_digest: str | None
    changed_probe_ids: tuple[str, ...]
    steps_used: int
    report_digest: str


def _digest(value: str, label: str) -> None:
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _candidate_digest(candidate: D12AttentionPolicyCandidateV1) -> str:
    return canonical_digest({
        "schema": "d12.attention-policy-candidate.v1",
        "namespace": candidate.namespace,
        "field_input_digest": candidate.field_input_digest,
        "proposal_schema_hash": candidate.proposal_schema_hash,
        "policy": asdict(candidate.policy),
    })


def _run(policy: AttentionPolicy) -> tuple[D12AttentionProbeOutputV1, ...]:
    provider = D07DomainProvider()
    output = []
    for probe_id, tickets in _PROBES:
        ranked = provider.rank_attention(tickets, policy, now=_NOW)
        focus = provider.allocate_focus(_FOCUS, tickets, policy, now=_NOW)
        scores = tuple((entry.ticket.ticket_id, entry.score) for entry in ranked)
        result = dict(probe_id=probe_id, input_digest=canonical_digest({
            "now": _NOW, "focus": _FOCUS, "tickets": tickets,
        }), ranked_scores=scores, primary_ticket_ref=focus.primary_ticket_ref,
            auxiliary_ticket_refs=focus.auxiliary_ticket_refs,
            focus_epoch=focus.focus_epoch, switch_reason=focus.switch_reason)
        output.append(D12AttentionProbeOutputV1(**result, output_digest=canonical_digest(result)))
    return tuple(output)


def run_d12_scheme_behavior_preview_v1(
    spec: D12BehaviorExperimentSpecV1,
    current_policy: AttentionPolicy,
    candidate: D12AttentionPolicyCandidateV1,
) -> D12BehaviorExperimentReportV1:
    """Compare only the fixed D07 probe corpus; never reads or writes production."""
    if type(spec) is not D12BehaviorExperimentSpecV1 or type(spec.namespace) is not NamespaceId:
        raise TypeError("exact experiment spec and namespace required")
    if type(spec.operation_id) is not str or not spec.operation_id.strip():
        raise ValueError("operation_id required")
    for name in ("compiled_digest", "current_policy_digest", "candidate_digest", "protocol_digest"):
        _digest(getattr(spec, name), name)
    if (spec.protocol != PROTOCOL or spec.protocol_digest != _PROTOCOL_DIGEST
            or spec.runner != RUNNER):
        raise ValueError("unsupported or changed D07 probe protocol/runner")
    if type(spec.max_steps) is not int or spec.max_steps < 0 or spec.max_steps > 256:
        raise ValueError("max_steps must be a bounded exact integer")
    if type(spec.scheme_fields) is not tuple or any(type(v) is not str for v in spec.scheme_fields):
        raise TypeError("scheme_fields must be an exact tuple of names")
    if type(current_policy) is not AttentionPolicy or canonical_digest(asdict(current_policy)) != spec.current_policy_digest:
        raise ValueError("baseline policy identity mismatch")
    if (type(candidate) is not D12AttentionPolicyCandidateV1
            or type(candidate.policy) is not AttentionPolicy
            or candidate.namespace != spec.namespace
            or candidate.domain != "d07"
            or candidate.field_names != (ATTENTION_POLICY_FIELD,)
            or candidate.status != "typed_candidate_not_persisted"
            or candidate.candidate_digest != spec.candidate_digest
            or candidate.candidate_digest != _candidate_digest(candidate)
            or candidate.proposal_schema_hash != D07DomainProvider().descriptor.request_schema_hash):
        raise ValueError("typed candidate identity mismatch")
    frozen_input_digest = canonical_digest({
        "protocol_digest": _PROTOCOL_DIGEST,
        "current_policy": asdict(current_policy),
        "candidate_policy": asdict(candidate.policy),
    })
    reason = None
    if spec.scheme_fields != (ATTENTION_POLICY_FIELD,):
        reason = "mixed_or_unsupported_scheme"
    elif spec.max_steps < _REQUIRED_STEPS:
        reason = "step_budget_insufficient"
    if reason is not None:
        payload = dict(spec=spec, status="HOLD", hold_reason=reason,
                       coverage=(),
                       frozen_input_digest=frozen_input_digest,
                       baseline_outputs=(), candidate_outputs=(),
                       baseline_output_digest=None, candidate_output_digest=None,
                       changed_probe_ids=(), steps_used=0)
        return D12BehaviorExperimentReportV1(**payload, report_digest=canonical_digest(payload))
    baseline, proposed = _run(current_policy), _run(candidate.policy)
    changed = tuple(before.probe_id for before, after in zip(baseline, proposed)
                    if before.output_digest != after.output_digest)
    payload = dict(spec=spec, status="isolated_behavior_only", hold_reason=None,
                   coverage=_COVERAGE,
                   frozen_input_digest=frozen_input_digest,
                   baseline_outputs=baseline, candidate_outputs=proposed,
                   baseline_output_digest=canonical_digest(baseline),
                   candidate_output_digest=canonical_digest(proposed),
                   changed_probe_ids=changed, steps_used=_REQUIRED_STEPS)
    return D12BehaviorExperimentReportV1(**payload, report_digest=canonical_digest(payload))
