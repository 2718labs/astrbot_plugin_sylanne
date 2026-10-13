"""Installed C04 V3 association math over one frozen, authorized graph input.

The graph and D04 originals are validated before this pure calculation.  A
candidate receives only its own conditioned salience; the cue's attention
score cannot stand in for a target's encoding baseline.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey
from ...memory_association import AssociationActivator, AssociationEdge
from ...runtime.c04_v3_contracts import (
    AssociationScoreV3, AssociationWorkInputV3, AssociationWorkResultV3,
)


ALGORITHM_ID = "d06.association_activation.v3"


@dataclass(frozen=True, slots=True)
class V3ActivationCandidate:
    source_ref: str
    activation: float
    conditioned_salience: float
    mood_weighted_activation: float


@dataclass(frozen=True, slots=True)
class V3ActivationComputation:
    candidates: tuple[V3ActivationCandidate, ...]
    edge_refs: tuple[str, ...]
    visited_nodes: int
    visited_edges: int
    iterations: int
    stop_reason: str
    coverage: str


def compute_association_activation_v3(work: object, *,
                                      conditioned_salience: dict[str, float]
                                      ) -> V3ActivationComputation:
    return _compute_association_activation_from_roots_v3(work,
        conditioned_salience=conditioned_salience, initial_activation={work.cue_source_ref: 1.0})


def _compute_association_activation_from_roots_v3(work: object, *,
                                      conditioned_salience: dict[str, float], initial_activation: dict[str, float]
                                      ) -> V3ActivationComputation:
    """Run bounded activation with individually authenticated target weights.

    ``conditioned_salience`` is assembled exclusively from each target's V3
    original by the strict input contract.  An absent target is ineligible.
    """
    by_key = {AtomKey.from_token(item.ref): item for item in work.reads}
    traversed: list[AssociationEdge] = []
    edge_refs: list[str] = []
    allowed = set(initial_activation)
    frontier = set(initial_activation)
    expanded: set[str] = set()
    queries = {item.source_ref: item for item in work.edge_pages}
    for _ in range(work.budget.max_hops):
        next_frontier: set[str] = set()
        for source in sorted(frontier):
            if source in expanded:
                continue
            expanded.add(source)
            query = queries.get(source)
            if query is None:
                continue
            for ref in sorted(query.edge_refs):
                value = by_key[AtomKey.from_token(ref)].value
                fit = 1.0 if not value["context_tags"] else float(bool(
                    set(value["context_tags"]) & set(work.context_tags)))
                if fit == 0:
                    continue
                target = value["target_ref"]
                traversed.append(AssociationEdge(
                    source, target, value["weight"], fit, ref))
                edge_refs.append(ref)
                allowed.add(target)
                if target not in expanded:
                    next_frontier.add(target)
        frontier = next_frontier
        if not frontier:
            break
    activation = AssociationActivator(work.policy).propagate(
        initial_activation, tuple(traversed))
    ranked = sorted((
        V3ActivationCandidate(ref, score, conditioned_salience[ref],
                              score * conditioned_salience[ref])
        for ref, score in activation.activations
        if (ref != work.cue_source_ref and ref in allowed and score > 0
            and ref in conditioned_salience)
    ), key=lambda item: (-item.mood_weighted_activation, item.source_ref))
    selected = tuple(ranked[:work.budget.max_candidates])
    if work.budget.max_hops == 0:
        reason = "hop_budget_exhausted"
    elif work.truncated:
        reason = "traversal_budget_or_page_limit"
    elif len(ranked) > len(selected):
        reason = "candidate_limit"
    elif not selected:
        reason = "no_eligible_association"
    else:
        reason = activation.stop_reason
    return V3ActivationComputation(
        selected, tuple(sorted(edge_refs)), len(activation.visited_refs),
        len(edge_refs), activation.iterations, reason,
        "partial" if work.truncated else "bounded_complete",
    )


def activate_association_work_v3(work: AssociationWorkInputV3) -> AssociationWorkResultV3:
    """Execute a strict V3 input and retain each target's own proof identity."""
    if type(work) is not AssociationWorkInputV3 or work.algorithm_id != ALGORITHM_ID:
        raise TypeError("only frozen AssociationWorkInputV3 is executable")
    # The typed contract validates the complete graph and target closure.
    work.validate_closure()
    conditions = {target.source_ref: target.condition for target in work.targets}
    salience = {ref: sum(condition.conditioned_salience_interval) / 2.0
                for ref, condition in conditions.items()}
    computed = compute_association_activation_v3(work, conditioned_salience=salience)
    result = AssociationWorkResultV3(
        work.namespace, work.operation_id, work.input_digest,
        work.algorithm_id, work.algorithm_build_digest,
        tuple(AssociationScoreV3(
            item.source_ref, item.activation, item.conditioned_salience,
            item.mood_weighted_activation, conditions[item.source_ref].digest)
            for item in computed.candidates),
        computed.visited_nodes, computed.visited_edges, computed.iterations,
        work.truncated, computed.stop_reason,
    )
    result.validate_input(work)
    return result


__all__ = ["ALGORITHM_ID", "V3ActivationCandidate",
           "V3ActivationComputation", "compute_association_activation_v3",
           "activate_association_work_v3"]
