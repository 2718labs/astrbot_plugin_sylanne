"""Bounded personal association candidates from a focused recollection cue.

Traversal reauthorizes committed association edges and their source/basis
records. Its output is a D07 choice input, not a C04 experience, new external
evidence, or a durable association write.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_association import ActivationPolicy, PersistentAssociationReader
from ...runtime_contracts import NamespaceId
from . import SelectionTicket
from .current_focus_binding import bind_current_c04_focus_v1
from .current_recollection_bridge import CurrentC04SourceCandidateV1


@dataclass(frozen=True, slots=True)
class CurrentAssociationBudgetV1:
    max_hops: int = 2
    max_edges: int = 128
    max_nodes: int = 128
    max_iterations: int = 32
    max_candidates: int = 32

    def __post_init__(self) -> None:
        for name, ceiling in (("max_hops", 2), ("max_edges", 128),
                              ("max_nodes", 128), ("max_iterations", 64),
                              ("max_candidates", 32)):
            value = getattr(self, name)
            floor = 0 if name == "max_hops" else 1
            if type(value) is not int or not floor <= value <= ceiling:
                raise ValueError(f"{name} is outside the bounded association policy")


@dataclass(frozen=True, slots=True)
class CurrentAssociationCandidateV1:
    source_ref: str
    activation: float
    mood_weighted_activation: float
    evidence_eligibility: str = "subjective_association_only"


@dataclass(frozen=True, slots=True)
class CurrentAssociationCandidatesV1:
    cue_source_ref: str
    candidates: tuple[CurrentAssociationCandidateV1, ...]
    edge_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: NamespaceEpoch
    visited_nodes: int
    visited_edges: int
    iterations: int
    stop_reason: str
    status: str = "candidate_hold_d07_choice_w01_fence"


def prepare_current_association_candidates_v1(
    cue: CurrentC04SourceCandidateV1, *, ticket: SelectionTicket,
    focus_snapshot: GraphSnapshot, namespace: NamespaceId,
    reader: PersistentAssociationReader, now: float, audience: str,
    purpose: str, budget: CurrentAssociationBudgetV1,
    context_tags: tuple[str, ...] = (),
) -> CurrentAssociationCandidatesV1:
    """Read at most two hops from one currently focused, mood-bound source."""
    if (type(namespace) is not NamespaceId
            or type(reader) is not PersistentAssociationReader
            or type(budget) is not CurrentAssociationBudgetV1
            or (reader.repository.bot, reader.repository.persona) != namespace.as_tuple):
        raise TypeError("association needs a bounded reader in the cue namespace")
    focused = bind_current_c04_focus_v1(
        cue, ticket=ticket, focus_snapshot=focus_snapshot,
        namespace=namespace, now=now, audience=audience, purpose=purpose,
    )
    source = AtomKey.from_token(focused.reconstruction.source_ref)
    traversal = reader.traverse(
        source.owner.subject,
        ActivationPolicy(0.5, 0.25, budget.max_iterations,
                         budget.max_nodes, 1e-6),
        audience=audience, purpose=purpose, context_tags=context_tags,
        max_hops=budget.max_hops, max_edges=budget.max_edges,
        expected_epoch=focused.graph_epoch,
    )
    versions: dict[AtomKey, GraphVersion] = {
        version.key: version for version in focused.read_versions
    }
    for version in traversal.read_versions:
        previous = versions.get(version.key)
        if previous is not None and previous != version:
            raise ValueError("association and C04 source versions conflict")
        versions[version.key] = version
    allowed = set(traversal.source_refs)
    salience = sum(focused.reconstruction.subjective_weight) / 2.0
    ranked = sorted(
        (CurrentAssociationCandidateV1(ref, activation, activation * salience)
         for ref, activation in traversal.activation.activations
         if ref != source.token and ref in allowed and activation > 0),
        key=lambda item: (-item.mood_weighted_activation, item.source_ref),
    )
    selected = tuple(ranked[:budget.max_candidates])
    if budget.max_hops == 0:
        reason = "hop_budget_exhausted"
    elif traversal.coverage == "partial":
        reason = "traversal_budget_or_page_limit"
    elif len(ranked) > len(selected):
        reason = "candidate_limit"
    elif not selected:
        reason = "no_eligible_association"
    else:
        reason = traversal.activation.stop_reason
    return CurrentAssociationCandidatesV1(
        source.token, selected, traversal.edge_refs,
        tuple(versions[key] for key in sorted(versions, key=lambda key: key.token)),
        focused.graph_epoch, len(traversal.activation.visited_refs),
        len(traversal.edge_refs), traversal.activation.iterations, reason,
    )


__all__ = [
    "CurrentAssociationBudgetV1", "CurrentAssociationCandidateV1",
    "CurrentAssociationCandidatesV1", "prepare_current_association_candidates_v1",
]
