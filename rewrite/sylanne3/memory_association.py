"""Bounded, deterministic activation over D06 personal associations."""

from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Mapping

from .graph_types import AtomKey, GraphVersion, NamespaceEpoch
from .memory_repository import MemoryRepository
from .memory_types import source_key, validate_association


def _nonempty(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a nonempty string")


def _unit(value: object, label: str, *, positive: bool = False) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    value = float(value)
    lower_ok = value > 0 if positive else value >= 0
    if not lower_ok or value > 1:
        boundary = "(0, 1]" if positive else "[0, 1]"
        raise ValueError(f"{label} must be in {boundary}")
    return value


@dataclass(frozen=True)
class AssociationEdge:
    source_ref: str
    target_ref: str
    weight: float
    context_fit: float
    basis_ref: str

    def __post_init__(self) -> None:
        _nonempty(self.source_ref, "source_ref")
        _nonempty(self.target_ref, "target_ref")
        object.__setattr__(self, "weight", _unit(self.weight, "weight"))
        object.__setattr__(self, "context_fit", _unit(self.context_fit, "context_fit"))
        _nonempty(self.basis_ref, "basis_ref")


@dataclass(frozen=True)
class ActivationPolicy:
    leak: float
    spread: float
    max_iterations: int
    max_nodes: int
    min_activation: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "leak", _unit(self.leak, "leak", positive=True))
        object.__setattr__(self, "spread", _unit(self.spread, "spread"))
        if self.spread >= self.leak:
            raise ValueError("spread must be less than leak")
        for field, ceiling in (("max_iterations", 256), ("max_nodes", 4096)):
            value = getattr(self, field)
            if type(value) is not int or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise ValueError(f"{field} must be an integer from 1 to {ceiling}")
        object.__setattr__(self, "min_activation", _unit(self.min_activation, "min_activation", positive=True))


@dataclass(frozen=True)
class ActivationResult:
    activations: tuple[tuple[str, float], ...]
    visited_refs: tuple[str, ...]
    basis_refs: tuple[str, ...]
    iterations: int
    stop_reason: str


class AssociationActivator:
    """Apply the D06 bounded activation operator without mutating associations."""

    def __init__(self, policy: ActivationPolicy):
        if not isinstance(policy, ActivationPolicy):
            raise TypeError("policy must be ActivationPolicy")
        self.policy = policy

    def propagate(
        self,
        cues: Mapping[str, float],
        edges: tuple[AssociationEdge, ...],
        *,
        inhibition: Mapping[str, float] | None = None,
    ) -> ActivationResult:
        cue_values = self._values(cues, "cues")
        inhibition_values = self._values(inhibition or MappingProxyType({}), "inhibition")
        if type(edges) is not tuple or any(not isinstance(edge, AssociationEdge) for edge in edges):
            raise TypeError("edges must be a tuple of AssociationEdge")
        nodes = set(cue_values) | set(inhibition_values)
        for edge in edges:
            nodes.add(edge.source_ref)
            nodes.add(edge.target_ref)
        if len(nodes) > self.policy.max_nodes:
            raise ValueError("association graph exceeds max_nodes")

        outgoing_totals: dict[str, float] = {}
        for edge in edges:
            outgoing_totals[edge.source_ref] = (
                outgoing_totals.get(edge.source_ref, 0.0)
                + edge.weight * edge.context_fit
            )
        normalized: list[tuple[AssociationEdge, float]] = []
        for edge in edges:
            raw = edge.weight * edge.context_fit
            total = outgoing_totals[edge.source_ref]
            normalized.append((edge, raw / total if total > 1.0 else raw))

        ordered_nodes = tuple(sorted(nodes))
        activation = {node: 0.0 for node in ordered_nodes}
        stop_reason = "iteration_limit"
        iterations = 0
        for iterations in range(1, self.policy.max_iterations + 1):
            incoming = {node: 0.0 for node in ordered_nodes}
            for edge, coefficient in normalized:
                incoming[edge.target_ref] += coefficient * activation[edge.source_ref]
            next_activation = {}
            for node in ordered_nodes:
                value = (
                    (1.0 - self.policy.leak) * activation[node]
                    + cue_values.get(node, 0.0)
                    + self.policy.spread * incoming[node]
                    - inhibition_values.get(node, 0.0)
                )
                next_activation[node] = min(1.0, max(0.0, value))
            delta = sum(abs(next_activation[node] - activation[node]) for node in ordered_nodes)
            activation = next_activation
            if delta <= self.policy.min_activation:
                stop_reason = "converged"
                break

        return ActivationResult(
            tuple((node, activation[node]) for node in ordered_nodes if activation[node] > 0),
            ordered_nodes,
            tuple(dict.fromkeys(edge.basis_ref for edge in edges)),
            iterations,
            stop_reason,
        )

    @staticmethod
    def _values(values: Mapping[str, float], label: str) -> dict[str, float]:
        if not isinstance(values, Mapping):
            raise TypeError(f"{label} must be a mapping")
        result = {}
        for key, value in values.items():
            _nonempty(key, f"{label} key")
            result[key] = _unit(value, f"{label} value")
        return result


@dataclass(frozen=True)
class AssociationTraversal:
    activation: ActivationResult
    source_refs: tuple[str, ...]
    edge_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    coverage: str


@dataclass(frozen=True)
class AssociationDeletionRefs:
    association_refs: tuple[str, ...]
    epoch: NamespaceEpoch
    coverage: str


class PersistentAssociationReader:
    """Read a bounded local neighborhood; every followed edge is reauthorized."""

    def __init__(self, repository: MemoryRepository):
        if not isinstance(repository, MemoryRepository):
            raise TypeError("repository must be MemoryRepository")
        self.repository = repository

    def collect_deletion_refs(
        self, source_id: str, *, max_pages: int = 16,
    ) -> AssociationDeletionRefs:
        """Find source-linked edges, including target/basis links and invalid rows.

        A partial result cannot authorize a completed deletion closure.
        """
        if type(source_id) is not str or not source_id:
            raise ValueError("source_id must be nonempty")
        if type(max_pages) is not int or not 1 <= max_pages <= 16:
            raise ValueError("max_pages must be between 1 and 16")
        namespace = (self.repository.bot, self.repository.persona)
        key = source_key(*namespace, source_id)
        store = self.repository.store
        epoch = store.graph_epoch(*namespace)
        after = None
        refs: list[str] = []
        for _ in range(max_pages):
            page = store.graph_query(
                *namespace, type_names=("memory.association.v1",),
                after=after, limit=512, expected_epoch=epoch, include_invalid=True,
            )
            for atom in page.snapshot.atoms:
                validate_association(atom.value)
                value = atom.value
                if key.token in (value["source_ref"], value["target_ref"],
                                 *value["basis_source_refs"]):
                    refs.append(atom.key.token)
            after = page.next_after
            if after is None:
                break
        if store.graph_epoch(*namespace) != epoch:
            raise ValueError("association closure namespace changed")
        return AssociationDeletionRefs(
            tuple(refs), epoch, "complete" if after is None else "partial",
        )

    def traverse(
        self,
        source_id: str,
        policy: ActivationPolicy,
        *,
        audience: str,
        purpose: str,
        context_tags: tuple[str, ...] = (),
        max_hops: int = 2,
        max_edges: int = 128,
        expected_epoch: NamespaceEpoch | None = None,
    ) -> AssociationTraversal:
        if type(source_id) is not str or not source_id:
            raise ValueError("source_id must be nonempty")
        if not isinstance(policy, ActivationPolicy):
            raise TypeError("policy must be ActivationPolicy")
        if type(max_hops) is not int or not 0 <= max_hops <= 2:
            raise ValueError("max_hops must be between 0 and 2")
        if type(max_edges) is not int or not 1 <= max_edges <= 256:
            raise ValueError("max_edges must be between 1 and 256")
        if type(context_tags) is not tuple or len(context_tags) > 8 or any(
            type(tag) is not str or not tag for tag in context_tags
        ):
            raise ValueError("context_tags must be up to eight nonempty strings")
        store = self.repository.store
        namespace = (self.repository.bot, self.repository.persona)
        epoch = store.graph_epoch(*namespace)
        if expected_epoch is not None and expected_epoch != epoch:
            raise ValueError("association traversal namespace epoch is stale")
        authorized: dict[str, bool] = {}
        versions: dict[AtomKey, GraphVersion] = {}

        def available(item_id: str) -> bool:
            if item_id not in authorized:
                source, proof = self.repository.read_source_evidence(
                    item_id, audience=audience, purpose=purpose,
                )
                if proof.epochs != (epoch,):
                    raise ValueError("association traversal epoch changed during access check")
                authorized[item_id] = source is not None
                if source is not None:
                    for version in proof.versions:
                        versions[version.key] = version
            return authorized[item_id]

        if not available(source_id):
            raise PermissionError("association cue is unavailable")
        frontier = (source_id,)
        visited = {source_id}
        edges: list[AssociationEdge] = []
        edge_refs: list[str] = []
        partial = False
        for _ in range(max_hops):
            next_frontier: list[str] = []
            for current in frontier:
                if len(edges) >= max_edges:
                    partial = True
                    break
                page = store.graph_query(
                    *namespace, type_names=("memory.association.v1",),
                    owner_kind="event", subject=current,
                    limit=min(32, max_edges - len(edges)), expected_epoch=epoch,
                )
                if page.next_after is not None:
                    partial = True
                for atom in page.snapshot.atoms:
                    validate_association(atom.value)
                    value = atom.value
                    source_key_ref = AtomKey.from_token(value["source_ref"])
                    target_key_ref = AtomKey.from_token(value["target_ref"])
                    if (source_key_ref != source_key(*namespace, current)
                            or atom.key.owner.subject != current
                            or (target_key_ref.owner.bot, target_key_ref.owner.persona) != namespace):
                        raise ValueError("association graph edge does not match its directed owner")
                    fit = 1.0 if not value["context_tags"] else float(bool(
                        set(value["context_tags"]) & set(context_tags)
                    ))
                    if fit == 0:
                        continue
                    basis_keys = tuple(AtomKey.from_token(ref) for ref in value["basis_source_refs"])
                    target_id = target_key_ref.owner.subject
                    if target_id not in visited and len(visited) >= policy.max_nodes:
                        partial = True
                        continue
                    if not available(target_key_ref.owner.subject) or any(
                        not available(key.owner.subject) for key in basis_keys
                    ):
                        continue
                    edges.append(AssociationEdge(
                        source_key_ref.token, target_key_ref.token, value["weight"],
                        fit, atom.key.token,
                    ))
                    edge_refs.append(atom.key.token)
                    versions[atom.key] = GraphVersion(atom.key, atom.revision)
                    if target_id not in visited:
                        visited.add(target_id)
                        next_frontier.append(target_id)
            frontier = tuple(next_frontier)
            if not frontier:
                break
        if store.graph_epoch(*namespace) != epoch:
            raise ValueError("association traversal namespace changed")
        cue = source_key(*namespace, source_id).token
        activation = AssociationActivator(policy).propagate({cue: 1.0}, tuple(edges))
        return AssociationTraversal(
            activation,
            tuple(source_key(*namespace, item).token for item in sorted(visited)
                  if authorized.get(item, False)),
            tuple(edge_refs), tuple(versions.values()), epoch,
            "partial" if partial else "bounded_complete",
        )


__all__ = [
    "ActivationPolicy",
    "ActivationResult",
    "AssociationActivator",
    "AssociationEdge",
    "AssociationDeletionRefs",
    "AssociationTraversal",
    "PersistentAssociationReader",
]
