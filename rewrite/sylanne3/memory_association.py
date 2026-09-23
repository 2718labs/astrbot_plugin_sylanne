"""Bounded, deterministic activation over D06 personal associations."""

from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Mapping


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


__all__ = [
    "ActivationPolicy",
    "ActivationResult",
    "AssociationActivator",
    "AssociationEdge",
]
