"""Graph-versioned reflection transitions; no task, budget, or Authority minting.

W01 must read the complete current graph, attest causal-root depth and actual
activity/cost receipts, then atomically adopt this candidate with a CAS guard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ...runtime_contracts import NamespaceId
from . import D07DomainProvider, ReflectionCheckpoint


SCHEMA = "d07.reflection_checkpoint.v1"


def reflection_checkpoint_key(namespace: NamespaceId, reflection_id: str) -> AtomKey:
    if type(namespace) is not NamespaceId or type(reflection_id) is not str or not reflection_id:
        raise ValueError("reflection identity is required")
    return AtomKey(Owner("persona", *namespace.as_tuple), SCHEMA, reflection_id)


@dataclass(frozen=True, slots=True)
class D07ReflectionTransitionCandidateV1:
    prior_version: GraphVersion
    graph_epoch: int
    causal_depth: int
    next_checkpoint: ReflectionCheckpoint
    proposed_write: GraphWrite
    status: str = "candidate_requires_w01_current_fence_depth_and_cost_adoption"


def compile_reflection_transition(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, reflection_id: str,
    resolved_slots: tuple[str, ...], discriminating_refs: tuple[str, ...],
    causal_depth: int,
) -> D07ReflectionTransitionCandidateV1 | None:
    """Repeated evidence cannot buy another reflection segment or reset depth."""
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(causal_depth) is not int or not 0 <= causal_depth < 2
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        return None
    try:
        key = reflection_checkpoint_key(namespace, reflection_id)
        atom = snapshot.get(key)
        if atom is None or not atom.valid or atom.revision < 1:
            return None
        spec = next(spec for spec in D07DomainProvider.type_specs() if spec.name == SCHEMA)
        spec.validator(atom.value)
        value = atom.value
        checkpoint = ReflectionCheckpoint(
            value["reflection_id"], value["meta_depth"], value["no_progress_count"],
            tuple(value["unresolved_slots"]), tuple(value["discriminating_refs"]),
            value["status"],
        )
        if checkpoint.reflection_id != key.name or checkpoint.meta_depth != causal_depth:
            return None
        advanced = D07DomainProvider.advance_reflection(
            checkpoint, resolved_slots=resolved_slots,
            discriminating_refs=discriminating_refs,
        )
        payload = asdict(advanced)
        payload["schema"] = SCHEMA
        payload["unresolved_slots"] = list(advanced.unresolved_slots)
        payload["discriminating_refs"] = list(advanced.discriminating_refs)
        write = GraphWrite(key, payload)
        return D07ReflectionTransitionCandidateV1(
            GraphVersion(key, atom.revision), snapshot.epochs[0].revision,
            causal_depth, advanced, write,
        )
    except (TypeError, ValueError, KeyError, StopIteration):
        return None


__all__ = ["D07ReflectionTransitionCandidateV1", "compile_reflection_transition",
           "reflection_checkpoint_key"]
