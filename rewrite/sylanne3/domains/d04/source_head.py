"""Candidate D04 source heads derived from one fenced D06 graph read.

These heads are conditional inputs to block assembly. The caller must validate
the live Authority fence and current access/deletion barrier while holding the
graph read transaction; this pure function cannot establish either fact.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...native_runtime.d04_block_instances import (
    D04BlockIdentity, D04BlockInstance, D04SourceHead,
)
from ...runtime_contracts import FenceScope, NamespaceId, canonical_digest


@dataclass(frozen=True, slots=True)
class D04SourceHeadRead:
    snapshot: GraphSnapshot
    namespace: NamespaceId
    audience: tuple[str, ...]
    purpose: str
    fence: FenceScope | None
    current_fence_confirmed: bool
    current_barrier_confirmed: bool
    complete: bool

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, GraphSnapshot):
            raise TypeError("snapshot must be GraphSnapshot")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if (type(self.audience) is not tuple or not self.audience
                or any(type(item) is not str or not item or item == "*"
                       for item in self.audience)):
            raise ValueError("audience must enumerate recipients")
        if self.purpose not in {"context", "expression", "consolidation", "audit"}:
            raise ValueError("unknown D06 source purpose")
        if self.fence is not None and not isinstance(self.fence, FenceScope):
            raise TypeError("fence must be FenceScope")
        if any(type(value) is not bool for value in (
            self.current_fence_confirmed, self.current_barrier_confirmed, self.complete,
        )):
            raise TypeError("read confirmations must be booleans")


@dataclass(frozen=True, slots=True)
class D04SourceHeadCandidate:
    heads: dict[D04BlockIdentity, D04SourceHead]
    held: dict[D04BlockIdentity, str]
    schema: str = "d04.source-head.engineering-candidate.v1"


def _qualified_head(
    source_ref: str, atoms: dict[AtomKey, object], read: D04SourceHeadRead,
) -> tuple[D04SourceHead | None, str | None]:
    try:
        root = AtomKey.from_token(source_ref)
    except (TypeError, ValueError):
        return None, "source_unknown"
    if root != source_key(*read.namespace.as_tuple, root.owner.subject or ""):
        return None, "source_namespace_mismatch"

    pending = [root.owner.subject]
    visited: set[str] = set()
    sources: list[tuple[str, int]] = []
    accesses: list[tuple[str, int]] = []
    while pending:
        source_id = pending.pop()
        if source_id in visited:
            continue
        visited.add(source_id)
        source = source_key(*read.namespace.as_tuple, source_id)
        access = access_key(*read.namespace.as_tuple, source_id)
        source_atom, access_atom = atoms.get(source), atoms.get(access)
        if (source_atom is None or access_atom is None
                or source_atom.revision < 1 or access_atom.revision < 1
                or not source_atom.valid or not access_atom.valid):
            return None, "source_or_ancestor_unknown"
        try:
            record = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
        except (TypeError, ValueError):
            return None, "source_or_ancestor_unknown"
        if record.source_id != source_id or access_atom.value["source_id"] != source_id:
            return None, "source_or_ancestor_mismatch"
        if (access_atom.value["status"] != "active"
                or read.purpose not in record.purposes
                or read.purpose not in access_atom.value["purposes"]
                or not set(read.audience).issubset(record.audiences)
                or not set(read.audience).issubset(access_atom.value["audiences"])):
            return None, "source_or_ancestor_access_denied"
        sources.append((source.token, source_atom.revision))
        accesses.append((access.token, access_atom.revision))
        pending.extend(record.parent_source_ids)
    return D04SourceHead(
        "sha256:" + canonical_digest(sorted(sources)),
        "sha256:" + canonical_digest(sorted(accesses)), True,
    ), None


def derive_d04_source_heads(
    instances: tuple[D04BlockInstance, ...], read: D04SourceHeadRead,
) -> D04SourceHeadCandidate:
    """Qualify each block's source and all ancestors without sharing failures."""
    if any(not isinstance(item, D04BlockInstance) for item in instances):
        raise TypeError("instances must contain D04BlockInstance values")
    if len({item.identity for item in instances}) != len(instances):
        raise ValueError("duplicate D04 block identity")
    fence = read.fence
    epoch = read.snapshot.epochs
    current = (
        read.complete and read.current_fence_confirmed
        and read.current_barrier_confirmed and fence is not None
        and fence.operation == "read" and fence.namespace == read.namespace
        and len(epoch) == 1 and epoch[0] == fence.graph_epoch
    )
    atoms = {atom.key: atom for atom in read.snapshot.atoms}
    if len(atoms) != len(read.snapshot.atoms):
        current = False
    if any((key.owner.bot, key.owner.persona) != read.namespace.as_tuple for key in atoms):
        current = False
    heads: dict[D04BlockIdentity, D04SourceHead] = {}
    held: dict[D04BlockIdentity, str] = {}
    for instance in instances:
        identity = instance.identity
        if not current:
            held[identity] = "graph_read_unconfirmed"
            continue
        head, reason = _qualified_head(identity.source_ref, atoms, read)
        if head is None:
            held[identity] = reason or "source_unknown"
        else:
            heads[identity] = head
    return D04SourceHeadCandidate(heads, held)


__all__ = ["D04SourceHeadRead", "D04SourceHeadCandidate", "derive_d04_source_heads"]
