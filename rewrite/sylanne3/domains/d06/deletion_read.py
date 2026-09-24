"""Bounded graph read for D06's historical part of a C07 deletion closure.

This is an inspection candidate. D11 must still authorize the request, read
reverse dependencies and caches, install the deletion fence, and issue receipts.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...contracts import StaleRead
from ...graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ...memory_repository import MemoryRepository
from ...memory_types import SourceRecord, source_key
from . import ErasureRequest


_MISSING_AUTHORITY_FACETS = (
    "request_authorization", "access_deletion_epoch", "current_dependency_index",
    "graph_cache_index", "other_domain_history", "independent_deletion_intent",
)


@dataclass(frozen=True)
class DeletionReadCandidate:
    request_id: str
    root_refs: tuple[str, ...]
    source_descendant_refs: tuple[str, ...]
    episode_refs: tuple[str, ...]
    trace_refs: tuple[str, ...]
    association_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    recollection_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch | None
    scan_complete: bool
    next_after: AtomKey | None
    missing_facets: tuple[str, ...]
    status: str


def read_deletion_closure_candidate(
    repository: MemoryRepository, request: ErasureRequest, *,
    page_limit: int = 100, max_pages: int = 64,
) -> DeletionReadCandidate:
    """Scan known D06 references with one epoch across every observed page.

    Full pagination means only the listed D06 value fields were covered. The
    current dependency DAG, caches, other domains, and deletion policy cannot
    be proven from GraphPage and therefore always keep this result on HOLD.
    """
    if not isinstance(repository, MemoryRepository) or not isinstance(request, ErasureRequest):
        raise TypeError("MemoryRepository and ErasureRequest are required")
    if type(page_limit) is not int or not 1 <= page_limit <= 512:
        raise ValueError("page_limit must be from 1 to 512")
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be positive")
    namespace = (repository.bot, repository.persona)
    roots = []
    for token in request.target_refs:
        key = AtomKey.from_token(token)
        if ((key.owner.bot, key.owner.persona) != namespace
                or key.type_name != "memory.source" or key.owner.kind != "event"
                or key.name != "record"):
            raise ValueError("deletion read requires same-namespace source targets")
        roots.append(key)
    if not roots or len(set(roots)) != len(roots):
        raise ValueError("deletion read requires unique source targets")

    epoch = None
    after = None
    atoms = []
    missing = list(_MISSING_AUTHORITY_FACETS)
    try:
        for _ in range(max_pages):
            page = repository.store.graph_query(
                *namespace, after=after, limit=page_limit,
                expected_epoch=epoch, include_invalid=True,
            )
            if epoch is None:
                epoch = page.snapshot.epochs[0]
            atoms.extend(page.snapshot.atoms)
            after = page.next_after
            if after is None:
                break
        if epoch is not None and repository.store.graph_epoch(*namespace) != epoch:
            raise StaleRead("deletion scan namespace changed")
    except StaleRead:
        return DeletionReadCandidate(
            request.request_id, tuple(key.token for key in roots),
            (), (), (), (), (), (), (), epoch, False, after,
            (*missing, "namespace_changed"), "partial_hold",
        )
    complete = after is None
    if not complete:
        missing.append("unread_pages")
    by_key = {atom.key: atom for atom in atoms}
    if any(key not in by_key or not by_key[key].valid for key in roots):
        missing.append("target_unavailable")

    source_parents = {}
    for atom in atoms:
        if atom.key.type_name != "memory.source":
            continue
        try:
            record = SourceRecord.from_dict(atom.value)
            if atom.key.owner.subject != record.source_id:
                raise ValueError("source identity differs from graph key")
            source_parents[atom.key] = tuple(record.parent_source_ids)
        except (TypeError, ValueError, KeyError):
            missing.append("unreadable_source_payload")
    affected = set(roots)
    changed = True
    while changed:
        changed = False
        for key, parent_ids in source_parents.items():
            if key not in affected and any(
                source_key(*namespace, parent) in affected for parent in parent_ids
            ):
                affected.add(key)
                changed = True

    affected_tokens = {key.token for key in affected}
    episodes = set()
    traces = set()
    associations = set()
    interpretations = set()
    recollections = set()
    for atom in atoms:
        value = atom.value
        kind = atom.key.type_name
        try:
            if kind == "memory.episode.v1" and set(value["source_refs"]) & affected_tokens:
                episodes.add(atom.key)
            elif kind == "memory.association.v1" and (
                {value["source_ref"], value["target_ref"], *value["basis_source_refs"]}
                & affected_tokens
            ):
                associations.add(atom.key)
            elif kind == "memory.interpretation" and any(
                source_key(*namespace, source_id).token in affected_tokens
                for source_id in value["source_ids"]
            ):
                interpretations.add(atom.key)
        except (TypeError, KeyError, ValueError):
            if kind in {"memory.episode.v1", "memory.association.v1", "memory.interpretation"}:
                missing.append("unreadable_memory_payload")
    episode_tokens = {key.token for key in episodes}
    related_tokens = affected_tokens | episode_tokens | {key.token for key in associations}
    for atom in atoms:
        value = atom.value
        kind = atom.key.type_name
        try:
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
                if value["episode_ref"] in episode_tokens:
                    traces.add(atom.key)
            elif kind == "d06.recollection.v1" and (
                set(value["content_refs"]) | set(value["activity_basis_refs"])
            ) & related_tokens:
                recollections.add(atom.key)
        except (TypeError, KeyError, ValueError):
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2",
                        "d06.recollection.v1"}:
                missing.append("unreadable_memory_payload")
    return DeletionReadCandidate(
        request.request_id, tuple(key.token for key in roots),
        tuple(sorted(key.token for key in affected.difference(roots))),
        tuple(sorted(key.token for key in episodes)),
        tuple(sorted(key.token for key in traces)),
        tuple(sorted(key.token for key in associations)),
        tuple(sorted(key.token for key in interpretations)),
        tuple(sorted(key.token for key in recollections)),
        tuple(GraphVersion(atom.key, atom.revision) for atom in atoms),
        epoch, complete, after, tuple(dict.fromkeys(missing)),
        "hold" if complete else "partial_hold",
    )
