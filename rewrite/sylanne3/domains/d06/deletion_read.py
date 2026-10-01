"""Bounded graph read for D06's historical part of a C07 deletion closure.

This is an inspection candidate. D11 must still authorize the request, read
reverse dependencies and caches, install the deletion fence, and issue receipts.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...contracts import StaleRead
from ...graph_coordinator import UnavailableGuard
from ...graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ...memory_repository import MemoryRepository
from ...memory_types import SourceRecord, source_key
from . import ErasureRequest


_MISSING_AUTHORITY_FACETS = (
    "request_authorization", "access_deletion_epoch",
    "current_reverse_dependency_snapshot", "historical_graph_values",
    "historical_reverse_dependency_snapshot",
    "source_derived_cache_inventory_unavailable",
    "retrieval_index_inventory_unavailable",
    "process_local_cache_inventory_unavailable",
    "other_domain_history", "independent_deletion_intent",
)

_COVERED_D06_FACETS = (
    "current_source_parent_refs", "current_episode_refs", "current_trace_refs",
    "current_association_refs", "current_interpretation_refs",
    "current_recollection_refs",
    "memory_retriever_direct_graph_atom_path",
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
    covered_facets: tuple[str, ...]
    missing_facets: tuple[str, ...]
    status: str
    historical_read_versions: tuple[GraphVersion, ...] = ()
    access_epoch: int | None = None
    delete_epoch: int | None = None
    current_dependency_refs: tuple[str, ...] = ()
    storage_path_status: str = "unverified"
    pending_c02_sources: tuple[tuple[str, str], ...] = ()
    graph_cache_refs: tuple[str, ...] = ()
    graph_cache_historical_versions: tuple[GraphVersion, ...] = ()
    other_domain_historical_versions: tuple[GraphVersion, ...] = ()


def read_deletion_closure_candidate(
    repository: MemoryRepository, request: ErasureRequest, *,
    page_limit: int = 100, max_pages: int = 64,
) -> DeletionReadCandidate:
    """Scan known D06 references with one epoch across every observed page.

    GraphPage contains current values and an epoch, but no dependency edges or
    historical graph versions. This reads current D06 value references only;
    absent reverse-edge/history ports and Authority evidence keep it on HOLD.
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
            (), (*missing, "namespace_changed"), "partial_hold",
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
    present_source_ids = {
        atom.key.owner.subject for atom in atoms
        if atom.key.type_name == "memory.source" and atom.key.owner.kind == "event"
    }
    for parent_ids in source_parents.values():
        if any(parent not in present_source_ids for parent in parent_ids):
            missing.append("missing_source_parent")
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
    related_tokens = (affected_tokens | episode_tokens
                      | {key.token for key in associations}
                      | {key.token for key in interpretations})
    for atom in atoms:
        value = atom.value
        kind = atom.key.type_name
        try:
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
                if value["episode_ref"] in episode_tokens:
                    traces.add(atom.key)
            elif kind == "d06.recollection_projection.v1" and (
                value["source_ref"] in affected_tokens
                or value["recollection_ref"] in affected_tokens
                or value["experience_ref"] in affected_tokens
            ):
                recollections.add(atom.key)
            elif kind == "d06.recollection.v1" and (
                set(value["content_refs"]) | set(value["activity_basis_refs"])
                | set(value["now_interpretation_refs"])
                | set(value["feeling_experience_refs"])
                | set(value["self_understanding_refs"])
            ) & related_tokens:
                recollections.add(atom.key)
        except (TypeError, KeyError, ValueError):
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2",
                        "d06.recollection.v1", "d06.recollection_projection.v1"}:
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
        epoch, complete, after, _COVERED_D06_FACETS,
        tuple(dict.fromkeys(missing)),
        "hold" if complete else "partial_hold",
    )


def read_deletion_closure_candidate_from_coordinator(
    coordinator, authority, lease: object, request: ErasureRequest, *,
    page_limit: int = 128, max_pages: int = 16,
) -> DeletionReadCandidate:
    """Read D06 deletion references through the coordinator's host-minted lease.

    The W01 deletion snapshot supplies current reverse edges and bounded history.
    Current D06 value references are scanned through coordinator queries at the
    same graph epoch. Every round rechecks access/delete epochs and the graph
    epoch; an incomplete page budget or drift returns HOLD.
    """
    from ...runtime_contracts import AuthorityContext, NamespaceId

    if not isinstance(authority, AuthorityContext):
        raise TypeError("AuthorityContext is required")
    if not isinstance(request, ErasureRequest):
        raise TypeError("ErasureRequest is required")
    if type(page_limit) is not int or not 1 <= page_limit <= 512:
        raise ValueError("page_limit must be from 1 to 512")
    if type(max_pages) is not int or not 1 <= max_pages <= 32:
        raise ValueError("max_pages must be from 1 to 32")
    namespace = authority.namespace
    if not isinstance(namespace, NamespaceId):
        raise TypeError("authority namespace is required")
    roots = tuple(AtomKey.from_token(token) for token in request.target_refs)
    if (not roots or len(set(roots)) != len(roots)
            or any((key.owner.bot, key.owner.persona) != namespace.as_tuple
                   or key.type_name != "memory.source" or key.owner.kind != "event"
                   or key.name != "record" for key in roots)):
        raise ValueError("deletion read requires unique same-namespace source targets")

    missing = [
        "source_derived_cache_inventory_unavailable",
        "retrieval_index_inventory_unavailable",
        "process_local_cache_inventory_unavailable",
        "other_domain_history", "independent_deletion_intent",
        "request_authorization",
    ]
    try:
        first = coordinator.read_deletion_snapshot_candidate(
            authority, lease, roots, page_limit=page_limit, max_pages=max_pages,
        )
    except (StaleRead, UnavailableGuard):
        return DeletionReadCandidate(
            request.request_id, tuple(key.token for key in roots),
            (), (), (), (), (), (), (), None, False, None, (),
            (*missing, "deletion_snapshot_unavailable"), "partial_hold",
        )

    epoch = first.epoch
    access_delete_epochs = (first.access_epoch, first.delete_epoch)
    read_versions = {version.key: version for version in first.read_set}
    snapshots = [first]
    current_atoms = {atom.key: atom for atom in first.snapshot.atoms}
    current_edges = list(first.current_reverse_edges)
    if not first.complete:
        missing.append("unread_historical_pages")
    if (request.access_epoch, request.deletion_epoch) != access_delete_epochs:
        missing.append("request_epoch_mismatch")

    affected = set(roots)
    frontier = set(roots)
    while frontier and first.complete:
        known_dependents = {edge.dependent.key for edge in current_edges}
        new_keys = known_dependents - affected
        if not new_keys:
            break
        affected.update(new_keys)
        frontier = new_keys
        try:
            snapshot = coordinator.read_deletion_snapshot_candidate(
                authority, lease, tuple(sorted(frontier, key=lambda key: key.token)),
                page_limit=page_limit, max_pages=max_pages,
            )
        except (StaleRead, UnavailableGuard):
            missing.append("current_snapshot_drift")
            break
        snapshots.append(snapshot)
        if (snapshot.epoch != epoch
                or (snapshot.access_epoch, snapshot.delete_epoch) != access_delete_epochs
                or snapshot.pending_c02_sources != first.pending_c02_sources):
            missing.append("current_snapshot_drift")
            break
        for version in snapshot.read_set:
            prior = read_versions.get(version.key)
            if prior is not None and prior != version:
                missing.append("current_snapshot_drift")
                break
            read_versions[version.key] = version
        current_atoms.update((atom.key, atom) for atom in snapshot.snapshot.atoms)
        current_edges.extend(snapshot.current_reverse_edges)
        if not snapshot.complete:
            missing.append("unread_historical_pages")
            break

    # Namespace-wide D06 value scan is necessary for semantic references such
    # as SourceRecord.parent_source_ids, which are not graph dependency edges.
    from ...graph_types import GraphPage
    from . import D06DomainProvider

    d06_atoms = dict(current_atoms)
    query_complete = True
    d06_specs = tuple(spec for spec in D06DomainProvider.type_specs()
                      if spec.writer_domain == "d06")
    d06_type_names = {spec.name for spec in d06_specs}
    if any(key.type_name not in d06_type_names for key in affected):
        missing.append("unresolved_other_domain_current_dependency")
    groups = {}
    for spec in d06_specs:
        for owner_kind in spec.owner_kinds:
            groups.setdefault(owner_kind, set()).add(spec.name)
    try:
        for owner_kind, names in groups.items():
            after = None
            for _ in range(max_pages):
                page = coordinator.query(
                    authority, lease, type_names=tuple(sorted(names)),
                    owner_kind=owner_kind, after=after, limit=page_limit,
                    expected_epoch=epoch,
                )
                if not isinstance(page, GraphPage) or page.snapshot.epochs != (epoch,):
                    query_complete = False
                    missing.append("current_snapshot_drift")
                    break
                d06_atoms.update((atom.key, atom) for atom in page.snapshot.atoms)
                after = page.next_after
                if after is None:
                    break
            else:
                query_complete = False
                missing.append("unread_current_d06_pages")
            if after is not None and query_complete:
                query_complete = False
                missing.append("unread_current_d06_pages")
            if not query_complete:
                break
    except (StaleRead, UnavailableGuard):
        query_complete = False
        missing.append("current_snapshot_drift")

    # Recheck the dedicated snapshot after semantic scans. It binds access and
    # deletion epochs under Authority's same D06-only read lease.
    if query_complete:
        try:
            final = coordinator.read_deletion_snapshot_candidate(
                authority, lease, roots, page_limit=page_limit, max_pages=max_pages,
            )
            if (final.epoch != epoch
                    or (final.access_epoch, final.delete_epoch) != access_delete_epochs
                    or final.pending_c02_sources != first.pending_c02_sources
                    or not final.complete):
                missing.append("current_snapshot_drift")
        except (StaleRead, UnavailableGuard):
            missing.append("current_snapshot_drift")

    by_key = dict(d06_atoms)
    if any(key not in by_key or not by_key[key].valid for key in roots):
        missing.append("target_unavailable")
    source_parents = {}
    for atom in d06_atoms.values():
        if atom.key.type_name != "memory.source":
            continue
        try:
            record = SourceRecord.from_dict(atom.value)
            if atom.key.owner.subject != record.source_id:
                raise ValueError("source identity differs from graph key")
            source_parents[atom.key] = tuple(record.parent_source_ids)
        except (TypeError, ValueError, KeyError):
            missing.append("unreadable_source_payload")
    changed = True
    while changed:
        changed = False
        for key, parent_ids in source_parents.items():
            if key not in affected and any(source_key(*namespace.as_tuple, parent) in affected
                                           for parent in parent_ids):
                affected.add(key)
                changed = True

    affected_tokens = {key.token for key in affected}
    episodes, traces, associations, interpretations, recollections = set(), set(), set(), set(), set()
    for atom in d06_atoms.values():
        kind, value = atom.key.type_name, atom.value
        try:
            if kind == "memory.episode.v1" and set(value["source_refs"]) & affected_tokens:
                episodes.add(atom.key)
            elif kind == "memory.association.v1" and (
                {value["source_ref"], value["target_ref"], *value["basis_source_refs"]}
                & affected_tokens
            ):
                associations.add(atom.key)
            elif kind == "memory.interpretation" and any(
                source_key(*namespace.as_tuple, source_id).token in affected_tokens
                for source_id in value["source_ids"]
            ):
                interpretations.add(atom.key)
        except (TypeError, KeyError, ValueError):
            if kind in {"memory.episode.v1", "memory.association.v1", "memory.interpretation"}:
                missing.append("unreadable_memory_payload")
    current_dependency_keys = {
        edge.dependent.key for snapshot in snapshots
        for edge in snapshot.current_reverse_edges
    }
    for key in current_dependency_keys:
        if key.type_name == "memory.episode.v1":
            episodes.add(key)
        elif key.type_name in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
            traces.add(key)
        elif key.type_name == "memory.association.v1":
            associations.add(key)
        elif key.type_name == "memory.interpretation":
            interpretations.add(key)
        elif key.type_name in {"d06.recollection.v1", "d06.recollection_projection.v1"}:
            recollections.add(key)
    episode_tokens = {key.token for key in episodes}
    for atom in d06_atoms.values():
        value, kind = atom.value, atom.key.type_name
        try:
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
                if value["episode_ref"] in episode_tokens:
                    traces.add(atom.key)
                    interpretations.update(AtomKey.from_token(ref)
                                           for ref in value["interpretation_refs"]
                                           if ref in by_key)
            elif kind == "d06.recollection_projection.v1":
                refs = {value["source_ref"], value["recollection_ref"], value["experience_ref"]}
                if refs & (affected_tokens | episode_tokens | {key.token for key in recollections}):
                    recollections.add(atom.key)
            elif kind == "d06.recollection.v1":
                refs = set().union(*(set(value[name]) for name in (
                    "content_refs", "activity_basis_refs", "now_interpretation_refs",
                    "feeling_experience_refs", "self_understanding_refs",
                )))
                related = (affected_tokens | episode_tokens
                           | {key.token for key in traces}
                           | {key.token for key in associations}
                           | {key.token for key in interpretations})
                if refs & related:
                    recollections.add(atom.key)
        except (TypeError, KeyError, ValueError):
            if kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2",
                        "d06.recollection.v1", "d06.recollection_projection.v1"}:
                missing.append("unreadable_memory_payload")

    history_by_version = {
        (row.atom.key, row.atom.revision): row
        for snapshot in snapshots for row in snapshot.history_rows
    }
    history_edges = tuple(edge for snapshot in snapshots for edge in snapshot.history_edges)
    reverse_history = {}
    for edge in history_edges:
        reverse_history.setdefault(edge.dependency, set()).add(edge.dependent)
    history_seeds = {version for version in history_by_version
                     if version[0] in affected}
    history_closure = set(history_seeds)
    pending = list(history_seeds)
    while pending:
        version = pending.pop()
        for dependent in reverse_history.get(GraphVersion(*version), ()):
            pair = (dependent.key, dependent.revision)
            if pair not in history_closure:
                history_closure.add(pair)
                pending.append(pair)
        key, revision = version
        row = history_by_version.get(version)
        if (row is None or key.type_name not in {
                "memory.subjective_trace.v1", "memory.subjective_trace.v2"}):
            continue
        if row.atom.value.get("episode_ref") not in episode_tokens:
            continue
        try:
            for token in row.atom.value["interpretation_refs"]:
                try:
                    ref = AtomKey.from_token(token)
                except (TypeError, ValueError):
                    missing.append("unresolved_historical_interpretation_ref")
                    continue
                if ((ref.owner.bot, ref.owner.persona) != namespace.as_tuple
                        or ref.type_name != "memory.interpretation"):
                    missing.append("unresolved_historical_interpretation_ref")
                    continue
                referenced_versions = {
                    pair for pair in history_by_version if pair[0] == ref
                }
                current = d06_atoms.get(ref)
                if not referenced_versions and (current is None or not current.valid):
                    missing.append("unresolved_historical_interpretation_ref")
                for pair in referenced_versions - history_closure:
                    history_closure.add(pair)
                    pending.append(pair)
        except (TypeError, KeyError, ValueError):
            missing.append("unreadable_historical_payload")

    historical_versions = tuple(sorted(
        (GraphVersion(key, revision) for key, revision in history_closure),
        key=lambda item: (item.key.token, item.revision),
    ))
    # The fenced graph port also sees D13 cache atoms and history belonging to
    # other graph writers. These are exact graph dependency hits only: sidecar
    # indexes, process caches, and semantic references outside graph edges
    # still need their own owner inventories before deletion can proceed.
    graph_cache_refs = tuple(sorted(
        key.token for key in current_dependency_keys
        if key.type_name == "d13.compressed_turn_block.v2"
    ))
    graph_cache_historical_versions = tuple(
        version for version in historical_versions
        if version.key.type_name == "d13.compressed_turn_block.v2"
    )
    other_domain_historical_versions = tuple(
        version for version in historical_versions
        if version.key.type_name not in d06_type_names
    )
    historical_refs = {key.token for key, _ in history_closure}
    # Include historical D06 objects in the same typed candidate facets.
    for key, revision in history_closure:
        row = history_by_version.get((key, revision))
        if row is None:
            missing.append("unresolved_historical_dependency")
            continue
        if key.type_name == "memory.episode.v1":
            episodes.add(key)
        elif key.type_name in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
            traces.add(key)
        elif key.type_name == "memory.association.v1":
            associations.add(key)
        elif key.type_name == "memory.interpretation":
            interpretations.add(key)
        elif key.type_name in {"d06.recollection.v1", "d06.recollection_projection.v1"}:
            recollections.add(key)
        elif key.type_name not in d06_type_names:
            missing.append("unresolved_other_domain_historical_dependency")
        kind, value = key.type_name, row.atom.value
        try:
            if kind == "memory.source":
                record = SourceRecord.from_dict(value)
                if any(source_key(*namespace.as_tuple, parent).token in affected_tokens
                       for parent in record.parent_source_ids):
                    historical_refs.add(key.token)
            elif kind == "memory.episode.v1":
                if set(value["source_refs"]) & affected_tokens:
                    episodes.add(key)
            elif kind in {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}:
                if value["episode_ref"] in episode_tokens:
                    traces.add(key)
                    interpretations.update(
                        AtomKey.from_token(ref) for ref in value["interpretation_refs"]
                        if ref in by_key
                    )
            elif kind == "memory.association.v1":
                if ({value["source_ref"], value["target_ref"], *value["basis_source_refs"]}
                        & affected_tokens):
                    associations.add(key)
            elif kind == "memory.interpretation":
                if any(source_key(*namespace.as_tuple, source_id).token in affected_tokens
                       for source_id in value["source_ids"]):
                    interpretations.add(key)
            elif kind == "d06.recollection_projection.v1":
                refs = {value["source_ref"], value["recollection_ref"], value["experience_ref"]}
                if refs & (affected_tokens | episode_tokens | historical_refs):
                    recollections.add(key)
            elif kind == "d06.recollection.v1":
                refs = set().union(*(set(value[name]) for name in (
                    "content_refs", "activity_basis_refs", "now_interpretation_refs",
                    "feeling_experience_refs", "self_understanding_refs",
                )))
                if refs & (affected_tokens | episode_tokens | historical_refs):
                    recollections.add(key)
        except (TypeError, KeyError, ValueError):
            missing.append("unreadable_historical_payload")

    unique_missing = tuple(dict.fromkeys(missing))
    complete = first.complete and query_complete and not any(
        item in unique_missing for item in (
            "unread_historical_pages", "unread_current_d06_pages",
            "current_snapshot_drift", "unresolved_historical_interpretation_ref",
            "unreadable_historical_payload",
        )
    )
    source_descendants = {
        key for key in affected if key.type_name == "memory.source" and key not in roots
    }
    affected_source_refs = {key.token for key in (*roots, *source_descendants)}
    pending_c02_sources = tuple(
        (operation_id, source_ref)
        for operation_id, source_ref in first.pending_c02_sources
        if source_ref in affected_source_refs
    )
    covered = (
        "current_d06_values", "current_reverse_dependency_edges",
        "historical_graph_values", "historical_dependency_edges",
        "memory_retriever_direct_graph_atom_path",
        "pending_first_ingress_c02_inventory",
    )
    if complete:
        covered += ("graph_backed_cache_dependency_inventory",
                    "other_domain_graph_dependency_history_inventory")
    return DeletionReadCandidate(
        request.request_id, tuple(key.token for key in roots),
        tuple(sorted(key.token for key in source_descendants)),
        tuple(sorted(key.token for key in episodes)),
        tuple(sorted(key.token for key in traces)),
        tuple(sorted(key.token for key in associations)),
        tuple(sorted(key.token for key in interpretations)),
        tuple(sorted(key.token for key in recollections)),
        tuple(sorted(read_versions.values(), key=lambda item: item.key.token)),
        epoch, complete, None,
        covered,
        unique_missing, "hold" if complete else "partial_hold",
        historical_versions, *access_delete_epochs,
        tuple(sorted(key.token for key in current_dependency_keys)),
        "graph_atoms_and_pending_c02_candidates",
        pending_c02_sources,
        graph_cache_refs, graph_cache_historical_versions,
        other_domain_historical_versions,
    )
