"""Pure D06 source-evidence projection over one W01-fenced graph read.

W01 owns candidate enumeration, namespace/query coverage, Authority access and
the final read fence. This function cannot certify those facts from graph
values; it only checks bounded source lineage content supplied in one epoch.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphPage, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, QueryEpoch
from . import source_correction_head_key


@dataclass(frozen=True, slots=True)
class CurrentMemoryQueryCoverageV1:
    status: str
    query_epoch: QueryEpoch
    next_after: str | None

    def __post_init__(self) -> None:
        if (self.status not in {"verified_complete", "partial"}
                or type(self.query_epoch) is not QueryEpoch
                or self.query_epoch.scope_ref != "memory.source"
                or (self.next_after is not None
                    and (type(self.next_after) is not str or not self.next_after))
                or (self.status == "verified_complete" and self.next_after is not None)):
            raise ValueError("D06 query coverage is invalid")


@dataclass(frozen=True, slots=True)
class CurrentMemoryEvidenceCandidateV1:
    source_ref: str
    source_revision: int
    source_kind: str
    assertion_status: str
    speaker_id: str
    occurred_at: float | None
    learned_at: float
    text: str
    provenance_root: str
    lineage_source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    audience: str
    purpose: str
    record: SourceRecord


@dataclass(frozen=True, slots=True)
class CurrentMemoryEvidencePageV1:
    status: str
    candidates: tuple[CurrentMemoryEvidenceCandidateV1, ...]
    missing_refs: tuple[str, ...]
    excluded_refs: tuple[str, ...]
    next_after: str | None
    page_complete: bool
    query_coverage: CurrentMemoryQueryCoverageV1
    graph_epoch: NamespaceEpoch
    access_epoch: int
    deletion_epoch: int
    read_versions: tuple[GraphVersion, ...]


def project_current_memory_evidence_page_v1(
    page: GraphPage, lineage_snapshot: GraphSnapshot, *,
    namespace: NamespaceId, graph_epoch: NamespaceEpoch,
    access_epoch: int, deletion_epoch: int,
    audience: str, purpose: str,
    query_coverage: CurrentMemoryQueryCoverageV1,
) -> CurrentMemoryEvidencePageV1:
    """Filter one source page; missing lineage always prevents complete output.

    `query_coverage.status='verified_complete'` is a W01 assertion under its current
    read fence, not something D06 can infer. W01 must read all ancestors and
    correction-head absence proofs in `lineage_snapshot` for every root.
    """
    if (type(page) is not GraphPage or type(lineage_snapshot) is not GraphSnapshot
            or type(namespace) is not NamespaceId
            or type(graph_epoch) is not NamespaceEpoch
            or (graph_epoch.bot, graph_epoch.persona) != namespace.as_tuple
            or page.snapshot.epochs != (graph_epoch,)
            or lineage_snapshot.epochs != (graph_epoch,)
            or type(access_epoch) is not int or access_epoch < 0
            or type(deletion_epoch) is not int or deletion_epoch < 0
            or type(audience) is not str or not audience or audience == "*"
            or type(purpose) is not str or not purpose or purpose == "*"
            or type(query_coverage) is not CurrentMemoryQueryCoverageV1
            or query_coverage.query_epoch != QueryEpoch(
                namespace, "memory.source", graph_epoch.revision)
            or query_coverage.next_after != (
                page.next_after.token if page.next_after is not None else None)):
        raise ValueError("D06 page needs one current, bounded, scoped read")
    roots = page.snapshot.atoms
    if len(roots) > 64 or len(lineage_snapshot.atoms) > 4096:
        raise ValueError("D06 evidence page exceeds read bounds")
    if (len({atom.key for atom in roots}) != len(roots)
            or len({atom.key for atom in lineage_snapshot.atoms})
            != len(lineage_snapshot.atoms)):
        raise ValueError("D06 evidence page repeats a graph key")
    if any(atom.key != source_key(*namespace.as_tuple, atom.key.owner.subject)
           or not atom.valid or atom.revision < 1 for atom in roots):
        raise ValueError("D06 page contains a noncurrent source candidate")
    allowed_types = {"memory.source", "memory.access",
                     source_correction_head_key(namespace, "probe").type_name}
    if any(NamespaceId.from_key(atom.key) != namespace
           or atom.key.type_name not in allowed_types
           for atom in lineage_snapshot.atoms):
        raise ValueError("D06 lineage snapshot crosses scope or type")
    if page.next_after is not None:
        if (not roots or page.next_after != roots[-1].key
                or any(left.key.token >= right.key.token
                       for left, right in zip(roots, roots[1:]))):
            raise ValueError("D06 page continuation differs from candidates")

    proof_atoms = {atom.key: atom for atom in lineage_snapshot.atoms}
    candidates: list[CurrentMemoryEvidenceCandidateV1] = []
    missing: set[str] = set()
    excluded: list[str] = []
    all_versions: dict[AtomKey, GraphVersion] = {}
    for root in roots:
        pending = [root.key.owner.subject]
        visited: set[str] = set()
        lineage: list[str] = []
        versions: dict[AtomKey, GraphVersion] = {}
        unavailable = False
        root_record: SourceRecord | None = None
        while pending:
            source_id = pending.pop()
            if source_id in visited:
                continue
            visited.add(source_id)
            if len(visited) > 256:
                raise ValueError("D06 evidence ancestry exceeds bound")
            source = source_key(*namespace.as_tuple, source_id)
            access = access_key(*namespace.as_tuple, source_id)
            head = source_correction_head_key(namespace, source_id)
            source_atom, access_atom, head_atom = (
                proof_atoms.get(item) for item in (source, access, head)
            )
            for key, atom in ((source, source_atom), (access, access_atom),
                              (head, head_atom)):
                if atom is None or (key != head and atom.revision == 0):
                    missing.add(key.token)
                if atom is not None:
                    versions[key] = GraphVersion(key, atom.revision)
            if source_atom is None or access_atom is None or head_atom is None:
                unavailable = True
                continue
            if (source_atom.revision < 1 or not source_atom.valid
                    or access_atom.revision < 1 or not access_atom.valid
                    or head_atom.revision != 0 or head_atom.valid):
                unavailable = True
                continue
            record = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
            if (record.source_id != source_id
                    or access_atom.value["source_id"] != source_id):
                raise ValueError("D06 evidence lineage identity differs")
            if source == root.key:
                if source_atom != root:
                    raise ValueError("D06 candidate and lineage source differ")
                root_record = record
            lineage.append(source.token)
            if (access_atom.value["status"] != "active"
                    or audience not in record.audiences
                    or audience not in access_atom.value["audiences"]
                    or purpose not in record.purposes
                    or purpose not in access_atom.value["purposes"]):
                unavailable = True
            pending.extend(record.parent_source_ids)
        all_versions.update(versions)
        if unavailable or root_record is None:
            excluded.append(root.key.token)
            continue
        candidates.append(CurrentMemoryEvidenceCandidateV1(
            root.key.token, root.revision, root_record.source_kind,
            root_record.assertion_status, root_record.speaker_id,
            root_record.occurred_at, root_record.recorded_at,
            root_record.text, root_record.provenance_root,
            tuple(lineage), tuple(versions[key] for key in sorted(
                versions, key=lambda item: item.token)), audience, purpose,
            root_record,
        ))
    complete = (query_coverage.status == "verified_complete"
                and page.next_after is None and not missing)
    return CurrentMemoryEvidencePageV1(
        "candidate_page_complete" if complete else "candidate_page_partial",
        tuple(candidates), tuple(sorted(missing)), tuple(excluded),
        page.next_after.token if page.next_after is not None else None,
        complete, query_coverage, graph_epoch, access_epoch, deletion_epoch,
        tuple(all_versions[key] for key in sorted(all_versions,
                                                  key=lambda item: item.token)),
    )


__all__ = ["CurrentMemoryEvidenceCandidateV1", "CurrentMemoryEvidencePageV1",
           "CurrentMemoryQueryCoverageV1", "project_current_memory_evidence_page_v1"]
