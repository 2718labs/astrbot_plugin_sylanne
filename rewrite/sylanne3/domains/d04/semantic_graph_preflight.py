"""Replay D04 semantic 24D drives against a supplied graph read.

This is an unsigned preflight. W01 must enumerate the complete drive inventory,
authenticate the graph read and source heads, then adopt it under a write fence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...native_runtime.d04_semantic_drive_candidate import (
    D04SemanticDriveCandidate, D04SemanticDriveHold, D04SemanticMechanismShare,
    compile_d04_semantic_drive_candidate, verify_d04_semantic_drive_rows,
)
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d06 import source_correction_head_key
from .affect import _decode_appraisal
from .numeric_drive import SourcedNumericDrive, sourced_numeric_drive_write


@dataclass(frozen=True, slots=True)
class D04SemanticGraphPreflight:
    candidate: D04SemanticDriveCandidate
    read_versions: tuple[GraphVersion, ...]
    source_closure_digest: str
    graph_epoch: int
    status: str = "candidate_hold_for_w01_current_adoption"


def preflight_d04_semantic_drive_graph(
    *, snapshot: GraphSnapshot, namespace: NamespaceId,
    checkpoint_ref: str, checkpoint_revision: int,
    role_start: float, role_end: float,
    shares: tuple[D04SemanticMechanismShare, ...],
    drives: tuple[SourcedNumericDrive, ...],
    audience: tuple[str, ...], purpose: str,
) -> D04SemanticGraphPreflight:
    """Check exact appraisal/source/access rows, ancestry and 24D drive rows.

    `read_versions` is a minimum positive/negative read set for W01's final
    transaction. This function cannot prove a query was complete or that the
    supplied snapshot came from the active Authority graph.
    """
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(audience) is not tuple or not audience
            or any(type(item) is not str or not item for item in audience)
            or purpose not in {"context", "expression", "consolidation", "audit"}
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        raise D04SemanticDriveHold("semantic graph read is incomplete or malformed")
    candidate = compile_d04_semantic_drive_candidate(
        checkpoint_ref=checkpoint_ref, checkpoint_revision=checkpoint_revision,
        role_start=role_start, role_end=role_end, shares=shares,
    )
    verify_d04_semantic_drive_rows(candidate, drives)
    checkpoint_key = AtomKey.from_token(checkpoint_ref)
    checkpoint_atom = snapshot.get(checkpoint_key)
    if (checkpoint_atom is None or not checkpoint_atom.valid
            or checkpoint_atom.revision != checkpoint_revision):
        raise D04SemanticDriveHold("semantic drive checkpoint is absent or stale")
    versions = [GraphVersion(checkpoint_key, checkpoint_revision)]
    source_refs: set[str] = set()
    for share in shares:
        key = AtomKey.from_token(share.appraisal_ref)
        atom = snapshot.get(key)
        try:
            appraisal = _decode_appraisal(atom.value) if atom is not None else None
        except (TypeError, ValueError) as exc:
            raise D04SemanticDriveHold("appraisal graph value is invalid") from exc
        if (key.owner.subject != share.appraisal.event_ref
                or atom is None or not atom.valid
                or atom.revision != share.appraisal_revision
                or appraisal != share.appraisal):
            raise D04SemanticDriveHold("appraisal graph value differs from semantic share")
        versions.append(GraphVersion(key, atom.revision))
        source_refs.update(share.appraisal.source_refs)
        for facet in share.appraisal.meaning_facets:
            source_refs.update(facet.source_refs)

    seen: set[str] = set()
    source_records: dict[str, SourceRecord] = {}
    source_closure_rows = []
    pending = sorted(source_refs)
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= 256:
            raise D04SemanticDriveHold("semantic source ancestry exceeds bound")
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise D04SemanticDriveHold("semantic source ref is invalid") from exc
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise D04SemanticDriveHold("semantic source crosses namespace or type")
        source = snapshot.get(key)
        access_key_ = access_key(*namespace.as_tuple, key.owner.subject)
        access = snapshot.get(access_key_)
        head_key = source_correction_head_key(namespace, key.owner.subject)
        head = snapshot.get(head_key)
        if (source is None or not source.valid or source.revision < 1
                or access is None or not access.valid or access.revision < 1
                or head is None or head.valid or head.revision != 0):
            raise D04SemanticDriveHold("semantic source, access or correction head is unavailable")
        try:
            record = SourceRecord.from_dict(source.value)
            validate_access(access.value)
        except (TypeError, ValueError) as exc:
            raise D04SemanticDriveHold("semantic source or access graph value is invalid") from exc
        if (record.source_id != key.owner.subject
                or access.value["source_id"] != record.source_id
                or access.value["status"] != "active"
                or purpose not in record.purposes or purpose not in access.value["purposes"]
                or not set(audience).issubset(record.audiences)
                or not set(audience).issubset(access.value["audiences"])):
            raise D04SemanticDriveHold("semantic source ancestry is not authorized")
        for share in shares:
            if share.source_ref == ref and (share.source != record
                    or share.source_revision != source.revision
                    or share.access_revision != access.revision):
                raise D04SemanticDriveHold("semantic source head differs from supplied share")
        seen.add(ref)
        source_records[ref] = record
        source_closure_rows.extend((
            (key.token, source.revision, canonical_digest(source.value), True),
            (access_key_.token, access.revision, canonical_digest(access.value), True),
            (head_key.token, 0, canonical_digest(head.value), False),
        ))
        versions.extend((GraphVersion(key, source.revision),
                         GraphVersion(access_key_, access.revision),
                         GraphVersion(head_key, 0)))
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)
    active: set[str] = set()
    settled: set[str] = set()

    def has_cycle(ref: str) -> bool:
        if ref in active:
            return True
        if ref in settled:
            return False
        active.add(ref)
        if any(has_cycle(source_key(*namespace.as_tuple, parent).token)
               for parent in source_records[ref].parent_source_ids):
            return True
        active.remove(ref)
        settled.add(ref)
        return False

    if any(has_cycle(ref) for ref in source_refs):
        raise D04SemanticDriveHold("semantic source ancestry contains a cycle")
    source_reality = {
        "observed": ("observed", "external_observation"),
        "reported": ("reported", "external_report"),
        "authored": ("authored", "authored_content"),
        "internal": ("derived", "inference"),
        "simulated": ("simulated", "simulation"),
    }
    for share in shares:
        appraisal = share.appraisal
        claimed = (appraisal.source_family, appraisal.content_reality)
        actual = {source_reality[source_records[ref].source_kind]
                  for ref in appraisal.source_refs}
        if actual != {claimed}:
            raise D04SemanticDriveHold(
                "appraisal reality differs from committed source kind")
        if any(source_records[ref].recorded_at > appraisal.learned_at
               for ref in appraisal.source_refs):
            raise D04SemanticDriveHold(
                "appraisal predates committed source knowledge")
    if not {row.source_ref for row in candidate.source_vectors} <= seen:
        raise D04SemanticDriveHold("numeric source is absent from semantic closure")
    for drive in drives:
        write = sourced_numeric_drive_write(drive)
        atom = snapshot.get(write.key)
        if (atom is None or not atom.valid or atom.revision != drive.drive_version
                or atom.value != write.value):
            raise D04SemanticDriveHold("numeric drive graph row differs from semantic replay")
        versions.append(GraphVersion(write.key, atom.revision))
    return D04SemanticGraphPreflight(
        candidate, tuple(dict.fromkeys(versions)),
        canonical_digest(tuple(sorted(source_closure_rows))),
        snapshot.epochs[0].revision,
    )


__all__ = ["D04SemanticGraphPreflight", "preflight_d04_semantic_drive_graph"]
