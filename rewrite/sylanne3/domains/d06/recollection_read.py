"""Content checks for a D06 projection in one coordinator-supplied snapshot.

The caller must own the current graph read fence and recheck the access and
deletion barrier before returning a result. This module grants no read authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_types import SourceRecord, source_key
from ...runtime_contracts import CommitReceipt, NamespaceId
from ..d04.affect import AffectScheme, MoodField, RecollectionExperience
from ..d04.recollection_read import inspect_recollection_experience_snapshot
from . import (
    _RECOLLECTION_PROJECTION_TYPE, _validate_recollection_projection,
    source_correction_head_key,
)


class RecollectionProjectionUnavailable(ValueError):
    """The supplied snapshot cannot support this subjective projection."""


@dataclass(frozen=True, slots=True)
class RecollectionProjectionSnapshotCandidate:
    projection_ref: str
    recollection_ref: str
    experience_ref: str
    source_ref: str
    source_kind: str
    assertion_status: str
    provenance_eligibility: str
    experience: RecollectionExperience
    mood: MoodField
    subjective_weight: tuple[float, float]
    subjective_tone: tuple[float, float]
    duration_interval: tuple[float, float] | None
    details: tuple[dict, ...]
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "snapshot_content_candidate"
    read_status: str = "hold_uncertified_c02_baseline"
    encoding_baseline_certified: bool = False


def _require_uncorrected_lineage(
    snapshot: GraphSnapshot, namespace: NamespaceId, source_refs: tuple[str, ...],
) -> None:
    """A corrected ancestor invalidates the old subjective projection too."""
    pending = list(source_refs)
    visited: set[str] = set()
    while pending:
        token = pending.pop()
        key = AtomKey.from_token(token)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("D06 recollection source lineage differs")
        if key.token in visited:
            continue
        visited.add(key.token)
        atom = snapshot.get(key)
        if atom is None or not atom.valid or atom.revision < 1:
            raise ValueError("D06 recollection source lineage is incomplete")
        record = SourceRecord.from_dict(atom.value)
        if record.source_id != key.owner.subject:
            raise ValueError("D06 recollection source identity differs")
        head = snapshot.get(source_correction_head_key(namespace, record.source_id))
        if head is None:
            raise ValueError("D06 correction head absence proof is missing")
        if head.revision != 0 or head.valid:
            raise ValueError("D06 source lineage has a correction head; rebuild recollection")
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)


def inspect_recollection_projection_snapshot(
    snapshot: GraphSnapshot, *, namespace: NamespaceId,
    audience: tuple[str, ...], purpose: str, projection_ref: str,
    receipt: CommitReceipt, scheme: AffectScheme,
) -> RecollectionProjectionSnapshotCandidate:
    """Bind a committed sidecar to the current D04 feeling and source closure.

    The receipt is a claim supplied by W01. Its provenance, the snapshot's
    completeness, and the live Authority fence are W01 responsibilities.
    """
    if not isinstance(snapshot, GraphSnapshot):
        raise TypeError("a coordinator-supplied GraphSnapshot is required")
    if not isinstance(namespace, NamespaceId):
        raise TypeError("namespace must be NamespaceId")
    if not isinstance(receipt, CommitReceipt) or not isinstance(scheme, AffectScheme):
        raise TypeError("a C04 receipt and active affect scheme are required")
    try:
        key = AtomKey.from_token(projection_ref)
        if (key.type_name != _RECOLLECTION_PROJECTION_TYPE
                or key.owner.kind != "activity"
                or NamespaceId.from_key(key) != namespace):
            raise ValueError("D06 projection identity differs")
        atom = snapshot.get(key)
        if atom is None or not atom.valid or atom.revision < 1:
            raise ValueError("D06 projection is absent")
        value = atom.value
        _validate_recollection_projection(value)
        if (key.name != value["projection_id"]
                or key.owner.subject != value["activity_id"]
                or GraphVersion(key, atom.revision) not in receipt.write_versions):
            raise ValueError("C04 receipt does not own the current D06 projection")

        mood_key = AtomKey.from_token(value["mood_ref"])
        source_key = AtomKey.from_token(value["source_ref"])
        source_atom = snapshot.get(source_key)
        mood_atom = snapshot.get(mood_key)
        if (source_atom is None or mood_atom is None
                or source_atom.revision != value["source_revision"]
                or mood_atom.revision != value["mood_revision"]):
            raise ValueError("D06 projection source or mood version is stale")

        checked = inspect_recollection_experience_snapshot(
            snapshot, namespace=namespace, audience=audience, purpose=purpose,
            experience_ref=value["experience_ref"], mood_key=mood_key,
            receipt=receipt, scheme=scheme,
        )
        experience = checked.experience
        # W01 must include every lineage head in its fenced read. A missing
        # atom is not an absence proof; a corrected ancestor cannot keep
        # coloring a current recollection through a still-accessible child.
        _require_uncorrected_lineage(
            snapshot, namespace, (checked.source_ref, *checked.mood.source_refs),
        )
        recollection_key = AtomKey.from_token(value["recollection_ref"])
        recollection_atom = snapshot.get(recollection_key)
        if recollection_atom is None or not recollection_atom.valid:
            raise ValueError("D06 recollection is unavailable")
        recollection = recollection_atom.value
        choice_key = AtomKey(
            recollection_key.owner, "d07.selection_ticket.v1",
            recollection["selection_ref"],
        )
        choice = snapshot.get(choice_key)
        if (choice is None or not choice.valid or choice.revision < 1
                or GraphVersion(choice_key, choice.revision) not in receipt.write_versions
                or choice.value.get("activity_id") != value["activity_id"]
                or choice.value.get("ticket_id") != recollection["selection_ref"]
                or choice.value.get("candidate_set_id") != recollection["candidate_set_id"]
                or choice.value.get("focus_epoch") != recollection["focus_epoch"]
                or choice.value.get("selected_candidate_ids") is None
                or len(choice.value["selected_candidate_ids"]) != 1):
            raise ValueError("D07 committed selection does not support this recollection")
        interpretation_refs = tuple(recollection["now_interpretation_refs"])
        if not interpretation_refs:
            raise ValueError("D07 current interpretation is missing")
        for ref in interpretation_refs:
            interpretation_key = AtomKey.from_token(ref)
            interpretation = snapshot.get(interpretation_key)
            if (interpretation_key.type_name != "d07.current_interpretation.v1"
                    or interpretation_key.owner != recollection_key.owner
                    or interpretation is None or not interpretation.valid
                    or interpretation.revision < 1
                    or GraphVersion(interpretation_key, interpretation.revision)
                    not in receipt.write_versions
                    or interpretation.value.get("activity_id") != value["activity_id"]
                    or interpretation.value.get("interpretation_id") != interpretation_key.name
                    or interpretation.value.get("current") is not True
                    or value["source_ref"] not in interpretation.value.get("source_refs", ())):
                raise ValueError("D07 committed interpretation does not support this recollection")
        if (value["recollection_ref"] != experience.recollection_ref
                or value["source_ref"] != checked.source_ref
                or value["activity_id"] != experience.activity_id
                or value["coupling_version"] != experience.coupling_version
                or tuple(value["subjective_weight"]) != experience.salience_interval
                or tuple(value["subjective_tone"]) != experience.tone_interval
                or any(detail["source_ref"] not in (None, checked.source_ref)
                       or detail["interpretation_ref"] not in (None, *interpretation_refs)
                       for detail in value["details"])):
            raise ValueError("D06 projection differs from the current C04 experience")
    except (TypeError, KeyError, ValueError) as exc:
        raise RecollectionProjectionUnavailable(str(exc)) from exc

    return RecollectionProjectionSnapshotCandidate(
        key.token, experience.recollection_ref, value["experience_ref"],
        checked.source_ref, checked.source_kind, checked.assertion_status,
        checked.provenance_eligibility, experience, checked.mood,
        experience.salience_interval, experience.tone_interval,
        tuple(value["duration_interval"]) if value["duration_interval"] is not None else None,
        tuple(dict(detail) for detail in value["details"]),
        checked.read_versions, checked.epoch,
    )


__all__ = [
    "RecollectionProjectionSnapshotCandidate", "RecollectionProjectionUnavailable",
    "inspect_recollection_projection_snapshot",
]
