"""Non-authorizing D04/D06 recollection checks over a supplied graph snapshot.

Only a coordinator holding the live Authority fence and graph read lock can
promote this candidate to a current read. No source literal is returned here.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_types import SourceRecord, source_key
from ...runtime_contracts import CommitReceipt, NamespaceId
from .affect import AffectProvider, AffectScheme, MoodField, RecollectionExperience
from .source_head import D04SourceHeadRead, _qualified_head


class RecollectionSnapshotUnavailable(ValueError):
    """The snapshot lacks a consistent recollection and accessible source."""


@dataclass(frozen=True)
class RecollectionExperienceSnapshotCandidate:
    experience: RecollectionExperience
    source_ref: str
    source_kind: str
    assertion_status: str
    provenance_eligibility: str
    mood: MoodField
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "snapshot_content_candidate"
    encoding_baseline_certified: bool = False


def inspect_recollection_experience_snapshot(
    snapshot: GraphSnapshot,
    *,
    namespace: NamespaceId,
    audience: tuple[str, ...],
    purpose: str,
    experience_ref: str,
    mood_key: AtomKey,
    receipt: CommitReceipt,
    scheme: AffectScheme,
) -> RecollectionExperienceSnapshotCandidate:
    """Check content only; receipt and snapshot origin require coordinator proof."""
    if not isinstance(snapshot, GraphSnapshot):
        raise TypeError("a GraphSnapshot is required; a read DTO is not authority")
    if not isinstance(namespace, NamespaceId):
        raise TypeError("namespace must be NamespaceId")
    if not isinstance(receipt, CommitReceipt) or not isinstance(scheme, AffectScheme):
        raise TypeError("a receipt claim and affect scheme are required")
    try:
        # This helper consumes namespace/audience/purpose only. Its fence flags
        # are deliberately false and never accepted from the caller.
        read = D04SourceHeadRead(
            snapshot, namespace, audience, purpose, None, False, False, False,
        )
        if (len(snapshot.epochs) != 1
                or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
                or any(NamespaceId.from_key(atom.key) != namespace
                       for atom in snapshot.atoms)):
            raise ValueError("snapshot namespace or read set is inconsistent")
        experience_key = AtomKey.from_token(experience_ref)
        if (experience_key.type_name != "d04.recollection_experience.v1"
                or experience_key.owner.kind != "activity"
                or NamespaceId.from_key(experience_key) != namespace
                or mood_key.type_name != "d04.mood_field.v1"
                or mood_key.owner.kind != "persona"
                or NamespaceId.from_key(mood_key) != namespace):
            raise ValueError("experience or mood key differs from D04 namespace")
        experience_atom = snapshot.get(experience_key)
        mood_atom = snapshot.get(mood_key)
        if (experience_atom is None or mood_atom is None
                or not experience_atom.valid or not mood_atom.valid
                or experience_atom.revision < 1 or mood_atom.revision < 1):
            raise ValueError("committed experience or mood is absent")
        specs = {
            spec.name: spec for spec in AffectProvider(active_scheme=scheme).type_specs()
        }
        experience = specs[experience_key.type_name].validator(experience_atom.value)
        mood = specs[mood_key.type_name].validator(mood_atom.value)
        if not isinstance(experience, RecollectionExperience) or not isinstance(mood, MoodField):
            raise ValueError("D04 experience or mood value is invalid")
        recollection_key = AtomKey.from_token(experience.recollection_ref)
        source = AtomKey.from_token(experience.memory_ref)
        if (recollection_key.type_name != "d06.recollection.v1"
                or recollection_key.owner != experience_key.owner
                or source != source_key(*namespace.as_tuple, source.owner.subject)
                or experience_key.name != experience.experience_id
                or experience.activity_id != experience_key.owner.subject
                or experience.memory_source_refs != (source.token,)
                or mood.mood_id != experience.mood_ref
                or mood.source_refs != experience.mood_source_refs
                or mood.coupling_version != experience.coupling_version
                or (mood.basis_version, mood.parameter_version, mood.coupling_version)
                != (scheme.scheme_version, scheme.parameter_version, scheme.coupling_version)):
            raise ValueError("C04 experience, source, or mood identity differs")
        recollection_atom = snapshot.get(recollection_key)
        source_atom = snapshot.get(source)
        if (recollection_atom is None or source_atom is None
                or not recollection_atom.valid or not source_atom.valid
                or recollection_atom.revision < 1 or source_atom.revision < 1):
            raise ValueError("C04 recollection or source is absent")
        recollection = recollection_atom.value
        if (recollection.get("recollection_id") != recollection_key.name
                or recollection.get("activity_id") != experience.activity_id
                or recollection.get("content_refs") != [source.owner.subject]
                or experience_key.token not in recollection.get("feeling_experience_refs", [])):
            raise ValueError("D06 recollection does not bind this source and D04 experience")
        versions = set(receipt.write_versions)
        if (receipt.status not in {"committed", "duplicate"}
                or receipt.activity_id != experience.activity_id
                or GraphVersion(experience_key, experience_atom.revision) not in versions
                or GraphVersion(recollection_key, recollection_atom.revision) not in versions
                or not receipt.ledger_refs or not receipt.outbox_refs):
            raise ValueError("C04 receipt claim differs from the snapshot")
        atoms = {atom.key: atom for atom in snapshot.atoms}
        for ref in {source.token, *mood.source_refs}:
            head, reason = _qualified_head(ref, atoms, read)
            if head is None:
                raise ValueError(f"source or mood basis is unavailable: {reason}")
        record = SourceRecord.from_dict(source_atom.value)
        if (record.source_id != source.owner.subject
                or recollection.get("provenance_eligibility") != [record.source_kind]):
            raise ValueError("D06 evidence status differs from the source")
    except (TypeError, KeyError, ValueError) as exc:
        raise RecollectionSnapshotUnavailable(str(exc)) from exc
    return RecollectionExperienceSnapshotCandidate(
        experience, source.token, record.source_kind, record.assertion_status,
        record.source_kind, mood, snapshot.versions, snapshot.epochs[0],
    )
