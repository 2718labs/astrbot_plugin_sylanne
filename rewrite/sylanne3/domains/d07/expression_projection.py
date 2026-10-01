"""Current adopted judgment candidate for D09 qualified expression.

The caller must furnish a complete W01 fenced read and guard all returned
versions at final admission. A candidate is never expression or send authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from ..d06 import source_correction_head_key
from . import BeliefRevision, D07DomainProvider, EvidenceStatus, Stance


@dataclass(frozen=True, slots=True)
class D07JudgmentExpressionCandidateV1:
    belief_ref: str
    belief_revision: int
    question_key: str
    proposition: str
    stance: str
    uncertainty: str
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    audience: str
    purpose: str = "expression"
    schema: str = "d07.judgment_expression_candidate.v1"


def project_adopted_judgment_for_expression(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, belief_ref: str,
    audience: str,
) -> D07JudgmentExpressionCandidateV1 | None:
    """Expose a current belief's stance, never an unadopted hypothesis."""
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(audience) is not str or not audience or audience == "*"
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        return None
    try:
        key = AtomKey.from_token(belief_ref)
        if (key.type_name != "d07.belief_revision.v1" or key.owner.kind != "persona"
                or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
            return None
        atom = snapshot.get(key)
        if atom is None or not atom.valid or atom.revision < 1:
            return None
        spec = next(item for item in D07DomainProvider.type_specs()
                    if item.name == "d07.belief_revision.v1")
        spec.validator(atom.value)
        value = atom.value
        belief = BeliefRevision(
            value["belief_id"], value["question_key"], value["hypothesis_ref"],
            value["proposition"], Stance(value["stance"]),
            value["subjective_conviction"], EvidenceStatus(value["evidence_status"]),
            tuple(value["eligibility"]), tuple(value["source_refs"]),
            tuple(value["source_families"]), value["current"], value["historical"],
            value["replaced_by"], tuple(value["invalidation_refs"]),
            value["invalidation_kind"],
        )
        if (key.name != belief.belief_id or not belief.current
                or not belief.source_refs
                or not {"subjective_reaction", "fact_expression"}.intersection(belief.eligibility)
                or belief.stance is Stance.SUSPEND):
            return None
        versions = [GraphVersion(key, atom.revision)]
        records: dict[str, SourceRecord] = {}
        pending = list(belief.source_refs)
        while pending:
            ref = pending.pop()
            if ref in records:
                continue
            if len(records) >= 256:
                return None
            source = AtomKey.from_token(ref)
            if source != source_key(*namespace.as_tuple, source.owner.subject or ""):
                return None
            access = access_key(*namespace.as_tuple, source.owner.subject)
            head = source_correction_head_key(namespace, source.owner.subject)
            satom, aatom, hatom = snapshot.get(source), snapshot.get(access), snapshot.get(head)
            if (satom is None or aatom is None or hatom is None
                    or not satom.valid or not aatom.valid or hatom.valid
                    or satom.revision < 1 or aatom.revision < 1 or hatom.revision != 0):
                return None
            record = SourceRecord.from_dict(satom.value)
            validate_access(aatom.value)
            if (record.source_id != source.owner.subject
                    or record.assertion_status not in {"confirmed", "reported"}
                    or audience not in record.audiences or "expression" not in record.purposes
                    or aatom.value["source_id"] != record.source_id
                    or aatom.value["status"] != "active"
                    or audience not in aatom.value["audiences"]
                    or "expression" not in aatom.value["purposes"]):
                return None
            records[ref] = record
            versions.extend((GraphVersion(source, satom.revision),
                             GraphVersion(access, aatom.revision), GraphVersion(head, 0)))
            pending.extend(source_key(*namespace.as_tuple, parent).token
                           for parent in record.parent_source_ids)
        active: set[str] = set()
        settled: set[str] = set()

        def cyclic(ref: str) -> bool:
            if ref in active:
                return True
            if ref in settled:
                return False
            active.add(ref)
            if any(cyclic(source_key(*namespace.as_tuple, parent).token)
                   for parent in records[ref].parent_source_ids):
                return True
            active.remove(ref)
            settled.add(ref)
            return False

        if any(cyclic(ref) for ref in belief.source_refs):
            return None
        # The proposition remains a subjective judgment at every confidence.
        uncertainty = {
            EvidenceStatus.SUPPORTED: "subjective_supported_not_certain",
            EvidenceStatus.REFUTED: "subjective_refuted_not_certain",
            EvidenceStatus.CONFLICTED: "subjective_conflicted",
            EvidenceStatus.INSUFFICIENT: "subjective_insufficient",
        }[belief.evidence_status]
        return D07JudgmentExpressionCandidateV1(
            belief_ref, atom.revision, belief.question_key, belief.proposition,
            belief.stance.value, uncertainty, tuple(sorted(records)),
            tuple(dict.fromkeys(versions)), audience,
        )
    except (TypeError, ValueError, KeyError, AttributeError, StopIteration):
        return None


__all__ = ["D07JudgmentExpressionCandidateV1", "project_adopted_judgment_for_expression"]
