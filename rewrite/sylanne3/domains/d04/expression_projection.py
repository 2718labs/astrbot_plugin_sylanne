"""Narrow candidate self-description read for D09 qualified expression.

W01 must supply a complete current snapshot under its read fence and guard
every returned graph version at final admission. This function grants no use,
model-call, or send authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from ..d06 import source_correction_head_key
from .affect import SelfUnderstanding, _decode_feeling, _decode_understanding


@dataclass(frozen=True, slots=True)
class D04SelfExpressionCandidateV1:
    understanding_ref: str
    understanding_revision: int
    feeling_ref: str
    description_hypotheses: tuple[str, ...]
    reason_hypotheses: tuple[str, ...]
    unknown_parts: tuple[str, ...]
    qualifier: str
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    audience: str
    purpose: str = "expression"
    schema: str = "d04.self_expression_candidate.v1"


def project_self_understanding_for_expression(
    snapshot: GraphSnapshot, namespace: NamespaceId, *,
    understanding_ref: str, feeling_ref: str, audience: str,
) -> D04SelfExpressionCandidateV1 | None:
    """Fail closed on missing, superseded, corrected, or inaccessible basis."""
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(audience) is not str or not audience or audience == "*"
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        return None
    try:
        ukey, fkey = AtomKey.from_token(understanding_ref), AtomKey.from_token(feeling_ref)
        if (ukey.type_name != "d04.self_understanding.v1" or fkey.type_name != "d04.feeling_state.v1"
                or ukey.owner.kind != "persona" or fkey.owner.kind != "persona"
                or (ukey.owner.bot, ukey.owner.persona) != namespace.as_tuple
                or (fkey.owner.bot, fkey.owner.persona) != namespace.as_tuple):
            return None
        uatom, fatom = snapshot.get(ukey), snapshot.get(fkey)
        if (uatom is None or fatom is None or not uatom.valid or not fatom.valid
                or uatom.revision < 1 or fatom.revision < 1):
            return None
        understanding: SelfUnderstanding = _decode_understanding(uatom.value)
        feeling = _decode_feeling(fatom.value)
        if (uatom.key.name != understanding.understanding_id
                or understanding.feeling_ref != feeling.process_id
                or not understanding.reflection_source_refs
                or understanding.revision != uatom.revision
                or feeling.revision != fatom.revision):
            return None
        roots = tuple(dict.fromkeys(
            understanding.reflection_source_refs + feeling.historical_source_refs
        ))
        versions = [GraphVersion(ukey, uatom.revision), GraphVersion(fkey, fatom.revision)]
        sources: dict[str, SourceRecord] = {}
        pending = list(roots)
        while pending:
            ref = pending.pop()
            if ref in sources:
                continue
            if len(sources) >= 256:
                return None
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                return None
            access = access_key(*namespace.as_tuple, key.owner.subject)
            head = source_correction_head_key(namespace, key.owner.subject)
            satom, aatom, hatom = snapshot.get(key), snapshot.get(access), snapshot.get(head)
            if (satom is None or aatom is None or hatom is None
                    or not satom.valid or not aatom.valid or hatom.valid
                    or satom.revision < 1 or aatom.revision < 1 or hatom.revision != 0):
                return None
            record = SourceRecord.from_dict(satom.value)
            validate_access(aatom.value)
            if (record.source_id != key.owner.subject
                    or record.assertion_status not in {"confirmed", "reported"}
                    or audience not in record.audiences or "expression" not in record.purposes
                    or aatom.value["source_id"] != record.source_id
                    or aatom.value["status"] != "active"
                    or audience not in aatom.value["audiences"]
                    or "expression" not in aatom.value["purposes"]):
                return None
            sources[ref] = record
            versions.extend((GraphVersion(key, satom.revision),
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
                   for parent in sources[ref].parent_source_ids):
                return True
            active.remove(ref)
            settled.add(ref)
            return False

        if any(cyclic(ref) for ref in roots):
            return None
        return D04SelfExpressionCandidateV1(
            understanding_ref, uatom.revision, feeling_ref,
            understanding.description_hypotheses, understanding.reason_hypotheses,
            understanding.unknown_parts, "tentative_self_interpretation",
            tuple(sorted(sources)), tuple(dict.fromkeys(versions)), audience,
        )
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


__all__ = ["D04SelfExpressionCandidateV1", "project_self_understanding_for_expression"]
