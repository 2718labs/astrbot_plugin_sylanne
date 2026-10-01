"""D07's source-qualified current focus read for a fenced graph caller.

The result is a candidate read set, never a focus, recall, or reply receipt.
The caller must obtain a complete current snapshot under W01's read fence and
adopt every returned version in its final graph transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from ..d06 import source_correction_head_key
from . import CurrentAttentionTicketReadV1, _read_focus_attention_ticket


@dataclass(frozen=True, slots=True)
class QualifiedAttentionReadV1:
    attention: CurrentAttentionTicketReadV1
    source_records: tuple[SourceRecord, ...]
    read_versions: tuple[GraphVersion, ...]
    audience: str
    purpose: str
    status: str = "candidate_requires_current_fence_and_final_admission"


def _read_qualified_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, now: float | None,
    audience: str, purpose: str,
) -> QualifiedAttentionReadV1 | None:
    """Reject incomplete, corrected, inaccessible, or disputed source closure.

    The selected ticket can reference several evidence roots. Every ancestor
    is checked once, so repeated retrievals never multiply evidence families.
    A correction head must be explicitly read at absent revision zero.
    """
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or (now is not None and
                (type(now) not in (int, float) or not math.isfinite(now)))
            or type(audience) is not str or not audience
            or type(purpose) is not str or not purpose):
        return None
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        return None
    attention = _read_focus_attention_ticket(snapshot, namespace, now=now)
    if attention is None:
        return None
    read_versions = [attention.focus_version, attention.ticket_version]
    records: dict[str, SourceRecord] = {}
    pending = list(attention.ticket.source_refs)
    while pending:
        ref = pending.pop()
        if ref in records:
            continue
        if len(records) >= 256:
            return None
        try:
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                return None
            source_atom = snapshot.get(key)
            access = access_key(*namespace.as_tuple, key.owner.subject)
            head = source_correction_head_key(namespace, key.owner.subject)
            access_atom, head_atom = snapshot.get(access), snapshot.get(head)
            if (source_atom is None or not source_atom.valid or source_atom.revision < 1
                    or access_atom is None or not access_atom.valid
                    or access_atom.revision < 1 or head_atom is None
                    or head_atom.valid or head_atom.revision != 0):
                return None
            record = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
            if (record.source_id != key.owner.subject
                    or record.assertion_status not in {"confirmed", "reported"}
                    or audience not in record.audiences
                    or purpose not in record.purposes
                    or access_atom.value["source_id"] != record.source_id
                    or access_atom.value["status"] != "active"
                    or audience not in access_atom.value["audiences"]
                    or purpose not in access_atom.value["purposes"]):
                return None
        except (KeyError, TypeError, ValueError):
            return None
        records[ref] = record
        read_versions.extend((GraphVersion(key, source_atom.revision),
                              GraphVersion(access, access_atom.revision),
                              GraphVersion(head, 0)))
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)
    # A source cannot be its own historical ancestor. A retry can refer to an
    # existing family, but a cycle has no valid original provenance root.
    active: set[str] = set()
    settled: set[str] = set()

    def has_cycle(ref: str) -> bool:
        if ref in active:
            return True
        if ref in settled:
            return False
        active.add(ref)
        record = records[ref]
        if any(has_cycle(source_key(*namespace.as_tuple, parent).token)
               for parent in record.parent_source_ids):
            return True
        active.remove(ref)
        settled.add(ref)
        return False

    if any(has_cycle(ref) for ref in attention.ticket.source_refs):
        return None
    return QualifiedAttentionReadV1(
        attention, tuple(records[ref] for ref in sorted(records)),
        tuple(dict.fromkeys(read_versions)), audience, purpose,
    )


def read_qualified_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, now: float,
    audience: str, purpose: str,
) -> QualifiedAttentionReadV1 | None:
    """Read live qualified focus under the caller's trusted current time."""
    return _read_qualified_focus_attention_ticket(
        snapshot, namespace, now=now, audience=audience, purpose=purpose)


def read_structural_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *,
    audience: str, purpose: str,
) -> QualifiedAttentionReadV1 | None:
    """Validate a focus/source closure without asserting time freshness."""
    return _read_qualified_focus_attention_ticket(
        snapshot, namespace, now=None, audience=audience, purpose=purpose)


__all__ = [
    "QualifiedAttentionReadV1", "read_qualified_focus_attention_ticket",
    "read_structural_focus_attention_ticket",
]
