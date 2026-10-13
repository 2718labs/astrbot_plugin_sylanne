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


@dataclass(frozen=True, slots=True)
class QualifiedPreparedAttentionReadV3:
    attention: CurrentAttentionTicketReadV1
    source_metadata: tuple[object, ...]
    read_versions: tuple[GraphVersion, ...]
    audience: str
    purpose: str
    status: str = "candidate_requires_current_fence_and_final_admission"


def _read_qualified_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, now: float | None,
    audience: str, purpose: str, prepared_inventory=None, prepared_full_read=None, db=None,
) -> QualifiedAttentionReadV1 | QualifiedPreparedAttentionReadV3 | None:
    """Reject incomplete, corrected, inaccessible, or disputed source closure.

    The selected ticket can reference several evidence roots. Every ancestor
    is checked once, so repeated retrievals never multiply evidence families.
    A correction head must be explicitly read at absent revision zero.
    """
    if prepared_inventory is not None and prepared_full_read is not None:
        return None
    if prepared_full_read is not None:
        from ...runtime.current_graph_full_read_v3 import (PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3,
            require_bound_graph_full_read_proof_for_db_v3,CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3)
        if type(prepared_full_read) not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
            return None
        actual=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
            required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
        if actual is not prepared_full_read or snapshot is not actual.projection:
            return None
        actual.operation.retain(8192)
    if prepared_inventory is not None:
        from ...runtime.dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3, PreparedCurrentDispatchSuccessorInventoryV3
        if type(prepared_inventory) not in (PreparedCurrentDispatchInventoryV3,PreparedCurrentDispatchSuccessorInventoryV3):
            return None
        prepared_inventory.require_current(db,namespace,prepared_inventory.query,snapshot)
    if (prepared_inventory is None and prepared_full_read is None and type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
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
    attention = _read_focus_attention_ticket(snapshot, namespace, now=now,prepared_inventory=prepared_inventory,prepared_full_read=prepared_full_read,db=db)
    if attention is None:
        return None
    metadata_only=prepared_inventory is not None or prepared_full_read is not None
    if prepared_full_read is not None:
        from ...runtime.current_graph_full_read_v3 import require_bound_graph_full_source_metadata_v3
        source_reader=lambda key:require_bound_graph_full_source_metadata_v3(db,namespace,key)
        operation=prepared_full_read.operation
    elif prepared_inventory is not None:
        source_reader=lambda key:prepared_inventory.source_metadata(db,namespace,prepared_inventory.query,key,require_grant=False)
        operation=prepared_inventory.operation
    else:source_reader=snapshot.get;operation=None
    family=_qualify_source_family_values_v3(snapshot,namespace,attention.ticket.source_refs,audience=audience,purpose=purpose,
        source_reader=source_reader,metadata_only=metadata_only,operation=operation)
    if family is None:return None
    records,witnesses,versions=family
    result_type=QualifiedPreparedAttentionReadV3 if metadata_only else QualifiedAttentionReadV1
    sources=witnesses if metadata_only else tuple(records[ref] for ref in sorted(records))
    return result_type(attention,sources,tuple(dict.fromkeys((attention.focus_version,attention.ticket_version,*versions))),audience,purpose)


def _qualify_source_node_values_v3(namespace,ref,source_atom,access_atom,head_atom,*,audience,purpose,metadata_only):
    """D07 ticket evidence keeps its original assertion-status restriction."""
    record=_qualify_source_rights_values_v3(namespace,ref,source_atom,access_atom,head_atom,
        audience=audience,purpose=purpose,metadata_only=metadata_only)
    return record if record is not None and record.assertion_status in {'confirmed','reported'}else None


def _qualify_source_rights_values_v3(namespace,ref,source_atom,access_atom,head_atom,*,audience,purpose,metadata_only):
    """Original pure Source/access/correction rule, without a read grant."""
    try:
        key=AtomKey.from_token(ref)
        if key!=source_key(*namespace.as_tuple,key.owner.subject or ''):return None
        if (source_atom is None or not source_atom.valid or source_atom.revision<1
                or access_atom is None or not access_atom.valid or access_atom.revision<1
                or not metadata_only and head_atom is None
                or head_atom is not None and(head_atom.valid or head_atom.revision!=0)):
            return None
        if metadata_only:
            from ...runtime.dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
            record=_SourceMetadataRecordV3(source_atom.metadata)
        else:record=SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if (record.source_id!=key.owner.subject
                or audience not in record.audiences or purpose not in record.purposes
                or access_atom.value['source_id']!=record.source_id or access_atom.value['status']!='active'
                or audience not in access_atom.value['audiences']or purpose not in access_atom.value['purposes']):
            return None
        return record
    except (KeyError,TypeError,ValueError):return None


def _qualify_source_family_values_v3(snapshot,namespace,roots,*,audience,purpose,source_reader,metadata_only,operation):
    """Pure original ancestry/access/correction rules; this result grants no read capability."""
    read_versions=[];witnesses={}
    records: dict[str, SourceRecord] = {}
    pending = list(roots)
    while pending:
        ref = pending.pop()
        if ref in records:
            continue
        if len(records) >= 256:
            return None
        try:key=AtomKey.from_token(ref)
        except(TypeError,ValueError):return None
        source_atom=source_reader(key)
        access=access_key(*namespace.as_tuple,key.owner.subject)
        head=source_correction_head_key(namespace,key.owner.subject)
        access_atom,head_atom=snapshot.get(access),snapshot.get(head)
        if metadata_only:operation.retain(8192)
        record=_qualify_source_node_values_v3(namespace,ref,source_atom,access_atom,head_atom,
            audience=audience,purpose=purpose,metadata_only=metadata_only)
        if record is None:return None
        records[ref] = record;witnesses[ref]=source_atom
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

    if any(has_cycle(ref) for ref in roots):
        return None
    return records,tuple(witnesses[ref] for ref in sorted(records)),tuple(dict.fromkeys(read_versions))


def read_qualified_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *, now: float,
    audience: str, purpose: str, prepared_inventory=None, prepared_full_read=None, db=None,
) -> QualifiedAttentionReadV1 | QualifiedPreparedAttentionReadV3 | None:
    """Read live qualified focus under the caller's trusted current time."""
    return _read_qualified_focus_attention_ticket(
        snapshot, namespace, now=now, audience=audience, purpose=purpose,prepared_inventory=prepared_inventory,prepared_full_read=prepared_full_read,db=db)


def require_qualified_attention_source_family_v3(snapshot,namespace,*,attention,audience,purpose,prepared_full_read,db):
    """Recheck current metadata rights/ancestry; freshness remains the trusted live D07 read."""
    if type(attention) is not CurrentAttentionTicketReadV1:
        raise ValueError('actual current D07 ticket required for Source family qualification')
    result=_read_qualified_focus_attention_ticket(snapshot,namespace,now=None,audience=audience,purpose=purpose,
        prepared_full_read=prepared_full_read,db=db)
    if type(result) is not QualifiedPreparedAttentionReadV3 or result.attention!=attention:
        raise ValueError('current FULL Source family, access, correction or D07 versions differ')
    return result


def read_prefinal_qualified_attention_source_family_v3(prefinal_inventory,*,audience,purpose,meter=None,roots=None):
    """Only an issued same-Work prefinal Source inventory may use the pure closure."""
    from ...runtime.current_graph_full_read_v3 import _PrefinalSourceInventoryV3
    from . import _qualify_focus_attention_values_v3
    if type(prefinal_inventory) is not _PrefinalSourceInventoryV3:
        raise ValueError('actual private prefinal Source inventory required')
    prefinal_inventory.require_current(meter=meter)
    source_reader=lambda key:prefinal_inventory.source_metadata(prefinal_inventory.db,prefinal_inventory.namespace,
        prefinal_inventory.query,key,require_grant=False,meter=meter)
    snapshot=prefinal_inventory.projection;namespace=prefinal_inventory.namespace
    attention=_qualify_focus_attention_values_v3(snapshot,namespace,now=None,source_reader=source_reader)
    if attention is None:raise ValueError('prefinal D07 focus/ticket/Source versions differ')
    selected=attention.ticket.source_refs if roots is None else roots
    family=_qualify_source_family_values_v3(snapshot,namespace,selected,audience=audience,purpose=purpose,
        source_reader=source_reader,metadata_only=True,operation=prefinal_inventory.operation)
    if family is None:raise ValueError('prefinal Source ancestry/access/correction/purpose/audience differs')
    records,witnesses,versions=family
    return QualifiedPreparedAttentionReadV3(attention,witnesses,
        tuple(dict.fromkeys((attention.focus_version,attention.ticket_version,*versions))),audience,purpose)


def read_structural_focus_attention_ticket(
    snapshot: GraphSnapshot, namespace: NamespaceId, *,
    audience: str, purpose: str,
) -> QualifiedAttentionReadV1 | None:
    """Validate a focus/source closure without asserting time freshness."""
    return _read_qualified_focus_attention_ticket(
        snapshot, namespace, now=None, audience=audience, purpose=purpose)


__all__ = [
    "QualifiedAttentionReadV1", "read_qualified_focus_attention_ticket",
    "read_structural_focus_attention_ticket", "require_qualified_attention_source_family_v3",
]
