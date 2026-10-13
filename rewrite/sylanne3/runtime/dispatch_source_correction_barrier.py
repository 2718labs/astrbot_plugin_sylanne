"""Conservative source-correction screen for current dispatch graph reads.

This is a negative graph query inside the caller's held write transaction.
It does not certify source eligibility or grant a platform handoff.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d06 import source_correction_head_key, validate_source_correction_head
from ..graph_types import AtomKey
from ..memory_types import source_key
from ..runtime_contracts import NamespaceId, QueryEpoch


@dataclass(frozen=True)
class CorrectionBarrierReadV1:
    missing_sources: tuple[str, ...]

    @property
    def clear(self) -> bool:
        return not self.missing_sources


def read_source_correction_barrier(
    db, namespace: NamespaceId, query: QueryEpoch,
    source_refs: tuple[str, ...], *, dependent_ref: str,
    prepared_inventory=None,
) -> CorrectionBarrierReadV1:
    """HOLD a dependent with corrected or unqualified legacy source refs.

    A `source:*` label is not a D06 graph address. It cannot prove that a
    correction head is absent, so it remains an explicit missing source.
    """
    if not db.in_transaction:
        raise ValueError("correction barrier requires the graph transaction")
    if (type(namespace) is not NamespaceId or type(query) is not QueryEpoch
            or query.namespace != namespace or query.scope_ref != "all"):
        raise ValueError("correction barrier requires a full namespace query")
    row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (row[0] if row else 0) != query.revision:
        raise ValueError("correction barrier graph epoch changed")
    if type(source_refs) is not tuple or not source_refs or type(dependent_ref) is not str:
        raise ValueError("correction barrier needs dependent source refs")
    from .dispatch_current_projection import _bound_dispatch_projection_v3
    from .current_graph_full_read_v3 import (
        require_bound_graph_full_source_metadata_for_barrier_v3,require_bound_graph_full_atom_v3)
    fixed = _bound_dispatch_projection_v3(db,namespace,query,prepared_inventory=prepared_inventory,source_metadata=True)
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphProjectionV3,require_authority_source_metadata_v3
    authority=type(fixed)is AuthorityGraphProjectionV3
    missing = []
    for ref in source_refs:
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError):
            missing.append(f"legacy_source_ref_unqualified:{dependent_ref}")
            continue
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
            missing.append(f"cross_namespace_source_ref:{dependent_ref}")
            continue
        if (key.type_name != "memory.source" or key.name != "record"
                or key.owner.kind != "event" or not key.owner.subject
                or key != source_key(*namespace.as_tuple, key.owner.subject)):
            missing.append(f"noncanonical_source_ref:{dependent_ref}")
            continue
        if fixed is None:
            source_row = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=? AND type_name='memory.source'",
            (key.token, *namespace.as_tuple),
        ).fetchone()
        elif authority:
            source=require_authority_source_metadata_v3(db,namespace,key.token)
            source_row=(source.revision,int(source.valid))
        else:
            source = require_bound_graph_full_source_metadata_for_barrier_v3(db,namespace,key)
            source_row = (source.revision,int(source.valid))
        if (source_row is None or type(source_row[0]) is not int
                or source_row[0] < 1 or source_row[1] != 1):
            missing.append(f"current_source_unavailable:{dependent_ref}")
            continue
        head = source_correction_head_key(namespace, key.owner.subject)
        if fixed is None:
            head_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=? AND type_name=?",
            (head.token, *namespace.as_tuple, head.type_name),
        ).fetchone()
        elif authority:
            actual_head=fixed.get(head)
            head_row=None if actual_head.revision==0 else (actual_head.revision,actual_head.value,int(actual_head.valid))
        else:
            actual_head = require_bound_graph_full_atom_v3(db,namespace,query,head)
            head_row = None if actual_head is None else (actual_head.revision,actual_head.value,int(actual_head.valid))
        if head_row is None:
            continue
        try:
            if type(head_row[0]) is not int or head_row[0] < 1:
                raise ValueError("head revision is invalid")
            validate_source_correction_head(head, json.loads(head_row[1]) if fixed is None else head_row[1])
        except (TypeError, ValueError, json.JSONDecodeError):
            missing.append(f"correction_head_unavailable:{dependent_ref}")
            continue
        missing.append(f"source_pending_reevaluation:{dependent_ref}")
    return CorrectionBarrierReadV1(tuple(dict.fromkeys(missing)))


__all__ = ["CorrectionBarrierReadV1", "read_source_correction_barrier"]
