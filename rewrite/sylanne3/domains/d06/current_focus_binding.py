"""Bind a D06 recollection candidate to D07's current qualified focus.

This adds guarded reads to a candidate. W01 still owns freshness, resource
issuance, and the atomic C04 commit; this function records no experience.
"""

from __future__ import annotations

from dataclasses import replace
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...runtime_contracts import NamespaceId
from ..d07.qualified_attention_read import read_qualified_focus_attention_ticket
from . import SelectionTicket
from .current_recollection_bridge import CurrentC04SourceCandidateV1


def bind_current_c04_focus_v1(
    candidate: CurrentC04SourceCandidateV1, *, ticket: SelectionTicket,
    focus_snapshot: GraphSnapshot, namespace: NamespaceId, now: float,
    audience: str, purpose: str,
) -> CurrentC04SourceCandidateV1:
    """Require the selected source in a live focus, then close the read set."""
    if (type(candidate) is not CurrentC04SourceCandidateV1
            or not isinstance(ticket, SelectionTicket)
            or type(focus_snapshot) is not GraphSnapshot
            or type(namespace) is not NamespaceId
            or type(now) not in (int, float) or not math.isfinite(now)
            or type(audience) is not str or not audience
            or type(purpose) is not str or not purpose):
        raise TypeError("typed C04 candidate, focus snapshot, and scope are required")
    if (candidate.status != "candidate_hold_w01_atomic_c04"
            or focus_snapshot.epochs != (candidate.graph_epoch,)
            or (candidate.graph_epoch.bot, candidate.graph_epoch.persona) != namespace.as_tuple
            or candidate.proposal.selection_ref != ticket.ticket_id
            or candidate.proposal.activity_id != ticket.activity_id
            or ticket.focus_epoch < 1):
        raise ValueError("C04 candidate and focus graph epoch or selection differ")
    focus = read_qualified_focus_attention_ticket(
        focus_snapshot, namespace, now=now, audience=audience, purpose=purpose,
    )
    selected = candidate.reconstruction.source_ref
    if (focus is None or focus.attention.focus.focus_epoch != ticket.focus_epoch
            or selected not in focus.attention.ticket.source_refs
            or not any(record.source_id == AtomKey.from_token(selected).owner.subject
                       for record in focus.source_records)):
        raise ValueError("C04 selected source lacks current qualified D07 focus")
    versions: dict[AtomKey, GraphVersion] = {
        version.key: version for version in candidate.read_versions
    }
    for version in focus.read_versions:
        old = versions.get(version.key)
        if old is not None and old != version:
            raise ValueError("C04 focus and source read revisions conflict")
        versions[version.key] = version
    return replace(
        candidate,
        read_versions=tuple(versions[key] for key in sorted(versions, key=lambda key: key.token)),
        focus_read_versions=focus.read_versions,
    )


__all__ = ["bind_current_c04_focus_v1"]
