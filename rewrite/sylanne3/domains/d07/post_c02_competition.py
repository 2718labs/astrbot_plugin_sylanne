"""Pure two-ticket D07 choice after a settled C02 ingress.

The caller must authenticate both tickets and their source closures under one
current graph fence. This function only chooses focus; it cannot submit work
or authorize a model call.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey
from . import AttentionPolicy, AttentionTicket, D07DomainProvider, FocusState


@dataclass(frozen=True, slots=True)
class PostC02AttentionChoiceV2:
    focus: FocusState
    selected_ticket_id: str
    inbound_deferred: bool
    wake_at: float | None


def choose_post_c02_attention_v2(
    current: FocusState,
    inbound: AttentionTicket,
    current_primary: AttentionTicket | None,
    policy: AttentionPolicy,
    *,
    now: float,
) -> PostC02AttentionChoiceV2:
    """Choose between the new ingress and one certified current primary.

    Focus refs in this pure result are ticket IDs. The graph writer translates
    them into canonical atom refs while committing the new ticket and focus.
    """
    if (type(current) is not FocusState or type(inbound) is not AttentionTicket
            or type(policy) is not AttentionPolicy
            or type(now) not in (int, float) or not math.isfinite(now)):
        raise ValueError("current focus, inbound ticket, policy and time required")
    if current.auxiliary_ticket_refs:
        raise ValueError("two-ticket choice cannot discard queued auxiliaries")
    if current_primary is None:
        if current.primary_ticket_ref is not None:
            raise ValueError("current primary must be supplied")
    else:
        if type(current_primary) is not AttentionTicket:
            raise ValueError("current primary must be a ticket")
        ref = current.primary_ticket_ref
        if ref is None:
            raise ValueError("current focus has no primary")
        try:
            current_id = AtomKey.from_token(ref).name
        except (TypeError, ValueError):
            current_id = ref
        if (current_id != current_primary.ticket_id
                or current_primary.ticket_id == inbound.ticket_id):
            raise ValueError("current ticket identity differs")

    def runnable(ticket: AttentionTicket) -> bool:
        return (ticket.valid_until > now and ticket.eligible
                and ticket.resources_available and not ticket.cancel_refs
                and ticket.served_fraction < 1.0)

    if not runnable(inbound):
        raise ValueError("inbound ticket is not runnable")
    old = current_primary if current_primary is not None and runnable(current_primary) else None
    tickets = (inbound,) if old is None else (old, inbound)
    ranked = D07DomainProvider.rank_attention(tickets, policy, now=now)
    selected = ranked[0].ticket
    deferred = selected.ticket_id != inbound.ticket_id
    auxiliary = inbound.ticket_id if deferred else old.ticket_id if old is not None else None
    focus = FocusState(
        current.persona_id, current.focus_epoch + 1, selected.ticket_id,
        (auxiliary,) if auxiliary is not None else (),
        "deferred_for_current_primary" if deferred else "selected_by_bounded_attention",
    )
    wake_at = min(old.valid_until, inbound.valid_until) if deferred and old is not None else None
    return PostC02AttentionChoiceV2(focus, selected.ticket_id, deferred, wake_at)


__all__ = ("PostC02AttentionChoiceV2", "choose_post_c02_attention_v2")
