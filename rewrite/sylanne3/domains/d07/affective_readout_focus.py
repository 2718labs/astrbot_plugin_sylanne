"""A bounded D07 focus candidate from D04's distinct 24-axis readout.

This is a declared semantic intervention, not proof that W01 adopted the
numeric checkpoint or that an action was authorized. W01 must qualify the D04
readout and source closure at the same final graph fence as any focus write.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math

from ...graph_types import AtomKey, GraphVersion
from ..d04.product_readout import AffectiveReadoutCandidate
from . import AttentionPolicy, AttentionTicket, D07DomainProvider, FocusState


@dataclass(frozen=True, slots=True)
class D07AffectiveFocusCandidateV1:
    focus: FocusState
    adjusted_ticket: AttentionTicket
    readout_proof_digest: str
    checkpoint_version: GraphVersion
    feeling_version: GraphVersion
    source_ref: str
    axis_id: str
    conservative_salience: float
    status: str = "candidate_requires_w01_current_d04_adoption_and_focus_cas"


def project_focus_from_affective_readout(
    current: FocusState, tickets: tuple[AttentionTicket, ...],
    policy: AttentionPolicy, readout: AffectiveReadoutCandidate, *,
    axis_id: str, gain: float, now: float,
) -> D07AffectiveFocusCandidateV1:
    """Intervene on one declared axis while retaining every other ticket."""
    if (type(readout) is not AffectiveReadoutCandidate
            or readout.status != "hold_for_d11_product_admission"
            or type(current) is not FocusState
            or type(tickets) is not tuple
            or any(type(ticket) is not AttentionTicket for ticket in tickets)
            or type(policy) is not AttentionPolicy
            or type(axis_id) is not str or not axis_id
            or type(gain) not in (int, float) or not math.isfinite(gain)
            or not 0.0 <= gain <= 1.0
            or type(now) not in (int, float) or not math.isfinite(now)):
        raise ValueError("typed bounded D04-to-D07 focus inputs are required")
    if len({ticket.ticket_id for ticket in tickets}) != len(tickets):
        raise ValueError("focus inventory repeats a ticket")
    if (len(readout.tendencies) != 24
            or len({item.axis_id for item in readout.tendencies}) != 24):
        raise ValueError("D04 tendency inventory is incomplete")
    matching = [ticket for ticket in tickets if ticket.question_key == readout.tendencies[0].target_ref]
    if len(matching) != 1:
        raise ValueError("readout must target exactly one attention question")
    ticket = matching[0]
    if (ticket.source_refs.count(readout.source_ref) != 1
            or ticket.causal_root != readout.source_ref
            or current.persona_id != AtomKey.from_token(readout.checkpoint_ref).owner.persona):
        raise ValueError("focus ticket and D04 source identity differ")
    tendencies = [item for item in readout.tendencies if item.axis_id == axis_id]
    if (len(tendencies) != 1
            or any(item.source_ref != readout.source_ref
                   or item.target_ref != ticket.question_key
                   or not math.isfinite(item.lower) or not math.isfinite(item.upper)
                   or item.lower > item.upper for item in readout.tendencies)):
        raise ValueError("D04 tendency inventory is incomplete or crosses source/target")
    tendency = tendencies[0]
    magnitude = (0.0 if tendency.lower <= 0 <= tendency.upper
                 else min(abs(tendency.lower), abs(tendency.upper)))
    salience = min(1.0, gain * magnitude)
    adjusted = replace(ticket, emotional_salience=salience)
    projected = tuple(adjusted if item.ticket_id == ticket.ticket_id else item
                      for item in tickets)
    focus = D07DomainProvider().allocate_focus(current, projected, policy, now=now)
    checkpoint = AtomKey.from_token(readout.checkpoint_ref)
    feeling = AtomKey.from_token(readout.graph_state_ref)
    if (checkpoint.type_name != "d04.numeric_checkpoint.v1"
            or feeling.type_name != "d04.feeling_state.v1"
            or checkpoint.owner != feeling.owner):
        raise ValueError("D04 checkpoint and feeling graph identities differ")
    return D07AffectiveFocusCandidateV1(
        focus, adjusted, readout.proof_digest,
        GraphVersion(checkpoint, readout.checkpoint_revision),
        GraphVersion(feeling, readout.graph_state_revision), readout.source_ref,
        axis_id, salience,
    )


__all__ = ["D07AffectiveFocusCandidateV1", "project_focus_from_affective_readout"]
