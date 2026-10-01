"""Current, segmented body time and real settled-component effects."""
from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import GraphWrite
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
from . import BodyDomain, BodyPassiveRates, BodyProfile, BodyQuote, BodyReservation, BodyState
from ..d01.production_operations_v1 import require_locator_v1, stage_result_v1


@dataclass(frozen=True, slots=True)
class AdvanceCurrentBodyRequestV1:
    clock_mapping_ref: str
    target_role_cursor: float
    trigger_original_ref: str

    def __post_init__(self):
        require_locator_v1(self.clock_mapping_ref, "clock_mapping_ref")
        require_locator_v1(self.trigger_original_ref, "trigger_original_ref")
        if type(self.target_role_cursor) not in (float, int) or not math.isfinite(self.target_role_cursor) or self.target_role_cursor < 0:
            raise ValueError("target role cursor must be finite and nonnegative")


@dataclass(frozen=True, slots=True)
class ApplyCurrentBodyEffectRequestV1:
    component_terminal_ref: str
    body_quote_ref: str
    settlement_operation_ref: str
    effect_policy_ref: str

    def __post_init__(self):
        for name in ("component_terminal_ref", "body_quote_ref", "settlement_operation_ref", "effect_policy_ref"):
            require_locator_v1(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class PassiveBodySegmentV1:
    from_cursor: float
    to_cursor: float
    rates: BodyPassiveRates
    policy_original: ProductionOriginalRefV1


@dataclass(frozen=True, slots=True)
class CurrentBodyAdvanceInputsV1:
    profile: BodyProfile
    state: BodyState
    segments: tuple[PassiveBodySegmentV1, ...]
    clock_original: ProductionOriginalRefV1
    trigger_original: ProductionOriginalRefV1
    reservations: tuple[BodyReservation, ...]
    target_covered: bool
    continuation_ref: str | None = None


@dataclass(frozen=True, slots=True)
class CurrentBodyEffectInputsV1:
    state: BodyState
    reservation: BodyReservation
    body_quote: BodyQuote
    component_id: str
    component_receipt_ref: str
    settlement_ref: str
    work_kind: str
    fatigue_increase: float
    load_increase: float
    actual_cost: float
    terminal_original: ProductionOriginalRefV1
    policy_original: ProductionOriginalRefV1
    cost_originals: tuple[ProductionOriginalRefV1, ...]
    existing_settlement: bool = False


def compile_advance_current_body_v1(frame, request, inputs):
    if type(request) is not AdvanceCurrentBodyRequestV1 or type(inputs) is not CurrentBodyAdvanceInputsV1:
        raise TypeError("exact current body request and inputs required")
    state = inputs.state
    if state.profile_id != inputs.profile.profile_id or inputs.profile.namespace != frame.envelope.authority.namespace:
        raise ValueError("body profile/state namespace changed")
    if request.target_role_cursor < state.cursor:
        raise ValueError("body cursor cannot run backwards")
    unresolved = tuple(reservation.reservation_id for reservation in inputs.reservations
        if reservation.status in {"reserved", "pending_confirmation", "overrun"})
    if unresolved:
        return stage_result_v1(frame, "d02", "advance_body", request,
            provenance={"state": state, "unresolved_reservations": unresolved},
            coverage="waiting_for_original", missing=("settled_or_independently_cancelled_body_work",))
    if request.target_role_cursor == state.cursor:
        return stage_result_v1(frame, "d02", "advance_body", request,
            provenance={"state": state, "duplicate_interval": True, "clock": inputs.clock_original})
    if not inputs.segments:
        return stage_result_v1(frame, "d02", "advance_body", request,
            coverage="waiting_for_original", missing=("installed_passive_rate_history",))
    if len(inputs.segments) > frame.limits.max_role_segments:
        raise ValueError("body segment inventory exceeds installed limit")
    for segment in inputs.segments:
        if segment.from_cursor != state.cursor or segment.to_cursor > request.target_role_cursor:
            raise ValueError("passive body history has a gap, overlap or future segment")
        state = BodyDomain.advance_passive_body(state, segment.rates,
            from_cursor=segment.from_cursor, to_cursor=segment.to_cursor)
    # One graph CAS is one BodyState revision even when the mathematical
    # interval crossed several real parameter boundaries.
    from dataclasses import replace
    state = replace(state, version=inputs.state.version + 1)
    complete = inputs.target_covered and state.cursor == request.target_role_cursor
    return stage_result_v1(frame, "d02", "advance_body", request,
        writes=(BodyDomain.state_write(frame.envelope.authority.namespace, state),),
        provenance={"prior_state": inputs.state, "segments": inputs.segments,
            "clock": inputs.clock_original, "trigger": inputs.trigger_original,
            "processed_until": state.cursor, "requested_until": request.target_role_cursor},
        coverage="complete" if complete else "partial",
        missing=() if complete else ("remaining_passive_rate_segments",),
        continuation=None if complete else inputs.continuation_ref,
        proposal_schema="d02.proposal.v1", proposal_hash=BodyDomain().descriptor.request_schema_hash)


def compile_apply_current_body_effect_v1(frame, request, inputs):
    if type(request) is not ApplyCurrentBodyEffectRequestV1 or type(inputs) is not CurrentBodyEffectInputsV1:
        raise TypeError("exact current settled body effect request and inputs required")
    quote = inputs.body_quote
    component = next((item for item in quote.components if item.component_id == inputs.component_id), None)
    if (component is None or quote.profile_id != inputs.state.profile_id
            or inputs.reservation.quote_id != quote.quote_id or quote.work_kind != inputs.work_kind
            or inputs.component_receipt_ref != request.component_terminal_ref):
        raise ValueError("body effect component/quote/reservation differs")
    domain = BodyDomain()
    result = domain.settle_component(inputs.state, inputs.reservation, inputs.component_id,
        actual_cost=inputs.actual_cost, component_receipt=inputs.component_receipt_ref)
    result = domain.apply_settled_work_effect(result, work_kind=inputs.work_kind,
        fatigue_increase=inputs.fatigue_increase, load_increase=inputs.load_increase)
    if inputs.existing_settlement:
        if not result.duplicate:
            raise ValueError("body settlement original exists without consumed component")
        writes = ()
    elif result.duplicate:
        raise ValueError("body component consumed without its settlement original")
    else:
        from ...graph_types import AtomKey
        settlement_key = AtomKey.from_token(inputs.settlement_ref)
        if settlement_key.owner.subject != quote.activity_id or settlement_key.type_name != "d02.settlement.v1":
            raise ValueError("body settlement key differs from original activity")
        writes = (domain.state_write(frame.envelope.authority.namespace, result.state),
            domain.reservation_write(frame.envelope.authority.namespace, quote.activity_id, result.reservation),
            domain.settlement_write(frame.envelope.authority.namespace, quote.activity_id, settlement_key.name, result))
    return stage_result_v1(frame, "d02", "apply_body_effect", request, writes=writes,
        provenance={"settlement": result, "terminal": inputs.terminal_original,
            "effect_policy": inputs.policy_original, "body_quote": quote,
            "component_id": inputs.component_id, "component_receipt": inputs.component_receipt_ref},
        costs=inputs.cost_originals,
        contribution_keys=() if result.duplicate else ("d02-component:" + inputs.reservation.effect_id + ":" + inputs.component_id,),
        receiver_events=() if result.duplicate else (("d10", "body_effect_settled"),),
        proposal_schema="d02.proposal.v1", proposal_hash=domain.descriptor.request_schema_hash)


D02_PRODUCTION_WRITE_TYPES_V1 = frozenset({"d02.body_state.v1", "d02.reservation.v1", "d02.settlement.v1"})


def verify_d02_production_stage_v1(stage):
    if stage.domain != "d02" or stage.operation_kind not in {"advance_body", "apply_body_effect"}:
        raise ValueError("unregistered D02 current stage")
    for proposal in stage.proposals:
        allowed = {"d02.body_state.v1"} if stage.operation_kind == "advance_body" else D02_PRODUCTION_WRITE_TYPES_V1
        if any(write.key.type_name not in allowed for write in proposal.typed_writes):
            raise ValueError("D02 current operation contains another write type")
        BodyDomain().validate(proposal)
    return stage
