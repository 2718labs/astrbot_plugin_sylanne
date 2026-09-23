"""Bounded D08-to-D09 expression planning, without platform delivery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...runtime_contracts import CheckReceipt
from .execution import (
    ActionIntent,
    CommunicationGrantRequest,
    CommunicationIntentGrant,
    QualificationDecision,
    RequiredCheckRegistry,
)

if TYPE_CHECKING:
    from ..d09 import ExpressionClaim, SegmentCandidate, StagingResult


@dataclass(frozen=True)
class CommunicationPlanResult:
    status: str
    decision: QualificationDecision | None
    grant: CommunicationIntentGrant | None
    staging: StagingResult | None
    missing: tuple[str, ...]


def prepare_expression_plan(
    registry: RequiredCheckRegistry,
    intent: ActionIntent,
    receipts: tuple[CheckReceipt, ...],
    request: CommunicationGrantRequest,
    claims: tuple[ExpressionClaim, ...],
    candidates: tuple[SegmentCandidate, ...],
    *,
    scene_ref: str,
    conversation_epoch: int,
    cancellation_epoch: int,
    now: float,
) -> CommunicationPlanResult:
    """Qualify an action, freeze its finite grant, then verify expression.

    The result is a preparation candidate only. D11 must revalidate every
    required check and issue a separate admission for each segment.
    """

    from ..d09 import D09ExpressionProvider

    if not isinstance(registry, RequiredCheckRegistry):
        raise TypeError("registry must be RequiredCheckRegistry")
    if not isinstance(request, CommunicationGrantRequest):
        raise TypeError("request must be CommunicationGrantRequest")
    if type(cancellation_epoch) is not int or cancellation_epoch < 0:
        raise ValueError("cancellation_epoch must be a nonnegative exact integer")
    if request.cancellation_epoch != cancellation_epoch:
        return CommunicationPlanResult("stale", None, None, None, ("cancellation_epoch",))

    decision = registry.qualify(intent, receipts, now=now)
    if decision.status != "qualified":
        missing = (
            decision.missing_check_kinds + decision.incomplete_check_kinds
            + decision.stale_check_kinds + decision.failed_check_kinds
        )
        return CommunicationPlanResult(decision.status, decision, None, None, missing)

    grant = registry.freeze_communication_grant(intent, decision, request, now=now)
    expression = D09ExpressionProvider()
    blueprint_result = expression.prepare_blueprint(
        grant, scene_ref, conversation_epoch, claims, now=now,
    )
    if blueprint_result.blueprint is None:
        return CommunicationPlanResult(
            blueprint_result.status, decision, grant, None, blueprint_result.missing,
        )
    staging = expression.verify_and_stage(blueprint_result.blueprint, candidates)
    return CommunicationPlanResult(
        staging.status, decision, grant, staging,
        staging.failures + staging.missing_slots,
    )
