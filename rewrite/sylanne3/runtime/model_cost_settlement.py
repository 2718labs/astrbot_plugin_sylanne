"""Content-free Authority facts for independent first-encoding cost accounting.

The installed port must perform the designated-observer mTLS terminal query.
These value checks bind its answer to the original call; constructing a value
here never authenticates an arbitrary caller or grants a graph write.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Callable

from ..authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_contract import FencePermitV2
from ..runtime_contracts import NamespaceId, canonical_digest
from .budget import (
    BudgetPrediction, BudgetReceipt, BudgetReservation, get_budget_lease,
    predict_budget_partial_settlement, predict_budget_settlement,
    settle_budget, settle_budget_partial,
)
from .d11_types import (
    cost_settlement_from_runtime, cost_settlement_graph_write,
    runtime_job_key,
)
from ..graph_types import GraphWrite
from .issuers import ResourceOutcome, ResourceQuote


class ModelCostUnavailable(RuntimeError):
    """The original Authority terminal or its cost dimensions are unavailable."""


@dataclass(frozen=True, slots=True)
class OriginalModelCostFactV1:
    intent: ModelEgressIntentV1
    recovery: ModelEgressRecoveryV1
    admission: ModelAdmissionV2
    receipt: ModelTerminalReceiptV2

    def __post_init__(self) -> None:
        intent, record, admission, receipt = (
            self.intent, self.recovery, self.admission, self.receipt)
        if (type(intent) is not ModelEgressIntentV1
                or type(record) is not ModelEgressRecoveryV1
                or type(admission) is not ModelAdmissionV2
                or type(receipt) is not ModelTerminalReceiptV2
                or record.intent != intent
                or record.state not in {"observed", "unknown"}
                or (admission.authority_id, admission.namespace,
                    admission.subject, admission.operation_id,
                    admission.call_id, admission.request_digest,
                    admission.provider_config_digest) != (
                    intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id, intent.request_digest,
                    intent.provider_config_digest)
                or (receipt.admission_id, receipt.call_id,
                    receipt.request_digest, receipt.observation_digest,
                    receipt.installation_id, receipt.host_incarnation) != (
                    admission.admission_id, intent.call_id,
                    intent.request_digest, record.observation_digest,
                    admission.installation_id, admission.host_incarnation)):
            raise ModelCostUnavailable("original model terminal identity differs")


def read_original_model_cost(
    port: Callable[[ModelEgressIntentV1], tuple],
    intent: ModelEgressIntentV1,
) -> OriginalModelCostFactV1:
    """Ask the installed, credential-owning port; never accept a caller fact."""
    if type(intent) is not ModelEgressIntentV1 or not callable(port):
        raise ModelCostUnavailable("trusted original model terminal port is absent")
    record, permit, admission, receipt = port(intent)
    if (type(permit) is not FencePermitV2
            or (permit.authority_id, permit.namespace, permit.subject,
                permit.operation_id, permit.operation,
                permit.token, permit.fence_epoch, permit.revision,
                permit.generation, canonical_digest(asdict(permit.pinned_anchor)))
            != (intent.authority_id, intent.namespace, intent.subject,
                intent.operation_id, "model_egress",
                intent.fence_token, intent.fence_epoch,
                intent.fence_revision, intent.authority_activation_generation,
                intent.anchor_digest)):
        raise ModelCostUnavailable("original model fence proof differs")
    return OriginalModelCostFactV1(intent, record, admission, receipt)


def original_model_budget_actual(
    fact: OriginalModelCostFactV1, quote: ResourceQuote,
) -> dict[str, int] | None:
    """Return a complete cost only when every declared dimension is measured.

    Provider token and currency counters are never D02 body energy. Cached
    input tokens are already included in input_tokens and are not added twice.
    """
    known, unknown = original_model_budget_measurement(fact, quote)
    return None if unknown else known


def original_model_budget_measurement(
    fact: OriginalModelCostFactV1, quote: ResourceQuote,
) -> tuple[dict[str, int], tuple[str, ...]]:
    """Keep known dimensions even when another declared dimension is unknown."""
    if type(fact) is not OriginalModelCostFactV1 or type(quote) is not ResourceQuote:
        raise TypeError("typed original cost and signed resource quote required")
    intent = fact.intent
    # The business namespace is checked by the coordinator against the signed
    # quote. Authority's namespace has a separate installation identity.
    if (quote.operation_id != intent.budget_reservation_operation_id
            or quote.parent_budget_lease_ref != intent.budget_lease_id
            or quote.work_kind != "d06.encode_source"):
        raise ModelCostUnavailable("original cost differs from D02 quote")
    if dict(intent.budget_ceiling) != dict(quote.ceiling):
        raise ModelCostUnavailable("Authority ceiling differs from original quote")
    if fact.recovery.state != "observed":
        return {}, tuple(sorted(quote.ceiling))
    usage, money = dict(fact.recovery.usage), dict(fact.recovery.cost)
    actual: dict[str, int] = {}
    unknown = []
    for dimension in quote.ceiling:
        if dimension in {"input_tokens", "output_tokens"}:
            if dimension in usage:
                actual[dimension] = usage[dimension]
            else:
                unknown.append(dimension)
        elif dimension == "model_tokens":
            if {"input_tokens", "output_tokens"} <= usage.keys():
                actual[dimension] = usage["input_tokens"] + usage["output_tokens"]
            else:
                unknown.append(dimension)
        elif dimension == "model_microusd":
            if dimension in money:
                actual[dimension] = money[dimension]
            else:
                unknown.append(dimension)
        else:
            unknown.append(dimension)
    return actual, tuple(sorted(unknown))


def outcome_from_original_model_cost(
    fact: OriginalModelCostFactV1, quote: ResourceQuote,
) -> ResourceOutcome:
    """Candidate D02 outcome; D02 issuer must still verify its trusted origin."""
    actual = original_model_budget_actual(fact, quote)
    return ResourceOutcome(
        outcome_id="model-cost:" + fact.intent.call_id,
        version=1, quote_id=quote.quote_id,
        bot_id=quote.bot_id, persona_id=quote.persona_id,
        activity_id=quote.activity_id, operation_id=quote.operation_id,
        actual=actual, execution_revoked=True,
        provider_receipt_ref=fact.intent.call_id,
    )


@dataclass(frozen=True, slots=True)
class OriginalModelCostPlanV1:
    """Read-only, versioned input for a future independent graph transaction.

    The prediction is tied to the current D11 lease version. It is not a
    spending permit and must be recomputed inside the eventual write txn.
    """

    namespace: NamespaceId
    bundle_operation_id: str
    original_operation_id: str
    call_id: str
    quote: ResourceQuote
    outcome: ResourceOutcome
    original_reservation_digest: str
    terminal_receipt_digest: str
    predicted_budget: BudgetPrediction
    known_actual: dict[str, int]
    unknown_dimensions: tuple[str, ...]
    schema: str = "sylanne.d11.original-model-cost-plan.v2"


@dataclass(frozen=True, slots=True)
class OriginalModelCostApplicationV1:
    """Budget receipt and D11 graph write prepared inside one caller transaction."""

    receipt: BudgetReceipt
    cost_write: GraphWrite
    schema: str = "sylanne.d11.original-model-cost-application.v1"


@dataclass(frozen=True, slots=True)
class OriginalModelCostCommitV1:
    status: str
    operation_id: str
    call_id: str
    quote_id: str
    quote_version: int
    terminal_receipt_digest: str
    cost_ref: str
    budget_receipt_digest: str
    commit_seq: int
    graph_revision: int
    graph_epoch: int
    schema: str = "sylanne.d11.original-model-cost-commit.v1"


def prepare_original_model_cost_plan(
    db, issuer, namespace: NamespaceId, fact: OriginalModelCostFactV1,
    *, quote_id: str, quote_version: int,
) -> OriginalModelCostPlanV1:
    """Join the historical signed quote, original ingress and D11 reservation.

    This performs only local SQLite reads. It must be called after the mTLS
    terminal query, with no network operation inside the graph lock.
    """
    if (type(namespace) is not NamespaceId
            or type(fact) is not OriginalModelCostFactV1
            or not callable(getattr(issuer, "original_signed_quote", None))):
        raise ModelCostUnavailable("typed original accounting inputs are required")
    quote = issuer.original_signed_quote(db, quote_id, quote_version)
    intent = fact.intent
    job_ref = runtime_job_key(*namespace.as_tuple, quote.activity_id,
                              intent.job_id).token
    if ((quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.graph_job_ref != job_ref
            or quote.operation_id != intent.budget_reservation_operation_id
            or quote.parent_budget_lease_ref != intent.budget_lease_id
            or dict(quote.ceiling) != dict(intent.budget_ceiling)
            or quote.work_kind != "d06.encode_source"):
        raise ModelCostUnavailable("original signed quote differs from model call")
    original = db.execute(
        "SELECT activity_id FROM graph_bundle_operations WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (quote.operation_id,),
    ).fetchone()
    if original != (quote.activity_id,):
        raise ModelCostUnavailable("original ingress business receipt is absent")
    lease = get_budget_lease(db, quote.parent_budget_lease_ref)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise ModelCostUnavailable("original budget lease crosses namespace")
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, quote.operation_id),
    ).fetchone()
    original_reserve = db.execute(
        "SELECT digest FROM runtime_budget_operations WHERE bot_id=? "
        "AND persona_id=? AND operation_id=? AND phase='reserve'",
        namespace.as_tuple + (quote.operation_id,),
    ).fetchone()
    if (reservation is None or original_reserve is None
            or reservation[0] != intent.budget_reservation_digest
            or original_reserve[0] != intent.budget_reservation_digest
            or reservation[2] != "reserved"):
        raise ModelCostUnavailable("original D11 reservation is not settleable")
    if json.loads(reservation[1]) != dict(quote.ceiling):
        raise ModelCostUnavailable("original D11 reservation ceiling differs")
    outcome = outcome_from_original_model_cost(fact, quote)
    known, unknown = original_model_budget_measurement(fact, quote)
    budget_reservation = BudgetReservation(
        lease.lease_id, quote.operation_id,
        intent.budget_reservation_digest, quote.ceiling)
    if known and unknown:
        predicted = predict_budget_partial_settlement(
            lease, quote.operation_id, intent.budget_reservation_digest,
            quote.ceiling, known, unknown, reservation=budget_reservation,
            execution_revoked=outcome.execution_revoked)
    else:
        predicted = predict_budget_settlement(
            lease, quote.operation_id, intent.budget_reservation_digest,
            quote.ceiling, outcome.actual, reservation=budget_reservation,
            execution_revoked=outcome.execution_revoked)
    return OriginalModelCostPlanV1(
        namespace,
        "model-cost-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "call_id": intent.call_id,
        })[:48],
        quote.operation_id, intent.call_id, quote, outcome,
        intent.budget_reservation_digest,
        canonical_digest(asdict(fact.receipt)), predicted, known, unknown,
    )


def apply_original_model_budget_in_transaction(
    db, issuer, plan: OriginalModelCostPlanV1,
    fact: OriginalModelCostFactV1,
) -> OriginalModelCostApplicationV1:
    """Settle D11 and form its graph atom inside the caller's SQLite txn.

    The coordinator must graph-commit ``cost_write`` in this *same* transaction
    under an Authority write fence; otherwise it must roll back. No network or
    D02 body calculation occurs here.
    """
    if not db.in_transaction or type(plan) is not OriginalModelCostPlanV1:
        raise ModelCostUnavailable("caller-owned cost graph transaction is required")
    current = prepare_original_model_cost_plan(
        db, issuer, plan.namespace, fact,
        quote_id=plan.quote.quote_id, quote_version=plan.quote.version,
    )
    if current != plan:
        raise ModelCostUnavailable("original cost plan became stale")
    if plan.known_actual and plan.unknown_dimensions:
        receipt = settle_budget_partial(
            db, plan.quote.parent_budget_lease_ref, plan.original_operation_id,
            plan.original_reservation_digest, plan.known_actual,
            plan.unknown_dimensions,
            execution_revoked=plan.outcome.execution_revoked)
    else:
        receipt = settle_budget(
            db, plan.quote.parent_budget_lease_ref, plan.original_operation_id,
            plan.original_reservation_digest, plan.outcome.actual,
            execution_revoked=plan.outcome.execution_revoked)
    if receipt != plan.predicted_budget.receipt:
        raise ModelCostUnavailable("settlement differs from original cost prediction")
    value = cost_settlement_from_runtime(
        db, bot_id=plan.namespace.bot_id,
        persona_id=plan.namespace.persona_id,
        activity_id=plan.quote.activity_id,
        bundle_operation_id=plan.bundle_operation_id,
        effect_id=plan.quote.effect_id,
        settlement_id=plan.bundle_operation_id,
        lease_id=plan.quote.parent_budget_lease_ref,
        cost_operation_id=plan.original_operation_id,
        budget_operation_id=plan.original_operation_id,
        budget_phase="settle", prior_unknown_ref=None,
        execution_revoked=plan.outcome.execution_revoked,
    )
    return OriginalModelCostApplicationV1(
        receipt, cost_settlement_graph_write(value))


__all__ = (
    "ModelCostUnavailable", "OriginalModelCostFactV1",
    "OriginalModelCostPlanV1", "prepare_original_model_cost_plan",
    "OriginalModelCostApplicationV1", "apply_original_model_budget_in_transaction",
    "OriginalModelCostCommitV1",
    "original_model_budget_actual", "outcome_from_original_model_cost",
    "original_model_budget_measurement",
    "read_original_model_cost",
)
