"""Conservative D11 accounting for a completed local first-ingress C02.

The caller must first reconcile the original C02 write fence to Authority's
finished state. No local CPU meter exists, so the entire signed upper bound
remains unconfirmed; this module never claims measured use or a provider bill.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from ..graph_types import GraphWrite
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from .budget import (
    BudgetPrediction, BudgetReceipt, BudgetReservation, get_budget_lease,
    predict_budget_settlement, settle_budget,
)
from .d11_types import (
    cost_settlement_from_runtime, cost_settlement_graph_write, runtime_job_key,
)
from .issuers import D06_FIRST_INGRESS_C02_WORK_KIND, ResourceOutcome, ResourceQuote


class C02CostUnavailable(RuntimeError):
    """The original local completion or its signed reservation is absent."""


@dataclass(frozen=True, slots=True)
class C02UnknownCostPlanV1:
    namespace: NamespaceId
    bundle_operation_id: str
    original_operation_id: str
    quote: ResourceQuote
    outcome: ResourceOutcome
    original_reservation_digest: str
    completion_digest: str
    predicted_budget: BudgetPrediction


@dataclass(frozen=True, slots=True)
class C02UnknownCostApplicationV1:
    receipt: BudgetReceipt
    cost_write: GraphWrite


def prepare_c02_unknown_cost_plan(
    db, issuer, namespace: NamespaceId, original_intent, read,
    verified_completion: CommitReceipt,
) -> C02UnknownCostPlanV1:
    """Bind a coordinator-verified finished C02 to its signed D02/D11 quote.

    ``verified_completion`` must come from the installed coordinator's
    ``_first_ingress_c02_duplicate_v1`` after it checks and finishes the
    original Authority write fence. This local check does not replace that
    remote proof.
    """
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_worker_model_result_contract import WorkerModelResultReadV1
    from .issuers import d06_first_ingress_c02_quote_id

    if (type(namespace) is not NamespaceId
            or type(original_intent) is not ModelEgressIntentV1
            or type(read) is not WorkerModelResultReadV1
            or type(verified_completion) is not CommitReceipt
            or verified_completion.status != "duplicate"):
        raise C02CostUnavailable("verified finished C02 completion required")
    read.require_original_intent(original_intent)
    request = read.request
    operation_id = request.consumer_operation_id
    if namespace != request.namespace or verified_completion.operation_id != operation_id:
        raise C02CostUnavailable("C02 completion identity differs")
    quote = issuer.original_signed_quote(
        db, d06_first_ingress_c02_quote_id(namespace, operation_id), 1)
    if ((quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.operation_id != operation_id
            or quote.work_kind != D06_FIRST_INGRESS_C02_WORK_KIND
            or quote.activity_id != verified_completion.activity_id):
        raise C02CostUnavailable("signed C02 quote differs from completion")
    row = db.execute(
        "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if (row is None or row[0] != verified_completion.operation_digest
            or row[1] != quote.activity_id):
        raise C02CostUnavailable("C02 business receipt differs")
    detail = json.loads(row[2]).get("first_ingress_c02")
    if (type(detail) is not dict
            or detail.get("read_request_digest") != request.digest
            or detail.get("read_result_digest") != canonical_digest(asdict(read))
            or detail.get("original_intent_digest") != canonical_digest(asdict(original_intent))
            or detail.get("terminal_receipt_digest") != canonical_digest(
                asdict(read.terminal_receipt))):
        raise C02CostUnavailable("C02 result receipt differs")
    event = db.execute(
        "SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? "
        "AND event_id=?", namespace.as_tuple + (quote.activity_id, operation_id),
    ).fetchone()
    fence = db.execute(
        "SELECT digest,finish_request_id FROM graph_bundle_fences_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    job = db.execute(
        "SELECT activity_id,operation_id,phase,lease_holder,lease_expires_utc "
        "FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?",
        (request.job_id, *namespace.as_tuple),
    ).fetchone()
    projection = db.execute(
        "SELECT valid,value FROM graph_atoms WHERE token=?",
        (runtime_job_key(*namespace.as_tuple, quote.activity_id,
                         request.job_id).token,),
    ).fetchone()
    if (event is None or fence is None or fence[0] != row[0]
            or not fence[1].startswith("finish:graph-write-")
            or job != (quote.activity_id, request.original_operation_id,
                       "completed", None, None)
            or projection is None or projection[0] != 1
            or json.loads(projection[1]).get("phase") != "completed"):
        raise C02CostUnavailable("C02 graph, job, or write-fence receipt is incomplete")
    lease = get_budget_lease(db, quote.parent_budget_lease_ref)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise C02CostUnavailable("C02 budget lease crosses namespace")
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, operation_id),
    ).fetchone()
    reserve = db.execute(
        "SELECT digest FROM runtime_budget_operations WHERE bot_id=? "
        "AND persona_id=? AND operation_id=? AND phase='reserve'",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if (reservation is None or reserve is None or reservation[0] != reserve[0]
            or reservation[2] != "reserved"
            or json.loads(reservation[1]) != dict(quote.ceiling)):
        raise C02CostUnavailable("original C02 reservation is not settleable")
    predicted = predict_budget_settlement(
        lease, operation_id, reservation[0], quote.ceiling, None,
        reservation=BudgetReservation(
            lease.lease_id, operation_id, reservation[0], quote.ceiling),
        execution_revoked=True)
    outcome = ResourceOutcome(
        "local-c02-completion:" + operation_id, 1, quote.quote_id,
        *namespace.as_tuple, quote.activity_id, operation_id,
        None, True, "local-c02-finished-fence:" + operation_id)
    return C02UnknownCostPlanV1(
        namespace,
        "c02-cost-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
        })[:48],
        operation_id, quote, outcome, reservation[0],
        canonical_digest({"digest": row[0], "finish_request_id": fence[1]}),
        predicted)


def apply_c02_unknown_budget_in_transaction(
    db, issuer, plan: C02UnknownCostPlanV1, original_intent, read,
    verified_completion: CommitReceipt,
) -> C02UnknownCostApplicationV1:
    if not db.in_transaction or type(plan) is not C02UnknownCostPlanV1:
        raise C02CostUnavailable("caller-owned accounting transaction required")
    if prepare_c02_unknown_cost_plan(
            db, issuer, plan.namespace, original_intent, read,
            verified_completion) != plan:
        raise C02CostUnavailable("C02 cost plan became stale")
    issuer.issue_c02_unknown_outcome(
        db, plan, original_intent, read, verified_completion)
    receipt = settle_budget(
        db, plan.quote.parent_budget_lease_ref, plan.original_operation_id,
        plan.original_reservation_digest, None, execution_revoked=True)
    if receipt != plan.predicted_budget.receipt:
        raise C02CostUnavailable("C02 unknown settlement differs from prediction")
    value = cost_settlement_from_runtime(
        db, bot_id=plan.namespace.bot_id, persona_id=plan.namespace.persona_id,
        activity_id=plan.quote.activity_id,
        bundle_operation_id=plan.bundle_operation_id,
        effect_id=plan.quote.effect_id,
        settlement_id=plan.bundle_operation_id,
        lease_id=plan.quote.parent_budget_lease_ref,
        cost_operation_id=plan.original_operation_id,
        budget_operation_id=plan.original_operation_id,
        budget_phase="settle", prior_unknown_ref=None,
        execution_revoked=True)
    return C02UnknownCostApplicationV1(receipt, cost_settlement_graph_write(value))


__all__ = (
    "C02CostUnavailable", "C02UnknownCostPlanV1",
    "C02UnknownCostApplicationV1", "prepare_c02_unknown_cost_plan",
    "apply_c02_unknown_budget_in_transaction",
)
