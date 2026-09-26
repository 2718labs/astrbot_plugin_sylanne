"""Conservative D11 accounting for a completed local first-ingress C02.

The caller must first reconcile the original C02 write fence to Authority's
finished state. No local CPU meter exists, so the entire signed upper bound
remains unconfirmed; this module never claims measured use or a provider bill.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from ..graph_types import GraphWrite
from ..runtime_contracts import (
    CommitReceipt, NamespaceId, canonical_digest, canonical_serialize,
)
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


@dataclass(frozen=True, slots=True)
class C02CommittedCostProofV1:
    """Content-free fields from an already committed C02 business receipt.

    Historical read/result digests have no independent Authority seal after
    the write fence finishes. They are local receipt consistency fields, not
    the basis for the conservative CPU accounting decision.
    """

    job_id: str
    original_operation_id: str
    consumer_operation_id: str
    read_request_digest: str
    read_result_digest: str
    original_intent_digest: str
    terminal_receipt_digest: str
    observation_digest: str
    result_digest: str


@dataclass(frozen=True, slots=True)
class C02OriginalIntentLookupV1:
    """Exact persisted V3 identity for the installed Authority lookup port."""

    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    installation_id: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str


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
            or type(read) not in (WorkerModelResultReadV1, C02CommittedCostProofV1)
            or type(verified_completion) is not CommitReceipt
            or verified_completion.status != "duplicate"):
        raise C02CostUnavailable("verified finished C02 completion required")
    if type(read) is WorkerModelResultReadV1:
        read.require_original_intent(original_intent)
        request = read.request
        proof = C02CommittedCostProofV1(
            request.job_id, request.original_operation_id,
            request.consumer_operation_id, request.digest,
            canonical_digest(asdict(read)), canonical_digest(asdict(original_intent)),
            canonical_digest(asdict(read.terminal_receipt)),
            read.observation.digest, canonical_digest(read.observation.result))
        if namespace != request.namespace:
            raise C02CostUnavailable("C02 read namespace differs")
    else:
        proof = read
    operation_id = proof.consumer_operation_id
    if verified_completion.operation_id != operation_id:
        raise C02CostUnavailable("C02 completion identity differs")
    quote = issuer.original_signed_quote(
        db, d06_first_ingress_c02_quote_id(namespace, operation_id), 1)
    if ((quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.operation_id != operation_id
            or quote.work_kind != D06_FIRST_INGRESS_C02_WORK_KIND
            or quote.activity_id != verified_completion.activity_id
            or quote.effect_id != verified_completion.effect_id):
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
            or detail != {key: getattr(proof, key) for key in (
                "read_request_digest", "read_result_digest",
                "original_intent_digest", "terminal_receipt_digest",
                "observation_digest", "result_digest")}
            or proof.original_intent_digest != canonical_digest(asdict(original_intent))
            or (type(read) is WorkerModelResultReadV1 and
                proof.terminal_receipt_digest != canonical_digest(
                    asdict(read.terminal_receipt)))):
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
        "SELECT activity_id,operation_id,phase,lease_holder,lease_expires_utc,"
        "fence,budget_ref "
        "FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?",
        (proof.job_id, *namespace.as_tuple),
    ).fetchone()
    projection = db.execute(
        "SELECT valid,value FROM graph_atoms WHERE token=?",
        (runtime_job_key(*namespace.as_tuple, quote.activity_id,
                         proof.job_id).token,),
    ).fetchone()
    if (event is None or fence is None or fence[0] != row[0]
            or not fence[1].startswith("finish:graph-write-")
            or job is None or job[:5] != (
                quote.activity_id, proof.original_operation_id,
                "completed", None, None)
            or quote.required_worker_fence != job[5]
            or quote.parent_budget_lease_ref != job[6]
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


def prepare_c02_terminal_unknown_cost_plan(
    db, issuer, namespace: NamespaceId, original_intent, seal, pinned_read,
    verified_completion: CommitReceipt,
) -> C02UnknownCostPlanV1:
    """Price a committed v2 terminal recovery from its archived original seal.

    The pinned read comes from the installed Authority query. The archive,
    signed quote, business receipt, completed job and reservation are all
    re-read here; neither a bare terminal fact nor a caller-built receipt is
    sufficient by itself.
    """
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_terminal_c02_recovery_contract import (
        TerminalRecoveryReadRequestV1,
    )
    from .c02_terminal_job import _PinnedTerminalRead
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .terminal_c02_recovery_candidate_v2 import (
        FrozenTerminalC02CandidateV2, inspect_frozen_terminal_c02_candidate_v2,
    )

    if (type(namespace) is not NamespaceId
            or type(original_intent) is not ModelEgressIntentV1
            or type(seal) is not FrozenTerminalC02CandidateV2
            or type(pinned_read) is not _PinnedTerminalRead
            or type(verified_completion) is not CommitReceipt
            or verified_completion.status != "duplicate"):
        raise C02CostUnavailable("verified committed v2 C02 completion required")
    key = seal.original_key
    operation_id = seal.consumer_operation_id
    fact = pinned_read.fact
    if (key.namespace != namespace
            or verified_completion.operation_id != operation_id
            or key.original_intent_digest != canonical_digest(asdict(original_intent))
            or (original_intent.authority_id, original_intent.namespace,
                original_intent.job_id, original_intent.operation_id,
                original_intent.call_id, original_intent.request_digest,
                original_intent.acquire_operation_id, original_intent.binding_digest)
            != (key.authority_id, key.authority_namespace, key.job_id,
                key.original_model_operation_id, key.call_id,
                key.model_request_digest, key.acquire_operation_id,
                key.binding_digest)
            or fact.request.original_key != key
            or fact.request.consumer_operation_id != operation_id
            or fact.result_digest != key.stable_result_digest):
        raise C02CostUnavailable("v2 C02 original Authority identity differs")
    archived = db.execute(
        "SELECT schema,bundle_digest,bundle_json,evidence_json,quote_json,seal_json "
        "FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if (archived is None or archived[0] != seal.schema
            or archived[1] != seal.bundle_digest
            or archived[5] != canonical_serialize(asdict(seal))):
        raise C02CostUnavailable("committed v2 C02 original seal differs")
    try:
        evidence = json.loads(archived[3])
        if (type(evidence) is not dict
                or archived[3] != canonical_serialize(evidence)):
            raise ValueError("noncanonical original evidence")
        inspection = inspect_frozen_terminal_c02_candidate_v2(
            namespace=namespace, operation_id=operation_id, seal=seal,
            bundle_json=archived[2], quote_json=archived[4])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise C02CostUnavailable("committed v2 C02 archive is invalid") from exc
    if (type(evidence.get("read_request")) is not dict
            or type(evidence.get("read_result_digest")) is not str
            or type(evidence.get("result_payload_digest")) is not str
            or type(evidence.get("terminal_read_attempt_id")) is not str
            or fact.request != TerminalRecoveryReadRequestV1(
                key, operation_id, evidence["terminal_read_attempt_id"])
            or evidence.get("original_intent_digest") != key.original_intent_digest
            or evidence.get("terminal_receipt_digest") != key.terminal_receipt_digest
            or evidence.get("observation_digest") != key.observation_digest
            or evidence.get("result_payload_digest") is None):
        raise C02CostUnavailable("v2 C02 archived read attempt differs")
    quote = issuer.original_signed_quote(db, seal.quote_id, seal.quote_version)
    if (archived[4] != canonical_serialize(asdict(quote))
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id, quote.work_kind) !=
               (*namespace.as_tuple, verified_completion.activity_id,
                operation_id, D06_FIRST_INGRESS_C02_WORK_KIND)
            or quote.effect_id != verified_completion.effect_id
            or inspection.bundle.envelope.identity.operation_id != operation_id):
        raise C02CostUnavailable("v2 C02 historical signed quote differs")
    row = db.execute(
        "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if (row is None or row[0] != verified_completion.operation_digest
            or row[0] != seal.bundle_digest or row[1] != quote.activity_id):
        raise C02CostUnavailable("v2 C02 business receipt differs")
    detail = json.loads(row[2]).get("first_ingress_c02")
    if detail != {
            "read_request_digest": canonical_digest(evidence["read_request"]),
            "read_result_digest": evidence["read_result_digest"],
            "original_intent_digest": key.original_intent_digest,
            "terminal_receipt_digest": key.terminal_receipt_digest,
            "observation_digest": key.observation_digest,
            "result_digest": evidence["result_payload_digest"],
            "seal_schema": seal.schema,
            "original_key_digest": key.digest,
            "signed_quote_digest": seal.quote_digest,
            "terminal_read_attempt_id": fact.request.read_attempt_id,
            "terminal_read_request_digest": fact.request.digest,
            "terminal_read_fact_digest": fact.digest,
    }:
        raise C02CostUnavailable("v2 C02 terminal receipt differs")
    event = db.execute(
        "SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? "
        "AND event_id=?", namespace.as_tuple + (quote.activity_id, operation_id),
    ).fetchone()
    fence = db.execute(
        "SELECT digest,finish_request_id FROM graph_bundle_fences_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    job = get_job(db, key.job_id)
    projection = db.execute(
        "SELECT valid,value FROM graph_atoms WHERE token=?",
        (runtime_job_key(*namespace.as_tuple, quote.activity_id,
                         key.job_id).token,),
    ).fetchone()
    if (event is None or fence is None or fence[0] != row[0]
            or not fence[1].startswith("finish:graph-write-")
            or (job.bot_id, job.persona_id, job.activity_id,
                job.operation_id, job.phase, job.lease_holder,
                job.lease_expires_utc, job.budget_ref, job.fence) !=
               (*namespace.as_tuple, quote.activity_id,
                key.original_operation_id, "completed", None, None,
                quote.parent_budget_lease_ref, quote.required_worker_fence)
            or job.result_ref is None
            or job_graph_write(job) != inspection.bundle.proposals[1].typed_writes[0]
            or projection is None or projection[0] != 1
            or json.loads(projection[1]) != job_graph_write(job).value):
        raise C02CostUnavailable("v2 C02 graph, job, or fence is incomplete")
    lease = get_budget_lease(db, quote.parent_budget_lease_ref)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise C02CostUnavailable("v2 C02 budget lease crosses namespace")
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
        raise C02CostUnavailable("v2 C02 original reservation is not settleable")
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


def apply_c02_terminal_unknown_budget_in_transaction(
    db, issuer, plan: C02UnknownCostPlanV1, namespace: NamespaceId,
    original_intent, seal, pinned_read, verified_completion: CommitReceipt,
) -> C02UnknownCostApplicationV1:
    if not db.in_transaction or type(plan) is not C02UnknownCostPlanV1:
        raise C02CostUnavailable("caller-owned v2 C02 accounting transaction required")
    if prepare_c02_terminal_unknown_cost_plan(
            db, issuer, namespace, original_intent, seal, pinned_read,
            verified_completion) != plan:
        raise C02CostUnavailable("v2 C02 cost plan became stale")
    issuer.issue_c02_terminal_unknown_outcome(
        db, plan, namespace, original_intent, seal, pinned_read,
        verified_completion)
    receipt = settle_budget(
        db, plan.quote.parent_budget_lease_ref, plan.original_operation_id,
        plan.original_reservation_digest, None, execution_revoked=True)
    if receipt != plan.predicted_budget.receipt:
        raise C02CostUnavailable("v2 C02 settlement differs from prediction")
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
    "C02CostUnavailable", "C02CommittedCostProofV1",
    "C02OriginalIntentLookupV1", "C02UnknownCostPlanV1",
    "C02UnknownCostApplicationV1", "prepare_c02_unknown_cost_plan",
    "apply_c02_unknown_budget_in_transaction",
    "prepare_c02_terminal_unknown_cost_plan",
    "apply_c02_terminal_unknown_budget_in_transaction",
)
