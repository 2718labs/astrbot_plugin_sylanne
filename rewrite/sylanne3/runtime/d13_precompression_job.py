"""D13 precompression intents over D11's existing job and budget contracts.

This module owns no tables, worker, model call, or cache. The installed D11
issuer must admit the work kind before the coordinator can commit an intent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import math
from typing import Mapping

from ..domains.d13.precompression import (
    COMPILER_VERSION, D13CurrentPaidModelVerifierV2, PrecompressionPlan,
    accept_verified_model_candidate_v2, adopt_candidate,
    decide_activation, plan_precompression,
)
from ..domains.d13.paid_lifecycle import (
    D13ExactActivationEvidenceV1, D13ExactActivationVerifierV1,
    D13PaidOriginalBindingV1, bind_paid_original_v1,
)
from ..model_broker.d13_precompression import (
    D13ExactTokenCountV1, D13PrecompressionInstallationV1,
    FrozenD13PrecompressionRequestV1, TEMPLATE_VERSION,
    freeze_d13_precompression_request_v1, gate_d13_exact_token_count_v1,
)
from ..runtime_contracts import (
    CommandEnvelope, CompressedTurnBlockV2, ConversationWindowProjectionV1,
    NamespaceId, VersionedRef, canonical_digest,
)
from ..domains.d13.provider import block_graph_value
from .budget import BudgetReceipt
from .jobs import PersistentJob

PAID_WORK_KIND = "d13.precompress.paid.v1"


class D13PrecompressionHold(RuntimeError):
    """Required current Authority, budget, job, or cache port is absent."""


@dataclass(frozen=True, slots=True)
class D13PrecompressionIntentV1:
    plan: PrecompressionPlan
    job: PersistentJob
    ceiling: Mapping[str, int]
    intent_digest: str

    def __post_init__(self) -> None:
        if (type(self.plan) is not PrecompressionPlan or
                type(self.job) is not PersistentJob or
                self.job.work_kind != "d13.precompress" or
                self.job.job_id != self.plan.job_ref or
                self.job.operation_id != self.plan.job_ref or
                self.job.phase != "queued" or
                self.job.fence != 0 or self.job.cancel_epoch != 0 or
                self.job.continuation.get("input_digest") != self.plan.input_digest or
                self.job.continuation.get("plan_digest") !=
                canonical_digest(asdict(self.plan)) or
                canonical_digest(self.job.continuation.get("plan")) !=
                canonical_digest(asdict(self.plan)) or
                type(self.ceiling) is not dict or not self.ceiling or
                any(type(amount) is not int or amount <= 0 for amount in self.ceiling.values()) or
                self.intent_digest != canonical_digest({
                    "schema": "d13.precompression-intent.v1", "plan": self.plan,
                    "job": self.job, "ceiling": dict(self.ceiling),
                })):
            raise ValueError("invalid D13 original job intent")


def validate_paid_job_continuation_v1(
    continuation: Mapping[str, object], operation_id: str, job_ref: str,
) -> None:
    """Reject paid quotes that omit the frozen original model identity."""
    if (type(continuation) is not dict or
            continuation.get("schema") != "d13.paid-precompression-job.v1" or
            continuation.get("original_operation_id") != operation_id or
            continuation.get("job_ref") != job_ref or
            continuation.get("call_id") is None or
            type(continuation.get("max_output_tokens")) is not int or
            continuation["max_output_tokens"] < 1 or
            any(type(continuation.get(name)) is not str or
                len(continuation[name]) != 64 or
                any(ch not in "0123456789abcdef" for ch in continuation[name])
                for name in ("binding_digest", "frozen_input_digest",
                             "wire_digest", "read_closure_digest")) or
            type(continuation.get("plan")) is not dict or
            continuation.get("plan", {}).get("job_ref") != job_ref or
            continuation.get("plan_digest") !=
            canonical_digest(continuation["plan"])):
        raise ValueError("paid D13 quote lacks its original frozen job")


@dataclass(frozen=True, slots=True)
class D13PaidPrecompressionIntentV1:
    """Complete paid schedule input; W01 still owns signing and graph write."""

    plan: PrecompressionPlan
    frozen: FrozenD13PrecompressionRequestV1
    binding: D13PaidOriginalBindingV1
    exact_count: D13ExactTokenCountV1 | None
    job: PersistentJob
    ceiling: Mapping[str, int]
    intent_digest: str

    def __post_init__(self) -> None:
        if (type(self.plan) is not PrecompressionPlan or
                type(self.frozen) is not FrozenD13PrecompressionRequestV1 or
                type(self.binding) is not D13PaidOriginalBindingV1 or
                type(self.job) is not PersistentJob or
                self.frozen != freeze_d13_precompression_request_v1(
                    self.frozen.window, self.plan, self.frozen.installation) or
                self.binding != bind_paid_original_v1(
                    self.frozen, original_operation_id=self.job.operation_id,
                    call_id=self.binding.call_id) or
                self.job.work_kind != PAID_WORK_KIND or
                self.job.phase != "queued" or self.job.fence != 0 or
                self.job.cancel_epoch != 0 or
                self.job.job_id != self.plan.job_ref or
                self.job.operation_id != self.plan.job_ref or
                gate_d13_exact_token_count_v1(
                    self.frozen, self.exact_count).status != "ready" or
                type(self.ceiling) is not dict or
                self.ceiling.get("output_tokens", 0) <
                self.frozen.installation.max_output_tokens or
                (self.ceiling.get("input_tokens", 0) <= 0 and
                 self.ceiling.get("model_tokens", 0) <=
                 self.frozen.installation.max_output_tokens) or
                self.exact_count is not None and
                (self.ceiling.get("input_tokens", 0) < self.exact_count.input_tokens and
                 self.ceiling.get("model_tokens", 0) <
                 self.exact_count.input_tokens + self.frozen.installation.max_output_tokens) or
                any(type(value) is not int or value <= 0
                    for value in self.ceiling.values()) or
                self.intent_digest != canonical_digest({
                    "schema": "d13.paid-precompression-intent.v1",
                    "plan": self.plan, "frozen": self.frozen,
                    "binding": self.binding, "exact_count": self.exact_count,
                    "job": self.job, "ceiling": dict(self.ceiling),
                })):
            raise ValueError("invalid independent paid D13 schedule intent")
        validate_paid_job_continuation_v1(
            self.job.continuation, self.job.operation_id, self.job.job_id)
        if (self.job.continuation["binding_digest"] != self.binding.binding_digest or
                self.job.continuation["frozen_input_digest"] != self.frozen.digest or
                self.job.continuation["wire_digest"] != self.frozen.wire_digest or
                self.job.continuation["read_closure_digest"] !=
                self.frozen.read_closure_digest):
            raise ValueError("paid D13 continuation differs from frozen original")


def prepare_paid_precompression_intent_v1(
    window: ConversationWindowProjectionV1,
    selected_main: D13PrecompressionInstallationV1, *,
    history_token_budget: int, background_capacity: bool,
    outstanding_candidate: bool, attempted_input_digests: frozenset[str],
    parent_budget_lease_ref: str, resource_ref: str,
    ceiling: Mapping[str, int], deadline_utc: float,
    exact_count: D13ExactTokenCountV1 | None = None,
) -> D13PaidPrecompressionIntentV1 | None:
    """Plan the main-model call under a separate paid lease and model ceiling."""
    if type(selected_main) is not D13PrecompressionInstallationV1:
        raise TypeError("installed selected main model required")
    plan = plan_precompression(
        window, history_token_budget, background_capacity=background_capacity,
        outstanding_candidate=outstanding_candidate,
        attempted_input_digests=attempted_input_digests)
    if plan is None:
        return None
    if (type(deadline_utc) not in (int, float) or
            not window.trusted_utc < deadline_utc <= plan.expires_at_utc):
        raise ValueError("paid D13 deadline must fit current source lifetime")
    frozen = freeze_d13_precompression_request_v1(window, plan, selected_main)
    call_id = "d13-paid-call:" + canonical_digest({
        "schema": "d13.paid-call-id.v1", "job_ref": plan.job_ref,
        "wire_digest": frozen.wire_digest,
    })[:48]
    binding = bind_paid_original_v1(
        frozen, original_operation_id=plan.job_ref, call_id=call_id)
    continuation = {
        "schema": "d13.paid-precompression-job.v1",
        "input_digest": plan.input_digest,
        "conversation_ref": window.conversation_ref,
        "first_sequence": plan.first_sequence,
        "last_sequence": plan.last_sequence,
        "candidate_ref": plan.candidate_ref,
        "plan": json.loads(json.dumps(asdict(plan))),
        "plan_digest": canonical_digest(asdict(plan)),
        "job_ref": plan.job_ref,
        "original_operation_id": plan.job_ref,
        "call_id": call_id,
        "binding_digest": binding.binding_digest,
        "frozen_input_digest": frozen.digest,
        "wire_digest": frozen.wire_digest,
        "read_closure_digest": frozen.read_closure_digest,
        "installation_id": selected_main.installation_id,
        "provider_id": selected_main.provider_id,
        "model_id": selected_main.model_id,
        "provider_config_digest": selected_main.provider_config_digest,
        "max_output_tokens": selected_main.max_output_tokens,
    }
    job = PersistentJob(
        plan.job_ref, plan.job_ref,
        "d13-paid-activity:" + plan.input_digest[:48], None,
        *window.namespace.as_tuple,
        "d13-paid-snapshot:" + plan.input_digest[:48],
        "queued", PAID_WORK_KIND, continuation, None,
        datetime.fromtimestamp(deadline_utc, timezone.utc).isoformat().replace(
            "+00:00", "Z"), parent_budget_lease_ref, resource_ref,
        {"d13_template": TEMPLATE_VERSION}, None, None, 0, 0, {}, None,
    )
    ceiling = dict(ceiling)
    digest = canonical_digest({
        "schema": "d13.paid-precompression-intent.v1",
        "plan": plan, "frozen": frozen, "binding": binding,
        "exact_count": exact_count, "job": job, "ceiling": ceiling,
    })
    return D13PaidPrecompressionIntentV1(
        plan, frozen, binding, exact_count, job, ceiling, digest)


def issue_paid_precompression_quote_v1(
    db, intent: D13PaidPrecompressionIntentV1, *,
    resource_issuer: object, budget_issuer: object,
    quote_version: int = 1, valid_until_utc: float,
):
    """Sign the distinct D02 quote against the live independent D11 grant.

    W01 calls this within the original fenced write transaction, before
    reserve_and_schedule and record_d13_paid_intent_original_v1.
    """
    from .d11_types import runtime_job_key
    from .issuers import (
        BudgetLeaseGrant, D02ResourceIssuer, D11BudgetGrantIssuer,
        IssuerAuthorityDenied, ResourceQuote,
    )

    if (type(intent) is not D13PaidPrecompressionIntentV1 or
            type(resource_issuer) is not D02ResourceIssuer or
            not isinstance(budget_issuer, D11BudgetGrantIssuer) or
            (getattr(budget_issuer, "resource_issuer", resource_issuer)
             is not resource_issuer) or
            not db.in_transaction or
            type(quote_version) is not int or quote_version < 1 or
            type(valid_until_utc) not in (int, float) or
            not math.isfinite(valid_until_utc) or
            valid_until_utc < datetime.fromisoformat(
                intent.job.deadline_utc.replace("Z", "+00:00")).timestamp()):
        raise ValueError("paid D13 quote requires one current write transaction")
    grant = budget_issuer.current_budget_grant(db, intent.job.budget_ref)
    if (type(grant) is not BudgetLeaseGrant or
            PAID_WORK_KIND not in grant.allowed_work_kinds or
            grant.valid_until_utc < valid_until_utc or
            any(value > grant.max_ceiling.get(name, 0)
                for name, value in intent.ceiling.items())):
        raise IssuerAuthorityDenied("independent paid D11 grant is insufficient")
    quote = ResourceQuote(
        "d13-paid-quote:" + intent.plan.input_digest[:48], quote_version,
        intent.job.bot_id, intent.job.persona_id, intent.job.activity_id,
        intent.job.operation_id, None, intent.job.budget_ref, PAID_WORK_KIND,
        intent.job.snapshot_ref,
        datetime.fromisoformat(
            intent.job.deadline_utc.replace("Z", "+00:00")).timestamp(),
        intent.job.resource_ref,
        runtime_job_key(intent.job.bot_id, intent.job.persona_id,
                        intent.job.activity_id, intent.job.job_id).token,
        (), (), dict(intent.ceiling), None, valid_until_utc,
        dict(intent.job.continuation),
    )
    resource_issuer.issue_quote(db, quote)
    return quote


def precompression_plan_from_wire_v1(payload) -> PrecompressionPlan:
    """The existing exact durable plan decoder, without a fabricated job DTO."""
    from dataclasses import fields
    if type(payload) is not dict or set(payload)!={field.name for field in fields(PrecompressionPlan)}:
        raise ValueError("invalid durable D13 plan fields")
    return PrecompressionPlan(
        job_ref=payload["job_ref"], candidate_ref=payload["candidate_ref"], input_digest=payload["input_digest"],
        first_sequence=payload["first_sequence"], last_sequence=payload["last_sequence"],
        source_dependencies=tuple(VersionedRef(**ref) for ref in payload["source_dependencies"]),
        scene_ref=VersionedRef(**payload["scene_ref"]), audience_ref=VersionedRef(**payload["audience_ref"]),
        access_epoch=payload["access_epoch"], delete_epoch=payload["delete_epoch"],
        activation_epoch=payload["activation_epoch"], expires_at_utc=payload["expires_at_utc"])


def plan_from_precompression_job_v1(job: PersistentJob) -> PrecompressionPlan:
    """Recover the immutable source closure from D11's durable original job."""
    if (type(job) is not PersistentJob
            or job.work_kind not in {"d13.precompress", PAID_WORK_KIND}):
        raise ValueError("D13 original job required")
    payload = job.continuation.get("plan")
    if type(payload) is not dict:
        raise ValueError("D13 job has no durable plan")
    try:
        plan = precompression_plan_from_wire_v1(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid durable D13 plan") from exc
    if (canonical_digest(asdict(plan)) != canonical_digest(payload) or
            job.continuation.get("plan_digest") != canonical_digest(payload) or
            job.job_id != plan.job_ref or
            job.operation_id != plan.job_ref or
            job.continuation.get("input_digest") != plan.input_digest or
            job.continuation.get("candidate_ref") != plan.candidate_ref or
            job.continuation.get("first_sequence") != plan.first_sequence or
            job.continuation.get("last_sequence") != plan.last_sequence):
        raise ValueError("D13 durable plan differs from original job")
    return plan


def prepare_precompression_intent_v1(
    window: ConversationWindowProjectionV1, *, history_token_budget: int,
    background_capacity: bool, outstanding_candidate: bool,
    attempted_input_digests: frozenset[str], parent_budget_lease_ref: str,
    resource_ref: str, ceiling: Mapping[str, int], deadline_utc: float,
) -> D13PrecompressionIntentV1 | None:
    """Pure plan. D11 must supply current quota, attempts and signed profile.

    No reservation or job exists until an installed coordinator accepts this
    exact identity in its graph transaction.
    """
    plan = plan_precompression(
        window, history_token_budget, background_capacity=background_capacity,
        outstanding_candidate=outstanding_candidate,
        attempted_input_digests=attempted_input_digests,
    )
    if plan is None:
        return None
    if (type(deadline_utc) not in (int, float) or
            not window.trusted_utc < deadline_utc <= plan.expires_at_utc):
        raise ValueError("D13 job deadline must be within raw source lifetime")
    job = PersistentJob(
        plan.job_ref, plan.job_ref,
        "d13-activity:" + plan.input_digest[:48], None,
        *window.namespace.as_tuple,
        "d13-snapshot:" + plan.input_digest[:48], "queued", "d13.precompress",
        {"schema": "d13.precompression-job.v1", "input_digest": plan.input_digest,
         "conversation_ref": window.conversation_ref,
         "first_sequence": plan.first_sequence, "last_sequence": plan.last_sequence,
         "candidate_ref": plan.candidate_ref,
         "plan": json.loads(json.dumps(asdict(plan))),
         "plan_digest": canonical_digest(asdict(plan))},
        None, datetime.fromtimestamp(deadline_utc, timezone.utc).isoformat().replace(
            "+00:00", "Z"), parent_budget_lease_ref, resource_ref,
        {"d13_compiler": COMPILER_VERSION}, None, None, 0, 0, {}, None,
    )
    digest = canonical_digest({
        "schema": "d13.precompression-intent.v1", "plan": plan,
        "job": job, "ceiling": dict(ceiling),
    })
    return D13PrecompressionIntentV1(plan, job, dict(ceiling), digest)


def submit_precompression_intent_v1(
    coordinator: object, envelope: CommandEnvelope, lease: object,
    intent: D13PrecompressionIntentV1,
) -> tuple[BudgetReceipt, PersistentJob]:
    """Use the existing fenced coordinator; fail closed without D13 admission.

    A transport error leaves the original operation outcome unknown. Retrying
    requires the same envelope and job identity so D11 can replay its receipt.
    """
    if type(intent) is not D13PrecompressionIntentV1 or type(envelope) is not CommandEnvelope:
        raise TypeError("typed D13 intent and command envelope required")
    from ..graph_coordinator import GraphCoordinator, budget_operation_digest

    if not isinstance(coordinator, GraphCoordinator):
        raise D13PrecompressionHold("installed GraphCoordinator is required")
    job, plan = intent.job, intent.plan
    read_versions = frozenset(VersionedRef(item.key.token, item.revision)
                              for item in envelope.version_guard.read_versions)
    quote_versions = envelope.version_guard.resource_lease_versions
    if len(quote_versions) != 1:
        raise D13PrecompressionHold("D13 requires one signed original resource quote")
    expected_quote_ref = f"{quote_versions[0].ref}:{quote_versions[0].version}"
    if (envelope.authority.issuer_domain != "d13" or
            envelope.identity.phase != "d13.precompress" or
            envelope.authority.namespace.as_tuple != (job.bot_id, job.persona_id) or
            envelope.identity.operation_id != job.operation_id or
            envelope.identity.activity_id != job.activity_id or
            envelope.identity.effect_id is not None or
            envelope.parent_budget_lease_ref != job.budget_ref or
            datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace(
                "+00:00", "Z") != job.deadline_utc or
            envelope.deadline_utc > plan.expires_at_utc or
            not {plan.scene_ref, plan.audience_ref, *plan.source_dependencies}.issubset(
                read_versions)):
        raise D13PrecompressionHold("D13 current command/read set differs from original plan")
    schedule = getattr(coordinator, "reserve_and_schedule", None)
    if not callable(schedule):
        raise D13PrecompressionHold("fenced D11 schedule port is absent")
    try:
        budget, persisted = schedule(envelope, lease)
    except Exception as exc:
        raise D13PrecompressionHold(
            "D13 schedule outcome unavailable; retry only the original operation") from exc
    expected_digest = budget_operation_digest(envelope, job.budget_ref, intent.ceiling)
    expected_job = replace(job, operator_versions={
        **job.operator_versions, "resource_quote": expected_quote_ref})
    if (type(budget) is not BudgetReceipt or type(persisted) is not PersistentJob or
            budget.status != "reserved" or
            budget.operation_id != job.operation_id or
            budget.lease_id != job.budget_ref or
            budget.digest != expected_digest or persisted != expected_job):
        raise D13PrecompressionHold("D13 schedule receipt differs; outcome requires reconciliation")
    return budget, persisted


def prepare_standby_v1(
    job: PersistentJob, *, holder: str, fence: int, now_utc: float,
    plan: PrecompressionPlan, candidate: CompressedTurnBlockV2,
    current_window: ConversationWindowProjectionV1,
) -> CompressedTurnBlockV2:
    """Pure worker result check. D11 must atomically CAS/save the returned block."""
    _require_live_worker_v1(job, holder=holder, fence=fence,
                            now_utc=now_utc, plan=plan,
                            current_window=current_window)
    return adopt_candidate(candidate, plan, current_window, job_fence_valid=True)


def _require_live_worker_v1(
    job: PersistentJob, *, holder: str, fence: int, now_utc: float,
    plan: PrecompressionPlan, current_window: ConversationWindowProjectionV1,
) -> None:
    if (type(now_utc) not in (int, float) or not math.isfinite(now_utc) or
            now_utc != current_window.trusted_utc or
            type(job) is not PersistentJob or job.job_id != plan.job_ref or
            job.work_kind not in {"d13.precompress", PAID_WORK_KIND}
            or job.phase != "running" or
            job.lease_holder != holder or job.fence != fence or job.cancel_epoch != 0 or
            job.lease_expires_utc is None or
            now_utc >= datetime.fromisoformat(
                job.lease_expires_utc.replace("Z", "+00:00")).timestamp() or
            now_utc >= datetime.fromisoformat(
                job.deadline_utc.replace("Z", "+00:00")).timestamp()):
        raise D13PrecompressionHold("D13 worker lost its original live fence")


def prepare_model_standby_candidate_v2(
    job: PersistentJob, *, holder: str, fence: int, now_utc: float,
    plan: PrecompressionPlan, candidate: CompressedTurnBlockV2,
    current_window: ConversationWindowProjectionV1,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None,
) -> CompressedTurnBlockV2:
    """Paid model standby candidate; W01 still owns same-tx job/cache CAS."""
    _require_live_worker_v1(job, holder=holder, fence=fence,
                            now_utc=now_utc, plan=plan,
                            current_window=current_window)
    try:
        return accept_verified_model_candidate_v2(
            candidate, plan, current_window, paid_verifier=paid_verifier)
    except ValueError as exc:
        raise D13PrecompressionHold("paid model candidate is not current") from exc


@dataclass(frozen=True, slots=True)
class D13ActivationCheckV1:
    decision: str
    reason: str
    reached_seventy_percent: bool
    raw_tail_within_forty_percent: bool


def check_activation_v1(
    standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *, history_token_budget: int,
    raw_window_input_tokens: int, raw_tail_input_tokens: int,
    raw_window_fits: bool,
    proven_future_saving: bool,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
    exact_activation_evidence: D13ExactActivationEvidenceV1 | None = None,
    exact_activation_verifier: D13ExactActivationVerifierV1 | None = None,
) -> D13ActivationCheckV1:
    """70/40 are diagnostic targets; D11 owns actual window/cost findings.

    Paid candidates require W09's typed same-main-model exact wire evidence.
    Missing evidence is HOLD; legacy booleans cannot authorize paid activation.
    """
    if (type(history_token_budget) is not int or history_token_budget <= 0 or
            type(raw_window_input_tokens) is not int or raw_window_input_tokens < 0 or
            type(raw_tail_input_tokens) is not int or raw_tail_input_tokens < 0 or
            raw_tail_input_tokens > raw_window_input_tokens):
        raise ValueError("actual window accounting is required")
    decision = decide_activation(
        standby, plan, window, raw_window_fits=raw_window_fits,
        proven_future_saving=proven_future_saving,
        paid_verifier=paid_verifier,
        exact_activation_evidence=exact_activation_evidence,
        exact_activation_verifier=exact_activation_verifier,
    )
    if decision == "invalid":
        reason = "stale_source_or_expired"
    elif decision == "activate":
        reason = ("exact_window_pressure" if exact_activation_evidence is not None
                  else "window_pressure" if not raw_window_fits
                  else "proven_future_cost")
    elif standby.compiler_version == "d13.model.extractive.v1":
        reason = ("exact_activation_proof_required"
                  if exact_activation_evidence is None or exact_activation_verifier is None
                  else "exact_wire_budget_not_met")
    else:
        reason = "keep_stable_prefix"
    return D13ActivationCheckV1(
        decision, reason,
        raw_window_input_tokens * 10 >= history_token_budget * 7,
        raw_tail_input_tokens * 10 <= history_token_budget * 4,
    )


def retirement_due_v1(block: CompressedTurnBlockV2, trusted_now_utc: float) -> bool:
    """Synchronous read barrier; physical removal remains a D11 transaction."""
    if (type(block) is not CompressedTurnBlockV2 or
            type(trusted_now_utc) not in (int, float) or not math.isfinite(trusted_now_utc)):
        raise TypeError("typed block and trusted clock required")
    return trusted_now_utc >= block.expires_at_utc or block.status == "retired"


@dataclass(frozen=True, slots=True)
class D13CacheTransitionIntentV1:
    """Candidate for one W01 graph CAS, never evidence of a committed change."""

    operation_id: str
    action: str
    namespace: NamespaceId
    conversation_ref: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    block: CompressedTurnBlockV2
    expected_cache_revision: int | None
    read_set: tuple[VersionedRef, ...]
    source_dependencies: tuple[VersionedRef, ...]
    access_epoch: int
    delete_epoch: int
    activation_epoch: int
    trusted_utc: float
    job_ref: str
    worker_fence: int | None
    reason: str
    input_digest: str

    def __post_init__(self) -> None:
        if (self.action not in {"adopt", "activate", "retire"} or
                type(self.namespace) is not NamespaceId or
                type(self.block) is not CompressedTurnBlockV2 or
                self.block.conversation_ref != self.conversation_ref or
                self.block.audience_ref != self.audience_ref or
                self.block.job_ref != self.job_ref or
                self.action != "retire" and
                not set(self.source_dependencies).issubset(self.read_set) or
                self.scene_ref not in self.read_set or self.audience_ref not in self.read_set or
                any(type(v) is not int or v < 0 for v in (
                    self.access_epoch, self.delete_epoch, self.activation_epoch)) or
                type(self.trusted_utc) not in (int, float) or
                not math.isfinite(self.trusted_utc)):
            raise ValueError("invalid D13 cache transition closure")
        if self.action == "adopt":
            if (self.block.status != "standby" or self.expected_cache_revision is not None or
                    type(self.worker_fence) is not int or self.worker_fence < 1):
                raise ValueError("adoption requires a live worker and absent cache row")
        elif (self.expected_cache_revision is None or
              type(self.expected_cache_revision) is not int or
              self.expected_cache_revision < 1 or self.worker_fence is not None or
              self.block.status != ("active" if self.action == "activate" else "retired")):
            raise ValueError("activation/retirement requires current cache CAS")
        expected = canonical_digest({
            "schema": "d13.cache-transition.v1", "action": self.action,
            "namespace": self.namespace, "conversation": self.conversation_ref,
            "scene": self.scene_ref, "audience": self.audience_ref,
            "block_digest": canonical_digest(block_graph_value(self.block)),
            "expected_cache_revision": self.expected_cache_revision,
            "read_set": self.read_set, "source_dependencies": self.source_dependencies,
            "access_epoch": self.access_epoch, "delete_epoch": self.delete_epoch,
            "activation_epoch": self.activation_epoch,
            "trusted_utc": self.trusted_utc, "job_ref": self.job_ref,
            "worker_fence": self.worker_fence, "reason": self.reason,
        })
        if self.input_digest != expected or self.operation_id != f"d13:cache:{expected[:48]}":
            raise ValueError("D13 cache transition identity differs")


@dataclass(frozen=True, slots=True)
class D13CacheCommitReceiptV1:
    """W01 returns this only after atomic graph CAS and deletion barrier check."""

    operation_id: str
    input_digest: str
    block_ref: str
    action: str
    graph_revision: int
    cache_revision: int
    deletion_epoch: int
    read_blocked: bool
    payload_reclaimed: bool
    cleanup_task_ref: str | None

    def __post_init__(self) -> None:
        if (self.action not in {"adopt", "activate", "retire"} or
                type(self.operation_id) is not str or not self.operation_id or
                type(self.input_digest) is not str or len(self.input_digest) != 64 or
                any(ch not in "0123456789abcdef" for ch in self.input_digest) or
                type(self.block_ref) is not str or not self.block_ref or
                type(self.graph_revision) is not int or self.graph_revision < 1 or
                type(self.cache_revision) is not int or self.cache_revision < 1 or
                type(self.deletion_epoch) is not int or self.deletion_epoch < 0 or
                type(self.read_blocked) is not bool or
                type(self.payload_reclaimed) is not bool or
                self.cleanup_task_ref is not None and
                (type(self.cleanup_task_ref) is not str or not self.cleanup_task_ref) or
                self.action == "retire" and
                (not self.read_blocked or
                 not self.payload_reclaimed and self.cleanup_task_ref is None)):
            raise ValueError("invalid D13 cache commit receipt")


def _transition_intent(
    action: str, window: ConversationWindowProjectionV1,
    block: CompressedTurnBlockV2, *, expected_cache_revision: int | None,
    worker_fence: int | None, reason: str,
) -> D13CacheTransitionIntentV1:
    read_set = (tuple(window.read_set) if action == "retire" else
                tuple(dict.fromkeys((*window.read_set, *block.source_dependencies))))
    values = dict(
        action=action, namespace=window.namespace,
        conversation_ref=window.conversation_ref, scene_ref=window.scene_ref,
        audience_ref=window.audience_ref, block=block,
        expected_cache_revision=expected_cache_revision, read_set=read_set,
        source_dependencies=block.source_dependencies,
        access_epoch=window.access_epoch, delete_epoch=window.delete_epoch,
        activation_epoch=window.activation_epoch, trusted_utc=window.trusted_utc,
        job_ref=block.job_ref, worker_fence=worker_fence, reason=reason,
    )
    digest = canonical_digest({
        "schema": "d13.cache-transition.v1", "action": action,
        "namespace": values["namespace"], "conversation": values["conversation_ref"],
        "scene": values["scene_ref"], "audience": values["audience_ref"],
        "block_digest": canonical_digest(block_graph_value(block)),
        "expected_cache_revision": expected_cache_revision,
        "read_set": read_set, "source_dependencies": block.source_dependencies,
        "access_epoch": window.access_epoch, "delete_epoch": window.delete_epoch,
        "activation_epoch": window.activation_epoch, "trusted_utc": window.trusted_utc,
        "job_ref": block.job_ref, "worker_fence": worker_fence, "reason": reason,
    })
    return D13CacheTransitionIntentV1(
        operation_id=f"d13:cache:{digest[:48]}", input_digest=digest, **values)


def prepare_adoption_intent_v1(
    job: PersistentJob, *, holder: str, fence: int, now_utc: float,
    plan: PrecompressionPlan, candidate: CompressedTurnBlockV2,
    current_window: ConversationWindowProjectionV1,
) -> D13CacheTransitionIntentV1:
    standby = prepare_standby_v1(
        job, holder=holder, fence=fence, now_utc=now_utc,
        plan=plan, candidate=candidate, current_window=current_window)
    return _transition_intent("adopt", current_window, standby,
                              expected_cache_revision=None,
                              worker_fence=fence, reason="candidate_validated")


def prepare_model_adoption_intent_v2(
    job: PersistentJob, *, holder: str, fence: int, now_utc: float,
    plan: PrecompressionPlan, candidate: CompressedTurnBlockV2,
    current_window: ConversationWindowProjectionV1,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None,
) -> D13CacheTransitionIntentV1:
    """Prepare absent-cache CAS for a paid, source-checked model candidate."""
    standby = prepare_model_standby_candidate_v2(
        job, holder=holder, fence=fence, now_utc=now_utc,
        plan=plan, candidate=candidate, current_window=current_window,
        paid_verifier=paid_verifier)
    return _transition_intent(
        "adopt", current_window, standby,
        expected_cache_revision=None, worker_fence=fence,
        reason="paid_extractive_candidate_validated")


def prepare_activation_intent_v1(
    standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
    current_window: ConversationWindowProjectionV1, *, cache_revision: int,
    history_token_budget: int, raw_window_input_tokens: int,
    raw_tail_input_tokens: int, raw_window_fits: bool,
    proven_future_saving: bool,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
    exact_activation_evidence: D13ExactActivationEvidenceV1 | None = None,
    exact_activation_verifier: D13ExactActivationVerifierV1 | None = None,
) -> D13CacheTransitionIntentV1:
    check = check_activation_v1(
        standby, plan, current_window, history_token_budget=history_token_budget,
        raw_window_input_tokens=raw_window_input_tokens,
        raw_tail_input_tokens=raw_tail_input_tokens,
        raw_window_fits=raw_window_fits,
        proven_future_saving=proven_future_saving,
        paid_verifier=paid_verifier,
        exact_activation_evidence=exact_activation_evidence,
        exact_activation_verifier=exact_activation_verifier)
    if check.decision != "activate":
        raise D13PrecompressionHold(f"D13 block is not activatable: {check.reason}")
    return _transition_intent("activate", current_window,
                              replace(standby, status="active"),
                              expected_cache_revision=cache_revision,
                              worker_fence=None, reason=check.reason)


def prepare_retirement_intent_v1(
    block: CompressedTurnBlockV2,
    current_window: ConversationWindowProjectionV1, *, cache_revision: int,
    source_invalidated: bool = False,
) -> D13CacheTransitionIntentV1:
    if (type(source_invalidated) is not bool or
            not source_invalidated and not retirement_due_v1(block, current_window.trusted_utc)):
        raise D13PrecompressionHold("D13 block has not expired or been invalidated")
    if block.status not in {"standby", "active"}:
        raise D13PrecompressionHold("only stored D13 cache can retire")
    return _transition_intent(
        "retire", current_window, replace(block, status="retired"),
        expected_cache_revision=cache_revision, worker_fence=None,
        reason="source_invalidated" if source_invalidated else "72h_expired")


def submit_cache_transition_v1(
    coordinator: object, lease: object, intent: D13CacheTransitionIntentV1,
) -> D13CacheCommitReceiptV1:
    """Require W01's atomic cache CAS. No local fallback or second store."""
    from ..graph_coordinator import GraphCoordinator

    if type(intent) is not D13CacheTransitionIntentV1:
        raise TypeError("typed D13 transition intent required")
    if not isinstance(coordinator, GraphCoordinator):
        raise D13PrecompressionHold("installed GraphCoordinator is required")
    commit = getattr(coordinator, "commit_d13_cache_transition_v1", None)
    if not callable(commit):
        raise D13PrecompressionHold("W01 D13 atomic cache transition port is absent")
    try:
        receipt = commit(intent, lease)
    except Exception as exc:
        raise D13PrecompressionHold(
            "D13 cache transition outcome unknown; reconcile original operation") from exc
    if (type(receipt) is not D13CacheCommitReceiptV1 or
            (receipt.operation_id, receipt.input_digest, receipt.block_ref, receipt.action) !=
            (intent.operation_id, intent.input_digest, intent.block.block_ref, intent.action) or
            receipt.deletion_epoch < intent.delete_epoch or
            intent.expected_cache_revision is not None and
            receipt.cache_revision <= intent.expected_cache_revision):
        raise D13PrecompressionHold("D13 cache transition receipt differs")
    return receipt


@dataclass(frozen=True, slots=True)
class D13CallUsageV1:
    """One trusted D11 receipt's measured dimensions; unknown stays unknown."""

    input_tokens: int
    output_tokens: int
    cached_input_tokens: int | None
    billed_microusd: int | None

    def __post_init__(self) -> None:
        if (type(self.input_tokens) is not int or self.input_tokens < 0 or
                type(self.output_tokens) is not int or self.output_tokens < 0 or
                self.cached_input_tokens is not None and
                (type(self.cached_input_tokens) is not int or
                 not 0 <= self.cached_input_tokens <= self.input_tokens) or
                self.billed_microusd is not None and
                (type(self.billed_microusd) is not int or self.billed_microusd < 0)):
            raise ValueError("invalid D13 measured usage")


@dataclass(frozen=True, slots=True)
class D13DualLedgerV1:
    foreground_window_tokens: int
    foreground_cached_tokens: int | None
    total_billed_microusd: int | None
    unused_candidate_cost_microusd: int | None


def combine_usage_v1(
    foreground: D13CallUsageV1, background: D13CallUsageV1 | None,
    *, candidate_used: bool,
) -> D13DualLedgerV1:
    """Cached tokens occupy the window and are never added to input twice."""
    if type(foreground) is not D13CallUsageV1 or (
            background is not None and type(background) is not D13CallUsageV1) or (
            type(candidate_used) is not bool):
        raise TypeError("trusted typed call usage required")
    total = (foreground.billed_microusd + background.billed_microusd
             if background is not None and foreground.billed_microusd is not None
             and background.billed_microusd is not None else
             foreground.billed_microusd if background is None else None)
    unused = (background.billed_microusd if background is not None and
              not candidate_used else None)
    return D13DualLedgerV1(foreground.input_tokens,
                           foreground.cached_input_tokens, total, unused)


@dataclass(frozen=True, slots=True)
class D13ProviderUsageV2:
    """D11-transcribed provider receipt; totals include any cache fees once."""

    call_ref: str
    receipt_digest: str
    role: str
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int | None
    cache_write_tokens: int | None
    total_billed_microusd: int | None
    cache_storage_microusd: int | None

    def __post_init__(self) -> None:
        if (type(self.call_ref) is not str or not self.call_ref or
                type(self.receipt_digest) is not str or
                len(self.receipt_digest) != 64 or
                any(ch not in "0123456789abcdef" for ch in self.receipt_digest) or
                self.role not in {"foreground", "precompression"} or
                any(type(v) is not int or v < 0 for v in (
                    self.input_tokens, self.output_tokens)) or
                self.cached_input_tokens is not None and
                (type(self.cached_input_tokens) is not int or
                 not 0 <= self.cached_input_tokens <= self.input_tokens) or
                self.cache_write_tokens is not None and
                (type(self.cache_write_tokens) is not int or
                 not 0 <= self.cache_write_tokens <= self.input_tokens) or
                self.cached_input_tokens is not None and
                self.cache_write_tokens is not None and
                self.cached_input_tokens + self.cache_write_tokens > self.input_tokens or
                self.total_billed_microusd is not None and
                (type(self.total_billed_microusd) is not int or
                 self.total_billed_microusd < 0) or
                self.cache_storage_microusd is not None and
                (type(self.cache_storage_microusd) is not int or
                 self.cache_storage_microusd < 0) or
                self.cache_storage_microusd is not None and
                self.total_billed_microusd is not None and
                self.cache_storage_microusd > self.total_billed_microusd):
            raise ValueError("invalid D13 provider usage receipt")


@dataclass(frozen=True, slots=True)
class D13AccountingV2:
    foreground_window_tokens: int
    foreground_cached_input_tokens: int | None
    foreground_cache_write_tokens: int | None
    precompression_input_tokens: int | None
    precompression_output_tokens: int | None
    total_billed_microusd: int | None
    unused_candidate_billed_microusd: int | None
    cost_status: str
    receipt_refs: tuple[str, ...]


def account_d13_calls_v2(
    foreground: D13ProviderUsageV2,
    precompression: D13ProviderUsageV2 | None, *, candidate_used: bool,
) -> D13AccountingV2:
    """Window counts all input; cost sums distinct actual calls, never cache twice.

    The caller must authenticate each original D11/provider receipt. A local
    prefix digest or estimated rate is not a measured saving.
    """
    if (type(foreground) is not D13ProviderUsageV2 or
            foreground.role != "foreground" or
            precompression is not None and
            (type(precompression) is not D13ProviderUsageV2 or
             precompression.role != "precompression" or
             precompression.call_ref == foreground.call_ref) or
            type(candidate_used) is not bool):
        raise ValueError("distinct original foreground/background receipts required")
    receipts = (foreground, precompression) if precompression is not None else (foreground,)
    reported = all(item.total_billed_microusd is not None for item in receipts)
    total = sum(item.total_billed_microusd for item in receipts) if reported else None
    unused = (precompression.total_billed_microusd if precompression is not None
              and not candidate_used else None)
    return D13AccountingV2(
        foreground.input_tokens, foreground.cached_input_tokens,
        foreground.cache_write_tokens,
        precompression.input_tokens if precompression is not None else None,
        precompression.output_tokens if precompression is not None else None,
        total, unused, "reported" if reported else "unknown",
        tuple(item.call_ref for item in receipts),
    )


__all__ = (
    "D13PrecompressionHold", "D13PrecompressionIntentV1",
    "D13PaidPrecompressionIntentV1", "validate_paid_job_continuation_v1",
    "prepare_paid_precompression_intent_v1",
    "issue_paid_precompression_quote_v1",
    "plan_from_precompression_job_v1",
    "prepare_precompression_intent_v1", "submit_precompression_intent_v1",
    "prepare_standby_v1", "D13ActivationCheckV1", "check_activation_v1",
    "prepare_model_standby_candidate_v2",
    "retirement_due_v1", "D13CallUsageV1", "D13DualLedgerV1", "combine_usage_v1",
    "D13CacheTransitionIntentV1", "D13CacheCommitReceiptV1",
    "prepare_adoption_intent_v1", "prepare_activation_intent_v1",
    "prepare_model_adoption_intent_v2",
    "prepare_retirement_intent_v1", "submit_cache_transition_v1",
    "D13ProviderUsageV2", "D13AccountingV2", "account_d13_calls_v2",
)
