"""Stage natural final-admission evidence without minting dispatch authority.

W01 must call this inside its held Authority write fence and then build and
admit the complete graph/D11 bundle in that same SQLite transaction. A typed
candidate or locally matching checks is never a final claim.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import math

from ..domains.d08.execution import (
    ActionIntent, ActionSchema, BASE_REQUIRED_PROVIDERS, Goal,
    GoalExecutionProvider, GoalPredicate, RequiredCheckRegistry,
    RequiredCheckSpec,
)
from ..domains.d08.natural_final import (
    NaturalFinalCommunicationCandidateV2,
    natural_final_action_parameters_digest_v2,
)
from ..domains.d08.natural_plan import natural_route_semantic_digest_v2
from ..domains.d09 import D09ExpressionProvider
from ..domains.d09.natural_batch import (
    prepare_natural_verified_batch_proposal_v2,
    prepare_natural_verified_batch_proposal_v3,
)
from ..domains.d09.natural_reply import NaturalFinalActionCandidateV2
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import (
    CheckReceipt, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, VersionedRef, canonical_digest, canonical_serialize,
)
from .d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, RuntimeOutboxValue,
    job_graph_write, outbox_graph_write,
)
from .dispatch_candidate import natural_dispatch_segment_payload_ref_v2
from .issuers import BudgetLeaseGrant, ResourceQuote
from .jobs import PersistentJob
from .post_c02_reply_bundle_v2 import post_c02_dispatch_runtime_refs_v2
from .post_c02_reply_action_v2 import (
    CurrentReplyCheckVersionsV2, post_c02_reply_action_ids_v2,
)
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from .restore_anchor import RestoreAnchor


@dataclass(frozen=True, slots=True)
class NaturalFinalAdmissionStageV2:
    status: str
    missing: tuple[str, ...]
    action_digest: str | None
    grant_digest: str | None
    checks_digest: str | None


def inspect_natural_final_admission_v2(
    candidate: NaturalFinalCommunicationCandidateV2,
    schema: ActionSchema,
    checks: tuple[CheckReceipt, ...],
    *,
    now_utc: float,
) -> NaturalFinalAdmissionStageV2:
    """Check the proposed payload grant against five supplied check receipts.

    Receipt provenance, the current graph read, signed D11 quote/job, and the
    atomic final claim are unavailable to this pure helper. Even a complete
    local match therefore remains HOLD. W01 must reissue checks and pass its
    own full bundle to ``D11BudgetJobIssuer.admit_runtime`` in the same tx.
    """
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise ValueError("finite now_utc required")

    def hold(reason: str) -> NaturalFinalAdmissionStageV2:
        return NaturalFinalAdmissionStageV2("hold", (reason,), None, None, None)

    if (type(candidate) is not NaturalFinalCommunicationCandidateV2
            or type(schema) is not ActionSchema
            or type(checks) is not tuple
            or any(type(check) is not CheckReceipt for check in checks)):
        return hold("typed_final_candidate_and_checks_required")
    action = candidate.action_intent
    grant = candidate.communication_grant
    request = candidate.communication_request
    if (candidate.status != "candidate_hold_w01_final_admission"
            or action is None or grant is None or request is None
            or schema.schema_id != action.schema_id
            or schema.action_kind != action.action_kind
            or schema.required_checks != action.required_checks
            or schema.proactive
            or grant.action_id != action.action_id
            or grant.intent_revision != action.revision
            or grant.target_ref != action.target_ref
            or grant.purpose != action.purpose
            or grant.audiences != request.audiences
            or grant.required_slots != request.required_slots
            or grant.allowed_claim_kinds != request.allowed_claim_kinds
            or grant.promise_grants or request.promise_grants
            or grant.communication_action_id != request.communication_action_id
            or grant.contact_id != request.contact_id
            or grant.batch_revision != request.batch_revision
            or grant.cancellation_epoch != request.cancellation_epoch
            or len(grant.segment_grants) != 1
            or len(request.segment_specs) != 1
            or grant.segment_grants[0].effect_id != action.identity.effect_id
            or grant.segment_grants[0].payload_digest
               != request.segment_specs[0].payload_digest
            or grant.valid_until <= now_utc):
        return hold("final_action_or_payload_grant_mismatch")
    if (len(checks) != len(action.required_checks)
            or {check.check_kind for check in checks}
               != {spec.check_kind for spec in action.required_checks}
            or not set(BASE_REQUIRED_PROVIDERS).issubset({
                (spec.check_kind, spec.provider_id)
                for spec in action.required_checks
            })):
        return hold("five_current_required_checks_absent")
    refs = tuple("check:" + canonical_digest({
        "kind": spec.check_kind, "provider": spec.provider_id,
        "subject": spec.subject_ref, "action": spec.action_ref,
        "purpose": spec.purpose, "criteria_version": spec.criteria_version,
        "input_versions": spec.required_input_versions,
    }) for spec in action.required_checks)
    if grant.required_check_refs != refs:
        return hold("grant_required_check_refs_mismatch")
    registry = RequiredCheckRegistry()
    registry.register(schema)
    decision = registry.qualify(action, checks, now=now_utc)
    if (decision.status != "qualified"
            or decision.receipt_digest != grant.qualification_receipt_digest
            or decision.valid_until != grant.valid_until):
        return hold("five_check_qualification_or_grant_mismatch")
    return NaturalFinalAdmissionStageV2(
        "hold",
        ("w01_current_receipt_provenance", "d11_natural_final_bundle_admission",
         "graph_atomic_final_claim"),
        canonical_digest(action), canonical_digest(grant),
        decision.receipt_digest,
    )


__all__ = ["NaturalFinalAdmissionStageV2", "inspect_natural_final_admission_v2"]


@dataclass(frozen=True, slots=True)
class NaturalFinalBundleStageV2:
    status: str
    bundle: DomainBundle | None
    job_ref: str | None
    outbox_ref: str | None
    missing: tuple[str, ...]


def prepare_natural_final_bundle_v2(
    *, envelope: CommandEnvelope,
    final: NaturalFinalActionCandidateV2,
    candidate: NaturalFinalCommunicationCandidateV2,
    schema: ActionSchema,
    checks: tuple[CheckReceipt, ...],
    staged_d08: DomainProposal,
    quote: ResourceQuote,
    budget_grant: BudgetLeaseGrant,
    pre_reserved_job: PersistentJob,
    now_utc: float,
    semantic_plan=None,
    generation_output: dict | None = None,
    segment_index: int = 0,
) -> NaturalFinalBundleStageV2:
    """Assemble a natural-only D08/D09/D11 bundle for W01's same-tx admission.

    The caller must have already staged D08's four action atoms, issued five
    current receipts, and reserved the signed D11 job in its Authority write
    fence. The returned bundle is not a send permit; W01 must call the real
    issuer and commit its final graph claim before host handoff.
    """
    def hold(reason: str) -> NaturalFinalBundleStageV2:
        return NaturalFinalBundleStageV2("hold", None, None, None, (reason,))

    if (type(envelope) is not CommandEnvelope
            or type(final) is not NaturalFinalActionCandidateV2
            or type(candidate) is not NaturalFinalCommunicationCandidateV2
            or type(staged_d08) is not DomainProposal
            or type(quote) is not ResourceQuote
            or type(budget_grant) is not BudgetLeaseGrant
            or type(pre_reserved_job) is not PersistentJob):
        return hold("typed_final_transaction_material_required")
    assessed = inspect_natural_final_admission_v2(
        candidate, schema, checks, now_utc=now_utc)
    if assessed.action_digest is None or assessed.grant_digest is None:
        return hold("five_current_checks_or_payload_grant_hold")
    action, grant = candidate.action_intent, candidate.communication_grant
    if (final.material is None or action is None or grant is None
            or envelope.identity != action.identity
            or envelope.authority.purpose != "expression"
            or envelope.authority.audience != grant.audiences
            or envelope.parent_budget_lease_ref != budget_grant.lease_id
            or final.material.paid_receipt.parent_budget_lease_id
               != budget_grant.lease_id
            or final.material.final_activity_id != action.identity.activity_id
            or final.material.final_operation_id != action.identity.operation_id
            or final.material.final_effect_id != action.identity.effect_id
            or final.material.payload_digest
               != grant.segment_grants[0].payload_digest
            or not set(final.material.current_reads).issubset(
                set(envelope.version_guard.read_versions))
            or staged_d08.domain != "d08"
            or staged_d08.envelope != envelope
            or {write.key.type_name for write in staged_d08.typed_writes}
               != {"d08.goal.v1", "d08.action_intent.v1",
                   "d08.action_schema.v1", "d08.action_cancellation.v1"}
            or len(staged_d08.typed_writes) != 4):
        return hold("final_identity_or_staged_action_changed")
    natural = (prepare_natural_verified_batch_proposal_v3(
        final, grant, plan=semantic_plan, generation_output=generation_output,
        segment_index=segment_index) if semantic_plan is not None else
        prepare_natural_verified_batch_proposal_v2(final, grant))
    if natural.write is None:
        return hold("natural_paid_verified_batch_hold")
    namespace, identity = envelope.authority.namespace, envelope.identity
    job_ref, outbox_ref, idempotency_key = post_c02_dispatch_runtime_refs_v2(
        namespace, identity)
    if ((quote.bot_id, quote.persona_id, quote.activity_id,
         quote.operation_id, quote.effect_id) != (
             *namespace.as_tuple, identity.activity_id,
             identity.operation_id, identity.effect_id)
            or quote.graph_job_ref != job_ref
            or quote.outbox_refs != (outbox_ref,)
            or quote.work_kind != "message"
            or quote.parent_budget_lease_ref != budget_grant.lease_id
            or quote.valid_until_utc <= now_utc
            or budget_grant.valid_until_utc <= now_utc
            or quote.deadline_utc != envelope.deadline_utc
            or envelope.version_guard.resource_lease_versions
               != (VersionedRef(quote.quote_id, quote.version),)
            or any(amount > budget_grant.max_ceiling.get(name, 0)
                   for name, amount in quote.ceiling.items())
            or (pre_reserved_job.job_id, pre_reserved_job.operation_id,
                pre_reserved_job.activity_id, pre_reserved_job.effect_id,
                pre_reserved_job.bot_id, pre_reserved_job.persona_id,
                pre_reserved_job.work_kind, pre_reserved_job.budget_ref)
               != (AtomKey.from_token(job_ref).name, identity.operation_id,
                   identity.activity_id, identity.effect_id,
                   *namespace.as_tuple, "message", budget_grant.lease_id)
            or pre_reserved_job.phase != "waiting"
            or pre_reserved_job.fence != 0
            or pre_reserved_job.cancel_epoch != 0
            or pre_reserved_job.result_ref is not None):
        return hold("signed_final_quote_or_reserved_job_changed")
    grant_key = AtomKey(Owner("activity", *namespace.as_tuple,
                              identity.activity_id),
                        "d08.communication_intent_grant.v1", grant.grant_id)
    keys = (grant_key, natural.write.key, AtomKey.from_token(job_ref),
            AtomKey.from_token(outbox_ref))
    reads = {row.key: row.revision for row in envelope.version_guard.read_versions}
    if len(reads) != len(envelope.version_guard.read_versions) or any(
            reads.get(key, 0) != 0 for key in keys):
        return hold("final_graph_heads_not_absent")
    extra = tuple(GraphVersion(key, 0) for key in keys if key not in reads)
    bundle_envelope = replace(envelope, version_guard=replace(
        envelope.version_guard,
        read_versions=envelope.version_guard.read_versions + extra))
    try:
        d08 = GoalExecutionProvider().validate(replace(
            staged_d08, envelope=bundle_envelope,
            typed_writes=staged_d08.typed_writes + (GraphWrite(
                grant_key, json.loads(canonical_serialize(asdict(grant)))),)))
        d09 = D09ExpressionProvider().validate(DomainProposal(
            "d09", "d09.proposal.v1",
            D09ExpressionProvider().descriptor.request_schema_hash,
            bundle_envelope, (natural.write,), DependencySet(), (), (),
        ))
        outbox = RuntimeOutboxValue(
            *namespace.as_tuple, identity.activity_id, identity.operation_id,
            identity.effect_id, AtomKey.from_token(outbox_ref).name,
            AtomKey.from_token(job_ref).name, job_ref,
            natural_dispatch_segment_payload_ref_v2(natural.write.key.token,
                                                  natural.write.value["segment"]["position"]),
            idempotency_key, "pending", envelope.authority.activation_generation,
        )
        d11 = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
            bundle_envelope, (job_graph_write(pre_reserved_job),
                              outbox_graph_write(outbox, AtomKey.from_token(job_ref))),
            DependencySet(current_invalidation=(GraphVersion(
                AtomKey.from_token(job_ref), 0),)),
            ("natural-reply:" + identity.operation_id,), (),
        )
        bundle = DomainBundle(
            bundle_envelope, (d08, d09, d11), (), (), (), (),
            (idempotency_key,), (job_ref,), (outbox_ref,),
        )
    except (TypeError, ValueError):
        return hold("natural_final_bundle_invalid")
    return NaturalFinalBundleStageV2(
        "candidate_hold_w01_final_admission", bundle, job_ref, outbox_ref,
        ("w01_current_authority_and_source_route_recheck",
         "d11_admit_runtime_same_transaction",
         "graph_atomic_final_claim"),
    )


__all__ += ["NaturalFinalBundleStageV2", "prepare_natural_final_bundle_v2"]


@dataclass(frozen=True, slots=True)
class NaturalFinalActionStageV2:
    status: str
    goal: Goal | None
    intent: ActionIntent | None
    schema: ActionSchema | None
    proposal: DomainProposal | None
    missing: tuple[str, ...]


def prepare_natural_final_action_stage_v2(
    *, envelope: CommandEnvelope,
    final: NaturalFinalActionCandidateV2,
    current_check_versions: CurrentReplyCheckVersionsV2,
    route_binding: CurrentReplyEntityRouteBindingV2,
    quote: ResourceQuote,
    grant: BudgetLeaseGrant,
    anchor: RestoreAnchor,
    now_utc: float,
    semantic_segment: bool = False,
) -> NaturalFinalActionStageV2:
    """Stage a fresh natural action and five specs, never their PASS receipts.

    W01 alone authenticates the E+1 query/route/check version sets and issues
    the five provider receipts in its held Authority transaction.
    """
    def hold(reason: str) -> NaturalFinalActionStageV2:
        return NaturalFinalActionStageV2("hold", None, None, None, None,
                                         (reason,))

    if (type(envelope) is not CommandEnvelope
            or type(final) is not NaturalFinalActionCandidateV2
            or final.status != "candidate_hold_w01_final_admission"
            or final.material is None
            or type(current_check_versions) is not CurrentReplyCheckVersionsV2
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(quote) is not ResourceQuote
            or type(grant) is not BudgetLeaseGrant
            or type(anchor) is not RestoreAnchor
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("typed_current_natural_action_inputs_required")
    material = final.material
    namespace = envelope.authority.namespace
    goal_id, action_id, schema_id = post_c02_reply_action_ids_v2(
        material.c02_operation_id, material.source_ref.ref)
    if semantic_segment:
        digest = canonical_digest({"schema": "sylanne.d08.natural-bubble-actions.v3",
            "parent_original_id": material.c02_operation_id,
            "source_ref": material.source_ref.ref, "operation_id": material.final_operation_id,
            "effect_id": material.final_effect_id})
        goal_id, action_id, schema_id = (prefix + digest for prefix in ("goal:", "action:", "schema:"))
    if (envelope.identity.activity_id != material.final_activity_id
            or envelope.identity.operation_id != material.final_operation_id
            or envelope.identity.effect_id != material.final_effect_id
            or envelope.authority.purpose != "expression"
            or envelope.authority.audience != (material.audience_id,)
            or envelope.parent_budget_lease_ref != grant.lease_id
            or not now_utc < envelope.deadline_utc
            or material.paid_receipt.verdict != "pass"
            or material.paid_receipt.namespace != namespace
            or material.paid_receipt.parent_budget_lease_id != grant.lease_id
            or material.route_binding_digest
               != natural_route_semantic_digest_v2(route_binding)
            or (route_binding.namespace, route_binding.c02_operation_id,
                route_binding.source_ref, route_binding.conversation_ref,
                route_binding.scene_ref) != (
                    namespace, material.c02_operation_id,
                    material.source_ref.ref, material.audience_id,
                    material.scene_id)
            or route_binding.target_entity_ref == ""
            or route_binding.valid_until_utc is not None
               and route_binding.valid_until_utc <= now_utc
            or material.source_ref.ref not in envelope.input_refs
            or material.source_ref.ref not in envelope.source_qualification.source_refs
            or not set(material.current_reads).issubset(
                set(envelope.version_guard.read_versions))
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id, quote.effect_id,
                quote.parent_budget_lease_ref) != (
                    *namespace.as_tuple, material.final_activity_id,
                    material.final_operation_id, material.final_effect_id,
                    grant.lease_id)
            or quote.work_kind != "message"
            or quote.work_kind not in grant.allowed_work_kinds
            or quote.valid_until_utc <= now_utc
            or grant.valid_until_utc <= now_utc
            or quote.deadline_utc != envelope.deadline_utc
            or anchor.execution_seq < 0):
        return hold("natural_final_identity_route_or_budget_changed")
    inputs = current_check_versions
    if (inputs.namespace != namespace
            or inputs.source_ref != material.source_ref.ref
            or inputs.quote_id != quote.quote_id
            or inputs.quote_version != quote.version
            or inputs.grant_id != grant.grant_id
            or inputs.grant_version != grant.version
            or len(inputs.sets) != len(BASE_REQUIRED_PROVIDERS)
            or {row.check_kind for row in inputs.sets}
               != {kind for kind, _ in BASE_REQUIRED_PROVIDERS}
            or not inputs.reservation_digest):
        return hold("five_current_check_version_sets_required")
    by_kind = {row.check_kind: row for row in inputs.sets}
    specs = []
    for kind, provider in BASE_REQUIRED_PROVIDERS:
        row = by_kind[kind]
        if (not row.criteria_ref or not row.versions
                or row.criteria_ref not in {part.ref for part in row.versions}
                or len({part.ref for part in row.versions}) != len(row.versions)):
            return hold("five_current_check_version_sets_required")
        specs.append(RequiredCheckSpec(
            kind, provider, f"persona:{namespace.persona_id}", action_id,
            "expression", row.criteria_ref, row.versions))
    predicate = GoalPredicate(
        "communicated", "d11.delivery", (),
        float(envelope.source_qualification.learned_at),
        float(envelope.deadline_utc))
    goal = Goal(goal_id, 1, "active", predicate,
                (material.source_ref.ref,), (), None, (), ())
    source_refs = tuple(dict.fromkeys((material.source_ref.ref, *(
        ref for claim in material.claims for ref in claim.source_refs))))
    intent = ActionIntent(
        action_id, 1, goal_id, (), route_binding.target_entity_ref,
        "communication", "expression", "limited",
        natural_final_action_parameters_digest_v2(material),
        envelope.identity, schema_id, tuple(specs), predicate,
        (material.final_effect_id,), None, source_refs)
    schema = ActionSchema(schema_id, "communication", False, tuple(specs))
    d08 = GoalExecutionProvider()
    try:
        proposal = DomainProposal(
            "d08", "d08.proposal.v1", d08.descriptor.request_schema_hash,
            envelope, (), DependencySet(), (), (),
        )
        proposal = d08.prepare_goal_candidate(
            proposal, goal, source_ref=material.source_ref.ref)
        proposal = d08.prepare_action_candidate(proposal, intent, schema)
    except (TypeError, ValueError):
        return hold("natural_final_action_graph_stage_invalid")
    return NaturalFinalActionStageV2(
        "candidate_hold_w01_current_five_checks", goal, intent, schema,
        proposal, ("w01_reissue_five_checks_e_plus_one", "d11_final_admission"),
    )


__all__ += ["NaturalFinalActionStageV2", "prepare_natural_final_action_stage_v2"]
