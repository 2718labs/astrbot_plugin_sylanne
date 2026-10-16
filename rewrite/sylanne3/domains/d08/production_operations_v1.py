"""Evidence-bound D08 bilateral acknowledgement and joint-plan adoption."""
from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphWrite, Owner
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, StagedDomainOperationV1
from ..d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from .commitment_acknowledgement import (
    BilateralAcknowledgementReadV1, prepare_coordinator_bilateral_acknowledgement_write_v1,
)
from .execution import ActionOutcome, GoalExecutionProvider, JointPlan, OutcomeSettlement, RequiredCheckSpec
from ...runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class RecheckCurrentActionRequestV1:
    action_intent_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1":
            raise ValueError("D08 recheck needs an actual current action intent")


@dataclass(frozen=True, slots=True)
class SettleCurrentObservedActionRequestV1:
    action_intent_ref: str
    outbound_receipt_ref: str
    cost_settlement_ref: str

    def __post_init__(self):
        if (AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1"
                or AtomKey.from_token(self.cost_settlement_ref).type_name != "runtime.cost_settlement"):
            raise ValueError("action settlement requires its actual intent and paid D11 cost")
        require_locator_v1(self.outbound_receipt_ref, "outbound_receipt_ref")


def observed_action_outcome_key_v1(action_key, intent):
    return AtomKey(action_key.owner, "d08.action_outcome.v1", "outcome:" + canonical_digest(
        (action_key.owner, intent.action_id, intent.identity.effect_id, intent.identity.attempt_id))[:48])


def compile_settle_current_observed_action_v1(frame, request, *, intent, outcome_key,
        outcome, observation_original, cost_original):
    if (type(request) is not SettleCurrentObservedActionRequestV1
            or type(outcome) is not ActionOutcome or outcome_key.name != outcome.outcome_id
            or observation_original.original_ref != request.outbound_receipt_ref
            or cost_original.original_ref != request.cost_settlement_ref):
        raise ValueError("action outcome differs from its actual settlement originals")
    settlement = OutcomeSettlement.from_outcome(intent, outcome)
    provider = GoalExecutionProvider()
    stage = stage_result_v1(frame, "d08", "settle_observed_action", request,
        writes=(GraphWrite(outcome_key, plain_v1(outcome), ()),),
        provenance={"conditioned_source_roots":frame.envelope.source_qualification.source_refs,"conditioned_original_deadline_utc":frame.envelope.deadline_utc,
            "action_outcome": outcome, "outcome_settlement": settlement,
            "observation_original": observation_original, "cost_original": cost_original},
        contribution_keys=("d08-observed-outcome:" + canonical_digest((outcome.outcome_id,
            observation_original.original_digest, cost_original.original_digest)),),
        receiver_events=(("d10", "action_outcome_observed_requires_current_life_qualification"),
            ("d01","general_growth_action_outcome_available"),("d07","conditioned_observed_outcome_committed_v1")),
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage


@dataclass(frozen=True, slots=True)
class CurrentActionRecheckInputsV1:
    recovery: object
    commitment_check: object
    boundary_check: object
    required_specs: tuple[object, ...]
    actual_originals: tuple[ProductionOriginalRefV1, ...]
    missing_originals: tuple[str, ...]


def compile_recheck_current_action_v1(frame, request, inputs):
    if type(request) is not RecheckCurrentActionRequestV1 or type(inputs) is not CurrentActionRecheckInputsV1:
        raise TypeError("D08 recheck needs exact current request and installed inputs")
    from .action_recovery import CurrentActionRecoveryCandidateV1
    from ..d05.relationship import BoundaryCheck
    from ...runtime_contracts import CheckReceipt
    if (type(inputs.recovery) is not CurrentActionRecoveryCandidateV1
            or type(inputs.commitment_check) is not CheckReceipt or type(inputs.boundary_check) is not BoundaryCheck
            or any(type(spec) is not RequiredCheckSpec for spec in inputs.required_specs)):
        raise TypeError("D08 recheck result contains an unregistered check shape")
    missing = inputs.missing_originals
    return stage_result_v1(frame, "d08", "recheck_action", request,
        provenance={"action_recovery": inputs.recovery, "commitment_check": inputs.commitment_check,
            "boundary_check": inputs.boundary_check, "required_specs": inputs.required_specs,
            "actual_originals": inputs.actual_originals,
            "admission": "requires_fresh_d11_dispatch_admission"},
        coverage="waiting_for_original" if missing else "complete", missing=missing,
        continuation="d08-action-recheck:" + canonical_digest(request.action_intent_ref)[:48]
            if missing else None)


@dataclass(frozen=True, slots=True)
class AcknowledgeCurrentBilateralRequestV1:
    commitment_ref: str
    inbound_source_ref: str
    outbound_receipt_ref: str
    acceptance_interpretation_ref: str

    def __post_init__(self):
        for name in ("commitment_ref", "inbound_source_ref", "outbound_receipt_ref", "acceptance_interpretation_ref"):
            require_locator_v1(getattr(self, name), name)
        if AtomKey.from_token(self.commitment_ref).type_name != "d08.commitment.v1":
            raise ValueError("bilateral acknowledgement requires a current commitment head")
        if AtomKey.from_token(self.inbound_source_ref).type_name != "memory.source":
            raise ValueError("bilateral acknowledgement requires an actual inbound D06 source")


@dataclass(frozen=True, slots=True)
class AdoptCurrentJointPlanRequestV1:
    joint_plan_proposal_ref: str
    party_consent_original_refs: tuple[str, ...]

    def __post_init__(self):
        require_locator_v1(self.joint_plan_proposal_ref, "joint_plan_proposal_ref")
        if (type(self.party_consent_original_refs) is not tuple
                or not 2 <= len(self.party_consent_original_refs) <= 16
                or len(set(self.party_consent_original_refs)) != len(self.party_consent_original_refs)):
            raise ValueError("joint plan needs bounded distinct actual party consent originals")
        for ref in self.party_consent_original_refs:
            require_locator_v1(ref, "party consent")


@dataclass(frozen=True, slots=True)
class CurrentBilateralInputsV1:
    read: BilateralAcknowledgementReadV1
    acceptance_original: ProductionOriginalRefV1
    outbound_original: ProductionOriginalRefV1
    actor_original: ProductionOriginalRefV1


@dataclass(frozen=True, slots=True)
class CurrentJointPlanInputsV1:
    plan: JointPlan
    proposal_original: ProductionOriginalRefV1
    consent_originals: tuple[ProductionOriginalRefV1, ...]
    terms_digest: str
    current_goal_refs: tuple[str, ...]
    boundary_originals: tuple[ProductionOriginalRefV1, ...]


class _BoundBilateralReadVerifierV1:
    """Pure consistency verifier for an independently reread installed input."""
    def __init__(self, read):
        self.read = read

    def __call__(self, value):
        return value == self.read


def compile_acknowledge_current_bilateral_v1(frame, request, inputs):
    if type(request) is not AcknowledgeCurrentBilateralRequestV1 or type(inputs) is not CurrentBilateralInputsV1:
        raise TypeError("exact bilateral request and independently read inputs required")
    read = inputs.read
    if (read.namespace != frame.envelope.authority.namespace or read.commitment_head.key.token != request.commitment_ref
            or read.inbound_source.key.token != request.inbound_source_ref
            or read.outbound_receipt.ref != request.outbound_receipt_ref):
        raise ValueError("bilateral current evidence belongs to another request")
    candidate, write = prepare_coordinator_bilateral_acknowledgement_write_v1(read,
        read_verifier=_BoundBilateralReadVerifierV1(read))
    provider = GoalExecutionProvider()
    return stage_result_v1(frame, "d08", "acknowledge_bilateral", request, writes=(write,),
        provenance={"acknowledgement": candidate, "read": read, "acceptance": inputs.acceptance_original,
            "outbound": inputs.outbound_original, "actor": inputs.actor_original},
        contribution_keys=("d08-bilateral-ack:" + candidate.commitment.commitment_id + ":" + str(candidate.commitment.revision),),
        receiver_events=(("d10", "bilateral_commitment_established"),),
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)


def compile_adopt_current_joint_plan_v1(frame, request, inputs):
    if type(request) is not AdoptCurrentJointPlanRequestV1 or type(inputs) is not CurrentJointPlanInputsV1:
        raise TypeError("exact joint plan request and current originals required")
    plan, ns = inputs.plan, frame.envelope.authority.namespace
    if (inputs.proposal_original.original_ref != request.joint_plan_proposal_ref
            or {original.original_ref for original in inputs.consent_originals} != set(request.party_consent_original_refs)):
        raise ValueError("joint plan proposal/party consent originals differ")
    owners = {node.owner_ref for node in plan.nodes}
    participants = {acceptance.participant_ref for acceptance in plan.acceptances}
    if len(participants) < 2 or participants != owners or len(participants) != len(plan.acceptances):
        raise ValueError("joint plan needs one exact consent for every participating node owner")
    for participant in owners:
        owned_nodes = {node.node_id for node in plan.nodes if node.owner_ref == participant}
        acceptance = next(item for item in plan.acceptances if item.participant_ref == participant)
        if not owned_nodes <= set(acceptance.accepted_scope):
            raise ValueError("party did not consent to all their concrete plan responsibilities")
    owner = Owner("activity", *ns.as_tuple, frame.envelope.identity.activity_id)
    write = GraphWrite(AtomKey(owner, "d08.joint_plan.v1", plan.plan_id), plain_v1(plan),
                       tuple(AtomKey.from_token(ref) for ref in plan.source_refs))
    provider = GoalExecutionProvider()
    stage = stage_result_v1(frame, "d08", "adopt_joint_plan", request, writes=(write,),
        provenance={"plan": plan, "proposal": inputs.proposal_original, "consents": inputs.consent_originals,
            "terms_digest": inputs.terms_digest, "current_goals": inputs.current_goal_refs,
            "current_boundaries": inputs.boundary_originals,
            "execution": "each_effect_requires_separate_current_action_and_required_checks"},
        contribution_keys=("d08-joint-plan:" + plan.plan_id + ":" + str(plan.revision),),
        receiver_events=(("d10", "joint_plan_adopted_requires_activity_qualification"),
                         ("d08", "joint_plan_adopted_requires_next_node_action")),
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage


def verify_d08_production_stage_v1(stage):
    if type(stage) is not StagedDomainOperationV1 or stage.domain != "d08" or stage.operation_kind not in {
            "acknowledge_bilateral", "adopt_joint_plan", "recheck_action", "settle_observed_action"}:
        raise ValueError("unregistered D08 current operation")
    provider = GoalExecutionProvider()
    specs = {spec.name: spec for spec in provider.register_types()}
    for proposal in stage.proposals:
        if (proposal.proposal_schema != "d08.proposal.v1"
                or proposal.proposal_schema_hash != provider.descriptor.request_schema_hash):
            raise ValueError("D08 current proposal schema differs")
        if stage.operation_kind == "acknowledge_bilateral":
            if len(proposal.typed_writes) != 1:
                raise ValueError("bilateral sanctioned transition must write exactly one commitment")
            write = proposal.typed_writes[0]
            if write.key.type_name != "d08.commitment.v1" or write.value["establishment_state"] != "acknowledged":
                raise ValueError("bilateral transition contains another write")
            specs[write.key.type_name].validator(write.value)
        elif stage.operation_kind == "settle_observed_action":
            if len(proposal.typed_writes) != 1 or proposal.typed_writes[0].key.type_name != "d08.action_outcome.v1":
                raise ValueError("observed action settlement must write its one actual outcome")
            provider.validate(proposal)
        else:
            if len(proposal.typed_writes) != 1 or proposal.typed_writes[0].key.type_name != "d08.joint_plan.v1":
                raise ValueError("joint-plan transition contains another write")
            provider.validate(proposal)
    return stage


D08_PRODUCTION_WRITE_TYPES_V1 = frozenset({"d08.commitment.v1", "d08.joint_plan.v1", "d08.action_outcome.v1"})
