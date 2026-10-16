"""Actual D07 evaluation originals -> current D05 Graph revision, no auxiliary ledger."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d05.relationship import RelationshipProvider
from ..domains.d05.relationship_revision_v2 import (
    RelationshipScopeV2, RelationshipEvaluationCandidateV2, InstalledRelationshipPolicyV2,
    RelationshipCheckpointV2, InteractionContributionV3, DimensionEstimateV2, RelationshipProfileV2,
    RelationshipExpectationV2, ReciprocityPatternV2, RepairProcessV2, rebuild_relationship_dimension_v2,
    PROFILE_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE, CHECKPOINT_TYPE, EXPECTATION_TYPE, RECIPROCITY_TYPE,
    REPAIR_TYPE, REVISION_OPERATION,
)
from ..domains.d05.production_operations_v1 import AdoptCurrentRelationshipContributionRequestV1
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..memory_types import access_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, waiting_stage_v1, production_read_plan_v1, raw_head_value_v1
from .d05_production_operations_v1 import InstalledD05ProductionReadersV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1


@dataclass(frozen=True, slots=True)
class AdoptCurrentRelationshipRevisionRequestV2:
    interpretation_ref: str
    policy_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.interpretation_ref).type_name != "d07.current_interpretation.v1" or not self.policy_ref:
            raise ValueError("relationship revision accepts only the actual D07 adopted interpretation locator")


INITIALIZE_OPERATION = "initialize_relationship_prior_v2"


@dataclass(frozen=True, slots=True)
class InitializeCurrentRelationshipPriorRequestV2:
    scope: RelationshipScopeV2
    policy_ref: str

    def __post_init__(self):
        if type(self.scope) is not RelationshipScopeV2 or type(self.policy_ref) is not str or not self.policy_ref:
            raise ValueError("relationship prior initialization accepts exact scope and installed policy locator")


def relationship_evaluation_question_scope_v2(scope, trigger_original_ref, policy_ref, policy_digest):
    return "d05.relationship-evaluation:" + canonical_digest((scope, trigger_original_ref, policy_ref, policy_digest))


def relationship_reassessment_question_scope_v2(scope, policy_ref, policy_digest, previous_head, previous_checkpoint_ref, basis_versions):
    return "d05.relationship-checkpoint-reassessment:" + canonical_digest((scope, policy_ref, policy_digest,
        previous_head, previous_checkpoint_ref, basis_versions))


def repair_response_question_scope_v2(repair):
    return "d05.repair-response:" + canonical_digest((repair.scope, repair.dispute_ref, repair.action_kind,
        repair.communication_original_ref, repair.communication_action_ref, repair.communication_effect_id))


def expectation_acceptance_question_scope_v2(expectation):
    return "d05.relationship-expectation:" + canonical_digest((expectation.scope, expectation.expectation_ref,
        expectation.expectation, expectation.intensity, expectation.commitment_ref))


def _decode_candidate(value):
    return decode_typed_production_value_v1(json.loads(value["proposition"]), RelationshipEvaluationCandidateV2)


def _scope_heads(read, db, scope):
    atom = read.head(db, scope.subject_head.key, required=True)
    if (GraphVersion(atom.key, atom.revision) != scope.subject_head or atom.value["entity_id"] != scope.subject_entity_ref
            or atom.value["status"] != "active"):
        raise MissingProductionOriginalV1("current_canonical_relationship_subject_version")
    evidence = tuple(atom.value["creation_evidence_refs"])
    roots = tuple(ref for ref in evidence if AtomKey.from_token(ref).type_name == "memory.source")
    read.source_family(db, roots)
    for ref in evidence:
        if AtomKey.from_token(ref).type_name != "memory.source":
            read.head(db, ref, required=True)
            read.original(ref)
    if scope.context_head is not None:
        context = read.head(db, scope.context_head.key, required=True)
        if GraphVersion(context.key, context.revision) != scope.context_head or context.key.token != scope.context_ref:
            raise MissingProductionOriginalV1("current_relationship_context_version")
        if context.key.type_name == "d03.role_binding":
            if (context.value["status"] != "active" or context.value["subject_persona_ref"] != "persona:" + scope.namespace.persona_id
                    or context.value["target_entity_ref"] not in {None, scope.subject_entity_ref}
                    or context.value["effective_from"] > read.frame.now_utc
                    or (context.value["effective_until"] is not None and read.frame.now_utc >= context.value["effective_until"])):
                raise MissingProductionOriginalV1("current_optional_relationship_role_context")
        roots = (context.key.token,) if context.key.type_name == "memory.source" else tuple(context.value["source_refs"])
        read.source_family(db, roots)

    return atom


def _scope_source_refs_v2(db, read, scope):
    subject = read.head(db, scope.subject_head.key, required=True)
    roots = [ref for ref in subject.value["creation_evidence_refs"] if AtomKey.from_token(ref).type_name == "memory.source"]
    if scope.context_head is not None:
        context = read.head(db, scope.context_head.key, required=True)
        roots.extend((context.key.token,) if context.key.type_name == "memory.source" else context.value["source_refs"])
    return tuple(dict.fromkeys(roots))


def _counterparty_response_sources_v2(db, read, interpretation, subject):
    from .ingress_observation import read_committed_ingress_identity
    records = read.source_family(db, tuple(interpretation.value["source_refs"]))
    bindings = read.complete_inventory(db, "d03.account_binding")
    matched = []
    for ref in interpretation.value["source_refs"]:
        record = records[ref]
        ingress = read_committed_ingress_identity(db, read.frame.envelope.authority.namespace, record.source_id)
        if ingress is None:
            continue
        identity = json.loads(ingress.identity_json)
        if any(atom.valid and atom.value["valid_from"] <= read.frame.now_utc
                and (atom.value["valid_until"] is None or read.frame.now_utc <= atom.value["valid_until"])
                and atom.value["entity_id"] == subject
                and atom.value["platform_identifier"] == identity["sender_ref"]
                and atom.value["platform_namespace"] == identity["platform_ref"] for atom in bindings):
            read.actor_entity(db, ref, expected_entity=subject)
            matched.append(ref)
    if not matched:
        raise MissingProductionOriginalV1("actual_current_scoped_counterparty_response_source")
    return tuple(matched)


def _semantic(read, db, ref):
    atom = read.head(db, ref, required=True)
    actual, original, _ = read.adopted_interpretation(db, ref, question_scope=atom.value["question_key"])
    history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (actual.key.token, actual.revision)).fetchone()
    operation = read.committed_operation(db, history[0])
    return actual, original, operation[2]


def _require_relationship_auxiliary_budget_v2(db, read, interpretation_ref, policy, issuer):
    from .d07_execution_v1 import TABLE, read_d07_original_v1, read_prepared_d07_execution_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_model_egress_wire import from_wire
    original = read_d07_original_v1(db, issuer, read.frame.envelope.authority.namespace, "adopted", interpretation_ref)
    if original is None:
        raise MissingProductionOriginalV1("actual_relationship_D07_model_adoption_and_auxiliary_budget")
    raw = original[0]
    interpretation = read.head(db, interpretation_ref, required=True)
    if (raw["schema"] != "d07.actual-cognition-adoption.v1" or raw["interpretation_ref"] != interpretation_ref
            or raw["interpretation_revision"] != interpretation.revision
            or raw["interpretation_value_digest"] != canonical_digest(interpretation.value)
            or raw["question_scope"] != interpretation.value["question_key"]):
        raise ValueError("relationship auxiliary original differs from this exact current interpretation adoption")
    operation = read.committed_operation(db, raw["adoption_operation_id"])
    if canonical_digest(json.loads(operation[1])) != raw["graph_receipt_digest"]:
        raise ValueError("relationship auxiliary adoption lost its actual W01 receipt")
    heads = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND payload_digest=? LIMIT 2",
        (*read.frame.envelope.authority.namespace.as_tuple, raw["prepared_digest"])).fetchall()
    if len(heads) != 1:
        raise MissingProductionOriginalV1("unique_relationship_D07_preparation_original")
    prepared = read_prepared_d07_execution_v1(db, issuer, read.frame.envelope.authority.namespace, heads[0][0])
    result = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if prepared.digest != raw["prepared_digest"] or result is None or result[1] != raw["actual_result_digest"]:
        raise ValueError("relationship auxiliary adoption changed its actual preparation/result original")
    sealed = read_d07_original_v1(db, issuer, prepared.namespace, "call", prepared.job_id)
    if sealed is None:
        raise MissingProductionOriginalV1("actual_sealed_relationship_D07_auxiliary_call")
    intent = from_wire(sealed[0], ModelEgressIntentV1)
    if intent.budget_lease_id != read.frame.envelope.parent_budget_lease_ref:
        raise MissingProductionOriginalV1("same_original_relationship_parent_budget")
    lease = get_budget_lease(db, intent.budget_lease_id)
    require_budget_family_admissible(db, intent.budget_lease_id)
    if (lease.bot_id, lease.persona_id) != prepared.namespace.as_tuple:
        raise ValueError("relationship auxiliary call belongs to another actual budget namespace")
    from .d07_execution_v1 import D07RelationshipPreparedV2
    from .foreground_call_plan_v1 import SLOTS, require_current_relationship_c3_cycle_v2
    from .foreground_cycle_v1 import read_observed_foreground_call_plan_v1
    if type(prepared) is not D07RelationshipPreparedV2:
        raise MissingProductionOriginalV1("actual_named_relationship_shared_C3_preparation")
    cycle_head = read.head(db, prepared.cycle_ref.key, required=True)
    _, cycle, revision = require_current_relationship_c3_cycle_v2(db, namespace=prepared.namespace,
        prepared=prepared, issuer=issuer)
    if cycle_head.revision != revision:
        raise ValueError("Relationship shared CallPlan is outside its actual current frame")
    observed = read_observed_foreground_call_plan_v1(db, namespace=prepared.namespace, continuation=cycle, issuer=issuer)
    attempts = tuple(row for row in observed.attempts if row.call_id == prepared.call_id)
    if len(attempts) != 1 or attempts[0].slot != "C3" or attempts[0].state != "completed":
        raise MissingProductionOriginalV1("actual_completed_relationship_registered_shared_C3")
    if sum(SLOTS[row.slot][3] for row in observed.attempts) > policy.max_auxiliary_calls:
        raise MissingProductionOriginalV1("relationship_shared_auxiliary_call_cap")



def _candidate(db, read, request, readers):
    interpretation = read.head(db, request.interpretation_ref, required=True)
    candidate = _decode_candidate(interpretation.value)
    scope = candidate.scope
    if scope.namespace != read.frame.envelope.authority.namespace:
        raise ValueError("relationship evaluation belongs to another directed namespace")
    semantic, semantic_original, sequence = _semantic(read, db, request.interpretation_ref)
    policy, policy_original = readers._policy(db, read, request.policy_ref)
    if type(policy) is not InstalledRelationshipPolicyV2:
        raise MissingProductionOriginalV1("needs_policy:installed_relationship_numeric_v2")
    rule = policy.rule(scope)
    _require_relationship_auxiliary_budget_v2(db, read, request.interpretation_ref, policy, readers.issuer)
    if candidate.contribution_kind not in dict(rule.kind_bounds):
        raise MissingProductionOriginalV1("needs_policy:relationship_kind_bound")
    context_types = {"role": "d03.role_binding", "event": "d03.world_event", "source": "memory.source"}
    if (rule.context_kind == "installed" and scope.context_head is not None
            or rule.context_kind != "installed" and (scope.context_head is None or scope.context_head.key.type_name != context_types[rule.context_kind])):
        raise ValueError("relationship candidate changed its installed context definition/kind")
    if semantic.value["question_key"] != relationship_evaluation_question_scope_v2(scope, candidate.trigger_original_ref, request.policy_ref, policy_original.original_digest):
        raise ValueError("relationship evaluation original changed its actual scope/current policy version")
    if (not set(candidate.applicable_effects) <= set(rule.applicable_effects)
            or candidate.valid_from > read.frame.now_utc
            or (candidate.valid_until is not None and read.frame.now_utc >= candidate.valid_until)):
        raise MissingProductionOriginalV1("current_relationship_candidate_applicability")
    _scope_heads(read, db, scope)
    records = read.source_family(db, tuple(dict.fromkeys((*candidate.source_refs, *policy.policy_source_refs, *_scope_source_refs_v2(db, read, scope)))))
    if not set(candidate.source_refs) <= set(semantic.value["source_refs"]):
        raise ValueError("relationship candidate sources differ from its actual adopted D07 evaluation")
    for ref in candidate.support_refs + candidate.counter_refs:
        key = AtomKey.from_token(ref)
        if key.type_name == "memory.source":
            if ref not in records:
                raise ValueError("relationship support/counter source is outside the actual source closure")
        elif key.type_name == "d07.current_interpretation.v1":
            _semantic(read, db, ref)
        else:
            raise ValueError("relationship support and counterexamples need actual D06/D07 originals")
    for ref in candidate.interpretation_refs:
        _semantic(read, db, ref)
    for ref in candidate.affect_refs:
        atom = read.head(db, ref, required=True)
        if atom.key.type_name not in {"d04.feeling_state.v1", "d04.appraisal_bundle.v1", "d04.recollection_experience.v1"}:
            raise ValueError("relationship affect context has another writer")
        history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (atom.key.token, atom.revision)).fetchone()
        read.committed_operation(db, history[0])
    if candidate.contribution_kind == "administrative_edit":
        source = records.get(candidate.trigger_original_ref)
        if (source is None or source.source_kind != "authored" or policy.policy_origin != "authored"
                or candidate.initial_estimate is None or candidate.requested_delta is not None
                or (rule.authored_prior_source_ref, rule.authored_prior_estimate) != (candidate.trigger_original_ref, candidate.initial_estimate)
                or candidate.initial_origin_ref != candidate.trigger_original_ref):
            raise MissingProductionOriginalV1("independent_Owner_installed_prior_or_actual_scoped_administrative_edit")
        trigger = read.original(candidate.trigger_original_ref)
        identity, aliases = source.provenance_root, ()
        families = (source.provenance_root,)
    else:
        semantics = {"external_interaction": "external_observation", "internal_recollection": "recollection", "simulated_trial": "simulation"}[candidate.contribution_kind]
        inputs = readers.read_contribution(db, read.frame, AdoptCurrentRelationshipContributionRequestV1(
            candidate.trigger_original_ref, scope.subject_entity_ref, scope.dimension, semantics, request.policy_ref))
        trigger, identity, aliases = inputs.trigger_original, inputs.contribution.canonical_event_or_family_ref, inputs.contribution.legacy_alias_keys
        if not set(inputs.contribution.source_refs) <= set(candidate.source_refs):
            raise ValueError("relationship candidate omitted actual trigger content sources")
        if candidate.contribution_kind == "internal_recollection":
            from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
            _, identity = read_committed_recollection_original_v1(db, scope.namespace, candidate.trigger_original_ref)
        families = tuple(sorted({records[ref].provenance_root for ref in inputs.contribution.source_refs}))
    if len(families) > policy.max_families:
        raise MissingProductionOriginalV1("bounded_relationship_independent_families")
    return candidate, policy, policy_original, semantic_original, sequence, trigger, identity, aliases, families, records


def _validate_ancillary(db, read, candidate):
    from ..domains.d08.execution import ActionIntent, ActionOutcome, Commitment
    expectation, reciprocity, repair = candidate.expectation, candidate.reciprocity, candidate.repair
    if expectation is not None:
        accepted_sources = set()
        for ref in expectation.negotiated_interpretation_refs:
            atom, _, _ = _semantic(read, db, ref)
            if atom.value["question_key"] != expectation_acceptance_question_scope_v2(expectation) or atom.value["proposition"] != "accepted":
                raise ValueError("negotiated expectation lacks its actual scoped counterparty acceptance")
            accepted_sources.update(_counterparty_response_sources_v2(db, read, atom, candidate.scope.subject_entity_ref))
        if expectation.commitment_ref is not None:
            atom = read.head(db, expectation.commitment_ref, required=True)
            commitment = decode_typed_production_value_v1(atom.value, Commitment)
            if (commitment.subject_ref != "persona:" + candidate.scope.namespace.persona_id
                    or commitment.counterparty_ref != candidate.scope.subject_entity_ref
                    or commitment.semantic_scope != expectation_acceptance_question_scope_v2(expectation)
                    or commitment.establishment_state != "acknowledged"
                    or not set(commitment.acknowledged_refs) <= accepted_sources):
                raise MissingProductionOriginalV1("actual_same_matter_D08_acknowledged_commitment")
            read.source_family(db, commitment.source_refs)
    if reciprocity is not None:
        for ref in reciprocity.visible_sample_refs:
            atom = read.head(db, ref, required=True)
            if (atom.key.type_name != "d03.world_event" or atom.value["reality"] != "host_observed"
                    or candidate.scope.subject_entity_ref not in {row[0] for row in atom.value["participant_roles"]}
                    or not set(atom.value["source_refs"]) <= set(candidate.source_refs)):
                raise ValueError("reciprocity needs this subject's actual visible samples, never silence/simulation")
            read.source_family(db, tuple(atom.value["source_refs"]))
    if repair is not None:
        for ref in repair.proposal_interpretation_refs:
            atom, _, _ = _semantic(read, db, ref)
            if atom.value["question_key"] != "d05.repair-proposal:" + canonical_digest((repair.scope, repair.dispute_ref, repair.action_kind)):
                raise ValueError("repair proposal interpretation targets another matter")
        for ref in repair.response_interpretation_refs:
            atom, _, _ = _semantic(read, db, ref)
            if (repair.communication_original_ref is None or atom.value["question_key"] != repair_response_question_scope_v2(repair)
                    or atom.value["proposition"] not in {"accepted", "declined", "pause_requested"}):
                raise ValueError("repair response is not bound to this original dispute/action/effect")
            _counterparty_response_sources_v2(db, read, atom, candidate.scope.subject_entity_ref)
        intents = read.complete_inventory(db, "d08.action_intent.v1") if repair.practice_progress_refs or repair.communication_action_ref else ()
        for ref in repair.practice_progress_refs:
            atom = read.head(db, ref, required=True)
            if atom.key.type_name != "d08.action_outcome.v1":
                raise ValueError("repair practice requires an actual D08 outcome")
            outcome = decode_typed_production_value_v1(atom.value, ActionOutcome)
            matches = tuple(item for item in intents if item.valid and item.value["action_id"] == outcome.action_id
                and item.value["identity"]["effect_id"] == outcome.effect_id)
            if len(matches) != 1 or matches[0].value["target_ref"] != repair.scope.subject_entity_ref or repair.dispute_ref not in matches[0].value["effect_scope"]:
                raise ValueError("repair practice outcome is not this subject's actual scoped action")
            history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (atom.key.token, atom.revision)).fetchone()
            read.committed_operation(db, history[0])
            for observation in outcome.observation_refs: read.original(observation)
        for ref in repair.reevaluated_estimate_refs:
            atom = read.head(db, ref, required=True)
            estimate = decode_typed_production_value_v1(atom.value, DimensionEstimateV2)
            if estimate.scope.scope_id != repair.scope.scope_id or estimate.status != "current":
                raise ValueError("repair reevaluation cannot settle an unrelated dimension/matter")
        if repair.communication_original_ref is not None:
            action = read.head(db, repair.communication_action_ref, required=True)
            intent = decode_typed_production_value_v1(action.value, ActionIntent)
            if (intent.identity.effect_id != repair.communication_effect_id or intent.target_ref != repair.scope.subject_entity_ref
                    or intent.action_kind != repair.action_kind or repair.dispute_ref not in intent.effect_scope):
                raise ValueError("repair invitation is not its actual directed dispute/action/effect")
            observation, _ = read.adopted_outbound_observation(db, repair.communication_original_ref)
            from ..authority_service.v2_contract import ExecutionBindingV2
            platform = observation.pending.platform_observation
            if type(platform.binding) is not ExecutionBindingV2:
                raise MissingProductionOriginalV1("actual_v2_admitted_repair_action_observation")
            origin = platform.binding.origin
            if (origin.effect_id != repair.communication_effect_id or platform.outcome != repair.communication_state
                    or platform.binding.action_intent_digest != canonical_digest(intent)):
                raise ValueError("repair communication changed its actual original action/effect/outcome")
        for ref in repair.contact_basis_refs:
            atom = read.head(db, ref, required=True)
            if (atom.key.type_name != "d05.boundary_rule" or atom.value["target_entity_ref"] != repair.scope.subject_entity_ref
                    or not set(atom.value["source_refs"]) <= set(candidate.source_refs)):
                raise ValueError("repair contact basis is not an independently sourced current directed boundary")


def _record_dependencies_v2(db, read, scope, source_refs, extra_refs=()):
    records = read.source_family(db, tuple(dict.fromkeys((*source_refs, *_scope_source_refs_v2(db, read, scope)))))
    keys = (scope.subject_head.key, *((scope.context_head.key,) if scope.context_head is not None else ()), *(AtomKey.from_token(ref) for ref in extra_refs),
        *(key for ref, record in records.items() for key in (AtomKey.from_token(ref),
            access_key(*scope.namespace.as_tuple, record.source_id), source_correction_head_key(scope.namespace, record.source_id))))
    for key in keys: read.head(db, key)
    return tuple(dict.fromkeys(keys))


def stage_adopt_current_relationship_revision_in_transaction_v2(db, *, frame, request, installed_readers):
    if type(request) is not AdoptCurrentRelationshipRevisionRequestV2 or type(installed_readers) is not InstalledD05ProductionReadersV1:
        raise TypeError("relationship revision needs exact installed request/readers")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        candidate, policy, policy_original, semantic_original, sequence, trigger, identity, aliases, families, records = _candidate(db, read, request, installed_readers)
        scope, rule = candidate.scope, policy.rule(candidate.scope)
        all_roots = tuple(dict.fromkeys((*candidate.source_refs, *policy.policy_source_refs, *_scope_source_refs_v2(db, read, scope))))
        _validate_ancillary(db, read, candidate)
        inventory = {name: read.complete_inventory(db, name) for name in (PROFILE_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE,
            CHECKPOINT_TYPE, EXPECTATION_TYPE, RECIPROCITY_TYPE, REPAIR_TYPE)}
        estimate_key = scope.key(ESTIMATE_TYPE)
        previous_head = read.head(db, estimate_key)
        previous = decode_typed_production_value_v1(previous_head.value, DimensionEstimateV2) if previous_head.valid else None
        contribution_key = scope.key(CONTRIBUTION_TYPE, (candidate.contribution_kind, identity))
        original_head = read.head(db, contribution_key)
        original_contribution = decode_typed_production_value_v1(original_head.value, InteractionContributionV3) if original_head.revision else None
        provenance = {"evaluation": semantic_original, "policy": policy_original, "duplicate": False, "held_reason": None}
        if (original_head.valid and original_contribution.evaluation_interpretation_ref == request.interpretation_ref
                and previous is not None and original_contribution.checkpoint_ref == previous.checkpoint_ref):
            return stage_result_v1(frame, "d05", REVISION_OPERATION, request, provenance={**provenance, "duplicate": True})
        checkpoint_writes = []
        new_checkpoint = candidate.initial_estimate is not None
        if new_checkpoint:
            origin = records[candidate.initial_origin_ref]
            if origin.source_kind == "authored":
                if (rule.authored_prior_source_ref, rule.authored_prior_estimate) != (candidate.initial_origin_ref, candidate.initial_estimate):
                    raise MissingProductionOriginalV1("independent_installed_relationship_authored_prior")
            elif not rule.allow_evidence_initialization:
                raise MissingProductionOriginalV1("installed_relationship_evidence_initialization_policy")
            checkpoint_original = request.interpretation_ref
            checkpoint_extra = [request.interpretation_ref]
            if previous_head.revision:
                if (previous is not None and previous.status == "current" or not rule.allow_reassessment_checkpoint
                        or candidate.reassessment_interpretation_ref is None):
                    raise MissingProductionOriginalV1("actual_relationship_checkpoint_reassessment")
                actual_previous = GraphVersion(previous_head.key, previous_head.revision)
                if actual_previous not in candidate.reassessment_basis_versions:
                    raise ValueError("relationship reassessment omitted its actual previous estimate version")
                for version in candidate.reassessment_basis_versions:
                    atom = read.head(db, version.key)
                    if (GraphVersion(atom.key, atom.revision) != version or version.revision < 1
                            or version.key.type_name not in {ESTIMATE_TYPE, "memory.access", "d06.source_correction_head.v1"}):
                        raise ValueError("relationship reassessment basis differs from its actual invalidation/current heads")
                prior_checkpoint = previous_head.value.get("checkpoint_ref")
                reset, _, _ = _semantic(read, db, candidate.reassessment_interpretation_ref)
                expected = relationship_reassessment_question_scope_v2(scope, policy.policy_ref, policy_original.original_digest,
                    actual_previous, prior_checkpoint, candidate.reassessment_basis_versions)
                if reset.value["question_key"] != expected or reset.value["proposition"] != "accepted":
                    raise ValueError("relationship checkpoint reset lacks its exact current adopted reassessment")
                checkpoint_original = candidate.reassessment_interpretation_ref
                checkpoint_extra.append(checkpoint_original)
            elif candidate.reassessment_interpretation_ref is not None:
                raise ValueError("unknown initial relationship cannot claim a previous-state reassessment")
            checkpoint_key = scope.key(CHECKPOINT_TYPE, checkpoint_original)
            if read.head(db, checkpoint_key).revision:
                raise MissingProductionOriginalV1("relationship_initialization_or_reassessment_original_already_consumed")
            origin_head = read.head(db, candidate.initial_origin_ref, required=True)
            checkpoint = RelationshipCheckpointV2(scope, candidate.initial_estimate, candidate.initial_origin_ref,
                checkpoint_original, "reassessment" if previous_head.revision else "evaluation_prior",
                GraphVersion(origin_head.key, origin_head.revision), canonical_digest(origin_head.value),
                policy.policy_ref, policy_original.original_digest, all_roots, checkpoint_key.token)
            dependencies = _record_dependencies_v2(db, read, scope,
                checkpoint.source_refs, checkpoint_extra)
            checkpoint_writes.append(GraphWrite(checkpoint_key, plain_v1(checkpoint), dependencies))
            current, previous_for_variation = [], None
        else:
            if previous is None:
                raise MissingProductionOriginalV1("sourced_relationship_unknown_initialization_or_qualified_reassessment")
            checkpoint_atom = read.head(db, previous.checkpoint_ref, required=True)
            checkpoint = decode_typed_production_value_v1(checkpoint_atom.value, RelationshipCheckpointV2)
            current = [decode_typed_production_value_v1(atom.value, InteractionContributionV3) for atom in inventory[CONTRIBUTION_TYPE]
                if atom.valid and atom.value["checkpoint_ref"] == checkpoint.checkpoint_ref]
            previous_for_variation = previous
            for row in current:
                read.source_family(db, row.source_refs)
                _semantic(read, db, row.evaluation_interpretation_ref)
        contribution = InteractionContributionV3(scope, identity, candidate.contribution_kind, families, all_roots,
            request.interpretation_ref, candidate.trigger_original_ref, original_contribution.original_sequence if original_contribution else sequence,
            checkpoint.checkpoint_ref, dict(rule.kind_bounds)[candidate.contribution_kind], candidate.support_refs, candidate.counter_refs,
            candidate.interpretation_refs, candidate.affect_refs, candidate.requested_delta if candidate.requested_delta is not None else 0.0,
            0.0, aliases, policy.policy_ref, policy_original.original_digest)
        latest = tuple(row for row in current if row.key != contribution.key) + (contribution,)
        rebuilt = rebuild_relationship_dimension_v2(checkpoint=checkpoint, contributions=latest, candidate=candidate,
            policy=policy, policy_digest=policy_original.original_digest, previous_estimate=previous_for_variation)
        writes = []
        if not rebuilt.held_reason:
            writes.extend(checkpoint_writes)
            for row in rebuilt.contributions:
                prior = read.head(db, row.key)
                if plain_v1(row) != prior.value:
                    extra = (row.evaluation_interpretation_ref, row.trigger_original_ref, *row.support_refs, *row.counter_refs,
                        *row.interpretation_refs, *row.affect_refs, row.checkpoint_ref)
                    dependencies = _record_dependencies_v2(db, read, row.scope, row.source_refs, extra)
                    writes.append(GraphWrite(row.key, plain_v1(row), dependencies))
            for value, type_name in ((candidate.expectation, EXPECTATION_TYPE), (candidate.reciprocity, RECIPROCITY_TYPE), (candidate.repair, REPAIR_TYPE)):
                if value is None:
                    continue
                suffix = value.expectation_ref if type_name == EXPECTATION_TYPE else value.pattern_ref if type_name == RECIPROCITY_TYPE else (value.dispute_ref, value.action_kind)
                key = scope.key(type_name, suffix)
                prior = read.head(db, key)
                extra = [request.interpretation_ref]
                if type_name == EXPECTATION_TYPE:
                    extra.extend(value.negotiated_interpretation_refs)
                    if value.commitment_ref: extra.append(value.commitment_ref)
                elif type_name == RECIPROCITY_TYPE:
                    extra.extend(value.visible_sample_refs)
                else:
                    extra.extend((*value.proposal_interpretation_refs, *value.response_interpretation_refs, *value.practice_progress_refs,
                        *value.reevaluated_estimate_refs, *value.contact_basis_refs))
                    if value.communication_action_ref: extra.append(value.communication_action_ref)
                    if prior.valid:
                        prior_repair = decode_typed_production_value_v1(prior.value, RepairProcessV2)
                        if prior_repair.invitation_pending and (prior_repair.communication_original_ref, prior_repair.communication_effect_id) != (value.communication_original_ref, value.communication_effect_id):
                            raise ValueError("unresolved repair invitation retains its actual effect; timeout cannot replace it")
                dependencies = _record_dependencies_v2(db, read, scope, value.source_refs, extra)
                writes.append(GraphWrite(key, plain_v1(value), dependencies))
        elif previous is None:
            raise MissingProductionOriginalV1(rebuilt.held_reason)
        estimate = rebuilt.estimate
        estimate_extra = (request.interpretation_ref, estimate.checkpoint_ref, *estimate.contribution_refs, *estimate.support_refs,
            *estimate.counter_refs, *estimate.interpretation_refs)
        estimate_dependencies = _record_dependencies_v2(db, read, scope, estimate.source_refs, estimate_extra)
        writes.append(GraphWrite(estimate_key, plain_v1(estimate), estimate_dependencies))
        profile_key = scope.key(PROFILE_TYPE, "profile")
        read.head(db, profile_key)
        estimates = tuple(atom for atom in inventory[ESTIMATE_TYPE] if atom.valid and atom.key != estimate_key
            and decode_typed_production_value_v1(atom.value, DimensionEstimateV2).scope.key(PROFILE_TYPE, "profile") == profile_key)
        if len(estimates) + 1 > policy.max_dimensions:
            raise MissingProductionOriginalV1("bounded_relationship_profile_dimensions")
        estimate_refs = tuple(sorted((estimate_key.token, *(atom.key.token for atom in estimates))))
        ancillary_refs = {name: tuple(sorted(set(atom.key.token for atom in inventory[name] if atom.valid
            and decode_typed_production_value_v1(atom.value, {EXPECTATION_TYPE: RelationshipExpectationV2, RECIPROCITY_TYPE: ReciprocityPatternV2, REPAIR_TYPE: RepairProcessV2}[name]).scope.key(PROFILE_TYPE, "profile") == profile_key)
            | {w.key.token for w in writes if w.key.type_name == name})) for name in (EXPECTATION_TYPE, RECIPROCITY_TYPE, REPAIR_TYPE)}
        sources = tuple(dict.fromkeys((*estimate.source_refs, *(ref for atom in estimates for ref in atom.value["source_refs"]))))
        profile = RelationshipProfileV2(scope, estimate_refs, ancillary_refs[EXPECTATION_TYPE], ancillary_refs[RECIPROCITY_TYPE], ancillary_refs[REPAIR_TYPE], sources)
        writes.append(GraphWrite(profile_key, plain_v1(profile), tuple(AtomKey.from_token(ref) for ref in (*estimate_refs,
            *profile.expectation_refs, *profile.reciprocity_refs, *profile.repair_refs))))
        provenance["held_reason"] = rebuilt.held_reason
        provider = RelationshipProvider()
        stage = stage_result_v1(frame, "d05", REVISION_OPERATION, request, writes=tuple(writes), provenance=provenance,
            contribution_keys=() if rebuilt.held_reason or original_contribution is not None or aliases else (contribution.key.name,),
            receiver_events=(("d08", "relationship_changed_requires_action_recheck"),),
            proposal_schema="d05.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        provider.validate(stage.proposals[0], frame.snapshot)
        return stage
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d05", REVISION_OPERATION, request, missing)


def read_plan_current_relationship_revision_v2(db, *, namespace, activity_id, operation_kind, request):
    if operation_kind != REVISION_OPERATION or type(request) is not AdoptCurrentRelationshipRevisionRequestV2:
        raise ValueError("exact relationship revision read plan required")
    from ..graph_types import owner_grant_key
    from .d05_production_operations_v1 import read_plan_current_d05_operation_v1
    keys = [owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.interpretation_ref)]
    roots, originals = [], [request.interpretation_ref, request.policy_ref]
    types = [PROFILE_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE, CHECKPOINT_TYPE, EXPECTATION_TYPE, RECIPROCITY_TYPE, REPAIR_TYPE,
        "d03.entity_anchor", "d03.account_binding", "d05.contribution", "d05.relationship_projection"]
    from .d07_execution_v1 import TABLE
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone():
        adopted = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='adopted' AND original_ref=?",
            (*namespace.as_tuple, request.interpretation_ref)).fetchone()
        if adopted:
            actual = json.loads(adopted[0])
            prepared_rows = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND payload_digest=? LIMIT 2",
                (*namespace.as_tuple, actual["prepared_digest"])).fetchall()
            if len(prepared_rows) == 1:
                prepared = json.loads(prepared_rows[0][0])
                if prepared.get("schema") == "d07.relationship-prepared.v2":
                    cycle_version = decode_typed_production_value_v1(prepared["cycle_ref"], GraphVersion)
                    keys.append(cycle_version.key)
                    originals.extend((prepared["semantic_question_ref"], prepared["c02_operation_id"]))
    raw = raw_head_value_v1(db, namespace, AtomKey.from_token(request.interpretation_ref))
    if raw:
        candidate = _decode_candidate(raw)
        scope = candidate.scope
        keys.extend((scope.subject_head.key, scope.key(ESTIMATE_TYPE), scope.key(PROFILE_TYPE, "profile"), scope.key(CHECKPOINT_TYPE, request.interpretation_ref)))
        if scope.context_head is not None:
            keys.append(scope.context_head.key)
            context = raw_head_value_v1(db, namespace, scope.context_head.key)
            if context:
                roots.extend((scope.context_head.key.token,) if scope.context_head.key.type_name == "memory.source" else context["source_refs"])

        roots.extend(candidate.source_refs)
        from .d05_production_operations_v1 import _relationship_trigger_sources_v1
        trigger_key = AtomKey.from_token(candidate.trigger_original_ref)
        trigger_value = raw_head_value_v1(db, namespace, trigger_key)
        trigger_roots = _relationship_trigger_sources_v1(namespace, trigger_key, trigger_value) if trigger_value else ()
        if candidate.contribution_kind == "internal_recollection":
            from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
            _, canonical_identity = read_committed_recollection_original_v1(db, namespace, candidate.trigger_original_ref)
        else:
            first_source = raw_head_value_v1(db, namespace, AtomKey.from_token(trigger_roots[0])) if trigger_roots else None
            canonical_identity = first_source["provenance_root"] if first_source else None
        if canonical_identity is not None:
            keys.append(scope.key(CONTRIBUTION_TYPE, (candidate.contribution_kind, canonical_identity)))
        keys.extend(AtomKey.from_token(ref) for ref in (*candidate.support_refs, *candidate.counter_refs, *candidate.interpretation_refs, *candidate.affect_refs))
        originals.extend((*candidate.interpretation_refs, candidate.trigger_original_ref))
        if candidate.reassessment_interpretation_ref is not None:
            keys.append(AtomKey.from_token(candidate.reassessment_interpretation_ref)); originals.append(candidate.reassessment_interpretation_ref)
            keys.append(scope.key(CHECKPOINT_TYPE, candidate.reassessment_interpretation_ref))
            keys.extend(version.key for version in candidate.reassessment_basis_versions)

        if candidate.contribution_kind != "administrative_edit":
            semantics = {"external_interaction": "external_observation", "internal_recollection": "recollection", "simulated_trial": "simulation"}[candidate.contribution_kind]
            oldplan = read_plan_current_d05_operation_v1(db, namespace=namespace, activity_id=activity_id,
                operation_kind="adopt_relationship_contribution", request=AdoptCurrentRelationshipContributionRequestV1(candidate.trigger_original_ref,
                    scope.subject_entity_ref, scope.dimension, semantics, request.policy_ref))
            types.extend(oldplan.fixed_type_ids); keys.extend(oldplan.exact_keys); roots.extend(oldplan.source_roots); originals.extend(oldplan.required_original_refs)
        for type_name in (PROFILE_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE, CHECKPOINT_TYPE, EXPECTATION_TYPE, RECIPROCITY_TYPE, REPAIR_TYPE):
            for (encoded,) in db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129", (*namespace.as_tuple, type_name)):
                value = json.loads(encoded)
                if canonical_digest((NamespaceId(**value["scope"]["namespace"]), AtomKey.from_token(value["scope"]["subject_head"]["key"]).name,
                        value["scope"]["relationship_domain"], value["scope"]["context_ref"], value["scope"]["dimension"],
                        value["scope"]["dimension_schema_version"])) == scope.scope_id:
                    roots.extend(value["source_refs"])
                    if type_name == CONTRIBUTION_TYPE:
                        refs = (value["evaluation_interpretation_ref"], value["trigger_original_ref"], value["checkpoint_ref"],
                            *value["support_refs"], *value["counter_refs"], *value["interpretation_refs"], *value["affect_refs"])
                        keys.extend(AtomKey.from_token(ref) for ref in refs)
                        originals.extend((value["evaluation_interpretation_ref"], value["trigger_original_ref"], *value["interpretation_refs"]))
                    elif type_name == CHECKPOINT_TYPE:
                        if value["initialization_kind"] != "authored_prior":
                            keys.append(AtomKey.from_token(value["initialization_original_ref"]))
                        originals.append(value["initialization_original_ref"])
                    elif type_name == ESTIMATE_TYPE:
                        keys.extend(AtomKey.from_token(ref) for ref in (value["checkpoint_ref"], *value["contribution_refs"],
                            *value["support_refs"], *value["counter_refs"], *value["interpretation_refs"]))
                        originals.extend(value["interpretation_refs"])
        entity = raw_head_value_v1(db, namespace, scope.subject_head.key)
        if entity:
            for ref in entity["creation_evidence_refs"]:
                if AtomKey.from_token(ref).type_name == "memory.source": roots.append(ref)
                else:
                    keys.append(AtomKey.from_token(ref)); originals.append(ref)
        policy_row = db.execute("SELECT payload_json FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1", (*namespace.as_tuple, request.policy_ref)).fetchone()
        if policy_row:
            policy = json.loads(policy_row[0])
            roots.extend(policy.get("policy_source_refs", ()))
        for value, type_name in ((candidate.expectation, EXPECTATION_TYPE), (candidate.reciprocity, RECIPROCITY_TYPE), (candidate.repair, REPAIR_TYPE)):
            if value is None: continue
            suffix = value.expectation_ref if type_name == EXPECTATION_TYPE else value.pattern_ref if type_name == RECIPROCITY_TYPE else (value.dispute_ref, value.action_kind)
            keys.append(scope.key(type_name, suffix))
            if type_name == EXPECTATION_TYPE:
                keys.extend(AtomKey.from_token(ref) for ref in value.negotiated_interpretation_refs)
                originals.extend(value.negotiated_interpretation_refs)
                if value.commitment_ref: keys.append(AtomKey.from_token(value.commitment_ref))
            elif type_name == RECIPROCITY_TYPE:
                keys.extend(AtomKey.from_token(ref) for ref in value.visible_sample_refs)
            else:
                keys.extend(AtomKey.from_token(ref) for ref in (*value.proposal_interpretation_refs, *value.response_interpretation_refs,
                    *value.practice_progress_refs, *value.reevaluated_estimate_refs, *value.contact_basis_refs))
                originals.extend((*value.proposal_interpretation_refs, *value.response_interpretation_refs))
                if value.communication_original_ref: originals.append(value.communication_original_ref)
                if value.communication_action_ref: keys.append(AtomKey.from_token(value.communication_action_ref))
                if value.practice_progress_refs or value.communication_action_ref:
                    types.append("d08.action_intent.v1")
                for outcome_ref in value.practice_progress_refs:
                    outcome = raw_head_value_v1(db, namespace, AtomKey.from_token(outcome_ref))
                    if outcome: originals.extend(outcome["observation_refs"])

    for key in tuple(keys):
        raw = raw_head_value_v1(db, namespace, key)
        if raw: roots.extend(raw.get("source_refs", ()))
    return production_read_plan_v1(types, keys, roots, originals)



def relationship_preferences_read_plan_v2(db, *, namespace, bindings):
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from ..runtime_storage_v3 import runtime_storage_v3
    from .current_method_learning_read_v3 import (require_bound_relationship_preferences_v3,
        read_bound_method_relationship_policy_v3)
    matched = tuple(row for row in bindings if type(row) is SourceNoteCandidateBindingV1)
    if not matched:
        return production_read_plan_v1(())
    keys, roots, originals = [], [], []
    types = [ESTIMATE_TYPE, "d03.entity_anchor", "d03.role_binding"]
    subjects = {AtomKey.from_token(row.target_entity_ref).name for row in matched}
    for row in matched:
        keys.extend((AtomKey.from_token(row.target_entity_ref), AtomKey.from_token(row.role_binding_ref)))
        role = raw_head_value_v1(db, namespace, keys[-1])
        if role: roots.extend(role["source_refs"])
    if runtime_storage_v3(db) is not None:
        # The separate SourceNote preference census includes invalid rows for coverage.
        estimates = require_bound_relationship_preferences_v3(db, namespace)
        raw_estimates = tuple(atom.value for atom in estimates if atom.valid)
    else:
        raw_estimates = tuple(json.loads(encoded) for (encoded,) in db.execute(
            "SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*namespace.as_tuple, ESTIMATE_TYPE)))
    if len(raw_estimates) > 128:
        raise MissingProductionOriginalV1("complete_current_relationship_preference_inventory")
    for raw in raw_estimates:
        estimate = decode_typed_production_value_v1(raw, DimensionEstimateV2)
        if estimate.scope.subject_entity_ref not in subjects:
            continue
        keys.append(estimate.scope.subject_head.key)
        if estimate.scope.context_head is not None:
            keys.append(estimate.scope.context_head.key)
            context = raw_head_value_v1(db, namespace, estimate.scope.context_head.key)
            if context: roots.extend((estimate.scope.context_head.key.token,) if estimate.scope.context_head.key.type_name == "memory.source" else context["source_refs"])
        keys.extend(AtomKey.from_token(ref) for ref in estimate.interpretation_refs)
        roots.extend(estimate.source_refs); originals.append(estimate.policy_ref)
        if runtime_storage_v3(db) is not None:
            raw_policy = read_bound_method_relationship_policy_v3(db, namespace, estimate.policy_ref)
        else:
            row = db.execute("SELECT payload_json FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1",
                (*namespace.as_tuple, estimate.policy_ref)).fetchone()
            raw_policy = None if row is None else json.loads(row[0])
        if raw_policy: roots.extend(raw_policy.get("policy_source_refs", ()))
    return production_read_plan_v1(types, keys, roots, originals)


def read_current_relationship_preferences_v2(db, *, frame, prepared, issuer):
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from ..domains.d05.relationship_revision_v2 import RelationshipPreferenceInputV2, RelationshipPreferenceProjectionV2
    from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
    refs = tuple(row.binding.candidate_ref for row in prepared.candidates)
    matched = tuple(row for row in prepared.candidates if type(row.binding) is SourceNoteCandidateBindingV1)
    if not matched:
        return RelationshipPreferenceProjectionV2(frame.envelope.authority.namespace, refs, (), (), tuple((ref, "unscoped") for ref in refs), (), ())
    read = CurrentDomainReadV1(frame); read.check(db)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, read.head(db, prepared.plan_head.key, required=True).value)
    nodes = {node.node_id: node for node in plan.nodes}
    heads = read.complete_inventory(db, ESTIMATE_TYPE)
    readers = InstalledD05ProductionReadersV1(issuer=issuer)
    inputs, roots, versions, statuses = [], [], [], {ref: "unscoped" for ref in refs}
    for row in matched:
        binding = row.binding
        target = read.head(db, binding.target_entity_ref, required=True)
        role = read.head(db, binding.role_binding_ref, required=True)
        if (role.value["target_entity_ref"] != target.value["entity_id"] or role.value["subject_persona_ref"] != "persona:" + prepared.namespace.persona_id
                or role.value["status"] != "active" or role.value["effective_from"] > frame.now_utc
                or (role.value["effective_until"] is not None and frame.now_utc >= role.value["effective_until"])):
            raise MissingProductionOriginalV1("current_relationship_candidate_directional_context")
        effect = nodes[binding.node_id].action_kind
        statuses[binding.candidate_ref] = "unknown"
        for atom in heads:
            if atom.key.owner.subject != target.value["entity_id"]:
                continue
            estimate = decode_typed_production_value_v1(atom.value, DimensionEstimateV2)
            scope = estimate.scope
            if scope.context_ref not in {binding.role_binding_ref, binding.project_ref, binding.source_ref}:
                continue
            if (not atom.valid or estimate.status != "current" or scope.subject_head != GraphVersion(target.key, target.revision)
                    or estimate.valid_from > frame.now_utc or (estimate.valid_until is not None and frame.now_utc >= estimate.valid_until)):
                statuses[binding.candidate_ref] = "held"; continue
            if scope.context_head is not None:
                context = read.head(db, scope.context_head.key, required=True)
                if GraphVersion(context.key, context.revision) != scope.context_head:
                    statuses[binding.candidate_ref] = "held"; continue
            policy, original = readers._policy(db, read, estimate.policy_ref)
            if type(policy) is not InstalledRelationshipPolicyV2:
                raise MissingProductionOriginalV1("needs_policy:relationship_candidate_preference")
            rule = policy.rule(scope)
            if original.original_digest != estimate.policy_digest:
                raise MissingProductionOriginalV1("current_relationship_estimate_policy_revision")
            if effect not in estimate.applicable_effects:
                continue
            if row.eligibility.hard_status != "eligible":
                continue
            read.source_family(db, estimate.source_refs)
            preferred_high = effect in rule.higher_preferred_effects
            preferred_low = effect in rule.lower_preferred_effects
            if not preferred_high and not preferred_low:
                continue
            above, below = estimate.estimate > rule.preference_pivot, estimate.estimate < rule.preference_pivot
            preference = "favored" if (preferred_high and above) or (preferred_low and below) else "disfavored" if above or below else "neutral"
            inputs.append(RelationshipPreferenceInputV2(binding.candidate_ref, scope, GraphVersion(atom.key, atom.revision), effect,
                preference, policy.policy_ref, policy.revision, original.original_digest))
            roots.extend(estimate.source_refs); versions.extend((GraphVersion(atom.key, atom.revision), GraphVersion(role.key, role.revision), GraphVersion(target.key, target.revision)))
            statuses[binding.candidate_ref] = "current"
    edges = {(a.candidate_ref, b.candidate_ref) for a in inputs for b in inputs if a.candidate_ref != b.candidate_ref
        and a.scope.scope_id == b.scope.scope_id and a.preference == "favored" and b.preference == "disfavored"}
    return RelationshipPreferenceProjectionV2(prepared.namespace, refs, tuple(sorted(edges)), tuple(inputs), tuple(sorted(statuses.items())),
        tuple(sorted(set(roots))), tuple(sorted(set(versions), key=lambda item: item.key.token)))


def stage_initialize_current_relationship_prior_v2(db, *, frame, request, installed_readers):
    if type(request) is not InitializeCurrentRelationshipPriorRequestV2 or type(installed_readers) is not InstalledD05ProductionReadersV1:
        raise TypeError("named relationship prior requires its actual installed Owner reader")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if request.scope.namespace != frame.envelope.authority.namespace:
        raise ValueError("relationship prior initialization belongs to another actual Owner namespace")
    policy, policy_original = installed_readers._policy(db, read, request.policy_ref)
    if type(policy) is not InstalledRelationshipPolicyV2:
        raise MissingProductionOriginalV1("needs_policy:installed_relationship_numeric_v2")
    scope = request.scope
    rule = policy.rule(scope)
    _scope_heads(read, db, scope)
    if rule.authored_prior_source_ref is None:
        raise MissingProductionOriginalV1("independently_authored_installed_relationship_prior")
    estimate_key = scope.key(ESTIMATE_TYPE)
    estimate_head = read.head(db, estimate_key)
    checkpoints = tuple(atom for atom in read.complete_inventory(db, CHECKPOINT_TYPE)
        if atom.value and decode_typed_production_value_v1(atom.value, RelationshipCheckpointV2).scope.scope_id == scope.scope_id)
    if estimate_head.revision or checkpoints:
        raise ValueError("authored prior initialization cannot replace or reset an existing relationship basis")
    records = read.source_family(db, tuple(dict.fromkeys((rule.authored_prior_source_ref, *policy.policy_source_refs,
        *_scope_source_refs_v2(db, read, scope)))))
    source = records[rule.authored_prior_source_ref]
    if source.qualification != "authored":
        raise ValueError("relationship prior requires its independently authored actual Source")
    origin = read.head(db, rule.authored_prior_source_ref, required=True)
    original = read.original(rule.authored_prior_source_ref)
    checkpoint_key = scope.key(CHECKPOINT_TYPE, frame.envelope.identity.operation_id)
    if read.head(db, checkpoint_key).revision:
        raise ValueError("relationship prior operation original was already consumed")
    roots = tuple(records)
    checkpoint = RelationshipCheckpointV2(scope, rule.authored_prior_estimate, rule.authored_prior_source_ref,
        frame.envelope.identity.operation_id, "authored_prior", GraphVersion(origin.key, origin.revision), canonical_digest(origin.value),
        policy.policy_ref, policy_original.original_digest, roots, checkpoint_key.token)
    estimate = DimensionEstimateV2(scope, rule.authored_prior_estimate, 0.0, "unknown", (), (), (), (), (),
        checkpoint_key.token, (), (), 0.0, policy.policy_ref, policy_original.original_digest,
        rule.applicable_effects, frame.now_utc, None, roots, "current")
    estimates = tuple(atom for atom in read.complete_inventory(db, ESTIMATE_TYPE)
        if atom.valid and decode_typed_production_value_v1(atom.value, DimensionEstimateV2).scope.key(PROFILE_TYPE) == scope.key(PROFILE_TYPE))
    if len(estimates) + 1 > policy.max_dimensions:
        raise MissingProductionOriginalV1("bounded_relationship_profile_dimensions")
    profile_key = scope.key(PROFILE_TYPE)
    prior_profile = read.head(db, profile_key)
    previous = None if not prior_profile.revision else decode_typed_production_value_v1(prior_profile.value, RelationshipProfileV2)
    estimate_refs = tuple(sorted((estimate_key.token, *(atom.key.token for atom in estimates))))
    all_roots = tuple(dict.fromkeys((*roots, *(ref for atom in estimates for ref in atom.value["source_refs"]))))
    profile = RelationshipProfileV2(scope, estimate_refs, () if previous is None else previous.expectation_refs,
        () if previous is None else previous.reciprocity_refs, () if previous is None else previous.repair_refs, all_roots)
    dependencies = _record_dependencies_v2(db, read, scope, roots)
    writes = (GraphWrite(checkpoint_key, plain_v1(checkpoint), dependencies),
        GraphWrite(estimate_key, plain_v1(estimate), (*dependencies, checkpoint_key)),
        GraphWrite(profile_key, plain_v1(profile), tuple(AtomKey.from_token(ref) for ref in
            (*profile.estimate_refs, *profile.expectation_refs, *profile.reciprocity_refs, *profile.repair_refs))))
    provenance = {"policy": policy_original, "initial_origin": original, "initialization": checkpoint}
    provider = RelationshipProvider()
    stage = stage_result_v1(frame, "d05", INITIALIZE_OPERATION, request, writes=writes, provenance=provenance,
        proposal_schema="d05.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage


def read_plan_initialize_current_relationship_prior_v2(db, *, namespace, activity_id, operation_kind, request, operation_id):
    from ..graph_types import owner_grant_key
    if operation_kind != INITIALIZE_OPERATION or type(request) is not InitializeCurrentRelationshipPriorRequestV2:
        raise ValueError("named relationship prior requires its exact read plan")
    scope = request.scope
    keys = [owner_grant_key(*namespace.as_tuple), scope.subject_head.key, scope.key(ESTIMATE_TYPE), scope.key(PROFILE_TYPE), scope.key(CHECKPOINT_TYPE, operation_id)]
    roots, originals = [], [request.policy_ref]
    if scope.context_head is not None:
        keys.append(scope.context_head.key)
    for key in (scope.subject_head.key, *((scope.context_head.key,) if scope.context_head is not None else ())):
        value = raw_head_value_v1(db, namespace, key)
        if value:
            evidence = (key.token,) if key.type_name == "memory.source" else value.get("source_refs", value.get("creation_evidence_refs", ()))
            for ref in evidence:
                if AtomKey.from_token(ref).type_name == "memory.source": roots.append(ref)
                else:
                    keys.append(AtomKey.from_token(ref)); originals.append(ref)
    row = db.execute("SELECT payload_json FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1",
        (*namespace.as_tuple, request.policy_ref)).fetchone()
    if row:
        policy = decode_typed_production_value_v1(json.loads(row[0]), InstalledRelationshipPolicyV2)
        rule = policy.rule(scope)
        roots.extend(policy.policy_source_refs)
        if rule.authored_prior_source_ref is not None:
            roots.append(rule.authored_prior_source_ref)
            originals.append(rule.authored_prior_source_ref)
    types = [PROFILE_TYPE, ESTIMATE_TYPE, CHECKPOINT_TYPE]
    for type_name in types:
        for (encoded,) in db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
                (*namespace.as_tuple, type_name)):
            roots.extend(json.loads(encoded)["source_refs"])
    return production_read_plan_v1(types, keys, tuple(dict.fromkeys(roots)), originals)
