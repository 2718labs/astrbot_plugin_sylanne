"""Closed receiver resolution from an adopted event and current W01 heads.

Ready commands remain ordinary current operations under a fresh Owner fence.
Missing execution, encoding or consent originals yield a durable precise wait.
This reader never acknowledges an effect, retries a dispatch or grants CPU.
"""
from dataclasses import dataclass
import json
from .domain_background_read_v3 import background_history_v3, background_json_loads_v3, background_inventory_v3

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d10 import decode_contact_policy, decode_proactive_opportunity
from ..domains.d10.production_operations_v1 import PrepareCurrentContactRequestV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_contracts_v1 import ProductionOutboxStageV1
from .domain_production_original_codec_v1 import _EVENTS
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


def verify_current_followup_trigger_v1(db, namespace, event, causal_original, issuer):
    """Authenticate the one fixed trigger emitted by each actual causal issuer."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(event) is not ProductionOutboxStageV1 or event.namespace != namespace
            or causal_original is None or causal_original["receipt"].operation_id != event.causal_operation_id):
        raise ValueError("followup trigger requires its actual causal W01 adoption")
    if (event.event_kind == "actual_life_outcome_available_for_growth"
            and event.trigger_original.original_ref.startswith("general-growth-outcome:")):
        from .d07_general_growth_attention_v1 import read_actual_general_growth_outcome_trigger_v1
        trigger = read_actual_general_growth_outcome_trigger_v1(db, namespace=namespace,
            original_ref=event.trigger_original.original_ref, issuer=issuer)
        if (trigger is None or trigger.digest != event.trigger_original.original_digest
                or trigger.causal_operation_id != event.causal_operation_id
                or trigger.causal_receipt_digest != canonical_digest(causal_original["receipt"])):
            raise ValueError("General outcome outbox changed its actual signed same-CAS trigger")
        return event.trigger_original
    if event.event_kind == 'general_growth_attention_available_for_service':
        from .d07_general_growth_attention_v1 import read_general_growth_attention_original_v1
        attention=read_general_growth_attention_original_v1(db,namespace=namespace,
            original_ref=event.trigger_original.original_ref,issuer=issuer)
        from ..domains.d01.production_operations_v1 import plain_v1
        if (attention is None or attention.registration_operation_id!=event.causal_operation_id
                or canonical_digest(plain_v1(attention))!=event.trigger_original.original_digest
                or canonical_digest(causal_original['receipt'])!=attention.registration_receipt_digest):
            raise ValueError('General service trigger differs from its actual registration CAS')
        return event.trigger_original
    if event.event_kind in _GENERAL_GROWTH_LIFECYCLE_V1:
        expected=_GENERAL_GROWTH_LIFECYCLE_V1[event.event_kind]
        if ((causal_original['domain'],causal_original['operation_kind'])!=('d01',expected[0])
                or causal_original.get('general_lifecycle_original')is None
                or event.trigger_original.original_digest!=causal_original['general_lifecycle_digest']):
            raise ValueError('General lifecycle trigger differs from the actual signed same-CAS input')
        return event.trigger_original
    if event.event_kind == "actual_internal_experience_requires_encoding":
        if (causal_original["domain"], causal_original["operation_kind"]) != ("d10", "advance_life"):
            raise ValueError("internal experience has another actual causal operation")
        key = AtomKey.from_token(event.trigger_original.original_ref)
        versions = tuple(version for version in causal_original["receipt"].write_versions if version.key == key)
        if len(versions) != 1 or key.type_name != "memory.source" or not key.owner.subject.startswith("d10-life-experience:"):
            raise ValueError("experience source is not an actual member of the causal composite receipt")
        row = background_history_v3(db,key.token,versions[0].revision,columns=('event_bot','event_persona','event_id','value','valid'))
        if row is None or row[:3] != (*namespace.as_tuple, event.causal_operation_id) or row[4] != 1:
            raise ValueError("experience source lost its actual causal Graph history")
        from ..memory_types import SourceRecord
        from ..domains.d06 import D06DomainAdapter, SourceAdmission
        from ..domains.d01.production_operations_v1 import plain_v1
        source = SourceRecord.from_dict(background_json_loads_v3(row[3]))
        progress = causal_original["payload"]["provenance"]["actual_progress"]
        expected_id = "d10-life-experience:" + canonical_digest((progress["activity_id"], progress["effect_id"]))[:48]
        expected_text = canonical_serialize({
            "kind": "life_step_completed", "project_ref": progress["project_ref"], "recipe_ref": progress["recipe_ref"],
            "step": progress["step"], "role_start": progress["role_start"], "role_end": progress["role_end"],
            "artifact_ref": progress["artifact_ref"], "terminal_ref": progress["terminal_ref"], "reality": progress["reality"]})
        root_ref = progress["source_refs"][-1]
        roots = tuple(version for version in causal_original["read_versions"] if version.key.token == root_ref)
        if len(roots) != 1:
            raise ValueError("experience admission lost its actual causal parent read")
        root = background_history_v3(db,root_ref,roots[0].revision,columns=('value','valid'))
        if root is None or root[1] != 1:
            raise ValueError("experience admission lost its actual parent source history")
        actual_parent = SourceRecord.from_dict(background_json_loads_v3(root[0]))
        family = actual_parent.provenance_root
        from ..graph_types import GraphAtom, GraphSnapshot
        from .d10_production_operations_v1 import experience_allowed_purposes_v1
        historical = []
        for version in causal_original["read_versions"]:
            if version.revision < 1 or version.key.type_name not in {"memory.source", "memory.access", "d11.owner_grant.v1"}:
                continue
            value = background_history_v3(db,version.key.token,version.revision,columns=('value','valid'))
            if value is None:
                raise ValueError("experience admission lost its actual parent/Owner permission history")
            historical.append(GraphAtom(version.key, version.revision, background_json_loads_v3(value[0]), bool(value[1])))
        purposes = experience_allowed_purposes_v1(GraphSnapshot(tuple(historical), ()), namespace, tuple(progress["source_refs"]))
        simulated = progress["reality"] == "role_simulation"
        admission = SourceAdmission(expected_id, expected_text, "persona:" + namespace.persona_id,
            "simulated" if simulated else "internal", "simulated" if simulated else "observed",
            "none" if simulated else "subjective_only", "committed",
            actual_parent.occurred_at, causal_original["payload"]["now_utc"], family,
            tuple(causal_original["payload"]["authority"]["audience"]),
            purposes,
            tuple(AtomKey.from_token(ref).owner.subject for ref in progress["source_refs"]))
        if (source.source_id != expected_id or source.text != expected_text
                or source.recorded_at != causal_original["payload"]["now_utc"]
                or tuple(source.parent_source_ids) != tuple(AtomKey.from_token(ref).owner.subject for ref in progress["source_refs"])
                or D06DomainAdapter(namespace).admit_source(admission).source != source
                or canonical_digest(plain_v1(admission)) != event.trigger_original.original_digest):
            raise ValueError("actual internal-experience trigger differs from its original admission bytes")
        return event.trigger_original
    if event.event_kind == "actual_offline_simulation_experiences_require_encoding":
        if (causal_original["domain"], causal_original["operation_kind"]) != ("d10", "advance_offline"):
            raise ValueError("offline experience has another actual causal operation")
        if event.trigger_original.original_ref != causal_original["payload"]["request"]["offline_interval_ref"]:
            raise ValueError("offline trigger names another registered interval")
        from .domain_production_read_plans_v1 import _signed_input
        actual = _signed_input(db, namespace, event.trigger_original.original_ref, issuer)
        if (actual is None or actual.kind != "d10.offline_interval"
                or actual.original_digest != event.trigger_original.original_digest):
            raise ValueError("offline trigger is not the actual signed interval original")
        return actual
    if (event.trigger_original.original_digest != causal_original["original_digest"]
            or event.trigger_original.original_ref != causal_original["domain"] + "-current:" + causal_original["original_digest"][:48]):
        raise ValueError("domain followup trigger differs from its actually adopted stage original")
    return event.trigger_original


@dataclass(frozen=True, slots=True)
class DomainFollowupCommandV1:
    receiver_domain: str
    operation_kind: str
    request: object
    activity_id: str
    audience_ref: str
    audience_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DomainFollowupResolutionV1:
    status: str
    commands: tuple[DomainFollowupCommandV1, ...]
    target_refs: tuple[str, ...]
    missing_originals: tuple[str, ...]
    continuation_ref: str | None = None

    def __post_init__(self):
        from .contact_followup_v1 import ContactFollowupCommandV1
        if (self.status not in {"ready", "waiting_for_original", "partial", "no_matching_general_start"}
                or type(self.commands) is not tuple or len(self.commands) > 16
                or any(type(command) not in {DomainFollowupCommandV1,ContactFollowupCommandV1,GeneralGrowthTrialFollowupCommandV1} for command in self.commands)
                or type(self.target_refs) is not tuple or len(self.target_refs) > 128
                or type(self.missing_originals) is not tuple or len(self.missing_originals) > 128
                or self.status == "ready" and (not self.commands or self.missing_originals or self.continuation_ref)):
            raise ValueError("domain followup resolution is not a bounded concrete result")


def _adopted_event(db, namespace, event):
    if (type(event) is not ProductionOutboxStageV1 or event.namespace != namespace
            or _EVENTS.get(event.event_kind) != event.receiver_domain):
        raise ValueError("followup requires the exact installed event kind/receiver")
    row = db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*namespace.as_tuple, event.dedupe_key)).fetchone()
    if (row is None or row[:5] != (event.causal_operation_id, event.receiver_domain, event.event_kind,
            event.trigger_original.original_ref, event.trigger_original.original_digest)
            or row[5] not in {"pending", "waiting"}):
        raise ValueError("followup has no matching current unconsumed durable outbox original")
    from .d07_general_growth_attention_v1 import read_general_growth_followup_cause_v1
    from .domain_background_read_v3 import _active_v3
    active = _active_v3(db)
    original = read_general_growth_followup_cause_v1(db, namespace=namespace, event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id, original_ref=event.trigger_original.original_ref,
        issuer=active.graph._GraphCoordinator__d11_issuer if active is not None else None)
    if original is None:
        if event.event_kind in _GENERAL_GROWTH_LIFECYCLE_V1:
            if active is None:raise ValueError('General lifecycle requires its actual metadata Work')
            original=read_general_growth_lifecycle_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
                causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
                issuer=active.graph._GraphCoordinator__d11_issuer)
        else:
            original=read_adopted_domain_operation_v1(db,namespace,event.causal_operation_id)
    if original is None:
        raise ValueError("followup lost its real causal W01 adoption")
    return original


def read_plan_current_domain_followup_v1(db, *, namespace, event):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("followup plan needs the actual current W01 SQL transaction")
    original = _adopted_event(db, namespace, event)
    if event.event_kind=='qualified_joint_contact_requires_prospective_v1':
        from .domain_background_read_v3 import _active_v3
        from .contact_prospective_v1 import read_plan_joint_contact_prospective_followup_v1
        active=_active_v3(db)
        if active is None:raise ValueError('Joint Contact receiver requires its actual registered background Work')
        return read_plan_joint_contact_prospective_followup_v1(db,namespace=namespace,event=event,
            issuer=active.graph._GraphCoordinator__d11_issuer)
    if event.event_kind=='qualified_contact_opportunity_requires_action':
        from .contact_initial_plan_source_v3 import initial_contact_followup_read_plan_v3
        initial_plan=initial_contact_followup_read_plan_v3(db,namespace,event,original)
        if initial_plan is not None:return initial_plan
    from .joint_node_execution_v1 import JOINT_EVENTS, QualifyJointPlanNodesRequestV1, joint_input_read_plan_v1, joint_result_versions_digest_v1
    if event.event_kind in JOINT_EVENTS:
        from ..domains.d08.execution import _decode_joint_plan
        plans = tuple(version.key for version in original["receipt"].write_versions if version.key.type_name == "d08.joint_plan.v1")
        if not plans and original["operation_kind"] == "input:observe_joint_external_node_v1":
            plans = (AtomKey.from_token(original["payload"]["request"]["plan_ref"]),)
        if len(plans) != 1:
            raise ValueError("Joint event must name its one actual adopted plan")
        from .d01_production_operations_v1 import raw_head_value_v1
        value = raw_head_value_v1(db, namespace, plans[0])
        plan = _decode_joint_plan(value)
        return joint_input_read_plan_v1(db, namespace=namespace, request=QualifyJointPlanNodesRequestV1(plans[0].token, plan.revision,
            joint_result_versions_digest_v1(db, namespace=namespace, plan=plan)))
    if event.event_kind == "joint_external_semantic_question_requires_fair_cognition":
        from .joint_external_observation_v1 import PrepareJointExternalSemanticQuestionRequestV1, joint_semantic_input_read_plan_v1, joint_semantic_question_ref_v1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        actual = decode_typed_production_value_v1(original["payload"]["request"], PrepareJointExternalSemanticQuestionRequestV1)
        plan = joint_semantic_input_read_plan_v1(db, namespace=namespace, request=actual)
        from ..domains.d07.concern_round import concern_round_key
        from .d01_production_operations_v1 import raw_head_value_v1
        ticket = raw_head_value_v1(db, namespace, actual.attention_ticket.key)
        return production_read_plan_v1((*plan.fixed_type_ids, "d02.body_profile.v1", "d02.body_state.v1", "d02.reservation.v1"),
            (*plan.exact_keys, concern_round_key(namespace, ticket["category"])), plan.source_roots,
            (*plan.required_original_refs, joint_semantic_question_ref_v1(actual)))
    fixed = {
        "d01": ("d01.persona_activation.v1", "d01.persona_plan.v1", "d07.current_interpretation.v1"),
        "d08": ("d08.action_intent.v1", "d08.action_outcome.v1", "d08.commitment.v1", "d08.goal.v1", "d08.joint_plan.v1",
            "d08.action_schema.v1", "d05.boundary_rule", "d05.relationship_projection"),
        "d10": ("d10.contact_policy.v1", "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2", "d10.life_project.v1",
            "d10.activity_recipe.v1", "d03.account_binding", "d03.entity_anchor", "d05.boundary_rule"),
        "d06": (), "d07": ("d07.concern_round.v1", "d07.reflection_checkpoint.v1", "d07.attention_ticket.v1"),
    }[event.receiver_domain]
    if event.event_kind == 'qualified_contact_opportunity_requires_action':
        from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
        fixed = tuple(dict.fromkeys((*fixed,*CONTACT_CURRENT_TYPES)))
    keys = [version.key for version in original["receipt"].write_versions]
    keys += [version.key for version in original["read_versions"]]
    roots = [key.token for key in keys if key.type_name == "memory.source"]
    for type_id in fixed:
        rows = background_inventory_v3(db,namespace,type_id,valid_only=True)
        for atom in rows:
            raw = atom.value
            roots += list(raw.get("source_refs", raw.get("creation_evidence_refs", ())))
            if type_id == "d10.proactive_opportunity.v1":
                roots.append(raw["source_ref"])
            if event.receiver_domain == "d10" and type_id == "d03.account_binding":
                from .d01_production_operations_v1 import raw_head_value_v1
                evidence_key = AtomKey.from_token(raw["verification_ref"])
                keys.append(evidence_key)
                evidence = raw_head_value_v1(db, namespace, evidence_key)
                if evidence is not None:
                    roots.extend(evidence["source_refs"])
    return production_read_plan_v1(fixed, keys, roots, (event.trigger_original.original_ref,))


def resolve_domain_followup_v1(db, current_frame, event, *, installed_graph=None):
    issuer=None if installed_graph is None else installed_graph._GraphCoordinator__d11_issuer
    read = CurrentDomainReadV1(current_frame)
    read.check(db)
    ns = current_frame.envelope.authority.namespace
    original = _adopted_event(db, ns, event)
    if event.event_kind in _GENERAL_GROWTH_LIFECYCLE_V1:
        return resolve_general_growth_lifecycle_followup_v1(db,current_frame,event,original)
    epoch = current_frame.snapshot.epochs[0].revision
    continuation = "domain-followup:" + canonical_digest((ns, event.dedupe_key, epoch))[:48]
    def wait(reason, targets=()):
        return DomainFollowupResolutionV1("waiting_for_original", (), tuple(targets), (reason,), continuation)
    if event.event_kind=='general_growth_action_outcome_available':
        from .domain_background_read_v3 import _active_v3
        active=_active_v3(db)
        if active is None:raise ValueError('General outcome requires its actual metadata Work')
        return resolve_general_growth_trial_metadata_v1(db,current_frame,event,original,
            issuer=active.graph._GraphCoordinator__d11_issuer)
    if event.event_kind in {'actual_life_outcome_available_for_growth','general_growth_attention_available_for_service'}:
        from .domain_background_read_v3 import _active_v3
        from .d07_general_growth_attention_v1 import (general_growth_background_parent_v1,
            resolve_general_growth_outcome_followup_v1,resolve_general_growth_service_followup_v1)
        active=_active_v3(db)
        trigger=general_growth_background_parent_v1(active) if active is not None else None
        resolver=(resolve_general_growth_outcome_followup_v1 if event.event_kind=='actual_life_outcome_available_for_growth'
            else resolve_general_growth_service_followup_v1)
        attention=resolver(db,read,event,trigger,issuer=active.graph._GraphCoordinator__d11_issuer)
        if event.event_kind!='actual_life_outcome_available_for_growth':return attention
        trials=resolve_general_growth_trial_metadata_v1(db,current_frame,event,original,
            issuer=active.graph._GraphCoordinator__d11_issuer)
        commands=(*trials.commands,*attention.commands)
        if len(commands)>current_frame.limits.max_followup_jobs:
            raise MissingProductionOriginalV1('bounded_independent_general_trial_attention_tail',continuation=continuation)
        targets=tuple(dict.fromkeys((*trials.target_refs,*attention.target_refs)))
        missing=tuple(dict.fromkeys((*trials.missing_originals,*attention.missing_originals)))
        status='partial'if missing and commands else 'ready'if commands else 'waiting_for_original'
        return DomainFollowupResolutionV1(status,commands,targets,missing,continuation if status!='ready'else None)
    if event.event_kind == "joint_external_semantic_question_requires_fair_cognition":
        from .joint_external_observation_v1 import resolve_joint_external_cognition_v1
        return resolve_joint_external_cognition_v1(db, frame=current_frame, original=original, issuer=issuer)
    from .joint_node_execution_v1 import JOINT_EVENTS, joint_followup_resolution_v1
    if event.event_kind in JOINT_EVENTS:
        return joint_followup_resolution_v1(db, frame=current_frame, original=original, issuer=issuer)
    if event.event_kind=='qualified_joint_contact_requires_prospective_v1':
        from .contact_prospective_v1 import resolve_joint_contact_prospective_followup_v1
        return resolve_joint_contact_prospective_followup_v1(db,current_frame,event,graph=installed_graph,continuation=continuation)
    if event.receiver_domain == "d10" and event.event_kind in {
            "boundary_changed_requires_contact_recheck", "source_correction_requires_contact_recheck"}:
        policies = tuple(atom for atom in read.complete_inventory(db, "d10.contact_policy.v1") if atom.valid)
        opportunities = tuple(atom for atom in read.complete_inventory(db, "d10.proactive_opportunity.v1") if atom.valid)
        read.complete_inventory(db, "d03.account_binding")
        read.complete_inventory(db, "d03.entity_anchor")
        commands, missing, targets = [], [], []
        from .contact_route_binding_v1 import contact_route_audience_v1, read_current_contact_route_binding_v1
        for atom in opportunities:
            opportunity = decode_proactive_opportunity(atom.value, ns)
            if opportunity.expires_at < current_frame.now_utc:
                continue
            targets.append(atom.key.token)
            matching = tuple(policy for policy in policies if
                (policy.value["subject_ref"], policy.value["channel"], policy.value["category"]) ==
                (opportunity.subject_ref, opportunity.channel, opportunity.category))
            if len(matching) != 1:
                missing.append("unique_current_contact_policy:" + atom.key.token)
                continue
            decode_contact_policy(matching[0].value, ns)
            accounts = tuple(value for value in read.complete_inventory(db, "d03.account_binding")
                if value.valid and value.value["entity_id"] == opportunity.subject_ref
                and value.value["valid_from"] <= current_frame.now_utc
                and (value.value["valid_until"] is None or current_frame.now_utc < value.value["valid_until"]))
            if len(accounts) != 1:
                missing.append("unique_current_contact_target_account:" + atom.key.token)
                continue
            account = accounts[0]
            try:
                audience = contact_route_audience_v1(db, ns, account.value)
                read_current_contact_route_binding_v1(db, read, account_ref=account.key.token,
                    target_entity_ref=opportunity.subject_ref, audience=audience)
            except MissingProductionOriginalV1 as error:
                missing.extend(error.missing_inputs)
                continue
            if len(commands) >= current_frame.limits.max_followup_jobs:
                missing.append("bounded_contact_followup_tail")
                break
            commands.append(DomainFollowupCommandV1("d10", "prepare_contact",
                PrepareCurrentContactRequestV1(atom.key.token, matching[0].key.token, account.key.token),
                "contact-followup:" + canonical_digest((event.dedupe_key, atom.key.token))[:48], audience))
        if not targets:
            return wait("current_contact_opportunity_from_actual_source")
        status = "partial" if missing and commands else "ready" if commands else "waiting_for_original"
        return DomainFollowupResolutionV1(status, tuple(commands), tuple(targets), tuple(dict.fromkeys(missing)),
            continuation if status != "ready" else None)
    if event.receiver_domain == "d06":
        # Actual experience keys must occur in the causal composite receipt,
        # and their original history must be the same adopted commit.
        targets = tuple(version.key.token for version in original["receipt"].write_versions
            if version.key.type_name == "memory.source" and version.key.owner.subject.startswith(
                ("d10-life-experience:", "d10-offline-experience:")))
        if not targets:
            return wait("actual_adopted_d10_experience_sources")
        for ref in targets:
            atom = read.head(db, ref, required=True)
            history = background_history_v3(db,ref,atom.revision,columns=('event_bot','event_persona','event_id','value','valid'))
            adopted_revision = next(version.revision for version in original["receipt"].write_versions if version.key.token == ref)
            if (history is None or history[:3] != (*ns.as_tuple, event.causal_operation_id)
                    or atom.revision != adopted_revision or history[4] != 1 or background_json_loads_v3(history[3]) != atom.value):
                raise ValueError("experience original is not from the actual causal D10 bundle")
        read.source_family(db, targets, purpose="consolidation")
        from ..domains.d06.structured_experience_v1 import EncodeCurrentStructuredExperienceRequestV1
        audience = original["payload"]["authority"]["audience"]
        commands = tuple(DomainFollowupCommandV1("d06", "encode_structured_experience",
            EncodeCurrentStructuredExperienceRequestV1(event.causal_operation_id, ref),
            "structured-experience:" + canonical_digest((event.dedupe_key, ref))[:48],
            audience[0], tuple(audience))
            for ref in targets[:current_frame.limits.max_followup_jobs])
        missing = ("actual_d04_then_feeling_and_d06_subjective_trace_encoding",)
        if len(commands) < len(targets):
            missing += ("bounded_structured_experience_tail",)
        return DomainFollowupResolutionV1("partial", commands, targets, missing, continuation)
    if event.receiver_domain == "d08":
        actions = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.action_intent.v1") if atom.valid)
        goals = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.goal.v1") if atom.valid)
        plans = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.joint_plan.v1") if atom.valid)
        if event.event_kind in {"relationship_changed_requires_action_recheck", "boundary_changed_requires_action_recheck",
                "source_correction_requires_boundary_recheck", "persona_growth_requires_commitment_reevaluation"}:
            if not actions:
                return wait("actual_current_d08_action_intents")
            from ..domains.d08.production_operations_v1 import RecheckCurrentActionRequestV1
            from ..domains.d08.execution import _decode_intent
            commands = []
            for ref in actions[:current_frame.limits.max_followup_jobs]:
                intent = _decode_intent(read.head(db, ref, required=True).value)
                commands.append(DomainFollowupCommandV1("d08", "recheck_action", RecheckCurrentActionRequestV1(ref),
                    intent.identity.activity_id, current_frame.envelope.authority.audience[0]))
            partial = len(commands) < len(actions)
            return DomainFollowupResolutionV1("partial" if partial else "ready", tuple(commands), actions,
                ("bounded_current_action_recheck_tail",) if partial else (), continuation if partial else None)
        if event.event_kind == "qualified_contact_opportunity_requires_action":
            from .contact_followup_v1 import resolve_contact_action_followup_v1
            return resolve_contact_action_followup_v1(db,current_frame,event,original,continuation,installed_graph)
        if event.event_kind == "joint_plan_adopted_requires_next_node_action":
            return wait("actual_d08_joint_node_action_intent_and_independent_party_scope", plans)
        return wait("actual_d08_value_ranked_action_candidates_and_required_checks", actions or goals)
    if event.receiver_domain == "d01":
        return wait("adopted_d07_growth_interpretation_and_actual_completed_trials", tuple(
            version.key.token for version in original["receipt"].write_versions if version.key.type_name == "d10.life_progress.v1"))
    if event.receiver_domain == "d10":
        projects = tuple(atom.key.token for atom in read.complete_inventory(db, "d10.life_project.v1") if atom.valid)
        return wait("actual_d08_life_action_outcome_with_settled_body_component_and_clock_originals", projects)
    if event.receiver_domain == "d07":
        return wait("actual_d07_execution_terminal_and_registered_resume_request", (event.trigger_original.original_ref,))
    raise ValueError("registered followup receiver has no concrete installed semantics")

_GENERAL_GROWTH_LIFECYCLE_V1={
    'general_growth_intent_available_for_future_trial':('freeze_general_growth_intent_v1','general_growth_intent_v1'),
    'general_growth_trial_start_available_for_observation':('register_general_growth_trial_start_v1','general_growth_trial_start_v1'),
    'general_growth_trial_completed_for_adoption':('derive_general_growth_trial_v1','general_growth_trial_v1')}


def read_general_growth_lifecycle_cause_v1(db,*,namespace,event_kind,causal_operation_id,original_ref,issuer):
    if event_kind not in _GENERAL_GROWTH_LIFECYCLE_V1:return None
    from .domain_background_read_v3 import (_active_v3,background_signed_input_row_v3,
        background_json_matches_v3,background_json_digest_v3,background_verify_signature_v3)
    from .d01_production_operations_v1 import TABLE,SIGN_KIND
    from .d01_general_growth_v1 import (GeneralGrowthIntentOriginalV1,GeneralGrowthTrialStartV1,GeneralGrowthTrialOriginalV1)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import _receipt
    from .d07_general_growth_attention_v1 import _general_growth_adopted_metadata_row_v1
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from ..graph_types import GraphVersion
    owner=_active_v3(db)
    if (owner is None or owner.kind not in('followup','followup_child')
            or owner.entry is None or owner.entry[:3]!=(causal_operation_id,'d01',event_kind)):
        raise ValueError('General lifecycle requires its actual metadata-only Background Work')
    operation_kind,input_kind=_GENERAL_GROWTH_LIFECYCLE_V1[event_kind]
    row=background_signed_input_row_v3(db,namespace,TABLE,original_ref,'kind',legacy_reader=lambda:None)
    if row is None or row[:2]!=(input_kind,causal_operation_id):
        raise ValueError('General lifecycle lost its actual signed produced original')
    background_verify_signature_v3(issuer._signer,SIGN_KIND,row[2],row[4])
    raw=background_json_loads_v3(row[2])
    if not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]:
        raise ValueError('General lifecycle signed metadata changed canonical EOF')
    cls={'general_growth_intent_v1':GeneralGrowthIntentOriginalV1,
        'general_growth_trial_start_v1':GeneralGrowthTrialStartV1,'general_growth_trial_v1':GeneralGrowthTrialOriginalV1}[input_kind]
    value=decode_typed_production_value_v1(raw,cls)
    metadata=_general_growth_adopted_metadata_row_v1(db,namespace,causal_operation_id)
    if metadata is None or metadata[:2]!=('d01',operation_kind):
        raise ValueError('General lifecycle has another actual producing stage')
    receipt=_receipt(background_json_loads_v3(metadata[6]))
    reads=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in background_json_loads_v3(metadata[5]))
    ledger=_producer_original_point_v3(db,table='graph_bundle_operations',
        columns=('digest','activity_id','effect_id','commit_seq'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    if (receipt.operation_id!=causal_operation_id or receipt.status!='committed'
            or receipt.operation_digest!=metadata[3]or canonical_digest(receipt)!=metadata[4]
            or ledger!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or any(NamespaceId.from_key(version.key)!=namespace for version in reads)
            or owner.entry_metadata[0]!=('d01',operation_kind,metadata[2])
            or owner.entry_column is None or not owner.entry_column.complete
            or owner.entry_column.column.sha256!=metadata[2]):
        raise ValueError('General lifecycle lacks the same-Work complete actual stage/receipt/ledger EOF')
    return {'domain':'d01','operation_kind':operation_kind,'original_digest':metadata[2],
        'read_versions':reads,'receipt':receipt,'payload':owner.entry_metadata[1],
        'general_lifecycle_original':value,'general_lifecycle_digest':row[3],'general_lifecycle_kind':input_kind}


def resolve_general_growth_lifecycle_followup_v1(db,frame,event,original):
    value=original['general_lifecycle_original']
    if event.event_kind=='general_growth_intent_available_for_future_trial':
        targets=(value.proposal_ref,*value.trial_start_refs)
        missing=('awaiting_actual_owner_registered_general_growth_trial_start',)
    elif event.event_kind=='general_growth_trial_start_available_for_observation':
        targets=(value.start_ref,value.completed_trial_ref)
        missing=('awaiting_actual_matching_general_growth_outcome_observation',)
    else:
        targets=(value.growth_proposal_ref,event.trigger_original.original_ref)
        missing=('awaiting_new_authorized_owner_adopt_general_growth_request',)
    return DomainFollowupResolutionV1('waiting_for_original',(),tuple(targets),missing,
        'general-growth-lifecycle:'+canonical_digest((event.namespace,event.dedupe_key))[:48])


def general_growth_start_matches_metadata_v1(raw,criterion):
    from .d01_general_growth_v1 import GeneralGrowthTrialStartV1
    if (type(raw)is not dict or set(raw)!=set(GeneralGrowthTrialStartV1.__dataclass_fields__)
            or raw['schema']!='d01.general-growth-trial-start.v1'
            or raw['namespace']!={'bot_id':criterion[0][0],'persona_id':criterion[0][1]}):
        raise ValueError('General pending census has unknown exact signed Start metadata')
    if criterion[4]=='action':
        return (raw['action_id'],raw['effect_id'],raw['attempt_id'])==criterion[5]
    plan=raw['planned_life_plan_original']
    return (raw['project_ref'],raw['activity_id'],raw['effect_id'])==criterion[5]and(type(plan)is dict
        and (plan['kind'],plan['original_ref'],plan['original_digest'])in criterion[6])


@dataclass(frozen=True,slots=True)
class GeneralGrowthTrialFollowupCommandV1:
    receiver_domain:str
    operation_kind:str
    request:object
    activity_id:str
    audience_ref:str
    audience_refs:tuple[str,...]
    start_original_ref:str
    start_original_digest:str
    start_producing_operation_id:str
    start_producing_original_digest:str
    source_authority:object
    parent_budget_lease_ref:str
    original_grant_digest:str
    original_deadline_utc:float
    original_budget_ancestor_refs:tuple[str,...]
    def __post_init__(self):
        from .d01_general_growth_v1 import DeriveCurrentGeneralGrowthTrialRequestV1
        from ..runtime_contracts import AuthorityContext
        import math
        if ((self.receiver_domain,self.operation_kind)!=('d01','derive_general_growth_trial_v1')
                or type(self.request)is not DeriveCurrentGeneralGrowthTrialRequestV1
                or type(self.source_authority)is not AuthorityContext
                or self.source_authority.purpose!='consolidation'
                or self.audience_refs!=self.source_authority.audience or not self.audience_refs
                or self.audience_ref!=self.audience_refs[0]or 'd01'not in self.source_authority.owner_scope
                or not self.parent_budget_lease_ref or not math.isfinite(self.original_deadline_utc)):
            raise ValueError('General derive handoff requires its exact actual Start purpose/audience/budget/deadline')


def _general_growth_outcome_criterion_v1(db,event,original,issuer):
    if event.event_kind=='general_growth_action_outcome_available':
        if (original['domain'],original['operation_kind'])!=('d08','settle_observed_action'):
            raise ValueError('General action notification has another actual settled-action producer')
        raw=original['payload']['provenance']['action_outcome']
        return (event.namespace.as_tuple,event.event_kind,event.causal_operation_id,original['original_digest'],
            'action',(raw['action_id'],raw['effect_id'],raw['attempt_id']),())
    from .d07_general_growth_attention_v1 import general_growth_followup_parent_v1
    trigger=general_growth_followup_parent_v1(db,event=event,issuer=issuer)
    if trigger is None:raise MissingProductionOriginalV1('actual_signed_general_life_outcome_trigger')
    plans=tuple((value.kind,value.original_ref,value.original_digest)for value in trigger.context_original_refs
        if value.kind=='d11.life_plan')
    if len(plans)!=1:raise ValueError('General Life completion lacks its unique actual verified immutable plan')
    return (event.namespace.as_tuple,event.event_kind,event.causal_operation_id,original['original_digest'],
        'life',(trigger.project_ref,trigger.activity_id,trigger.effect_id),plans)


def read_general_growth_trial_followup_commands_v1(db,*,event,original,issuer,now):
    from .domain_background_read_v3 import (background_general_growth_start_census_v1,
        background_verify_signature_v3,background_json_digest_v3,background_json_matches_v3)
    from .d01_production_operations_v1 import SIGN_KIND
    from .d01_general_growth_v1 import (DeriveCurrentGeneralGrowthTrialRequestV1,
        RegisterCurrentGeneralGrowthTrialStartRequestV1,GeneralGrowthTrialStartV1)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import AuthorityContext
    criterion=_general_growth_outcome_criterion_v1(db,event,original,issuer)
    from .domain_background_read_v3 import _active_v3,background_point_v3
    owner=_active_v3(db)
    if owner.kind=='followup_child':page=('child',owner.handoff.command.start_original_ref)
    else:
        prior=background_point_v3(db,table='graph_domain_production_outbox_v1',columns=('receipt_json',),
            key_columns=('bot','persona','dedupe_key'),key=(*event.namespace.as_tuple,event.dedupe_key),legacy_reader=lambda:None)
        continuation=None if prior is None or prior[0]is None else background_json_loads_v3(prior[0])['continuation_ref']
        prefix='general-start-cursor:'
        page=('page',continuation[len(prefix):]if type(continuation)is str and continuation.startswith(prefix)else None)
    criterion=(*criterion,page)
    rows=background_general_growth_start_census_v1(db,criterion=criterion)
    commands=[];missing=[];targets=[]
    for ref,row in rows:
        raw=background_json_loads_v3(row[2])
        background_verify_signature_v3(issuer._signer,SIGN_KIND,row[2],row[4])
        if not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]:
            raise ValueError('General Start metadata differs from its complete canonical signed bytes')
        start,producer,request=_verified_general_start_metadata_v1(db,event.namespace,ref,row,raw)
        if _completed_general_trial_metadata_v1(db,event.namespace,start,issuer):
            continue
        authority=decode_typed_production_value_v1(producer['payload']['authority'],AuthorityContext)
        deadline=min((start.observation_deadline_utc,*(value[1]for value in start.ancestor_operations)))
        targets.append(ref)
        if authority.actor!=owner.authority.actor:
            missing.append('general_growth_start_current_owner_actor_changed:'+ref);continue
        if (authority.purpose not in owner.owner.purposes or not set(authority.audience)<=set(owner.owner.audiences)
                or 'workbench.activate'not in owner.owner.capabilities):
            missing.append('general_growth_start_current_owner_permission_changed:'+ref);continue
        if now>=deadline:
            missing.append('general_growth_original_start_deadline_expired:'+ref);continue
        if criterion[4]=='action':
            outcome=original['payload']['provenance']['action_outcome']
            if outcome['result_level']!='completed_verified'or outcome['unknown_effects']:
                missing.append('general_growth_action_not_completed_verified:'+ref);continue
            versions=tuple(version for version in original['receipt'].write_versions
                if version.key.type_name=='d08.action_outcome.v1'and version.key.name==outcome['outcome_id'])
        else:
            versions=tuple(version for version in original['receipt'].write_versions
                if version.key.type_name=='d10.life_progress.v1'and version.key.owner.subject==start.activity_id
                and version.key.name==start.effect_id)
        if len(versions)!=1:raise ValueError('General outcome has no unique actual causal write member')
        derived=DeriveCurrentGeneralGrowthTrialRequestV1(start.completed_trial_ref,request.general_growth_intent_ref,
            start.proposal_ref,versions[0].key.token)
        commands.append(GeneralGrowthTrialFollowupCommandV1('d01','derive_general_growth_trial_v1',derived,
            start.activity_id,authority.audience[0],authority.audience,ref,row[3],row[1],producer['original_digest'],
            authority,start.parent_budget_lease_ref,start.original_grant_digest,deadline,
            tuple(value[0][len('budget:'):]for value in start.ancestor_operations if value[0].startswith('budget:'))))
    return tuple(commands),tuple(targets),tuple(missing)


def resolve_general_growth_trial_metadata_v1(db,frame,event,original,*,issuer):
    commands,targets,missing=read_general_growth_trial_followup_commands_v1(db,event=event,
        original=original,issuer=issuer,now=frame.now_utc)
    from .domain_background_read_v3 import _active_v3
    census=_active_v3(db).general_trial_census
    continuation='general-start-cursor:'+(census.matches[-1][0]if census.matches else '')
    if census.incomplete_count and not targets:
        return DomainFollowupResolutionV1('waiting_for_original',(),(),('general_growth_metadata_page_wrap',),continuation)
    if not targets:
        return DomainFollowupResolutionV1('no_matching_general_start',(),(),(),None)
    status='partial'if missing and commands else 'ready'if commands else 'waiting_for_original'
    if census.incomplete_count>len(targets):
        status='partial'
        missing=(*missing,'general_growth_matching_start_tail')
    return DomainFollowupResolutionV1(status,commands,targets,missing,continuation if status!='ready'else None)


def _completed_general_trial_metadata_v1(db,namespace,start,issuer):
    from .domain_background_read_v3 import (background_signed_input_row_v3,background_verify_signature_v3,
        background_json_matches_v3,background_json_digest_v3)
    from .d01_production_operations_v1 import TABLE,SIGN_KIND
    from .d01_general_growth_v1 import GeneralGrowthTrialOriginalV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d07_general_growth_attention_v1 import _general_growth_adopted_metadata_row_v1
    from .domain_production_originals_v1 import _receipt
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row=background_signed_input_row_v3(db,namespace,TABLE,start.completed_trial_ref,'kind',legacy_reader=lambda:None)
    if row is None:return False
    if row[0]!='general_growth_trial_v1':raise ValueError('General completed ref has another immutable original kind')
    background_verify_signature_v3(issuer._signer,SIGN_KIND,row[2],row[4])
    raw=background_json_loads_v3(row[2])
    if not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]:
        raise ValueError('General completed original lost canonical signed EOF')
    from .domain_background_read_v3 import _active_v3,_general_growth_metadata_decode_peak_v1
    actual_reader=_active_v3(db)
    actual_reader.reserve_heap_v3(extra=16384)
    actual_reader.reserve_heap_v3(extra=_general_growth_metadata_decode_peak_v1(raw))
    trial=decode_typed_production_value_v1(raw,GeneralGrowthTrialOriginalV1)
    if (trial.trial_start_ref,trial.growth_proposal_ref,trial.completed)!=(start.start_ref,start.proposal_ref,True):
        raise ValueError('General completed original is not the actual registered Start/proposal')
    metadata=_general_growth_adopted_metadata_row_v1(db,namespace,row[1])
    if metadata is None or metadata[:2]!=('d01','derive_general_growth_trial_v1'):
        raise ValueError('General completed evidence has another actual producing operation')
    receipt=_receipt(background_json_loads_v3(metadata[6]))
    ledger=_producer_original_point_v3(db,table='graph_bundle_operations',
        columns=('digest','activity_id','effect_id','commit_seq'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,row[1]),legacy_reader=lambda:None)
    if (receipt.status!='committed'or receipt.operation_id!=row[1]or receipt.operation_digest!=metadata[3]
            or canonical_digest(receipt)!=metadata[4]
            or ledger!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
        raise ValueError('General completed signed evidence lacks the real successful receipt and ledger')
    return True



def _verified_general_start_metadata_v1(db,namespace,ref,row,raw):
    from .d01_general_growth_v1 import GeneralGrowthTrialStartV1,RegisterCurrentGeneralGrowthTrialStartRequestV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_background_read_v3 import _active_v3,_general_growth_metadata_decode_peak_v1
    actual_reader=_active_v3(db)
    actual_reader.reserve_heap_v3(extra=16384)
    actual_reader.reserve_heap_v3(extra=_general_growth_metadata_decode_peak_v1(raw))
    start=decode_typed_production_value_v1(raw,GeneralGrowthTrialStartV1)
    producer=read_adopted_domain_operation_v1(db,namespace,row[1])
    if producer is None or (producer['domain'],producer['operation_kind'])!=('d01','register_general_growth_trial_start_v1'):
        raise ValueError('General Start lacks its real preexecution registered W01')
    request=decode_typed_production_value_v1(producer['payload']['request'],RegisterCurrentGeneralGrowthTrialStartRequestV1)
    if (start.start_ref!=ref or start.producing_operation_id!=row[1]
            or start.producing_receipt_digest!=canonical_digest(producer['receipt'])
            or (request.original_ref,request.growth_proposal_ref,request.completed_trial_ref,request.planned_head,
                request.project_ref,request.recipe_ref,request.step_id)!=(start.start_ref,start.proposal_ref,
                start.completed_trial_ref,start.planned_head,start.project_ref,start.recipe_ref,start.step_id)
            or producer['payload']['parent_budget']!=start.parent_budget_lease_ref):
        raise ValueError('General Start lost the exact signed producer/request/receipt identity')
    return start,producer,request
