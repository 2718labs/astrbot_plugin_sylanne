"""Closed B3 DomainOriginal business projections; these codecs issue no authority."""
from dataclasses import fields
from ..graph_types import AtomKey,GraphVersion,GraphWrite
from ..runtime_contracts import canonical_digest,NamespaceId
from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionQueryCoverageV1
from .domain_production_erasure_v1 import DomainProductionErasureHold,_exact,decode_typed_production_value_v1

LONG_KINDS=frozenset(('adopt_long_term_plan_v1','prepare_joint_window_v1','enter_current_joint_window_v1','finalize_current_joint_window_v1','advance_long_term_window_v1','pause_long_term_plan_v1','resume_long_term_plan_v1','stop_long_term_plan_v1'))
POLICY_KINDS=frozenset(('create_habit_policy_v1','revise_habit_policy_v1','pause_habit_policy_v1','resume_habit_policy_v1','stop_habit_policy_v1'))
HABIT_KINDS=POLICY_KINDS|frozenset(('register_habit_occurrence_v1','qualify_habit_occurrence_v1','record_habit_miss_v1','adopt_habit_outcome_v1','register_current_habit_source_note_life_plan_v1'))
HABIT_D08_KINDS=frozenset(('instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1'))
JOINT_HABIT_BUSINESS_KINDS_V1=LONG_KINDS|HABIT_KINDS|HABIT_D08_KINDS|{'record_habit_window_cue_v1'}

def _refs(*values):
    return {AtomKey.from_token(value).token for value in values if value is not None}

def _heads(versions):return {v.key.token for v in versions}
def _original(raw):
    value=decode_typed_production_value_v1(raw,ProductionOriginalRefV1)
    return value,_heads(value.read_versions)

def _occurrence(raw):
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from ..domains.d10.habit_policy_v1 import HABIT_OCCURRENCE_TYPE
    value=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,raw)
    refs=_refs(value.policy_ref,value.recipe_ref,value.action_intent_ref,value.goal_ref,value.plan_ref,*value.source_refs)
    return value,refs

def _qualification(raw):
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
    value=decode_typed_production_value_v1(raw,HabitOccurrenceQualificationOriginalV1);s=value.selector
    return value,_heads(value.read_versions)|_refs(value.occurrence_head.key.token,s.policy_ref,s.recipe_ref,s.target_ref,*s.source_refs,*value.counted_occurrence_refs)

def _standing(raw):
    from ..authority_service.d10_habit_contract_v1 import HabitStandingPolicyOriginalV1
    from ..domains.d10.habit_policy_v1 import habit_policy_dependency_refs_v1
    value=decode_typed_production_value_v1(raw,HabitStandingPolicyOriginalV1)
    return value,_refs(*habit_policy_dependency_refs_v1(value.definition))

def habit_window_cue_from_domain_plain_v1(raw):
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueOriginalV1
    return decode_typed_production_value_v1(raw,HabitWindowCueOriginalV1)

def _cue_refs(value):return _heads(value.read_versions)|_refs(value.selector.policy_ref,value.selector.subscription_job_ref)

def _current(raw):
    from ..authority_service.current_habit_occurrence_v1 import habit_current_from_wire_v1
    from ..domains.d10.habit_policy_v1 import habit_policy_dependency_refs_v1
    value=habit_current_from_wire_v1(raw)
    return value,_heads(value.read_versions)|_refs(value.owner_guard.grant_ref,*habit_policy_dependency_refs_v1(value.policy_original.definition))

def _long_refs(value):
    from ..domains.d08.long_term_plan_v1 import LongTermPlanV1,JointWindowV1,LongTermWindowAdvanceV1
    if type(value)is LongTermPlanV1:
        refs=_refs(value.goal_ref,value.project_ref,value.current_window_ref,*value.source_refs)
        for m in value.milestones:refs|=_refs(m.goal_ref,m.project_ref,*m.source_refs)
        return refs
    if type(value)is JointWindowV1:
        refs=_refs(value.long_term_plan_ref,value.prior_window_ref,value.final_joint_plan_ref,*value.source_refs)
        for n in value.node_drafts:
            refs|=_refs(n.goal_ref,n.project_ref,n.recipe_ref,*n.source_refs)
            if n.executor_kind=='source_note':refs|=_refs(n.typed_request_ref,n.target_ref)
        return refs
    if type(value)is LongTermWindowAdvanceV1:return _refs(value.plan_ref,value.previous_window_ref,value.next_window_ref,*value.source_refs)
    raise DomainProductionErasureHold('unknown typed long-window projection')

def _joint(raw):
    from .joint_node_execution_v1 import JointPlanQualificationV1
    value=decode_typed_production_value_v1(raw,JointPlanQualificationV1)
    return value,_heads(value.read_versions)|_refs(value.plan_ref,*value.source_refs)

def _long_business(domain,kind,raw):
    from ..domains.d08.long_term_plan_v1 import LONG_PLAN_TYPE,JOINT_WINDOW_TYPE,WINDOW_ADVANCE_TYPE,long_term_value_from_wire_v1
    if domain!='d08':raise DomainProductionErasureHold('long-window original has another writer')
    if kind=='adopt_long_term_plan_v1':
        _exact(raw,('plan','authorization'));value=long_term_value_from_wire_v1(LONG_PLAN_TYPE,raw['plan']);authorization,refs=_original(raw['authorization'])
        if(authorization.original_ref,authorization.original_digest)!=(value.owner_authorization_original_ref,value.owner_authorization_original_digest):raise DomainProductionErasureHold('long plan changed its actual Owner adoption original')
        return refs|_long_refs(value)
    if kind=='prepare_joint_window_v1':
        _exact(raw,('window','long_plan_head','draft_original','conditioned_preference'));value=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,raw['window']);head=decode_typed_production_value_v1(raw['long_plan_head'],GraphVersion);draft,refs=_original(raw['draft_original'])
        if head.key.token!=value.long_term_plan_ref or head.revision!=value.long_term_plan_revision or(draft.original_ref,draft.original_digest)!=(value.draft_terms_original_ref,value.draft_terms_original_digest):raise DomainProductionErasureHold('window changed its real plan/draft commitments')
        if raw['conditioned_preference']is not None:
            from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
            p=decode_typed_production_value_v1(raw['conditioned_preference'],ConditionedLifeStrategyProjectionV1)
            refs|=_heads((p.project_head,p.recipe_head,p.plan_head,p.goal_head))|_heads(p.condition_match.condition_heads)|_refs(*p.source_refs,*p.condition_match.source_refs)
        return refs|_long_refs(value)|{head.key.token}
    if kind=='enter_current_joint_window_v1':
        _exact(raw,('window','prior_actual_qualification'));value=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,raw['window']);refs=_long_refs(value)
        if value.state!='preparing':raise DomainProductionErasureHold('enter window cannot make it executable')
        if raw['prior_actual_qualification']is not None:_,more=_joint(raw['prior_actual_qualification']);refs|=more
        return refs
    if kind=='finalize_current_joint_window_v1':
        _exact(raw,('window','joint_qualification','accepted_final_terms'));value=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,raw['window']);qualified,refs=_joint(raw['joint_qualification']);terms,more=_original(raw['accepted_final_terms'])
        if value.state not in {'ready','waiting'}or(value.final_joint_plan_ref,value.final_joint_plan_revision)!=(qualified.plan_ref,qualified.plan_revision)or(value.final_terms_original_ref,value.final_terms_original_digest)!=(terms.original_ref,terms.original_digest):raise DomainProductionErasureHold('final window needs exact real final qualification/terms')
        return refs|more|_long_refs(value)
    if kind=='advance_long_term_window_v1':
        _exact(raw,('advance','actual_node_qualification','milestone_evidence'));value=long_term_value_from_wire_v1(WINDOW_ADVANCE_TYPE,raw['advance']);qualified,refs=_joint(raw['actual_node_qualification']);evidence=decode_typed_production_value_v1(raw['milestone_evidence'],tuple[ProductionOriginalRefV1,...])
        if(value.joint_qualification_original_ref,value.joint_qualification_original_digest,value.result_versions_digest)!=(qualified.original_ref,qualified.digest,qualified.result_versions_digest)or tuple(v.original_ref for v in evidence)!=value.milestone_evidence_original_refs:raise DomainProductionErasureHold('advance must retain its actual predecessor predicate originals')
        for v in evidence:refs|=_heads(v.read_versions)
        return refs|_long_refs(value)
    _exact(raw,('before','after'));before=long_term_value_from_wire_v1(LONG_PLAN_TYPE,raw['before']);after=long_term_value_from_wire_v1(LONG_PLAN_TYPE,raw['after'])
    expected={'pause_long_term_plan_v1':'paused','resume_long_term_plan_v1':'waiting','stop_long_term_plan_v1':'stopped'}[kind]
    if after.revision!=before.revision+1 or after.state!=expected or any(getattr(before,f.name)!=getattr(after,f.name)for f in fields(type(before))if f.name not in {'revision','state'}):raise DomainProductionErasureHold('long-plan control cannot rewrite the descriptive commitment')
    return _long_refs(before)|_long_refs(after)

def _subscription(raw):
    from .habit_schedule_driver_v1 import habit_subscription_from_wire_v1,HabitWindowScheduleCensusV1
    from .jobs import PersistentJob,_job_from_dict
    from .d11_types import job_graph_write
    _exact(raw,('before','after','core_cue_original','window_census'));refs=set();jobs=[]
    for group in ('before','after'):
        rows=raw[group]
        if type(rows)is not list or len(rows)>2:raise DomainProductionErasureHold('Habit subscription changes only its old/new revision jobs')
        for row in rows:
            _exact(row,{f.name for f in fields(PersistentJob)});job=_job_from_dict(row);value=habit_subscription_from_wire_v1(row['continuation']);refs|=_refs(value.policy_ref,*value.source_refs,job_graph_write(job).key.token);jobs.append(job)
    if raw['core_cue_original']is not None:refs|=_cue_refs(habit_window_cue_from_domain_plain_v1(raw['core_cue_original']))
    census=raw['window_census']
    if census is not None:
        _exact(census,{f.name for f in fields(HabitWindowScheduleCensusV1)})
        versions=decode_typed_production_value_v1(census['observed_versions'],tuple[GraphVersion,...]);coverage=decode_typed_production_value_v1(census['query_coverage'],tuple[ProductionQueryCoverageV1,...])
        value=HabitWindowScheduleCensusV1(decode_typed_production_value_v1(census['namespace'],NamespaceId),census['policy_ref'],census['window_id'],decode_typed_production_value_v1(census['occurrence_refs'],tuple[str,...]),decode_typed_production_value_v1(census['graph_cue_original_refs'],tuple[str,...]),decode_typed_production_value_v1(census['core_cue_original_refs'],tuple[str,...]),versions,coverage,census['coverage'])
        if value.coverage!='complete':raise DomainProductionErasureHold('subscription cursor requires actual complete cross-revision census')
        refs|=_heads(versions)|_refs(value.policy_ref,*value.occurrence_refs)
    return refs

def _selected(raw):
    from .d10_habit_v1 import HabitSelectedExecutionV1
    from ..domains.d08.personal_candidate_v1 import PersonalCandidateFutureIdentityV1
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    _exact(raw,{f.name for f in fields(HabitSelectedExecutionV1)})
    future=decode_typed_production_value_v1(raw['future_identity'],PersonalCandidateFutureIdentityV1);selector=decode_typed_production_value_v1(raw['phase_selector'],ArtifactDraftPhaseSelectorV2)
    for name in ('decision_digest','prepared_candidates_digest'):
        from ..domains.d10.habit_policy_v1 import _sha
        _sha(raw[name])
    value=HabitSelectedExecutionV1(future,selector,raw['prepared_candidates_operation_id'],raw['prepared_candidates_digest'],raw['decision_ref'],raw['decision_digest'])
    return value,_refs(value.decision_ref,selector.decision_ref,selector.plan_ref,selector.task.cycle_job_ref,future.action_ref)

def _life_plan(raw):
    from .d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
    value=life_from_wire_v1(raw,RegisteredLifePlanV2)
    return value,_refs(*(getattr(value,name).ref for name in ('project','recipe','action_intent','input_source','input_access')))

def _habit_business(domain,kind,raw):
    from .d10_habit_v1 import HabitSourceNoteContextV1,habit_source_note_context_from_wire_v1
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1,habit_policy_dependency_refs_v1,HABIT_DISPOSITION_TYPE,HABIT_OUTCOME_TYPE
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    if domain!='d10':raise DomainProductionErasureHold('Habit bookkeeping original has another writer')
    if kind in POLICY_KINDS:
        _exact(raw,('policy','core_standing_original','habit_draft_managed_target','habit_subscription_transition'));policy=graph_adopted_habit_policy_from_wire_v1(raw['policy']);standing,refs=_standing(raw['core_standing_original'])
        if policy.definition!=standing.definition or(policy.core_original_ref,policy.core_original_digest)!=(standing.original_ref,standing.digest):raise DomainProductionErasureHold('Graph policy must mirror exactly its independent standing original')
        target=raw['habit_draft_managed_target']
        if target is not None:
            _exact(target,('selector_commitment','decision_ref','decision_digest','phase_selector_digest','future_identity_digest'))
            from ..domains.d10.habit_policy_v1 import _sha
            for name in ('selector_commitment','decision_digest','phase_selector_digest','future_identity_digest'):_sha(target[name])
            refs|=_refs(target['decision_ref'])
        return refs|_subscription(raw['habit_subscription_transition'])|_refs(*habit_policy_dependency_refs_v1(policy.definition))
    if kind in {'record_habit_miss_v1','register_habit_occurrence_v1'}and set(raw)=={'miss_disposition'}:
        value=habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE,raw['miss_disposition'])
        return _refs(value.policy_ref,*value.source_refs)
    if kind=='register_habit_occurrence_v1':
        _exact(raw,('occurrence','actual_cue','selected_execution','window_census_digest','counted_occurrence_refs'));occ,refs=_occurrence(raw['occurrence'])
        from .habit_schedule_driver_v1 import SemanticHabitCueObservationV1
        from .domain_mesh_contract_v1 import HabitCueObservationV1
        cue_type=SemanticHabitCueObservationV1 if set(raw['actual_cue'])=={f.name for f in fields(SemanticHabitCueObservationV1)}else HabitCueObservationV1
        cue=decode_typed_production_value_v1(raw['actual_cue'],cue_type)
        if(occ.namespace,occ.policy_ref,occ.policy_revision,occ.cue_original_ref,occ.cue_original_digest,occ.cue_stable_key)!=(cue.namespace,cue.policy_ref,cue.policy_revision,cue.cue_original_ref,cue.cue_original_digest,cue.cue_stable_key)or occ.state!='registered':raise DomainProductionErasureHold('occurrence registration must retain the actual cue identity')
        from ..domains.d10.habit_policy_v1 import _sha
        _sha(raw['window_census_digest']);counted=decode_typed_production_value_v1(raw['counted_occurrence_refs'],tuple[str,...]);refs|=_refs(*cue.source_refs,*counted)
        if raw['selected_execution']is not None:
            target,more=_selected(raw['selected_execution']);refs|=more
            if(occ.occurrence_operation_id,occ.effect_id,occ.attempt_id,occ.activity_id)!=(target.future_identity.action_operation_id,target.future_identity.effect_id,target.future_identity.attempt_id,target.future_identity.activity_id):raise DomainProductionErasureHold('Draft occurrence must preserve the original selected generation')
        elif occ.executor_kind!='source_note':raise DomainProductionErasureHold('Draft registration cannot omit the actual selected generation')
        return refs
    if kind=='qualify_habit_occurrence_v1':
        _exact(raw,('occurrence','core_qualification'));occ,refs=_occurrence(raw['occurrence']);q,more=_qualification(raw['core_qualification'])
        if occ.state!='qualified'or occ.qualification_original_ref!=q.original_ref or(occ.occurrence_operation_id,occ.effect_id,occ.attempt_id)!=(q.selector.execution_operation_id,q.selector.effect_id,q.selector.attempt_id):raise DomainProductionErasureHold('Habit qualification is an exact independent original of this durable occurrence')
        return refs|more
    if kind=='adopt_habit_outcome_v1':
        _exact(raw,('habit_outcome','actual_life_progress','actual_terminal','actual_accounting'));value=habit_value_from_wire_v1(HABIT_OUTCOME_TYPE,raw['habit_outcome'])
        from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
        from .d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
        progress=decode_typed_production_value_v1(raw['actual_life_progress'],LifeProgressHeadV1);terminal=life_from_wire_v1(raw['actual_terminal'],D11LifeTerminalV1);accounting=decode_typed_production_value_v1(raw['actual_accounting'],tuple[ProductionOriginalRefV1,...])
        if terminal.status!='completed'or progress.actuality!='completed'or progress.reality!='real_execution'or value.actual_terminal_original_ref!=terminal.original_ref or tuple(v.original_ref for v in accounting)!=value.accounting_original_refs or(progress.activity_id,progress.effect_id)!=(terminal.binding.activity_id,terminal.binding.effect_id):raise DomainProductionErasureHold('Habit outcome requires actual completed Life progress, terminal and accounting originals')
        refs=_refs(value.occurrence_ref,value.life_progress_ref,value.encoding_trigger_ref,*value.source_refs,progress.project_ref,progress.recipe_ref,*progress.source_refs)
        for v in accounting:refs|=_heads(v.read_versions)
        return refs
    _exact(raw,('life_plan','habit_occurrence_ref','occurrence','core_qualification','action_original_ref','action_original_digest','body_original_ref','body_original_digest'));plan,refs=_life_plan(raw['life_plan']);occ,more=_occurrence(raw['occurrence']);q,qrefs=_qualification(raw['core_qualification'])
    from .d10_habit_v1 import habit_source_note_life_ids_v1
    ids=habit_source_note_life_ids_v1(occ.namespace,occ.occurrence_id,plan.project.ref)
    if kind!='register_current_habit_source_note_life_plan_v1'or raw['habit_occurrence_ref']!=q.occurrence_head.key.token or occ.life_plan_original_ref!=ids['plan_ref']or(plan.operation_id,plan.activity_id,plan.effect_id,plan.attempt_id,plan.parent_budget_lease_ref)!=(occ.occurrence_operation_id,occ.activity_id,occ.effect_id,occ.attempt_id,occ.parent_root_grant_ref)or(raw['action_original_ref'],raw['body_original_ref'])!=(ids['action_original_ref'],ids['body_original_ref']):raise DomainProductionErasureHold('Habit registered Life plan must retain exact preceding Action/Body and original execution')
    from ..domains.d10.habit_policy_v1 import _sha
    _sha(raw['action_original_digest']);_sha(raw['body_original_digest'])
    return refs|more|qrefs|_refs(raw['habit_occurrence_ref'])


def _habit_d08_business(domain,kind,raw):
    from .d10_habit_v1 import habit_source_note_context_from_wire_v1
    if domain!='d08':raise DomainProductionErasureHold('Habit context/Action original has another writer')
    if kind=='instantiate_current_habit_source_note_context_v1':
        _exact(raw,('habit_source_note_context','before_checkpoint','core_qualification','habit_execution_current','occurrence'));context=habit_source_note_context_from_wire_v1(raw['habit_source_note_context'])
        from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE,decode_project_checkpoint_type_v1
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,raw['before_checkpoint']);occ,refs=_occurrence(raw['occurrence']);q,more=_qualification(raw['core_qualification']);current,cr=_current(raw['habit_execution_current'])
        if current.qualification_original!=q or context.qualification_original_ref!=q.original_ref or(context.goal_head.key.token,context.plan_head.key.token)!=(occ.goal_ref,occ.plan_ref)or context.occurrence_ref!=q.occurrence_head.key.token or context.occurrence_before_revision!=current.request.expected_occurrence_revision:raise DomainProductionErasureHold('Habit context must retain actual qualification and newly committed occurrence context')
        heads=(context.project_head,context.checkpoint_before_head,context.parent_plan_head,context.parent_goal_head,context.input_source_head,context.role_binding_head,context.target_entity_head,context.goal_head,context.plan_head)
        return refs|more|cr|_heads(heads)|_refs(checkpoint.project_ref,checkpoint.plan_ref)
    shape=('source_note_target_entity_ref','source_note_role_binding_ref','source_note_project_ref','source_note_recipe_ref','source_note_goal_ref','derived_request','occurrence','core_standing_original','core_qualification','habit_execution_current','habit_context')
    _exact(raw,shape)
    from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1
    request=decode_typed_production_value_v1(raw['derived_request'],PrepareSourceNoteActionRequestV1);occ,refs=_occurrence(raw['occurrence']);standing,sr=_standing(raw['core_standing_original']);q,qr=_qualification(raw['core_qualification']);current,cr=_current(raw['habit_execution_current']);context,rr=_original(raw['habit_context'])
    if current.policy_original!=standing or current.qualification_original!=q or(occ.context_original_ref,occ.context_original_digest)!=(context.original_ref,context.original_digest)or context.kind!='d08.current-instantiate_current_habit_source_note_context_v1':raise DomainProductionErasureHold('Habit Action requires its actual preceding context and independent standing/current qualification')
    declared=(raw['source_note_project_ref'],raw['source_note_recipe_ref'],raw['source_note_goal_ref'],raw['source_note_target_entity_ref'],raw['source_note_role_binding_ref'])
    if declared!=(request.project_ref,request.recipe_ref,request.goal_ref,request.target_entity_ref,request.role_binding_ref):raise DomainProductionErasureHold('Habit Action must retain the exact original SourceNote inputs')
    return refs|sr|qr|cr|rr|_refs(*declared,request.source_ref)


def _life_transition(raw):
    from .d10_habit_v1 import HabitLifeOccurrenceTransitionV1
    from ..authority_service.d10_habit_execution_contract_v1 import habit_occurrence_execution_from_wire_v1
    from ..authority_service.current_habit_artifact_restriction_v1 import habit_artifact_additional_from_wire_v1
    _exact(raw,{f.name for f in fields(HabitLifeOccurrenceTransitionV1)})
    selector_raw=raw['execution_selector'];selector=habit_occurrence_execution_from_wire_v1(selector_raw)if selector_raw['schema']=='d10.habit-occurrence-execution-selector.v1'else habit_artifact_additional_from_wire_v1(selector_raw)
    action=decode_typed_production_value_v1(raw['action_head'],GraphVersion);write=decode_typed_production_value_v1(raw['write'],GraphWrite);occ,refs=_occurrence(write.value)
    if raw['schema']!='d10.habit-life-occurrence-transition.v1'or selector.operation_kind!='prepare_life'or selector.occurrence_ref!=raw['occurrence_ref']or selector.expected_occurrence_revision!=raw['occurrence_before_revision']or write.key.token!=raw['occurrence_ref']or occ.state!='active'or raw['qualification_original_ref']!=selector.qualification_original_ref or raw['qualification_original_digest']!=selector.qualification_original_digest:raise DomainProductionErasureHold('Life transition is only this exact qualified-to-active occurrence member')
    from ..domains.d10.habit_policy_v1 import _sha
    for name in ('occurrence_before_digest','action_digest','qualification_original_digest','core_current_digest'):_sha(raw[name])
    for name in ('occurrence_before_revision','job_fence','job_cancel_epoch'):
        minimum=0 if name=='job_cancel_epoch'else 1
        if type(raw[name])is not int or raw[name]<minimum:raise DomainProductionErasureHold('Habit Life transition requires actual revision/fence/cancellation metadata')
    for name in ('job_id','job_holder','qualification_original_ref'):
        if type(raw[name])is not str or not raw[name]:raise DomainProductionErasureHold('Habit Life transition requires actual original job identity')
    return selector,occ,refs|_refs(action.key.token)|{k.token for k in write.dependencies}


def validate_joint_habit_business_provenance_v1(domain,kind,raw):
    """Decode named business fields; never search arbitrary JSON or predicate parameter text."""
    if type(raw)is not dict:raise DomainProductionErasureHold('B3 provenance must be its exact named object')
    if kind in LONG_KINDS:return tuple(sorted(_long_business(domain,kind,raw)))
    if kind in HABIT_D08_KINDS:return tuple(sorted(_habit_d08_business(domain,kind,raw)))
    if kind in HABIT_KINDS:return tuple(sorted(_habit_business(domain,kind,raw)))
    if kind=='record_habit_window_cue_v1':
        if domain!='d11':raise DomainProductionErasureHold('time cue has another actual writer')
        expected={'core_cue_original','policy_head','habit_subscription_transition'}
        core=habit_window_cue_from_domain_plain_v1(raw['core_cue_original'])
        if core.execution_state!='due':expected.add('miss_disposition')
        _exact(raw,expected);head=decode_typed_production_value_v1(raw['policy_head'],GraphVersion)
        if(head.key.token,head.revision)!=(core.selector.policy_ref,core.selector.policy_revision):raise DomainProductionErasureHold('Graph cue must retain the real Core policy/window original')
        refs=_cue_refs(core)|_subscription(raw['habit_subscription_transition'])|{head.key.token}
        if core.execution_state!='due':
            from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
            from ..domains.d10.habit_policy_v1 import HABIT_DISPOSITION_TYPE
            miss=habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE,raw['miss_disposition'])
            if(miss.policy_ref,miss.window_id,miss.cue_original_ref,miss.disposition)!=(core.selector.policy_ref,core.selector.window_id,core.original_ref,core.execution_state):raise DomainProductionErasureHold('late cue may record only its exact original miss rule')
            refs|=_refs(miss.policy_ref,*miss.source_refs)
        return tuple(sorted(refs))
    if(domain,kind)==('d10','prepare_life')and 'habit_life_occurrence_transition'in raw:
        _exact(raw,('prepared_binding','execution','habit_life_occurrence_transition'))
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
        binding=life_from_wire_v1(raw['prepared_binding'],D11LifeExecutionBindingV1);selector,occ,refs=_life_transition(raw['habit_life_occurrence_transition'])
        if raw['execution']!='requires_actual_d11_once_claim_and_durable_artifact_postcondition'or(selector.operation_id,occ.occurrence_operation_id,occ.activity_id,occ.effect_id,occ.attempt_id)!=(binding.prepare_operation_id,binding.operation_id,binding.activity_id,binding.effect_id,binding.attempt_id):raise DomainProductionErasureHold('Habit Life transition must be the actual original prepared job identity')
        return tuple(sorted(refs|_refs(binding.owner_grant_ref)))
    if 'managed_window_argument'in raw:
        if(domain,kind)not in {('d08','prepare_selected_source_note_action_v2'),('d10','input:register_joint_node_execution_binding_v1')}:raise DomainProductionErasureHold('managed preparation wrapper has another actual legacy producer')
        from .joint_window_management_v1 import managed_window_argument_from_wire_v1
        from .domain_production_erasure_v1 import validate_domain_stage_provenance_v1
        value=managed_window_argument_from_wire_v1(raw['managed_window_argument']);inner={k:v for k,v in raw.items()if k!='managed_window_argument'}
        refs=set(validate_domain_stage_provenance_v1(domain,kind,inner))|_refs(value.window_ref)
        if value.executor_kind=='source_note':refs|=_refs(value.typed_input_original_ref)
        return tuple(sorted(refs))
    raise DomainProductionErasureHold('unknown B3 business provenance kind/variant')
