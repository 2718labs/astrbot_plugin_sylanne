"""Independent Habit metadata, Source groups and exact fresh-WRITE data inputs.

The Beta1 reader supplies bounded SQL/JSON mechanics. Only this module's private
registries admit Habit selectors; an old READ result never issues WRITE authority.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass,field,fields,is_dataclass,asdict,replace
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .domain_production_contracts_v1 import ProductionReadPlanV1,ProductionOriginalRefV1
from .dispatch_current_inventory_v3 import _heap

HABIT_SOURCE_WORK_KIND_V3='current_habit_source_read_v3'
HABIT_SCHEDULE_READ_KIND_V3='read_current_habit_schedule_v3'
HABIT_RECEIPT_READ_KIND_V3='read_current_habit_receipt_v3'
HABIT_POLICY_READ_KIND_V3='qualify_current_habit_definition_v3'
_ISSUER=object()
_STATES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_PENDING=WeakKeyDictionary()
_PENDING_READERS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class HabitScheduleReadSelectorV3:
    namespace:NamespaceId
    installation_id:str

@dataclass(frozen=True,slots=True)
class HabitReceiptReadSelectorV3:
    selector:object

@dataclass(frozen=True,slots=True)
class HabitDefinitionReadSelectorV3:
    action:str
    definition:object
    business_operation_id:str

@dataclass(slots=True)
class _HabitSourceStateV3:
    reader:object
    identity:tuple
    selector:object=None
    context:object=None
    tasks:dict=field(default_factory=dict)
    selected:set=field(default_factory=set)
    selected_keys:set=field(default_factory=set)
    body_keys:set=field(default_factory=set)
    source_roots:set=field(default_factory=set)
    source_groups:dict=field(default_factory=dict)
    history:set=field(default_factory=set)
    producers:set=field(default_factory=set)
    originals:set=field(default_factory=set)
    metadata_complete:bool=False
    source_permission:object=None
    owner_binding:object=None
    core_inputs:object=None
    prepared:object=None
    frame:object=None
    policy_versions:dict=field(default_factory=dict)
    parameter_tasks:dict=field(default_factory=dict)
    retired_keys:set=field(default_factory=set)
    budget_ancestry:tuple|None=None
    root_locator:tuple|None=None
    read_deadline:float|None=None
    original_execution_deadline:float|None=None
    schema_locator:object=None
    receipt:object=None
    committed_original:object=None
    cue_originals:dict=field(default_factory=dict)
    cue_inventory:object=None


def habit_source_operation_types_v3():
    from .d10_habit_v1 import _REQUESTS as habit
    from .d08_long_term_plan_v1 import _REQUESTS as longterm
    from .habit_schedule_driver_v1 import RecordHabitWindowCueRequestV1
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_followup_source_v3 import operation_types_v3
    return {**operation_types_v3(),**habit,**longterm,'record_habit_window_cue_v1':RecordHabitWindowCueRequestV1,
        'prepare_source_note_body':installed_operation_v1('prepare_source_note_body').request_type,
        'prepare_life':installed_operation_v1('prepare_life').request_type,
        HABIT_SCHEDULE_READ_KIND_V3:HabitScheduleReadSelectorV3,
        HABIT_RECEIPT_READ_KIND_V3:HabitReceiptReadSelectorV3,
        HABIT_POLICY_READ_KIND_V3:HabitDefinitionReadSelectorV3}


def _identity(reader):
    return(reader.graph,reader.runtime,reader.work,reader.operation,reader.fence,reader.namespace,
        reader.selection_digest,reader.graph_stamp,reader.catalogue_hash,reader.operation_kind,
        reader.request,reader.operation_id,reader.authority,reader.initial_monotonic_deadline)


def register_habit_source_work_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    if(reader.work.kind!=HABIT_SOURCE_WORK_KIND_V3 or reader.operation_kind not in habit_source_operation_types_v3()
            or type(reader.request)is not habit_source_operation_types_v3()[reader.operation_kind]
            or reader in _STATES):
        raise AuthorityUnavailable('Habit Source requires its once-issued exact own Work and typed request')
    _STATES[reader]=_HabitSourceStateV3(reader,_identity(reader),owner_binding=reader.owner_binding)


def require_habit_source_work_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    state=_STATES.get(reader)
    if(state is None or state.reader is not reader or state.identity!=_identity(reader)
            or reader.work.kind!=HABIT_SOURCE_WORK_KIND_V3 or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.operation.closed):
        raise AuthorityUnavailable('Habit Source lost its exact private Work/selector/selection/READ')
    reader.work._require_invocation(reader.graph)
    return state


def _active(db):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None or reader.work.kind!=HABIT_SOURCE_WORK_KIND_V3:return None
    require_habit_source_work_v3(reader)
    return reader


_HEAD_FIELDS=frozenset({'schema','namespace','definition','core_namespace','installation_id','core_policy_revision',
    'core_original_ref','core_original_digest','adoption_operation_id','source_refs','source_ids','input_source',
    'source_ref','parent_source_ids','policy_ref','policy_revision','policy_digest','occurrence_id','window_id',
    'window_start_utc','window_end_utc','cue_original_ref','cue_original_digest','cue_stable_key',
    'occurrence_operation_id','activity_id','effect_id','attempt_id','recipe_ref','recipe_revision','executor_kind',
    'parent_root_grant_ref','parent_root_grant_digest','original_deadline_utc','cancellation_generation','state',
    'action_intent_ref','life_plan_original_ref','qualification_original_ref','outcome_original_ref','admitted_at_utc',
    'actual_started_at_utc','context_original_ref','context_original_digest','goal_ref','plan_ref','project_ref',
    'next_step','reality','checkpoint_ref','current_window_ref','previous_window_ref','next_window_ref',
    'node_drafts','final_joint_plan_ref','final_joint_plan_revision','final_binding_refs','source_roots',
    'milestone_refs','terms_original_ref','binding_refs','result_original_refs','owner_ref','party_scope',
    'phase','job_id','work_kind','continuation','wake_condition','cancel_epoch','lease_holder','budget_ref',
    'deadline_utc','result_ref','operator_versions','operation_id','intent_ref','cancellation_point',
    'pending_original_effects','pending_effect_ids','unknown_effects','node_id','nodes','target_ref','scope_refs',
    'arguments','encoding_context','retention','recovery','production_operation_id','producing_operation_id',
    'identity','action_id','action_ref','result_level','completed_effects','unresolved_effects','requires_verification',
    'parent_budget_lease_ref','snapshot_ref','resource_ref','fence','lease_expires_utc','continuation_digest',
    'wake_condition_digest','operator_versions_digest','usage_digest','window_index','next_window_index',
    'standing_original_ref','standing_original_digest','due_at_utc','reason','profile_id'})
_CENSUS_TYPES=frozenset({'d02.body_profile.v1','d02.body_state.v1','d02.reservation.v1','d10.habit_policy.v1','d10.habit_occurrence.v1','d08.long_term_plan.v1',
    'd08.joint_window.v1','d10.project_checkpoint.v1','d08.personal_plan.v1','d08.decision_record.v2',
    'd08.action_intent.v1','d08.action_schema.v1','d08.action_outcome.v1','runtime.job','d03.role_binding','d03.entity_anchor',
    'd05.boundary_rule','d07.focus.v1','d07.attention_ticket.v1'})


def retain_habit_metadata_path_v3(task,path):
    if task.identity[0]in {'budget_grant','cue_original'}:return True
    if task.identity[0]=='job_continuation':
        if not path:return True
        return path[0]in _HEAD_FIELDS or path[0]in {'request','selected_scope','selector','phase_selector'}and (len(path)<2 or path[1]in _HEAD_FIELDS)
    if task.identity[0]=='life_prepared':
        from .life_prepared_source_metadata_v3 import retain_life_prepared_locator_path_v3
        return retain_life_prepared_locator_path_v3(path)
    if not path:return True
    if path[0]in {'nodes','node_drafts'}:
        return len(path)<3 or path[2]in {'schema','node_id','owner_ref','depends_on','action_kind','cancellation_point',
            'compensation_ref','resource_ref','pending_original_effects','carried_forward_verified','wait_condition',
            'source_refs','goal_ref','plan_ref','target_ref','activity_id','effect_id','attempt_id','state'}
    if path[0]in {'arguments','encoding_context','continuation','recovery','retention'}:
        if len(path)>2 and path[1]in {'request','selected_scope','artifact_phase_selector','phase_selector','future_identity'}:
            return path[2]in {'schema','namespace','source_refs','source_ref','project_ref','goal_ref','plan_ref',
                'action_intent_ref','policy_ref','policy_revision','occurrence_ref','parent_budget_lease_ref','target_ref',
                'activity_id','effect_id','attempt_id','operation_id','deadline_utc','original_deadline_utc'}
        return len(path)<2 or path[1]in {'schema','source_refs','source_ref','policy_ref','policy_revision',
            'policy_digest','standing_original_ref','standing_original_digest','window_id','window_index',
            'window_start_utc','window_end_utc','due_at_utc','original_deadline_utc','cancellation_generation',
            'project_ref','goal_ref','plan_ref','occurrence_ref','parent_budget_lease_ref','action_intent_ref',
            'request','selected_scope','artifact_phase_selector','phase_selector','future_identity'}
    if path[0]=='provenance':
        return len(path)<2 or path[1]in {'source_refs','source_roots','habit_occurrence_ref','habit_source_note_context',
            'core_standing_original','core_qualification','occurrence','habit_subscription_transition','life_plan'}
    return path[0]in _HEAD_FIELDS or path[0]in {'identity','authority','parent_budget','observed_originals'}


def habit_metadata_spec_v3(reader,identity):
    state=require_habit_source_work_v3(reader)
    if identity not in state.selected:raise AuthorityUnavailable('Habit metadata was not selected by its actual closed recipe')
    kind,value=identity
    if kind=='cue_original':
        return('graph_d10_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*reader.namespace.as_tuple,value),('kind','producing_operation_id','payload_digest','signature'),(),
            'd11.d10-production-input.v1')
    if kind=='job_continuation':
        job_id,token=value
        if AtomKey.from_token(token)not in state.selected_keys:raise AuthorityUnavailable('Habit SQL continuation has no actual Graph census head')
        return('runtime_jobs','continuation_json',('job_id',),(job_id,),
            ('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','phase','work_kind',
             'deadline_utc','budget_ref','lease_holder','fence','cancel_epoch'),tuple((name,)for name in _HEAD_FIELDS),None)
    if kind=='budget_grant':
        lease_id,version=value
        return('runtime_budget_grants','grant_json',('lease_id','version'),value,
            ('lease_id','version','signature','status'),(),'budget-grant.v1')
    if kind=='head':
        key=AtomKey.from_token(value)
        if NamespaceId.from_key(key)!=reader.namespace:raise AuthorityUnavailable('Habit metadata crossed namespace')
        return('graph_atoms','value',('token','bot','persona'),(value,*reader.namespace.as_tuple),
            ('revision','valid','value_cell_id'),tuple((name,)for name in _HEAD_FIELDS),None)
    if kind=='producer':
        if value not in state.producers:raise AuthorityUnavailable('Habit producer was not derived from an actual Graph event')
        return('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),
            (*reader.namespace.as_tuple,value),('domain','operation_kind','request_digest','original_digest'),
            (('schema',),('namespace',),('identity',),('authority',),('parent_budget',),('observed_originals',),
             ('provenance','source_refs'),('provenance','source_roots'),('provenance','occurrence'),
             ('provenance','habit_source_note_context'),('provenance','habit_subscription_transition')),None)
    if kind=='life_prepared':
        from .life_prepared_source_metadata_v3 import life_prepared_locator_spec_v3
        return life_prepared_locator_spec_v3(reader.namespace,value)
    if kind=='history':
        token,revision=value
        if value not in state.history:raise AuthorityUnavailable('Habit historical revision was not actually selected')
        return('graph_history','value',('token','revision'),(token,revision),
            ('event_bot','event_persona','event_id','valid','value_cell_id'),tuple((name,)for name in _HEAD_FIELDS),None)
    raise AuthorityUnavailable('Unregistered fixed Habit metadata selector')


def _graph_refs(value):
    if type(value)is AtomKey:return (value,)
    if type(value)is GraphVersion:return (value.key,)
    if type(value)is str:
        if not value.startswith('["'):return ()
        return (AtomKey.from_token(value),)
    if is_dataclass(value):return _graph_refs(asdict(value))
    if type(value)is dict:return tuple(key for child in value.values()for key in _graph_refs(child))
    if type(value)in(tuple,list):return tuple(key for child in value for key in _graph_refs(child))
    return ()


def _select_refs(reader,value,*,body=False):
    state=require_habit_source_work_v3(reader)
    for key in _graph_refs(value):
        if NamespaceId.from_key(key)!=reader.namespace:raise AuthorityUnavailable('Habit fixed locator crossed namespace')
        state.selected.add(('head',key.token));state.selected_keys.add(key)
        if body:state.body_keys.add(key)
        if body and key.type_name=='memory.source':state.source_roots.add(key.token)


def finish_habit_metadata_v3(task,value):
    reader=task.reader;state=require_habit_source_work_v3(reader)
    kind,selected=task.identity
    if kind=='cue_original':
        from .habit_schedule_driver_v1 import CUE_INPUT_KIND
        from .joint_habit_provenance_v1 import habit_window_cue_from_domain_plain_v1
        if task.metadata[0]!=CUE_INPUT_KIND or task.column.signature_verified is not True:
            raise AuthorityUnavailable('Habit cue metadata lacks actual registered kind and complete outer HMAC EOF')
        cue=habit_window_cue_from_domain_plain_v1(value)
        if cue.selector.namespace!=reader.namespace or cue.original_ref!=selected:
            raise AuthorityUnavailable('Habit cue metadata changed its actual selector/namespace/digest')
        state.cue_originals[selected]=cue;state.producers.add(task.metadata[1]);state.originals.add(selected)
        return cue
    if kind=='job_continuation':
        job_id,token=selected
        head=state.tasks.get(('head',token))
        if(head is None or not head.complete or head.result is None or task.metadata is None
                or tuple(task.metadata[4:6])!=reader.namespace.as_tuple
                or task.metadata[0]!=job_id or task.column.canonical_digest!=head.result['continuation_digest']):
            raise AuthorityUnavailable('Habit SQL continuation differs from its exact current Graph job/namespace/digest')
        for name,index in (('job_id',0),('operation_id',1),('activity_id',2),('effect_id',3),('phase',6),
                ('work_kind',7),('deadline_utc',8),('parent_budget_lease_ref',9),('lease_holder',10),('fence',11),('cancel_epoch',12)):
            if head.result[name]!=task.metadata[index]:raise AuthorityUnavailable('Habit SQL job metadata differs from its actual Graph mirror')
        _select_refs(reader,value,body=AtomKey.from_token(token)in state.body_keys)
        return value
    if kind=='budget_grant':
        from .issuers import BudgetLeaseGrant
        raw=dict(value);raw['allowed_work_kinds']=tuple(raw['allowed_work_kinds'])
        grant=BudgetLeaseGrant(**raw)
        if((grant.lease_id,grant.version)!=selected or (grant.bot_id,grant.persona_id)!=reader.namespace.as_tuple
                or task.column.signature_verified is not True):
            raise AuthorityUnavailable('Habit signed budget metadata differs from its actual selected lease/version/namespace')
        from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3
        if task.metadata[3]!='active'and habit_maintenance_source_reader_v3(reader)is None:
            raise AuthorityUnavailable('Habit execution requires an active signed original budget grant')
        return grant
    if kind=='life_prepared':
        from .life_prepared_source_metadata_v3 import finish_life_prepared_locator_v3
        facts=finish_life_prepared_locator_v3(namespace=reader.namespace,original_ref=selected,header=task.metadata,
            projection=value,fields_seen=task.column.beta1_metadata_fields_seen,whole_digest=task.column.canonical_digest,
            signer=reader.graph._GraphCoordinator__d11_issuer._signer)
        _select_refs(reader,facts.read_versions)
        state.source_roots.update(facts.source_roots);state.originals.add(selected)
        return facts
    if value is None:return None
    if type(value)is not dict:raise AuthorityUnavailable('Habit locator is not an exact registered object')
    if kind=='head':
        key=AtomKey.from_token(selected)
        state.selected_keys.add(key)
        if task.metadata is not None and task.metadata[1]!=1:
            state.retired_keys.add(key)
            return None
        if task.metadata is not None and task.metadata[0]>0:
            version=(key.token,task.metadata[0]);state.history.add(version);state.selected.add(('history',version))
        if key.type_name=='d10.habit_policy.v1':
            from ..domains.d10.habit_policy_v1 import GraphAdoptedHabitPolicyV1,graph_adopted_habit_policy_from_wire_v1
            if set(task.column.beta1_metadata_fields_seen)!={f.name for f in fields(GraphAdoptedHabitPolicyV1)}:
                raise AuthorityUnavailable('Habit policy metadata changed its actual full schema')
            policy=graph_adopted_habit_policy_from_wire_v1(value)
            if policy.definition.namespace!=reader.namespace:raise AuthorityUnavailable('Habit policy crossed namespace')
            state.producers.add(policy.adoption_operation_id)
            state.policy_versions[(key.token,policy.definition.revision,policy.digest)]=policy.definition
        elif key.type_name=='d10.habit_occurrence.v1':
            from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceV1,habit_value_from_wire_v1
            if set(task.column.beta1_metadata_fields_seen)!={f.name for f in fields(HabitOccurrenceV1)}:
                raise AuthorityUnavailable('Habit occurrence metadata changed its actual full schema')
            habit_value_from_wire_v1(key.type_name,value)
        if key.type_name=='runtime.job':
            state.selected.add(('job_continuation',(value['job_id'],selected)))
        if 'adoption_operation_id'in value:state.producers.add(value['adoption_operation_id'])
        if 'occurrence_operation_id'in value:state.producers.add(value['occurrence_operation_id'])
        for field_name in ('life_plan_original_ref','context_original_ref','outcome_original_ref'):
            if value.get(field_name):state.originals.add(value[field_name])
    elif kind=='history':
        token,revision=selected
        if task.metadata[:2]!=reader.namespace.as_tuple:
            raise AuthorityUnavailable('Habit history metadata changed actual producer namespace')
        state.producers.add(task.metadata[2])
        key=AtomKey.from_token(token)
        if key.type_name=='d10.habit_policy.v1'and task.metadata[3]==1:
            from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
            policy=graph_adopted_habit_policy_from_wire_v1(value)
            state.policy_versions[(token,policy.definition.revision,policy.digest)]=policy.definition
    elif kind=='producer':
        if (task.column.canonical_digest!=task.metadata[3]
                or value.get('schema')!=task.metadata[0]+'.current-'+task.metadata[1]+'.v1'):
            raise AuthorityUnavailable('Habit producer metadata differs from its complete actual Original EOF')
        if value.get('namespace')!={'bot_id':reader.namespace.bot_id,'persona_id':reader.namespace.persona_id}:
            raise AuthorityUnavailable('Habit committed producer metadata changed its namespace')
        if value.get('identity',{}).get('operation_id')!=selected:
            raise AuthorityUnavailable('Habit committed producer metadata changed its actual operation')
    _select_refs(reader,value,body=kind=='head' and AtomKey.from_token(selected)in state.body_keys)
    return value


def create_current_habit_metadata_task_v3(reader,identity):
    state=require_habit_source_work_v3(reader)
    if identity not in state.selected:raise AuthorityUnavailable('Habit metadata task has no exact selected locator')
    task=state.tasks.get(identity)
    if task is None:
        if identity[0]=='cue_inventory':task=_HabitCueInventoryTaskV3(reader)
        elif identity[0]=='policy_history':task=_HabitPolicyHistoryTaskV3(reader,identity[1])
        else:
            from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
            task=create_current_beta1_metadata_task_v3(reader,identity)
        state.tasks[identity]=task
    return task


def _metadata(reader,identity):
    state=require_habit_source_work_v3(reader);state.selected.add(identity)
    task=state.tasks.get(identity)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(reader,('habit_metadata',identity))
    with runtime_storage_quantum_v3(reader.db)as meter:task.require_header_v3(meter)
    return task.result


def require_habit_source_plan_metadata_v3(reader):
    state=require_habit_source_work_v3(reader)
    if not reader.inventory_sealed:raise AuthorityUnavailable('Habit metadata requires the actual complete fixed header census')
    _select_refs(reader,reader.request)
    _habit_definition_v3(reader)
    from .habit_followup_source_v3 import select_metadata_v3
    select_metadata_v3(reader)
    state.selected.add(('cue_inventory',None))
    for token,head in reader.heads.items():
        if AtomKey.from_token(token).type_name in _CENSUS_TYPES:
            state.selected.add(('head',token))
    while True:
        before=frozenset(state.selected)
        for identity in sorted(before,key=repr):_metadata(reader,identity)
        for operation in tuple(state.producers):
            state.selected.add(('producer',operation));_metadata(reader,('producer',operation))
        for identity,task in tuple(state.tasks.items()):
            if(identity[0]=='head'and AtomKey.from_token(identity[1]).type_name=='d10.habit_occurrence.v1'
                    and task.complete and task.result is not None):
                occurrence=task.result
                slot=(occurrence['policy_ref'],occurrence['policy_revision'],occurrence['policy_digest'])
                if slot not in state.policy_versions:
                    history=('policy_history',occurrence['policy_ref']);state.selected.add(history);_metadata(reader,history)
                    if slot not in state.policy_versions:
                        raise AuthorityUnavailable('Habit occurrence has no exact authenticated historical policy revision')
        _habit_schedule_metadata_selection_v3(reader)
        _habit_original_root_metadata_v3(reader)
        _habit_output_metadata_v3(reader)
        if frozenset(state.selected)==before:break
    state.metadata_complete=True
    return state


def pin_habit_owner_entry_v3(reader):
    state=require_habit_source_work_v3(reader)
    if not state.metadata_complete or reader.general_owner_entry is None:
        raise AuthorityUnavailable('Habit Owner pin requires complete fixed metadata then actual Owner17')
    state.owner_binding=reader.owner_binding


def habit_source_groups_v3(reader,roots):
    state=require_habit_source_work_v3(reader)
    if not state.metadata_complete or reader.owner_binding is None:
        raise AuthorityUnavailable('Habit ALL groups require complete actual metadata and current Owner17')
    definition=_habit_definition_v3(reader)
    definitions=(()if definition is None else (definition,))
    if reader.operation_kind==HABIT_SCHEDULE_READ_KIND_V3:
        from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
        definitions=tuple(graph_adopted_habit_policy_from_wire_v1(task.result).definition
            for identity,task in state.tasks.items()if identity[0]=='head'
            and AtomKey.from_token(identity[1]).type_name=='d10.habit_policy.v1'and task.result is not None)
    groups={}
    for current in definitions:
        for audience in current.audience:
            groups.setdefault(('context',(audience,)),set()).update(current.source_refs if reader.operation_kind==HABIT_SCHEDULE_READ_KIND_V3 else roots)
            if reader.authority.purpose=='consolidation':
                groups.setdefault(('consolidation',(audience,)),set()).update(roots)
    if not groups:
        for audience in reader.authority.audience:
            groups[('context',(audience,))]=set(roots)
            if reader.authority.purpose=='consolidation':
                groups[('consolidation',(audience,))]=set(roots)
    if set(roots)!={ref for refs in groups.values()for ref in refs}:
        raise AuthorityUnavailable('Habit Source groups changed their exact complete selected root union')
    return tuple((purpose,audiences,tuple(sorted(refs)))for(purpose,audiences),refs in sorted(groups.items())if refs)


def require_habit_sources_v3(reader,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_habit_source_work_v3(reader)
    cap=qualify_current_beta1_source_groups_v3(reader,roots)
    state.source_permission=cap
    return cap


def require_habit_body_v3(reader,table,key):
    state=require_habit_source_work_v3(reader)
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    if require_beta1_source_control_point_v3(reader,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if state.source_permission is None:raise AuthorityUnavailable('Habit body cannot precede current Owner17 and every exact Source group')
    state.source_permission.require_for_v3(reader)
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if table=='graph_history'and ((atom.token,key[1])not in state.history or atom not in state.body_keys
                and atom.token not in state.source_permission.source_refs):
            raise AuthorityUnavailable('Habit historical body has no actual frozen revision locator')
        if table=='graph_atoms'and atom not in state.body_keys and atom.token not in state.source_permission.source_refs:
            raise AuthorityUnavailable('Habit body is outside its complete actual metadata selection')
    elif table in {'graph_domain_production_originals_v1','graph_bundle_operations','graph_events'}:
        if tuple(key[:2])!=reader.namespace.as_tuple or key[2]not in state.producers:
            raise AuthorityUnavailable('Habit producer body was not derived from an actual selected COMMIT')
    elif table=='graph_d11_life_originals_v1':
        if tuple(key[:2])!=reader.namespace.as_tuple or key[-1]not in state.originals:
            raise AuthorityUnavailable('Habit Life body is outside its fixed original locator set')
    else:raise AuthorityUnavailable('Habit has no fixed protected body reader for this table')


def require_habit_point_v3(reader,request):
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    table,columns,key_columns,key=request
    from .habit_body_cpu_source_v3 import require_body_point_v3
    if require_body_point_v3(reader,request):return
    if request[:3]not in _HOST_ATTACHMENT_SHAPES_V3:
        raise AuthorityUnavailable('Habit point shape is not in the actual installed fixed-column registry')
    if table=='runtime_jobs':
        state=require_habit_source_work_v3(reader)
        matches=tuple(atom for atom in state.body_keys if atom.type_name=='runtime.job' and atom.name==key[0])
        if len(key)!=1 or len(matches)!=1 or state.source_permission is None:
            raise AuthorityUnavailable('Habit SQL job body has no exact Source-qualified current Graph selector')
        state.source_permission.require_for_v3(reader)
        task=state.tasks.get(('job_continuation',(key[0],matches[0].token)))
        if task is None or not task.complete:raise AuthorityUnavailable('Habit SQL job body cannot precede complete matching continuation metadata EOF')
        return
    if table in {'graph_atoms','graph_history','graph_dependencies'}:
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=reader.namespace:
            raise AuthorityUnavailable('Habit exact graph point crossed namespace')
    elif table!='runtime_budget_grants'and tuple(key[:2])!=reader.namespace.as_tuple:
        raise AuthorityUnavailable('Habit exact original point crossed namespace')
    if table=='runtime_budget_grants':
        from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3,require_habit_maintenance_budget_selector_v3
        if habit_maintenance_source_reader_v3(reader)is not None:
            require_habit_maintenance_budget_selector_v3(reader,key)
        elif key[0]!=reader.parent_budget_lease_ref:raise AuthorityUnavailable('Habit budget selector changed its original parent Root')
        return
    return require_habit_body_v3(reader,table,key)


def current_habit_source_read_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    reader=_active(db)
    if(reader is None or reader.namespace!=namespace or reader.activity_id!=activity_id
            or reader.operation_kind!=operation_kind or reader.request!=request):
        raise AuthorityUnavailable('Habit read plan requires its exact independently issued Source Work')
    state=require_habit_source_plan_metadata_v3(reader)
    exact=set(state.body_keys)
    exact.add(owner_grant_key(*namespace.as_tuple))
    fixed=tuple(sorted(_CENSUS_TYPES))
    return ProductionReadPlanV1(fixed,tuple(sorted(exact,key=lambda key:key.token)),
        tuple(sorted(state.source_roots)),tuple(sorted(state.originals)))


def _clear_habit_frame_binding_v3(reader):
    binding=_FRAME_BINDINGS.pop(reader,None)
    if binding is not None:
        frame,pending,proof=binding
        _HABIT_FRAME_READSETS_V3.pop(id(frame),None)
        _FRAME_METADATA.pop(proof,None)


def release_habit_source_work_v3(reader):
    from .habit_followup_source_v3 import release_followup_reader_v3
    release_followup_reader_v3(reader)
    from .habit_maintenance_source_v3 import release_habit_maintenance_source_v3
    release_habit_maintenance_source_v3(reader)
    _STATES.pop(reader,None);_WRITES.pop(reader,None);_clear_habit_frame_binding_v3(reader)
    capsule=_PENDING_READERS.pop(reader,None)
    if capsule is not None and capsule.reader is reader:_PENDING.pop(capsule,None)


@dataclass(frozen=True,slots=True)
class HabitCoreInputsV3:
    policy_original:object
    occurrence_qualification:object
    timecue_original:object
    execution_current:object

@dataclass(slots=True)
class _HabitWriteStateV3:
    reader:object
    prepared:object
    graph:object
    scope:object
    issued:object
    evidence:object
    owner_entry:object=None
    owner_binding:object=None
    active:bool=True

_WRITE_PENDING=WeakKeyDictionary()


def require_habit_prepared_write_v3(source_inputs,graph,context,selector,operation,request):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    from .habit_maintenance_issuance_v1 import habit_maintenance_typed_command_digest_v1
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    command_digest=(habit_maintenance_typed_command_digest_v1(operation,request)if type(selector)is HabitOriginalMaintenanceSelectorV1 else habit_typed_command_digest_v1(operation,request))
    if type(source_inputs)is not PreparedMethodDomainInputsV3:
        raise AuthorityUnavailable('Habit WRITE requires its actual privately issued Source inputs')
    source_inputs._actual_v3();reader=source_inputs.owner
    state=require_habit_source_work_v3(reader)
    if(reader.graph is not graph or state.context is not context or state.selector!=selector
            or reader.operation_kind!=operation.operation_kind or reader.request!=request
            or selector.request_digest!=command_digest
            or source_inputs.plan!=reader.selected_plan or source_inputs.envelope!=reader.selected_envelope
            or not reader.inputs_sealed or not reader.read_finished or not reader.business_started
            or reader.business_completed or not state.metadata_complete or state.source_permission is None
            or reader.operation.closed or time.monotonic()>=reader.initial_monotonic_deadline):
        raise AuthorityUnavailable('Habit fresh WRITE changed its actual same-Work phase, original Root or inputs')
    if state.prepared is None:state.prepared=source_inputs
    elif state.prepared is not source_inputs:raise AuthorityUnavailable('Habit selected input issuance changed after READ EOF')
    return reader


def require_habit_write_owner_identity_v3(reader,scope,issued):
    state=require_habit_source_work_v3(reader)
    pending=_WRITE_PENDING.get(reader)
    if(pending is None or not pending.active or pending.reader is not reader or pending.scope is not scope
            or pending.issued is not issued or pending.prepared is not state.prepared
            or not reader.read_finished or not reader.inputs_sealed or not reader.business_started
            or reader.business_completed or reader.operation.closed or scope.operation!='write'
            or scope is reader.fence.scope or scope.namespace!=reader.namespace):
        raise AuthorityUnavailable('Habit Owner WRITE has no exact private same-Work pending producer')
    from .habit_control_issuance_v1 import require_habit_control_issuance_v1 as require_habit_activity_issuance_v1
    current=require_habit_activity_issuance_v1(issued,reader.graph,scope)
    if(current is not pending.evidence or current.request!=state.selector
            or issued.operation.operation_kind!=reader.operation_kind or issued.command!=reader.request
            or current.current_self.self_entity_ref!=reader.authority.actor):
        raise AuthorityUnavailable('Habit Owner WRITE changed its actual same-Scope Core current qualification')
    return pending


@contextmanager
def bind_habit_prepared_write_v3(source_inputs,*,graph,scope,issued):
    from .habit_control_issuance_v1 import require_habit_control_issuance_v1 as require_habit_activity_issuance_v1
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from ..authority_service.owner_location_read_v3 import (prepare_current_host_habit_write_owner_read_entry_v3,
        prepare_current_host_habit_maintenance_write_owner_read_entry_v3)
    from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    from .habit_control_issuance_v1 import habit_control_deadline_v1
    reader=source_inputs.owner;state=require_habit_source_work_v3(reader)
    evidence=require_habit_activity_issuance_v1(issued,graph,scope)
    require_habit_prepared_write_v3(source_inputs,graph,state.context,evidence.request,issued.operation,issued.command)
    if reader.db.in_transaction or reader in _WRITE_PENDING:
        raise AuthorityUnavailable('Habit WRITE qualification must begin once outside Graph SQL')
    pending=_HabitWriteStateV3(reader,source_inputs,graph,scope,issued,evidence)
    _WRITE_PENDING[reader]=pending
    try:
        entry=(prepare_current_host_habit_maintenance_write_owner_read_entry_v3(reader,scope,issued)
            if type(issued)is _IssuedHabitMaintenanceV1 else prepare_current_host_habit_write_owner_read_entry_v3(reader,scope,issued))
        pending.owner_entry=entry
        owner=entry.require_permission_v3(reader)
        pending.owner_binding=owner
        core_versions={version.key:version.revision for version in evidence.read_versions}
        for version in state.source_permission.versions:
            if core_versions.get(version.key)!=version.revision:
                raise AuthorityUnavailable('Habit fresh WRITE lacks independent current Core qualification for a selected Source/access/correction head')
        if(evidence.current_self.permit!=scope.permit or owner.authorization_head!=entry.current_owner_guard.authorization_head
                or _habit_now_v3(reader)>=habit_control_deadline_v1(issued,reader)
                or (scope.graph_revision,scope.graph_epoch)!=(reader.graph_stamp[0].graph_revision,reader.graph_stamp[1])):
            raise AuthorityUnavailable('Habit fresh WRITE changed current Source/Self/Owner/Graph/original deadline')
        state.core_inputs=HabitCoreInputsV3(evidence.policy_original,evidence.qualification_original,
            None if type(issued)is _IssuedHabitMaintenanceV1 else evidence.timecue_original,
            evidence if type(evidence.request)is HabitOccurrenceExecutionSelectorV1 else None)
        _WRITES[reader]=pending
        yield pending
    finally:
        pending.active=False
        _WRITES.pop(reader,None);_WRITE_PENDING.pop(reader,None)
        state.core_inputs=None;state.frame=None
        _clear_habit_frame_binding_v3(reader)
        if pending.owner_entry is not None:pending.owner_entry.release_v3()


def register_habit_write_phase_v3(inputs,scope,current_owner):
    reader=inputs.owner
    if not reader.inputs_sealed:return
    if reader.session_proof is not None:
        from .current_habit_owner_write_v3 import require_current_habit_owner_write_v3
        return require_current_habit_owner_write_v3(inputs,reader.graph,scope,current_owner)
    pending=require_habit_write_phase_v3(reader)
    if(pending.prepared is not inputs or pending.scope is not scope or current_owner!=pending.owner_binding
            or inputs.plan!=reader.selected_plan):
        raise AuthorityUnavailable('Habit cached data cannot issue a fresh Source WRITE phase')
    pending.owner_entry.require_for_v3(reader)
    return pending


def require_habit_write_phase_v3(reader):
    from .current_method_learning_read_v3 import _method_active
    if reader.session_proof is not None:
        from .current_habit_owner_write_v3 import require_current_habit_owner_write_for_reader_v3
        require_habit_source_work_v3(reader)
        return require_current_habit_owner_write_for_reader_v3(reader)
    pending=_WRITES.get(reader)
    if(pending is None or not pending.active or _WRITE_PENDING.get(reader)is not pending
            or pending.prepared.owner is not reader or pending.prepared.plan!=reader.selected_plan
            or not reader.read_finished or not reader.business_started):
        raise AuthorityUnavailable('Habit Source body WRITE lacks its actual fresh private issuance')
    require_habit_write_owner_identity_v3(reader,pending.scope,pending.issued)
    if reader.db.in_transaction:
        if _method_active(reader.db)is not reader:
            raise AuthorityUnavailable('Habit WRITE body is outside its exact same-Work data Binder')
        pending.owner_entry.require_for_v3(reader)
    return pending


def _habit_write_operation_id_v3(reader,pending):
    return pending.operation_id if reader.session_proof is not None else pending.evidence.request.operation_id


def _habit_write_owner_guard_v3(reader,pending):
    if reader.session_proof is None:return pending.evidence.owner_guard
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    owner=pending.current_owner
    return ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,owner.grant_revision,
        owner.grant_digest.removeprefix('sha256:'),owner.authorization_head.removeprefix('sha256:'))


def require_habit_owner_policy_write_v3(graph,scope,authority,lease,operation_kind,request):
    from .d10_habit_v1 import POLICY_OPERATIONS
    reader=_active(graph._GraphCoordinator__store._db)
    if reader is None or reader.session_proof is None or operation_kind not in POLICY_OPERATIONS:
        raise AuthorityUnavailable('Habit policy Core issue requires its actual Owner Source Work')
    pending=require_habit_write_phase_v3(reader);state=require_habit_source_work_v3(reader)
    if(pending.graph is not graph or pending.scope is not scope or pending.authority is not authority
            or pending.lease is not lease or reader.operation_kind!=operation_kind or reader.request!=request
            or state.prepared is not pending.inputs or not state.metadata_complete
            or state.source_permission is None):
        raise AuthorityUnavailable('Habit policy issue changed actual Source/command/Owner fresh WRITE')
    pending.require_for_v3(reader)
    return pending


def bind_habit_policy_core_original_v3(graph,scope,operation_kind,request,original):
    from ..authority_service.d10_habit_contract_v1 import HabitStandingPolicyOriginalV1
    reader=_active(graph._GraphCoordinator__store._db)
    if reader is None:raise AuthorityUnavailable('Habit Core policy lost its actual same-Work Source')
    pending=require_habit_owner_policy_write_v3(graph,scope,reader.authority,reader.lease,operation_kind,request)
    action=('issue'if operation_kind=='create_habit_policy_v1'else'revoke'if operation_kind=='stop_habit_policy_v1'else'revise')
    if(type(original)is not HabitStandingPolicyOriginalV1 or original.namespace!=reader.namespace
            or original.definition!=request.definition or original.owner_actor_id!=reader.authority.actor
            or(original.operation_id,original.action)!=('habit-policy:'+pending.operation_id,action)):
        raise AuthorityUnavailable('Habit Core policy differs from the exact actual fresh Owner WRITE')
    graph._GraphCoordinator__habit_occurrence_port_v1.require_issued_policy_v3(scope=scope,
        definition=request.definition,operation_id=original.operation_id,action=action,original=original)
    state=require_habit_source_work_v3(reader)
    if state.core_inputs is not None:raise AuthorityUnavailable('Habit policy Core original was bound twice')
    state.core_inputs=HabitCoreInputsV3(original,None,None,None)


def release_habit_owner_write_phase_v3(reader):
    state=_STATES.get(reader)
    if state is not None:
        state.core_inputs=None;state.frame=None
    _clear_habit_frame_binding_v3(reader)


def read_bound_current_habit_frame_inputs_v3(db,*,graph,scope,plan,issued):
    reader=_active(db)
    if reader is None or not db.in_transaction or not reader.store._lock._is_owned():
        raise AuthorityUnavailable('Habit frame requires actual same-Work bound W01 data')
    pending=require_habit_write_phase_v3(reader)
    if(pending.graph is not graph or pending.scope is not scope or pending.issued is not issued
            or pending.prepared.plan!=plan):
        raise AuthorityUnavailable('Habit frame changed its independently prepared exact plan/current Scope')
    return pending.prepared


def require_habit_compile_inputs_v3(db,*,graph,scope,issued,operation,request,now_utc):
    from .habit_control_issuance_v1 import habit_control_deadline_v1
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('Habit compiler lost its actual Source Binder')
    pending=require_habit_write_phase_v3(reader)
    if(pending.scope is not scope or pending.issued is not issued or reader.graph is not graph
            or issued.operation!=operation or issued.command!=request or now_utc>=habit_control_deadline_v1(issued,reader)):
        raise AuthorityUnavailable('Habit compiler changed actual command/Source/Owner/original deadline')
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
    guard=pending.evidence.owner_guard
    readers=installed_readers_for_operation_v1(graph,operation,scope=scope,owner_guard=guard,
        owner_binding=pending.owner_binding)
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    if type(readers)is InstalledD10ProductionReadersV1:
        readers.habit_policy_original_v1=pending.evidence.policy_original
    plan=pending.prepared.plan
    originals=read_current_domain_original_refs_v1(db,namespace=reader.namespace,plan=plan,installed_readers=readers)
    policies=read_current_domain_policy_refs_v1(db,namespace=reader.namespace,plan=plan,installed_readers=readers)
    return plan,originals,policies,readers


def require_current_habit_source_frame_v3(db,*,frame,operation_kind,request):
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('Habit domain entry requires its actual independent Source Work')
    pending=require_habit_write_phase_v3(reader)
    if(frame.envelope.identity.operation_id!=_habit_write_operation_id_v3(reader,pending)
            or frame.envelope.authority.actor!=reader.authority.actor
            or frame.envelope.authority.purpose!=reader.authority.purpose
            or frame.envelope.authority.audience!=reader.authority.audience
            or operation_kind!=reader.operation_kind or request!=reader.request
            or frame.owner_guard!=_habit_write_owner_guard_v3(reader,pending)):
        raise AuthorityUnavailable('Habit frame is outside its exact current private Source/actual stage CAS')
    if reader.session_proof is None and not set(pending.evidence.read_versions)<=set(frame.envelope.version_guard.read_versions):
        raise AuthorityUnavailable('Habit frame omitted independent current Core read versions')
    require_current_habit_frame_metadata_v3(frame,graph=reader.graph,scope=pending.scope,issued=pending.issued)
    state=require_habit_source_work_v3(reader)
    if state.frame is None:state.frame=frame
    elif state.frame is not frame:raise AuthorityUnavailable('Habit stage changed its actual current Frame')
    return pending


def register_current_habit_source_frame_v3(db,frame,scope):
    reader=_active(db)
    if reader is None:return frame
    if not reader.inputs_sealed or not reader.read_finished:
        raise AuthorityUnavailable('Habit business Frame cannot precede actual Source READ completion')
    pending=require_habit_write_phase_v3(reader)
    if pending.scope is not scope:
        raise AuthorityUnavailable('Habit business Frame changed its actual fresh WRITE Scope')
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=reader.operation_kind,request=reader.request)
    return frame


def require_current_habit_core_inputs_v3(db,*,frame,operation_kind,request):
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=operation_kind,request=request)
    return require_habit_source_work_v3(_active(db)).core_inputs


def require_current_habit_executor_inputs_v3(db,*,frame,action_ref,issuer):
    reader=_active(db)
    if reader is None:
        from .ordinary_source_note_habit_classification_v3 import require_current_ordinary_source_note_habit_classification_v3
        return require_current_ordinary_source_note_habit_classification_v3(db,frame=frame,action_ref=action_ref,issuer=issuer)
    if issuer is not reader.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable('Habit executor requires its actual installed Source reader')
    state=require_habit_source_work_v3(reader)
    matching=[]
    for identity,task in state.tasks.items():
        if(identity[0]=='head'and AtomKey.from_token(identity[1]).type_name=='d10.habit_occurrence.v1'
                and task.complete and task.result is not None and task.result['action_intent_ref']==action_ref):
            matching.append(task.result)
    if matching:
        if len(matching)!=1:raise AuthorityUnavailable('Habit executor target has ambiguous actual occurrence responsibility')
        require_current_habit_source_frame_v3(db,frame=frame,operation_kind=reader.operation_kind,request=reader.request)
        if state.core_inputs is None or state.core_inputs.execution_current is None:
            raise AuthorityUnavailable('Habit executor requires its actual fresh phase Core qualification')
        return state.core_inputs
    if not state.metadata_complete:raise AuthorityUnavailable('An absent Habit index is not an ordinary execution proof')
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    for token,head in reader.heads.items():
        if AtomKey.from_token(token).type_name=='d10.habit_occurrence.v1':
            task=state.tasks.get(('head',token))
            if task is None or not task.complete or task.result is None:
                raise AuthorityUnavailable('Ordinary classification lacks complete actual occurrence metadata')
    return None


class _HabitPolicyHistoryTaskV3:
    def __init__(self,reader,policy_ref):
        self.reader,self.policy_ref=reader,policy_ref
        self.after=0;self.child=self.column=None;self.complete=False;self.result=()
    def require_header_v3(self,meter):
        self.reader.require_current(meter=meter)
        return self.result
    def advance(self,meter):
        reader=self.reader;state=require_habit_source_work_v3(reader)
        reader.require_current(meter=meter)
        if self.complete:return True
        if self.child is not None:
            if not self.child.advance(meter):return False
            self.child.require_header_v3(meter)
            self.child=None
            return False
        row=meter.read_fixed_row(reader.db,'graph_history',('revision','event_bot','event_persona','event_id','valid'),
            'token=? AND revision>? ORDER BY revision',(self.policy_ref,self.after))
        if row is None:self.complete=True;return True
        if row[1:3]!=reader.namespace.as_tuple:
            raise AuthorityUnavailable('Habit policy revision census crossed actual namespace')
        self.after=row[0];state.producers.add(row[3])
        identity=('history',(self.policy_ref,self.after));state.history.add(identity[1]);state.selected.add(identity)
        self.child=create_current_habit_metadata_task_v3(reader,identity)
        return False


def _frame_state(db,frame):
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('Habit census requires its actual private Source Work')
    state=require_habit_source_work_v3(reader)
    if not state.metadata_complete or state.frame is not frame:
        raise AuthorityUnavailable('Habit census requires its exact actual qualified current Frame')
    pending=require_habit_write_phase_v3(reader)
    if frame.envelope.identity.operation_id!=_habit_write_operation_id_v3(reader,pending):
        raise AuthorityUnavailable('Habit census changed actual same-Scope operation')
    return reader,state


def _occurrence_metadata_entries(reader,state,frame,*,policy_ref=None,project_ref=None):
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceCensusEntryV1
    rows=[];versions={v.key:v.revision for v in frame.envelope.version_guard.read_versions}
    for identity,task in state.tasks.items():
        if identity[0]!='head' or AtomKey.from_token(identity[1]).type_name!='d10.habit_occurrence.v1':continue
        if not task.complete:raise AuthorityUnavailable('Habit occurrence census has not reached full metadata EOF')
        if task.result is None:
            if policy_ref is not None or project_ref is not None:
                raise AuthorityUnavailable('Retired Habit occurrence is not an ordinary or absent responsibility proof')
            continue
        value=task.result
        if policy_ref is not None and value['policy_ref']!=policy_ref:continue
        if project_ref is not None:
            definition=state.policy_versions.get((value['policy_ref'],value['policy_revision'],value['policy_digest']))
            if definition is None:raise AuthorityUnavailable('Habit project census lacks exact original policy revision')
            if definition.project_ref!=project_ref:continue
        key=AtomKey.from_token(identity[1]);revision=task.metadata[0]
        if versions.get(key)!=revision:
            raise AuthorityUnavailable('Habit occurrence census is outside the actual current Frame readset')
        rows.append(HabitOccurrenceCensusEntryV1(key.token,revision,task.column.canonical_digest,
            value['policy_ref'],value['policy_revision'],value['window_id'],value['state'],
            value['admitted_at_utc'],value['actual_started_at_utc'],value['effect_id']))
    return tuple(sorted(rows,key=lambda row:row.ref))


def read_current_habit_occurrence_census_v3(db,*,frame,policy_ref):
    reader,state=_frame_state(db,frame)
    return _occurrence_metadata_entries(reader,state,frame,policy_ref=policy_ref)


def read_current_habit_project_occurrence_census_v3(db,*,frame,project_ref):
    reader,state=_frame_state(db,frame)
    return _occurrence_metadata_entries(reader,state,frame,project_ref=project_ref)


def require_current_habit_project_context_transition_v3(db,*,frame,project_ref,checkpoint,plan):
    reader,state=_frame_state(db,frame)
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    heads=[];outcomes={};targets=set();goal_name=AtomKey.from_token(plan.goal_ref).name
    for (policy_ref,revision,digest),definition in state.policy_versions.items():
        if definition.project_ref==project_ref:
            targets.add(definition.target_ref);targets.add(AtomKey.from_token(definition.target_ref).name)
    for identity,task in state.tasks.items():
        if identity[0]!='head':continue
        key=AtomKey.from_token(identity[1])
        if key.type_name not in {'runtime.job','d08.action_intent.v1','d08.action_outcome.v1'}:continue
        if not task.complete or task.result is None or key in state.retired_keys:
            raise MissingProductionOriginalV1('complete_current_ordinary_and_Habit_unknown_responsibility_metadata')
        value=task.result;heads.append((key,value))
        if key.type_name=='d08.action_outcome.v1':
            slot=(value['action_id'],value['effect_id'],value['attempt_id'])
            outcomes.setdefault(slot,[]).append(value)
    unresolved=[]
    for key,value in heads:
        if key.type_name=='d08.action_outcome.v1':continue
        identity=value.get('identity',{})
        refs={ref.token for ref in _graph_refs(value)}
        related=(project_ref in refs or value.get('goal_ref')==goal_name or value.get('target_ref')in targets
            or identity.get('activity_id')==frame.envelope.identity.activity_id
            or value.get('activity_id')==frame.envelope.identity.activity_id
            or frame.envelope.identity.effect_id is not None and (identity.get('effect_id')==frame.envelope.identity.effect_id
                or value.get('effect_id')==frame.envelope.identity.effect_id))
        if not related:continue
        if key.type_name=='runtime.job':
            if(value['phase']in {'queued','running','waiting','deferred','draining','pending_confirmation'}
                    or value.get('pending_original_effects')or value.get('pending_effect_ids')or value.get('unknown_effects')):
                unresolved.append(key.token)
            continue
        slot=(value['action_id'],identity['effect_id'],identity['attempt_id'])
        actual=outcomes.get(slot,())
        if(len(actual)!=1 or actual[0]['result_level']not in {'completed_verified','failed_verified'}
                or actual[0]['unknown_effects']):unresolved.append(key.token)
    if unresolved:
        raise MissingProductionOriginalV1('actual_project_ordinary_or_Habit_responsibility:'+canonical_digest(tuple(sorted(unresolved))))
    if AtomKey.from_token(checkpoint.plan_ref).name!=plan.plan_id or any(node.pending_original_effects for node in plan.nodes):
        raise MissingProductionOriginalV1('actual_current_project_checkpoint_without_pending_original_effects')
    return state


@dataclass(slots=True,eq=False,weakref_slot=True)
class _HabitPendingSourceV3:
    graph:object
    context:object
    bundle:object
    operation:object
    work:object
    selector:object
    operation_kind:str
    request:object
    authority:object
    fence:object
    initial_deadline_utc:float
    initial_monotonic_deadline:float
    reader:object=None
    phase:str='metadata'
    descriptor:tuple|None=None
    metadata_digest:str|None=None
    owner_lease:object=None
    owner_session:object=None


def _pending_identity(capsule):
    return(capsule.graph,capsule.context,capsule.bundle,capsule.operation,capsule.work,capsule.selector,
        capsule.operation_kind,capsule.request,capsule.authority,capsule.fence,capsule.initial_deadline_utc,
        capsule.initial_monotonic_deadline,capsule.phase,capsule.descriptor,capsule.metadata_digest,
        capsule.owner_lease,capsule.owner_session)


def require_pending_habit_factory_v3(capsule,*,graph,operation,fence,authority,operation_kind,request):
    if(type(capsule)is not _HabitPendingSourceV3 or _PENDING.get(capsule)!=_pending_identity(capsule)
            or capsule.graph is not graph or capsule.operation is not operation or capsule.fence is not fence
            or capsule.authority!=authority or capsule.operation_kind!=operation_kind or capsule.request!=request
            or capsule.work.kind!=HABIT_SOURCE_WORK_KIND_V3 or capsule.work.operation is not operation
            or capsule.work.coordinator is not graph or capsule.work.state not in (capsule,capsule.reader)
            or capsule.phase not in {'metadata','source'} or operation.closed or fence.scope.operation!='read'
            or authority.namespace!=capsule.bundle.installation_policy.namespace
            or time.monotonic()>=capsule.initial_monotonic_deadline
            or operation.deadline_utc>capsule.initial_deadline_utc):
        raise AuthorityUnavailable('Habit pending reader was not admitted by its actual private factory and original READ')
    capsule.work._require_invocation(graph)
    return capsule


def bind_pending_habit_reader_v3(reader,capsule):
    require_pending_habit_factory_v3(capsule,graph=reader.graph,operation=reader.operation,fence=reader.fence,
        authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    if reader.session_proof is None and any(value is not None for value in
            (reader.owner_binding,reader.owner_guard,reader.material_owner_guard)):
        raise AuthorityUnavailable('Habit pending metadata cannot invent an Owner binding')
    if reader in _PENDING_READERS:raise AuthorityUnavailable('Habit pending reader can bind only once')
    _PENDING_READERS[reader]=capsule
    capsule.reader=reader
    _PENDING[capsule]=_pending_identity(capsule)


def require_habit_source_factory_reader_v3(reader,work,*,registration=False):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    from ..graph_worker import GraphStorageWorkV3
    if(type(reader)is not _MethodLearningReadV3 or reader not in _READERS or type(work)is not GraphStorageWorkV3
            or work.kind!=HABIT_SOURCE_WORK_KIND_V3 or work.state is not reader or reader.work is not work
            or work.operation is not reader.operation or work.coordinator is not reader.graph
            or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or reader.operation_kind not in habit_source_operation_types_v3()
            or type(reader.request)is not habit_source_operation_types_v3()[reader.operation_kind]
            or reader.fence.scope.operation!='read' or reader.projection_types or reader.preplan_families
            or any((reader.background_followup,reader.background_host_lifecycle,reader.background_offline))):
        raise AuthorityUnavailable('Habit Source registry requires its exact independently selected actual Work')
    work._require_invocation(reader.graph)
    if reader.session_proof is not None:
        from .d10_habit_v1 import POLICY_OPERATIONS
        from .d08_long_term_plan_v1 import OPERATIONS as longterm
        if reader.operation_kind not in (POLICY_OPERATIONS|longterm|{HABIT_POLICY_READ_KIND_V3}):
            raise AuthorityUnavailable('Owner session cannot select a background Habit execution profile')
        if registration:work._require_invocation(reader.graph,initial=True)
        reader.graph._authorize(reader.lease,reader.authority,habit_source_required_domains_v3(reader.operation_kind),owner_read=True)
        return reader
    capsule=reader.source_pending_owner
    if capsule in _PENDING:
        require_pending_habit_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
            fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
        return reader
    state=_STATES.get(reader)
    if state is None or state.identity!=_identity(reader) or state.owner_binding is not reader.owner_binding:
        raise AuthorityUnavailable('Habit Source lost its actual consumed pending factory/current Owner')
    return reader


def _habit_self_v3(reader):
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    scope=reader.fence.scope
    current=reader.graph._GraphCoordinator__self_identity_port.current_self_identity(namespace=reader.namespace,
        authority_namespace=scope.authority_namespace,request_operation_id=scope.operation_id,permit=scope.permit)
    if(type(current)is not AuthorityCurrentSelfIdentityV1 or current.permit!=scope.permit
            or current.namespace!=reader.namespace):
        raise AuthorityUnavailable('Habit Source requires its actual same-permit current Self observation')
    descriptor=tuple(getattr(current,name)for name in (
        'namespace','authority_namespace','authority_id','installation_id','manifest_digest','activation_generation',
        'graph_incarnation','role_head_id','graph_revision','graph_epoch','origin_graph_incarnation',
        'storage_admission_digest','persona_ref','self_entity_ref','mapping_id','mapping_revision',
        'mapping_revocation_epoch','registration_operation_id','registration_digest','owner_authorization_revision',
        'owner_authorization_head','owner_minimum_revocation_revision','owner_revocation_epoch'))
    return current,descriptor


def _habit_pending_reader_v3(capsule):
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    graph,operation,fence=capsule.graph,capsule.operation,capsule.fence
    reader=begin_current_method_learning_read_v3(graph,operation,fence,
        runtime=graph._GraphCoordinator__domain_production_runtime_v1,authority=capsule.authority,
        lease=capsule.owner_lease,operation_kind=capsule.operation_kind,request=capsule.request,
        operation_id=operation.operation_id,activity_id=_pending_habit_activity_v3(capsule),
        audience_ref=capsule.authority.audience[0],parent_budget_lease_ref=_pending_habit_root_ref_v3(capsule),
        request_digest=canonical_digest((capsule.operation_kind,capsule.request,capsule.selector)),
        owner_binding=None,owner_guard=None,session_proof=None,initial_now_utc=capsule.initial_deadline_utc-60.0,
        source_pending_owner=capsule)
    reader.work=capsule.work
    reader.initial_monotonic_deadline=capsule.initial_monotonic_deadline
    reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
    reader.source_pending_owner=capsule
    capsule.reader=reader;capsule.work.state=reader
    _PENDING[capsule]=_pending_identity(capsule)
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3
    register_current_beta1_source_work_v3(reader,capsule.work)
    bind_pending_habit_reader_v3(reader,capsule)
    state=_STATES[reader];state.context,state.selector=capsule.context,capsule.selector
    state.selected_keys.update(_graph_refs(capsule.request))
    _select_refs(reader,capsule.request,body=True)
    _select_refs(reader,capsule.selector,body=True)
    if capsule.operation_kind not in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,HABIT_RECEIPT_READ_KIND_V3,'resolve_current_habit_followup_v3'}:
        state.producers.add(capsule.selector.operation_id)
    return reader


def _prepare_habit_source_work_v3(graph,context,*,selector,operation_kind,request):
    from uuid import uuid4
    from ..runtime_context import RuntimeContext
    from ..runtime_contracts import AuthorityContext
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
        finish_runtime_storage_operation_v3)
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if(type(context)is not RuntimeContext or context._v2_coordinator is not graph or assembly is None
            or context._v2_model_bundle is not assembly.admin_bundle or selector.namespace!=context._v2_namespace
            or type(request)is not habit_source_operation_types_v3()[operation_kind]):
        raise AuthorityUnavailable('Habit factory crossed its actual installed Host context/typed selector')
    graph._admin(context._v2_bootstrap)
    bundle=assembly.admin_bundle;now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
        graph._GraphCoordinator__scene_clock_policy))
    operation_id='habit-source-read:'+uuid4().hex
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            generation=graph._v2_graph_stamp(selector.namespace)[0].requirements.activation_generation
            purpose='consolidation'if operation_kind=='adopt_habit_outcome_v1'else'context'
            from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_execution_purpose_v1
            if type(selector)is HabitOccurrenceExecutionSelectorV1:purpose=habit_execution_purpose_v1(selector)
            authority=AuthorityContext('habit-source-metadata','d10','habit-source-metadata',selector.namespace,
                ('activity',),purpose,('owner',),'habit-source-read.v3',generation)
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id+':metadata')
            capsule=_HabitPendingSourceV3(graph,context,bundle,operation,None,selector,operation_kind,request,
                authority,fence,operation.deadline_utc,time.monotonic()+60.0)
            work=create_graph_storage_work_v3(graph,kind=HABIT_SOURCE_WORK_KIND_V3,operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=capsule,operation=operation)
            capsule.work=work;_PENDING[capsule]=_pending_identity(capsule)
            from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
            if type(selector)is HabitOriginalMaintenanceSelectorV1:
                from .habit_maintenance_source_v3 import register_habit_maintenance_source_factory_v3
                register_habit_maintenance_source_factory_v3(capsule)
            work._require_invocation(graph,initial=True)
            _habit_pending_reader_v3(capsule)
            work.phase='habit_metadata_eof'
            return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def prepare_current_habit_schedule_read_v3(graph,context):
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    selector=HabitScheduleReadSelectorV3(context._v2_namespace,bundle.installation_policy.installation_id)
    return _prepare_habit_source_work_v3(graph,context,selector=selector,operation_kind=HABIT_SCHEDULE_READ_KIND_V3,request=selector)


def prepare_current_habit_window_cue_write_v3(graph,context,selector):
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1
    from .habit_schedule_driver_v1 import habit_window_cue_request_v1
    if type(selector)is not HabitWindowCueSelectorV1:raise TypeError('Habit cue factory requires its exact durable window selector')
    return prepare_current_habit_activity_source_v3(graph,context,selector=selector,
        operation_kind='record_habit_window_cue_v1',request=habit_window_cue_request_v1(selector))


def prepare_current_habit_activity_source_v3(graph,context,*,selector,operation_kind,request):
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_activity_issuance_v1 import habit_activity_operation_kind_v1,habit_typed_command_digest_v1
    operation=installed_operation_v1(operation_kind)
    if(habit_activity_operation_kind_v1(selector)!=operation_kind or type(request)is not operation.request_type
            or selector.request_digest!=habit_typed_command_digest_v1(operation,request)):
        raise AuthorityUnavailable('Habit Source factory changed the exact actual phase request/operation digest')
    return _prepare_habit_source_work_v3(graph,context,selector=selector,operation_kind=operation_kind,request=request)


def _transition_habit_source_scope_v3(old):
    from .current_beta1_source_read_v3 import release_current_beta1_source_work_v3
    from .current_method_learning_read_v3 import _READERS
    state=require_habit_source_work_v3(old);capsule=_PENDING_READERS.get(old)
    if(capsule is None or capsule.phase!='metadata' or not state.metadata_complete
            or state.source_permission is not None or old.selected_plan is not None or old.read_finished):
        raise AuthorityUnavailable('Habit Source transition requires its actual complete metadata-only first Scope')
    current,descriptor=_habit_self_v3(old)
    old.graph._validate_read_fence_v3(old.fence)
    digest=canonical_digest(tuple(sorted((repr(identity),task.column.canonical_digest if task.column is not None else None)
        for identity,task in state.tasks.items())))
    definition=_habit_definition_v3(old)
    audiences=set()if definition is None else set(definition.audience)
    if old.operation_kind==HABIT_SCHEDULE_READ_KIND_V3:
        for identity,task in state.tasks.items():
            if identity[0]=='head'and AtomKey.from_token(identity[1]).type_name=='d10.habit_policy.v1'and task.result is not None:
                audiences.update(task.result['definition']['audience'])
    if not audiences:audiences.update(old.authority.audience)
    old.graph._finish_read_fence_v3(old.fence);old.read_finished=True
    capsule.authority=replace(old.authority,actor=current.self_entity_ref,audience=tuple(sorted(audiences)))
    capsule.fence=old.graph._begin_read_fence_v3(capsule.authority,operation_id=old.operation_id)
    capsule.phase,capsule.descriptor,capsule.metadata_digest='source',descriptor,digest
    capsule.reader=None;capsule.work.state=capsule;_PENDING[capsule]=_pending_identity(capsule)
    reader=_habit_pending_reader_v3(capsule)
    fresh,fresh_descriptor=_habit_self_v3(reader)
    if fresh_descriptor!=descriptor:raise AuthorityUnavailable('Habit Source Scope current Self changed after its metadata descriptor')
    reader.current_self=fresh
    from .habit_followup_source_v3 import transfer_child_binding_v3
    transfer_child_binding_v3(old,reader)
    release_current_beta1_source_work_v3(old);_READERS.discard(old)
    return reader


def require_habit_background_owner_identity_v3(reader):
    state=require_habit_source_work_v3(reader)
    capsule=_PENDING_READERS.get(reader)
    if(capsule is None or capsule.phase!='source' or not state.metadata_complete
            or reader.session_proof is not None or reader.fence.authority!=reader.authority):
        raise AuthorityUnavailable('Habit background Owner17 requires its actual second Source Scope and complete metadata EOF')
    require_pending_habit_factory_v3(capsule,graph=reader.graph,operation=reader.operation,fence=reader.fence,
        authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    return state


def habit_background_cause_metadata_v3(reader):
    state=require_habit_background_owner_identity_v3(reader)
    capsule=_PENDING_READERS[reader]
    return(reader.namespace,capsule.bundle.installation_policy.installation_id,state.selector,
        capsule.metadata_digest,capsule.descriptor,tuple(sorted(state.source_roots)),
        reader.operation.deadline_utc,reader.initial_monotonic_deadline)


def prepare_habit_owner_entry_v3(reader):
    state=require_habit_source_work_v3(reader)
    capsule=_PENDING_READERS.get(reader)
    if not state.metadata_complete or capsule is not None and capsule.phase!='source':return None
    from ..authority_service.owner_location_read_v3 import (prepare_current_host_semantic_background_owner_read_entry_v3,
        prepare_current_host_method_owner_read_entry_v3)
    if reader.general_owner_entry is None:
        reader.general_owner_entry=(prepare_current_host_method_owner_read_entry_v3(reader)if reader.session_proof is not None
            else prepare_current_host_semantic_background_owner_read_entry_v3(reader))
    entry=reader.general_owner_entry;entry.require_permission_v3(reader)
    with reader.store._lock:
        owner=entry.require_for_v3(reader)
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    reader.owner_binding,reader.owner_guard=owner,entry.current_owner_guard
    reader.material_owner_guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,
        owner.grant_revision,owner.grant_digest.removeprefix('sha256:'),owner.authorization_head.removeprefix('sha256:'))
    state.owner_binding=owner
    return entry


_HABIT_PARAMETERS=WeakKeyDictionary()

class _HabitActionParameterTaskV3:
    def __init__(self,reader,operation_id,values):
        from .current_method_learning_read_v3 import _freeze_value_v3
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        state=require_habit_source_work_v3(reader)
        if state.source_permission is None:raise AuthorityUnavailable('Habit Action parameters require actual ALL before any materialization')
        state.source_permission.require_for_v3(reader)
        self.reader,self.operation_id=reader,operation_id
        reader.operation.retain(_heap(values)*2+65536)
        self.frozen=_freeze_value_v3(values);self.stream=CanonicalValueStreamV3(values)
        self.complete=False;self.digest=None
        _HABIT_PARAMETERS[self]=(reader,reader.work,reader.operation,operation_id,self.frozen,reader.graph_stamp)
    def advance(self,meter):
        self.reader.require_current(meter=meter)
        state=require_habit_source_work_v3(self.reader)
        state.source_permission.require_for_v3(self.reader)
        if self.complete:return True
        self.stream.read_fragment(meter)
        if self.stream.complete:self.digest=self.stream.hash.hexdigest();self.complete=True;self.stream=None
        return self.complete


def current_habit_source_note_action_parameter_digest_v3(db,namespace,operation_id,values):
    from .current_method_learning_read_v3 import _need_method_input,_freeze_value_v3
    reader=_active(db)
    if(reader is None or namespace!=reader.namespace or reader.operation_kind!='prepare_current_habit_source_note_action_v1'):
        raise AuthorityUnavailable('Habit canonical parameters require their exact own Source operation')
    state=require_habit_source_work_v3(reader)
    if state.selector is None or state.selector.operation_id!=operation_id or state.source_permission is None:
        raise AuthorityUnavailable('Habit canonical parameters changed their actual phase/ALL-qualified input')
    task=state.parameter_tasks.get(operation_id)
    if task is None or not task.complete:
        _need_method_input(reader,('habit_parameters',(operation_id,values)))
    if(_HABIT_PARAMETERS.get(task)!=(reader,reader.work,reader.operation,operation_id,task.frozen,reader.graph_stamp)
            or task.frozen!=_freeze_value_v3(values)):
        raise AuthorityUnavailable('Habit Action parameters differ from their actual same-Work canonical tuple EOF')
    reader.require_current()
    return task.digest


def create_current_habit_parameter_task_v3(reader,operation_id,values):
    state=require_habit_source_work_v3(reader)
    if state.selector.operation_id!=operation_id:raise AuthorityUnavailable('Habit parameter task changed its actual business operation')
    task=state.parameter_tasks.get(operation_id)
    if task is None:task=_HabitActionParameterTaskV3(reader,operation_id,values);state.parameter_tasks[operation_id]=task
    return task


_HABIT_COMMON_READ_DOMAINS_V3=frozenset({'d03','d05','d06','d07','d08','d10','d11'})
_HABIT_BODY_READ_OPERATIONS_V3=frozenset({'resolve_current_habit_followup_v3','prepare_current_habit_source_note_action_v1',
    'prepare_source_note_body','register_current_habit_source_note_life_plan_v1','prepare_life','adopt_habit_outcome_v1'})

def habit_source_required_domains_v3(operation_kind):
    if operation_kind not in habit_source_operation_types_v3():
        raise AuthorityUnavailable('Unknown exact Habit Source operation domains')
    return (_HABIT_COMMON_READ_DOMAINS_V3|{'d02'}if operation_kind in _HABIT_BODY_READ_OPERATIONS_V3
        else _HABIT_COMMON_READ_DOMAINS_V3)


_FRAME_METADATA=WeakKeyDictionary()
_FRAME_BINDINGS=WeakKeyDictionary()
_HABIT_FRAME_READSETS_V3={}

@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _HabitFrameMetadataProofV3:
    prepared:object
    read_versions:tuple
    query_coverage:tuple
    digest:str
    def require_current_v3(self):
        actual=_FRAME_METADATA.get(self)
        if actual is None:raise AuthorityUnavailable('Habit metadata proof has no actual private issuance')
        reader,graph,scope,issued,stamp,heads,identity=actual
        pending=require_habit_write_phase_v3(reader)
        if(pending.prepared is not self.prepared or pending.graph is not graph or pending.scope is not scope
                or pending.issued is not issued or reader.graph_stamp!=stamp or _identity(reader)!=identity
                or reader.graph._v2_graph_stamp(reader.namespace)!=stamp or tuple(sorted(reader.heads.items()))!=heads
                or not reader.inventory_sealed or not require_habit_source_work_v3(reader).metadata_complete):
            raise AuthorityUnavailable('Habit metadata proof changed its actual Work/EOF/Owner/Scope/epoch')
        pending.owner_entry.require_for_v3(reader)
        return self


def is_habit_prepared_inputs_v3(prepared):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3,_INPUTS
    if type(prepared)is not PreparedMethodDomainInputsV3:return False
    state=_STATES.get(prepared.owner)
    return (state is not None and prepared.owner.work.kind==HABIT_SOURCE_WORK_KIND_V3
        and _INPUTS.get(prepared)==(prepared.owner,prepared.plan,prepared.envelope,prepared.read_scope,
        prepared.graph_stamp,prepared.owner_rights))


def habit_metadata_inventory_v3(prepared,type_id):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(prepared)is not PreparedMethodDomainInputsV3:
        raise AuthorityUnavailable('Habit metadata inventory requires actual selected Method inputs')
    if not is_habit_prepared_inputs_v3(prepared):raise AuthorityUnavailable('Habit inputs have no actual same-Work private issuance')
    reader=prepared.owner;state=require_habit_source_work_v3(reader)
    if(type_id not in _CENSUS_TYPES or type_id not in prepared.plan.fixed_type_ids
            or not reader.inventory_sealed or not state.metadata_complete or prepared.plan!=reader.selected_plan):
        raise AuthorityUnavailable('Habit metadata inventory lacks its fixed complete header census')
    reader.require_current()
    rows=tuple(GraphVersion(AtomKey.from_token(token),header[0])for token,header in sorted(reader.heads.items())
        if AtomKey.from_token(token).type_name==type_id)
    if len(rows)>128:raise AuthorityUnavailable('Habit metadata inventory exceeds the original fixed-family 128-row bound')
    for version in rows:
        task=state.tasks.get(('head',version.key.token))
        if task is None or not task.complete or task.metadata is None or task.metadata[0]!=version.revision:
            raise AuthorityUnavailable('Habit metadata inventory has not completed every actual row EOF')
    return rows


def habit_selected_metadata_read_set_v3(prepared):
    if not is_habit_prepared_inputs_v3(prepared):
        raise AuthorityUnavailable('Habit metadata readset requires its actual private same-Work input')
    reader=prepared.owner;state=require_habit_source_work_v3(reader)
    if not state.metadata_complete or not reader.inventory_sealed or state.source_permission is None:
        raise AuthorityUnavailable('Habit metadata readset lacks actual Source qualification and complete EOF')
    from ..runtime_contracts import QueryEpoch
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    query=QueryEpoch(reader.namespace,'namespace',reader.graph_stamp[1].revision)
    pages=[];versions={}
    for type_id in prepared.plan.fixed_type_ids:
        if type_id not in _CENSUS_TYPES:continue
        rows=habit_metadata_inventory_v3(prepared,type_id)
        pages.append(ProductionQueryCoverageV1(query,type_id,rows,True,None))
        for version in rows:versions[version.key]=version.revision
    for key in state.selected_keys:
        task=state.tasks.get(('head',key.token))
        if task is None or not task.complete:raise AuthorityUnavailable('Habit selected metadata closure lacks actual row EOF')
        revision=0 if task.metadata is None else task.metadata[0]
        if key in versions and versions[key]!=revision:
            raise AuthorityUnavailable('Habit metadata closure has conflicting same-key revisions')
        versions[key]=revision
    if len(versions)>1024:raise AuthorityUnavailable('Habit full metadata readset exceeds the original 1024-head bound')
    read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
    coverage=tuple(pages)
    return read_versions,coverage


def prepare_habit_frame_metadata_v3(prepared,*,graph,scope,issued):
    from ..runtime_contracts import QueryEpoch
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    reader=prepared.owner;state=require_habit_source_work_v3(reader)
    pending=require_habit_write_phase_v3(reader)
    if(pending.prepared is not prepared or pending.graph is not graph or pending.scope is not scope
            or pending.issued is not issued or state.prepared is not prepared):
        raise AuthorityUnavailable('Habit metadata issuance changed actual fresh-WRITE selected inputs')
    read_versions,coverage=habit_selected_metadata_read_set_v3(prepared)
    digest=canonical_digest(('habit-frame-metadata-proof.v3',reader.namespace,reader.selection_digest,
        reader.graph_stamp,prepared.plan,read_versions,coverage,tuple(sorted((repr(identity),
        None if task.column is None else task.column.canonical_digest)for identity,task in state.tasks.items()))))
    proof=_HabitFrameMetadataProofV3(prepared,read_versions,coverage,digest)
    _FRAME_METADATA[proof]=(reader,graph,scope,issued,reader.graph_stamp,tuple(sorted(reader.heads.items())),_identity(reader))
    return proof.require_current_v3()


def require_current_habit_frame_metadata_v3(frame,*,graph,scope,issued):
    reader=_active(graph._GraphCoordinator__store._db)
    if reader is None:raise AuthorityUnavailable('Habit Frame metadata requires its actual current Source Binder')
    pending=require_habit_write_phase_v3(reader)
    if(pending.graph is not graph or pending.scope is not scope or pending.issued is not issued
            or frame.envelope.identity.operation_id!=_habit_write_operation_id_v3(reader,pending)):
        raise AuthorityUnavailable('Habit Frame metadata changed its actual issued command/Scope')
    binding=_FRAME_BINDINGS.get(reader)
    if binding is None:
        proof=prepare_habit_frame_metadata_v3(pending.prepared,graph=graph,scope=scope,issued=issued)
        full={version.key:version.revision for version in proof.read_versions}
        for version in frame.snapshot.versions:
            if version.key in full and full[version.key]!=version.revision:
                raise AuthorityUnavailable('Habit Frame body and header readsets disagree on the same key')
            full[version.key]=version.revision
        if len(full)>1024:raise AuthorityUnavailable('Habit body plus metadata exceeds the original complete head bound')
        actual=tuple(GraphVersion(key,revision)for key,revision in sorted(full.items(),key=lambda item:item[0].token))
        if(frame.envelope.version_guard.read_versions!=actual or frame.query_coverage!=proof.query_coverage
                or frame.owner_guard!=_habit_write_owner_guard_v3(reader,pending)):
            raise AuthorityUnavailable('Habit Frame envelope/CAS coverage differs from actual body plus metadata proof')
        _FRAME_BINDINGS[reader]=(frame,pending,proof)
    else:
        if binding[0]is not frame or binding[1]is not pending:raise AuthorityUnavailable('Habit Frame was rebound to another Work or WRITE')
        proof=binding[2]
    proof.require_current_v3()
    _HABIT_FRAME_READSETS_V3[id(frame)]=(frame,frame.envelope.version_guard.read_versions,proof)
    return proof


def current_habit_frame_read_versions_v3(frame):
    record=_HABIT_FRAME_READSETS_V3.get(id(frame))
    if record is None:return frame.snapshot.versions
    if record[0]is not frame:
        raise AuthorityUnavailable('Habit stage frame differs from the actual private readset binding')
    return record[1]


def current_habit_frame_census_v3(frame):
    record=_HABIT_FRAME_READSETS_V3.get(id(frame))
    if record is None:return None
    if record[0]is not frame:
        raise AuthorityUnavailable('Habit census has another privately bound actual frame')
    proof=record[2];proof.require_current_v3()
    reader=proof.prepared.owner;pending=require_habit_write_phase_v3(reader)
    if _FRAME_BINDINGS.get(reader)!=(frame,pending,proof):
        raise AuthorityUnavailable('Habit census lost its exact Source/Owner/Scope lifetime')
    body={version.key for version in frame.snapshot.versions}
    metadata=tuple(version for version in record[1]if version.key not in body)
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1
    profile=('habit-original-maintenance-census.v1'if type(frame)is CurrentHabitMaintenanceFrameV1 else'habit-current-census.v1')
    return {'metadata_profile':profile,'metadata_only_versions':metadata,'census_digest':proof.digest}


def current_habit_owner_census_v3(frame,domain,operation_kind,request):
    actual=current_habit_frame_census_v3(frame)
    if actual is None:return None
    reader=_HABIT_FRAME_READSETS_V3[id(frame)][2].prepared.owner
    if reader.session_proof is None:return None
    from .d10_habit_v1 import POLICY_OPERATIONS
    from .d08_long_term_plan_v1 import OPERATIONS
    expected='d10'if operation_kind in POLICY_OPERATIONS else'd08'if operation_kind in OPERATIONS else None
    if(domain!=expected or expected is None or reader.operation_kind!=operation_kind or reader.request!=request):
        raise AuthorityUnavailable('Owner census differs from its exact actual command and installed writer')
    require_habit_write_phase_v3(reader).require_for_v3(reader)
    return actual


def _habit_now_v3(reader):
    now=reader.initial_now_utc+max(0.0,time.monotonic()-(reader.initial_monotonic_deadline-60.0))
    if time.monotonic()>=reader.initial_monotonic_deadline or now>=reader.operation.deadline_utc:
        raise AuthorityUnavailable('Habit Source exceeded its original absolute READ deadline')
    return now


def _habit_selector_policy_ref_v3(selector):
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceBirthSelectorV1,HabitWindowCueSelectorV1
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(selector)is HabitOriginalMaintenanceSelectorV1:return selector.policy_ref
    if type(selector)is HabitOccurrenceExecutionSelectorV1:return selector.qualification_selector.policy_ref
    if type(selector)in {HabitOccurrenceBirthSelectorV1,HabitWindowCueSelectorV1,HabitOccurrenceSelectorV1}:return selector.policy_ref
    from .habit_followup_source_v3 import selector_policy_ref_v3
    return selector_policy_ref_v3(selector)


def _habit_definition_v3(reader):
    state=require_habit_source_work_v3(reader)
    from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3,maintenance_original_definition_v3
    if habit_maintenance_source_reader_v3(reader)is not None:return maintenance_original_definition_v3(reader)
    if type(state.selector)is HabitDefinitionReadSelectorV3:
        _select_refs(reader,state.selector.definition,body=True)
        return state.selector.definition
    from .d10_habit_v1 import POLICY_OPERATIONS
    if reader.operation_kind in POLICY_OPERATIONS:
        _select_refs(reader,reader.request.definition,body=True)
        return reader.request.definition
    ref=_habit_selector_policy_ref_v3(state.selector)
    if ref is None:return None
    key=AtomKey.from_token(ref);state.body_keys.add(key)
    value=_metadata(reader,('head',ref))
    if value is None:raise AuthorityUnavailable('Habit actual selected policy is absent or retired')
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
    definition=graph_adopted_habit_policy_from_wire_v1(value).definition
    _select_refs(reader,definition,body=True)
    return definition


def _habit_original_root_metadata_v3(reader):
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    state=require_habit_source_work_v3(reader);definition=_habit_definition_v3(reader)
    from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3,read_habit_maintenance_root_metadata_v3
    if habit_maintenance_source_reader_v3(reader)is not None:
        return read_habit_maintenance_root_metadata_v3(reader,definition)
    installed=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    root_ref=installed.root_lease.lease_id if definition is None else definition.parent_root_grant_ref
    parent=root_ref
    chain=[];seen=set();cursor=parent
    with runtime_storage_quantum_v3(reader.db)as meter:
        while cursor is not None:
            if cursor in seen or len(chain)>=64:raise AuthorityUnavailable('Habit budget ancestry is cyclic or exceeds its fixed bound')
            seen.add(cursor)
            row=_beta1_metadata_row_v3(reader,meter,'runtime_budget_leases',
                ('lease_id','parent_id','bot_id','persona_id','version','state'),'lease_id=?',(cursor,))
            if(row is None or row[0]!=cursor or tuple(row[2:4])!=reader.namespace.as_tuple
                    or type(row[4])is not int or row[4]<1 or row[5]!='active'):
                raise AuthorityUnavailable('Habit original budget ancestry is foreign, missing or inactive')
            chain.append(row)
            if row[1]is None:break
            cursor=row[1]
    if not chain or chain[-1][0]!=root_ref or root_ref!=installed.root_lease.lease_id:
        raise AuthorityUnavailable('Habit original Root is not the actual installed root of this budget ancestry')
    chain=tuple(chain)
    if state.budget_ancestry is not None and state.budget_ancestry!=chain:
        raise AuthorityUnavailable('Habit original parent/Root ancestry changed during metadata EOF')
    state.budget_ancestry=chain
    with runtime_storage_quantum_v3(reader.db)as meter:
        row=_beta1_metadata_row_v3(reader,meter,'runtime_budget_grants',('lease_id','version','signature','status'),
            'lease_id=? ORDER BY version DESC',(root_ref,))
    if row is None or row[3]!='active':raise AuthorityUnavailable('Habit original Root grant is absent or inactive')
    grant=_metadata(reader,('budget_grant',row[:2]))
    task=state.tasks[('budget_grant',row[:2])]
    if task.metadata!=row:raise AuthorityUnavailable('Habit Root signed metadata was superseded')
    if definition is not None and (grant.grant_id,grant.version,canonical_digest(grant))!=(
            definition.parent_root_grant_id,definition.parent_root_grant_version,definition.parent_root_grant_digest):
        raise AuthorityUnavailable('Habit Source cannot upgrade its original policy Root grant')
    if grant!=installed.root_grant:raise AuthorityUnavailable('Habit original Root differs from actual installed signed grant')
    limit=min(reader.operation.deadline_utc,grant.valid_until_utc,
        grant.valid_until_utc if definition is None else definition.original_valid_until_utc)
    selector=state.selector
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    selected=selector.qualification_selector if type(selector)is HabitOccurrenceExecutionSelectorV1 else selector
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceBirthSelectorV1,HabitWindowCueSelectorV1
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
    if type(selected)in {HabitOccurrenceBirthSelectorV1,HabitWindowCueSelectorV1,HabitOccurrenceSelectorV1}:
        if selected.parent_root_grant_ref!=root_ref or selected.parent_root_grant_digest!=canonical_digest(grant):
            raise AuthorityUnavailable('Habit current selector changed original Root descriptor')
        limit=min(limit,selected.original_deadline_utc)
    from .habit_followup_source_v3 import original_limit_v3
    limit=original_limit_v3(reader,grant,limit)
    if _habit_now_v3(reader)>=limit:raise AuthorityUnavailable('Habit Source exceeded its actual control/execution lifetime')
    locator=(root_ref,grant.grant_id,grant.version,canonical_digest(grant),limit)
    if state.root_locator is not None and state.root_locator!=locator:
        raise AuthorityUnavailable('Habit original Root descriptor changed before Source disclosure')
    state.root_locator=locator;state.read_deadline=limit
    if reader.parent_budget_lease_ref!=root_ref:raise AuthorityUnavailable('Habit original Source factory Root differs from authenticated metadata')
    return locator


def _habit_output_metadata_v3(reader):
    state=require_habit_source_work_v3(reader)
    from .d08_long_term_plan_v1 import OPERATIONS as longterm,long_term_operation_metadata_output_keys_v1
    if reader.operation_kind in longterm:
        keys=long_term_operation_metadata_output_keys_v1(reader.namespace,operation_kind=reader.operation_kind,request=reader.request)
    elif reader.operation_kind in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,HABIT_RECEIPT_READ_KIND_V3,'resolve_current_habit_followup_v3'}:return
    else:
        from .d10_habit_v1 import habit_operation_metadata_output_keys_v1,habit_operation_metadata_original_refs_v1
        from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
        definition=_habit_definition_v3(reader);occurrence=None
        if hasattr(reader.request,'occurrence_ref'):
            value=_metadata(reader,('head',reader.request.occurrence_ref))
            if value is None:raise AuthorityUnavailable('Habit operation has no actual current occurrence metadata')
            occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',value)
        elif hasattr(state.selector,'occurrence_ref'):
            value=_metadata(reader,('head',state.selector.occurrence_ref))
            if value is None:raise AuthorityUnavailable('Habit selected phase lost its actual occurrence metadata')
            occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',value)
        cue=state.selector
        outcome_digest=(_habit_outcome_producer_digest_v3(reader)
            if reader.operation_kind=='adopt_habit_outcome_v1' else None)
        from .habit_maintenance_source_v3 import habit_maintenance_business_activity_v3
        keys=habit_operation_metadata_output_keys_v1(reader.namespace,operation_kind=reader.operation_kind,
            request=reader.request,occurrence=occurrence,definition=definition,activity_id=habit_maintenance_business_activity_v3(reader),cue=cue,
            outcome_production_digest=outcome_digest)
        if occurrence is not None:
            state.originals.update(habit_operation_metadata_original_refs_v1(reader.namespace,
                operation_kind=reader.operation_kind,occurrence=occurrence,definition=definition,request=reader.request))
    for key in keys:
        state.selected_keys.add(key);state.body_keys.add(key);_metadata(reader,('head',key.token))


def _pending_habit_root_ref_v3(capsule):
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
    selector=capsule.selector
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(selector)is HabitOriginalMaintenanceSelectorV1:
        from .habit_maintenance_source_v3 import pending_habit_maintenance_identity_v3
        return pending_habit_maintenance_identity_v3(capsule)[0]
    if type(selector)is HabitOccurrenceExecutionSelectorV1:return selector.qualification_selector.parent_root_grant_ref
    if type(selector)in {HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,HabitOccurrenceSelectorV1}:
        return selector.parent_root_grant_ref
    if type(selector)is HabitDefinitionReadSelectorV3:return selector.definition.parent_root_grant_ref
    return capsule.bundle.installation_policy.root_lease.lease_id


def require_habit_pending_current_v3(reader,*,meter=None):
    capsule=_PENDING_READERS.get(reader)
    if(capsule is None or reader.owner_binding is not None or reader.owner_guard is not None
            or reader.material_owner_guard is not None or reader.selected_plan is not None
            or reader.inputs_sealed or reader.read_finished):
        raise AuthorityUnavailable('Habit pending metadata cannot confer Owner/Source/body authority')
    require_pending_habit_factory_v3(capsule,graph=reader.graph,operation=reader.operation,fence=reader.fence,
        authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    if reader.graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp:
        raise AuthorityUnavailable('Habit pending metadata graph stamp changed before actual Owner17')
    _habit_now_v3(reader)
    return reader


_SCHEMA_LOCATORS=WeakKeyDictionary()

class _HabitActionSchemaLocatorV3:
    def __init__(self,reader):
        state=require_habit_source_work_v3(reader)
        if(reader.operation_kind!='prepare_current_habit_source_note_action_v1' or state.source_permission is None
                or reader.inputs_sealed or not state.metadata_complete):
            raise AuthorityUnavailable('Habit Action schema locator requires actual ALL-qualified phase material')
        self.reader=reader;self.complete=False;self.key=None;self.parameter_digest=None
        self.values=self.identity=self.request=self.goal=None
        _SCHEMA_LOCATORS[self]=(reader,reader.work,reader.operation,reader.selection_digest)
    def _head(self,ref):
        from .current_method_learning_read_v3 import method_graph_head_v3
        key=AtomKey.from_token(ref);state=require_habit_source_work_v3(self.reader)
        if key not in state.body_keys:raise AuthorityUnavailable('Habit schema material was not predeclared by metadata EOF')
        atom=method_graph_head_v3(self.reader.db,self.reader.namespace,key)
        if not atom.valid or atom.revision<1:raise AuthorityUnavailable('Habit schema material is absent or retired')
        return atom
    def advance(self,meter):
        from .current_method_learning_read_v3 import _READING
        from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1,source_note_action_parts_v1
        from ..domains.d08.execution import _decode_goal
        from ..runtime_contracts import OperationIdentity
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        from .d11_life_contract_v1 import life_artifact_ref_v1
        reader=self.reader;state=require_habit_source_work_v3(reader)
        reader.require_current(meter=meter);state.source_permission.require_for_v3(reader)
        if _SCHEMA_LOCATORS.get(self)!=(reader,reader.work,reader.operation,reader.selection_digest):
            raise AuthorityUnavailable('Habit Action schema locator lost its actual private Work')
        if self.complete:return True
        token=_READING.set(reader)
        try:
            if self.values is None:
                from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
                occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',_metadata(reader,('head',state.selector.occurrence_ref)))
                definition=_habit_definition_v3(reader);pinned=definition.source_note_input
                self.request=PrepareSourceNoteActionRequestV1(definition.project_ref,definition.recipe_ref,
                    pinned.source_ref,occurrence.goal_ref,definition.target_ref,pinned.role_binding_ref)
                project,recipe,source,goal=(self._head(ref)for ref in(self.request.project_ref,
                    self.request.recipe_ref,self.request.source_ref,self.request.goal_ref))
                reader.operation.retain(_heap(goal.value)*2+65536)
                self.goal=_decode_goal(goal.value)
                legacy=reader.installed_readers.legacy_readers
                build=read_installed_d11_life_build_v1(legacy.package_root,legacy.manifest_digest)
                artifact=life_artifact_ref_v1(reader.namespace,occurrence.effect_id)
                self.values=(project.value,recipe.value,source.value,artifact,build)
                digest=canonical_digest({'input_refs':sorted(set(reader.selected_plan.source_roots+reader.selected_plan.required_original_refs))})
                self.identity=OperationIdentity(occurrence.activity_id,occurrence.effect_id,state.selector.operation_id,
                    reader.operation_kind,occurrence.attempt_id,digest)
            self.parameter_digest=current_habit_source_note_action_parameter_digest_v3(reader.db,
                reader.namespace,state.selector.operation_id,self.values)
            parts=source_note_action_parts_v1(namespace=reader.namespace,identity=self.identity,
                request=self.request,goal=self.goal,parameter_digest=self.parameter_digest)
            self.key=parts[2][1]
            state.body_keys.add(self.key);state.selected_keys.add(self.key)
            _metadata(reader,('head',self.key.token))
            from .current_method_learning_read_v3 import method_graph_head_v3
            method_graph_head_v3(reader.db,reader.namespace,self.key)
            self.complete=True
            return True
        finally:_READING.reset(token)


def verify_prepared_habit_source_note_schema_key_v3(db,namespace,operation_id,key):
    reader=_active(db)
    if reader is None or namespace!=reader.namespace:raise AuthorityUnavailable('Habit schema key requires actual same-Work bound input')
    state=require_habit_source_work_v3(reader);locator=state.schema_locator
    if(state.selector.operation_id!=operation_id or locator is None or not locator.complete or locator.key!=key
            or _SCHEMA_LOCATORS.get(locator)!=(reader,reader.work,reader.operation,reader.selection_digest)
            or key not in reader.selected_plan.exact_keys):
        raise AuthorityUnavailable('Habit Action schema differs from its actual ALL-materialized fixed locator/absence')
    require_habit_write_phase_v3(reader)
    return key


_HABIT_READ_RESULTS=WeakKeyDictionary()
_HABIT_SOURCE_CAPS=WeakKeyDictionary()

def habit_source_cap_registry_v3(reader):
    require_habit_source_work_v3(reader)
    return _HABIT_SOURCE_CAPS


def _habit_read_envelope_v3(reader):
    from ..runtime_contracts import CommandEnvelope,OperationIdentity,VersionGuard,QueryEpoch,SourceQualification,RUNTIME_SCHEMA
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    state=require_habit_source_work_v3(reader);_habit_original_root_metadata_v3(reader)
    versions={}
    with runtime_storage_quantum_v3(reader.db)as meter:
        for kind in ('scheme','operator','policy'):
            row=_beta1_metadata_row_v3(reader,meter,'graph_guard_versions',('version',),
                'bot=? AND persona=? AND ref=? AND kind=?',(*reader.namespace.as_tuple,'current',kind))
            if row is None:raise AuthorityUnavailable('Habit Source requires actual registered current guard versions')
            versions[kind]=row[0]
    return CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(reader.activity_id,None,reader.operation_id,
        reader.operation_kind,reader.operation_id,canonical_digest({'input_refs':[]})),reader.authority,
        VersionGuard((),(QueryEpoch(reader.namespace,'namespace',reader.graph_stamp[1].revision),),
            reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch,reader.catalogue_hash,
            versions['scheme'],versions['operator'],versions['policy'],(),(),()),
        SourceQualification((),'derived',None,reader.initial_now_utc,'inference','ineligible',None,'not_applicable'),(),
        reader.parent_budget_lease_ref,state.read_deadline,
        reader.initial_monotonic_deadline-(reader.operation.deadline_utc-state.read_deadline),
        'habit-source-current:'+reader.operation_id,())


def _habit_prepare_selected_v3(reader):
    from .domain_production_registry_v1 import installed_operation_v1,installed_readers_for_operation_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3,_ISSUER
    from .domain_production_frame_v1 import _materialize_current_domain_frame_fields_v1
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    state=require_habit_source_plan_metadata_v3(reader)
    if reader.general_owner_entry is None:raise AuthorityUnavailable('Habit selected inputs require actual complete current Owner17')
    reader.general_owner_entry.require_permission_v3(reader)
    if reader.selected_envelope is None:reader.selected_envelope=_habit_read_envelope_v3(reader)
    plan=current_habit_source_read_plan_v3(reader.db,namespace=reader.namespace,activity_id=reader.activity_id,
        operation_kind=reader.operation_kind,request=reader.request)
    reader.selected_plan=plan
    require_habit_sources_v3(reader,plan.source_roots)
    if reader.operation_kind not in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,HABIT_RECEIPT_READ_KIND_V3,'resolve_current_habit_followup_v3'}:
        operation=installed_operation_v1(reader.operation_kind)
        if reader.installed_readers is None:
            reader.installed_readers=installed_readers_for_operation_v1(reader.graph,operation,scope=reader.fence.scope,
                owner_guard=reader.material_owner_guard,owner_binding=reader.owner_binding)
    if reader.operation_kind=='prepare_current_habit_source_note_action_v1':
        if state.schema_locator is None:state.schema_locator=_HabitActionSchemaLocatorV3(reader)
        with runtime_storage_quantum_v3(reader.db)as meter:
            if not state.schema_locator.advance(meter):return False
        plan=current_habit_source_read_plan_v3(reader.db,namespace=reader.namespace,activity_id=reader.activity_id,
            operation_kind=reader.operation_kind,request=reader.request)
        reader.selected_plan=plan
    if reader.installed_readers is not None:
        reader.observed_originals=read_current_domain_original_refs_v1(reader.db,namespace=reader.namespace,
            plan=plan,installed_readers=reader.installed_readers)
        reader.installed_policy_refs=read_current_domain_policy_refs_v1(reader.db,namespace=reader.namespace,
            plan=plan,installed_readers=reader.installed_readers)
    from .habit_followup_source_v3 import READ_KIND,finish_selected_v3,validate_child_source_v3
    if reader.operation_kind==READ_KIND:return finish_selected_v3(reader)
    validate_child_source_v3(reader)
    if reader.operation_kind==HABIT_SCHEDULE_READ_KIND_V3:
        value=_habit_schedule_scan_v3(reader)
        reader.operation.retain(_heap(value)*2+65536)
        reader.result=_HabitReadResultV3(reader,value);reader.complete=True
        return True
    if(reader.operation_kind not in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,HABIT_RECEIPT_READ_KIND_V3,'resolve_current_habit_followup_v3'}
            and reader.session_proof is None and state.selector.operation_id in state.producers):
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        actual=read_adopted_domain_operation_v1(reader.db,reader.namespace,state.selector.operation_id)
        if actual is not None:
            if(actual['operation_kind']!=reader.operation_kind or actual['request_digest']!=canonical_digest(reader.request)
                    or actual['receipt'].status!='committed'
                    or actual['payload'].get('parent_budget')!=reader.parent_budget_lease_ref):
                raise AuthorityUnavailable('Habit saved COMMIT differs from the actual current selector/command/original Root')
            reader.operation.retain(65536+_heap(actual['payload']['missing_inputs'])*2)
            state.receipt=actual['receipt']
            state.committed_original={'original_digest':actual['original_digest'],
                'payload':{name:actual['payload'][name]for name in ('coverage','missing_inputs','continuation_ref')}}
    temporary=PreparedMethodDomainInputsV3(_ISSUER,reader,plan,reader.selected_envelope)
    reader.result=temporary
    state.prepared=temporary
    reader.frame_fields=_materialize_current_domain_frame_fields_v1(reader.graph,reader.db,
        envelope=reader.selected_envelope,scope=reader.fence.scope,plan=plan,now_utc=_habit_now_v3(reader),
        expected_owner_guard=reader.material_owner_guard,
        expected_rights=(reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch),
        observed_originals=reader.observed_originals,installed_policy_refs=reader.installed_policy_refs,
        limits=ProductionOperationLimitsV1(),prepared_inputs=temporary)
    reader.inputs_sealed=reader.complete=True
    return True


def _habit_dependency_v3(reader,needed):
    from .current_method_learning_read_v3 import _MethodPointReadV3,_MethodInventoryReadV3
    from .current_beta1_source_read_v3 import create_current_beta1_source_metadata_task_v3
    kind,actual=needed.request
    if kind=='habit_metadata':task=create_current_habit_metadata_task_v3(reader,actual)
    elif kind=='habit_parameters':task=create_current_habit_parameter_task_v3(reader,*actual)
    elif kind=='beta1_source_metadata':task=create_current_beta1_source_metadata_task_v3(reader,actual)
    elif kind=='point':
        require_habit_point_v3(reader,actual)
        task=reader.points.get(actual)
        if task is None:task=_MethodPointReadV3(reader,actual);reader.points[actual]=task
    elif kind=='inventory':
        if reader.selected_plan is None or actual not in reader.selected_plan.fixed_type_ids:
            raise AuthorityUnavailable('Habit inventory has no actual complete selected read recipe')
        task=reader.inventories.get(actual)
        if task is None:task=_MethodInventoryReadV3(reader,actual);reader.inventories[actual]=task
    else:raise AuthorityUnavailable('Unregistered exact Habit Source Work dependency')
    reader.pending_input=task


def advance_current_habit_source_work_v3(graph,work):
    from .current_method_learning_read_v3 import _READING,bind_prepared_method_learning_read_v3,MethodInputNeededV3,_BUSINESS_RESULTS
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from ..graph_worker import GraphStorageStepV3,GraphStorageWorkV3
    from .habit_maintenance_followup_v3 import is_maintenance_locator_v3,advance_habit_maintenance_locator_v3
    if is_maintenance_locator_v3(work.state):return advance_habit_maintenance_locator_v3(graph,work)
    from .habit_followup_source_v3 import is_locator_v3,advance_locator_v3
    if is_locator_v3(work.state):return advance_locator_v3(graph,work)
    reader=work.state;state=require_habit_source_work_v3(reader)
    if reader.graph is not graph or reader.work is not work:raise AuthorityUnavailable('Habit Source Work advanced on another actual graph')
    with bind_runtime_storage_operation_v3(work.operation,reader.db):
        _habit_now_v3(reader)
        if reader.inputs_sealed:
            if not reader.read_finished:
                graph._validate_read_fence_v3(reader.fence)
                graph._finish_read_fence_v3(reader.fence);reader.read_finished=True;work.phase='habit_business_write'
                return GraphStorageStepV3('progress')
            if reader.business_started:raise AuthorityUnavailable('Habit Source same-Work business completes exactly once')
            reader.business_started=True;proof=reader.result
            with bind_prepared_method_learning_read_v3(proof,graph,reader.db):
                if reader.session_proof is not None:value=graph._complete_current_method_operation_v3(reader,proof)
                else:
                    from .habit_activity_runtime_v1 import run_current_habit_activity_v1
                    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
                    if type(state.selector)is HabitOriginalMaintenanceSelectorV1:
                        from .habit_original_maintenance_runtime_v1 import run_current_habit_original_maintenance_v1
                        run=run_current_habit_original_maintenance_v1
                    else:run=run_current_habit_activity_v1
                    value=run(graph,state.context,selector=state.selector,
                        operation_kind=reader.operation_kind,request=reader.request,source_inputs=proof)
            if type(value)is GraphStorageWorkV3:raise AuthorityUnavailable('Habit prepared WRITE cannot issue another Source Work')
            proof.business_result=value;_BUSINESS_RESULTS[proof]=(work,value);reader.business_completed=True
            return GraphStorageStepV3('complete',proof)
        graph._validate_read_fence_v3(reader.fence)
        if not reader.inventory_sealed:
            with reader.store._lock:reader.advance()
            return GraphStorageStepV3('progress')
        token=_READING.set(reader)
        try:
            with reader.store._lock:
                if reader.pending_input is not None:
                    with runtime_storage_quantum_v3(reader.db)as meter:
                        reader.pending_input.advance(meter)
                        if reader.pending_input.complete:reader.pending_input=None
                    return GraphStorageStepV3('progress')
            if not state.metadata_complete:
                with bind_prepared_method_learning_read_v3(reader.inventory,graph,reader.db),reader.store._lock:
                    reader.db.execute('BEGIN')
                    try:require_habit_source_plan_metadata_v3(reader)
                    finally:reader.db.rollback()
                return GraphStorageStepV3('progress')
            capsule=_PENDING_READERS.get(reader)
            if capsule is not None and capsule.phase=='metadata':
                _transition_habit_source_scope_v3(reader)
                return GraphStorageStepV3('progress')
            prepare_habit_owner_entry_v3(reader)
            fresh,descriptor=_habit_self_v3(reader)
            if capsule is not None and descriptor!=capsule.descriptor:
                raise AuthorityUnavailable('Habit Source current Self changed after the original metadata descriptor')
            reader.current_self=fresh
            with bind_prepared_method_learning_read_v3(reader.inventory,graph,reader.db),reader.store._lock:
                reader.db.execute('BEGIN')
                try:_habit_prepare_selected_v3(reader)
                finally:reader.db.rollback()
            if type(reader.result)is _HabitReadResultV3:
                from .habit_followup_source_v3 import complete_read_result_v3
                complete_read_result_v3(reader)
                graph._validate_read_fence_v3(reader.fence)
                graph._finish_read_fence_v3(reader.fence);reader.read_finished=True
                return GraphStorageStepV3('complete',reader.result)
        except MethodInputNeededV3 as needed:
            with reader.store._lock,runtime_storage_quantum_v3(reader.db):_habit_dependency_v3(reader,needed)
        finally:_READING.reset(token)
        if not reader.read_finished:graph._validate_read_fence_v3(reader.fence)
        return GraphStorageStepV3('progress')


def read_current_habit_receipt_v3(graph,context,selector,*,source_inputs,saved_projection):
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_originals_v1 import _receipt_wire
    from .c09_foreground_attempt_v1 import _RECEIPT_FIELDS
    reader=source_inputs.owner;state=require_habit_source_work_v3(reader)
    operation=installed_operation_v1(reader.operation_kind)
    require_habit_prepared_write_v3(source_inputs,graph,context,selector,operation,reader.request)
    actual=state.committed_original;receipt=state.receipt
    if (actual is None or receipt is None or receipt.operation_id!=selector.operation_id
            or receipt.status!='committed' or type(saved_projection)is not dict
            or set(saved_projection)!=_RECEIPT_FIELDS
            or saved_projection['schema']!='sylanne.domain-production-receipt.v1'
            or (saved_projection['domain'],saved_projection['operation_kind'],saved_projection['operation_id'],saved_projection['activity_id'])
                !=(operation.domain,operation.operation_kind,selector.operation_id,receipt.activity_id)
            or saved_projection['original_ref']!=operation.domain+'-current:'+actual['original_digest'][:48]
            or saved_projection['original_digest']!=actual['original_digest']
            or saved_projection['receipt']!=_receipt_wire(receipt)
            or saved_projection['receipt_digest']!=canonical_digest(receipt)
            or saved_projection['coverage']!=actual['payload']['coverage'] or saved_projection['missing_inputs']!=actual['payload']['missing_inputs']
            or saved_projection['continuation_ref']!=actual['payload']['continuation_ref']):
        raise AuthorityUnavailable('Habit replay disclosure differs from its actual Source-qualified same-Work COMMIT')
    return saved_projection


def finish_current_habit_source_work_v3(graph,work,error):
    from .current_method_learning_read_v3 import finish_current_method_learning_read_v3
    from .habit_maintenance_followup_v3 import is_maintenance_locator_v3,finish_habit_maintenance_locator_v3
    if is_maintenance_locator_v3(work.state):return finish_habit_maintenance_locator_v3(graph,work,error)
    from .habit_followup_source_v3 import is_locator_v3,finish_locator_v3
    if is_locator_v3(work.state):return finish_locator_v3(graph,work,error)
    reader=work.state
    if reader.graph is not graph or reader.work is not work:raise AuthorityUnavailable('Habit finalizer crossed its actual Source Work')
    payload=reader.result
    try:return finish_current_method_learning_read_v3(graph,work,error)
    finally:
        if error is not None and type(payload)is _HabitReadResultV3:
            _HABIT_READ_RESULTS.pop(payload,None);payload.value=None


def require_habit_source_terminal_value_v3(value,work):
    from .habit_maintenance_followup_v3 import is_maintenance_locator_v3,require_habit_maintenance_terminal_v3
    if is_maintenance_locator_v3(work.state):return require_habit_maintenance_terminal_v3(value,work)
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(value)is _HabitReadResultV3:return value.require_result_v3(work)
    if(type(value)is not PreparedMethodDomainInputsV3 or work.kind!=HABIT_SOURCE_WORK_KIND_V3
            or value.owner is not work.state):raise AuthorityUnavailable('Habit terminal has no actual private same-Work result')
    return value.require_business_result_v3(work)


def _pending_habit_activity_v3(capsule):
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(capsule.selector)is HabitOriginalMaintenanceSelectorV1:
        from .habit_maintenance_source_v3 import pending_habit_maintenance_identity_v3
        return pending_habit_maintenance_identity_v3(capsule)[1]
    if capsule.operation_kind in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,HABIT_RECEIPT_READ_KIND_V3,'resolve_current_habit_followup_v3'}:
        return capsule.operation.operation_id
    from .habit_activity_runtime_v1 import habit_activity_phase_identity_v1
    return habit_activity_phase_identity_v1(capsule.selector)[0]


_HABIT_JOB_COLUMNS_V3=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref',
    'phase','work_kind','continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref',
    'operator_versions_json','lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref')

def read_bound_current_habit_job_v3(db,job_id):
    reader=_active(db)
    if reader is None:return False,None
    state=require_habit_source_work_v3(reader)
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3,method_graph_head_v3
    from .jobs import _job_from_row
    from .d11_types import job_graph_write
    request=('runtime_jobs',_HABIT_JOB_COLUMNS_V3,('job_id',),(job_id,))
    require_habit_point_v3(reader,request)
    handled,row=read_bound_method_learning_attachment_v3(db,table=request[0],columns=request[1],key_columns=request[2],key=request[3])
    if not handled or row is None:raise AuthorityUnavailable('Habit selected SQL job is absent from its actual retained READ')
    job=_job_from_row(row)
    if(job.bot_id,job.persona_id)!=reader.namespace.as_tuple:raise AuthorityUnavailable('Habit actual SQL job crossed namespace')
    write=job_graph_write(job);atom=method_graph_head_v3(db,reader.namespace,write.key)
    if not atom.valid or atom.revision<1 or atom.value!=write.value:
        raise AuthorityUnavailable('Habit actual SQL job differs from its Source-qualified current Graph mirror')
    return True,job


class _HabitReadResultV3:
    def __init__(self,reader,value):
        self.reader,self.value=reader,value
        _HABIT_READ_RESULTS[self]=(reader,reader.work,reader.operation,reader.selection_digest,value)
    def require_result_v3(self,work):
        reader=self.reader
        if(_HABIT_READ_RESULTS.get(self)!=(reader,work,reader.operation,reader.selection_digest,self.value)
                or work.state is not reader or not reader.read_finished or not reader.complete
                or reader.operation_kind not in {HABIT_SCHEDULE_READ_KIND_V3,HABIT_POLICY_READ_KIND_V3,'resolve_current_habit_followup_v3'}):
            raise AuthorityUnavailable('Habit readonly result lost its actual private same-Work complete READ')
        return self.value
    def release_payload_v3(self):
        if _HABIT_READ_RESULTS.pop(self,None)is None:return
        from .current_method_learning_read_v3 import _release_method_registered_payloads_v3
        reader=self.reader
        _release_method_registered_payloads_v3(reader)
        if reader.inventory is not None:reader.inventory.release_payload_v3()
        reader.points.clear();reader.inventories.clear();reader.input_heads.clear()
        self.value=None


def _habit_schedule_scan_v3(reader):
    from .habit_schedule_driver_v1 import (HabitSubscriptionV1,HabitSubscriptionNoWindowV1,
        HabitScheduleEntryV1,HabitScheduleScanV1,habit_subscription_from_wire_v1,SUBSCRIPTION_KIND)
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
    from .current_method_learning_read_v3 import method_graph_head_v3
    state=require_habit_source_work_v3(reader);entries=[];missing=[];nearest=None
    for identity,task in sorted(state.tasks.items(),key=lambda item:repr(item[0])):
        if identity[0]!='head' or AtomKey.from_token(identity[1]).type_name!='runtime.job' or task.result is None:continue
        value=task.result
        if value['work_kind']!=SUBSCRIPTION_KIND or value['phase']not in {'waiting','deferred'}:continue
        token=identity[1];state.body_keys.add(AtomKey.from_token(token))
        continuation=_metadata(reader,('job_continuation',(value['job_id'],token)))
        subscription=habit_subscription_from_wire_v1(continuation)
        policy_value=_metadata(reader,('head',subscription.policy_ref))
        if policy_value is None:
            missing.append('retired_or_absent_policy:'+subscription.policy_ref);continue
        policy=graph_adopted_habit_policy_from_wire_v1(policy_value);d=policy.definition
        if(subscription.namespace!=reader.namespace or subscription.policy_revision!=d.revision
                or subscription.policy_digest!=policy.digest or subscription.standing_original_ref!=policy.core_original_ref
                or subscription.standing_original_digest!=policy.core_original_digest
                or subscription.cancellation_generation!=d.cancellation_generation):
            missing.append('superseded_subscription:'+token);continue
        _,job=read_bound_current_habit_job_v3(reader.db,value['job_id'])
        head=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(token))
        absent=()
        if type(subscription)is HabitSubscriptionNoWindowV1:
            if job.phase!='deferred' or job.wake_condition is not None:raise AuthorityUnavailable('Habit no-window subscription has a forbidden runnable wake')
            absent=('no_executable_window',)
        elif d.state!='enabled' or _habit_now_v3(reader)>=subscription.original_deadline_utc:
            absent=('expired_or_disabled_original_policy',)
        elif job.phase!='waiting' or job.lease_holder is not None:
            absent=('actual_unleased_waiting_subscription',)
        if not absent:nearest=subscription.due_at_utc if nearest is None else min(nearest,subscription.due_at_utc)
        entries.append(HabitScheduleEntryV1(policy,subscription,job,GraphVersion(head.key,head.revision),
            'hold'if absent else 'complete',absent))
    return HabitScheduleScanV1(reader.namespace,tuple(entries),nearest,'hold'if missing else 'complete',None,tuple(missing))


def _habit_schedule_metadata_selection_v3(reader):
    if reader.operation_kind!=HABIT_SCHEDULE_READ_KIND_V3:return
    from .habit_schedule_driver_v1 import SUBSCRIPTION_KIND,habit_subscription_from_wire_v1
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
    state=require_habit_source_work_v3(reader)
    for identity,task in tuple(state.tasks.items()):
        if identity[0]!='job_continuation' or not task.complete or task.result is None:continue
        if task.metadata[7]!=SUBSCRIPTION_KIND or task.metadata[6]not in {'waiting','deferred'}:continue
        subscription=habit_subscription_from_wire_v1(task.result)
        state.body_keys.add(AtomKey.from_token(identity[1][1]))
        state.source_roots.update(subscription.source_refs)
        policy_raw=_metadata(reader,('head',subscription.policy_ref))
        if policy_raw is not None:
            definition=graph_adopted_habit_policy_from_wire_v1(policy_raw).definition
            state.source_roots.update(definition.source_refs)



class _HabitCueInventoryTaskV3:
    def __init__(self,reader):
        self.reader=reader;self.after='';self.child=self.column=None;self.complete=False;self.result=()
    def require_header_v3(self,meter):
        self.reader.require_current(meter=meter)
        return self.result
    def advance(self,meter):
        from .habit_schedule_driver_v1 import CUE_INPUT_KIND
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        reader=self.reader;state=require_habit_source_work_v3(reader);reader.require_current(meter=meter)
        if self.complete:return True
        if self.child is not None:
            if not self.child.advance(meter):return False
            self.child.require_header_v3(meter);self.child=None;return False
        row=_beta1_metadata_row_v3(reader,meter,'graph_d10_production_inputs_v1',('original_ref',),
            'bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref',
            (*reader.namespace.as_tuple,CUE_INPUT_KIND,self.after))
        if row is None:
            self.complete=True;self.result=tuple(sorted(state.cue_originals));state.cue_inventory=self
            return True
        self.after=row[0]
        if len(state.cue_originals)>=128:raise AuthorityUnavailable('Habit cue census exceeds its original fixed-family 128-row bound')
        identity=('cue_original',row[0]);state.selected.add(identity)
        self.child=create_current_habit_metadata_task_v3(reader,identity)
        return False


def read_bound_current_habit_cue_original_v3(db,*,frame,original_ref,original_digest):
    reader,state=_frame_state(db,frame)
    if state.cue_inventory is None or not state.cue_inventory.complete:
        raise AuthorityUnavailable('Habit cue original lacks its actual complete metadata census')
    cue=state.cue_originals.get(original_ref)
    if cue is None or cue.digest!=original_digest:raise AuthorityUnavailable('Habit cue differs from the actual frozen registered original')
    require_habit_write_phase_v3(reader)
    return cue



def read_current_habit_schedule_census_v3(db,*,frame,policy_ref,window_id):
    """Join the actual cross-revision occurrence and Graph/Core cue EOFs."""
    from .habit_schedule_driver_v1 import HabitWindowScheduleCensusV1
    from .domain_production_contracts_v1 import actual_frame_read_versions_v1
    from ..domains.d10.habit_policy_v1 import habit_policy_key_v1
    reader,state=_frame_state(db,frame)
    pending=require_habit_write_phase_v3(reader)
    if reader.session_proof is None or state.core_inputs is None:
        raise AuthorityUnavailable('Habit subscription census needs its actual Owner policy WRITE')
    original=state.core_inputs.policy_original
    definition=reader.request.definition
    if (original is None or original.definition!=definition
            or policy_ref!=habit_policy_key_v1(reader.namespace,definition.policy_id).token
            or state.cue_inventory is None or not state.cue_inventory.complete):
        raise AuthorityUnavailable('Habit subscription census lost its exact issued policy or Graph cue EOF')
    action=('issue' if reader.operation_kind=='create_habit_policy_v1' else
        'revoke' if reader.operation_kind=='stop_habit_policy_v1' else 'revise')
    port=reader.graph._GraphCoordinator__habit_occurrence_port_v1
    inventory=port.require_issued_policy_window_cue_inventory_v1(scope=pending.scope,
        definition=definition,operation_id=original.operation_id,action=action,original=original)
    if (inventory.namespace!=reader.namespace or inventory.policy_ref!=policy_ref
            or inventory.window_id!=window_id):
        raise AuthorityUnavailable('Habit subscription census differs from the actual Core current window')
    occurrences=_occurrence_metadata_entries(reader,state,frame,policy_ref=policy_ref)
    refs=tuple(sorted(row.ref for row in occurrences if row.window_id==window_id))
    cues=tuple(sorted(ref for ref,cue in state.cue_originals.items()
        if cue.selector.policy_ref==policy_ref and cue.selector.window_id==window_id))
    versions=actual_frame_read_versions_v1(frame)
    return HabitWindowScheduleCensusV1(reader.namespace,policy_ref,window_id,refs,cues,
        inventory.core_cue_original_refs,versions,frame.query_coverage,'complete')


def _habit_outcome_producer_digest_v3(reader):
    """Locate the output key from the exact current progress producing history EOF."""
    state=require_habit_source_work_v3(reader)
    ref=reader.request.life_progress_ref
    key=AtomKey.from_token(ref)
    if key.type_name!='d10.life_progress.v1' or NamespaceId.from_key(key)!=reader.namespace:
        raise AuthorityUnavailable('Habit outcome metadata requires its actual current Life progress')
    _metadata(reader,('head',ref))
    head=state.tasks[('head',ref)]
    if head.metadata is None or head.metadata[:2]!=(reader.request.life_progress_revision,1):
        raise AuthorityUnavailable('Habit outcome current progress revision is absent or changed')
    revision=head.metadata[0]
    state.history.add((ref,revision));state.selected.add(('history',(ref,revision)))
    _metadata(reader,('history',(ref,revision)))
    history=state.tasks[('history',(ref,revision))]
    operation_id=history.metadata[2]
    state.producers.add(operation_id);state.selected.add(('producer',operation_id))
    _metadata(reader,('producer',operation_id))
    producer=state.tasks[('producer',operation_id)]
    if (producer.metadata[:2]!=('d10','advance_life')
            or 'd10-current:'+producer.metadata[3][:48]!=reader.request.growth_trigger_ref):
        raise AuthorityUnavailable('Habit outcome locator is not the exact actual advance_life producer')
    return producer.metadata[3]


def current_habit_independent_core_original_refs_v3(db):
    """Expose only actual privately bound current-WRITE Core originals to the frame."""
    reader=_active(db)
    if reader is None:return ()
    state=require_habit_source_work_v3(reader)
    facts=state.core_inputs
    if facts is None:return ()
    require_habit_write_phase_v3(reader)
    from ..authority_service.d10_habit_contract_v1 import (HabitStandingPolicyOriginalV1,
        HabitOccurrenceQualificationOriginalV1,HabitWindowCueOriginalV1)
    result=[]
    originals=[(facts.policy_original,HabitStandingPolicyOriginalV1,'d10.habit_standing_policy'),
        (facts.occurrence_qualification,HabitOccurrenceQualificationOriginalV1,'d10.habit_occurrence_qualification'),
        (facts.timecue_original,HabitWindowCueOriginalV1,'d11.habit_window_cue')]
    from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    pending=require_habit_write_phase_v3(reader)
    if type(pending.issued)is _IssuedHabitMaintenanceV1:
        originals.append((pending.evidence.standing_original,HabitStandingPolicyOriginalV1,'d10.habit_standing_policy'))
    for original,expected,kind in originals:
        if original is None:continue
        if type(original)is not expected:
            raise AuthorityUnavailable('Habit Core original has another exact registered type')
        namespace=(original.selector.namespace if expected is HabitWindowCueOriginalV1 else original.namespace)
        if namespace!=reader.namespace:raise AuthorityUnavailable('Habit Core original crossed its actual Source namespace')
        # Original support versions are historical; fresh Core observation supplies current Source support.
        versions=tuple(version for version in pending.evidence.read_versions if version.key.type_name=='memory.source')
        result.append(ProductionOriginalRefV1(kind,original.original_ref,original.digest,versions))
    return tuple(result)


def current_habit_installed_owner_guard_v3(graph,*,scope,operation,owner_guard,owner_binding):
    """Use the actual Owner17 authorization guard; a Frame guard cannot manufacture one."""
    reader=_active(graph._GraphCoordinator__store._db)
    if reader is None:return None
    state=require_habit_source_work_v3(reader)
    if (reader.graph is not graph or reader.operation_kind!=operation.operation_kind
            or type(reader.request)is not operation.request_type or state.source_permission is None
            or not state.metadata_complete):
        raise AuthorityUnavailable('Habit installed readers changed the actual Source operation/current permission')
    actual=None
    if scope is reader.fence.scope and not reader.read_finished:
        if reader.general_owner_entry is None or owner_binding is not reader.owner_binding or owner_guard!=reader.material_owner_guard:
            raise AuthorityUnavailable('Habit READ readers lost their actual completed Owner17 entry')
        entry=reader.general_owner_entry
    else:
        pending=require_habit_write_phase_v3(reader)
        if pending.scope is not scope or owner_guard!=_habit_write_owner_guard_v3(reader,pending):
            raise AuthorityUnavailable('Habit WRITE readers changed their actual fresh Scope or production guard')
        if reader.session_proof is not None:
            entry=pending.owner_entry;actual=pending.guard
            if owner_binding is not pending.current_owner:
                raise AuthorityUnavailable('Habit Owner WRITE reader changed its actual current Owner binding')
        else:
            entry=pending.owner_entry
            if owner_binding is not pending.owner_binding:
                raise AuthorityUnavailable('Habit background WRITE reader changed its actual Owner binding')
    entry.require_for_v3(reader)
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    if actual is None:actual=entry.current_owner_guard
    if type(actual)is not OwnerAuthorizationGuardV1 or actual.namespace!=scope.namespace:
        raise AuthorityUnavailable('Habit installed reader has no actual current Owner authorization guard')
    return actual


def require_current_joint_window_management_v3(db,*,frame,operation_kind,request):
    from .current_joint_window_source_read_v3 import require_current_joint_window_management_v3 as current
    return current(db,frame=frame,operation_kind=operation_kind,request=request)


def read_current_joint_window_execution_classification_v3(db,*,namespace,issuer,action_ref=None,binding=None,frame=None):
    from .current_joint_window_source_read_v3 import read_current_joint_window_execution_classification_v3 as current
    return current(db,namespace=namespace,issuer=issuer,action_ref=action_ref,binding=binding,frame=frame)


def prepare_current_managed_joint_node_source_work_v3(graph,context,argument,request):
    from .current_joint_window_source_read_v3 import prepare_current_managed_joint_node_source_work_v3 as current
    return current(graph,context,argument,request)


def require_current_habit_artifact_frame_inputs_v3(db,*,frame,selector,issuer):
    """The actual Artifact profile proves ordinary or returns its extra restriction."""
    from .artifact_borrowed_source_v3 import require_artifact_borrowed_frame_facts_v3
    return require_artifact_borrowed_frame_facts_v3(db,frame=frame,selector=selector,issuer=issuer)
