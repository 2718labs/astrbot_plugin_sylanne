"""Private normal Habit followups; every next phase derives from an actual producer."""
from dataclasses import dataclass,fields
from weakref import WeakKeyDictionary
import time
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion

READ_KIND='resolve_current_habit_followup_v3'
_EVENTS={
    'habit_cue_observed_requires_occurrence':('d11','record_habit_window_cue_v1','d10','register_habit_occurrence_v1'),
    'habit_occurrence_registered_requires_qualification':('d10','register_habit_occurrence_v1','d11','qualify_habit_occurrence_v1'),
    'qualified_habit_occurrence_requires_recipe':('d10','qualify_habit_occurrence_v1','d08','instantiate_current_habit_source_note_context_v1'),
    'habit_source_note_context_ready_requires_action':('d08','instantiate_current_habit_source_note_context_v1','d08','prepare_current_habit_source_note_action_v1'),
    'habit_source_note_action_requires_original_life':('d08','prepare_current_habit_source_note_action_v1','d11','prepare_source_note_body'),
    'habit_source_note_body_requires_original_plan_v3':('d02','prepare_source_note_body','d10','register_current_habit_source_note_life_plan_v1'),
    'habit_life_plan_requires_original_preparation':('d10','register_current_habit_source_note_life_plan_v1','d11','prepare_life'),
}
_ISSUER=object()
_LOCATORS=WeakKeyDictionary()
_SELECTORS=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()
_CHILDREN=WeakKeyDictionary()
_FRAME_CHILDREN={}
PROVENANCE='habit_followup_target_v3'

@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _HabitFollowupSelectorV3:
    namespace:NamespaceId
    policy_ref:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    producer_operation_id:str
    dedupe_key:str
    old_selector:object

def operation_types_v3():return {READ_KIND:_HabitFollowupSelectorV3}

def selector_policy_ref_v3(selector):
    if type(selector)is not _HabitFollowupSelectorV3:return None
    _require_selector(selector)
    return selector.policy_ref

def _require_selector(selector):
    locator=_SELECTORS.get(selector)
    if locator is None or locator.selector is not selector or _LOCATORS.get(locator)is None:
        raise AuthorityUnavailable('Habit followup selector lacks actual complete producer metadata EOF')
    return locator

def original_limit_v3(reader,grant,limit):
    if reader.operation_kind!=READ_KIND:return limit
    selector=reader.request;_require_selector(selector)
    if(selector.parent_root_grant_ref!=grant.lease_id or selector.parent_root_grant_digest!=canonical_digest(grant)):
        raise AuthorityUnavailable('ordinary Habit followup cannot upgrade its original Root')
    return min(limit,selector.original_deadline_utc)

def _retain(path):
    if not path:return True
    if path[0]in {'schema','namespace','identity','parent_budget'}:return True
    if path[0]!='provenance':return False
    if len(path)==1:return True
    if path[1]!='habit_activity_execution_v1':return False
    return not(len(path)>=4 and path[2]=='selector'and path[3]=='command')

class _ProducerColumnV3:
    def __init__(self,locator):
        from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3
        self.locator=locator;self.operation=locator.operation
        self.total=None;self.offset=0;self.result=None;self.complete=False
        self.capture=ConditionedLocatorJSONV3(self);self.capture.retain_path_v3=_retain
    def _actual(self):self.locator.require_current();return self
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        self._actual();l=self.locator
        if self.complete:return True
        header=meter.read_fixed_row(l.db,'graph_domain_production_originals_v1',
            ('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest'),
            'bot=? AND persona=? AND operation_id=?',(*l.namespace.as_tuple,l.header[0]))
        if header!=l.producer_header:raise AuthorityUnavailable('Habit producer changed during metadata EOF')
        if self.total is None:
            with legacy_cell_read_transaction_v2(l.db):
                row=l.db.execute('SELECT typeof(original_payload_json),length(CAST(original_payload_json AS BLOB)) '
                    'FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
                    (*l.namespace.as_tuple,l.header[0])).fetchone()
            meter.charge_read(16)
            if row is None or row[0]!='text':raise AuthorityUnavailable('Habit producer original metadata is absent')
            self.total=row[1];return False
        if self.offset<self.total:
            with legacy_cell_read_transaction_v2(l.db):
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(l.db,table='graph_domain_production_originals_v1',
                    column='original_payload_json',where='bot=? AND persona=? AND operation_id=?',
                    parameters=(*l.namespace.as_tuple,l.header[0]),start=self.offset,
                    length=min(1024,self.total-self.offset),meter=meter)
            if(total,kind)!=(self.total,'text'):raise AuthorityUnavailable('Habit physical producer metadata changed')
            self.capture._reserve_v3(len(chunk)*8+65536)
            self.capture.parser.feed(chunk,self.capture._emit_v3);self.offset+=len(chunk);return False
        parsed=self.capture.parser.finish();self.capture._flush_text_v3()
        if parsed.byte_count!=self.total or parsed.sha256!=l.producer_header[3]:
            raise AuthorityUnavailable('Habit producer lacks its exact canonical complete metadata digest')
        self.result=self.capture.value;self.complete=True;return True

class _LocatorV3:
    def __init__(self,issuer,graph,context,bundle,operation,key,header):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Habit followup requires its actual private factory')
        self.graph,self.context,self.bundle,self.operation=graph,context,bundle,operation
        self.store=graph._GraphCoordinator__store;self.db=self.store._db
        self.namespace=bundle.installation_policy.namespace;self.key,self.header=key,header
        self.graph_stamp=graph._v2_graph_stamp(self.namespace)
        self.producer_header=self.bundle_header=self.column=self.selector=self.work=None
        self.initial_deadline=operation.deadline_utc;self.monotonic_deadline=time.monotonic()+60.0
        _LOCATORS[self]=(graph,context,bundle,operation,key,header,self.graph_stamp)
    def require_current(self):
        if(_LOCATORS.get(self)!=(self.graph,self.context,self.bundle,self.operation,self.key,self.header,self.graph_stamp)
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph
                or self.operation.closed or time.monotonic()>=self.monotonic_deadline
                or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp):
            raise AuthorityUnavailable('Habit metadata lost its actual Work/Graph/context')
        self.work._require_invocation(self.graph)
    def advance(self,meter):
        self.require_current()
        current=meter.read_fixed_row(self.db,'graph_domain_production_outbox_v1',
            ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state','consumer_operation_id'),
            'bot=? AND persona=? AND dedupe_key=?',(*self.namespace.as_tuple,self.key))
        if current!=self.header:raise AuthorityUnavailable('Habit outbox changed during metadata EOF')
        if self.producer_header is None:
            self.producer_header=meter.read_fixed_row(self.db,'graph_domain_production_originals_v1',
                ('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.header[0]))
            if self.producer_header is None:raise AuthorityUnavailable('Habit outbox has no actual committed producer')
            return False
        if self.bundle_header is None:
            self.bundle_header=meter.read_fixed_row(self.db,'graph_bundle_operations',('digest','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.header[0]))
            if(self.bundle_header is None or self.bundle_header[0]!=self.producer_header[5]
                    or type(self.bundle_header[1])is not int or self.bundle_header[1]<1):
                raise AuthorityUnavailable('Habit producer lacks actual positive shared COMMIT')
            return False
        if self.column is None:self.column=_ProducerColumnV3(self);return False
        if not self.column.advance(meter):return False
        from .habit_activity_history_v1 import _root_selector_v1
        raw=self.column.result;domain,kind=self.producer_header[:2];event=self.header[2]
        if((domain,kind,self.header[1])!=_EVENTS[event][:3]or raw['schema']!=domain+'.current-'+kind+'.v1'
                or raw['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or(raw['identity']['operation_id'],raw['identity']['phase'])!=(self.header[0],kind)
                or self.header[3]!=domain+'-current:'+self.producer_header[3][:48]
                or self.header[4]!=self.producer_header[3]
                or self.key!=canonical_digest((self.namespace,self.header[0],self.header[1],event))):
            raise AuthorityUnavailable('Habit fixed producer/original/outbox membership differs')
        old=_metadata_producer_selector_v3(domain,kind,raw['provenance']['habit_activity_execution_v1'])
        root=old.qualification_selector if type(old)is _ExecutionProducerLocatorV3 else _root_selector_v1(old)
        if old.namespace!=self.namespace or old.operation_id!=self.header[0]or raw['parent_budget']!=root.parent_root_grant_ref:
            raise AuthorityUnavailable('Habit producer changed its actual original selector/Root')
        self.selector=_HabitFollowupSelectorV3(self.namespace,root.policy_ref,root.parent_root_grant_ref,
            root.parent_root_grant_digest,root.original_deadline_utc,self.header[0],self.key,old)
        _SELECTORS[self.selector]=self;return True

def prepare_current_habit_followup_v3(graph,bootstrap,bundle,*,dedupe_key,context):
    from ..runtime_context import RuntimeContext
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,runtime_storage_quantum_v3,finish_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    from .current_habit_source_read_v3 import HABIT_SOURCE_WORK_KIND_V3
    from uuid import uuid4
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,'habit-followup-read:'+uuid4().hex,now+60.0)
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db),graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(graph._GraphCoordinator__store._db)as meter:
            header=meter.read_fixed_row(graph._GraphCoordinator__store._db,'graph_domain_production_outbox_v1',
                ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state','consumer_operation_id'),
                'bot=? AND persona=? AND dedupe_key=?',(*bundle.installation_policy.namespace.as_tuple,dedupe_key))
        if header is None or header[2]not in _EVENTS:
            finish_runtime_storage_operation_v3(operation);return False,None
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        if(type(context)is not RuntimeContext or context._v2_coordinator is not graph
                or context._v2_bootstrap is not bootstrap or context._v2_model_bundle is not bundle
                or context._v2_namespace!=bundle.installation_policy.namespace
                or assembly is None or assembly.admin_bundle is not bundle):
            raise AuthorityUnavailable('normal Habit followup requires actual installed RuntimeContext')
        if header[5]not in {'pending','waiting'}or header[6]is not None:
            raise AuthorityUnavailable('Habit event has no pending undisposed actual phase')
        locator=_LocatorV3(_ISSUER,graph,context,bundle,operation,dedupe_key,header)
        work=create_graph_storage_work_v3(graph,kind=HABIT_SOURCE_WORK_KIND_V3,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=locator,operation=operation)
        locator.work=work;work._require_invocation(graph,initial=True);work.phase='habit_followup_metadata_eof'
        return True,work
    except BaseException:finish_runtime_storage_operation_v3(operation);raise

def is_locator_v3(value):return type(value)is _LocatorV3

def advance_locator_v3(graph,work):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_contracts import AuthorityContext
    from .current_habit_source_read_v3 import _HabitPendingSourceV3,_PENDING,_pending_identity,_habit_pending_reader_v3
    locator=work.state;locator.require_current()
    with bind_runtime_storage_operation_v3(work.operation,locator.db):
        with locator.store._lock,runtime_storage_quantum_v3(locator.db)as meter:
            if not locator.advance(meter):return GraphStorageStepV3('progress')
        from .habit_maintenance_followup_v3 import promote_expired_habit_followup_v3
        if promote_expired_habit_followup_v3(locator):return GraphStorageStepV3('progress')
        generation=locator.graph_stamp[0].requirements.activation_generation
        purpose=('context'if _EVENTS[locator.header[2]][3]in {'register_habit_occurrence_v1','qualify_habit_occurrence_v1','instantiate_current_habit_source_note_context_v1'}else'consolidation')
        authority=AuthorityContext('habit-source-metadata','d10','habit-source-metadata',locator.namespace,
            ('activity',),purpose,('owner',),'habit-source-read.v3',generation)
        fence=graph._begin_read_fence_v3(authority,operation_id=work.operation_id+':metadata')
        capsule=_HabitPendingSourceV3(graph,locator.context,locator.bundle,work.operation,work,
            locator.selector,READ_KIND,locator.selector,authority,fence,locator.initial_deadline,locator.monotonic_deadline)
        work.state=capsule;_PENDING[capsule]=_pending_identity(capsule)
        _habit_pending_reader_v3(capsule);work.phase='habit_followup_owner_source_eof'
    return GraphStorageStepV3('progress')

def finish_locator_v3(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    locator=work.state
    if locator.graph is not graph or locator.work is not work:raise AuthorityUnavailable('Habit finalizer changed actual Work')
    _LOCATORS.pop(locator,None);finish_runtime_storage_operation_v3(work.operation)

def select_metadata_v3(reader):
    from .current_habit_source_read_v3 import require_habit_source_work_v3,_select_refs,_metadata
    state=require_habit_source_work_v3(reader)
    from .habit_body_cpu_source_v3 import select_host_body_metadata_v3
    select_host_body_metadata_v3(reader)
    child=_CHILDREN.get(reader)
    if child is not None:
        handoff,_=child;handoff.require_current(reader.graph,state.context,handoff.bundle)
        state.producers.add(handoff.locator.header[0])
    if reader.operation_kind!=READ_KIND:return
    locator=_require_selector(state.selector)
    if locator.context is not state.context:raise AuthorityUnavailable('Habit actual Source context changed')
    state.producers.add(locator.header[0])
    _select_refs(reader,state.selector.old_selector,body=True)
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
    old=state.selector.old_selector
    for token,head in reader.heads.items():
        key=AtomKey.from_token(token)
        if key.type_name!='d10.habit_occurrence.v1':continue
        value=_metadata(reader,('head',token))
        if value is None or value['policy_ref']!=state.selector.policy_ref:continue
        selected=(old.occurrence_ref==token if type(old)in {HabitOccurrenceExecutionSelectorV1,_ExecutionProducerLocatorV3} else
            value['cue_original_ref']==old.cue_original_ref)
        if selected:_select_refs(reader,value,body=True);state.body_keys.add(key)

class HabitFollowupPreparedV3:
    def __init__(self,issuer,reader,locator,selector,kind,request,producer):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Habit next phase requires actual protected Source resolver')
        self.graph,self.context,self.bundle=reader.graph,locator.context,locator.bundle
        self.reader,self.locator,self.selector,self.kind,self.request=reader,locator,selector,kind,request
        self.producer_digest,self.receipt_digest=producer['original_digest'],canonical_digest(producer['receipt'])
        from ..domains.d01.production_operations_v1 import plain_v1
        self.target=plain_v1({'schema':'d10.habit-followup-target.v3','dedupe_key':locator.key,
            'producer_operation_id':locator.header[0],'producer_original_digest':self.producer_digest,
            'producer_receipt_digest':self.receipt_digest,'event_kind':locator.header[2],
            'selector':selector,'selector_digest':canonical_digest(selector),'operation_id':selector.operation_id,
            'operation_kind':kind,'request':request,'request_digest':canonical_digest(request),
            'parent_root_grant_ref':reader.parent_budget_lease_ref,'original_deadline_utc':selector.original_deadline_utc})
        _PREPARED[self]=(self.graph,self.context,self.bundle,reader,locator,selector,kind,request,canonical_digest(self.target))
    def require_current(self,graph,context,bundle):
        if(_PREPARED.get(self)!=(graph,context,bundle,self.reader,self.locator,self.selector,self.kind,self.request,canonical_digest(self.target))
                or graph is not self.graph or context is not self.context or bundle is not self.bundle):
            raise AuthorityUnavailable('Habit handoff changed actual producer or full frozen selector')
        return self

def _typed(kind,request):
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    return habit_typed_command_digest_v1(installed_operation_v1(kind),request)

def finish_selected_v3(reader):
    from .current_habit_source_read_v3 import require_habit_source_work_v3,_HabitReadResultV3,_habit_now_v3
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .habit_activity_history_v1 import validate_habit_activity_provenance_v1,_root_selector_v1
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1,habit_occurrence_id_v1,habit_occurrence_key_v1,HabitOccurrenceSelectorV1
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceBirthSelectorV1,HabitWindowCueSelectorV1
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,HabitOccurrencePhaseCommandV1,HabitSourceNoteLifeCommandV1
    from .d10_habit_v1 import RegisterHabitOccurrenceRequestV1,QualifyHabitOccurrenceRequestV1,habit_registration_operation_id_v1,habit_source_note_context_operation_id_v1,habit_source_note_life_ids_v1
    from .dispatch_current_inventory_v3 import _heap
    state=require_habit_source_work_v3(reader);locator=_require_selector(state.selector)
    producer=read_adopted_domain_operation_v1(reader.db,reader.namespace,locator.header[0])
    if(producer is None or producer['original_digest']!=locator.producer_header[3]
            or canonical_digest(producer['receipt'])!=locator.producer_header[4]or producer['receipt'].status!='committed'):
        raise AuthorityUnavailable('Habit protected producer differs from actual metadata/COMMIT')
    payload=producer['payload'];old,_=validate_habit_activity_provenance_v1(producer['domain'],producer['operation_kind'],payload['provenance']['habit_activity_execution_v1'])
    if _selector_metadata_projection_v3(old)!=_selector_metadata_projection_v3(state.selector.old_selector):
        raise AuthorityUnavailable('Habit protected original changed its complete actual metadata descriptor')
    root=_root_selector_v1(old)
    policy_head=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(root.policy_ref))
    policy=graph_adopted_habit_policy_from_wire_v1(policy_head.value);d=policy.definition
    if((d.revision,policy.digest,policy.core_original_ref,policy.core_original_digest)!=(root.policy_revision,root.policy_digest,root.standing_authorization_original_ref,root.standing_authorization_original_digest)
            or d.parent_root_grant_ref!=root.parent_root_grant_ref or d.parent_root_grant_digest!=root.parent_root_grant_digest):
        raise AuthorityUnavailable('Habit current standing policy superseded the original producer')
    kind=_EVENTS[locator.header[2]][3]
    if type(old)is HabitWindowCueSelectorV1:
        from .joint_habit_provenance_v1 import habit_window_cue_from_domain_plain_v1
        core=habit_window_cue_from_domain_plain_v1(payload['provenance']['core_cue_original'])
        if core.selector!=old or core.execution_state!='due':raise AuthorityUnavailable('Habit registration needs actual due Core cue')
        occurrence_id=habit_occurrence_id_v1(reader.namespace,d.policy_id,d.revision,old.window_id,old.cue_stable_key)
        operation=habit_registration_operation_id_v1(reader.namespace,occurrence_id)
        request=RegisterHabitOccurrenceRequestV1(root.policy_ref,policy_head.revision,core.original_ref,core.digest)
        deadline=min(old.window_end_utc,old.due_at_utc+d.execution_seconds,d.original_valid_until_utc,old.original_deadline_utc)
        selector=HabitOccurrenceBirthSelectorV1(reader.namespace,old.installation_id,root.policy_ref,d.revision,policy.digest,
            policy.core_original_ref,policy.core_original_digest,core.original_ref,core.digest,old.cue_stable_key,
            'd11-current:'+producer['original_digest'][:48],producer['original_digest'],
            old.window_id,old.window_start_utc,old.window_end_utc,operation,_typed(kind,request),d.parent_root_grant_ref,
            d.parent_root_grant_digest,deadline,d.cancellation_generation)
    else:
        occurrence_ref=(old.occurrence_ref if type(old)is HabitOccurrenceExecutionSelectorV1 else
            habit_occurrence_key_v1(reader.namespace,payload['provenance']['occurrence']['occurrence_id']).token)
        atom=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(occurrence_ref))
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
        if producer['operation_kind']!='prepare_source_note_body':
            member=tuple(v for v in producer['receipt'].write_versions if v.key==atom.key)
            if member!=(GraphVersion(atom.key,atom.revision),):
                raise AuthorityUnavailable('Habit next phase must observe its exact producer occurrence member')
        elif atom.revision!=old.expected_occurrence_revision:
            raise AuthorityUnavailable('Habit Body continuation current occurrence revision changed')
        if(occurrence.policy_ref!=root.policy_ref or occurrence.policy_digest!=policy.digest
                or occurrence.parent_root_grant_digest!=d.parent_root_grant_digest
                or occurrence.state not in {'registered','waiting','qualified'}):
            raise AuthorityUnavailable('Habit next phase has no exact current ordinary occurrence')
        if kind=='qualify_habit_occurrence_v1':
            request=QualifyHabitOccurrenceRequestV1(occurrence_ref,atom.revision)
            operation='habit-qualify:'+canonical_digest((reader.namespace,occurrence.occurrence_id))[:48]
            selector=HabitOccurrenceSelectorV1(reader.namespace,occurrence.policy_ref,occurrence.policy_revision,occurrence.policy_digest,
                occurrence.window_id,occurrence.window_start_utc,occurrence.window_end_utc,occurrence.cue_original_ref,
                occurrence.cue_original_digest,occurrence.cue_stable_key,'d10-current:'+producer['original_digest'][:48],producer['original_digest'],operation,
                occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,_typed(kind,request),
                occurrence.recipe_ref,occurrence.recipe_revision,occurrence.executor_kind,policy.core_original_ref,policy.core_original_digest,
                occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest,occurrence.original_deadline_utc,'context',
                d.audience,d.target_ref,occurrence.cancellation_generation,occurrence.source_refs)
        else:
            if occurrence.executor_kind!='source_note':raise AuthorityUnavailable('SourceNote consumer cannot execute an Artifact generation')
            if producer['operation_kind']=='qualify_habit_occurrence_v1':
                from .joint_habit_provenance_v1 import _qualification
                qualification,_=_qualification(payload['provenance']['core_qualification'])
                q=qualification.selector;qualification_ref,qualification_digest=qualification.original_ref,qualification.digest
            else:q=old.qualification_selector;qualification_ref,qualification_digest=old.qualification_original_ref,old.qualification_original_digest
            ids=habit_source_note_life_ids_v1(reader.namespace,occurrence.occurrence_id,d.project_ref)
            if kind=='instantiate_current_habit_source_note_context_v1':
                operation=habit_source_note_context_operation_id_v1(reader.namespace,occurrence.occurrence_id)
                command=HabitOccurrencePhaseCommandV1(occurrence_ref,atom.revision)
            elif kind=='prepare_current_habit_source_note_action_v1':
                operation=occurrence.occurrence_operation_id;command=HabitOccurrencePhaseCommandV1(occurrence_ref,atom.revision)
            elif kind=='prepare_source_note_body':
                value=_body_command_v3(reader,occurrence,atom,q,qualification_ref,qualification_digest,locator,producer)
                reader.operation.retain(_heap(value)*2+65536)
                reader.result=_HabitReadResultV3(reader,value);reader.complete=True
                return True
            elif kind=='register_current_habit_source_note_life_plan_v1':
                operation=ids['plan_operation_id'];command=HabitOccurrencePhaseCommandV1(occurrence_ref,atom.revision)
            else:operation=ids['prepare_operation_id'];command=HabitSourceNoteLifeCommandV1(ids['plan_ref'],operation)
            from .domain_production_registry_v1 import installed_operation_v1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from dataclasses import asdict
            command_wire=asdict(command);command_wire.pop('schema');command_wire.pop('preparation',None)
            request=decode_typed_production_value_v1(command_wire,installed_operation_v1(kind).request_type)
            selector=HabitOccurrenceExecutionSelectorV1(reader.namespace,q,qualification_ref,qualification_digest,
                occurrence_ref,atom.revision,kind,operation,_typed(kind,request),command)
    if _habit_now_v3(reader)>=selector.original_deadline_utc:raise AuthorityUnavailable('ordinary Habit original window expired')
    value=HabitFollowupPreparedV3(_ISSUER,reader,locator,selector,kind,request,producer)
    reader.operation.retain(_heap(value)*2+65536)
    reader.result=_HabitReadResultV3(reader,value);reader.complete=True
    return True

def _body_command_v3(reader,occurrence,atom,q,qualification_ref,qualification_digest,locator,producer):
    from .habit_body_cpu_source_v3 import host_body_basis_v3
    selected,basis=host_body_basis_v3(reader,occurrence=occurrence,occurrence_atom=atom,qualification_selector=q,
        qualification_ref=qualification_ref,qualification_digest=qualification_digest)
    return _BodyPreparationPendingV3(_ISSUER,reader,locator,selected,basis,producer)

def prepare_habit_followup_child_v3(graph,context,bundle,*,handoff):
    from .habit_maintenance_followup_v3 import HabitMaintenanceFollowupPreparedV3,prepare_habit_maintenance_followup_child_v3
    if type(handoff)is HabitMaintenanceFollowupPreparedV3:
        return prepare_habit_maintenance_followup_child_v3(graph,context,bundle,handoff=handoff)
    from .current_habit_source_read_v3 import prepare_current_habit_activity_source_v3
    handoff.require_current(graph,context,bundle)
    work=prepare_current_habit_activity_source_v3(graph,context,selector=handoff.selector,
        operation_kind=handoff.kind,request=handoff.request)
    _CHILDREN[work.state]=(handoff,canonical_digest(handoff.target))
    return work

def validate_child_source_v3(reader):
    pair=_CHILDREN.get(reader)
    if pair is None:return
    handoff,digest=pair
    from .habit_maintenance_followup_v3 import HabitMaintenanceFollowupPreparedV3,validate_habit_maintenance_child_source_v3
    if type(handoff)is HabitMaintenanceFollowupPreparedV3:
        return validate_habit_maintenance_child_source_v3(reader,handoff,digest)
    handoff.require_current(reader.graph,handoff.context,handoff.bundle)
    from .current_habit_source_read_v3 import require_habit_source_work_v3,_habit_now_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    state=require_habit_source_work_v3(reader)
    if(state.context is not handoff.context or state.selector!=handoff.selector or reader.request!=handoff.request
            or digest!=canonical_digest(handoff.target)or _habit_now_v3(reader)>=handoff.selector.original_deadline_utc):
        raise AuthorityUnavailable('Habit child changed its frozen producer/selector/original window')
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,handoff.locator.header[0])
    if original is None or original['original_digest']!=handoff.producer_digest or canonical_digest(original['receipt'])!=handoff.receipt_digest:
        raise AuthorityUnavailable('Habit child lost its actual producer original')
    if handoff.kind=='prepare_source_note_body':
        from .habit_body_cpu_source_v3 import host_body_basis_v3
        from .current_method_learning_read_v3 import method_graph_head_v3
        from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
        prep=handoff.selector.command.preparation
        atom=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(handoff.selector.occurrence_ref))
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
        _,basis=host_body_basis_v3(reader,occurrence=occurrence,occurrence_atom=atom,
            qualification_selector=handoff.selector.qualification_selector,qualification_ref=handoff.selector.qualification_original_ref,
            qualification_digest=handoff.selector.qualification_original_digest,selector=prep.selector)
        if basis!=prep.basis:raise AuthorityUnavailable('Habit fresh Body Source changed prepared actual policy/budget/CPU basis')

def transfer_child_binding_v3(old,new):
    pair=_CHILDREN.pop(old,None)
    if pair is not None:_CHILDREN[new]=pair

def bind_followup_frame_v3(frame,reader):
    pair=_CHILDREN.get(reader)
    if pair is not None:_FRAME_CHILDREN[id(frame)]=(frame,pair[0],reader)

def release_followup_frame_v3(frame):_FRAME_CHILDREN.pop(id(frame),None)

def append_followup_provenance_v3(frame,provenance):
    if provenance is not None and PROVENANCE in provenance:raise AuthorityUnavailable('Habit target provenance is reserved')
    pair=_FRAME_CHILDREN.get(id(frame))
    from .habit_maintenance_followup_v3 import HabitMaintenanceFollowupPreparedV3
    from .habit_maintenance_followup_v3 import append_habit_maintenance_followup_target_v3
    if pair is not None and type(pair[1])is HabitMaintenanceFollowupPreparedV3:
        return append_habit_maintenance_followup_target_v3(provenance,pair)
    append_habit_maintenance_followup_target_v3(provenance,None)
    return provenance if pair is None else {**(provenance or {}),PROVENANCE:pair[1].target}

def habit_stage_events_v3(frame,domain,kind,events):
    from .habit_activity_runtime_v1 import _HABIT_FRAMES_V1
    if domain=='d02'and kind=='prepare_source_note_body'and id(frame)in _HABIT_FRAMES_V1:
        return (*events,('d10','habit_source_note_body_requires_original_plan_v3'))
    return events

def _require_actual_followup_w01_phase_v3(witness,reader):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .current_habit_source_read_v3 import _WRITES,_WRITE_PENDING
    phase=_WRITES.get(reader)
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or phase is None or _WRITE_PENDING.get(reader)is not phase or not phase.active
            or phase.prepared.owner is not reader or not reader.read_finished or not reader.business_started
            or witness.graph is not reader.graph or witness.scope is not phase.scope
            or witness.runtime is not reader.runtime or witness.guard!=phase.evidence.owner_guard):
        raise AuthorityUnavailable("Habit post-CAS disposition lost its actual validated W01 Scope/Source phase")
    return phase


def record_habit_followup_before_witness_release_v3(witness,db,*,frame,stage,receipt):
    if id(frame)not in _FRAME_CHILDREN:return
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1
    original=record_adopted_domain_operation_v1(db,stage,receipt)
    return record_habit_followup_disposition_after_cas_v3(witness,db,frame=frame,stage=stage,receipt=receipt,original=original)


def record_habit_followup_disposition_after_cas_v3(witness,db,*,frame,stage,receipt,original):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    pair=_FRAME_CHILDREN.get(id(frame))
    if pair is None:return
    from .habit_maintenance_followup_v3 import HabitMaintenanceFollowupPreparedV3,record_habit_maintenance_followup_after_cas_v3
    if type(pair[1])is HabitMaintenanceFollowupPreparedV3:
        return record_habit_maintenance_followup_after_cas_v3(witness,db,frame=frame,stage=stage,receipt=receipt,original=original,pair=pair)
    actual,handoff,reader=pair
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    phase=_require_actual_followup_w01_phase_v3(witness,reader)
    evidence=require_habit_activity_issuance_v1(phase.issued,reader.graph,phase.scope)
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or witness.frame is not actual or frame is not actual or witness.graph is not reader.graph
            or witness.runtime is not reader.runtime or witness.scope is not phase.scope
            or witness.request!=handoff.request or witness.operation.operation_kind!=handoff.kind
            or receipt.status!='committed'or receipt.operation_id!=handoff.selector.operation_id
            or receipt.operation_digest!=witness.bundle.digest or evidence.request!=handoff.selector
            or not db.in_transaction or db is not reader.db or stage.original_digest!=original.original_digest):
        raise AuthorityUnavailable('Habit disposition requires actual current Core and same-CAS W01 witness')
    import json
    if json.loads(stage.original_payload_json)['provenance'].get(PROVENANCE)!=handoff.target:
        raise AuthorityUnavailable('Habit child original does not seal its frozen next selector')
    header=handoff.locator.header
    value={'schema':'d10.habit-followup-disposition.v3','state':'completed','target':handoff.target,
        'consumer_operation_id':receipt.operation_id,'receipt_digest':canonical_digest(receipt),
        'original_ref':original.original_ref,'original_digest':original.original_digest}
    cursor=db.execute('UPDATE graph_domain_production_outbox_v1 SET state=?,consumer_operation_id=?,receipt_json=? '
        'WHERE bot=? AND persona=? AND dedupe_key=? AND causal_operation_id=? AND receiver_domain=? AND event_kind=? '
        'AND original_ref=? AND original_digest=? AND state=? AND consumer_operation_id IS ?',
        ('completed',receipt.operation_id,canonical_serialize(value),*reader.namespace.as_tuple,handoff.locator.key,*header))
    if cursor.rowcount!=1:raise AuthorityUnavailable('Habit event changed before exact same-CAS disposition')
    return value


_TARGET_FIELDS=frozenset({'schema','dedupe_key','producer_operation_id','producer_original_digest',
    'producer_receipt_digest','event_kind','selector','selector_digest','operation_id','operation_kind',
    'request','request_digest','parent_root_grant_ref','original_deadline_utc'})

def validate_followup_target_v3(domain,kind,raw):
    from .habit_activity_history_v1 import habit_activity_selector_from_wire_v1,_root_selector_v1,HABIT_ACTIVITY_KINDS_V1
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if(type(raw)is not dict or set(raw)!=_TARGET_FIELDS or raw['schema']!='d10.habit-followup-target.v3'
            or raw['event_kind']not in _EVENTS or _EVENTS[raw['event_kind']][3]!=kind
            or HABIT_ACTIVITY_KINDS_V1.get(kind)!=domain):
        raise ValueError('Habit followup target has another fixed producer/phase/schema')
    selector=habit_activity_selector_from_wire_v1(raw['selector']);root=_root_selector_v1(selector)
    request=decode_typed_production_value_v1(raw['request'],installed_operation_v1(kind).request_type)
    if(raw['selector']!=plain_v1(selector)or raw['selector_digest']!=canonical_digest(selector)
            or selector.request_digest!=_typed(kind,request)or raw['request']!=plain_v1(request)
            or raw['request_digest']!=canonical_digest(request)or raw['operation_kind']!=kind
            or raw['operation_id']!=selector.operation_id or raw['parent_root_grant_ref']!=root.parent_root_grant_ref
            or raw['original_deadline_utc']!=selector.original_deadline_utc
            or raw['dedupe_key']!=canonical_digest((selector.namespace,raw['producer_operation_id'],
                _EVENTS[raw['event_kind']][2],raw['event_kind']))):
        raise ValueError('Habit followup target changed its exact full selector/command/original Root')
    for name in ('producer_original_digest','producer_receipt_digest'):
        if type(raw[name])is not str or len(raw[name])!=64 or any(c not in '0123456789abcdef'for c in raw[name]):
            raise ValueError('Habit followup producer commitments require exact canonical digests')
    return selector


_BODY_PENDING=WeakKeyDictionary()

class _BodyPreparationPendingV3:
    def __init__(self,issuer,reader,locator,selector,basis,producer):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Habit CPU preparation requires its actual private Source resolver')
        self.reader,self.locator,self.selector,self.basis,self.producer=reader,locator,selector,basis,producer
        _BODY_PENDING[self]=(reader,locator,selector,canonical_digest(basis))

def complete_read_result_v3(reader):
    from .current_habit_source_read_v3 import _HabitReadResultV3,_HABIT_READ_RESULTS
    result=reader.result
    if type(result)is not _HabitReadResultV3:return
    value=result.value
    if type(value)is not _BodyPreparationPendingV3:return
    if(_BODY_PENDING.get(value)!=(reader,value.locator,value.selector,canonical_digest(value.basis))
            or reader.db.in_transaction or not reader.complete or reader.read_finished):
        raise AuthorityUnavailable('Habit CPU paired preparation lost its actual Source EOF/READ')
    port=reader.graph._GraphCoordinator__habit_occurrence_port_v1
    prepared,permit=port.prepare_habit_body_cpu_for_fence_v3(scope=reader.fence.scope,request=value.selector)
    port.require_issued_body_preparation_v3(scope=reader.fence.scope,request=value.selector,evidence=prepared)
    if permit!=reader.fence.scope.permit or prepared.basis!=value.basis:
        raise AuthorityUnavailable('Host and Core independently observed different actual Body CPU bases')
    from ..authority_service.d10_habit_execution_contract_v1 import HabitSourceNoteBodyCommandV1,HabitOccurrenceExecutionSelectorV1
    from .d02_life_body_preparation_v1 import PrepareSourceNoteBodyRequestV1
    command=HabitSourceNoteBodyCommandV1(value.selector.action_intent_ref,value.selector.body_policy_id,
        value.selector.body_policy_version,value.selector.effect_policy_ref,prepared.cpu_ceiling_ms,prepared)
    request=PrepareSourceNoteBodyRequestV1(command.action_intent_ref,command.body_policy_id,command.body_policy_version,
        command.effect_policy_ref,command.cpu_ceiling_ms)
    selected=HabitOccurrenceExecutionSelectorV1(reader.namespace,value.selector.qualification_selector,
        value.selector.qualification_original_ref,value.selector.qualification_original_digest,value.selector.occurrence_ref,
        value.selector.expected_occurrence_revision,'prepare_source_note_body',value.selector.operation_id,
        _typed('prepare_source_note_body',request),command)
    producer=value.producer
    handoff=HabitFollowupPreparedV3(_ISSUER,reader,value.locator,selected,'prepare_source_note_body',request,producer)
    result.value=handoff;_HABIT_READ_RESULTS[result]=(reader,reader.work,reader.operation,reader.selection_digest,handoff)
    _BODY_PENDING.pop(value,None)

def require_body_w01_basis_v3(runtime,db,*,frame,selector,request,stage,provenance):
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    if type(selector)is not HabitOccurrenceExecutionSelectorV1 or selector.operation_kind!='prepare_source_note_body':return
    from .current_habit_source_read_v3 import _active,require_habit_write_phase_v3
    from .current_method_learning_read_v3 import method_graph_head_v3
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from .habit_body_cpu_source_v3 import host_body_basis_v3,require_current_body_basis_rows_v3
    reader=_active(db);pending=require_habit_write_phase_v3(reader)
    if pending.graph is not runtime.graph or pending.scope is not frame_scope_v3(frame):
        raise AuthorityUnavailable('Habit Body W01 lost actual private fresh WRITE phase')
    prep=selector.command.preparation
    atom=method_graph_head_v3(db,selector.namespace,AtomKey.from_token(selector.occurrence_ref))
    occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
    selected,basis=host_body_basis_v3(reader,occurrence=occurrence,occurrence_atom=atom,
        qualification_selector=selector.qualification_selector,qualification_ref=selector.qualification_original_ref,
        qualification_digest=selector.qualification_original_digest,selector=prep.selector)
    if basis!=prep.basis or request.cpu_ceiling_ms!=prep.cpu_ceiling_ms:
        raise AuthorityUnavailable('Habit Body W01 changed its fixed actual CPU preparation')
    require_current_body_basis_rows_v3(reader,prep)
    from ..authority_service.habit_body_preparation_v3 import BODY_PREPARATION_PROVENANCE_V3,preparation_domain_plain_v3
    if provenance.get(BODY_PREPARATION_PROVENANCE_V3)!=preparation_domain_plain_v3(prep):
        raise AuthorityUnavailable('Habit Body W01 original lacks its complete actual preparation basis')
    from .d02_life_body_preparation_v1 import LifeBodyPreparationStageV1
    if(type(stage)is not LifeBodyPreparationStageV1 or stage.quote.ceiling!={'cpu_ms':prep.cpu_ceiling_ms}
            or stage.quote.valid_until_utc>prep.valid_until_utc):
        raise AuthorityUnavailable('Habit actual Body quote differs from the prepared single-attempt CPU/window')

def frame_scope_v3(frame):
    from .habit_activity_runtime_v1 import _HABIT_FRAMES_V1
    record=_HABIT_FRAMES_V1.get(id(frame))
    if record is None or record[0]is not frame:raise AuthorityUnavailable('Habit Body frame has no actual current issuance')
    return record[3]

def append_body_preparation_provenance_v3(frame,domain,kind,provenance):
    from ..authority_service.habit_body_preparation_v3 import BODY_PREPARATION_PROVENANCE_V3,preparation_domain_plain_v3
    if provenance is not None and BODY_PREPARATION_PROVENANCE_V3 in provenance:
        raise AuthorityUnavailable('Habit Body preparation provenance is reserved for its actual current private frame')
    from .habit_activity_runtime_v1 import _HABIT_FRAMES_V1
    record=_HABIT_FRAMES_V1.get(id(frame))
    if record is None or record[0]is not frame or kind!='prepare_source_note_body' or domain!='d02':return provenance
    issued=record[2]
    if issued.operation.operation_kind!=kind:return provenance
    return {**(provenance or {}),BODY_PREPARATION_PROVENANCE_V3:preparation_domain_plain_v3(issued.evidence.request.command.preparation)}


def release_followup_reader_v3(reader):
    _CHILDREN.pop(reader,None)
    if reader.operation_kind==READ_KIND and reader.complete and reader.read_finished:
        locator=_SELECTORS.pop(reader.request,None)
        if locator is not None:_LOCATORS.pop(locator,None)
        port=reader.graph._GraphCoordinator__habit_occurrence_port_v1
        if port is not None:port.release_scope_v3(reader.fence.scope)


def validate_body_preparation_provenance_v3(domain,kind,provenance):
    from ..authority_service.habit_body_preparation_v3 import BODY_PREPARATION_PROVENANCE_V3,preparation_from_domain_plain_v3,preparation_domain_plain_v3
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1,validate_habit_activity_provenance_v1
    if type(provenance)is not dict or BODY_PREPARATION_PROVENANCE_V3 not in provenance:return None
    if(domain,kind)!=('d02','prepare_source_note_body')or HABIT_ACTIVITY_PROVENANCE_V1 not in provenance:
        raise ValueError('Habit Body CPU preparation is reserved for its exact actual ordinary Body phase')
    prep=preparation_from_domain_plain_v3(provenance[BODY_PREPARATION_PROVENANCE_V3])
    selected,refs=validate_habit_activity_provenance_v1(domain,kind,provenance[HABIT_ACTIVITY_PROVENANCE_V1])
    if selected.command.preparation!=prep or preparation_domain_plain_v3(prep)!=provenance[BODY_PREPARATION_PROVENANCE_V3]:
        raise ValueError('Habit Body signed preparation changed its full current phase selector')
    b=prep.basis;p=prep.selector
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d02.body_quote_original import FixedBodyPolicyV1
    from .d02_production_operations_v1 import SettledBodyEffectPolicyV1
    from .budget import BudgetLease
    body=decode_typed_production_value_v1(b['body_policy'],FixedBodyPolicyV1)
    effect=decode_typed_production_value_v1(b['effect_policy'],SettledBodyEffectPolicyV1)
    parent=BudgetLease(**b['parent_lease'])
    if(body.policy_id,body.version,effect.policy_ref,parent.lease_id)!=(p.body_policy_id,p.body_policy_version,p.effect_policy_ref,p.qualification_selector.parent_root_grant_ref):
        raise ValueError('Habit Body preparation changed actual policy/component/original parent identities')
    versions=(*b['source_versions'],*b['body_heads'],b['occurrence_head'],b['action_head'])
    tracked=tuple(AtomKey.from_token(v['key']).token for v in versions)
    if b['occurrence_head']['key']!=p.occurrence_ref or b['occurrence_head']['revision']!=p.expected_occurrence_revision or b['action_head']['key']!=p.action_intent_ref:
        raise ValueError('Habit Body preparation changed exact original occurrence/Action head')
    if any(NamespaceId.from_key(AtomKey.from_token(ref))!=p.namespace for ref in tracked):raise ValueError('Habit Body CPU provenance crossed namespace')
    business={name:value for name,value in provenance.items()if name!=BODY_PREPARATION_PROVENANCE_V3}
    return business,tuple(sorted(set((*refs,*tracked))))

@dataclass(frozen=True,slots=True)
class _ExecutionProducerLocatorV3:
    namespace:NamespaceId
    qualification_selector:object
    qualification_original_ref:str
    qualification_original_digest:str
    occurrence_ref:str
    expected_occurrence_revision:int
    operation_kind:str
    operation_id:str
    request_digest:str
    schema:str

def _selector_metadata_projection_v3(selector):
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    raw=plain_v1(selector)
    if type(selector)is HabitOccurrenceExecutionSelectorV1:raw={name:value for name,value in raw.items()if name!='command'}
    return raw

def _metadata_producer_selector_v3(domain,kind,raw):
    from .habit_activity_history_v1 import validate_habit_activity_provenance_v1
    value=raw['selector']
    if value['schema']!='d10.habit-occurrence-execution-selector.v1':
        return validate_habit_activity_provenance_v1(domain,kind,raw)[0]
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from ..authority_service.d10_habit_execution_contract_v1 import HABIT_SOURCE_NOTE_EXECUTION_KINDS_V1
    from .habit_activity_history_v1 import HABIT_ACTIVITY_KINDS_V1
    if(set(value)!={f.name for f in fields(_ExecutionProducerLocatorV3)}
            or kind not in HABIT_SOURCE_NOTE_EXECUTION_KINDS_V1 or HABIT_ACTIVITY_KINDS_V1[kind]!=domain
            or value['operation_kind']!=kind or value['operation_id']!=raw['permit_operation_id']):
        raise AuthorityUnavailable('Habit metadata execution descriptor changed its exact original phase fields')
    q=habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',value['qualification_selector'])
    if(q.standing_authorization_original_ref,q.standing_authorization_original_digest)!=(raw['standing_original_ref'],raw['standing_original_digest']):
        raise AuthorityUnavailable('Habit metadata execution descriptor changed original standing authority')
    return _ExecutionProducerLocatorV3(**{**value,'namespace':NamespaceId(**value['namespace']),'qualification_selector':q})
