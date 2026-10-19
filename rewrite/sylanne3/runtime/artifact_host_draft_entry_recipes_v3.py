"""Legacy draft metadata and finite no-search READ recipes.

This module describes commands. W01, model dispatch and native effects remain
with their existing independently authorized callers.
"""
from ..authority_service.contract import AuthorityUnavailable
from dataclasses import asdict
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_types import Owner
from ..graph_coordinator import UnavailableGuard
from ..graph_types import AtomKey
from .domain_background_read_v3 import background_json_loads_v3,background_json_digest_v3
from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3,ArtifactControlValueV3,ArtifactControlNextV3

_ENTRY_KINDS_V3=frozenset({'run_current_post_c02_task_no_search_v1','run_current_post_c02_artifact_draft_operation_v1'})
_METADATA_ENTRIES_V3=frozenset({'run_current_post_c02_task_no_search_v1',
    'run_current_post_c02_artifact_draft_operation_v1','read_current_post_c02_artifact_draft_resume_v1'})

def artifact_draft_metadata_paths_v3(profile,path):
    if not path:return True
    if profile=='frozen':
        if path[0]=='sources':return len(path)<=2 or len(path)==3 and path[2]in {'ref','revision','value_digest'}
        return path[0]in {'schema','selector','task_source_ref','current_self_ref','current_self_digest',
            'root_registration_digest','target','source_read_versions','source_query_epoch','access_epoch','delete_epoch','deadline_utc'}
    if profile=='project':return path[0]in {'topic'}
    if profile=='graph_locator':
        return path[0]in {'schema','revision','state','topic','source_refs','reason_refs','satisfaction_predicate',
            'goal_ref','goal_revision','plan_ref','plan_revision','project_ref','recipe_ref','work_version_refs',
            'artifact_ref','source_versions','last_fact_versions','actor_ref','completed_node_refs','progress_refs','identity','social_role','norm_refs'}
    if profile=='continuation_producer':
        if path[0]in {'schema','namespace','identity'}:return True
        if path[0]=='request':return len(path)==1 or path[1]in {'selector','task','project_ref','goal_ref','plan_ref','recipe_ref',
            'predecessor_result_ref','correction_head_ref','c02_operation_id','source_ref','root_registration_ref'}
        if path[0]!='provenance':return False
        if len(path)==1:return True
        if path[1]in {'artifact_goal_ref','artifact_plan_ref','artifact_recipe_ref','artifact_content_adoption','content_adoption'}:return True
        return path[1]=='basis'and(len(path)==2 or path[2]in {'goal_ref','plan_ref','project_ref','recipe_ref','checkpoint_ref',
            'current_versions','last_valid_versions','goal','plan','checkpoint','predecessor_result_ref','predecessor_target','correction_head_ref'})
    if profile=='life_locator':
        if 'intent'in path:return len(path)==1 or path[-1]in {'kind','filename'}
        if 'observation'in path:return path[-1]=='observation'or path[-1]=='status'
        return not any(part in {'requirements_json','value_json','body_contract_json','record','draft_text','request_json','result_json','worker_read_json'}for part in path)
    if profile=='status':
        if path[0]=='request_json':return False
        if path[0]=='observation':return len(path)==1 or path[1]=='status'
        return True
    raise AuthorityUnavailable('Unregistered fixed legacy draft metadata profile')

class _LegacySignedV3:
    def __init__(self,state,kind,ref,profile):
        from .artifact_host_control_metadata_v3 import _SignedControlV3
        self.state,self.kind,self.ref=state,kind,ref
        self.task=_SignedControlV3(state,kind,ref,profile);self.complete=False;self.absent=False
        self.header=self.value=None
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE
        r=self.state.reader
        if self.task.header is None:
            row=meter.read_fixed_row(r.db,TABLE,('payload_digest',),
                'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,self.kind,self.ref))
            if row is None:self.absent=self.complete=True;return True
        if not self.task.advance(meter):return False
        self.header,self.value=self.task.header,self.task.value
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.header[0]))
        if bundle is None or type(bundle[0])is not int or bundle[0]<1:
            raise AuthorityUnavailable('Legacy draft signed metadata lacks its actual positive W01 producer')
        self.complete=True;return True
    def close_v3(self):
        column=self.task.column
        if column is not None:column.release_retention_v3()
        self.task=self.state=self.value=None

class ArtifactDraftEntryMetadataV3:
    def __init__(self,state):
        from .artifact_host_control_metadata_v3 import require_artifact_control_owner_identity_v3
        if require_artifact_control_owner_identity_v3(state.reader)is not state:
            raise AuthorityUnavailable('Legacy draft metadata requires its actual same-Work Owner entry')
        self.state=state;self.stage='scopes';self.scopes=[];self.scope_index=0;self.pending=None
        self.task=self.prepared=self.frozen=None;self.statuses={};self.status_index=0
        self.roots=list(state.current_roots);self.originals=[];self.producer=None;self.continuation=None;self.complete=False;self.closed=False
        q=state.selector;registry=state.root_registrations
        self.scope_candidates=[]
        if registry is not None:
            from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
            for root,raw,header,original,producer_header,reads,receipt in registry.scope_matches:
                scope=original.get('provenance',{}).get('artifact_task_scope')
                if(scope is not None and scope.get('c02_operation_id')==q.c02_operation_id
                        and scope.get('source_ref')==q.source_ref):
                    self.scope_candidates.append((task_scope_ref_v1(root.registration_ref),scope))
                    self.roots.extend(v.key.token for v in reads if v.key.type_name=='memory.source')
        if state.seed.root is not None:
            from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
            self.task=artifact_draft_task_selector_v1(q.namespace,c02_operation_id=q.c02_operation_id,
                root_registration_ref=state.seed.root.registration_ref)
        state.reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.scopes,self.roots,self.originals,self.statuses,self.scope_candidates))*3+8192
    def _publish(self,item):
        if item.absent:return
        self.originals.append((item.kind,item.ref,item.header,item.value))
        raw=item.value
        for name in ('source_ref','task_source_ref'):
            if type(raw.get(name))is str:self.roots.append(raw[name])
        if item.kind=='c4_frozen':self.roots.extend(row['ref']for row in raw['sources'])
        if item.kind=='c4_adopted':
            self.roots.extend(raw['content']['source_refs']);self.roots.append(raw['task_source']['ref'])
    def advance(self,meter):
        if self.closed:raise AuthorityUnavailable('Legacy draft metadata lifetime ended')
        s=self.state;r=s.reader;s.require_current_v3(meter)
        if self.complete:return True
        if self.stage=='scopes':
            if self.scope_index==len(self.scope_candidates):
                if self.task is None:self._finish();return True
                from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
                self.ids=artifact_draft_model_ids_v1(self.task)
                self.pending=_LegacySignedV3(s,'c4_prepared',self.ids['job'],'control_small');self.stage='prepared';return False
            if self.pending is None:
                self.pending=_LegacySignedV3(s,'artifact_task_scope',self.scope_candidates[self.scope_index][0],'control_small')
                return False
            if not self.pending.advance(meter):return False
            if self.pending.absent or self.pending.value!=self.scope_candidates[self.scope_index][1]:
                raise AuthorityUnavailable('Legacy no-search Scope lost actual signed Root producer metadata')
            self.scopes.append((self.pending.ref,self.pending.value));self._publish(self.pending)
            self.pending.close_v3();self.pending=None;self.scope_index+=1;return False
        if self.stage=='prepared':
            if not self.pending.advance(meter):return False
            if self.pending.absent:
                self.pending.close_v3();self.pending=None;self.stage='status';return False
            from .d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV1,artifact_draft_model_from_wire_v1
            p=artifact_draft_model_from_wire_v1(self.pending.value,ArtifactDraftModelPreparedV1)
            policy=r.bundle.installation_policy
            if(p.selector!=self.task or p.operation_id!=self.pending.header[0]
                    or(p.installation_id,p.manifest_digest)!=(policy.installation_id,policy.manifest_digest)
                    or p.parent_budget_lease_ref!=s.seed.budget.lease or p.actor_ref!=r.current_self.self_entity_ref
                    or p.owner_guard!=s.seed.expected_owner_guard):
                raise AuthorityUnavailable('Legacy draft prepared metadata changed actual Task/Root/Owner/Self/install')
            from .artifact_host_control_metadata_v3 import _utc_v3,_ControlProducerV3
            if r.now>=_utc_v3(p.deadline_utc):raise AuthorityUnavailable('Legacy draft original preparation deadline expired')
            self.prepared=p;self._publish(self.pending)
            self.producer=_ControlProducerV3(s,p.operation_id,'d11',('prepare_artifact_draft_model',))
            self.stage='producer';return False
        if self.stage=='producer':
            if not self.producer.advance(meter):return False
            if self.producer.original.get('provenance',{}).get('original_prepared')!=self.pending.value:
                raise AuthorityUnavailable('Legacy draft prepared metadata lost actual W01 provenance')
            self.roots.extend(v.key.token for v in self.producer.read_versions if v.key.type_name=='memory.source')
            self.pending.close_v3()
            self.pending=_LegacySignedV3(s,'c4_frozen',self.prepared.frozen_ref,('control_legacy_draft','frozen'))
            self.stage='frozen';return False
        if self.stage=='frozen':
            if not self.pending.advance(meter):return False
            raw=self.pending.value;p=self.prepared
            from ..domains.d01.production_operations_v1 import plain_v1
            if(self.pending.absent or self.pending.header[1]!=p.frozen_digest
                    or self.pending.header[0]!=p.operation_id or raw['selector']!=plain_v1(self.task)
                    or raw['task_source_ref']!=s.selector.source_ref
                    or raw['root_registration_digest']!=canonical_digest(plain_v1(s.seed.root))
                    or raw['current_self_ref']!=r.current_self.self_entity_ref):
                raise AuthorityUnavailable('Legacy frozen target metadata lost signed prepared/Source/Root/Self binding')
            self.frozen=raw;self._publish(self.pending);self.pending.close_v3();self.pending=None;self.stage='status';return False
        if self.stage=='continuation':
            if not self.continuation.advance(meter):return False
            self._finish();return True
        specs=(('c4_request','request'),('c4_call','call'),('c4_paid','paid'),('c4_result','result'),('c4_adopted','adopt'))
        if self.status_index==len(specs):
            self._validate_statuses()
            if s.selector.entry_kind=='run_current_post_c02_artifact_draft_operation_v1':
                self.continuation=ArtifactContinuationMetadataV3(s,self.task);self.stage='continuation';return False
            self._finish();return True
        kind,slot=specs[self.status_index]
        if self.pending is None:
            self.pending=_LegacySignedV3(s,kind,self.ids[slot],('control_legacy_draft','status'));return False
        if not self.pending.advance(meter):return False
        if not self.pending.absent:self._publish(self.pending)
        self.statuses[kind]=None if self.pending.absent else(self.pending.header,self.pending.value)
        self.pending.close_v3();self.pending=None;self.status_index+=1;return False
    def _validate_statuses(self):
        p=self.prepared;rows={k:None if v is None else v[1]for k,v in self.statuses.items()}
        if p is None:
            if any(v is not None for v in rows.values()):
                raise AuthorityUnavailable('Legacy resume lost actual prepared metadata before sealed stages')
            return
        request,call,paid,result,adopted=(rows['c4_'+name]for name in ('request','call','paid','result','adopted'))
        if request is not None and request['prepared_digest']!=p.digest:
            raise AuthorityUnavailable('Legacy sealed request changed original prepared digest')
        if call is not None:
            from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
            from ..authority_service.v2_model_egress_wire import from_wire
            intent=from_wire(call,ModelEgressIntentV1)
            if(request is None or(intent.call_id,intent.job_id,intent.binding_digest,intent.request_digest)!=(
                    p.call_id,p.job_id,p.digest,request['request_digest'])):
                raise AuthorityUnavailable('Legacy sealed call changed actual request/job/prepared binding')
        if paid is not None:
            from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
            actual=decode_artifact_draft_original_v1('c4_paid',paid)
            if call is None or(actual.call_id,actual.quote_id,actual.quote_version)!=(p.call_id,p.quote_id,1):
                raise AuthorityUnavailable('Legacy paid Original changed its actual call/quote')
        if result is not None:
            from ..authority_service.d11_artifact_draft_model_v1 import(ArtifactDraftModelResultReadRequestV1,
                artifact_draft_model_result_from_wire_v1)
            q=artifact_draft_model_result_from_wire_v1(result['request'],ArtifactDraftModelResultReadRequestV1)
            if(paid is None or q.selector!=p.selector or(q.job_id,q.call_id,q.binding_digest)!=(p.job_id,p.call_id,p.digest)
                    or result['observation']['status']!='completed'
                    or paid['terminal_receipt_digest']!=canonical_digest(result['terminal_receipt'])):
                raise AuthorityUnavailable('Legacy result metadata lost actual paid terminal/request/observation status')
        if adopted is not None:
            from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1,artifact_draft_content_from_wire_v1
            a=artifact_draft_content_from_wire_v1(adopted,ArtifactDraftContentAdoptionV1)
            if(result is None or a.selector!=p.selector or a.prepared_digest!=p.digest
                    or(a.paid_original_ref,a.paid_original_digest)!=(self.ids['paid'],self.statuses['c4_paid'][0][1])
                    or(a.result_original_ref,a.result_original_digest)!=(self.ids['result'],self.statuses['c4_result'][0][1])):
                raise AuthorityUnavailable('Legacy adoption metadata lost actual same-task paid/result commitments')
    def _finish(self):
        s=self.state
        roots=tuple(dict.fromkeys(self.roots))
        for ref in roots:
            key=AtomKey.from_token(ref)
            from ..runtime_contracts import NamespaceId
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=s.reader.namespace:
                raise AuthorityUnavailable('Legacy draft metadata declares a foreign Source')
        s.current_roots=roots;s.semantic_locators.roots=list(roots)
        s.group_specs=[('control:'+str(i//32),roots[i:i+32],s.purpose,s.audiences)for i in range(0,len(roots),32)]
        for kind,ref,header,raw in self.originals:
            s.verified_metadata_v3['graph_d11_life_originals_v1',kind,ref]={
                'projection':raw,'header':header,'payload_digest':header[1],'operation_id':header[0],
                'source_roots':roots,'selector':self.task,'producer_header':None}
        if self.continuation is not None:
            for operation,(layout,header,raw,receipt)in self.continuation.producers.items():
                s.verified_metadata_v3[layout[0],header[1],operation]={
                    'projection':raw,'header':header,'payload_digest':header[3],'operation_id':operation,
                    'source_roots':roots,'selector':None,'producer_header':header,'read_versions':receipt.read_versions,
                    'write_versions':receipt.write_versions,'physical_layout':layout}
        self.complete=True;s.reader.operation.refresh_retained_state_v3(self)
    def close_v3(self):
        if self.closed:return
        self.closed=True
        if self.pending is not None:self.pending.close_v3()
        if self.continuation is not None:self.continuation.close_v3()
        self.continuation=None
        if self.producer is not None:
            for column in self.producer.columns:column.release_retention_v3()
            self.producer.columns.clear()
        self.pending=self.producer=self.prepared=self.frozen=self.task=None
        self.scopes.clear();self.originals.clear();self.statuses.clear();self.roots.clear();self.scope_candidates.clear()
        self.state.reader.operation.unregister_retained_state_v3(self);self.state=None

def _metadata(reader,state):
    from .artifact_host_control_metadata_v3 import control_state_for_dispatch_v3
    value=state.draft_metadata
    if(control_state_for_dispatch_v3(reader)is not state or not state.source_complete
            or value is None or not value.complete or value.closed or value.state is not state):
        raise AuthorityUnavailable('Actual current Owner/Source-qualified legacy draft metadata required')
    return value

def _no_search_probe_v3(reader,state):
    import json
    from .d07_task_history_v1 import TaskNoSearchProbeV1,AdoptCurrentTaskNoSearchRequestV1
    from ..model_broker.first_ingress_encoding import FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    q=state.selector;m=_metadata(reader,state)
    row=state.control_point_v3('graph_first_ingress_c02_committed_seals_v2',('evidence_json',),
        ('bot','persona','operation_id'),(*reader.namespace.as_tuple,q.c02_operation_id))
    if row is None:raise AuthorityUnavailable('actual_committed_C02_metadata_before_history_probe')
    evidence=background_json_loads_v3(row[0]);nested=evidence.get('c1_task_result_v1')
    if nested is None or nested.get('template_version')!=FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION:
        return TaskNoSearchProbeV1('not_applicable','older_C1_template',None)
    from .c1_artifact_task_intent_v1 import validate_c1_task_result_evidence_v1
    actual=validate_c1_task_result_evidence_v1(evidence)
    output=actual.observation.result
    raw=json.loads(output['text'])
    if type(raw)is not dict:raise ValueError('actual_C1_v4_historical_candidate_output_not_object')
    candidate=raw.get('historical_dependency_candidate')
    if candidate is None:return TaskNoSearchProbeV1('not_applicable','no_historical_dependency_candidate',None)
    if type(candidate)is not dict:raise ValueError('actual C1 v4 candidate metadata has an invalid type')
    if not m.scopes:return TaskNoSearchProbeV1('not_applicable','no_actual_task_scope',None)
    if len(m.scopes)!=1:raise ValueError('task history probe has ambiguous actual scope metadata')
    scope_ref,scope=m.scopes[0]
    if scope['task_kind']!='draft_then_corrected_revision'or scope['objective_ref']is None:
        return TaskNoSearchProbeV1('not_applicable','not_an_initial_Goal_task',None)
    from .d11_life_preparation_v1 import _read
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1,_c02_task_material_v1
    c1=_read(reader.db,issuer=reader.graph._GraphCoordinator__d11_issuer,namespace=reader.namespace,
        kind='c1_task_intent',ref=c1_task_intent_ref_v1(reader.namespace,q.c02_operation_id))
    if c1 is None:raise AuthorityUnavailable('actual_signed_C1_original_before_no_search')
    material=_c02_task_material_v1(reader.db,reader.namespace,q.c02_operation_id)
    if material is None or material[3].token!=q.source_ref:raise AuthorityUnavailable('actual_same_C02_Source_C1_before_no_search')
    saved=_read(reader.db,issuer=reader.graph._GraphCoordinator__d11_issuer,namespace=reader.namespace,
        kind='artifact_task_objective',ref=scope['objective_ref'])
    if saved is None or canonical_digest(saved[0])!=scope['objective_digest']:
        raise AuthorityUnavailable('actual_task_objective_metadata')
    goal=saved[0]['goal_ref']
    head=state.control_point_v3('graph_atoms',('revision','valid'),('token','bot','persona'),(goal,*reader.namespace.as_tuple))
    if head is None:return TaskNoSearchProbeV1('not_applicable','no_actual_task_Goal',None)
    if head[1]!=1:raise AuthorityUnavailable('current_valid_task_Goal_metadata')
    return TaskNoSearchProbeV1('candidate',None,AdoptCurrentTaskNoSearchRequestV1(q.c02_operation_id,q.source_ref,scope_ref,goal,head[0]))

def artifact_host_draft_entry_recipe_v3(reader,state):
    if state.selector.entry_kind=='run_current_post_c02_artifact_draft_operation_v1':
        return _legacy_draft_entry_v3(reader,state)
    if state.selector.entry_kind!='run_current_post_c02_task_no_search_v1'or state.selector.stage!='start':
        raise ValueError('Unregistered finite draft entry/stage')
    from ..domains.d01.production_operations_v1 import plain_v1
    from .d07_task_history_v1 import OPERATION
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:probe=_no_search_probe_v3(reader,state)
        finally:reader.db.rollback()
    if probe.status=='not_applicable':return ArtifactControlValueV3(plain_v1(probe))
    return ArtifactControlCommandV3(OPERATION,probe.request,after='no_search')

def artifact_host_draft_post_recipe_v3(reader,state,result,original,complete):
    if state.selector.stage in {'draft_select','draft_prepare','draft_role'}:
        return _legacy_draft_post_v3(reader,state,result,original,complete)
    if state.selector.stage!='no_search':raise ValueError('Unregistered finite draft receipt stage')
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d07_task_history_v1 import OPERATION,CurrentTaskNoSearchDecisionV1,CurrentTaskNoSearchOriginalV1
    if original['operation_kind']!=OPERATION:raise AuthorityUnavailable('No-search receipt names another actual operation')
    payload=original['payload']
    if payload['coverage']!='complete':
        return ArtifactControlValueV3({'status':'held','receipt':result,'missing_inputs':payload['missing_inputs']})
    p=payload['provenance']
    if 'task_no_search_decision'in p:
        decision=decode_typed_production_value_v1(p['task_no_search_decision'],CurrentTaskNoSearchDecisionV1)
        return ArtifactControlValueV3({'status':'not_applicable','decision':plain_v1(decision),'receipt':result})
    value=decode_typed_production_value_v1(p['task_no_search'],CurrentTaskNoSearchOriginalV1)
    if value.namespace!=reader.namespace or value.request.c02_operation_id!=state.selector.c02_operation_id:
        raise AuthorityUnavailable('No-search adopted Original changed its actual C02 namespace')
    return ArtifactControlValueV3({'status':'no_search','need':plain_v1(value.need),'receipt':result,
        'original_ref':'d07-current:'+original['original_digest'][:48],'original_digest':original['original_digest']})

def _read_artifact_draft_resume_v3(reader,state):
    m=_metadata(reader,state);q=state.selector
    if m.task is None:raise AuthorityUnavailable('actual signed draft responsibility is not configured for this cycle')
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .jobs import get_job
    cycle=get_job(reader.db,foreground_cycle_ids_v1(reader.namespace,q.c02_operation_id)[1])
    p=m.prepared;model=None if p is None else get_job(reader.db,p.job_id)
    dedupe=None if p is None else canonical_digest((reader.namespace,p.operation_id,'d11','artifact_draft_model_queued'))
    queued=None if dedupe is None else state.control_point_v3('graph_domain_production_outbox_v1',('state',),
        ('bot','persona','dedupe_key'),(*reader.namespace.as_tuple,dedupe))
    return {'schema':'d11.artifact-draft-resume.v1','c02_operation_id':q.c02_operation_id,'source_ref':q.source_ref,
        'root_registration_ref':m.task.root_registration_ref,'selector':m.task,'cycle_job_id':cycle.job_id,
        'cycle_phase':cycle.phase,'cycle_cancel_generation':cycle.cancel_epoch,'cycle_deadline_utc':cycle.deadline_utc,
        'model_job_id':m.ids['job'],'model_phase':None if model is None else model.phase,
        'model_lease_holder':None if model is None else model.lease_holder,
        'model_lease_expires_utc':None if model is None else model.lease_expires_utc,
        'model_cancel_generation':None if model is None else model.cancel_epoch,'prepared':p is not None,
        'target_mode':None if m.frozen is None else m.frozen['target']['mode'],
        **{name:m.statuses.get(kind)is not None for name,kind in
            (('request_sealed','c4_request'),('call_sealed','c4_call'),('paid','c4_paid'),('result','c4_result'),('adopted','c4_adopted'))},
        'queued_dedupe_key':dedupe,'queued_state':None if queued is None else queued[0]}

def read_artifact_draft_resume_v3(reader,state):
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:return _read_artifact_draft_resume_v3(reader,state)
        finally:reader.db.rollback()


class _ContinuationProducerV3:
    def __init__(self,state,operation):
        self.state,self.operation=state,operation;self.task=None
    def advance(self,meter):
        from .artifact_task_choice_catalogue_metadata_v3 import read_task_catalogue_producer_layout_v3
        from .artifact_host_control_metadata_v3 import _ControlProducerV3,_ControlColumnV3
        r=self.state.reader
        if self.task is None:
            table,column,cell,header=read_task_catalogue_producer_layout_v3(r,meter,self.operation)
            self.task=_ControlProducerV3(self.state,self.operation,header[0],(header[1],))
            self.task.advance(meter)
            self.task.columns[0].release_retention_v3()
            self.task.columns[0]=_ControlColumnV3(self.state,('control_legacy_draft','continuation_producer'),
                table=table,column=column,cell_id=cell,key_columns=('bot','persona','operation_id'),
                key=(*r.namespace.as_tuple,self.operation))
            return False
        return self.task.advance(meter)
    def close_v3(self):
        if self.task is not None:
            for column in self.task.columns:column.release_retention_v3()
            self.task.columns.clear()
        self.task=self.state=None

class ArtifactContinuationMetadataV3:
    """Complete bounded namespace project metadata, then exact declared edges."""
    def __init__(self,state,task):
        self.state,self.task=state,task;self.after='';self.through=None;self.watermark=False;self.count=0
        self.project=None;self.column=None;self.history_column=None;self.producer=None;self.header=self.history=None
        self.phase='census';self.candidates=[];self.graph_rows={};self.life_rows={};self.producers={}
        self.queue=[];self.seen=set();self.pending=None;self.pending_spec=None;self.roots=[];self.complete=False;self.closed=False
        root=state.seed.root
        if len(root.filenames)!=1:raise ValueError('one registered filename required')
        self.filename=root.filenames[0]
        from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
        self._enqueue('selected',artifact_continuation_operation_id_v1(task),'continuation_producer')
        self.amendment=None
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1,_decode
        from .artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_original_ref_v1,amendment_key_v1,KIND
        for record in state.root_registrations.scope_matches if state.root_registrations is not None else ():
            old_root,_,_,original,_,_,_=record
            scope_raw=original.get('provenance',{}).get('artifact_task_scope')
            if old_root.registration_ref==root.registration_ref and scope_raw is not None and scope_raw.get('task_kind')=='continue':
                scope=_decode(scope_raw,IngressArtifactTaskScopeOriginalV1)
                objective=_decode(original['provenance']['artifact_task_objective'],ArtifactTaskObjectiveV1)
                value=amendment_from_scope_v1(scope,objective)
                self.amendment=(value,amendment_original_ref_v1(value),amendment_key_v1(state.reader.namespace,root.registration_ref))
                self._enqueue(KIND,self.amendment[1],'life_locator')
                self._enqueue('graph',self.amendment[2].token,'graph_locator')
        from .d08_personal_plan_v1 import artifact_draft_action_keys_v1,artifact_goal_plan_keys_v1
        from .d03_life_project_context_v1 import life_project_context_keys_v1
        action=artifact_draft_action_keys_v1(state.reader.namespace,c02_operation_id=task.c02_operation_id,
            root_registration_ref=task.root_registration_ref)[0]
        self._enqueue('graph_optional',action.token,'graph_locator')
        controls=artifact_goal_plan_keys_v1(state.reader.namespace,c02_operation_id=task.c02_operation_id,root_registration_ref=task.root_registration_ref)
        for key in life_project_context_keys_v1(state.reader.namespace,controls[2].token):self._enqueue('graph_optional',key.token,'graph_locator')
        self._enqueue('optional:plan','artifact-draft-final-plan:'+task.digest[:40],'life_locator')
        self._enqueue('optional:prepared','artifact-draft-life-prepare:'+task.digest[:40],'life_locator')
        state.reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.candidates,self.graph_rows,self.life_rows,self.producers,self.queue,self.seen,self.roots))*3+8192
    def _enqueue(self,kind,ref,profile=None):
        key=(kind,ref)
        if key not in self.seen:self.seen.add(key);self.queue.append((kind,ref,profile))
    def _sources(self,raw):
        def visit(value):
            if type(value)is dict:
                for name,item in value.items():
                    if name in {'source_ref','task_source_ref'}and type(item)is str:self.roots.append(item)
                    elif name=='source_refs'and type(item)is list:self.roots.extend(item)
                    elif name=='reason_refs'and type(item)is list:
                        for ref in item:
                            if type(ref)is str and ref.startswith('[')and AtomKey.from_token(ref).type_name=='memory.source':self.roots.append(ref)
                    elif name in {'key','ref'}and type(item)is str and item.startswith('['):
                        key=AtomKey.from_token(item)
                        if key.type_name=='memory.source':self.roots.append(item)
                    elif type(item)in (dict,list):visit(item)
            elif type(value)is list:
                for item in value:
                    if type(item)in (dict,list):visit(item)
        visit(raw)
    def _edges(self,raw):
        self._sources(raw)
        for name in ('goal_ref','plan_ref','project_ref','recipe_ref','correction_head_ref'):
            ref=raw.get(name)
            if type(ref)is str:self._enqueue('graph',ref,'graph_locator')
        for ref in raw.get('work_version_refs',()):self._enqueue('graph',ref,'graph_locator')
        root_ref=raw.get('initial_root_registration_ref')
        if type(root_ref)is str:
            from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
            self._enqueue('draft_root_capability',root_ref,'life_locator')
            self._enqueue('artifact_task_scope',task_scope_ref_v1(root_ref),'life_locator')
        ref=raw.get('artifact_ref',raw.get('predecessor_result_ref'))
        if type(ref)is str:self._enqueue('adopted_life',ref,'life_locator')
        predicate=raw.get('satisfaction_predicate')
        if type(predicate)is dict:
            pairs=predicate.get('parameters',predicate.get('arguments',()))
            if type(pairs)is list:
                for key,value in pairs:
                    if key=='objective_ref':self._enqueue('artifact_task_objective',value,'control_small')
        terminal=raw.get('terminal')
        if type(terminal)is dict:
            binding=terminal.get('binding',{})
            if type(binding.get('prepared_original_ref'))is str:
                self._enqueue('prepared',binding['prepared_original_ref'],'life_locator')
        for name,kind in {'previous_milestone_ref':'artifact_task_milestone','previous_verified_original_ref':'c4_phase_verified',
                'prev_verified_original_ref':'c4_phase_verified','content_adoption_ref':'c4_phase_adopted',
                'extent_original_ref':'artifact_task_text_extent','task_basis_ref':'artifact_task_amendment_basis',
                'amendment_original_ref':'artifact_task_amendment','task_scope_ref':'artifact_task_scope',
                'objective_ref':'artifact_task_objective','c1_intent_ref':'c1_task_intent','approval_original_ref':'artifact_standing_predecision_approval'}.items():
            if type(raw.get(name))is str:self._enqueue(kind,raw[name],'life_locator')
        selector=raw.get('selector')
        if type(selector)is dict and selector.get('schema')=='d11.artifact-draft-phase-selector.v2':
            from ..model_broker.artifact_draft_v1 import(ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2,artifact_draft_model_ids_v2)
            phase=artifact_draft_from_wire_v2(selector,ArtifactDraftPhaseSelectorV2);ids=artifact_draft_model_ids_v2(phase)
            self._enqueue('c4_phase_prepared',ids['job'],'life_locator');self._enqueue('c4_phase_frozen',ids['frozen'],'life_locator')
        identity=raw.get('identity')
        if(type(identity)is dict and type(identity.get('operation_id'))is str and self.pending_spec is not None
                and self.pending_spec[0]in {'graph','graph_optional'}
                and AtomKey.from_token(self.pending_spec[1]).type_name=='d08.action_intent.v1'):
            self._enqueue('optional:draft_action','life-draft-root:'+identity['operation_id'],'life_locator')
        operation=raw.get('action_operation_id')
        if type(operation)is str:
            self._enqueue('optional:life_body_preparation','life-body:d02-life-body:'+operation,'life_locator')
        for row in raw.get('read_rows',()):
            ref=row.get('ref')
            if type(ref)is str:
                key=AtomKey.from_token(ref)
                if key.type_name=='memory.source':self.roots.append(ref)
                else:self._enqueue('graph',ref,'graph_locator')
    def advance(self,meter):
        if self.closed:raise AuthorityUnavailable('Continuation metadata lifetime ended')
        s=self.state;r=s.reader;s.require_current_v3(meter)
        if self.complete:return True
        from .artifact_host_control_metadata_v3 import _ControlColumnV3
        if self.phase=='census':
            if not self.watermark:
                row=meter.read_fixed_row(r.db,'graph_atoms',('token',),
                    "bot=? AND persona=? AND type_name='d10.life_project.v1' ORDER BY token DESC LIMIT 1",r.namespace.as_tuple)
                self.through=None if row is None else row[0];self.watermark=True
                if row is None:self.phase='edges'
                return False
            row=meter.read_fixed_row(r.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                "bot=? AND persona=? AND type_name='d10.life_project.v1' AND token>? AND token<=? ORDER BY token LIMIT 1",
                (*r.namespace.as_tuple,self.after,self.through))
            if row is None:self.phase='edges';return False
            self.after=row[0];self.count+=1
            if self.count>128:raise AuthorityUnavailable('complete_existing_artifact_project_inventory')
            self.project=row[0];self.header=tuple(row)
            self.column=_ControlColumnV3(s,('control_legacy_draft','project'),table='graph_atoms',column='value',
                key_columns=('token','bot','persona'),key=(row[0],*r.namespace.as_tuple),cell_id=row[3])
            self.phase='project';return False
        if self.phase=='project':
            if not self.column.advance(meter):return False
            raw=self.column.require_v3(r)
            if raw.get('topic')!=self.filename:
                self.column.release_retention_v3();self.column=None;self.phase='census';return False
            self.history=meter.read_fixed_row(r.db,'graph_history',('revision','event_id','value_cell_id'),
                'token=? AND valid=1 AND revision<=? ORDER BY revision DESC LIMIT 1',(self.project,self.header[1]))
            if self.history is None:raise AuthorityUnavailable('actual_existing_artifact_project_history')
            self.history_column=_ControlColumnV3(s,('control_legacy_draft','project'),table='graph_history',column='value',
                key_columns=('token','revision'),key=(self.project,self.history[0]),cell_id=self.history[2])
            self.phase='history';return False
        if self.phase=='history':
            if not self.history_column.advance(meter):return False
            if self.history_column.semanticlogical_digest_v3()!=self.column.semanticlogical_digest_v3():
                raise AuthorityUnavailable('actual_existing_artifact_project_history')
            self.producer=_ContinuationProducerV3(s,self.history[1]);self.phase='project_producer';return False
        if self.phase=='project_producer':
            if not self.producer.advance(meter):return False
            cp=self.producer.task;raw=cp.original.get('provenance',{})
            if(cp.domain,cp.header[1])==('d10','create_artifact_project'):
                content=raw['artifact_content_adoption'];refs=tuple(raw[name]for name in
                    ('artifact_goal_ref','artifact_plan_ref','artifact_recipe_ref'))
            elif(cp.domain,cp.header[1])==('d08','revise_existing_artifact_v1'):
                content=raw['content_adoption'];refs=tuple(raw['basis'][name]for name in('goal_ref','plan_ref','recipe_ref'))
            else:raise ValueError('existing artifact project has another producer')
            from ..domains.d01.production_operations_v1 import plain_v1
            target=content['target'];root=s.seed.root
            if(target['root_resource_id'],target['root_identity'],target['filename'])==(root.resource_id,plain_v1(root.root_identity),self.filename):
                self.candidates.append((self.project,self.header[1],self.history[0],self.history[1],*refs))
                self.graph_rows[self.project]=({'revision':self.header[1],'valid':self.header[2],'cell':self.header[3],
                    'producer':self.history[1]},self.column.require_v3(r),self.column.semanticlogical_digest_v3(),self.history)
                self._adopt_producer(cp);self._sources(content)
                for ref in refs:self._enqueue('graph',ref,'graph_locator')
                from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
                self._enqueue('graph',project_checkpoint_key_v1(r.namespace,self.project).token,'graph_locator')
            self.column.release_retention_v3();self.history_column.release_retention_v3();self.producer.close_v3()
            self.column=self.history_column=self.producer=None;self.phase='census';return False
        if self.phase=='selected_producer':
            if not self.producer.advance(meter):return False
            cp=self.producer.task;self._adopt_producer(cp);self._edges(cp.original['request'])
            self.producer.close_v3();self.producer=None;self.pending_spec=None;self.phase='edges';return False
        if self.phase=='edge_producer':
            if not self.producer.advance(meter):return False
            ref=self.pending_spec[1];version=self.pending_header[0]
            if not any(v.key.token==ref and v.revision==version for v in self.producer.task.receipt.write_versions):
                raise AuthorityUnavailable('Continuation control head lost actual same-W01 write membership')
            self._adopt_producer(self.producer.task);self.producer.close_v3();self.producer=None
            self.pending_spec=None;self.phase='edges';return False
        if not self.queue and self.pending is None:
            self._finish();return True
        if self.pending is None:
            kind,ref,profile=self.queue.pop(0);self.pending_spec=(kind,ref,profile)
            if kind=='selected':
                row=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',('operation_kind',),
                    'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,ref))
                if row is None:
                    from .domain_production_originals_v1 import PHYSICAL_TABLE
                    row=meter.read_fixed_row(r.db,PHYSICAL_TABLE,('operation_kind',),
                        'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,ref))
                    if row is None:self.pending_spec=None;return False
                if row!=('select_existing_artifact_continuation_v1',):
                    raise AuthorityUnavailable('Actual task selection locator names another producer')
                self.producer=_ContinuationProducerV3(s,ref);self.phase='selected_producer';return False
            if kind in {'graph','graph_optional'}:
                key=AtomKey.from_token(ref)
                from ..runtime_contracts import NamespaceId
                if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable('Continuation metadata Graph edge crossed namespace')
                if key.type_name=='memory.source':self.roots.append(ref);self.pending_spec=None;return False
                header=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'token=? AND bot=? AND persona=?',(ref,*r.namespace.as_tuple))
                if header is None:
                    if kind=='graph_optional':self.pending_spec=None;return False
                    raise AuthorityUnavailable('actual_existing_artifact_control_metadata')
                history=meter.read_fixed_row(r.db,'graph_history',('event_id','value_cell_id','valid'),
                    'token=? AND revision=?',(ref,header[0]))
                if history is None or history[1:]!=(header[2],header[1]):
                    raise AuthorityUnavailable('Continuation control lost actual current history member')
                self.pending_header=(*header,history[0])
                self.pending=_ControlColumnV3(s,('control_legacy_draft',profile),table='graph_atoms',column='value',
                    key_columns=('token','bot','persona'),key=(ref,*r.namespace.as_tuple),cell_id=header[2])
            else:self.pending=_LegacySignedV3(s,kind.removeprefix('optional:'),ref,('control_legacy_draft',profile))
            return False
        kind,ref,profile=self.pending_spec
        if kind in {'graph','graph_optional'}:
            if not self.pending.advance(meter):return False
            raw=self.pending.require_v3(r)
            self.graph_rows[ref]=({'revision':self.pending_header[0],'valid':self.pending_header[1],'cell':self.pending_header[2],
                'producer':self.pending_header[3]},raw,self.pending.semanticlogical_digest_v3(),None)
            self._edges(raw)
            self.pending.release_retention_v3();self.pending=None
            self.producer=_ContinuationProducerV3(s,self.pending_header[3]);self.phase='edge_producer';return False
        if not self.pending.advance(meter):return False
        if self.pending.absent:
            if not kind.startswith('optional:'):raise AuthorityUnavailable('actual_existing_artifact_signed_locator')
            self.pending.close_v3();self.pending=None;self.pending_spec=None;return False
        kind=kind.removeprefix('optional:')
        self.life_rows[kind,ref]=(self.pending.header,self.pending.value);self._edges(self.pending.value)
        self.pending.close_v3();self.pending=None;self.pending_spec=None;return False
    def _adopt_producer(self,cp):
        self.producers[cp.operation]=(cp.layout,cp.header,cp.original,cp.receipt)
        self.roots.extend(v.key.token for v in cp.read_versions if v.key.type_name=='memory.source')
    def _finish(self):
        s=self.state
        for ref in self.roots:
            key=AtomKey.from_token(ref)
            from ..runtime_contracts import NamespaceId
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=s.reader.namespace:
                raise AuthorityUnavailable('Continuation metadata declares a foreign Source root')
        s.draft_metadata.roots.extend(self.roots)
        for(kind,ref),(header,raw)in self.life_rows.items():
            s.draft_metadata.originals.append((kind,ref,header,raw))
        self.complete=True;s.reader.operation.refresh_retained_state_v3(self)
    def close_v3(self):
        if self.closed:return
        self.closed=True
        if self.pending is not None:
            if self.pending_spec[0]in {'graph','graph_optional'}:self.pending.release_retention_v3()
            else:self.pending.close_v3()
        for column in (self.column,self.history_column):
            if column is not None:column.release_retention_v3()
        if self.producer is not None:self.producer.close_v3()
        self.pending=self.column=self.history_column=self.producer=None
        self.graph_rows.clear();self.life_rows.clear();self.producers.clear();self.candidates.clear();self.queue.clear()
        self.roots.clear();self.seen.clear();self.state.reader.operation.unregister_retained_state_v3(self);self.state=None



def _point_v3(state,ref,columns=('revision','value','valid')):
    return state.control_point_v3('graph_atoms',columns,('token','bot','persona'),(ref,*state.reader.namespace.as_tuple))

def _discover_existing_v3(reader,state,task):
    """The old semantic checks, over the completed exact metadata census."""
    m=_metadata(reader,state);inventory=m.continuation
    if inventory is None or not inventory.complete or inventory.closed:
        raise AuthorityUnavailable('Actual complete namespace Artifact project metadata required')
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_continuation_originals_v1 import ExistingArtifactContinuationRequestV1
    from ..domains.d08.execution import _decode_goal
    from ..domains.d08.personal_plan_v1 import PLAN_TYPE,decode_personal_plan_type_v1
    from ..domains.d10.project_checkpoint_v1 import(CHECKPOINT_TYPE,WORK_TYPE,
        decode_project_checkpoint_type_v1,project_checkpoint_key_v1)
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1,D11DraftTerminalV1,life_from_wire_v1
    from .d11_life_preparation_v1 import read_prepared_life_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from ..domains.d06 import source_correction_head_key
    root=state.seed.root;ns=reader.namespace;issuer=reader.graph._GraphCoordinator__d11_issuer;matches=[]
    for ref,revision,history_revision,operation,goal_ref,plan_ref,recipe_ref in inventory.candidates:
        head=_point_v3(state,ref)
        if head is None or head[0]!=revision or head[2]!=1:
            raise AuthorityUnavailable('current_existing_artifact_project_invalid_or_changed')
        original=read_adopted_domain_operation_v1(reader.db,ns,operation)
        if original is None:raise AuthorityUnavailable('actual_existing_artifact_project_producer')
        p=original['payload']['provenance']
        content=p['artifact_content_adoption']if original['operation_kind']=='create_artifact_project'else p['content_adoption']
        target=content['target']
        if(target['root_resource_id'],target['root_identity'],target['filename'])!=(
                root.resource_id,plain_v1(root.root_identity),root.filenames[0]):
            raise AuthorityUnavailable('Existing artifact changed actual Root/file target')
        goal_row=_point_v3(state,goal_ref)
        if goal_row is None or goal_row[2]!=1 or _decode_goal(background_json_loads_v3(goal_row[1])).state!='active':
            raise AuthorityUnavailable('active_existing_artifact_goal_without_revival')
        require_artifact_task_objective_original_v1(reader.db,namespace=ns,goal_ref=goal_ref,
            goal=_decode_goal(background_json_loads_v3(goal_row[1])),issuer=issuer)
        plan_row=_point_v3(state,plan_ref);checkpoint_row=_point_v3(state,project_checkpoint_key_v1(ns,ref).token)
        if plan_row is None or checkpoint_row is None:raise AuthorityUnavailable('recover_original_existing_artifact_checkpoint')
        plan=decode_personal_plan_type_v1(PLAN_TYPE,background_json_loads_v3(plan_row[1]))
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,background_json_loads_v3(checkpoint_row[1]))
        amendment=_current_amendment_v3(reader,state,task.root_registration_ref)
        corrections=[]
        if amendment is not None:
            if(amendment[0].goal_ref,amendment[0].project_ref,amendment[0].source_ref)!=(goal_ref,ref,root.source_ref):
                raise ValueError('ordinary task amendment identifies another project or incoming Source')
            corrections.append(amendment[2].token)
        else:
            for source_ref in plan.source_refs:
                key=source_correction_head_key(ns,AtomKey.from_token(source_ref).owner.subject)
                row=_point_v3(state,key.token)
                if row is not None and row[2]==1 and background_json_loads_v3(row[1])['state']=='pending_reevaluation':
                    corrections.append(key.token)
        if len(corrections)!=1:raise AuthorityUnavailable('unique_actual_pending_artifact_correction')
        witnesses=[]
        for work_ref in checkpoint.work_version_refs:
            row=_point_v3(state,work_ref)
            if row is None or row[2]!=1:raise AuthorityUnavailable('actual_existing_artifact_work_version')
            work=decode_project_checkpoint_type_v1(WORK_TYPE,background_json_loads_v3(row[1]))
            adopted=read_adopted_life_original_v1(reader.db,namespace=ns,result_ref=work.artifact_ref,issuer=issuer)
            if adopted is None:raise AuthorityUnavailable('query_original_draft_effect_without_new_attempt')
            terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
            if type(terminal)is not D11DraftTerminalV1 or terminal.status!='completed':
                raise AuthorityUnavailable('query_original_draft_effect_without_new_attempt')
            prepared=read_prepared_life_v1(reader.db,binding=terminal.binding,issuer=issuer)
            if prepared is None:raise AuthorityUnavailable('actual_signed_old_draft_prepared')
            witness=require_draft_terminal_readback_v1(prepared=prepared,terminal=terminal)
            if(prepared.plan.project.ref,witness.filename)!=(ref,root.filenames[0]):
                raise ValueError('existing work belongs to another artifact')
            witnesses.append((witness.version,work.artifact_ref))
        if not witnesses:raise AuthorityUnavailable('recover_original_existing_artifact_progress')
        latest=max(version for version,_ in witnesses)
        results=[result for version,result in witnesses if version==latest]
        if len(results)!=1:raise AuthorityUnavailable('unique_actual_latest_artifact_version')
        matches.append(ExistingArtifactContinuationRequestV1(task,ref,goal_ref,plan_ref,recipe_ref,results[0],corrections[0]))
    if len(matches)>1:raise AuthorityUnavailable('unique_existing_artifact_project_for_actual_owner_root')
    return matches[0]if matches else None

def _current_amendment_v3(reader,state,root_ref):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import(SCOPE_KIND,task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,
        ArtifactTaskObjectiveV1,require_task_scope_archive_v1,_decode)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_task_amendment_v1 import(KIND,amendment_from_scope_v1,amendment_original_ref_v1,
        amendment_key_v1,require_amendment_history_v1)
    from ..domains.d01.production_operations_v1 import plain_v1
    ns=reader.namespace;issuer=reader.graph._GraphCoordinator__d11_issuer
    saved=_read(reader.db,issuer=issuer,namespace=ns,kind=SCOPE_KIND,ref=task_scope_ref_v1(root_ref))
    if saved is None:return None
    scope=_decode(saved[0],IngressArtifactTaskScopeOriginalV1)
    if scope.task_kind!='continue':return None
    producer=read_adopted_domain_operation_v1(reader.db,ns,saved[1])
    if producer is None:raise AuthorityUnavailable('actual_task_amendment_scope_producer')
    require_task_scope_archive_v1(reader.db,namespace=ns,root=scope.root,producer=producer)
    objective=_decode(producer['payload']['provenance']['artifact_task_objective'],ArtifactTaskObjectiveV1)
    value=amendment_from_scope_v1(scope,objective);ref=amendment_original_ref_v1(value)
    original=_read(reader.db,issuer=issuer,namespace=ns,kind=KIND,ref=ref)
    key=amendment_key_v1(ns,root_ref);head=_point_v3(state,key.token)
    if(original is None or original!=(plain_v1(value),saved[1])or head is None
            or head[0]!=1 or head[2]!=1 or background_json_loads_v3(head[1])!=plain_v1(value)):
        raise AuthorityUnavailable('current_original_task_amendment_head')
    require_amendment_history_v1(reader.db,value=value,producer=producer,scope=scope,objective=objective)
    return value,ref,key



def _build_draft_request_v3(reader, state, operation_kind):
    self = reader.graph
    installed_bundle = reader.bundle
    db = reader.db
    ns = reader.namespace
    c02_operation_id = state.selector.c02_operation_id
    source_ref = state.selector.source_ref
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, WakeArtifactDraftCycleRequestV1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d11_artifact_draft_model_v1 import PrepareArtifactDraftModelRequestV1, AcquireArtifactDraftModelRequestV1, read_artifact_draft_prepared_v1
    from .d11_artifact_draft_content_v1 import AdoptArtifactDraftContentRequestV1
    from .d08_personal_plan_v1 import ComposeCurrentArtifactGoalPlanRequestV1, ProposeCurrentArtifactActionRequestV1, artifact_draft_action_keys_v1
    from .d10_project_checkpoint_v1 import CreateCurrentArtifactProjectRequestV1
    from .d02_life_body_preparation_v1 import PrepareArtifactDraftBodyRequestV1
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
    from .d10_project_checkpoint_v1 import InitializeCurrentProjectCheckpointRequestV1
    from .jobs import get_job
    from .artifact_continuation_originals_v1 import read_selected_artifact_continuation_request_v1, artifact_control_keys_for_task_v1
    continuation_operations = {'await_existing_artifact_revision_v1', 'select_existing_artifact_continuation_v1', 'revise_existing_artifact_v1'}
    constructors = {'prepare_artifact_draft_model': PrepareArtifactDraftModelRequestV1, 'acquire_artifact_draft_model': AcquireArtifactDraftModelRequestV1, 'adopt_artifact_draft_content': AdoptArtifactDraftContentRequestV1}
    post_content = {'compose_artifact_goal_plan': ComposeCurrentArtifactGoalPlanRequestV1, 'create_artifact_project': CreateCurrentArtifactProjectRequestV1, 'propose_artifact_draft_action': ProposeCurrentArtifactActionRequestV1}
    if operation_kind not in {*constructors, *post_content, *continuation_operations, 'prepare_artifact_draft_project_context', 'prepare_artifact_draft_body', 'wake_artifact_draft_cycle_v1', 'input:register_artifact_draft_plan_v3', 'prepare_life', 'initialize_project_checkpoint', 'input:register_life_outcome_v2', 'advance_life', 'settle_project_checkpoint', 'settle_personal_goal'}:
        raise ValueError('artifact caller accepts only its fixed installed task operations')
    cycle = get_job(db, foreground_cycle_ids_v1(ns, c02_operation_id)[1])
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=ns, job=cycle, issuer=self._GraphCoordinator__d11_issuer)
    if responsibility is None or responsibility.root_registration_ref is None or responsibility.source_ref != source_ref:
        raise UnavailableGuard('artifact task has no actual adopted signed draft responsibility; HOLD')
    task = artifact_draft_task_selector_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=responsibility.root_registration_ref)
    if operation_kind in continuation_operations:
        if operation_kind in {'await_existing_artifact_revision_v1', 'select_existing_artifact_continuation_v1'}:
            request = _discover_existing_v3(reader, state, task)
            if request is None:
                return ArtifactControlValueV3({'status': 'no_existing_artifact', 'mode': 'create'})
        else:
            selected = read_selected_artifact_continuation_request_v1(db, namespace=ns, selector=task)
            if selected is None:
                raise UnavailableGuard('amendment lacks actual adopted artifact selection; HOLD')
            request = selected[0]
    elif operation_kind == 'wake_artifact_draft_cycle_v1':
        prepared = read_artifact_draft_prepared_v1(db, namespace=ns, issuer=self._GraphCoordinator__d11_issuer, selector=task)
        if prepared is None:
            raise UnavailableGuard('artifact terminal wake lacks its actual queued preparation; HOLD')
        request = WakeArtifactDraftCycleRequestV1(task, canonical_digest((ns, prepared.operation_id, 'd11', 'artifact_draft_model_queued')))
    elif operation_kind in post_content:
        if operation_kind == 'propose_artifact_draft_action':
            from .d03_life_project_context_v1 import life_project_context_keys_v1
            from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
            project_key = artifact_control_keys_for_task_v1(db, namespace=ns, c02_operation_id=c02_operation_id, root_registration_ref=responsibility.root_registration_ref)[2]
            for context_key in life_project_context_keys_v1(ns, project_key.token):
                context = state.control_point_v3('graph_atoms', ('valid',), ('token', 'bot', 'persona'), (context_key.token, *ns.as_tuple))
                if context != (1,):
                    raise UnavailableGuard('artifact Action awaits its actual adopted project role; HOLD')
        request = post_content[operation_kind](c02_operation_id, responsibility.root_registration_ref)
    elif operation_kind == 'prepare_artifact_draft_project_context':
        from .d03_life_project_context_v1 import PrepareArtifactDraftProjectContextRequestV1, life_project_context_keys_v1
        from .ingress_artifact_task_scope_v1 import standing_artifact_policy_v1
        standing = standing_artifact_policy_v1(installed_bundle)
        keys = artifact_control_keys_for_task_v1(db, namespace=ns, c02_operation_id=c02_operation_id, root_registration_ref=responsibility.root_registration_ref)
        contexts = tuple((state.control_point_v3('graph_atoms', ('value', 'valid'), ('token', 'bot', 'persona'), (key.token, *ns.as_tuple)) for key in life_project_context_keys_v1(ns, keys[2].token)))
        if all((row is not None and row[1] == 1 for row in contexts)):
            role = background_json_loads_v3(contexts[1][0])
            if (role['social_role'], tuple(role['norm_refs'])) != (standing.social_role, standing.norm_refs):
                raise UnavailableGuard('actual project role differs from the installed standing choice; HOLD')
            return ArtifactControlValueV3({'status': 'current_project_role'})
        request = PrepareArtifactDraftProjectContextRequestV1(keys[2].token, keys[3].token, source_ref, standing.social_role, standing.norm_refs)
    elif operation_kind == 'prepare_artifact_draft_body':
        configured = installed_bundle.artifact_draft.body_policy
        action_key = artifact_draft_action_keys_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=responsibility.root_registration_ref)[0]
        request = PrepareArtifactDraftBodyRequestV1(action_key.token, configured.policy_ref, configured.policy_version, configured.effect_component_policy_ref, configured.cpu_ceiling_ms)
    elif operation_kind == 'initialize_project_checkpoint':
        from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
        keys = artifact_goal_plan_keys_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=responsibility.root_registration_ref)
        request = InitializeCurrentProjectCheckpointRequestV1(keys[2].token, keys[1].token)
    elif operation_kind == 'prepare_life':
        request = PrepareCurrentLifeRequestV1('artifact-draft-final-plan:' + task.digest[:40], 'artifact-draft-life-prepare:' + task.digest[:40])
    elif operation_kind == 'input:register_artifact_draft_plan_v3':
        request = _build_final_plan_v3(reader, state, task, cycle)
    elif operation_kind in {'input:register_life_outcome_v2', 'advance_life', 'settle_project_checkpoint', 'settle_personal_goal'}:
        from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1, SettleCurrentPersonalGoalRequestV1
        from .d10_project_checkpoint_v1 import SettleCurrentProjectCheckpointRequestV1
        from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
        from .domain_production_inputs_v1 import RegisterCurrentLifeOutcomeInputRequestV2
        from .d11_life_contract_v1 import RegisteredLifeOutcomeV2, D11LifeTerminalV1, life_from_wire_v1
        from .d11_life_preparation_v1 import read_registered_life_plan_v2
        from .d11_life_terminal_v1 import read_adopted_life_original_v1
        from .d11_types import runtime_cost_settlement_key
        from ..domains.d08.production_operations_v1 import observed_action_outcome_key_v1
        from ..domains.d08.execution import _decode_intent
        from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
        from .d11_life_contract_v1 import draft_artifact_ref_v1
        ids = artifact_draft_file_ids_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=task.root_registration_ref)
        keys = artifact_control_keys_for_task_v1(db, namespace=ns, c02_operation_id=c02_operation_id, root_registration_ref=task.root_registration_ref)
        progress_ref = AtomKey(Owner('activity', *ns.as_tuple, ids['activity_id']), 'd10.life_progress.v1', ids['effect']).token
        outcome_ref = 'artifact-draft-outcome:' + task.digest[:40]
        if operation_kind == 'advance_life':
            request = AdvanceCurrentLifeRequestV1(keys[2].token, outcome_ref)
        elif operation_kind == 'settle_project_checkpoint':
            from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
            from .d11_life_preparation_v1 import read_prepared_life_v1
            actual = read_adopted_life_original_v1(db, namespace=ns, result_ref=draft_artifact_ref_v1(ns, ids['effect']), issuer=self._GraphCoordinator__d11_issuer)
            if actual is None:
                raise UnavailableGuard('checkpoint requires actual same-effect file adoption; HOLD')
            terminal = life_from_wire_v1(actual['terminal'], D11LifeTerminalV1)
            prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=self._GraphCoordinator__d11_issuer)
            if prepared is None:
                raise UnavailableGuard('checkpoint requires actual same-effect preparation; HOLD')
            require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
            checkpoint_key = project_checkpoint_key_v1(ns, keys[2].token)
            checkpoint_row = state.control_point_v3('graph_atoms', ('revision', 'value', 'valid'), ('token', 'bot', 'persona'), (checkpoint_key.token, *ns.as_tuple))
            if checkpoint_row is None or checkpoint_row[2] != 1:
                raise UnavailableGuard('checkpoint settlement needs the actual current control head; HOLD')
            checkpoint_value = background_json_loads_v3(checkpoint_row[1])
            if checkpoint_value['revision'] != checkpoint_row[0] or checkpoint_value['plan_ref'] != keys[1].token:
                raise ValueError('checkpoint settlement control revision or plan differs')
            request = SettleCurrentProjectCheckpointRequestV1(keys[2].token, keys[1].token, progress_ref, None, checkpoint_row[0])
        elif operation_kind == 'settle_personal_goal':
            control_rows = tuple((state.control_point_v3('graph_atoms', ('revision', 'value', 'valid'), ('token', 'bot', 'persona'), (key.token, *ns.as_tuple)) for key in keys[:2]))
            if any((row is None or row[2] != 1 for row in control_rows)):
                raise UnavailableGuard('goal settlement needs actual current Goal and Plan heads; HOLD')
            goal_value, plan_value = (background_json_loads_v3(row[1]) for row in control_rows)
            if goal_value['revision'] != control_rows[0][0] or plan_value['revision'] != control_rows[1][0] or plan_value['goal_ref'] != keys[0].token or (plan_value['goal_revision'] != control_rows[0][0]):
                raise ValueError('goal settlement current Goal/Plan revisions differ')
            request = SettleCurrentPersonalGoalRequestV1(keys[0].token, keys[1].token, progress_ref, control_rows[0][0], control_rows[1][0])
        else:
            plan = read_registered_life_plan_v2(db, namespace=ns, issuer=self._GraphCoordinator__d11_issuer, original_ref='artifact-draft-final-plan:' + task.digest[:40])
            if plan is None:
                raise UnavailableGuard('draft outcome requires its actual registered plan; HOLD')
            adopted = read_adopted_life_original_v1(db, namespace=ns, result_ref=draft_artifact_ref_v1(ns, ids['effect']), issuer=self._GraphCoordinator__d11_issuer)
            if adopted is None:
                raise UnavailableGuard('draft outcome requires actual same-effect adoption; HOLD')
            terminal = life_from_wire_v1(adopted['terminal'], D11LifeTerminalV1)
            action_key = AtomKey.from_token(plan.action_intent.ref)
            action_row = state.control_point_v3('graph_atoms', ('value', 'valid'), ('token',), (action_key.token,))
            if action_row is None or action_row[1] != 1:
                raise UnavailableGuard('draft outcome requires its actual adopted Action; HOLD')
            action = _decode_intent(background_json_loads_v3(action_row[0]))
            request = RegisterCurrentLifeOutcomeInputRequestV2(outcome_ref, RegisteredLifeOutcomeV2(plan_original_ref=terminal.binding.plan_original_ref, action_outcome_ref=observed_action_outcome_key_v1(action_key, action).token, start_original_ref=terminal.claim.original_ref, terminal_original_ref=terminal.original_ref, artifact_ref=terminal.binding.artifact_ref, artifact_digest=terminal.payload.artifact_digest, paid_cost_refs=(runtime_cost_settlement_key(*ns.as_tuple, terminal.binding.activity_id, terminal.binding.reservation_operation_id).token,)))
    else:
        request = constructors[operation_kind](task)
    return request

def _build_final_plan_v3(reader, state, task, cycle):
    self = reader.graph
    db = reader.db
    installed_bundle = reader.bundle
    'Build candidate C from adopted content/A/B; the actual input compiler rechecks every member.'
    from .artifact_continuation_originals_v1 import artifact_control_keys_for_task_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1, artifact_draft_file_ids_v1
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1, artifact_draft_content_from_wire_v1
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1, artifact_draft_action_keys_v1
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    from .d11_life_contract_v1 import LifeBodyComponentContractV1, LifeInputRefV1
    from .domain_production_inputs_v1 import RegisterCurrentDraftFilePlanInputRequestV3
    from ..memory_types import access_key
    from datetime import datetime, timezone
    ns = task.namespace
    ids = artifact_draft_file_ids_v1(ns, c02_operation_id=task.c02_operation_id, root_registration_ref=task.root_registration_ref)
    raw = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind='c4_adopted', ref=artifact_draft_model_ids_v1(task)['adopt'])
    if raw is None:
        raise UnavailableGuard('final plan C requires actual adopted C4 content; HOLD')
    content = artifact_draft_content_from_wire_v1(raw[0], ArtifactDraftContentAdoptionV1)
    keys = artifact_control_keys_for_task_v1(db, namespace=ns, c02_operation_id=task.c02_operation_id, root_registration_ref=task.root_registration_ref)
    action_key = artifact_draft_action_keys_v1(ns, c02_operation_id=task.c02_operation_id, root_registration_ref=task.root_registration_ref)[0]
    root = _require_draft_action_root_v3(reader,state,action_key.token)
    body_raw = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind='life_body_preparation', ref='life-body:d02-life-body:' + root.action_operation_id)
    if body_raw is None:
        raise UnavailableGuard('final plan C requires actual adopted Body B; HOLD')
    body = life_body_preparation_original_from_wire_v1(body_raw[0])
    contract = LifeBodyComponentContractV1(*(getattr(body, name) for name in ('body_quote_ref', 'body_quote_version', 'body_quote_digest', 'resource_quote_ref', 'resource_quote_version', 'resource_quote_digest', 'reservation_ref', 'settlement_ref', 'component_id', 'effect_policy_ref', 'body_prepare_operation_id')))
    quote = self._GraphCoordinator__d02_issuer.original_signed_quote(db, body.resource_quote_ref, body.resource_quote_version)
    grant = self._GraphCoordinator__d11_issuer.current_budget_grant(db, cycle.budget_ref)
    deadline = min(datetime.fromisoformat(content.original_deadline_utc.replace('Z', '+00:00')).timestamp(), quote.valid_until_utc, grant.valid_until_utc)

    def frozen(key):
        row = state.control_point_v3('graph_atoms', ('revision', 'value', 'valid'), ('token', 'bot', 'persona'), (key.token, *ns.as_tuple))
        if row is None or row[2] != 1:
            raise UnavailableGuard('final plan C lost an actual adopted input; HOLD')
        return LifeInputRefV1(key.token, row[0], background_json_digest_v3(row[1],background_json_loads_v3(row[1])))
    source_key = AtomKey.from_token(content.task_source.ref)
    plan = RegisteredDraftFilePlanV3(frozen(keys[2]), frozen(keys[3]), frozen(action_key), frozen(source_key), frozen(access_key(*ns.as_tuple, source_key.owner.subject)), root.activity_id, root.effect_id, ids['attempt'], root.action_operation_id, ids['execution_call'], content.activity_scope_ref, content.activity_scope_digest, root.audiences, cycle.budget_ref, installed_bundle.artifact_draft.body_policy.cpu_ceiling_ms, datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace('+00:00', 'Z'), content.algorithm_build_digest, content.postcondition_build_digest, canonical_serialize(asdict(contract)), content.target, content.content)
    return RegisterCurrentDraftFilePlanInputRequestV3('artifact-draft-final-plan:' + task.digest[:40], plan)

def _legacy_draft_entry_v3(reader,state):
    q=state.selector;values=dict(q.arguments);requested=values['operation_kind']
    if q.stage not in {'start','draft_wait','draft_select','draft_prepare','draft_role','draft_action'}:
        raise ValueError('Unregistered finite legacy draft stage')
    m=_metadata(reader,state)
    if m.task is None:raise AuthorityUnavailable('actual_adopted_signed_draft_responsibility')
    if q.stage=='start'and requested=='prepare_artifact_draft_model':
        if m.prepared is not None:
            from .d11_artifact_draft_model_v1 import PrepareArtifactDraftModelRequestV1
            return ArtifactControlCommandV3(requested,PrepareArtifactDraftModelRequestV1(m.task))
        return ArtifactControlNextV3(q.entry_kind,'draft_wait',q.arguments,q.completed_receipts)
    if q.stage=='start'and requested=='propose_artifact_draft_action':
        from ..host.authority_profile import AdminArtifactDraftPolicyV2
        if type(reader.bundle.artifact_draft)is AdminArtifactDraftPolicyV2:
            return ArtifactControlNextV3(q.entry_kind,'draft_role',q.arguments,q.completed_receipts)
    stages={'draft_wait':('prepare_artifact_draft_model','await_existing_artifact_revision_v1','draft_select'),
        'draft_select':('prepare_artifact_draft_model','select_existing_artifact_continuation_v1','draft_prepare'),
        'draft_prepare':('prepare_artifact_draft_model','prepare_artifact_draft_model','return'),
        'draft_role':('propose_artifact_draft_action','prepare_artifact_draft_project_context','draft_role'),
        'draft_action':('propose_artifact_draft_action','propose_artifact_draft_action','return')}
    operation,after=requested,'return'
    if q.stage in stages:
        expected,operation,after=stages[q.stage]
        if requested!=expected:raise AuthorityUnavailable('Legacy stage changed its exact original requested operation')
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:request=_build_draft_request_v3(reader,state,operation)
        finally:reader.db.rollback()
    if type(request)is ArtifactControlValueV3:
        if q.stage in {'draft_wait','draft_select'}and request.value.get('status')=='no_existing_artifact':
            return ArtifactControlNextV3(q.entry_kind,'draft_prepare',q.arguments,q.completed_receipts)
        if q.stage=='draft_role'and request.value.get('status')=='current_project_role':
            return ArtifactControlNextV3(q.entry_kind,'draft_action',q.arguments,q.completed_receipts)
        return request
    if operation=='wake_artifact_draft_cycle_v1':after='wake_acquire'
    return ArtifactControlCommandV3(operation,request,after=after)

def _legacy_draft_post_v3(reader,state,result,original,complete):
    q=state.selector
    stages={'draft_select':('await_existing_artifact_revision_v1','draft_select'),
        'draft_prepare':('select_existing_artifact_continuation_v1','draft_prepare'),
        'draft_role':('prepare_artifact_draft_project_context','draft_action')}
    if q.stage not in stages:raise ValueError('Unregistered finite legacy draft post stage')
    expected,next_stage=stages[q.stage]
    if q.entry_kind!='run_current_post_c02_artifact_draft_operation_v1'or q.operation_kind!=expected:
        raise AuthorityUnavailable('Legacy receipt stage changed actual registered predecessor operation')
    return ArtifactControlNextV3(q.entry_kind,next_stage,q.arguments,complete)


def _require_draft_action_root_v3(reader,state,action_ref):
    from .d11_life_preparation_v1 import _read
    from .d08_life_admission_v1 import draft_action_root_from_wire_v1
    from .d04_root_original_store_v1 import _receipt
    m=_metadata(reader,state);inventory=m.continuation
    if inventory is None or not inventory.complete:raise AuthorityUnavailable('Actual draft Action metadata closure required')
    refs=[ref for(kind,ref),(header,raw)in inventory.life_rows.items()
        if kind=='draft_action'and raw.get('action_intent_ref')==action_ref]
    if len(refs)!=1:raise AuthorityUnavailable('actual_signed_artifact_draft_action_root')
    raw,operation=_read(reader.db,issuer=reader.graph._GraphCoordinator__d11_issuer,
        namespace=reader.namespace,kind='draft_action',ref=refs[0])
    root=draft_action_root_from_wire_v1(raw);receipt=_receipt(reader.db,reader.namespace,operation)
    if(operation!=root.action_operation_id or canonical_digest(receipt)!=root.receipt_digest
            or{(v.key.token,v.revision)for v in receipt.write_versions}!={(ref,revision)for ref,revision,digest in root.write_commitments}):
        raise AuthorityUnavailable('draft signed root lost actual adopted Action receipt')
    for ref,revision,digest in root.write_commitments:
        row=state.control_point_v3('graph_history',('event_id','value','valid'),('token','revision'),(ref,revision))
        if(row is None or row[0]!=operation or row[2]!=1
                or background_json_digest_v3(row[1],background_json_loads_v3(row[1]))!=digest):
            raise AuthorityUnavailable('draft root lost actual immutable history member')
    return root
