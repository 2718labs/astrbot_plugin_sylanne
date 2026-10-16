"""Canonical cause locator mechanics shared by independent Host and Authority Works.

These projections carry no Owner, Source, CoreSelf or write qualification.
The caller owns actual row membership, the READ fence, clock and private issuer.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import AuthorityContext,NamespaceId,canonical_digest

PRODUCER_HEADER_COLUMNS_V3=('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest')
CONDITIONED_RECEIVER_DOMAINS_V3={
    'conditioned_simulation_committed_v1':'d07','conditioned_observed_outcome_committed_v1':'d07',
    'conditioned_calibration_resolution_committed_v1':'d01','conditioned_method_review_committed_v1':'d01',
    'conditioned_conditions_committed_v1':'d07','conditioned_life_phase_committed_v1':'d10'}
OUTBOX_HEADER_COLUMNS_V3=('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state')


def conditioned_producer_locator_spec_v3(namespace,operation_id):
    if type(namespace)is not NamespaceId or type(operation_id)is not str or not operation_id:
        raise TypeError('conditioned producer locator needs exact namespace and operation')
    return('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),
        (*namespace.as_tuple,operation_id),PRODUCER_HEADER_COLUMNS_V3,
        (('schema',),('namespace',),('identity',),('authority',),('parent_budget',),
         ('provenance','conditioned_source_roots'),('provenance','conditioned_original_deadline_utc'),
         ('provenance','artifact_task_milestone','original_deadline_utc'),
         ('provenance','artifact_task_milestone','source_head')),None)


def retain_conditioned_producer_locator_path_v3(path):
    if not path:return True
    if path[0]in {'schema','namespace','identity','authority','parent_budget'}:return True
    if path[0]!='provenance':return False
    if len(path)==1:return True
    if path[1]in {'conditioned_source_roots','conditioned_original_deadline_utc'}:return True
    return path[1]=='artifact_task_milestone'and(len(path)==2 or path[2]in {'original_deadline_utc','source_head'})


@dataclass(frozen=True,slots=True)
class ConditionedProducerSourceMetadataV3:
    namespace: NamespaceId
    dedupe_key: str
    causal_operation_id: str
    domain: str
    operation_kind: str
    receiver_domain: str
    event_kind: str
    trigger_ref: str
    trigger_digest: str
    original_digest: str
    receipt_digest: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    source_refs: tuple[str,...]
    authority: AuthorityContext
    task_source_head: GraphVersion|None
    header: tuple


def finish_conditioned_producer_locator_v3(*,namespace,dedupe_key,outbox_header,header,
        bundle_metadata,projection,whole_digest,producer_events):
    if(type(namespace)is not NamespaceId or type(dedupe_key)is not str or not dedupe_key
            or len(outbox_header)!=6 or len(header)!=6 or len(bundle_metadata)!=2):
        raise ValueError('conditioned cause metadata shape differs')
    operation_id,receiver,event,trigger_ref,trigger_digest,state=outbox_header
    domain,kind,_,digest,receipt_digest,bundle_digest=header
    if(event not in producer_events or receiver!=CONDITIONED_RECEIVER_DOMAINS_V3[event]
            or dedupe_key!=canonical_digest((namespace,operation_id,receiver,event))
            or(domain,kind)not in producer_events[event]
            or state not in {'pending','waiting'}or bundle_metadata[0]!=bundle_digest
            or type(bundle_metadata[1])is not int or bundle_metadata[1]<1
            or whole_digest!=digest or digest!=trigger_digest):
        raise ValueError('conditioned cause is not its exact fixed actual COMMIT/outbox member')
    if(projection['schema']!=domain+'.current-'+kind+'.v1'
            or projection['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
            or projection['identity']['operation_id']!=operation_id
            or trigger_ref!=domain+'-current:'+digest[:48]):
        raise ValueError('conditioned cause namespace/producer/schema/original locator differs')
    raw=projection['authority']
    authority=AuthorityContext(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'owner_scope':tuple(raw['owner_scope']),'audience':tuple(raw['audience'])})
    if authority.namespace!=namespace:raise ValueError('conditioned cause authority namespace differs')
    provenance=projection['provenance']
    deadline=provenance['conditioned_original_deadline_utc']
    if type(deadline)not in {float,int}or not math.isfinite(deadline):
        raise ValueError('conditioned cause absolute original deadline is invalid')
    roots=tuple(provenance['conditioned_source_roots'])
    if len(roots)>32 or len(set(roots))!=len(roots):raise ValueError('conditioned cause roots exceed actual Source bounds')
    for ref in roots:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=namespace:
            raise ValueError('conditioned cause roots are not canonical namespace Source locators')
    task_source_head=None
    artifact_task=provenance.get('artifact_task_milestone')
    if artifact_task is not None:
        if event!='conditioned_observed_outcome_committed_v1'or(domain,kind)!=('d08','register_artifact_task_milestone_v2'):
            raise ValueError('conditioned artifact task TTL belongs to another fixed producer')
        task_deadline=artifact_task['original_deadline_utc']
        if type(task_deadline)not in {float,int}or not math.isfinite(task_deadline):
            raise ValueError('conditioned artifact task original TTL is invalid')
        deadline=min(deadline,task_deadline)
        source=artifact_task['source_head']
        if set(source)!={'key','revision'}:raise ValueError('conditioned artifact task Source head fields differ')
        task_source_head=GraphVersion(AtomKey.from_token(source['key']),source['revision'])
        if task_source_head.key.token not in roots or task_source_head.revision<1:
            raise ValueError('conditioned artifact task Source is outside its producing closure')
    parent=projection['parent_budget']
    if type(parent)is not str or not parent:raise ValueError('conditioned cause lacks its original Root budget')
    return ConditionedProducerSourceMetadataV3(namespace,dedupe_key,operation_id,domain,kind,receiver,event,
        trigger_ref,trigger_digest,digest,receipt_digest,parent,deadline,roots,authority,task_source_head,tuple(outbox_header))


CONDITIONED_LOCATOR_FIELDS_V3=frozenset({'schema','namespace','runtime_identity','source_refs','scope_refs','population_scope_refs',
    'applicable_scope','exclusions','condition_predicate_ref','predicate_ref','prediction_refs','resolution_refs',
    'counterexample_refs','counterexamples','previous_ref','last_review_ref','review_ref','candidate_ref','expected_persona_head',
    'target_head','resolution_target_ref','target_observable','observer_kind','resolution_rule','registered_at','expires_at',
    'valid_from','valid_until','strategy_ref','condition_heads','prediction_ref','outcome_ref','task_class','support_family_refs',
    'support_families','trial_refs','rollback_predicate_ref','goal_ref','goal_revision','baseline_snapshot','baseline','alternatives',
    'calibration_policy_ref','method_outcome_review_ref','simulation_request_ref','simulation_activity_id','baseline_assumption_ref',
    'alternative_assumption_refs','forecasts','condition_goal_head','assumption_heads','match_scope_project_ref',
    'project_head','recipe_head','plan_head','goal_head','condition_match','forecast_plan_ref','forecast_plan_digest',
    'registered_request_ref','snapshot_refs','assumption_refs','block_id','kind','plasticity','active_head','plan_head_id',
    'head_id','version','blocks','plan_ref','project_ref','recipe_ref','next_step','previous_progress_ref','action_ref','intent_ref',
    'observation_refs','previous_revision','continuity_anchor','legacy_origin','plasticity_policy_ref','support_original_refs',
    'counterevidence_original_ref','continuity_original_ref','trial_original_refs','exclusion_refs',
    'revision','revision_kind','adopt_before','plasticity_policy_digest','terminal_provenance',
    'capability_id','strategy_id','plan_id','plan_version','resolved_at','observation_unit_ref',
    'question_key','stance','evidence_status','current','observed_at','action_id','activity_id','effect_id','attempt_id',
    'commitment_refs','target_ref','action_kind','purpose','identity','cost_refs','result_level','artifact_ref','terminal_ref',
    'receipt_refs','reality','step','role_start','role_end','bot_id','persona_id','bundle_operation_id','settlement_id',
    'lease_id','cost_operation_id','budget_operation_id','budget_phase','prior_unknown_ref','execution_revoked',
    'operation_id','job_id','phase','work_kind','deadline_utc','parent_budget_lease_ref','cancel_epoch','lease_holder',
    'lease_expires_utc','fence','cancel_refs','action_revision','action_digest','state','actor','reason_refs',
    'scope_project_ref','semantic_question_ref','resolution_ref','branch_ref','changed_assumption_refs','unmodelled_refs'})


def retain_conditioned_business_locator_path_v3(identity,path):
    if identity[0]=='root_grant':return True
    if identity[0]=='producer':
        if not path:return True
        if path[0]in {'schema','namespace','identity','read_versions'}:return True
        if path[0]!='provenance':return False
        if len(path)==1:return True
        if path[1]in {'source_refs','conditioned_source_roots','conditioned_original_deadline_utc'}:return True
        if path[1]=='conditioned_frozen_targets':
            return len(path)<=2 or path[2]=='target_census'or path[2]=='targets'and(len(path)<=4 or path[4]in {'child_id','operation_kind'})
        if path[1]=='conditioned_followup_target_commitment':return True
        return path[1]=='execution'and(len(path)<=2 or path[2]in {'operation_id','execution_id','work_kind','input_digest',
            'parent_budget_ref','source_refs','source_read_versions','job_id','terminal_ref','call_id','effect_id','activity_id','attempt_id','owner_guard'})
    if identity[0]=='general_signed':
        from .d01_general_growth_v1 import general_growth_owner_metadata_retains_path_v1
        table,kind,_=identity[1]
        return general_growth_owner_metadata_retains_path_v1(table,kind,path)
    if identity[0]=='simulation_request':
        return not path or(path[0]in {'schema','request_digest','dedicated_budget_ref'}or path[0]=='request'and(len(path)==1 or path[1]in {'activity_id','snapshot_refs'}))
    if identity[0]=='life_prepared':
        from .life_prepared_source_metadata_v3 import retain_life_prepared_locator_path_v3
        return retain_life_prepared_locator_path_v3(path)
    if not path:return True
    if path[0]=='forecasts':
        return len(path)<=2 or path[2]in {'namespace','prediction_id','task_class','condition_predicate_ref','branch_ref','target_head',
            'target_observable','assumption_refs','assumption_heads','condition_goal_head','condition_goal_revision','observer_kind',
            'resolution_rule','resolution_target_ref','expires_at','registered_at','source_refs','schema','content_reality','producer_kind'}
    if path[0]=='condition_match':return len(path)==1 or path[1]in CONDITIONED_LOCATOR_FIELDS_V3
    if path[0]=='terminal_provenance':return len(path)<2 or path[1]in {'binding','prepared_digest'}
    if path[0]=='blocks':
        return len(path)<3 or path[2]in {'block_id','kind','plasticity'}
    return path[0]in CONDITIONED_LOCATOR_FIELDS_V3


class ConditionedMetadataJSONStreamV3:
    def __new__(cls,column,*,ensure_ascii,wire_metadata=None):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        class Stream(C09CanonicalJSONStreamV2):
            def _append_decoded_codepoint(self,codepoint):
                state=self._string
                if state is None or state['mode']!='value':return super()._append_decoded_codepoint(codepoint)
                column._actual()
                if wire_metadata is not None and wire_metadata.consume_codepoint_v3(state['path'],codepoint):return
                if not column.retain_path_v3(state['path']):return
                high=column.text_high
                if high is not None:
                    column.text_high=None
                    if 0xdc00<=codepoint<=0xdfff:
                        column.text_chars.append(chr(0x10000+((high-0xd800)<<10)+codepoint-0xdc00));return
                    column.text_chars.append(chr(high))
                if 0xd800<=codepoint<=0xdbff:column.text_high=codepoint
                else:column.text_chars.append(chr(codepoint))
        return Stream(ensure_ascii=ensure_ascii)


class ConditionedLocatorJSONV3:
    """Mechanical nested JSON parser retaining only declared semantic locators."""
    def __init__(self,column):
        self.column=column;self.operation=column.operation
        self.fields_seen=set()
        self.nodes={};self.value=None;self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.text_high=None
        self.reserved=0;self.buffer=bytearray();self.parser=ConditionedMetadataJSONStreamV3(self,ensure_ascii=True)
    def _actual(self):self.column._actual();return self
    def retain_path_v3(self,path):return not path or path[0]in CONDITIONED_LOCATOR_FIELDS_V3
    def _reserve_v3(self,extra=0):
        from .dispatch_current_inventory_v3 import _heap
        total=_heap((self.nodes,self.value,self.scalar,self.text_parts,self.text_chars,self.buffer,
            self.fields_seen))+extra+65536
        if total>self.reserved:self.operation.retain(total-self.reserved);self.reserved=total
    def _put_v3(self,path,value):
        if not path:self.value=value
        elif type(self.nodes[path[:-1]])is list:self.nodes[path[:-1]].append(value)
        else:self.nodes[path[:-1]][path[-1]]=value
    def _flush_text_v3(self):
        if self.text_chars:self.text_parts.append(''.join(self.text_chars));self.text_chars=[]
    def _emit_v3(self,event):
        if event.kind=='key'and len(event.path)==1:self.fields_seen.add(event.key)
        if not self.retain_path_v3(event.path):return
        import json
        if event.kind in ('object_start','array_start'):
            self._reserve_v3(1024);value={}if event.kind=='object_start'else[]
            self.nodes[event.path]=value;self._put_v3(event.path,value)
        elif event.kind=='scalar_start':
            self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.text_high=None
        elif event.kind=='scalar_chunk'and event.scalar_kind!='string':
            self._reserve_v3(len(event.raw)*4+1024);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            if event.scalar_kind=='string':
                if self.text_high is not None:self.text_chars.append(chr(self.text_high));self.text_high=None
                self._flush_text_v3();self._reserve_v3(sum(map(len,self.text_parts))*4+1024)
                value=''.join(self.text_parts);self.text_parts=[]
            else:value=json.loads(self.scalar)
            self.scalar=bytearray();self._put_v3(event.path,value)
    def feed_codepoint_v3(self,codepoint):
        encoded=chr(codepoint).encode('utf8')
        self._reserve_v3(len(encoded)*8+1024);self.buffer.extend(encoded)
        if len(self.buffer)>=1024:self.parser.feed(bytes(self.buffer),self._emit_v3);self.buffer.clear()
    def finish_v3(self):
        if self.buffer:self.parser.feed(bytes(self.buffer),self._emit_v3);self.buffer.clear()
        self.parser.finish();self._flush_text_v3()
        return self.value,self.fields_seen


class ConditionedClaimCaptureV3:
    def __init__(self,task):
        self.task=task;self.path=None;self.parser=None;self.locators=[];self.discard=False;self.failed=False
        self.marker='';self.known_schema=False
    def consume_codepoint_v3(self,path,codepoint):
        if len(path)!=3 or path[0]!='blocks'or type(path[1])is not int or path[2]!='claim':return False
        if path!=self.path:
            self._finish_claim_v3();self.path=path;self.parser=None;self.discard=False;self.failed=False;self.marker='';self.known_schema=False
        self.marker=(self.marker+chr(codepoint))[-96:]
        if any(schema in self.marker for schema in('d01.semantic-identity','d01.conditioned-capability','d01.conditioned-strategy')):
            self.known_schema=True
        if self.failed or self.discard:return True
        if self.parser is None:
            if codepoint!=123:self.discard=True;return True
            self.parser=ConditionedLocatorJSONV3(self.task.column)
        try:self.parser.feed_codepoint_v3(codepoint)
        except ValueError:self.failed=True;self.parser=None
        return True
    def _finish_claim_v3(self):
        if self.path is None:return
        if self.failed:
            if self.known_schema:raise ValueError('declared conditioned/semantic Self locator is malformed')
            return
        if self.parser is None:return
        try:value,seen=self.parser.finish_v3()
        except ValueError:
            if self.known_schema:raise ValueError('declared conditioned/semantic Self locator is malformed')from None
            return
        if type(value)is not dict:return
        schema=value.get('schema')
        if schema in {'d01.conditioned-capability-revision.v1','d01.conditioned-strategy-revision.v1'}:
            from ..domains.d01.conditioned_self_v1 import require_conditioned_record_locator_v1,CAPABILITY_TYPE,STRATEGY_TYPE
            type_id=CAPABILITY_TYPE if schema=='d01.conditioned-capability-revision.v1'else STRATEGY_TYPE
            require_conditioned_record_locator_v1(value,seen,namespace=self.task.reader.namespace,type_name=type_id)
            identity=value['capability_id']if type_id==CAPABILITY_TYPE else value['strategy_id']
            from ..domains.d01.conditioned_self_v1 import conditioned_revision_record_name_v1
            name=conditioned_revision_record_name_v1(namespace=self.task.reader.namespace,type_name=type_id,record_id=identity,
                revision=value['revision'],review_ref=value['last_review_ref']if type_id==CAPABILITY_TYPE else value['review_ref'])
            from ..graph_types import Owner
            value['_conditioned_record_ref']=AtomKey(Owner('persona',*self.task.reader.namespace.as_tuple),type_id,name).token
            self.locators.append(value)
        else:
            from ..domains.d01.identity_v3 import SEMANTIC_SCHEMA_V3
            if schema==SEMANTIC_SCHEMA_V3:
                from ..domains.d01.conditioned_self_v1 import require_semantic_self_locator_v1
                from ..domains.d01.identity_v3 import RuntimeIdentityRef
                from .dispatch_current_inventory_v3 import _detach_value_v3
                outer=_detach_value_v3(self.task.column.frozen)if self.task.column.complete else self.task.column.value
                block=outer['blocks'][self.path[1]]
                identity=RuntimeIdentityRef.from_owner_guard(self.task.reader.namespace,self.task.reader.owner_guard)
                require_semantic_self_locator_v1(value,seen,runtime_identity=identity,outer_block_id=block['block_id'])
                self.locators.append(value)
    def finish_v3(self):
        self._finish_claim_v3();self.path=None;self.parser=None
