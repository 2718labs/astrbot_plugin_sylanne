"""Same-Work ingress recall locator EOF, before any business Source Body."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .source_correction_read_v3 import _heap
_DOMAIN='graph_domain_production_originals_v1'
_D07='graph_d07_execution_originals_v1'
_C04='graph_c04_internal_work_prepared_v1'
_ENTRIES=frozenset({'prepare_current_post_c02_recall_need_v1','run_current_post_c02_task_no_search_v1',
 'run_current_post_c02_ingress_recall_model_operation_v1','select_current_post_c02_ingress_recall_seed_v1',
 'run_current_post_c02_ingress_c04_operation_v4','read_current_ingress_recall_resume_v1',
 'advance_current_post_c02_ingress_c04_v4','acquire_post_c02_foreground_cycle_v1','_read_post_c02_foreground_cycle_v1'})

def ingress_control_required_v3(s):
    if s.seed is None or s.profile=='discovery':return False
    if getattr(s.reader.selector,'entry_kind',None)in _ENTRIES:return True
    from .d06_ingress_recall_v1 import NEED_OPERATION
    from .d07_ingress_recall_preparation_v1 import OPERATION
    from .d07_ingress_recall_acquisition_v1 import ACQUIRE_OPERATION
    from .d07_ingress_recall_result_v1 import RESULT_OPERATION,FINISH_OPERATION,ADOPT_OPERATION
    from .d06_ingress_c03_read_v1 import OPERATION as C03
    from .c04_ingress_preparation_v4 import OPERATIONS
    return getattr(s.reader.selector,'operation_kind',None)in{NEED_OPERATION,OPERATION,ACQUIRE_OPERATION,RESULT_OPERATION,FINISH_OPERATION,ADOPT_OPERATION,C03,*OPERATIONS}

def ingress_control_metadata_paths_v3(role,path):
    if not path:return True
    if role.startswith('producer:'):
        part=role.split(':',1)[1]
        if path[0]in{'schema','namespace','identity','authority','parent_budget','owner_guard'}:return True
        if path[0]=='writes':return part=='selection'and len(path)<=2
        if path[0]!='provenance':return False
        if len(path)==1:return True
        fields={'need':{'need'},'c3':{'prepared_digest','prepared_job_id','need_ref','need_digest'},
         'acquire':{'prepared_digest','request_digest'},'routing':{'adoption'},'selection':{'selection'},
         'c04_prepare':{'schema','binding_digest','prepared_digest','selection_ref','self_scope_digest','initiating_self',
          'owner_guard','before_parent','after_parent','child_job_ref','reservation_receipt_digest','self_scope_original'},
         'c04_adopt':{'schema','binding_digest','prepare_operation_id','adoption_operation_id','plan_digest','proof_digest','before_parent','after_parent'}}[part]
        if path[1]not in fields:return False
        return not(part=='routing'and len(path)>2 and path[2]in{'query_terms','meaningful_unknowns','missing_items'})
    if role in{'c04','quote'}:return True
    if role=='signed:adopted':return path[0]not in{'query_terms','meaningful_unknowns','missing_items'}
    if path[0]in{'read_rows','post_read_rows'}:return len(path)<=2 or len(path)==3 and path[2]in{'ref','revision','valid'}
    return path[0]in{'schema','namespace','operation_id','prepare_operation_id','adoption_operation_id','activity_id',
     'effect_id','attempt_id','job_id','call_id','execution_id','work_kind','audience','purpose','stage_input_digest','prepared_digest',
     'quote_id','quote_version','quote_digest','reservation_digest','body_policy_id','body_policy_version','body_quote_ref',
     'body_quote_version','body_quote_digest','body_reservation_ref','body_state_ref','body_profile_ref','component_id',
     'activation_generation','graph_epoch','access_epoch','delete_epoch','need_ref','need_digest','c02_operation_id',
     'cycle_job_ref','responsibility_ref','responsibility_digest','recall_policy_digest','cancel_generation',
     'graph_receipt_digest','writes_digest','self_authority_json','owner_guard_json','cost_ref','paid',
     'unknown_dimensions','unpaid_cost','terminal_ref','cost_receipt_refs','source_refs'}

class _DomainV3:
    def __init__(self,owner,role,operation,domain,kind):
        self.owner,self.role,self.operation,self.domain,self.kind=owner,role,operation,domain,kind
        self.header=None;self.columns=[];self.index=0;self.complete=self.absent=False
        self.original=self.receipt=None;self.read_versions=()
    def advance(self,meter):
        from .artifact_host_control_metadata_v3 import _ControlColumnV3
        from .domain_production_originals_v1 import _receipt
        s=self.owner.state;r=s.reader;key=(*r.namespace.as_tuple,self.operation)
        row=meter.read_fixed_row(r.db,_DOMAIN,('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
         'bot=? AND persona=? AND operation_id=?',key)
        if self.header is None:
            if row is None:self.complete=self.absent=True;return True
            if row[:2]!=(self.domain,self.kind):raise AuthorityUnavailable('Ingress fixed producer has another actual kind')
            self.header=tuple(row)
            self.columns=[_ControlColumnV3(s,('control_ingress','producer:'+self.role)if name=='original_payload_json'else'control_small',
             table=_DOMAIN,column=name,key_columns=('bot','persona','operation_id'),key=key)
             for name in('original_payload_json','read_versions_json','receipt_json')];return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Ingress producer changed during EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        original,reads,raw=(c.require_v3(r)for c in self.columns);receipt=_receipt(raw)
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads)
        if(self.columns[0].sha256!=self.header[3]or original.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
         or original.get('schema')!=self.domain+'.current-'+self.kind+'.v1'or original.get('identity',{}).get('operation_id')!=self.operation
         or original.get('parent_budget')!=s.seed.budget.lease
         or receipt.status!='committed'or receipt.operation_id!=self.operation or receipt.operation_digest!=self.header[4]
         or canonical_digest(receipt)!=self.header[5]or receipt.read_versions!=versions or len(versions)>1024):
            raise AuthorityUnavailable('Ingress producer canonical Original/receipt/readset EOF differs')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
         'bot=? AND persona=? AND operation_id=?',key)
        if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):raise AuthorityUnavailable('Ingress producer lacks actual W01')
        from ..domains.d01.production_operations_v1 import plain_v1
        if s.seed.expected_owner_guard is not None and original.get('owner_guard')!=plain_v1(s.seed.expected_owner_guard):
            raise AuthorityUnavailable('Ingress producer changed its actual original Owner pairing')
        self.original,self.receipt,self.read_versions=original,receipt,versions;self.complete=True;return True
    def close_v3(self):
        for column in self.columns:column.release_retention_v3()

class _RowV3:
    def __init__(self,owner,role,table,kind,ref):
        self.owner,self.role,self.table,self.kind,self.ref=owner,role,table,kind,ref
        self.header=self.column=self.value=None;self.complete=self.absent=False
    def advance(self,meter):
        from .artifact_host_control_metadata_v3 import _ControlColumnV3
        r=self.owner.state.reader
        if self.table==_D07:
            columns=('payload_digest','signature');keys=('bot','persona','kind','original_ref');key=(*r.namespace.as_tuple,self.kind,self.ref)
            where='bot=? AND persona=? AND kind=? AND original_ref=?';column='payload_json'
        elif self.table==_C04:
            columns=('binding_digest','prepared_digest');keys=('bot','persona','operation_id');key=(*r.namespace.as_tuple,self.ref)
            where='bot=? AND persona=? AND operation_id=?';column='prepared_json'
        else:
            columns=('signature',);keys=('quote_id','version');key=self.ref;where='quote_id=? AND version=?';column='quote_json'
        row=meter.read_fixed_row(r.db,self.table,columns,where,key)
        if self.header is None:
            if row is None:self.complete=self.absent=True;return True
            self.header=tuple(row);self.column=_ControlColumnV3(self.owner.state,('control_ingress',self.role),
             table=self.table,column=column,key_columns=keys,key=key);return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Ingress exact row changed during EOF')
        if not self.column.advance(meter):return False
        value=self.column.require_v3(r)
        if self.table==_D07:
            from .d07_execution_v1 import SIGN_KIND
            if self.column.sha256!=self.header[0]:raise AuthorityUnavailable('Ingress signed D07 canonical EOF differs')
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,self.kind,self.ref,self.header[0])),self.header[1])
        elif self.table==_C04:
            if self.column.sha256!=self.header[1]:raise AuthorityUnavailable('Ingress C04 prepared canonical EOF differs')
        else:r.graph._GraphCoordinator__d11_issuer.resource_issuer._signer.verify('resource-quote.v1',canonical_serialize(value),self.header[0])
        self.value=value;self.complete=True;return True
    def close_v3(self):
        if self.column is not None:self.column.release_retention_v3()

class IngressRecallControlMetadataV3:
    def __init__(self,state):
        if state.source_complete or state.owner_entry is None:raise AuthorityUnavailable('Ingress metadata requires Owner before Source Body')
        self.state=state;self.tasks=[];self.index=0;self.records={};self.roots=set(state.current_roots);self.keys={}
        self.need=self.prepared=self.routing=self.selection=self.c04=None;self.complete=False
        from .d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1,NEED_OPERATION
        from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1,OPERATION
        from .d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1,ACQUIRE_OPERATION
        from .d07_ingress_recall_result_v1 import ADOPT_OPERATION
        from .d06_ingress_c03_selection_v1 import ingress_c03_selection_operation_id_v1
        from .d06_ingress_c03_read_v1 import OPERATION as SELECT
        ns=state.reader.namespace;c02=state.reader.selector.c02_operation_id;self.ids=ingress_recall_model_ids_v1(ns,c02)
        self._domain('need',ingress_recall_need_operation_id_v1(ns,c02),'d07',NEED_OPERATION)
        self._domain('c3',self.ids['prepare'],'d07',OPERATION)
        self.tasks.append(('prepared',_RowV3(self,'signed:prepared',_D07,'prepared',self.ids['job'])))
        self._domain('acquire',ingress_recall_acquire_operation_id_v1(ns,c02),'d11',ACQUIRE_OPERATION)
        for kind,ref in(('prepare_commit',self.ids['job']),('request',self.ids['job']),('call',self.ids['job']),
         ('paid_cost',self.ids['job']),('body_cost',self.ids['job']),('result','d07-result:'+self.ids['call']),('execution','d07-terminal:'+self.ids['call'])):
            self.tasks.append((kind,_RowV3(self,'signed:'+kind,_D07,kind,ref)))
        self._domain('routing',self.ids['adopt'],'d07',ADOPT_OPERATION)
        self.tasks.append(('adopted',_RowV3(self,'signed:adopted',_D07,'adopted',self.ids['adopt'])))
        self._domain('selection',ingress_c03_selection_operation_id_v1(ns,c02),'d06',SELECT)
        state.reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.roots,self.keys,tuple(task.__dict__ for _,task in self.tasks),self.need,self.prepared,self.routing,self.selection,self.c04))*3+8192
    def _domain(self,role,operation,domain,kind):self.tasks.append((role,_DomainV3(self,role,operation,domain,kind)))
    def _record(self,role):return next(task for name,task in self.tasks if name==role)
    def _versions(self,versions):
        for version in versions:
            key=version.key
            if NamespaceId.from_key(key)!=self.state.reader.namespace:raise AuthorityUnavailable('Ingress readset crossed namespace')
            self.keys[key.token,version.revision]=version
            if key.type_name=='memory.source':
                self.roots.add(key.token);old=self.state.expected_source_versions_v3.setdefault(key,version.revision)
                if old!=version.revision:raise AuthorityUnavailable('Ingress signed parents disagree on a Source version')
    def _publish(self,role,task):
        if isinstance(task,_DomainV3):
            identity=(_DOMAIN,task.kind,task.operation)
            if task.absent:self.records[identity]=None;return
            self._versions((*task.read_versions,*task.receipt.write_versions))
            entry={'projection':task.original,'header':task.header,'payload_digest':task.header[3],'operation_id':task.operation,
             'source_roots':(),'selector':None,'producer_header':task.header,'read_versions':task.read_versions,'write_versions':task.receipt.write_versions}
        else:
            identity=(task.table,task.kind,task.ref)
            if task.absent:self.records[identity]=None;return
            entry={'projection':task.value,'header':task.header,'payload_digest':task.column.sha256,'operation_id':None,
             'source_roots':(),'selector':None,'producer_header':None}
        self.records[identity]=entry
    def advance(self,meter):
        s=self.state;s.require_current_v3(meter);s.owner_entry.require_for_v3(s.reader)
        if self.complete:return True
        if self.index>=len(self.tasks):self._finish();return True
        role,task=self.tasks[self.index]
        if not task.advance(meter):return False
        self._publish(role,task);self._validate(role,task);self.index+=1;s.reader.operation.refresh_retained_state_v3(self);return False
    def _validate(self,role,task):
        s=self.state;r=s.reader;q=r.selector
        from .foreground_cycle_v1 import foreground_cycle_ids_v1,foreground_responsibility_ref_v1
        from .d11_types import runtime_job_key
        activity,cycle=foreground_cycle_ids_v1(r.namespace,q.c02_operation_id);cycle_ref=runtime_job_key(*r.namespace.as_tuple,activity,cycle).token
        if task.absent:
            if role in{'c3_quote','c04_quote'}:raise AuthorityUnavailable('Ingress actual signed original quote is absent')
            if role=='prepared'and not self._record('c3').absent:raise AuthorityUnavailable('Ingress actual C3 producer lost signed preparation')
            if role=='adopted'and not self._record('routing').absent:raise AuthorityUnavailable('Ingress actual routing producer lost signed adoption')
            if role=='c04_prepared'and not self._record('c04_prepare').absent:raise AuthorityUnavailable('Ingress actual C04 producer lost prepared original')
            return
        if role in{'request','call','paid_cost','body_cost','result','execution','acquire','routing'}and self.prepared is None:
            raise AuthorityUnavailable('Ingress child original has no actual complete signed C3 preparation')
        if role=='need':
            from ..domains.d07 import IngressRecallNeedV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            self.need=decode_typed_production_value_v1(task.original['provenance']['need'],IngressRecallNeedV1);n=self.need;responsibility=s.seed.responsibility
            if(n.c02_operation_id!=q.c02_operation_id or n.source_ref!=q.source_ref or n.cycle_job_ref!=cycle_ref or responsibility is None
             or(n.responsibility_ref,n.responsibility_digest)!=(foreground_responsibility_ref_v1(r.namespace,q.c02_operation_id),responsibility.digest)
             or n.cancel_generation or n.policy_digest!=r.bundle.d06_recall.policy_digest):raise AuthorityUnavailable('Ingress Need changed C02/Source/cycle/responsibility/policy')
            self._versions((GraphVersion(AtomKey.from_token(n.source_ref),n.source_revision),GraphVersion(AtomKey.from_token(n.focus_ref),n.focus_revision),
             GraphVersion(AtomKey.from_token(n.attention_ticket_ref),n.attention_ticket_revision)))
        elif role=='prepared':
            p=task.value;n=self.need;producer=self._record('c3')
            if(n is None or producer.absent or p.get('schema')!='d07.ingress-recall-prepared.v1'
             or p.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
             or(p.get('operation_id'),p.get('job_id'),p.get('call_id'),p.get('execution_id'),p.get('adoption_operation_id'))!=
              (self.ids['prepare'],self.ids['job'],self.ids['call'],self.ids['execution'],self.ids['adopt'])
             or(p.get('activity_id'),p.get('effect_id'),p.get('attempt_id'))!=(activity,self.ids['effect'],self.ids['attempt'])
             or p.get('work_kind')!='recall_need'or p.get('c02_operation_id')!=q.c02_operation_id
             or(p.get('cycle_job_ref'),p.get('need_ref'),p.get('need_digest'),p.get('responsibility_ref'),p.get('responsibility_digest'))!=
              (cycle_ref,'d07-current:'+self._record('need').header[3][:48],canonical_digest(n),n.responsibility_ref,n.responsibility_digest)
             or p.get('cancel_generation')or p.get('recall_policy_digest')!=n.policy_digest
             or producer.original['provenance'].get('prepared_digest')!=task.header[0]):raise AuthorityUnavailable('Ingress signed prepared lost exact actual Need/producer digest')
            import json
            authority=json.loads(p['self_authority_json'])
            producer_authority=producer.original.get('authority',{})
            if(authority.get('actor')!=r.current_self.self_entity_ref or authority.get('actor')!=producer_authority.get('actor')
             or tuple(p['audience'])!=tuple(producer_authority.get('audience',()))or p['purpose']!=producer_authority.get('purpose')):
                raise AuthorityUnavailable('Ingress C3 prepared changed actual Self/purpose/audience')
            self.prepared=p;self._versions(tuple(GraphVersion(AtomKey.from_token(row['ref']),row['revision'])for row in p['read_rows']))
            self.tasks.append(('c3_quote',_RowV3(self,'quote','runtime_resource_quotes','quote',(p['quote_id'],p['quote_version']))))
        elif role=='prepare_commit':
            producer=self._record('c3')
            if(self.prepared is None or task.value.get('schema')!='d07.preparation-commit.v1'
             or task.value.get('prepared_digest')!=self._record('prepared').header[0]or task.value.get('prepare_operation_id')!=self.ids['prepare']
             or task.value.get('graph_receipt_digest')!=canonical_digest(producer.receipt)):raise AuthorityUnavailable('Ingress C3 commit lost actual signed prepared/W01')
            self._versions(tuple(GraphVersion(AtomKey.from_token(row['ref']),row['revision'])for row in task.value['post_read_rows']))
        elif role=='adopted':
            raw=task.value;producer=self._record('routing')
            if(self.prepared is None or producer.absent or raw.get('schema')!='d07.ingress-recall-adoption.v1'
             or raw.get('c02_operation_id')!=q.c02_operation_id or raw.get('cycle_job_ref')!=cycle_ref or raw.get('adoption_operation_id')!=self.ids['adopt']
             or raw.get('prepared_digest')!=self._record('prepared').header[0]or raw.get('graph_receipt_digest')!=canonical_digest(producer.receipt)
             or{k:v for k,v in raw.items()if k!='graph_receipt_digest'}!=producer.original['provenance']['adoption']):raise AuthorityUnavailable('Ingress routing lost actual signed preparation/W01 adoption')
            self.routing=raw;self.roots.update(raw.get('selected_source_refs',()))
        elif role=='selection':self._selection(task,cycle_ref)
        elif role=='c04_prepared':self._c04(task)
        elif role in{'c3_quote','c04_quote'}:
            from .issuers import ResourceQuote
            raw=dict(task.value);raw['outbox_refs']=tuple(raw['outbox_refs']);raw['d02_settlement_refs']=tuple(raw['d02_settlement_refs']);quote=ResourceQuote(**raw)
            expected=self.prepared['quote_digest']if role=='c3_quote'else self.c04.binding.resource_quote_digest
            operation=self.ids['prepare']if role=='c3_quote'else self.c04.binding.operation_id
            if((quote.bot_id,quote.persona_id)!=r.namespace.as_tuple or quote.operation_id!=operation
             or quote.parent_budget_lease_ref!=s.seed.budget.lease or canonical_digest(quote)!=expected):raise AuthorityUnavailable('Ingress signed quote Root/operation/digest differs')
            s.recipe_quotes_v3.add((quote.quote_id,quote.version))
    def _selection(self,task,cycle_ref):
        s=self.state;r=s.reader;q=r.selector
        from .d06_ingress_c03_selection_v1 import C03DirectSelectionOriginalV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        value=decode_typed_production_value_v1(task.original['provenance']['selection'],C03DirectSelectionOriginalV1);receipt=task.receipt
        if(self.need is None or self.routing is None or value.namespace!=r.namespace or value.c02_operation_id!=q.c02_operation_id
         or(value.cycle_job_ref,value.cue_source_ref)!=(cycle_ref,q.source_ref)
         or(value.installation_id,value.manifest_digest)!=(r.bundle.installation_policy.installation_id,r.bundle.installation_policy.manifest_digest)
         or(value.need_ref,value.need_digest)!=('d07-current:'+self._record('need').header[3][:48],canonical_digest(self.need))
         or value.routing_adoption_ref!=self.ids['adopt']or value.routing_adoption_digest!=self._record('adopted').header[0]
         or(value.responsibility_ref,value.responsibility_digest)!=(self.need.responsibility_ref,self.need.responsibility_digest)
         or value.cancel_generation or(value.purpose,tuple(value.audience))!=(s.purpose,tuple(s.audiences))
         or len(receipt.invalidated_epochs)!=1 or receipt.invalidated_epochs[0].revision!=value.query_epoch.revision+1
         or task.original.get('writes')!=[]):raise AuthorityUnavailable('Ingress C03 lost actual Need/routing/Root/CAS bridge')
        self.selection=value;self._versions(value.source_family_read_versions)
        if value.selected_source_ref is None:return
        self._versions((GraphVersion(AtomKey.from_token(value.selected_source_ref),value.selected_source_revision),))
        from .c04_self_scope_v4 import ingress_c04_ids_v4,PREPARE_OPERATION
        from .c04_ingress_preparation_v4 import ADOPT_OPERATION
        self.c04_ids=ingress_c04_ids_v4(r.namespace,q.c02_operation_id,task.header[3]);self._domain('c04_prepare',self.c04_ids['prepare'],'d06',PREPARE_OPERATION)
        self.tasks.append(('c04_prepared',_RowV3(self,'c04',_C04,'prepared',self.c04_ids['prepare'])))
        self._domain('c04_adopt',self.c04_ids['adopt'],'d06',ADOPT_OPERATION)
    def _c04(self,task):
        s=self.state;r=s.reader;raw=dict(task.value);shape=dict(raw.pop('binding'))
        from ..authority_service.internal_work_contract import InternalWorkBindingV1
        from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
        from .c04_ingress_preparation_v4 import validate_self_c04_provenance_v4,PREPARE_OPERATION
        from ..graph_coordinator import namespace_ref
        binding=InternalWorkBindingV1(**shape);p=C04InternalWorkPreparedV1(binding=binding,**raw);producer=self._record('c04_prepare')
        if producer.absent:raise AuthorityUnavailable('Ingress C04 prepared lacks actual W01 producer')
        provenance=producer.original['provenance'];validate_self_c04_provenance_v4('d06',PREPARE_OPERATION,provenance)
        st=self._record('selection');selected=self.selection;bridge={'query_epoch':selected.query_epoch.revision,
         'commit_after_epoch':st.receipt.invalidated_epochs[0].revision,'metadata_receipt_digest':canonical_digest(st.receipt)}
        material=provenance.get('self_scope_original',{}).get('scope_payload')
        from .c04_prepare_service_v3 import c04_prepare_job_id_v3
        from .d11_types import runtime_job_key
        child_ref=runtime_job_key(*r.namespace.as_tuple,selected.child_activity_id,c04_prepare_job_id_v3(r.namespace,binding.operation_id)).token
        if(material is None or(binding.namespace,binding.operation_id,binding.execution_id,binding.activity_id)!=
          (namespace_ref(r.namespace),self.c04_ids['prepare'],self.c04_ids['execution'],selected.child_activity_id)
         or binding.parent_budget_lease_ref!=s.seed.budget.lease or p.prepared_digest!=task.header[1]or binding.binding_digest!=task.header[0]
         or provenance['child_job_ref']!=child_ref
         or provenance['prepared_digest']!=task.header[1]or provenance['binding_digest']!=task.header[0]
         or material['selection_original_digest']!=st.header[3]or material['c03_metadata_bridge']!=bridge
         or material['request']['c02_operation_id']!=r.selector.c02_operation_id or material['request']['job_ref']!=selected.cycle_job_ref
         or material['request']['recall_policy_digest']!=r.bundle.d06_recall.policy_digest
         or material['request']['source_ref']!=r.selector.source_ref or material['request']['c03_selection_ref']!='d06-current:'+st.header[3][:48]
         or material['request']['c03_selection_digest']!=canonical_digest(selected)or provenance['selection_ref']!='d06-current:'+st.header[3][:48]
         or provenance['initiating_self']!=r.current_self.self_entity_ref):raise AuthorityUnavailable('Ingress C04 native prepared/Root/C03 bridge differs')
        self.c04=p;self._versions(tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in p.read_versions))
        self.tasks.append(('c04_quote',_RowV3(self,'quote','runtime_resource_quotes','quote',(binding.resource_quote_ref,binding.resource_quote_version))))
    def _finish(self):
        s=self.state;r=s.reader
        for ref in self.roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable('Ingress metadata declares a foreign/non-Source root')
        roots=tuple(dict.fromkeys((*s.current_roots,*sorted(self.roots))));s.current_roots=roots
        for identity,entry in self.records.items():
            if entry is not None:entry['source_roots']=roots;s.verified_metadata_v3[identity]=entry
        special={ref for spec in s.special_source_groups_v3 for ref in spec[1]};ordinary=tuple(ref for ref in roots if ref not in special)
        s.group_specs=[('control:'+str(i//32),ordinary[i:i+32],s.purpose,s.audiences)for i in range(0,len(ordinary),32)]+s.special_source_groups_v3;self.complete=True
    def close_v3(self):
        for _,task in self.tasks:task.close_v3()
        self.state.reader.operation.unregister_retained_state_v3(self)

def index_ingress_control_points_v3(s,roots):
    task=getattr(s,'ingress_recall_metadata',None)
    if task is None:return
    if not task.complete or not s.source_complete:raise AuthorityUnavailable('Ingress point index precedes actual metadata/Source ALL')
    from .artifact_host_control_recipes_v3 import _operation,_put,_job,_graph,_D07_COLUMNS
    for role,original in task.tasks:
        if isinstance(original,_DomainV3):_operation(s,original.operation,roots,('actual_ingress_recall',),(role,),None if original.absent else original.receipt.activity_id)
        elif original.table==_D07:
            key=(*s.reader.namespace.as_tuple,original.kind,original.ref)
            for column in _D07_COLUMNS:_put(s,_D07,('bot','persona','kind','original_ref'),key,column,'signed_original',roots,('actual_ingress_recall',),(role,))
            entry=task.records[_D07,original.kind,original.ref]
            s.recipe_originals_v3[_D07,original.kind,original.ref]={'roots':tuple(roots),'parent':('actual_ingress_recall',),'field':(role,),'digest':None if entry is None else entry['payload_digest']}
        elif original.table==_C04:
            for column in('binding_digest','prepared_digest','prepared_json'):_put(s,_C04,('bot','persona','operation_id'),(*s.reader.namespace.as_tuple,original.ref),column,'domain_original',roots,('actual_ingress_recall',),(role,))
    for version in task.keys.values():_graph(s,version.key.token,roots,('actual_ingress_recall',),('readset',),version.revision)
    if task.prepared is not None:
        p=task.prepared;_job(s,p['job_id'],p['activity_id'],roots,('actual_ingress_recall',),('c3_job',))
    if task.c04 is not None:
        from .c04_prepare_service_v3 import c04_prepare_job_id_v3
        p=task.c04;_job(s,c04_prepare_job_id_v3(s.reader.namespace,p.binding.operation_id),p.binding.activity_id,roots,('actual_ingress_recall',),('c04_job',))

def read_ingress_control_signed_metadata_v3(s,table,kind,ref):
    task=getattr(s,'ingress_recall_metadata',None)
    if task is None or(table,kind,ref)not in task.records:return False,None
    if not task.complete or not s.source_complete:raise AuthorityUnavailable('Ingress Body precedes actual metadata/Source ALL')
    return True,task.records[table,kind,ref]
