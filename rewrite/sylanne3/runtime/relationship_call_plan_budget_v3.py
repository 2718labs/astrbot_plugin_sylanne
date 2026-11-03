"""D05-only complete CallPlan budget metadata in the actual qualified Method Work."""
from dataclasses import asdict,replace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .foreground_call_plan_v1 import SLOTS,ForegroundModelAttemptV1,ForegroundModelAttemptV2
from .dispatch_current_inventory_v3 import _heap

_KEY=object()
_TASKS=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()
_JOB=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','work_kind','budget_ref',
    'phase','fence','cancel_epoch','lease_holder','result_ref')
_PREPARED_FIELDS=('schema','namespace','operation_id','activity_id','effect_id','attempt_id','job_id','call_id',
    'execution_id','work_kind','stage_input_digest','quote_id','quote_version','quote_digest','reservation_digest',
    'model_request_digest','cycle_ref','cycle_digest','call_plan_digest','c02_operation_id','cancel_generation',
    'semantic_question_ref','semantic_question_digest','cycle_job_ref','selector','parent_budget_lease_ref','installation_id',
    'manifest_digest','acquire_operation_id','prepare_operation_id','binding_digest','body_quote_ref','body_quote_version','body_quote_digest',
    'body_reservation_ref','body_policy_id','body_policy_version','frozen_digest','frozen_ref')
_COST_FIELDS=('schema','paid','unpaid_cost','unknown_dimensions','prepared_digest','cost_ref','result_original_ref',
    'result_original_digest','terminal_receipt_digest','terminal_digest','status','quote_id','quote_version','cost_value','budget_receipt','result_ref','result_digest','call_id','job_id','operation_id','activity_id','effect_id',
    'execution_id','parent_budget_ref','input_digest','terminal_ref','cost_receipt_refs','digest','input_tokens','output_tokens')


def _state_v3(reader):
    from .current_relationship_source_read_v3 import require_current_relationship_numeric_reader_v3
    return require_current_relationship_numeric_reader_v3(reader)


def _require_task_v3(task,meter=None):
    state=_state_v3(task.reader)
    if(_TASKS.get(task)!=(task.reader,task.reader.work,task.reader.operation,task.selector)
            or state.numeric_budget_tasks.get(task.selector)is not task
            or state.numeric_prepared is not task.prepared
            or (state.numeric_interpretation_ref,state.numeric_prepared_digest)!=task.selector):
        raise AuthorityUnavailable('D05 CallPlan budget lost its exact qualified Method owner/selection')
    task.reader.require_current(meter=meter)
    return state


class PreparedRelationshipCallPlanBudgetV3:
    def __init__(self,key,task,attempts):
        if key is not _KEY or not task.complete:raise TypeError('actual complete D05 CallPlan metadata issuer required')
        self.task,self.attempts=task,tuple(attempts)
        self.auxiliary_calls=sum(SLOTS[value.slot][3]for value in self.attempts)
        _PROOFS[self]=(task,self.attempts,self.auxiliary_calls)
    def require_v3(self,db,namespace,interpretation_ref,prepared,policy):
        task=self.task;_require_task_v3(task)
        if(_PROOFS.get(self)!=(task,self.attempts,self.auxiliary_calls)or db is not task.reader.db
                or not db.in_transaction or namespace!=task.reader.namespace or prepared is not task.prepared
                or interpretation_ref!=task.selector[0]):
            raise AuthorityUnavailable('D05 CallPlan budget proof crossed its exact actual consumer')
        with runtime_storage_quantum_v3(db)as meter:task.require_headers_v3(meter)
        if self.auxiliary_calls>policy.max_auxiliary_calls:
            from .d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1('relationship_shared_auxiliary_call_cap')
        return self


class _RelationshipCallPlanBudgetTaskV3:
    def __init__(self,key,reader,selector):
        if key is not _KEY:raise TypeError('actual D05 budget task issuer required')
        state=_state_v3(reader)
        if selector!=(state.numeric_interpretation_ref,state.numeric_prepared_digest):
            raise AuthorityUnavailable('D05 CallPlan budget selector differs from its signed preparation')
        self.reader,self.selector,self.prepared=reader,selector,state.numeric_prepared
        self.profiles,self.tasks,self.headers,self.observed={},{},[],[]
        self.committed_digests={}
        self.current=self.result=None;self.cycle=self.plan=None;self.complete=False;self.index=0;self.meter=None
        self.program=self._program_v3()
        _TASKS[self]=(reader,reader.work,reader.operation,selector)
        state.numeric_budget_tasks[selector]=self
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.profiles,self.headers,tuple(asdict(value)for value in self.observed),self.committed_digests,
            None if self.cycle is None else asdict(self.cycle)))+65536
    def fixed_v3(self,table,columns,where,key):
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        r=self.reader;row=_beta1_metadata_row_v3(r,self.meter,table,columns,where,key)
        r.operation.reserve_retained_state_growth_v3(self,_heap(row)*2+4096)
        try:self.headers.append((table,columns,where,key,row))
        finally:r.operation.finish_retained_state_growth_v3(self)
        return row
    def json_v3(self,table,column,keys,key,headers,paths):
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        state=_require_task_v3(self,self.meter)
        self.reader.operation.reserve_retained_state_growth_v3(self,16384)
        try:
            identity=('relationship_budget',self.selector,self.index);self.index+=1
            self.profiles[identity]=(table,column,tuple(keys),tuple(key),tuple(headers),tuple(paths),None)
            state.selected.add(identity)
            child=create_current_beta1_metadata_task_v3(self.reader,identity);self.tasks[identity]=child
        finally:self.reader.operation.finish_retained_state_growth_v3(self)
        while not child.complete:yield child
        child.require_header_v3(self.meter)
        return child.result,child
    def original_v3(self,table,kind,ref,fields,sign_kind=None):
        ns=self.reader.namespace;headers=('payload_digest','signature')if sign_kind else('payload_digest',)
        value,task=yield from self.json_v3(table,'payload_json',('bot','persona','kind','original_ref'),
            (*ns.as_tuple,kind,ref),headers,tuple((name,)if type(name)is str else name for name in fields))
        if value is None:return None,None
        if task.column.canonical_digest!=task.metadata[0]:raise AuthorityUnavailable('D05 slot original lost complete canonical SHA')
        if sign_kind:
            self.reader.graph._GraphCoordinator__d11_issuer._signer.verify(sign_kind,
                canonical_serialize((ns,kind,ref,task.metadata[0])),task.metadata[1])
        return value,task.metadata[0]
    def job_v3(self,job_id):
        row=self.fixed_v3('runtime_jobs',_JOB,'job_id=?',(job_id,))
        if row is None:return None
        value=dict(zip(_JOB,row))
        if(value['bot_id'],value['persona_id'])!=self.reader.namespace.as_tuple:
            raise AuthorityUnavailable('D05 slot job crossed its actual namespace')
        return value
    def require_headers_v3(self,meter):
        _require_task_v3(self,meter)
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        for table,columns,where,key,expected in self.headers:
            if _beta1_metadata_row_v3(self.reader,meter,table,columns,where,key)!=expected:
                raise AuthorityUnavailable('D05 complete CallPlan metadata changed before its actual consumer')
        for task in self.tasks.values():task.require_header_v3(meter)
    def advance(self,meter):
        _require_task_v3(self,meter);self.meter=meter
        try:
            if self.complete:self.require_headers_v3(meter);return True
            if self.current is not None:
                if not self.current.advance(meter):return False
                self.current=None
            try:self.current=next(self.program)
            except StopIteration:
                self.complete=True;self.result=PreparedRelationshipCallPlanBudgetV3(_KEY,self,self.observed)
            return self.complete
        finally:
            self.reader.operation.refresh_retained_state_v3(self)
            self.meter=None

    def quote_v3(self,quote_id,version):
        from .issuers import ResourceQuote
        value,task=yield from self.json_v3('runtime_resource_quotes','quote_json',('quote_id','version'),
            (quote_id,version),('signature',),tuple((name,)for name in ResourceQuote.__dataclass_fields__))
        if value is None:raise AuthorityUnavailable('D05 slot has no actual signed resource quote')
        if canonical_digest(value)!=task.column.canonical_digest:raise AuthorityUnavailable('D05 signed quote whole EOF differs')
        self.reader.graph._GraphCoordinator__d11_issuer.resource_issuer._signer.verify('resource-quote.v1',canonical_serialize(value),task.metadata[0])
        raw=dict(value);raw['outbox_refs']=tuple(raw['outbox_refs']);raw['d02_settlement_refs']=tuple(raw['d02_settlement_refs'])
        quote=ResourceQuote(**raw)
        if(quote.quote_id,quote.version,quote.bot_id,quote.persona_id)!=(quote_id,version,*self.reader.namespace.as_tuple):
            raise AuthorityUnavailable('D05 quote crossed its exact slot/namespace')
        return quote
    def reservation_v3(self,lease_id,operation_id):
        head=self.fixed_v3('runtime_budget_reservations',('digest','state'),'lease_id=? AND operation_id=?',(lease_id,operation_id))
        value,task=yield from self.json_v3('runtime_budget_reservations','ceiling_json',('lease_id','operation_id'),
            (lease_id,operation_id),('digest','state'),((),))
        if head is None or value is None:raise AuthorityUnavailable('D05 slot actual budget reservation absent')
        return head,value
    def committed_v3(self,operation_id):
        key=(*self.reader.namespace.as_tuple,operation_id)
        head=self.fixed_v3('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        value,task=yield from self.json_v3('graph_bundle_operations','receipt_json',('bot','persona','operation_id'),key,
            ('digest','activity_id','effect_id','commit_seq'),(('commit_seq',),('ledger_refs',),('outbox_refs',),('phase',),
            ('prepared_digest',),('seal_digest',),('review_seal_digest',),('job_ref',),('review_job_ref',),
            ('c02_operation_id',),('source_ref',),('generation_original_operation_id',),('relationship_c3',),('quote_id',),('reservation_digest',)))
        if head is None or value is None or head[3]<1:
            raise AuthorityUnavailable('D05 slot protocol original lacks actual committed Graph receipt')
        if 'commit_seq'in value and value['commit_seq']!=head[3]:raise AuthorityUnavailable('D05 slot Graph receipt sequence differs')
        event=self.fixed_v3('graph_events',('digest','epoch_revision'),'bot=? AND persona=? AND session=? AND event_id=?',
            (*self.reader.namespace.as_tuple,head[1],operation_id))
        if event is None:raise AuthorityUnavailable('D05 slot protocol original lacks actual Graph event')
        from ..runtime_contracts import CommitReceipt
        from ..graph_types import AtomKey,GraphVersion,NamespaceEpoch
        eventkey=(*self.reader.namespace.as_tuple,head[1],operation_id)
        reads,reads_task=yield from self.json_v3('graph_events','reads',('bot','persona','session','event_id'),eventkey,
            ('digest','epoch_revision'),((),))
        writes,writes_task=yield from self.json_v3('graph_events','revisions',('bot','persona','session','event_id'),eventkey,
            ('digest','epoch_revision'),((),))
        actual=CommitReceipt('committed',operation_id,head[0],head[1],head[2],head[3],
            tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads),
            tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in writes),
            (NamespaceEpoch(*self.reader.namespace.as_tuple,event[1]),),tuple(value['ledger_refs']),tuple(value['outbox_refs']))
        self.committed_digests[operation_id]=canonical_digest(actual)
        return head,value,event
    def prepared_attempt_v3(self,attempt):
        ns=self.reader.namespace
        kinds=('d07.concern','d07.reflection','d07.recall_need')if attempt.slot=='C3'else('artifact_draft_v1',)
        rows=self.reader.db.execute('SELECT job_id,work_kind FROM runtime_jobs WHERE bot_id=? AND persona_id=? '
            'AND operation_id=? AND work_kind IN ('+','.join('?'for _ in kinds)+') ORDER BY job_id LIMIT 2',
            (*ns.as_tuple,attempt.reservation_operation_id,*kinds)).fetchall()
        self.meter.charge_read(sum(len(row[0].encode('utf8'))+len(row[1].encode('utf8'))+128 for row in rows))
        if len(rows)!=1:raise AuthorityUnavailable('D05 attempt lacks its unique actual namespace/operation RuntimeJob producer')
        job=rows[0][0]
        actual=self.fixed_v3('runtime_jobs',('job_id','work_kind','operation_id'),'job_id=?',(job,))
        if actual!=(job,rows[0][1],attempt.reservation_operation_id):raise AuthorityUnavailable('D05 attempt job locator changed')
        if attempt.slot=='C3':
            raw,digest=yield from self.original_v3('graph_d07_execution_originals_v1','prepared',job,_PREPARED_FIELDS,'d07.execution-original.v1')
            if raw is None or raw['call_id']!=attempt.call_id or raw['operation_id']!=attempt.reservation_operation_id:
                raise AuthorityUnavailable('D05 C3 actual job/prepared/call binding differs')
            return raw,digest,False
        found=[]
        for kind in('c4_prepared','c4_phase_prepared'):
            raw,digest=yield from self.original_v3('graph_d11_life_originals_v1',kind,job,_PREPARED_FIELDS,'d11.life-original.v1')
            if raw is not None:found.append((raw,digest,kind=='c4_phase_prepared'))
        if len(found)!=1 or found[0][0]['call_id']!=attempt.call_id or found[0][0]['operation_id']!=attempt.reservation_operation_id:
            raise AuthorityUnavailable('D05 C4 actual job has ambiguous/missing registered prepared version')
        return found[0]
    def common_attempt_v3(self,slot,p,digest,attempt):
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        quote=yield from self.quote_v3(p['quote_id'],1 if slot=='C4'else p['quote_version'])
        head,ceiling=yield from self.reservation_v3(quote.parent_budget_lease_ref,p['operation_id'])
        parent=self.plan.protected_reply_lease_ref if slot in('C5','C6')else self.plan.parent_budget_lease_ref
        if(quote.parent_budget_lease_ref!=parent or canonical_digest(quote)!=p['quote_digest']
                or quote.work_kind!=SLOTS[slot][0]or head[0]!=p['reservation_digest']
                or ceiling!=dict(quote.ceiling)):
            raise AuthorityUnavailable('D05 slot quote/reservation/root differs from its actual original')
        base=ForegroundModelAttemptV1(slot,p['call_id'],None,p['operation_id'],head[0],parent,
            quote.ceiling['input_tokens'],quote.ceiling['output_tokens'],'reserved')
        if attempt is not None:
            expected=replace(attempt,state='reserved',terminal_ref=None)
            if(type(expected)is ForegroundModelAttemptV1 and expected!=base
                    or (expected.call_id,expected.reservation_operation_id,expected.reservation_digest,expected.budget_lease_ref,
                        expected.input_ceiling,expected.output_ceiling)!=(base.call_id,base.reservation_operation_id,
                        base.reservation_digest,base.budget_lease_ref,base.input_ceiling,base.output_ceiling)):
                raise AuthorityUnavailable('D05 official CallPlan attempt differs from actual physical reservation')
            base=replace(attempt,state='reserved',terminal_ref=None)
        job=self.job_v3(p['job_id'])
        if job is None or job['operation_id']!=p['operation_id']or job['budget_ref']!=parent:
            raise AuthorityUnavailable('D05 slot original changed its actual job/budget')
        return base,job,head,quote
    def natural_v3(self,stage,generation=None):
        from .natural_reply_job_v2 import _table,_seal,natural_job_ids_v2
        from .model_cost_settlement import original_model_cost_operation_id_v1
        ns=self.reader.namespace;ids=natural_job_ids_v2(ns,self.cycle.c02_operation_id,stage)
        table=_table(stage);key=(*ns.as_tuple,self.cycle.c02_operation_id)
        row=self.fixed_v3(table,('state','terminal_receipt_digest'),'bot=? AND persona=? AND parent_original_id=?',key)
        value,task=yield from self.json_v3(table,'seal_json',('bot','persona','parent_original_id'),key,
            ('state','terminal_receipt_digest'),tuple((name,)for name in _natural_seal_fields_v3(stage)))
        if value is None:
            if self.job_v3(ids[0])is not None:raise AuthorityUnavailable('D05 absent natural seal cannot hide actual child job')
            return None
        seal=_seal(stage,value)
        if((seal.job_id,seal.original_operation_id,seal.acquire_operation_id,seal.call_id,seal.reservation_operation_id)!=ids
                or seal.namespace!=ns or row[0]not in('queued','acquired','terminal')
                or (row[0]=='terminal')!=(row[1]is not None)):
            raise AuthorityUnavailable('D05 natural slot metadata differs from actual closed seal/state')
        job=self.job_v3(seal.job_id)
        bundle,receipt,event=yield from self.committed_v3(seal.original_operation_id)
        quote=yield from self.quote_v3(receipt['quote_id'],1)
        reserved,ceiling=yield from self.reservation_v3(seal.parent_budget_lease_id,seal.reservation_operation_id)
        if reserved[0]!=receipt['reservation_digest']:
            raise AuthorityUnavailable('D05 natural slot actual original reservation commitment differs')
        name='seal_digest'if stage=='generation'else'review_seal_digest';ref='job_ref'if stage=='generation'else'review_job_ref'
        from .d11_types import runtime_job_key
        if job is None:raise AuthorityUnavailable('D05 natural seal has no actual RuntimeJob')
        jobref=runtime_job_key(*ns.as_tuple,job['activity_id'],job['job_id']).token
        if(job is None or job['operation_id']!=seal.original_operation_id or job['work_kind']!='natural_'+stage
                or seal.parent_budget_lease_id!=self.plan.protected_reply_lease_ref or job['budget_ref']!=seal.parent_budget_lease_id
                or quote.parent_budget_lease_ref!=seal.parent_budget_lease_id
                or quote.work_kind!='natural_'+stage or ceiling!=dict(quote.ceiling)
                or receipt[name]!=canonical_digest(asdict(seal))or receipt[ref]!=jobref or bundle[1]!=job['activity_id']):
            raise AuthorityUnavailable('D05 natural slot lost its actual seal/Graph/job/signed quote lineage')
        if stage=='generation':
            if receipt['c02_operation_id']!=self.cycle.c02_operation_id or receipt['source_ref']!=self.cycle.source_ref or seal.source_ref!=self.cycle.source_ref:
                raise AuthorityUnavailable('D05 natural generation belongs to another actual C02 Source')
        elif(generation is None or seal.generation_original_operation_id!=generation.original_operation_id
                or seal.generation_call_id!=generation.call_id or receipt['generation_original_operation_id']!=generation.original_operation_id):
            raise AuthorityUnavailable('D05 natural review changed its actual generation lineage')
        terminal=None
        if row[0]=='terminal':
            terminal=original_model_cost_operation_id_v1(ns,seal.call_id)
            yield from self.committed_v3(terminal)
            if job['phase']!='completed':raise AuthorityUnavailable('D05 natural terminal has no actual completed job')
        state='completed'if terminal else'unknown'if reserved[1]in('unknown','partial_unknown','unconfirmed')else'dispatch_started'if row[0]=='acquired'else'reserved'
        slot='C5'if stage=='generation'else'C6'
        self.observed.append(ForegroundModelAttemptV1(slot,seal.call_id,None,seal.reservation_operation_id,reserved[0],
            seal.parent_budget_lease_id,ceiling['input_tokens'],ceiling['output_tokens'],state,terminal))
        return seal

    def job_quote_v3(self,job_id):
        value,task=yield from self.json_v3('runtime_jobs','operator_versions_json',('job_id',),(job_id,),
            ('job_id','operation_id','phase','fence','cancel_epoch'),(('resource_quote',),))
        if value is None or 'resource_quote'not in value:raise AuthorityUnavailable('D05 slot job lacks its original signed quote locator')
        quote,version=value['resource_quote'].rsplit(':',1)
        return quote,int(version)
    def c1_v3(self):
        from .terminal_c02_recovery_candidate_v2 import FrozenTerminalC02CandidateV2
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .model_cost_settlement import original_model_cost_operation_id_v1
        from ..memory_types import source_key
        ns=self.reader.namespace;key=(*ns.as_tuple,self.cycle.c02_operation_id)
        raw,task=yield from self.json_v3('graph_first_ingress_c02_committed_seals_v2','seal_json',('bot','persona','operation_id'),key,
            ('bundle_digest',),tuple((name,)for name in FrozenTerminalC02CandidateV2.__dataclass_fields__))
        if raw is None:raise AuthorityUnavailable('D05 CallPlan has no actual archived C1 C02 metadata seal')
        seal=decode_typed_production_value_v1(raw,FrozenTerminalC02CandidateV2);original=seal.original_key
        if seal.bundle_digest!=task.metadata[0]or original.namespace!=ns or seal.consumer_operation_id!=self.cycle.c02_operation_id:
            raise AuthorityUnavailable('D05 C1 archived seal differs from actual C02 origin')
        binding=self.fixed_v3('runtime_encoding_call_bindings_v1',('source_id','source_revision','access_revision','budget_lease_id',
            'budget_reservation_operation_id','binding_digest','model_request_digest','call_id'),'bot=? AND persona=? AND job_id=?',
            (*ns.as_tuple,original.job_id))
        job=self.job_v3(original.job_id)
        if(binding is None or job is None or job['phase']!='completed' or binding[3]!=self.plan.parent_budget_lease_ref
                or (binding[5],binding[6],binding[7])!=(original.binding_digest,original.model_request_digest,original.call_id)
                or self.cycle.source_ref!=source_key(*ns.as_tuple,binding[0]).token):
            raise AuthorityUnavailable('D05 C1 actual completed encoding job/call/Source/budget differs')
        qid,version=yield from self.job_quote_v3(original.job_id)
        quote=yield from self.quote_v3(qid,version)
        archived,archived_task=yield from self.json_v3('graph_first_ingress_c02_committed_seals_v2','quote_json',('bot','persona','operation_id'),key,
            ('bundle_digest',),tuple((name,)for name in quote.__dataclass_fields__))
        if canonical_digest(archived)!=canonical_digest(quote)or canonical_digest(quote)!=seal.quote_digest or(quote.quote_id,quote.version)!=(seal.quote_id,seal.quote_version):
            raise AuthorityUnavailable('D05 C1 actual archived signed quote differs')
        reservation,ceiling=yield from self.reservation_v3(binding[3],binding[4])
        if quote.work_kind!='d06.encode_source'or quote.parent_budget_lease_ref!=binding[3]or ceiling!=dict(quote.ceiling):
            raise AuthorityUnavailable('D05 C1 original reservation differs from actual signed quote')
        committed,receipt,event=yield from self.committed_v3(self.cycle.c02_operation_id)
        if committed[0]!=seal.bundle_digest:raise AuthorityUnavailable('D05 C1 seal lacks its actual adopted C02 bundle')
        terminal=original_model_cost_operation_id_v1(ns,binding[7]);yield from self.committed_v3(terminal)
        self.observed.append(ForegroundModelAttemptV1('C1',binding[7],None,binding[4],reservation[0],binding[3],
            ceiling['input_tokens'],ceiling['output_tokens'],'completed',terminal))
    def c2_v3(self):
        from .d04_product_pipeline_v3 import ids
        identity=ids(self.reader.namespace,self.cycle.c02_operation_id)
        p,digest=yield from self.original_v3('graph_d04_originals_v3','appraisal',identity['job'],_PREPARED_FIELDS)
        if p is None:
            if self.job_v3(identity['job'])is not None:raise AuthorityUnavailable('D05 absent C2 original cannot hide actual job')
            return
        if(p['operation_id'],p['job_id'],p['call_id'])!=(identity['operation'],identity['job'],identity['call']):
            raise AuthorityUnavailable('D05 C2 original belongs to another actual C02')
        base,job,reservation,quote=yield from self.common_attempt_v3('C2',p,digest,None)
        yield from self.committed_v3(p['operation_id'])
        paid,paid_digest=yield from self.original_v3('graph_d04_originals_v3','appraisal_cost',p['job_id'],_COST_FIELDS)
        terminal=None
        if paid is not None:
            result,result_digest=yield from self.original_v3('graph_d04_originals_v3','appraisal_result',paid['result_original_ref'],
                ('schema','prepared_digest','request_digest','output_digest','call_id','operation_id'))
            if(paid['paid']is not True or paid['prepared_digest']!=digest or result is None
                    or result_digest!=paid['result_original_digest']or job['phase']!='completed'):
                raise AuthorityUnavailable('D05 C2 actual paid/result/terminal original differs')
            terminal=paid['result_original_ref']
        state='completed'if terminal else'unknown'if reservation[1]in('unknown','partial_unknown','unconfirmed')else'dispatch_started'if job['phase']=='running'else'reserved'
        self.observed.append(replace(base,state=state,terminal_ref=terminal))
    def c3_v3(self,attempt,p,digest):
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        from .d07_execution_v1 import TABLE,SIGN_KIND
        target=attempt.call_id==self.prepared.call_id
        if(p['call_id']!=attempt.call_id or p['operation_id']!=attempt.reservation_operation_id
                or p.get('c02_operation_id')!=self.cycle.c02_operation_id
                or (p.get('cycle_job_ref')!=self.prepared.cycle_ref.key.token if p['schema']=='d07.ingress-recall-prepared.v1'
                    else p.get('cycle_ref',{}).get('key')!=asdict(self.prepared.cycle_ref.key))
                or p['namespace']!=asdict(self.reader.namespace)):
            raise AuthorityUnavailable('D05 C3 complete preparation crossed its actual cycle/call')
        if target and digest!=self.prepared.digest:raise AuthorityUnavailable('D05 target C3 differs from actual Source-qualified preparation')
        base,job,reservation,quote=yield from self.common_attempt_v3('C3',p,digest,attempt)
        prepared_commit,prepared_commit_digest=yield from self.original_v3(TABLE,'prepare_commit',p['job_id'],
            ('schema','prepared_digest','graph_receipt_digest','prepare_operation_id','operation_id','job_id'),SIGN_KIND)
        if prepared_commit is None or prepared_commit['prepared_digest']!=digest:
            raise AuthorityUnavailable('D05 C3 has no actual committed preparation original')
        yield from self.committed_v3(prepared_commit['prepare_operation_id'])
        if self.committed_digests[prepared_commit['prepare_operation_id']]!=prepared_commit['graph_receipt_digest']:
            raise AuthorityUnavailable('D05 C3 preparation lost its complete actual W01 receipt')
        sealed,sealed_digest=yield from self.original_v3(TABLE,'call',p['job_id'],tuple(ModelEgressIntentV1.__dataclass_fields__),SIGN_KIND)
        intent=None if sealed is None else from_wire(sealed,ModelEgressIntentV1)
        if intent is not None and(intent.job_id!=p['job_id']or intent.call_id!=p['call_id']or intent.binding_digest!=digest
                or intent.budget_lease_id!=quote.parent_budget_lease_ref or intent.budget_reservation_operation_id!=p['operation_id']
                or intent.budget_reservation_digest!=p['reservation_digest']or intent.worker_fence!=job['fence']):
            raise AuthorityUnavailable('D05 C3 sealed actual call differs from its job/preparation/reservation')
        paid,paid_digest=yield from self.original_v3(TABLE,'paid_cost',p['job_id'],_COST_FIELDS,SIGN_KIND)
        body,body_digest=yield from self.original_v3(TABLE,'body_cost',p['job_id'],_COST_FIELDS,SIGN_KIND)
        execution,execution_digest=yield from self.original_v3(TABLE,'execution','d07-terminal:'+p['call_id'],_COST_FIELDS,SIGN_KIND)
        result,result_digest=yield from self.original_v3(TABLE,'result','d07-result:'+p['call_id'],
            ('schema','request','terminal_receipt',('observation','subject'),('observation','operation_id'),
             ('observation','call_id'),('observation','request_digest'),('observation','status')),SIGN_KIND)
        terminal=None
        if execution is not None:
            if(intent is None or result is None or paid is None or body is None or paid['paid']is not True
                    or paid['unknown_dimensions']or body['unpaid_cost']or job['phase']!='completed'
                    or job['result_ref']!=execution['terminal_ref']or execution['input_digest']!=p['stage_input_digest']
                    or (execution['operation_id'],execution['activity_id'],execution['effect_id'],execution['execution_id'],execution['parent_budget_ref'])
                        !=(p['operation_id'],p['activity_id'],p['effect_id'],p['execution_id'],quote.parent_budget_lease_ref)
                    or execution['cost_receipt_refs']!=[paid['cost_ref']]):
                raise AuthorityUnavailable('D05 C3 completed attempt lacks its actual signed result/paid/body/terminal chain')
            request=result['request'];observed=result['observation'];receipt=result['terminal_receipt']
            if((request['namespace'],request['job_id'],request['call_id'],request['original_operation_id'],request['binding_digest'],request['model_request_digest'])
                        !=(asdict(self.reader.namespace),p['job_id'],p['call_id'],p['operation_id'],digest,intent.request_digest)
                    or request['acquire_operation_id']!=intent.acquire_operation_id
                    or(observed['subject'],observed['operation_id'],observed['call_id'],observed['request_digest'])
                        !=(intent.subject,intent.operation_id,intent.call_id,intent.request_digest)
                    or(receipt['call_id'],receipt['request_digest'])!=(p['call_id'],intent.request_digest)
                    or canonical_digest(receipt)!=paid['terminal_digest']or receipt['observation_digest']!=paid['result_digest']
                    or(body['prepared_digest'],body['terminal_digest'],body['result_digest'])!=(digest,paid['terminal_digest'],paid['result_digest'])):
                raise AuthorityUnavailable('D05 C3 actual scoped result/cost terminal metadata differs from the sealed call')
            terminal=execution['terminal_ref']
        if paid is not None and paid['prepared_digest']!=digest:
            raise AuthorityUnavailable('D05 C3 paid original changed its actual preparation')
        if target:
            adopted,adopted_digest=yield from self.original_v3(TABLE,'adopted',self.selector[0],
                ('schema','interpretation_ref','interpretation_revision','interpretation_value_digest','adoption_operation_id',
                 'graph_receipt_digest','prepared_digest','actual_result_digest','question_scope'),SIGN_KIND)
            state=_state_v3(self.reader)
            if(adopted is None or adopted_digest!=state.numeric_adopted_digest or adopted['prepared_digest']!=digest
                    or adopted['actual_result_digest']!=result_digest or terminal is None):
                raise AuthorityUnavailable('D05 target relationship C3 has no unique complete actual adoption/result/terminal chain')
            yield from self.committed_v3(adopted['adoption_operation_id'])
            if self.committed_digests[adopted['adoption_operation_id']]!=adopted['graph_receipt_digest']:
                raise AuthorityUnavailable('D05 C3 adopted interpretation lost its actual complete W01 receipt')
        state='completed'if terminal else'unknown'if intent is not None or paid is not None or reservation[1]in('unknown','partial_unknown','unconfirmed')else'not_dispatched'if job['phase']in('failed','cancelled')else'reserved'
        self.observed.append(replace(base,state=state,terminal_ref=terminal))

    def c4_v3(self,attempt,p,digest,phase):
        from ..model_broker.artifact_draft_v1 import (artifact_draft_from_wire_v1,artifact_draft_from_wire_v2,
            ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2)
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        kind='c4_phase_'if phase else'c4_'
        selector=(artifact_draft_from_wire_v2(p['selector'],ArtifactDraftPhaseSelectorV2)if phase else
            artifact_draft_from_wire_v1(p['selector'],ArtifactDraftTaskSelectorV1))
        task=selector.task if phase else selector
        if(task.c02_operation_id!=self.cycle.c02_operation_id or task.namespace!=self.reader.namespace
                or p['call_id']!=attempt.call_id or p['parent_budget_lease_ref']!=self.plan.parent_budget_lease_ref
                or phase and(type(attempt)is not ForegroundModelAttemptV2 or attempt.phase_selector!=selector)):
            raise AuthorityUnavailable('D05 C4 actual preparation belongs to another C02/phase/root')
        ids=(artifact_draft_model_ids_v2 if phase else artifact_draft_model_ids_v1)(selector)
        if(p['job_id'],p['operation_id'],p['call_id'])!=(ids['job'],ids['prepare'],ids['call']):
            raise AuthorityUnavailable('D05 C4 actual deterministic job/call/prepare identity differs')
        base,job,reservation,quote=yield from self.common_attempt_v3('C4',p,digest,attempt)
        yield from self.committed_v3(p['operation_id'])
        sealed,sealed_digest=yield from self.original_v3('graph_d11_life_originals_v1',kind+'call',p['call_id'],
            tuple(ModelEgressIntentV1.__dataclass_fields__),'d11.life-original.v1')
        intent=None if sealed is None else from_wire(sealed,ModelEgressIntentV1)
        if intent is not None and(intent.call_id!=p['call_id']or intent.job_id!=p['job_id']or intent.binding_digest!=digest
                or intent.budget_lease_id!=quote.parent_budget_lease_ref or intent.budget_reservation_operation_id!=p['operation_id']
                or intent.budget_reservation_digest!=p['reservation_digest']):
            raise AuthorityUnavailable('D05 C4 actual sealed call differs from its preparation/reservation')
        paid,paid_digest=yield from self.original_v3('graph_d11_life_originals_v1',kind+'paid',ids['paid'],_COST_FIELDS,'d11.life-original.v1')
        result,result_digest=yield from self.original_v3('graph_d11_life_originals_v1',kind+'result',ids['result'],
            ('schema','request','terminal_receipt'),'d11.life-original.v1')
        terminal=None
        if result is not None:
            request=result['request']
            if(paid is None or paid['terminal_receipt_digest']!=canonical_digest(result['terminal_receipt'])
                    or request['binding_digest']!=digest or request['selector']!=p['selector']
                    or paid['status']!='committed' or paid['call_id']!=p['call_id']):
                raise AuthorityUnavailable('D05 C4 completed physical phase lost its actual paid terminal/result original')
            yield from self.committed_v3(paid['operation_id'])
            terminal=ids['result']
        state='completed'if terminal else'unknown'if paid is not None or intent is not None or reservation[1]in('unknown','partial_unknown','unconfirmed')else'reserved'
        self.observed.append(replace(base,state=state,terminal_ref=terminal))
    def lease_v3(self,lease_id):
        ns=self.reader.namespace
        row=self.fixed_v3('runtime_budget_leases',('parent_id','bot_id','persona_id','currency','version','state'),'lease_id=?',(lease_id,))
        if row is None or row[1:3]!=ns.as_tuple or row[5]in('unknown','partial_unknown','unconfirmed','overrun'):
            raise AuthorityUnavailable('D05 actual budget family namespace/state is inadmissible')
        if self.fixed_v3('runtime_budget_debt_blocks',('cause_lease_id','cause_operation_id'),'lease_id=? ORDER BY cause_lease_id,cause_operation_id',(lease_id,))is not None:
            raise AuthorityUnavailable('D05 actual budget ancestry has unresolved overrun debt')
        limits,limits_task=yield from self.json_v3('runtime_budget_leases','limits_json',('lease_id',),(lease_id,),
            ('parent_id','bot_id','persona_id','currency','version','state'),((),))
        grant_head=self.fixed_v3('runtime_budget_grants',('version','status'),'lease_id=? ORDER BY version DESC',(lease_id,))
        if grant_head is None or grant_head[1]!='active':raise AuthorityUnavailable('D05 budget family has no actual active latest grant')
        grant,grant_task=yield from self.json_v3('runtime_budget_grants','grant_json',('lease_id','version'),(lease_id,grant_head[0]),
            ('signature','status'),((),))
        if grant is None:raise AuthorityUnavailable('D05 actual budget family lost its signed current grant')
        from .issuers import BudgetLeaseGrant
        raw=dict(grant);raw['allowed_work_kinds']=tuple(raw['allowed_work_kinds'])
        actual=BudgetLeaseGrant(**raw)
        self.reader.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1',canonical_serialize(grant),grant_task.metadata[0])
        if(actual.lease_id,actual.version,actual.bot_id,actual.persona_id)!=(lease_id,grant_head[0],*ns.as_tuple):
            raise AuthorityUnavailable('D05 actual current budget grant crossed its lease/version')
        return row,limits,actual
    def allocation_v3(self,cycle_job):
        ns=self.reader.namespace
        parent=yield from self.lease_v3(self.plan.parent_budget_lease_ref)
        seen={self.plan.parent_budget_lease_ref};ancestor=parent[0][0]
        while ancestor is not None:
            if ancestor in seen:raise AuthorityUnavailable('D05 original budget ancestry is cyclic')
            seen.add(ancestor);actual_parent=yield from self.lease_v3(ancestor);ancestor=actual_parent[0][0]
        child=yield from self.lease_v3(self.plan.protected_reply_lease_ref)
        key=(*ns.as_tuple,cycle_job['operation_id'])
        raw,task=yield from self.json_v3('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),key,
            ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
            (('request','c02_operation_id'),('request','source_ref'),('request','protected_reply_lease_ref'),
             ('provenance','reply_allocation'),('provenance','after_job','budget_ref'),('provenance','before_job')))
        if raw is None or task.metadata[0]!='d11'or task.metadata[1]not in('create_foreground_cycle','create_foreground_cycle_v2'):
            raise AuthorityUnavailable('D05 actual CallPlan lacks its adopted original protected budget allocation')
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
        allocation=decode_typed_production_value_v1(raw['provenance']['reply_allocation'],ForegroundReplyAllocationV1)
        if(allocation.namespace!=ns or allocation.c02_operation_id!=self.cycle.c02_operation_id
                or allocation.parent_lease_ref!=self.plan.parent_budget_lease_ref
                or allocation.child_lease_id!=self.plan.protected_reply_lease_ref
                or (child[0][0],child[0][3],child[1],child[2])!=(allocation.parent_lease_ref,allocation.currency,dict(allocation.child_limits),allocation.child_grant())
                or raw['request']['c02_operation_id']!=self.cycle.c02_operation_id or raw['request']['source_ref']!=self.cycle.source_ref
                or raw['request']['protected_reply_lease_ref']!=allocation.child_lease_id
                or raw['provenance']['before_job']is not None):
            raise AuthorityUnavailable('D05 protected child allocation differs from its actual original parent/child grant')
        created=self.fixed_v3('runtime_budget_operations',('digest','lease_id'),'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',
            (*ns.as_tuple,allocation.allocation_operation_id,'create'))
        receipt,receipt_task=yield from self.json_v3('runtime_budget_operations','receipt_json',('bot_id','persona_id','operation_id','phase'),
            (*ns.as_tuple,allocation.allocation_operation_id,'create'),('digest','lease_id'),((),))
        if(created!=(allocation.digest,allocation.child_lease_id)or receipt is None
                or(receipt['status'],receipt['operation_id'],receipt['digest'],receipt['lease_id'],receipt['version'])!=
                    ('created',allocation.allocation_operation_id,allocation.digest,allocation.child_lease_id,1)
                or any(receipt[name]for name in('used','reserved','unconfirmed'))):
            raise AuthorityUnavailable('D05 protected reply lease has no exact original untouched child creation receipt')
        yield from self.committed_v3(cycle_job['operation_id'])

    def _program_v3(self):
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1,ForegroundCycleContinuationV1,ForegroundCycleContinuationV2
        from .jobs import PersistentJob
        r=self.reader;ns=r.namespace
        cycle_job=self.job_v3(self.prepared.cycle_ref.key.name)
        if cycle_job is None or cycle_job['cancel_epoch']:
            raise AuthorityUnavailable('D05 actual relationship CallPlan parent job is absent or cancelled')
        raw,task=yield from self.json_v3('runtime_jobs','continuation_json',('job_id',),(cycle_job['job_id'],),
            ('job_id','operation_id','phase','fence','cancel_epoch'),((),))
        self.cycle=foreground_cycle_from_wire_v1(raw);self.plan=self.cycle.call_plan
        if(type(self.cycle)not in(ForegroundCycleContinuationV1,ForegroundCycleContinuationV2)
                or self.cycle.c02_operation_id!=self.prepared.c02_operation_id
                or self.cycle.cancel_generation!=self.prepared.cancel_generation
                or self.plan.parent_budget_lease_ref!=r.selected_envelope.parent_budget_lease_ref
                or cycle_job['budget_ref']!=self.plan.parent_budget_lease_ref):
            raise AuthorityUnavailable('D05 relationship budget changed its actual official C02/cycle/parent plan')
        head,head_task=yield from self.json_v3('graph_atoms','value',('token','bot','persona'),
            (self.prepared.cycle_ref.key.token,*ns.as_tuple),('revision','valid','value_cell_id'),
            tuple((name,)for name in PersistentJob.__dataclass_fields__ if not name.startswith('_')))
        if(head is None or head_task.metadata[1]!=1 or head['job_id']!=cycle_job['job_id']or head['continuation']!=raw
                or any(head[name]!=value for name,value in cycle_job.items())):
            raise AuthorityUnavailable('D05 actual complete cycle SQL/Graph job metadata differs')
        yield from self.allocation_v3(cycle_job)
        yield from self.c1_v3();yield from self.c2_v3()
        for attempt in self.plan.attempts:
            if attempt.slot in('C3','C4'):
                p,digest,phase=yield from self.prepared_attempt_v3(attempt)
                if attempt.slot=='C3':yield from self.c3_v3(attempt,p,digest)
                else:yield from self.c4_v3(attempt,p,digest,phase)
        generation=yield from self.natural_v3('generation')
        yield from self.natural_v3('review',generation)
        from .foreground_call_plan_v1 import ForegroundCallPlanV2
        from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
        if type(self.plan)in(ForegroundCallPlanV2,ForegroundCallPlanV3):
            group=self.plan.phase_group
            for index,(ref,digest)in enumerate(group.completed_phase_originals):
                raw,actual=yield from self.original_v3('graph_d11_life_originals_v1','c4_phase_verified',ref,
                    ('selector','content_adoption_ref','content_adoption_digest','prev_verified_original_ref','prev_verified_original_digest',
                     'producing_operation_id','structurally_verified','method_qualified','schema'),'d11.life-original.v1')
                if(raw is None or actual!=digest or raw['selector']['phase_index']!=index or not raw['structurally_verified']or not raw['method_qualified']
                        or canonical_digest(raw['selector']['task'])!=canonical_digest(group.selector.task)):
                    raise AuthorityUnavailable('D05 actual CallPlan phase group lost its complete signed ordered verification')
                yield from self.committed_v3(raw['producing_operation_id'])
        actual=[attempt for attempt in self.observed if attempt.call_id==self.prepared.call_id]
        if len(actual)!=1 or actual[0].slot!='C3'or actual[0].state!='completed':
            raise AuthorityUnavailable('D05 target relationship C3 is not uniquely actually completed')
        aux={value.call_id:value for value in self.observed if value.slot in('C3','C4')}
        replace(self.plan,attempts=tuple(aux[value.call_id]if value.slot in('C3','C4')else value for value in self.plan.attempts))
        self.require_headers_v3(self.meter)
        return
    def release_v3(self):
        _TASKS.pop(self,None)
        if self.result is not None:_PROOFS.pop(self.result,None)
        self.program.close()
        self.profiles.clear();self.tasks.clear();self.headers.clear();self.observed.clear();self.committed_digests.clear()
        self.current=self.result=self.cycle=self.plan=None
        self.reader.operation.unregister_retained_state_v3(self)


def _natural_seal_fields_v3(stage):
    from . import natural_reply_job_v2 as module
    prefix='NaturalReplyGenerationOriginalSealV'if stage=='generation'else'NaturalReplyReviewOriginalSealV'
    return tuple(dict.fromkeys(name for version in(2,3,4,6,7)
        for name in vars(module)[prefix+str(version)].__dataclass_fields__))


def relationship_call_plan_budget_metadata_spec_v3(reader,identity):
    state=_state_v3(reader)
    if(type(identity)is not tuple or len(identity)!=3 or identity[0]!='relationship_budget'
            or identity not in state.selected):
        raise AuthorityUnavailable('D05 budget metadata has no actual selected parent task')
    task=state.numeric_budget_tasks.get(identity[1])
    if type(task)is not _RelationshipCallPlanBudgetTaskV3:
        raise AuthorityUnavailable('D05 budget metadata requires the actual independent CallPlan producer')
    _require_task_v3(task)
    if identity not in task.profiles:raise AuthorityUnavailable('D05 budget metadata has no finite actual slot recipe')
    return task.profiles[identity]


def finish_relationship_call_plan_budget_metadata_v3(task,value):
    state=_state_v3(task.reader);parent=state.numeric_budget_tasks.get(task.identity[1])
    if(type(parent)is not _RelationshipCallPlanBudgetTaskV3 or parent.tasks.get(task.identity)is not task
            or task.spec!=relationship_call_plan_budget_metadata_spec_v3(task.reader,task.identity)):
        raise AuthorityUnavailable('D05 slot metadata EOF belongs to another actual CallPlan producer')
    return value


def create_relationship_call_plan_budget_task_v3(reader,selector):
    state=_state_v3(reader)
    if(reader.inputs_sealed or reader.read_finished or reader.business_started or reader.fence.scope.operation!='read'):
        raise AuthorityUnavailable('D05 CallPlan budget must be prepared by the actual unsealed Source READ')
    task=state.numeric_budget_tasks.get(selector)
    if task is None:task=_RelationshipCallPlanBudgetTaskV3(_KEY,reader,selector)
    _require_task_v3(task)
    return task


def require_relationship_call_plan_budget_v3(db,*,namespace,interpretation_ref,prepared,policy):
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    reader=_method_active(db)
    if reader is None:raise AuthorityUnavailable('D05 CallPlan budget has no actual qualified Method Binder')
    from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
    if(type(policy)is not InstalledRelationshipPolicyV2 or policy.namespace!=namespace or policy.policy_ref!=reader.request.policy_ref):
        raise AuthorityUnavailable('D05 budget consumer requires its actual installed scoped numeric policy')
    state=_state_v3(reader);selector=(interpretation_ref,prepared.digest)
    if(namespace!=reader.namespace or prepared is not state.numeric_prepared or selector!=
            (state.numeric_interpretation_ref,state.numeric_prepared_digest)):
        raise AuthorityUnavailable('D05 CallPlan budget consumer changed its actual interpretation/preparation')
    task=state.numeric_budget_tasks.get(selector)
    if task is None or not task.complete:_need_method_input(reader,('relationship_call_plan_budget',selector))
    if type(task.result)is not PreparedRelationshipCallPlanBudgetV3:
        raise AuthorityUnavailable('D05 CallPlan budget lost actual complete private proof')
    return task.result.require_v3(db,namespace,interpretation_ref,prepared,policy)
