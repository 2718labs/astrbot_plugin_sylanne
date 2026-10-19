
"""Exact actual foreground writer outputs; captures grant no read permission."""
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from weakref import WeakKeyDictionary
import hashlib,json,time
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,CommitReceipt,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,runtime_storage_v3,_runtime_bounded_fixed_row_v3
from .dispatch_current_inventory_v3 import _heap,_freeze_value_v3
from .domain_production_contracts_v1 import CurrentOperationFrameV1,StagedDomainOperationV1

_KEY=object()
_BOUND=ContextVar('foreground_actual_writer_outputs_v3',default=None)
_CAPTURES=WeakKeyDictionary()
_ACTIVE_WRITERS=WeakKeyDictionary()
_DOMAIN='graph_domain_production_originals_v1'
_LIFE='graph_d11_life_originals_v1'
_D07='graph_d07_execution_originals_v1'
_D01='graph_d01_production_inputs_v1'

def _small(c,table,columns,where,key):
    with runtime_storage_quantum_v3(c.db)as meter:
        return _runtime_bounded_fixed_row_v3(c.db,meter,table,columns,where,key)

def _source_capture(reader,frame):
    from .foreground_command_source_v3 import _STATES,_FRAMES
    state=_STATES.get(reader);record=_FRAMES.get(id(frame))
    if state is not None:
        if record is None or record[0]is not frame or record[1]is not state:
            raise AuthorityUnavailable('Writer capture lacks actual complete foreground Source frame')
        state.capability.require_v3()
        return('command',state,record,state.identity,state.capability,
            state.capability.identity,state.monotonic_deadline)
    if reader.operation_kind!='input:register_artifact_phase_draft_plan_v2':return None
    from .artifact_borrowed_source_v3 import _STATES as OLD_STATES
    from .artifact_frame_control_reads_v3 import _record_v3
    state=OLD_STATES.get(reader);record=_record_v3(frame,current=True)
    if state is None or record is None or record[1]is not reader:
        raise AuthorityUnavailable('Exact phase-plan writer lacks its actual old Artifact Source frame')
    state.capability.require_v3()
    return('phase_plan',state,record,state.identity,state.capability,
        state.capability.identity,min(state.initial_monotonic_deadline,state.current_monotonic_deadline))

class _ForegroundWriterV3:
    def __init__(self,key,db,*,reader,graph,prior_frame,stage,issued,scope,process_lease,request,source):
        if key is not _KEY:raise AuthorityUnavailable('Actual private writer capture issuer required')
        from .domain_production_commit_v1 import _members
        from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
        primary,proposals,_,_,_=_members(stage)
        if(type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
                or type(prior_frame)is not CurrentOperationFrameV1 or type(primary)is not StagedDomainOperationV1
                or db is not reader.db or graph is not reader.graph or issued is not reader.issued or scope is not issued.scope
                or request is not reader.request or not reader.inputs_sealed or not reader.business_started or reader.business_completed
                or not db.in_transaction or not reader.store._lock._is_owned()
                or reader.runtime._active_foreground_issuance_v1 is not issued
                or reader.runtime._active_foreground_process_lease_v1 is not process_lease
                or primary.operation_id!=reader.operation_id or primary.operation_kind!=reader.operation_kind
                or prior_frame.envelope.identity.operation_id!=reader.operation_id or primary.namespace!=reader.namespace
                or prior_frame.owner_guard!=reader.material_owner_guard
                or prior_frame.envelope.version_guard.read_versions!=primary.read_versions):
            raise AuthorityUnavailable('Writer capture changed actual Borrowed Work/typed frame/stage/WRITE')
        reader.result._actual_v3();reader.work._require_invocation(graph)
        self.reader,self.db,self.graph,self.namespace=reader,db,graph,reader.namespace
        self.frame,self.stage,self.primary=prior_frame,stage,primary
        self.issued,self.scope,self.process_lease,self.request=issued,scope,process_lease,request
        self.source=source;self.pre_stamp=reader.graph_stamp;self.deadline=source[-1]
        self.operation=reader.operation;self.work=reader.work;self.runtime=reader.runtime
        self.authority_epochs=reader.authority_epochs
        self.expected_jobs=_expected_jobs(self);self.saved_jobs={}
        self.request_digest=reader.request_digest;self.primary_digest=canonical_digest(primary)
        self.primary_raw=json.loads(primary.original_payload_json)
        self.declared_writes={}
        for proposal in proposals:
            for write in proposal.typed_writes:
                if write.key in self.declared_writes:raise AuthorityUnavailable('Actual writer has duplicate declared Graph slot')
                self.declared_writes[write.key]=write
        self.prior_points={};self.owned={};self.pending_slots={};self.values_slots={}
        self.receipt=self.after_stamp=self.witness=self.after_epochs=None
        self.domain_content=None;self.phase='captured'
        self._capture_points()
        self.identity=(reader,db,graph,prior_frame,stage,primary,issued,scope,process_lease,request,
            self.operation,self.work,self.pre_stamp,self.request_digest,self.primary_digest,source,self.authority_epochs)
        _CAPTURES[self]=self.identity
        reader.operation.retain(_heap((self.prior_points,self.primary_raw))+8192)
    def _capture_points(self):
        from .current_method_learning_read_v3 import MethodJSONColumnV3
        r=self.reader
        for request,task in (*r.points.items(),*r.attachments.items()):
            if not task.complete:raise AuthorityUnavailable('Writer capture cannot retain unfinished Body points')
            if task.table not in {_DOMAIN,_LIFE,_D07,_D01,'graph_atoms','graph_history','graph_bundle_operations',
                    'graph_events','runtime_jobs','runtime_resource_quotes','graph_d02_production_policies_v1',
                    'graph_d05_production_policies_v1','runtime_budget_grants','runtime_budget_leases',
                    'runtime_budget_reservations','runtime_budget_operations','graph_first_ingress_c02_committed_seals_v2',
                    'runtime_encoding_call_bindings_v1','graph_c04_internal_work_prepared_v1','graph_ingress_observations',
                    'graph_d02_action_components_v1','d02_fixed_body_policies_v1','graph_dependencies'}:
                continue
            values=None
            if task.row is not None:
                values=dict(zip(task.columns,(v.wire if type(v)is MethodJSONColumnV3 else v for v in task.row)))
                values.update(dict(zip(task.metadata_columns,task.metadata)))
            if task.table=='graph_history'and values is not None:
                criteria=dict(zip(task.key_columns,task.key))
                if 'token'in criteria and 'revision'in criteria:
                    extra=_small(self,'graph_history',('event_bot','event_persona','event_session','event_id'),
                        'token=? AND revision=?',(criteria['token'],criteria['revision']))
                    if extra is None or extra[:2]!=self.namespace.as_tuple:
                        raise AuthorityUnavailable('Writer captured history lost actual namespace/event header')
                    values=dict(values);values.update(zip(('event_bot','event_persona','event_session','event_id'),extra))
                    values.update(token=criteria['token'],revision=criteria['revision'])
            self.prior_points[request]=(task.table,tuple(task.key_columns),tuple(task.key),
                tuple(task.metadata_columns),task.metadata,None if values is None else MappingProxyType(values))
    def require_current(self):
        _require_source_binding(self)
        from .current_method_learning_read_v3 import _READERS
        r=self.reader
        if(_BOUND.get()is not self or _CAPTURES.get(self)!=self.identity or r not in _READERS
                or r.work is not self.work or self.work.state is not r or self.work.operation is not self.operation
                or r.authority_epochs!=self.authority_epochs
                or self.operation.closed or runtime_storage_v3(self.db)is not self.operation.handle
                or not self.db.in_transaction or not r.store._lock._is_owned()
                or r.runtime is not self.runtime or self.runtime._active_foreground_issuance_v1 is not self.issued
                or self.runtime._active_foreground_process_lease_v1 is not self.process_lease
                or time.monotonic()>=self.deadline):
            raise AuthorityUnavailable('Writer output context lost actual Work/transaction/issuance/original lifetime')
        self.work._require_invocation(self.graph)
        if self.phase=='active':
            if(_ACTIVE_WRITERS.get(self)!=(self.identity,self.witness,self.receipt,self.after_stamp,self.after_epochs)
                    or self.graph._v2_graph_stamp(self.namespace)!=self.after_stamp):
                raise AuthorityUnavailable('Writer outputs lost actual activated CAS/post stamp')
            with runtime_storage_quantum_v3(self.db)as meter:
                if r._epochs(meter)!=self.authority_epochs or self.after_epochs!=self.authority_epochs:raise AuthorityUnavailable('Writer output authority epochs changed')
                head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,owner_grant_key(*self.namespace.as_tuple).token))
            if head!=r.owner_head:raise AuthorityUnavailable('Writer upstream Owner head changed')
        elif self.graph._v2_graph_stamp(self.namespace)!=self.pre_stamp:
            raise AuthorityUnavailable('Captured writer has no activated actual receipt for changed Graph')
        return self
    def prior_row(self,table,columns,key_columns,key):
        self.require_current()
        if self.phase!='active':return False,None
        requested=dict(zip(key_columns,key))
        for record in self.prior_points.values():
            t,keys,pk,metadata_columns,metadata,values=record
            if t!=table:continue
            stored=dict(zip(keys,pk))
            if table in {'graph_atoms','graph_history'}:
                if requested.get('token')!=stored.get('token'):continue
                if table=='graph_history'and requested.get('revision')!=stored.get('revision'):continue
                if requested.get('bot',self.namespace.bot_id)!=self.namespace.bot_id or requested.get('persona',self.namespace.persona_id)!=self.namespace.persona_id:
                    raise AuthorityUnavailable('Writer inherited Graph point crossed actual namespace')
            elif keys!=tuple(key_columns)or pk!=tuple(key):continue
            current=_small(self,t,metadata_columns,' AND '.join(name+'=?'for name in keys),pk)
            if current!=metadata:raise AuthorityUnavailable('Writer inherited point changed after completed pre-CAS EOF')
            if values is None:return True,None
            if any(name not in values for name in columns):continue
            if any(name in values and values[name]!=value for name,value in requested.items()):return True,None
            return True,tuple(values[name]for name in columns)
        return False,None
    def put(self,table,key_columns,key,values,*,header_columns,header):
        self.require_current()
        identity=(table,tuple(key_columns),tuple(key))
        record=(MappingProxyType(dict(values)),tuple(header_columns),tuple(header))
        prior=self.owned.get(identity)
        if prior is not None and prior!=record:raise AuthorityUnavailable('Writer actual output slot was reused with different content')
        self.owned[identity]=record
    def output_row(self,table,columns,key_columns,key):
        self.require_current()
        if self.phase!='active':return False,None
        requested=dict(zip(key_columns,key))
        for(t,keys,pk),(values,header_columns,header)in self.owned.items():
            if t!=table:continue
            stored=dict(zip(keys,pk))
            if table in {'graph_atoms','graph_history'}:
                if requested.get('token')!=stored.get('token'):continue
                if table=='graph_history'and requested.get('revision')!=stored.get('revision'):continue
                if requested.get('bot',self.namespace.bot_id)!=self.namespace.bot_id or requested.get('persona',self.namespace.persona_id)!=self.namespace.persona_id:
                    raise AuthorityUnavailable('Writer actual Graph output crossed namespace')
            elif keys!=tuple(key_columns)or pk!=tuple(key):continue
            current=_small(self,t,header_columns,' AND '.join(name+'=?'for name in keys),pk)
            if current!=header:raise AuthorityUnavailable('Writer actual output metadata changed after registration')
            if any(name not in values for name in columns):raise AuthorityUnavailable('Writer output has no registered column projection')
            if any(name in values and values[name]!=value for name,value in requested.items()):return True,None
            return True,tuple(values[name]for name in columns)
        return False,None

@contextmanager
def bind_foreground_command_writer_v3(db,*,graph,prior_frame,stage,issued,scope,process_lease,request):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None:
        yield None;return
    source=_source_capture(reader,prior_frame)
    if source is None:
        yield None;return
    if _BOUND.get()is not None:raise AuthorityUnavailable('Actual writer capture cannot be nested')
    c=_ForegroundWriterV3(_KEY,db,reader=reader,graph=graph,prior_frame=prior_frame,stage=stage,
        issued=issued,scope=scope,process_lease=process_lease,request=request,source=source)
    token=_BOUND.set(c)
    try:yield c
    finally:
        _BOUND.reset(token);_ACTIVE_WRITERS.pop(c,None);_CAPTURES.pop(c,None)
        c.prior_points.clear();c.owned.clear();c.pending_slots.clear();c.values_slots.clear()
        c.saved_jobs.clear();c.expected_jobs.clear()
        c.domain_content=c.receipt=c.witness=None;c.phase='released'

def _active(db):
    c=_BOUND.get()
    if c is None:return None
    if c.db is not db:raise AuthorityUnavailable('Actual writer crossed selected database')
    if c.phase!='active':return None
    return c.require_current()

def activate_foreground_command_writer_commit_v3(db,*,witness,actual_receipt):
    c=_BOUND.get()
    if c is None:return None
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from ..contracts import Event,Scope,canonical_json
    from ..authority_service.v2_contract import to_wire
    from .domain_production_commit_v1 import foreground_domain_finish_digest_v1
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or type(actual_receipt)is not CommitReceipt or c.db is not db or c.phase!='captured'
            or witness.graph is not c.graph or witness.runtime is not c.runtime or witness.scope is not c.scope
            or witness.frame is not c.frame or witness.stage is not c.stage or witness.request is not c.request
            or witness.operation.operation_kind!=c.reader.operation_kind
            or actual_receipt.status!='committed' or actual_receipt.operation_id!=c.primary.operation_id
            or actual_receipt.read_versions!=c.frame.envelope.version_guard.read_versions
            or(actual_receipt.activity_id,actual_receipt.effect_id)!=(c.frame.envelope.identity.activity_id,c.frame.envelope.identity.effect_id)):
        raise AuthorityUnavailable('Writer activation requires this exact real W01 witness and returned receipt')
    after=c.graph._v2_graph_stamp(c.namespace)
    if(after[0].graph_revision!=c.pre_stamp[0].graph_revision+1
            or after[1].revision!=c.pre_stamp[1].revision+1 or actual_receipt.invalidated_epochs!=(after[1],)):
        raise AuthorityUnavailable('Writer activation lacks its exact one-CAS before/after Graph stamp')
    bundle=_small(c,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*c.namespace.as_tuple,actual_receipt.operation_id))
    if bundle!=(actual_receipt.operation_digest,actual_receipt.activity_id,actual_receipt.effect_id,actual_receipt.commit_seq):
        raise AuthorityUnavailable('Writer activation lost actual bundle COMMIT')
    event_key=(*c.namespace.as_tuple,actual_receipt.activity_id,actual_receipt.operation_id)
    expected_event=Event(Scope(*c.namespace.as_tuple,actual_receipt.activity_id),actual_receipt.operation_id,
        c.frame.envelope.source_qualification.learned_at,'domain_bundle',{'bundle_digest':actual_receipt.operation_digest})
    event=_small(c,'graph_events',('digest','epoch_revision'),'bot=? AND persona=? AND session=? AND event_id=?',event_key)
    if event!=(expected_event.digest,after[1].revision):raise AuthorityUnavailable('Writer activation lost actual Graph event')
    fence=_small(c,'graph_bundle_fences_v2',('digest','permit_json','pre_graph_revision','pre_graph_epoch',
        'post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'),
        'bot=? AND persona=? AND operation_id=?',(*c.namespace.as_tuple,actual_receipt.operation_id))
    expected=(actual_receipt.operation_digest,canonical_json(to_wire(c.scope.permit)),c.pre_stamp[0].graph_revision,
        c.pre_stamp[1].revision,after[0].graph_revision,after[1].revision,'finish:'+c.scope.operation_id,
        foreground_domain_finish_digest_v1(c.reader.evidence.request,c.scope.permit))
    if fence!=expected:raise AuthorityUnavailable('Writer activation changed original permit/fence/prepost/finish trace')
    c.receipt,c.after_stamp,c.witness=actual_receipt,after,witness
    with runtime_storage_quantum_v3(db)as meter:c.after_epochs=c.reader._epochs(meter)
    if c.after_epochs!=c.authority_epochs:
        raise AuthorityUnavailable('Actual CAS changed original Source/access/deletion authority epochs')
    c.phase='active';_ACTIVE_WRITERS[c]=(c.identity,witness,actual_receipt,after,c.after_epochs)
    from .domain_production_originals_v1 import _receipt_wire
    receipt_wire=canonical_serialize(_receipt_wire(actual_receipt))
    c.put('graph_bundle_operations',('bot','persona','operation_id'),(*c.namespace.as_tuple,actual_receipt.operation_id),
        dict(bot=c.namespace.bot_id,persona=c.namespace.persona_id,operation_id=actual_receipt.operation_id,
            digest=bundle[0],activity_id=bundle[1],effect_id=bundle[2],commit_seq=bundle[3],receipt_json=receipt_wire),
        header_columns=('digest','activity_id','effect_id','commit_seq'),header=bundle)
    c.put('graph_events',('bot','persona','session','event_id'),event_key,
        dict(bot=c.namespace.bot_id,persona=c.namespace.persona_id,session=actual_receipt.activity_id,event_id=actual_receipt.operation_id,
            digest=event[0],epoch_revision=event[1],reads=canonical_serialize([[v.key.token,v.revision]for v in actual_receipt.read_versions]),
            revisions=canonical_serialize([[v.key.token,v.revision]for v in actual_receipt.write_versions]),
            invalidated=_small(c,'graph_events',('invalidated',),'bot=? AND persona=? AND session=? AND event_id=?',event_key)[0]),
        header_columns=('digest','epoch_revision'),header=event)
    _register_graph_outputs(c,expected_event.digest)
    _register_saved_jobs(c,witness)
    return c

def _register_graph_outputs(c,event_digest):
    from ..runtime_storage_v3 import begin_runtime_cell_read_v3,read_runtime_cell_origin_v3
    versions={v.key:v for v in c.receipt.write_versions}
    for key,write in c.declared_writes.items():
        version=versions.get(key)
        if version is None:raise AuthorityUnavailable('Writer declared output is absent from actual receipt')
        header=_small(c,'graph_atoms',('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?',(key.token,*c.namespace.as_tuple))
        if header is None or header[:2]!=(version.revision,1):raise AuthorityUnavailable('Writer Graph output lacks actual receipt revision')
        normalized=c.reader.store._registry.validate(key,write.value)
        logical=canonical_serialize(normalized)
        with runtime_storage_quantum_v3(c.db)as meter:
            cell=begin_runtime_cell_read_v3(c.db,header[2],erasure_owner_ref=key.token)
            raw=logical if cell.header[0]=='canonical-json.ascii.v1'else json.dumps(normalized,ensure_ascii=False,sort_keys=True,separators=(',',':'))
            origin=read_runtime_cell_origin_v3(c.db,header[2],header=cell.header,meter=meter)
        if(cell.header[0]not in {'canonical-json.ascii.v1','canonical-json.utf8.v1'}or cell.header[2]!=c.primary.operation_id
                or cell.header[3]!=len(raw.encode('utf8'))or cell.header[5]!=hashlib.sha256(raw.encode('utf8')).hexdigest()
                or origin is None or origin['operation_id']!=c.primary.operation_id or origin['event_digest']!=event_digest
                or origin['locator']!={'table':'graph_atoms','token':key.token,'revision':version.revision}):
            raise AuthorityUnavailable('Writer Graph output lacks actual committed canonical-cell origin/digest')
        values=dict(token=key.token,bot=c.namespace.bot_id,persona=c.namespace.persona_id,revision=version.revision,
            value=logical,valid=1,value_cell_id=header[2])
        c.put('graph_atoms',('token','bot','persona'),(key.token,*c.namespace.as_tuple),values,
            header_columns=('revision','valid','value_cell_id'),header=header)
        history=_small(c,'graph_history',('valid','value_cell_id','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=?',(key.token,version.revision))
        if history!=(1,header[2],*c.namespace.as_tuple,c.receipt.activity_id,c.primary.operation_id):
            raise AuthorityUnavailable('Writer Graph history lost exact current event/cell origin')
        c.put('graph_history',('token','revision'),(key.token,version.revision),
            dict(values,event_bot=history[2],event_persona=history[3],event_session=history[4],event_id=history[5]),
            header_columns=('valid','value_cell_id','event_bot','event_persona','event_session','event_id'),header=history)

def require_foreground_command_writer_prior_v3(db,*,reader,prior_frame,stage,actual_receipt,scope,issued,process_lease):
    c=_active(db)
    if c is None:return None
    if(c.phase!='active'or reader is not c.reader or prior_frame is not c.frame or stage is not c.stage and stage is not c.primary
            or actual_receipt!=c.receipt or scope is not c.scope or issued is not c.issued or process_lease is not c.process_lease):
        raise AuthorityUnavailable('Writer prior proof changed actual capture/stage/receipt/Scope')
    return c

def foreground_writer_owns_output_point_v3(db,request):
    c=_active(db)
    if c is None or c.phase!='active':return False
    table,columns,keys,key=request
    return c.output_row(table,tuple(columns),tuple(keys),tuple(key))[0]

def read_bound_foreground_writer_point_v3(db,*,table,columns,key_columns,key):
    c=_active(db)
    if c is None or c.phase!='active':return False,None
    handled,row=c.output_row(table,tuple(columns),tuple(key_columns),tuple(key))
    if handled:return True,row
    return c.prior_row(table,tuple(columns),tuple(key_columns),tuple(key))

def register_foreground_writer_domain_original_v3(db,stage,receipt,content):
    c=_active(db)
    if c is None:return False
    raw=_domain_shape(c,stage,receipt,content)
    header=_small(c,_DOMAIN,('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*c.namespace.as_tuple,stage.operation_id))
    if header!=(stage.domain,stage.operation_kind,stage.request_digest,stage.original_digest,receipt.operation_digest,canonical_digest(receipt)):
        raise AuthorityUnavailable('Writer Domain DTO requires actual INSERT or verified-equal existing row')
    names=('domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest')
    c.put(_DOMAIN,('bot','persona','operation_id'),(*c.namespace.as_tuple,stage.operation_id),
        dict(zip(names,content)),header_columns=('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),header=header)
    c.domain_content=(stage,raw,tuple(content))
    return True

def read_foreground_writer_head_v3(db,namespace,key):
    c=_active(db)
    if c is None or c.phase!='active':return False,None
    if namespace!=c.namespace or NamespaceId.from_key(key)!=namespace:raise AuthorityUnavailable('Writer head crossed namespace')
    handled,row=read_bound_foreground_writer_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),
        key_columns=('token','bot','persona'),key=(key.token,*namespace.as_tuple))
    if not handled:return False,None
    return True,GraphAtom(key,0,{},False)if row is None else GraphAtom(key,row[0],json.loads(row[1]),bool(row[2]))

def foreground_writer_atom_digest_v3(db,atom):
    c=_active(db)
    if c is None or c.phase!='active':return False,None
    handled,actual=read_foreground_writer_head_v3(db,c.namespace,atom.key)
    if not handled or actual!=atom or atom.revision<1:raise AuthorityUnavailable('Writer atom digest escaped actual owned/inherited point')
    return True,canonical_digest(atom.value)


def _domain_shape(c,stage,receipt,content):
    if(c.phase!='active'or receipt!=c.receipt or type(stage)is not StagedDomainOperationV1
            or(stage.namespace,stage.operation_id,stage.operation_kind,stage.request_digest)!=(c.namespace,c.primary.operation_id,c.primary.operation_kind,c.primary.request_digest)):
        raise AuthorityUnavailable('Writer Domain slot changed actual stage/receipt')
    raw=json.loads(stage.original_payload_json)
    if stage.original_digest!=c.primary.original_digest:
        if stage.operation_kind not in {'derive_ingress_artifact_task_scope_v1','settle_personal_goal'}:
            raise AuthorityUnavailable('Writer Domain rewrite is outside exact companion producers')
        expected=dict(c.primary_raw)
        expected['writes']=[{'key':w.key.token,'value':w.value,'dependencies':[k.token for k in w.dependencies]}for w in c.declared_writes.values()]
        if raw!=expected:raise AuthorityUnavailable('Writer Domain rewrite changed actual companion members')
    elif canonical_digest(raw)!=stage.original_digest or raw!=c.primary_raw:
        raise AuthorityUnavailable('Writer Domain slot differs from captured exact payload')
    from .domain_production_originals_v1 import _receipt_wire
    expected_content=(stage.domain,stage.operation_kind,stage.request_digest,stage.original_digest,
        stage.original_payload_json,canonical_serialize([[v.key.token,v.revision]for v in stage.read_versions]),
        receipt.operation_digest,canonical_serialize(_receipt_wire(receipt)),canonical_digest(receipt))
    if tuple(content)!=expected_content:raise AuthorityUnavailable('Writer Domain record differs from actual stage/receipt serialization')
    return raw

def read_foreground_writer_domain_prior_v3(db,stage,receipt,content):
    c=_active(db)
    if c is None:return False,None
    _domain_shape(c,stage,receipt,content)
    key=(*c.namespace.as_tuple,stage.operation_id)
    names=('domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest')
    handled,row=c.output_row(_DOMAIN,names,('bot','persona','operation_id'),key)
    if handled:return True,row
    header=_small(c,_DOMAIN,('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if header is None:return True,None
    handled,row=c.prior_row(_DOMAIN,names,('bot','persona','operation_id'),key)
    if not handled:raise AuthorityUnavailable('Writer cannot treat uncaptured existing Domain Body as verified equal')
    return True,row

def _frame_allowed(c,frame):
    if frame is c.frame:return True
    from .current_method_learning_read_v3 import _method_post_commit_active_v3
    successor=_method_post_commit_active_v3(c.db)
    return(successor is not None and successor.prior_frame is c.frame and frame.snapshot is successor.snapshot
        and frame.query_coverage==successor.coverage and frame.envelope.identity.operation_id==c.primary.operation_id)

def _actual_life_recorder(recorder):
    from .artifact_phase_postconditions_v1 import record_artifact_phase_postcondition_after_cas_v1
    from .artifact_phase_observation_v1 import record_artifact_phase_observation_after_cas_v1
    from .artifact_task_observer_v1 import record_artifact_task_milestone_after_cas_v2
    from .artifact_task_text_extent_v1 import record_artifact_task_text_extent_after_cas_v1
    from .foreground_activity_issuance_v1 import record_foreground_life_scope_after_commit_v1
    from .ingress_artifact_task_scope_v1 import record_task_scope_after_commit_v1
    from .source_note_foreground_v1 import record_source_note_responsibility_after_cas_v1
    from .d08_source_note_action_v1 import record_source_note_action_after_cas_v1
    from .d02_life_body_preparation_v1 import record_life_body_preparation_after_cas_v1
    from .d11_life_preparation_v1 import record_registered_life_plan_v2
    from .d10_life_outcome_v2 import record_current_life_outcome_v2
    from .d11_artifact_draft_content_v1 import record_artifact_draft_content_after_cas_v1,record_artifact_draft_phase_verified_after_cas_v2
    from .d08_life_admission_v1 import record_draft_action_root_v1
    return recorder in {record_artifact_phase_postcondition_after_cas_v1,record_artifact_phase_observation_after_cas_v1,
        record_artifact_task_milestone_after_cas_v2,record_artifact_task_text_extent_after_cas_v1,
        record_foreground_life_scope_after_commit_v1,record_task_scope_after_commit_v1,
        record_source_note_responsibility_after_cas_v1,record_source_note_action_after_cas_v1,
        record_life_body_preparation_after_cas_v1,record_registered_life_plan_v2,record_current_life_outcome_v2,
        record_artifact_draft_content_after_cas_v1,record_artifact_draft_phase_verified_after_cas_v2,record_draft_action_root_v1}

def _life_value(c,recorder,frame,kind,ref,operation_id,value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if not _actual_life_recorder(recorder)or not _frame_allowed(c,frame):
        raise AuthorityUnavailable('Writer Life output requires its actual installed typed recorder/frame')
    raw=plain_v1(value);wire=canonical_serialize(raw)
    if operation_id!=c.primary.operation_id:
        # Existing Action roots may be reused only from this exact completed prior slot.
        if kind!='draft_action':raise AuthorityUnavailable('Writer cannot create another producer operation output')
        return raw,wire,False
    op=c.primary.operation_kind
    if kind=='activity_scope':
        from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1
        from .d11_life_contract_v1 import LifeInputRefV1
        e=c.reader.evidence;root=e.root_capability
        if root is None or op=='derive_ingress_artifact_task_scope_v1':
            raise AuthorityUnavailable('Writer has no exact ordinary activity-scope output')
        key=AtomKey.from_token(e.request.plan_source_ref)
        handled,atom=read_foreground_writer_head_v3(c.db,c.namespace,key)
        if not handled or atom.revision<1:raise AuthorityUnavailable('Activity scope requires unchanged exact plan Source')
        if key in c.declared_writes:raise AuthorityUnavailable('Activity scope cannot substitute a newly written plan Source')
        expected=DraftActivityScopeV1(c.receipt.activity_id,e.current_self.self_entity_ref,e.request.ingress_operation_id,
            e.request.c02_operation_id,LifeInputRefV1(key.token,atom.revision,canonical_digest(atom.value)),
            e.request.parent_budget_lease_ref,root.registration_ref,canonical_digest(plain_v1(root)),e.valid_until_utc,
            frame.owner_guard.grant_ref,frame.owner_guard.grant_revision,frame.owner_guard.grant_digest)
        expected_ref='foreground-scope:'+canonical_digest((c.namespace,expected))[:48]
        if raw!=plain_v1(expected)or ref!=expected_ref:raise AuthorityUnavailable('Writer activity scope changed exact Self/Source/Root/digest')
    elif kind in {'artifact_candidate_preparation_parent','artifact_phase_postcondition_policy','artifact_phase_postcondition_contract',
            'artifact_phase_assessment','artifact_task_milestone_v2','artifact_task_text_extent','source_note_foreground_responsibility',
            'artifact_phase_observation_basis_v1','draft_root_capability','artifact_task_scope','artifact_task_objective',
            'artifact_task_continuation_authorization_v2','artifact_task_amendment'}:
        fields={'artifact_candidate_preparation_parent':'candidate_preparation_parent',
            'artifact_phase_postcondition_policy':'postcondition_policy','artifact_phase_postcondition_contract':'postcondition_contract',
            'artifact_phase_assessment':'phase_assessment','artifact_task_milestone_v2':'artifact_task_milestone',
            'artifact_task_text_extent':'artifact_task_text_extent','source_note_foreground_responsibility':'responsibility',
            'artifact_phase_observation_basis_v1':'artifact_observation_basis','draft_root_capability':'draft_root_capability',
            'artifact_task_scope':'artifact_task_scope','artifact_task_objective':'artifact_task_objective',
            'artifact_task_continuation_authorization_v2':'artifact_task_scope','artifact_task_amendment':'artifact_task_amendment'}
        if c.domain_content is None:raise AuthorityUnavailable('Writer Life output requires its actually recorded Domain DTO')
        provenance=c.domain_content[1].get('provenance',{})
        expected=provenance.get(fields[kind])
        if kind=='artifact_task_continuation_authorization_v2':
            expected=None if expected is None else expected.get('continuation_authorization')
        if kind=='artifact_task_amendment':
            from .artifact_task_amendment_v1 import amendment_from_scope_v1
            from .ingress_artifact_task_scope_v1 import _decode,IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1
            scope=_decode(provenance['artifact_task_scope'],IngressArtifactTaskScopeOriginalV1)
            objective=_decode(provenance['artifact_task_objective'],ArtifactTaskObjectiveV1)
            expected=plain_v1(amendment_from_scope_v1(scope,objective))
        if raw!=expected:raise AuthorityUnavailable('Writer signed output changed actual Domain provenance member')
        if kind=='draft_root_capability':expected_ref=raw['registration_ref']
        elif kind=='artifact_task_scope':
            from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
            expected_ref=task_scope_ref_v1(raw['root']['registration_ref'])
        elif kind=='artifact_task_objective':
            from .ingress_artifact_task_scope_v1 import task_objective_ref_v1
            expected_ref=task_objective_ref_v1(value)
        elif kind=='source_note_foreground_responsibility':
            from .foreground_cycle_v1 import foreground_responsibility_ref_v1
            expected_ref=foreground_responsibility_ref_v1(c.namespace,raw['c02_operation_id'])
        elif kind=='artifact_task_text_extent':
            from .artifact_task_text_extent_v1 import artifact_task_text_extent_ref_v1
            expected_ref=artifact_task_text_extent_ref_v1(value)
        elif kind=='artifact_task_amendment':
            from .artifact_task_amendment_v1 import amendment_original_ref_v1
            expected_ref=amendment_original_ref_v1(value)
        else:expected_ref=value.original_ref
        if ref!=expected_ref:raise AuthorityUnavailable('Writer Life output changed exact typed derived reference')
    elif kind=='plan':
        from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
        if type(value)is not RegisteredDraftFilePlanV3:raise AuthorityUnavailable('Writer final plan is not actual typed draft plan')
        if op=='input:register_artifact_draft_plan_v3':
            if value!=c.request.plan or ref!=c.request.original_ref:raise AuthorityUnavailable('Writer plan changed exact registered request')
        elif op=='input:register_artifact_phase_draft_plan_v2':
            from .d11_life_product_adapter_v1 import artifact_phase_draft_plan_ref_v2
            if ref!=artifact_phase_draft_plan_ref_v2(c.request.selector)or value.target.root_registration_ref!=c.request.selector.task.root_registration_ref:
                raise AuthorityUnavailable('Writer phase plan changed exact task/derived slot')
        else:raise AuthorityUnavailable('Writer command cannot produce a final plan')
        # Actual typed recorder has already checked Body/build/action authority. Frozen refs must be actual selected current values.
        for name in ('project','recipe','action_intent','input_source','input_access'):
            frozen=getattr(value,name);key=AtomKey.from_token(frozen.ref)
            handled,atom=read_foreground_writer_head_v3(c.db,c.namespace,key)
            if not handled or(atom.revision,canonical_digest(atom.value))!=(frozen.revision,frozen.digest):
                raise AuthorityUnavailable('Writer final plan changed actual frozen current slot')
    elif kind=='outcome':
        if op!='input:register_life_outcome_v2'or value!=c.request.outcome or ref!=c.request.original_ref:
            raise AuthorityUnavailable('Writer Life outcome changed exact registered request')
    elif kind=='c4_phase_verified':
        if op!='verify_artifact_draft_phase_v2'or value is not c.stage.verified or ref!=value.original_ref:
            raise AuthorityUnavailable('Writer phase verification output is not its actual frozen verified stage')
    elif kind in {'c4_adopted','c4_phase_adopted'}:
        from .d11_artifact_draft_content_v1 import _artifact_model_ids,_artifact_model_phase_v2
        p=c.stage.prepared;f=c.stage.frozen;ids=_artifact_model_ids(p)
        expected_kind='c4_phase_adopted'if _artifact_model_phase_v2(p)else'c4_adopted'
        from ..memory_types import source_key
        key=source_key(*c.namespace.as_tuple,c.stage.source.source_id)
        version=next(v for v in c.receipt.write_versions if v.key==key)
        from .d11_artifact_draft_contract_v1 import FrozenDraftContentV1
        from .d11_life_contract_v1 import LifeInputRefV1
        expected_content=plain_v1(FrozenDraftContentV1(LifeInputRefV1(key.token,version.revision,canonical_digest(c.stage.source.to_dict())),
            c.stage.output.content_digest,len(c.stage.source.text.encode()),(key.token,*(x.ref for x in f.sources))))
        if(kind!=expected_kind or ref!=ids['adopt']or raw['selector']!=plain_v1(p.selector)or raw['prepared_digest']!=p.digest
                or raw['content']!=expected_content or raw['adoption_operation_id']!=c.primary.operation_id):
            raise AuthorityUnavailable('Writer content adoption changed actual generated Source/selector/receipt')
        scope_key=(_LIFE,('bot','persona','kind','original_ref'),(*c.namespace.as_tuple,'activity_scope',raw['activity_scope_ref']))
        found=c.owned.get(scope_key)
        if found is None or canonical_digest(json.loads(found[0]['payload_json']))!=raw['activity_scope_digest']:
            raise AuthorityUnavailable('Writer content adoption lost its actual same-CAS activity scope')
    elif kind=='life_body_preparation':
        from .d02_life_body_preparation_v1 import LifeBodyPreparationOriginalV1
        staged=c.stage;write=staged.stage.proposals[0].typed_writes[0]
        root,body,quote,policy=staged.root,staged.body,staged.quote,staged.effect_policy
        version=next(v for v in c.receipt.write_versions if v.key==write.key)
        expected=LifeBodyPreparationOriginalV1(root.action_intent_ref,root.action_intent_digest,root.action_operation_id,
            c.primary.operation_id,root.activity_id,root.effect_id,body.quote_id,1,canonical_digest(body),
            quote.quote_id,quote.version,canonical_digest(quote),write.key.token,version.revision,
            canonical_digest(write.value),quote.d02_settlement_refs[0],policy.component_id,policy.policy_ref,
            policy.revision,canonical_digest(plain_v1(policy)),canonical_digest(c.receipt))
        if raw!=plain_v1(expected)or ref!='life-body:'+c.primary.operation_id:
            raise AuthorityUnavailable('Writer Body output changed actual reservation/quote/receipt')
    elif kind in {'draft_action','source_note_action'}:
        if kind=='draft_action':
            action=c.declared_writes.get(AtomKey.from_token(raw['action_intent_ref']))
            if op not in {'propose_artifact_draft_action','propose_artifact_draft_phase_action_v2'}or action is None:
                raise AuthorityUnavailable('Writer draft root has no actual declared Action slot')
            expected_ref='life-draft-root:'+c.primary.operation_id
        else:
            action=next((w for w in c.declared_writes.values()if w.key.type_name=='d08.action_intent.v1'),None)
            if op!='prepare_selected_source_note_action_v2'or action is None:
                raise AuthorityUnavailable('Writer SourceNote root has no actual selected Action')
            expected_ref='life-root:'+c.primary.operation_id
        versions={v.key:v.revision for v in c.receipt.write_versions}
        commitments=tuple((w.key.token,versions[w.key],canonical_digest(w.value))for w in c.declared_writes.values())
        if(ref!=expected_ref or raw['action_intent_ref']!=action.key.token or raw['action_intent_digest']!=canonical_digest(action.value)
                or raw['action_operation_id']!=c.primary.operation_id or raw['activity_id']!=c.receipt.activity_id
                or raw['effect_id']!=c.receipt.effect_id or sorted(raw['write_commitments'])!=sorted([list(x)for x in commitments])
                or raw['receipt_digest']!=canonical_digest(c.receipt)):
            raise AuthorityUnavailable('Writer action root changed actual typed writes/current receipt')
        for token,revision,digest,producer,receipt_digest in raw['context_commitments']:
            handled,atom=read_foreground_writer_head_v3(c.db,c.namespace,AtomKey.from_token(token))
            if not handled or(atom.revision,canonical_digest(atom.value))!=(revision,digest):
                raise AuthorityUnavailable('Writer action root changed actual captured context')
    else:raise AuthorityUnavailable('Writer command has no declared Life output kind')
    return raw,wire,True

def record_foreground_writer_life_v3(db,*,recorder,frame,actual_receipt=None,issuer,namespace,kind,ref,operation_id,value):
    from .d11_life_preparation_v1 import _record
    c=_active(db)
    if c is None:return _record(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref,operation_id=operation_id,value=value)
    if namespace!=c.namespace or issuer is not c.graph._GraphCoordinator__d11_issuer or actual_receipt is not None and actual_receipt!=c.receipt:
        raise AuthorityUnavailable('Writer Life producer changed actual issuer/namespace/receipt')
    raw,wire,new=_life_value(c,recorder,frame,kind,ref,operation_id,value)
    key=(*namespace.as_tuple,kind,ref);identity=(_LIFE,('bot','persona','kind','original_ref'),key)
    c.pending_slots[identity]=(operation_id,wire,canonical_digest(raw),issuer._signer.sign('d11.life-original.v1',
        canonical_serialize((namespace,kind,ref,canonical_digest(raw)))),new)
    try:return _record(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref,operation_id=operation_id,value=value)
    finally:c.pending_slots.pop(identity,None)

def read_foreground_writer_life_prior_v3(db,*,issuer,namespace,kind,ref,operation_id,value):
    c=_active(db)
    if c is None:return False,None
    key=(*namespace.as_tuple,kind,ref);identity=(_LIFE,('bot','persona','kind','original_ref'),key)
    expected=c.pending_slots.get(identity)
    if expected is None:raise AuthorityUnavailable('Writer Life record has no exact actual typed output declaration')
    names=('producing_operation_id','payload_json','payload_digest','signature')
    handled,row=c.output_row(_LIFE,names,identity[1],key)
    if handled:return True,row
    header=_small(c,_LIFE,('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',key)
    if header is None:
        if not expected[4]:raise AuthorityUnavailable('Writer cannot create a prior producer Action root')
        return True,None
    handled,row=c.prior_row(_LIFE,names,identity[1],key)
    if not handled:raise AuthorityUnavailable('Writer cannot trust uncaptured existing Life Body')
    return True,row

def register_foreground_writer_life_original_v3(db,*,issuer,namespace,kind,ref,operation_id,wire,digest,signature):
    c=_active(db)
    if c is None:return False
    key=(*namespace.as_tuple,kind,ref);identity=(_LIFE,('bot','persona','kind','original_ref'),key)
    expected=c.pending_slots.get(identity)
    if expected is None or expected[:4]!=(operation_id,wire,digest,signature):
        raise AuthorityUnavailable('Writer signed Life output differs from exact declared actual value')
    if not expected[4]:return True
    header=_small(c,_LIFE,('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',key)
    if header!=(operation_id,digest,signature):raise AuthorityUnavailable('Writer Life output requires actual INSERT/equal row')
    c.put(_LIFE,identity[1],key,dict(bot=namespace.bot_id,persona=namespace.persona_id,kind=kind,original_ref=ref,
        producing_operation_id=operation_id,payload_json=wire,payload_digest=digest,signature=signature),
        header_columns=('producing_operation_id','payload_digest','signature'),header=header)
    return True

def declare_foreground_writer_d07_v3(db,*,issuer,namespace,kind,ref,payload,stage,receipt):
    c=_active(db)
    if c is None:return False
    from ..domains.d01.production_operations_v1 import plain_v1
    if(c.primary.operation_kind!='prepare_artifact_phase_observation_v1'or stage is not c.primary or receipt!=c.receipt
            or issuer is not c.graph._GraphCoordinator__d11_issuer or namespace!=c.namespace or kind!='semantic_question'
            or c.domain_content is None):
        raise AuthorityUnavailable('Writer D07 output is not its actual observation Domain stage')
    basis=c.domain_content[1]['provenance']['artifact_observation_basis'];question=basis['question']
    from .artifact_phase_observation_v1 import observation_basis_from_wire_v1
    typed=observation_basis_from_wire_v1(basis)
    if ref!=typed.ids['question']or plain_v1(payload)!=question:
        raise AuthorityUnavailable('Writer D07 question changed actual typed basis member')
    c.pending_slots[_D07,('bot','persona','kind','original_ref'),(*namespace.as_tuple,kind,ref)]=question
    return True

def read_foreground_writer_d07_prior_v3(db,issuer,namespace,kind,ref):
    c=_active(db)
    if c is None:return False,None
    key=(*namespace.as_tuple,kind,ref);identity=(_D07,('bot','persona','kind','original_ref'),key)
    if identity not in c.pending_slots:return False,None
    names=('payload_json','payload_digest','signature')
    handled,row=c.output_row(_D07,names,identity[1],key)
    if handled:return True,(json.loads(row[0]),row[1])
    header=_small(c,_D07,('payload_digest','signature'),'bot=? AND persona=? AND kind=? AND original_ref=?',key)
    if header is None:return True,None
    handled,row=c.prior_row(_D07,names,identity[1],key)
    if not handled:raise AuthorityUnavailable('Writer D07 prior is neither exact absent nor captured EOF')
    return True,None if row is None else(json.loads(row[0]),row[1])

def register_foreground_writer_d07_original_v3(db,issuer,namespace,kind,ref,wire,digest,signature):
    c=_active(db)
    if c is None:return False
    key=(*namespace.as_tuple,kind,ref);identity=(_D07,('bot','persona','kind','original_ref'),key)
    value=c.pending_slots.get(identity)
    if value is None:return False
    if canonical_serialize(value)!=wire or canonical_digest(value)!=digest:
        raise AuthorityUnavailable('Writer D07 bytes differ from actual basis question')
    header=_small(c,_D07,('payload_digest','signature'),'bot=? AND persona=? AND kind=? AND original_ref=?',key)
    if header!=(digest,signature):raise AuthorityUnavailable('Writer D07 DTO requires actual INSERT/equal row')
    c.put(_D07,identity[1],key,dict(bot=namespace.bot_id,persona=namespace.persona_id,kind=kind,original_ref=ref,
        payload_json=wire,payload_digest=digest,signature=signature),header_columns=('payload_digest','signature'),header=header)
    return True

def read_foreground_writer_life_output_refs_v3(db,*,kind,operation_id):
    c=_active(db)
    if c is None:return False,None
    if kind!='activity_scope'or operation_id!=c.primary.operation_id:
        raise AuthorityUnavailable('Writer output-ref lookup has no arbitrary kind/producer scope')
    rows=tuple((key[3],)for(table,keys,key),(values,_,_)in c.owned.items()
        if table==_LIFE and key[:3]==(*c.namespace.as_tuple,kind)and values['producing_operation_id']==operation_id)
    if len(rows)!=1:raise AuthorityUnavailable('Writer content adoption requires its one actual activity-scope output')
    return True,rows

def declare_foreground_writer_values_v3(db,*,recorder,frame,producing_operation_id,candidate_set_ref,context_ref,candidates,context):
    c=_active(db)
    if c is None:return False
    from .d01_production_operations_v1 import InstalledD01ProductionReadersV1,FrozenValuesCandidateSetV1,FrozenValuesContextV1
    from ..domains.d01.production_operations_v1 import plain_v1
    if(type(recorder)is not InstalledD01ProductionReadersV1 or recorder.issuer is not c.graph._GraphCoordinator__d11_issuer
            or c.primary.operation_kind!='input:freeze_values'or producing_operation_id!=c.primary.operation_id
            or(candidate_set_ref,context_ref)!=(c.request.candidate_set_ref,c.request.context_ref)
            or not _frame_allowed(c,frame)or type(candidates)is not FrozenValuesCandidateSetV1 or type(context)is not FrozenValuesContextV1):
        raise AuthorityUnavailable('Writer values output changed actual installed freeze producer/request/frame')
    atoms={a.key:a for a in frame.snapshot.atoms}
    for head in(*candidates.candidate_heads,*context.context_heads,*context.condition_heads):
        atom=atoms.get(head.key)
        if atom is None or atom.revision!=head.revision or not atom.valid:
            raise AuthorityUnavailable('Writer frozen values output has no exact actual post-frame head')
    for kind,ref,value in(('values_candidates',candidate_set_ref,candidates),('values_context',context_ref,context)):
        c.values_slots[kind,ref]=(recorder,frame,canonical_serialize(plain_v1(value)))
    return True

def read_foreground_writer_d01_prior_v3(db,*,recorder,frame,original_ref,producing_operation_id,kind,value,expected):
    c=_active(db)
    if c is None:return False,None
    from ..domains.d01.production_operations_v1 import plain_v1
    declared=c.values_slots.get((kind,original_ref))
    if(declared!=(recorder,frame,canonical_serialize(plain_v1(value)))or producing_operation_id!=c.primary.operation_id
            or tuple(expected)[:2]!=(kind,producing_operation_id)):
        raise AuthorityUnavailable('Writer D01 output differs from exact typed frozen values declaration')
    key=(*c.namespace.as_tuple,original_ref);names=('kind','producing_operation_id','payload_json','payload_digest','signature')
    handled,row=c.output_row(_D01,names,('bot','persona','original_ref'),key)
    if handled:return True,row
    header=_small(c,_D01,('kind','producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND original_ref=?',key)
    if header is None:return True,None
    handled,row=c.prior_row(_D01,names,('bot','persona','original_ref'),key)
    if not handled:raise AuthorityUnavailable('Writer D01 existing output has no captured exact EOF')
    return True,row

def register_foreground_writer_d01_original_v3(db,*,recorder,frame,original_ref,producing_operation_id,kind,value,expected,roots):
    c=_active(db)
    if c is None:return False
    from ..domains.d01.production_operations_v1 import plain_v1
    if c.values_slots.get((kind,original_ref))!=(recorder,frame,canonical_serialize(plain_v1(value))):
        raise AuthorityUnavailable('Writer D01 registration lost actual typed freeze result')
    key=(*c.namespace.as_tuple,original_ref)
    header=_small(c,_D01,('kind','producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND original_ref=?',key)
    if header!=(expected[0],expected[1],expected[3],expected[4]):
        raise AuthorityUnavailable('Writer D01 DTO requires actual INSERT/equal row')
    c.put(_D01,('bot','persona','original_ref'),key,
        dict(bot=c.namespace.bot_id,persona=c.namespace.persona_id,original_ref=original_ref,kind=kind,
            producing_operation_id=producing_operation_id,payload_json=expected[2],payload_digest=expected[3],
            signature=expected[4],source_refs_json=canonical_serialize(roots)),
        header_columns=('kind','producing_operation_id','payload_digest','signature'),header=header)
    return True



_JOB_COLUMNS=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref','phase','work_kind',
    'continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref','operator_versions_json',
    'lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref')
_JOB_HEADER=tuple(name for name in _JOB_COLUMNS if name not in {
    'continuation_json','wake_condition_json','operator_versions_json','usage_json'})

def _expected_jobs(c):
    from .foreground_cycle_v1 import ForegroundCycleStageV1
    from .d07_ingress_recall_acquisition_v1 import D07IngressRecallAcquisitionStageV1
    from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1,ArtifactDraftContentStageV2
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4
    stage=c.stage
    if type(stage)in {ForegroundCycleStageV1,D07IngressRecallAcquisitionStageV1,
            D07IngressRecallResultStageV1,ArtifactDraftContentStageV1,ArtifactDraftContentStageV2}:
        jobs=(stage.after_job,)
    elif type(stage)is SelfC04AdoptionStageV4:
        jobs=(stage.after_child,stage.after_parent)
    else:
        jobs=()
    if any((job.bot_id,job.persona_id)!=c.namespace.as_tuple for job in jobs):
        raise AuthorityUnavailable('Writer frozen RuntimeJob output crossed actual namespace')
    return {job.job_id:job for job in jobs}

def record_foreground_writer_saved_job_v3(db,job,*,recorder):
    c=_BOUND.get()
    if c is None:return False
    expected=c.expected_jobs.get(job.job_id)
    if expected is None:return False
    from .jobs import _save_job
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    if(c.db is not db or c.phase!='captured' or _CAPTURES.get(c)!=c.identity
            or recorder is not _save_job or type(job)is not type(expected) or job!=expected or not db.in_transaction
            or not c.reader.store._lock._is_owned() or c.runtime._active_foreground_issuance_v1 is not c.issued
            or c.runtime._active_foreground_process_lease_v1 is not c.process_lease):
        raise AuthorityUnavailable('RuntimeJob output requires this exact successful typed W01 saver')
    witnesses=tuple(w for w in _ACTIVE.values()if type(w)is _ProductionCommitWitnessV1
        and w.graph is c.graph and w.runtime is c.runtime and w.frame is c.frame and w.stage is c.stage
        and w.scope is c.scope and w.request is c.request)
    if len(witnesses)!=1:
        raise AuthorityUnavailable('RuntimeJob save lost actual same-command W01 witness')
    prior=c.saved_jobs.get(job.job_id)
    record=(job,witnesses[0])
    if prior is not None and prior!=record:
        raise AuthorityUnavailable('Actual RuntimeJob output was saved by another witness')
    c.saved_jobs[job.job_id]=record
    return True

def _register_saved_jobs(c,witness):
    from .jobs import _job_dict,_json
    for job_id,(job,saving_witness)in c.saved_jobs.items():
        if saving_witness is not witness or c.expected_jobs.get(job_id)!=job:
            raise AuthorityUnavailable('RuntimeJob output was not saved by actual receipt witness')
        raw=_job_dict(job)
        for name in ('continuation','wake_condition','operator_versions','usage'):
            value=raw.pop(name)
            raw[name+'_json']=None if value is None else _json(value)
        expected=tuple(raw[name]for name in _JOB_HEADER)
        actual=_small(c,'runtime_jobs',_JOB_HEADER,'job_id=?',(job_id,))
        if actual!=expected:
            raise AuthorityUnavailable('Actual saved RuntimeJob metadata changed before returned CAS receipt')
        c.put('runtime_jobs',('job_id',),(job_id,),raw,header_columns=_JOB_HEADER,header=actual)

def read_bound_foreground_writer_job_v3(db,job_id):
    c=_active(db)
    if c is None:return False,None
    handled,row=read_bound_foreground_writer_point_v3(db,table='runtime_jobs',columns=_JOB_COLUMNS,
        key_columns=('job_id',),key=(job_id,))
    if not handled:return False,None
    from .jobs import _job_from_row
    return True,_job_from_row(row)


def _require_source_binding(c):
    kind,state,frame_record,state_identity,capability,capability_identity,_=c.source
    if kind=='command':
        from .foreground_command_source_v3 import _STATES,_CAPABILITIES,_FRAMES
    else:
        from .artifact_borrowed_source_v3 import _STATES,_CAPABILITIES
        from .artifact_frame_control_reads_v3 import _FRAMES
    if(_STATES.get(c.reader)is not state or _FRAMES.get(id(c.frame))is not frame_record
            or state.identity is not state_identity or state.capability is not capability
            or capability.state is not state or capability.identity is not capability_identity
            or _CAPABILITIES.get(capability)is not capability_identity or state.work is not c.work):
        raise AuthorityUnavailable('Writer lost its exact original registered Source capability/frame binding')
