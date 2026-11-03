"""Independent Owner topology READ and Numeric Source historical metadata proofs."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict,dataclass,fields
from time import monotonic
from uuid import uuid4
from weakref import WeakKeyDictionary
import json
import math

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion,owner_grant_key
from ..runtime_contracts import AuthorityContext,FenceScope,NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import(begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,begin_runtime_cell_read_v3,
    read_runtime_cell_origin_v3)
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_KIND='d04_root_topology_read_v1'
_KEY=object()
_READERS=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()
_CONSUMED=WeakKeyDictionary()
_WRITE=ContextVar('d04_root_topology_write_v1',default=None)
_CHECKPOINT_TYPES=('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2')


@dataclass(frozen=True,slots=True)
class RootTopologyReadRequestV1:
    command_operation_id:str
    command_input_digest:str
    root_operation_id:str
    effective_until:float


def _identity(r):
    return(r.graph,r.work,r.operation,r.fence,r.authority,r.lease,r.session_proof,r.request,
        r.selection_digest,r.graph_stamp,r.operation.deadline_utc,r.initial_monotonic_deadline,r.initial_reading)


def _actual(r):
    if(type(r)is not _RootTopologyReadV1 or _READERS.get(r)!=_identity(r)
            or r.operation.closed or r.work.state is not r or r.work.operation is not r.operation):
        raise AuthorityUnavailable('RootTopology requires its actual registered independent READ Work')
    r.work._require_invocation(r.graph)
    return r


def require_actual_d04_root_topology_owner_reader_v1(reader):
    r=_actual(reader)
    if(r.read_finished or r.fence.scope.operation!='read' or r.complete):
        raise AuthorityUnavailable('RootTopology Owner READ cannot resume its finished Scope')
    _require_factory(r.graph,r.authority,r.lease,r.request)
    return(r.graph,r.graph._GraphCoordinator__content_fence_v2,r.bundle,r.fence.scope,
        ((r.authority.purpose,tuple(r.authority.audience),()),))


def _require_factory(graph,authority,lease,request):
    from ..graph_coordinator import OwnerLeaseBindingV1
    from .d04_owner_initialization_v3 import _operation,_installation,TOPOLOGY_SCHEMA
    if(type(authority)is not AuthorityContext or authority.issuer_domain!='d12'
            or 'persona'not in authority.owner_scope or type(request)is not RootTopologyReadRequestV1):
        raise AuthorityUnavailable('RootTopology has only its actual installed D12 Owner command')
    _operation(request.command_operation_id);_operation(request.root_operation_id)
    if(type(request.effective_until)is not float or not math.isfinite(request.effective_until)
            or request.command_input_digest!=canonical_digest((TOPOLOGY_SCHEMA,authority.namespace,
                request.command_operation_id,request.root_operation_id,request.effective_until))):
        raise AuthorityUnavailable('RootTopology command differs from its actual typed mutation')
    graph._authorize(lease,authority,frozenset({'d04','d11','d12'}),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if(type(owner)is not OwnerLeaseBindingV1 or session is None or 'workbench.activate'not in owner.capabilities
            or owner.namespace!=authority.namespace or owner.actor!=authority.actor or session[1].principal!=owner.principal):
        raise AuthorityUnavailable('RootTopology requires its actual signed Owner lease/session and activate capability')
    assembly,preset=_installation(graph,authority)
    return owner,session,assembly,preset


def _column_selector(r,name):
    ns=r.namespace.as_tuple;rootop=r.request.root_operation_id
    fixed={
        'root':('graph_d04_root_originals_v3','original_json',('bot','persona','operation_id'),(*ns,rootop),('original_digest',)),
        'freeze':('runtime_d11_d04_root_freezes_v3','original_json',('bot','persona','operation_id'),(*ns,rootop),('signature',)),
        'event_revisions':('graph_events','revisions',('bot','persona','session','event_id'),(*ns,'d04.authored_root.v3',rootop),('digest','epoch_revision')),
        'event_invalidated':('graph_events','invalidated',('bot','persona','session','event_id'),(*ns,'d04.authored_root.v3',rootop),('digest','epoch_revision'))}
    if name in fixed:return fixed[name]
    if r.freeze is None or r.root is None or r.freeze.original_digest!=r.root.signed_freeze_digest:
        raise AuthorityUnavailable('RootTopology budget locator has no actual verified signed root freeze')
    f=r.freeze
    budget={
        'grant':('runtime_budget_grants','grant_json',('lease_id','version'),(f.parent_budget_lease_ref,f.grant_version),('signature',)),
        'reserve':('runtime_budget_operations','receipt_json',('bot_id','persona_id','operation_id','phase'),(*ns,f.reserve_operation_id,'reserve'),('digest','lease_id')),
        'quote':('runtime_budget_reservations','ceiling_json',('lease_id','operation_id'),(f.parent_budget_lease_ref,f.reserve_operation_id),('digest',))}
    if name not in budget:raise AuthorityUnavailable('RootTopology has no such original selector')
    return budget[name]


class _RootTopologyReadV1:
    def __init__(self,key,graph,authority,lease,request,operation,fence,reading,now,owner,session,assembly,preset):
        if key is not _KEY:raise TypeError('RootTopology has no public reader constructor')
        self.graph,self.authority,self.lease,self.request=graph,authority,lease,request
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.runtime=graph._GraphCoordinator__domain_production_runtime_v1
        self.bundle,self.preset=assembly.admin_bundle,preset
        self.namespace,self.operation,self.fence=authority.namespace,operation,fence
        self.operation_id,self.selection_digest=operation.operation_id,operation.selection_digest
        self.graph_stamp=(fence.metadata,fence.epoch)
        self.owner_binding,self.session_proof,self.owner_guard=owner,session,None
        self.owner_entry=self.owner_snapshot=self.work=None
        self.owner_task=None
        self.initial_reading,self.initial_now_utc=reading,now
        self.initial_monotonic_deadline=monotonic()+operation.deadline_utc-now
        self.read_finished=self.complete=False
        self.phase='owner';self.columns={};self.column_specs={};self.values={};self.headers={}
        self.queue=[];self.census=[];self.cursor='';self.reserved=0
        self.root=self.freeze=self.candidate=self.members=self.member_rows=None
        self.result=None;self.pending_write_scope=None
    @property
    def now_utc(self):
        from .first_ingress_v2 import trusted_upper
        now=trusted_upper(self.initial_reading)
        if now>=self.operation.deadline_utc or monotonic()>=self.initial_monotonic_deadline:
            raise AuthorityUnavailable('RootTopology exceeded its original installed READ deadline')
        return now
    def require_current(self,*,meter):
        _actual(self);self.now_utc
        self.operation.handle.require_current(meter)
        if(self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp
                or self.graph._GraphCoordinator__owner_session_proofs.get(self.lease)!=self.session_proof):
            raise AuthorityUnavailable('RootTopology current Graph/Owner session changed')
        return self
    @contextmanager
    def quantum_v1(self):
        _actual(self)
        if self.read_finished:raise AuthorityUnavailable('RootTopology cannot reopen its completed READ')
        self.owner_entry.require_permission_v3(self)
        with bind_runtime_storage_operation_v3(self.operation,self.db),self.store._lock,runtime_storage_quantum_v3(self.db)as meter:
            if self.db.in_transaction:raise AuthorityUnavailable('RootTopology requires its own actual READ quantum')
            self.db.execute('BEGIN')
            try:
                self.require_current(meter=meter)
                yield meter
                self.require_current(meter=meter)
            finally:self.db.rollback()
        self.owner_entry.require_permission_v3(self)
    def reserve(self):
        from .dispatch_current_inventory_v3 import _heap
        size=_heap((self.values,self.headers,self.census,self.root,self.freeze,self.candidate,
            self.members,self.member_rows))+65536
        if size>self.reserved:self.operation.retain(size-self.reserved);self.reserved=size
    def add_column(self,name,table,column,key_columns,key,header_columns):
        if name in self.columns:return
        if(table,column,tuple(key_columns),tuple(key),tuple(header_columns))!=_column_selector(self,name):
            raise AuthorityUnavailable('RootTopology column is outside its exact signed original recipe')
        where=' AND '.join(n+'=?'for n in key_columns)
        with self.quantum_v1()as meter:
            header=meter.read_fixed_row(self.db,table,tuple(header_columns),where,key)
        if header is None:raise AuthorityUnavailable('RootTopology fixed producing original/control is absent: '+name)
        self.column_specs[name]=(table,column,tuple(key_columns),tuple(key),tuple(header_columns),header)
        self.columns[name]=DispatchOriginalJSONReadV3(self,table=table,column=column,key_columns=tuple(key_columns),key=tuple(key))
        self.queue.append(name)
    def add_atom(self,name,key):
        from ..domains.d12.types import character_draft_key,active_scheme_head_key
        from ..domains.d01 import _activation_key
        expected={'draft':character_draft_key(self.namespace),'head':active_scheme_head_key(self.namespace),
            'activation':_activation_key(self.namespace)}
        if name not in expected or key!=expected[name]:
            raise AuthorityUnavailable('RootTopology administrative keys do not grant generic Graph Body')
        with self.quantum_v1()as meter:
            row=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(key.token,*self.namespace.as_tuple))
            if row is None or row[0]<1 or row[1]!=1:raise AuthorityUnavailable('RootTopology fixed administrative control is absent/invalid')
            header=tuple(begin_runtime_cell_read_v3(self.db,row[2],erasure_owner_ref=key.token,meter=meter).header)
        self.headers[key.token]=(row,header)
        self.columns[name]=DispatchOriginalJSONReadV3(self,table='graph_atoms',column='value',
            key_columns=('token','bot','persona'),key=(key.token,*self.namespace.as_tuple),cell_id=row[2])
        self.queue.append(name)
    def advance_column(self):
        name=self.queue[0];column=self.columns[name]
        with self.quantum_v1()as meter:column.advance(meter)
        if column.complete:
            self.values[name]=column.require_v3(self);self.queue.pop(0);self.reserve()


def prepare_current_d04_root_topology_read_v1(graph,authority,lease,*,operation_id,root_operation_id,effective_until,request_digest):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from .first_ingress_v2 import trusted_upper
    request=RootTopologyReadRequestV1(operation_id,request_digest,root_operation_id,float(effective_until))
    owner,session,assembly,preset=_require_factory(graph,authority,lease,request)
    require_graph_storage_work_admission_v3(graph)
    port=graph._GraphCoordinator__content_fence_v2
    reading=port.read_ingress_clock(assembly.admin_bundle.ingress_clock);now=trusted_upper(reading)
    deadline=assembly.admin_bundle.installation_policy.root_grant.valid_until_utc
    if now>=deadline:raise AuthorityUnavailable('RootTopology actual installed Root grant expired')
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,'d04-root-topology-read:'+uuid4().hex,deadline)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation.operation_id,owner_session_proof=session)
        r=_RootTopologyReadV1(_KEY,graph,authority,lease,request,operation,fence,reading,now,owner,session,assembly,preset)
        work=create_graph_storage_work_v3(graph,kind=_KIND,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=r,operation=operation)
        r.work=work;_READERS[r]=_identity(r)
        return work
    except BaseException:
        if fence is not None:graph._finish_read_fence_v3(fence)
        finish_runtime_storage_operation_v3(operation)
        raise


def _json(encoded):
    value=json.loads(encoded)
    if canonical_serialize(value)!=encoded:raise AuthorityUnavailable('RootTopology original nested canonical EOF differs')
    return value


def _decode_signed_root_v1(namespace,root_operation_id,preset,issuer,root_raw,root_digest,root_eof,freeze_raw,freeze_signature):
    from .d04_root_original_store_v3 import D04RootOriginalV3,_body
    from .d11_d04_root_freeze_v3 import D11RootFreezeOriginalV3,_content,_SIGN_KIND,D11RootFreezeReadV3
    from ..domains.d04.authored_lineage_v3 import decode_authored_root_candidate_v3
    if(set(root_raw)!={f.name for f in fields(D04RootOriginalV3)}-{'original_digest'}
            or root_eof!=root_digest):
        raise AuthorityUnavailable('RootTopology exact root original whole-column commitment differs')
    root=D04RootOriginalV3(**{**root_raw,'namespace':NamespaceId(**root_raw['namespace']),
        'original_digest':root_digest})
    if(canonical_digest(_body(root))!=root.original_digest or root.namespace!=namespace
            or root.operation_id!=root_operation_id
            or root.status!='authored_root_committed_no_observed_sources'):
        raise AuthorityUnavailable('RootTopology initial authored root whole EOF/identity differs')
    if set(freeze_raw)!={f.name for f in fields(D11RootFreezeOriginalV3)}:
        raise AuthorityUnavailable('RootTopology signed freeze exact fields differ')
    issuer._signer.verify(_SIGN_KIND,canonical_serialize(freeze_raw),freeze_signature)
    freeze=D11RootFreezeOriginalV3(**{**freeze_raw,'namespace':NamespaceId(**freeze_raw['namespace']),
        'quote_ceiling':tuple(tuple(v)for v in freeze_raw['quote_ceiling'])})
    f=freeze
    if(f.namespace!=namespace or f.operation_id!=root_operation_id
            or canonical_digest(_content(f))!=f.original_digest or f.original_digest!=root.signed_freeze_digest):
        raise AuthorityUnavailable('RootTopology actual signed freeze/content differs')
    raw=_json(f.freeze_read_json)
    read=D11RootFreezeReadV3(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'active_scheme_head':VersionedRef(**raw['active_scheme_head']),'draft_head':VersionedRef(**raw['draft_head'])})
    candidate=decode_authored_root_candidate_v3(_json(root.candidate_json))
    output=_json(root.output_json);rows=tuple(tuple(row)for row in output['rows'])
    box=_json(root.initial_box_json)
    box_fields=dict(box);proof_digest=box_fields.pop('proof_digest')
    if(candidate.namespace!=namespace.as_tuple or candidate.preset!=preset
            or read.namespace!=namespace or read.operation_id!=root_operation_id
            or read.candidate_digest!=candidate.digest or read.preset_digest!=preset.digest
            or read.authored_write_set_digest!=root.write_set_digest
            or _json(read.authored_write_set_json)!=output['rows']or canonical_digest(rows)!=root.write_set_digest
            or len(rows)!=6 or any(rev!=1 for _,rev,_ in rows)
            or tuple(ref for ref,_,_ in rows)!=tuple(sorted({ref for ref,_,_ in rows}))
            or output['issuance_digest']!=read.output_projection_digest
            or proof_digest!=read.abi2_initial_box_digest or canonical_digest(box_fields)!=proof_digest
            or box['candidate_digest']!=candidate.digest
            or canonical_digest(box['production_binding'])!=box['binding_digest']):
        raise AuthorityUnavailable('RootTopology signed initial candidate/output/read set differs')
    return root,freeze,candidate,rows,read


def _root_values(r):
    r.root,r.freeze,r.candidate,rows,read=_decode_signed_root_v1(r.namespace,r.request.root_operation_id,r.preset,
        r.graph._GraphCoordinator__d11_issuer,r.values['root'],r.column_specs['root'][5][0],r.columns['root'].sha256,
        r.values['freeze'],r.column_specs['freeze'][5][0])
    f=r.freeze
    from ..domains.d12.types import CharacterDraft,ActiveSchemeHeadV1,character_draft_key,active_scheme_head_key
    draft_raw=dict(r.values['draft']);draft_raw.pop('schema')
    head_raw=dict(r.values['head']);head_raw.pop('schema')
    draft,head=CharacterDraft(**draft_raw),ActiveSchemeHeadV1(**head_raw)
    dk,hk=character_draft_key(r.namespace),active_scheme_head_key(r.namespace)
    if(draft.scope!=r.namespace.persona_id or draft.revision!=r.headers[dk.token][0][0]
            or head.scope!=r.namespace.persona_id or head.generation!=r.headers[hk.token][0][0]
            or head.adopted_operation_id!=r.request.root_operation_id or head.draft_ref!=dk.token
            or head.draft_revision!=draft.revision or head.draft_digest!=canonical_digest(draft)
            or read.active_scheme_head!=VersionedRef(hk.token,head.generation)
            or read.draft_head!=VersionedRef(dk.token,draft.revision)or read.draft_digest!=canonical_digest(draft)
            or r.request.effective_until<=r.candidate.cursor):
        raise AuthorityUnavailable('RootTopology requires its exact current adopted root draft/head and positive interval')
    r.member_rows=rows
    r.add_column('grant','runtime_budget_grants','grant_json',('lease_id','version'),
        (f.parent_budget_lease_ref,f.grant_version),('signature',))
    r.add_column('reserve','runtime_budget_operations','receipt_json',('bot_id','persona_id','operation_id','phase'),
        (*r.namespace.as_tuple,f.reserve_operation_id,'reserve'),('digest','lease_id'))
    r.add_column('quote','runtime_budget_reservations','ceiling_json',('lease_id','operation_id'),
        (f.parent_budget_lease_ref,f.reserve_operation_id),('digest',))
    r.add_column('event_revisions','graph_events','revisions',('bot','persona','session','event_id'),
        (*r.namespace.as_tuple,'d04.authored_root.v3',r.request.root_operation_id),('digest','epoch_revision'))
    r.add_column('event_invalidated','graph_events','invalidated',('bot','persona','session','event_id'),
        (*r.namespace.as_tuple,'d04.authored_root.v3',r.request.root_operation_id),('digest','epoch_revision'))


def _signed_budget(r):
    from .issuers import _decode_grant
    from .d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3
    f=r.freeze;payload=canonical_serialize(r.values['grant']);signature=r.column_specs['grant'][5][0]
    r.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1',payload,signature)
    grant=_decode_grant(payload)
    if((grant.lease_id,grant.version)!=(f.parent_budget_lease_ref,f.grant_version)
            or signature!=f.grant_signature or canonical_digest(asdict(grant))!=f.grant_digest
            or grant.allowed_work_kinds!=(ROOT_WORK_KIND_V3,)or tuple(sorted(grant.max_ceiling.items()))!=f.quote_ceiling
            or r.column_specs['reserve'][5]!=(f.reserve_digest,f.parent_budget_lease_ref)
            or canonical_digest(r.values['reserve'])!=f.reserve_receipt_digest
            or r.column_specs['quote'][5]!=(f.reserve_digest,)
            or tuple(sorted(r.values['quote'].items()))!=f.quote_ceiling):
        raise AuthorityUnavailable('RootTopology original signed grant/reservation/quote differs')
    event=r.column_specs['event_revisions'][5]
    receipt={'status':'committed','revisions':r.values['event_revisions'],'invalidated':[],
        'epoch':{'bot':r.namespace.bot_id,'persona':r.namespace.persona_id,'revision':event[1]}}
    if(event!=r.column_specs['event_invalidated'][5]or event[0]!=r.root.graph_event_digest
            or r.values['event_invalidated']!=[]or r.values['event_revisions']!=[[ref,1]for ref,_,_ in r.member_rows]
            or canonical_digest(receipt)!=r.root.graph_receipt_digest):
        raise AuthorityUnavailable('RootTopology genuine producing GraphReceipt membership differs')


def _numeric_members(r,meter):
    from ..domains.d04.authored_lineage_v3 import(decode_authored_numeric_checkpoint_v2,
        decode_authored_feeling_state_v1,decode_authored_mood_state_v1,validate_authored_joint_predecessor_v3)
    rows={ref:(revision,value)for ref,revision,value in r.member_rows}
    members={};checkpoints=set()
    for ref,(revision,value)in rows.items():
        key=AtomKey.from_token(ref)
        if(NamespaceId.from_key(key)!=r.namespace or key.owner.kind!='persona' or revision!=1):
            raise AuthorityUnavailable('RootTopology signed root has foreign/noninitial numeric rows')
        if key.type_name!='d04.numeric_checkpoint.v2':continue
        checkpoint=decode_authored_numeric_checkpoint_v2(value)
        state_ref=checkpoint.graph_state.ref
        if state_ref not in rows or rows[state_ref][0]!=1:raise AuthorityUnavailable('RootTopology signed state member is absent')
        state_value=rows[state_ref][1]
        decode=decode_authored_feeling_state_v1 if checkpoint.block.kind=='feeling'else decode_authored_mood_state_v1
        state=decode(state_value)
        if(key.name!=checkpoint.block.block_id or checkpoint.namespace!=r.namespace.as_tuple
                or checkpoint.commit_operation_id!=r.request.root_operation_id or state.root_operation_id!=r.request.root_operation_id
                or checkpoint.root_candidate_digest!=r.candidate.digest or state.root_candidate_digest!=r.candidate.digest
                or state.status!='authored_initial_parameter_not_observation'or state.active_driver_refs
                or getattr(state,'historical_source_refs',())or getattr(state,'source_refs',())
                or getattr(state,'interpretation_refs',())or checkpoint.block.template_id in members):
            raise AuthorityUnavailable('RootTopology has only exact initial source-free authored numeric members')
        validate_authored_joint_predecessor_v3(checkpoint,state,1)
        members[checkpoint.block.template_id]=(ref,checkpoint);checkpoints.add(ref)
    templates={t.template_id:t.kind for t in r.preset.block_templates}
    if(set(members)!=set(templates)or len(checkpoints)!=3
            or any(members[k][1].block.kind!=v for k,v in templates.items())
            or {ref for ref,_,_,_ in r.census}!=checkpoints):
        raise AuthorityUnavailable('RootTopology complete checkpoint HEAD census/template set differs')
    for ref,revision,value in r.member_rows:
        key=AtomKey.from_token(ref)
        head=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,ref))
        history=meter.read_fixed_row(r.db,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
            'token=? AND revision=?',(ref,1))
        if(head is None or head[:2]!=(1,1)or history!=(1,*r.namespace.as_tuple,'d04.authored_root.v3',r.request.root_operation_id,head[2])):
            raise AuthorityUnavailable('RootTopology current/history are not the unadvanced original GV1 members')
        header=tuple(begin_runtime_cell_read_v3(r.db,head[2],erasure_owner_ref=ref,meter=meter).header)
        if header[5]!=canonical_digest(value):raise AuthorityUnavailable('RootTopology numeric whole-value commitment changed')
        read_runtime_cell_origin_v3(r.db,head[2],header=header,meter=meter)
        r.headers[ref]=(head,header)
    r.members=members


def advance_current_d04_root_topology_read_v1(graph,work):
    from ..graph_worker import GraphStorageStepV3
    r=_actual(work.state)
    if graph is not r.graph:raise AuthorityUnavailable('RootTopology Work crossed Graph')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        if r.phase=='owner':
            from ..authority_service.owner_location_read_v3 import prepare_current_host_d04_root_topology_owner_entry_v1
            if r.owner_task is None:r.owner_task=prepare_current_host_d04_root_topology_owner_entry_v1(r)
            if not r.owner_task.advance():return GraphStorageStepV3('progress')
            r.owner_entry=r.owner_task.take_result_v3();r.owner_task=None
            r.owner_binding=r.owner_entry.require_permission_v3(r);r.owner_guard=r.owner_entry.current_owner_guard
            r.owner_value=r.owner_entry.grant_value_v3(r)
            r.phase='initial_columns'
        elif r.phase=='initial_columns':
            from ..domains.d12.types import character_draft_key,active_scheme_head_key
            from ..domains.d01 import _activation_key
            r.add_column('root','graph_d04_root_originals_v3','original_json',('bot','persona','operation_id'),
                (*r.namespace.as_tuple,r.request.root_operation_id),('original_digest',))
            r.add_column('freeze','runtime_d11_d04_root_freezes_v3','original_json',('bot','persona','operation_id'),
                (*r.namespace.as_tuple,r.request.root_operation_id),('signature',))
            r.add_atom('draft',character_draft_key(r.namespace));r.add_atom('head',active_scheme_head_key(r.namespace))
            r.add_atom('activation',_activation_key(r.namespace));r.phase='root_columns'
        elif r.phase=='root_columns':
            if r.queue:r.advance_column()
            else:_root_values(r);r.phase='budget_columns'
        elif r.phase=='budget_columns':
            if r.queue:r.advance_column()
            else:_signed_budget(r);r.phase='census'
        elif r.phase=='census':
            with r.quantum_v1()as meter:
                row=meter.read_fixed_row(r.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND type_name IN (?,?) AND token>? ORDER BY token',
                    (*r.namespace.as_tuple,*_CHECKPOINT_TYPES,r.cursor))
            if row is None:r.phase='verify'
            else:
                if len(r.census)==3:raise AuthorityUnavailable('RootTopology checkpoint namespace has extra members')
                r.census.append(row);r.cursor=row[0];r.reserve()
        elif r.phase=='verify':
            with r.quantum_v1()as meter:
                _numeric_members(r,meter)
                owner_key=owner_grant_key(*r.namespace.as_tuple)
                row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,owner_key.token))
                if row is None or row[0]<1 or row[1]!=1:raise AuthorityUnavailable('RootTopology current Owner control disappeared')
                header=tuple(begin_runtime_cell_read_v3(r.db,row[2],erasure_owner_ref=owner_key.token,meter=meter).header)
                if header[5]!=canonical_digest(r.owner_value):raise AuthorityUnavailable('RootTopology Owner control differs from actual Owner EOF')
                r.headers[owner_key.token]=(row,header)
                for name in('draft','head','activation'):
                    key=AtomKey.from_token(r.columns[name].key[0]);r.store._registry.validate(key,r.values[name])
            from ..authority_service.owner_location_read_v3 import freeze_current_d04_root_topology_owner_eof_v1
            r.owner_snapshot=freeze_current_d04_root_topology_owner_eof_v1(r)
            r.owner_entry.require_permission_v3(r);graph._validate_read_fence_v3(r.fence)
            graph._finish_read_fence_v3(r.fence);r.read_finished=True;r.complete=True
            r.result=PreparedCurrentD04RootTopologyV1(_KEY,r);r.reserve()
            return GraphStorageStepV3('complete',r.result)
        else:raise AuthorityUnavailable('RootTopology Work is already terminal')
    return GraphStorageStepV3('progress')


class PreparedCurrentD04RootTopologyV1:
    def __init__(self,key,reader):
        if key is not _KEY or not reader.complete or not reader.read_finished:raise TypeError('actual completed RootTopology READ required')
        self.reader=reader;_CONSUMED[self]=False
        _PREPARED[self]=(_identity(reader),reader.root,reader.freeze,reader.candidate,reader.members,reader.member_rows,
            reader.owner_snapshot,reader.headers,reader.values,reader.census,_seal(reader))
    @property
    def consumed(self):return _CONSUMED.get(self,False)
    def require_invocation_v1(self,graph,authority,lease,*,operation_id,request_digest,domains,capability):
        r=_prepared(self)
        if(not self.consumed or graph is not r.graph or authority is not r.authority or lease is not r.lease
                or(operation_id,request_digest)!=(r.request.command_operation_id,r.request.command_input_digest)
                or tuple(domains)!=('d04','d11','d12')or capability!='workbench.activate'):
            raise AuthorityUnavailable('RootTopology retained READ differs from its exact original Owner WRITE')
        return self
    def observe_write_v1(self,graph,authority,lease,*,issuer,scope,original_owner,session_proof,metadata,epoch):
        r=_prepared(self)
        self.require_invocation_v1(graph,authority,lease,operation_id=r.request.command_operation_id,
            request_digest=r.request.command_input_digest,domains=('d04','d11','d12'),capability='workbench.activate')
        expected='owner-domain-'+canonical_digest((r.namespace,r.request.command_operation_id,r.request.command_input_digest))[:48]
        if(issuer is not graph._GraphCoordinator__graph_capability or type(scope)is not FenceScope
                or scope.operation!='write'or scope.namespace!=r.namespace
                or scope.operation_id!=expected or scope.permit.operation_id!=expected
                or scope is r.fence.scope or session_proof!=r.session_proof or original_owner!=r.owner_binding
                or(metadata,epoch)!=r.graph_stamp):
            raise AuthorityUnavailable('RootTopology fresh WRITE observation has no actual Root-issued command Scope')
        r.pending_write_scope=scope
        from ..authority_service.owner_location_read_v3 import observe_current_d04_root_topology_owner_write_v1
        return observe_current_d04_root_topology_owner_write_v1(r,graph,authority,lease,scope,original_owner,session_proof,metadata,epoch)
    def release_payload_v1(self):
        r=self.reader
        if r is None:return
        _PREPARED.pop(self,None);_CONSUMED.pop(self,None);self.reader=None
        _release(r)


def _seal(r):
    return canonical_digest((r.root.original_digest,r.freeze.original_digest,r.candidate.digest,
        r.member_rows,r.members,r.values,r.owner_value,r.headers,r.census))


def _prepared(value):
    record=_PREPARED.get(value)
    if(type(value)is not PreparedCurrentD04RootTopologyV1 or record is None or value.reader is None):
        raise AuthorityUnavailable('actual retained RootTopology private qualification required')
    r=_actual(value.reader)
    if(record[:10]!=(_identity(r),r.root,r.freeze,r.candidate,r.members,r.member_rows,r.owner_snapshot,r.headers,r.values,r.census)
            or record[10]!=_seal(r) or not r.complete or not r.read_finished or r.result is not value):
        raise AuthorityUnavailable('RootTopology complete original EOF qualification changed')
    r.now_utc
    return r


def consume_current_d04_root_topology_read_v1(value,*,graph,work):
    r=_prepared(value)
    if r.graph is not graph or r.work is not work or value.consumed:
        raise AuthorityUnavailable('RootTopology private result may be consumed once only')
    _CONSUMED[value]=True
    return value


def require_actual_d04_root_topology_write_reader_v1(reader,scope):
    r=_actual(reader)
    if(r.result not in _PREPARED or not r.result.consumed or not r.complete or not r.read_finished
            or r.pending_write_scope is not scope or scope is r.fence.scope or scope.operation!='write'):
        raise AuthorityUnavailable('RootTopology WRITE needs its privately retained actual READ/command observation')
    _prepared(r.result)
    return r


def _check_current(r,meter):
    r.require_current(meter=meter)
    for ref,(expected,header)in r.headers.items():
        row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,ref))
        if row!=expected:raise AuthorityUnavailable('RootTopology current fixed header changed before WRITE')
        current=tuple(begin_runtime_cell_read_v3(r.db,row[2],erasure_owner_ref=ref,meter=meter).header)
        if current!=header:raise AuthorityUnavailable('RootTopology actual complete value commitment changed')
        read_runtime_cell_origin_v3(r.db,row[2],header=header,meter=meter)
    cursor='';actual=[]
    while True:
        row=meter.read_fixed_row(r.db,'graph_atoms',('token','revision','valid','value_cell_id'),
            'bot=? AND persona=? AND type_name IN (?,?) AND token>? ORDER BY token',
            (*r.namespace.as_tuple,*_CHECKPOINT_TYPES,cursor))
        if row is None:break
        if len(actual)==3:raise AuthorityUnavailable('RootTopology complete negative checkpoint census changed')
        actual.append(row);cursor=row[0]
    if actual!=r.census:raise AuthorityUnavailable('RootTopology checkpoint HEAD census changed')
    for table,column,keys,key,header_columns,header in r.column_specs.values():
        actual=meter.read_fixed_row(r.db,table,header_columns,' AND '.join(k+'=?'for k in keys),key)
        if actual!=header:raise AuthorityUnavailable('RootTopology immutable original header changed')


@contextmanager
def bind_current_d04_root_topology_write_v1(value,graph,authority,lease,*,issuer,scope,guard,current_owner,metadata,epoch):
    r=_prepared(value)
    require_actual_d04_root_topology_write_reader_v1(r,scope)
    if(issuer is not graph._GraphCoordinator__graph_capability or _WRITE.get()is not None
            or graph is not r.graph or authority is not r.authority or lease is not r.lease
            or not r.db.in_transaction or not r.store._lock._is_owned()):
        raise AuthorityUnavailable('RootTopology needs the actual Root-owned same-transaction WRITE binding')
    from ..authority_service.owner_location_read_v3 import require_current_d04_root_topology_owner_write_v1
    with bind_runtime_storage_operation_v3(r.operation,r.db),runtime_storage_quantum_v3(r.db)as meter:
        require_current_d04_root_topology_owner_write_v1(r,scope,current_owner,guard,metadata,epoch,meter)
        _check_current(r,meter)
    token=_WRITE.set((value,graph,authority,lease,scope,guard,current_owner))
    try:yield value
    finally:_WRITE.reset(token)


def require_current_d04_root_topology_write_v1(value,graph,authority,lease,*,db,scope,current_owner):
    r=_prepared(value);bound=_WRITE.get()
    if(bound is None or bound[:5]!=(value,graph,authority,lease,scope)or bound[6]is not current_owner
            or db is not r.db or not db.in_transaction):
        raise AuthorityUnavailable('RootTopology consumer has no actual same-W01 retained qualification')
    from ..authority_service.owner_location_read_v3 import require_current_d04_root_topology_owner_write_v1
    with runtime_storage_quantum_v3(db)as meter:
        require_current_d04_root_topology_owner_write_v1(r,scope,current_owner,bound[5],*r.graph_stamp,meter)
        _check_current(r,meter)
    return r


def finish_current_d04_root_topology_read_v1(graph,work,error):
    r=work.state
    if r not in _READERS:return
    if error is not None:_release(r)
    else:work.result_lease=r.operation


def release_current_d04_root_topology_result_v1(work):
    r=work.state
    if r not in _READERS:return
    if r.result is not None:
        _PREPARED.pop(r.result,None);_CONSUMED.pop(r.result,None);r.result.reader=None
    _release(r)


def _release(r):
    if r not in _READERS:return
    try:
        if not r.read_finished:r.graph._finish_read_fence_v3(r.fence);r.read_finished=True
    finally:
        try:
            if r.owner_task is not None:r.owner_task.release_v3();r.owner_task=None
            if r.owner_entry is not None:r.owner_entry.release_v3()
        finally:
            _READERS.pop(r,None);r.columns.clear();r.values.clear();r.headers.clear();r.census.clear()
            r.root=r.freeze=r.candidate=r.members=r.member_rows=r.owner_snapshot=r.result=None
            if not r.operation.closed:finish_runtime_storage_operation_v3(r.operation)


# Numeric Source verification is independent from the administrative READ above.
_SOURCE_TOPOLOGY_TASKS=WeakKeyDictionary()
_SOURCE_TOPOLOGY_FACTS=WeakKeyDictionary()
_SOURCE_TOPOLOGY_COLUMNS=WeakKeyDictionary()
_SOURCE_TOPOLOGY_WRITE=ContextVar('d04_source_topology_write_v1',default=None)
_TOPOLOGY_FIELDS=frozenset({'schema','namespace','operation_id','request_digest','installation_id',
    'marker_ref','marker_value','root_operation_id','root_original_digest','root_freeze_digest','policy',
    'owner_admission','prerequisite_rows','write_rows','event_digest','graph_receipt'})



from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class _SourceTopologyMetadataStreamV1(OrdinaryOriginMetadataStreamV3):
    def __init__(self,profile,reserve,*,ensure_ascii=True):
        super().__init__(profile='adoption',ensure_ascii=ensure_ascii,reserve=reserve)
        self.source_profile=profile
        self.input_parser=(_SourceTopologyMetadataStreamV1('numeric_input',reserve)if profile=='prepared'else None)
        self.input_buffer=bytearray();self.string_parsers={};self.string_buffers={};self.string_digests={}
    def _string_metadata_path_v1(self,path):
        return(self.source_profile=='numeric_input'and(path[:1]==('read_rows',)and len(path)==3 and path[-1]=='value_json'
            or path[:2]==('evidence_inputs','read_rows')and len(path)==4 and path[-1]=='value_json'
            or path[:2]==('evidence_inputs','field_payloads')and len(path)==4 and path[-1]==1))
    def _retains(self,path):
        if self.source_profile=='historical_hash':return not path
        if self.source_profile=='historical_job':return not path or path[0]in {'phase','usage_digest','result_ref'}
        if self.source_profile=='numeric_input':
            return not self._string_metadata_path_v1(path)
        if self.source_profile=='prepared':return not path or path[0]in {'binding','original_ref','schema'}
        if self.source_profile!='topology':return True
        if not path:return True
        if path[0]not in _TOPOLOGY_FIELDS:return False
        if path[0]!='prerequisite_rows'or len(path)<3 or path[2]!=2:return True
        row=self.metadata['prerequisite_rows'][path[1]]
        return AtomKey.from_token(row[0]).type_name in {'d12.owner_grant.v1','d01.persona_activation.v1','d12.active_scheme_head.v1'}
    def _commits(self,path):
        return not path or(self.source_profile=='topology'and len(path)==3 and path[0]=='prerequisite_rows'and path[2]==2)
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is not None and state['mode']=='value':
            path=state['path']
            if self.input_parser is not None and path==('input_payload_json',):
                self.input_buffer.extend(chr(codepoint).encode('utf8'))
                if len(self.input_buffer)>=1024:
                    self.input_parser.advance_fragment_v3(bytes(self.input_buffer),self.meter);self.input_buffer.clear()
                return
            if self._string_metadata_path_v1(path):
                parser=self.string_parsers.get(path)
                if parser is None:
                    parser=C09CanonicalJSONStreamV2(ensure_ascii=True);self.string_parsers[path]=parser
                buffer=self.string_buffers.setdefault(path,bytearray());buffer.extend(chr(codepoint).encode('utf8'))
                if len(buffer)>=1024:
                    parser.feed(bytes(buffer),lambda event:None);buffer.clear()
                return
        return C09CanonicalJSONStreamV2._append_decoded_codepoint(self,codepoint)
    def _event(self,event):
        if event.kind=='scalar_end'and event.path in self.string_parsers:
            parser=self.string_parsers.pop(event.path);buffer=self.string_buffers.pop(event.path)
            if buffer:parser.feed(bytes(buffer),lambda item:None)
            self.string_digests[event.path]=parser.finish().sha256
        if event.kind=='scalar_end'and self.input_parser is not None and event.path==('input_payload_json',):
            if self.input_buffer:
                self.input_parser.advance_fragment_v3(bytes(self.input_buffer),self.meter);self.input_buffer.clear()
            self.input_result=self.input_parser.finish_metadata_v3()
        if event.kind=='key'and not self._retains(event.path):
            if self.source_profile in {'numeric_input','prepared'}:self.fields.setdefault(event.path[:-1],set()).add(event.key)
            self._hash_to(event.end_offset);return
        return super()._event(event)


class _SourceTopologyColumnV1:
    def __init__(self,task,spec):
        if(type(task)is not _SourceTopologyTaskV1 or _SOURCE_TOPOLOGY_TASKS.get(task.reader)is not task
                or task.issuing_spec!=spec):
            raise AuthorityUnavailable('numeric metadata column requires its exact private Task selector')
        self.task,self.spec=task,spec
        _SOURCE_TOPOLOGY_COLUMNS[self]=(task,spec)
        self.offset,self.total,self.complete=0,None,False
        self.header=self.result=self.cell=None
        self.parser=None
    def reserve(self,extra=0):
        self.task.reserve_v1(extra)
    def advance(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..runtime_storage_v3 import RuntimeCellReadV3
        if(_SOURCE_TOPOLOGY_COLUMNS.get(self)!=(self.task,self.spec)or self.task.column is not self):
            raise AuthorityUnavailable('numeric metadata column left its actual issued selector')
        r=self.task.require_reader_v1();table,column,keys,key,header_columns,profile=self.spec
        where=' AND '.join(k+'=?'for k in keys)
        if self.header is None:
            self.header=meter.read_fixed_row(r.db,table,header_columns,where,key)
            if self.header is None:raise AuthorityUnavailable('numeric topology exact producing original is absent')
            if table=='graph_history':
                if column!='value'or keys!=('token','revision')or header_columns[-1]!='value_cell_id':
                    raise AuthorityUnavailable('numeric topology historical column selector differs')
                token=AtomKey.from_token(key[0])
                if NamespaceId.from_key(token)!=r.namespace:
                    raise AuthorityUnavailable('numeric topology historical column crossed namespace')
                if profile=='historical_numeric'and token.type_name!='d04.contribution_ledger.v1':
                    raise AuthorityUnavailable('numeric ancestry ledger is not its exact registered family')
                if profile=='historical_job'and token.type_name!='runtime.job':
                    raise AuthorityUnavailable('numeric ancestry terminal job selector differs')
                self.cell=RuntimeCellReadV3(r.operation.handle,self.header[-1],erasure_owner_ref=key[0],meter=meter)
            self.parser=_SourceTopologyMetadataStreamV1(profile,self.reserve,
                ensure_ascii=self.cell is None or self.cell.header[0]!='canonical-json.utf8.v1')
        if self.cell is None:
            raw,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=table,column=column,where=where,
                parameters=key,start=self.offset,length=1024,meter=meter)
            if kind!='text'or self.total is not None and total!=self.total:
                raise AuthorityUnavailable('numeric topology producing column changed during whole EOF')
            self.total=total
            if raw:self.parser.advance_fragment_v3(raw,meter);self.offset+=len(raw)
            done=self.offset==total
        else:
            raw=self.cell.read_fragment(meter=meter)
            if raw is not None:self.parser.advance_fragment_v3(raw,meter)
            done=self.cell.ordinal==self.cell.header[4]
            if done:self.cell.finish(meter=meter)
            total=self.cell.header[3]
        if done:
            metadata,commits,ranges,fields_,parsed=self.parser.finish_metadata_v3()
            if parsed.byte_count!=total or self.cell is not None and parsed.sha256!=self.cell.header[5]:
                raise AuthorityUnavailable('numeric topology complete canonical cell EOF differs')
            self.result=(metadata,self.header,parsed.sha256,commits,fields_)
            self.complete=True


def _source_topology_identity_v1(r):
    return(r.graph,r.work,r.operation,r.fence,r.selector,r.selection_digest,r.graph_stamp,
        r.bundle.installation_policy.manifest_digest,r.ordinary_readout,r.selected_readout)


class _SourceTopologyTaskV1:
    def __init__(self,key,reader):
        if key is not _KEY:raise TypeError('actual numeric Source metadata issuer required')
        self.reader=reader;self.identity=_source_topology_identity_v1(reader)
        self.complete=False;self.fact=None;self.send_value=None;self.started=False
        self.phase='metadata';self.growth=False;self.issuing_spec=None
        self.histories=[];self.originals=[];self.column=None;self.rows=None
        self.ancestry={};self.visiting=set();self.numeric_operations={};self.series_operations={};self.prepared_metadata={}
        self.source_roots=set();self.body_source_roots=set();self.source_versions=();self.meter=None;self.history_check=None
        self.steps=_source_topology_steps_v1(self)
        _SOURCE_TOPOLOGY_TASKS[reader]=self
        reader.operation.register_retained_state_v3(self)
    def require_reader_v1(self):
        from .d04_source_work_v3 import require_installed_d04_source_reader_v3
        r=require_installed_d04_source_reader_v3(self.reader)
        if(_SOURCE_TOPOLOGY_TASKS.get(r)is not self or self.identity!=_source_topology_identity_v1(r)
                or r.selector.stage!='numeric_prepare'or r.read_finished or r.phase not in {'body','numeric_topology'}
                or r.selected_readout is None or r.ordinary_readout is None):
            raise AuthorityUnavailable('numeric topology metadata requires its actual post-ALL/pre-WRITE Source Work')
        r.ordinary_readout.require_current_v3(r)
        return r
    def _runtime_retained_heap_bytes_v3(self):
        from dataclasses import is_dataclass
        from sys import getsizeof
        seen=set()
        def size(value):
            if id(value)in seen:return 0
            seen.add(id(value));result=getsizeof(value)
            if type(value)is dict:return result+sum(size(k)+size(v)for k,v in value.items())
            if type(value)in(tuple,list,set,frozenset):return result+sum(size(v)for v in value)
            if is_dataclass(value)and not isinstance(value,type):
                return result+sum(size(getattr(value,f.name))for f in fields(value))
            if isinstance(value,C09CanonicalJSONStreamV2):
                return result+sum(size(getattr(value,n))for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')+(0 if type(value)is C09CanonicalJSONStreamV2 else size(value.__dict__))
            return result
        amount=size((self.histories,self.originals,self.rows,self.ancestry,self.visiting,self.numeric_operations,
            self.series_operations,self.prepared_metadata,self.source_roots,self.body_source_roots,self.source_versions,self.send_value,
            None if self.fact is None else(self.fact.ancestry,self.fact.rows,self.fact.source_versions)))
        if self.column is not None:
            c=self.column;amount+=size((c.spec,c.parser,c.header,c.result,None if c.cell is None else c.cell.__dict__))
        iterator=self.steps
        while iterator is not None:
            frame=iterator.gi_frame
            if frame is not None:
                amount+=size({k:v for k,v in frame.f_locals.items()if k not in {'task','r','assembly','preset','compatibility'}})
            iterator=iterator.gi_yieldfrom
        return amount+65536
    def reserve_v1(self,extra=0):
        op=self.reader.operation
        if self.growth:op.finish_retained_state_growth_v3(self)
        op.reserve_retained_state_growth_v3(self,extra+65536);self.growth=True
    def advance(self,meter):
        self.reserve_v1()
        try:return self._advance_v1(meter)
        finally:
            if self.growth:self.reader.operation.finish_retained_state_growth_v3(self);self.growth=False
    def _advance_v1(self,meter):
        r=self.require_reader_v1();r.require_current(meter=meter);self.meter=meter
        if self.phase=='source_union':
            _source_topology_sources_v1(self)
            self.phase='sealed';self.complete=True
            self.fact=_SourceTopologyFactV1(_KEY,self)
            self.numeric_operations.clear();self.series_operations.clear();self.prepared_metadata.clear()
            return
        if self.column is not None:
            self.column.advance(meter)
            if self.column.complete:
                result=self.column.result;self.originals.append((self.column.spec,self.column.header,result[2]))
                if self.column.spec[-1]=='prepared':
                    parser=self.column.parser
                    self.prepared_metadata[self.column.spec[3][-1]]=(parser.input_result,dict(parser.input_parser.string_digests),dict(parser.fields))
                if self.history_check is not None:
                    token,revision,valid,digest,event=self.history_check
                    if result[1][:5]!=(int(valid),*event)or result[3].get(())!=digest:
                        raise AuthorityUnavailable('numeric topology complete historical canonical commitment/event differs')
                    self.histories.append((token,revision,result[1],tuple(self.column.cell.header),digest))
                    self.history_check=None;result=True
                _SOURCE_TOPOLOGY_COLUMNS.pop(self.column)
                self.send_value=result;self.column=None
            return
        try:
            request=next(self.steps)if not self.started else self.steps.send(self.send_value)
            self.started=True;self.send_value=None
        except StopIteration as done:
            self.rows=done.value
            self.steps=None;self.phase='source_union'
            return
        kind,*args=request
        if kind=='column':self._issue_column_v1(_KEY,args[0])
        elif kind=='row':
            table,columns,keys,key=args
            self.send_value=meter.read_fixed_row(r.db,table,columns,' AND '.join(k+'=?'for k in keys),key)
        elif kind=='next':
            table,columns,keys,key,order,cursor=args
            self.send_value=meter.read_fixed_row(r.db,table,columns,
                ' AND '.join(k+'=?'for k in keys)+' AND '+order+'>? ORDER BY '+order,(*key,cursor))
        elif kind in {'history','read_history'}:
            if kind=='history':
                token,revision,digest,event=args;valid=True
            else:token,revision,valid,digest,event=args
            self.history_check=(token,revision,valid,digest,event)
            self._issue_column_v1(_KEY,('graph_history','value',('token','revision'),(token,revision),
                ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),'historical_hash'))
        else:raise AuthorityUnavailable('numeric topology metadata has no such private request')
    def _issue_column_v1(self,key,spec):
        if key is not _KEY or self.complete or self.phase!='metadata':
            raise AuthorityUnavailable('numeric column issuance requires the actual metadata Task continuation')
        self.require_reader_v1();self.issuing_spec=spec
        try:self.column=_SourceTopologyColumnV1(self,spec)
        finally:self.issuing_spec=None


def prepare_source_topology_metadata_v1(reader):
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    r=require_installed_d04_source_reader_v3(reader)
    if(not source_topology_required_v1(r)or r.phase!='body'or r.read_finished
            or r.selected_readout is None or r.namespace_reader is None or not r.namespace_reader.graph_eof):
        raise AuthorityUnavailable('numeric topology metadata has no actual completed Source/selected Body issuer')
    r.ordinary_readout.require_current_v3(r)
    existing=_SOURCE_TOPOLOGY_TASKS.get(r)
    if existing is not None:existing.require_reader_v1();return existing
    return _SourceTopologyTaskV1(_KEY,r)


def release_source_topology_metadata_v1(reader):
    task=_SOURCE_TOPOLOGY_TASKS.pop(reader,None)
    if task is not None:
        reader.operation.unregister_retained_state_v3(task)
        if task.column is not None:_SOURCE_TOPOLOGY_COLUMNS.pop(task.column,None)
        if task.fact is not None:_SOURCE_TOPOLOGY_FACTS.pop(task.fact,None)
        task.column=task.steps=task.fact=task.rows=None
        task.histories.clear();task.originals.clear();task.ancestry.clear();task.numeric_operations.clear()
        task.series_operations.clear();task.prepared_metadata.clear()


def source_topology_required_v1(reader):
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    r=require_installed_d04_source_reader_v3(reader)
    return(r.selector.stage=='numeric_prepare'and r.commit.__module__==__package__+'.d04_installed_numeric_v3'
        and r.commit.__qualname__=='prepare_post_c02_joint_numeric_v3.<locals>.commit')


def _src_col(table,column,keys,key,headers,profile='numeric'):
    return('column',(table,column,tuple(keys),tuple(key),tuple(headers),profile))


def _src_row(table,columns,keys,key):return('row',table,tuple(columns),tuple(keys),tuple(key))


def _source_topology_steps_v1(task):
    from ..domains.d04.authored_topology_v3 import TYPE_NAME,decode_authored_root_topology_v3,authored_topology_key_v3
    from .d04_owner_initialization_v3 import(_installed_topology_policy,_topology_edges,TOPOLOGY_TABLE,
        TOPOLOGY_SCHEMA,TOPOLOGY_ACTIVITY)
    from ..authority_service.v2_contract import from_wire,FencePermitV2
    from ..authority_service.v2_owner_contract import OwnerGraphCommitProofV1,canonical_digest as owner_digest
    from ..graph_types import validate_owner_grant_v1
    from .restore_anchor import RestoreAnchor
    from ..domains.d12.types import active_scheme_head_key,character_draft_key
    from ..domains.d01 import _activation_key
    r=task.reader;ns=r.namespace;assembly=r.graph._GraphCoordinator__d04_installed_joint_assembly
    preset,policy=_installed_topology_policy(assembly.package_root,assembly.installation_policy.manifest_digest,
        assembly.available_cpu_features)
    result={}
    markers=tuple(a for a in r.snapshot.atoms if a.key.type_name==TYPE_NAME and a.valid)
    for marker_atom in markers:
        key=marker_atom.key
        raw,header,whole,commits,fieldsets=yield _src_col(TOPOLOGY_TABLE,'original_json',
            ('bot','persona','operation_id'),(*ns.as_tuple,key.name),('original_digest',),'topology')
        if(fieldsets.get(())!=_TOPOLOGY_FIELDS or whole!=header[0]or raw.get('schema')!=TOPOLOGY_SCHEMA
                or raw.get('namespace')!=asdict(ns)or raw.get('operation_id')!=key.name
                or raw.get('marker_ref')!=key.token or raw.get('policy')!=policy
                or type(raw.get('installation_id'))is not str or not raw['installation_id']):
            raise AuthorityUnavailable('numeric topology original complete EOF/schema/identity differs')
        marker=decode_authored_root_topology_v3(raw['marker_value'])
        if(marker_atom.revision!=1 or marker_atom.value!=raw['marker_value']
                or authored_topology_key_v3(ns,marker.operation_id)!=key
                or marker.preset_digest!=preset.digest or marker.policy_digest!=policy['content_digest']
                or marker.operator_sha256!=preset.assets.operator_sha256
                or marker.owner_binding_digest!=canonical_digest(raw['owner_admission'])
                or marker.request_digest!=raw['request_digest']or marker.root_operation_id!=raw['root_operation_id']):
            raise AuthorityUnavailable('numeric topology actual marker and installed metadata differ')
        if marker.manifest_digest!=assembly.installation_policy.manifest_digest:
            compatibility=r.graph._GraphCoordinator__d04_historical_compatibility_v1
            if compatibility is None:raise AuthorityUnavailable('numeric topology historical package is not registered')
            compatibility.require_original_manifest_v1(marker.manifest_digest)
        root,freeze,candidate,initial_rows=yield from _source_signed_root_v1(task,marker.root_operation_id,preset)
        if(root.original_digest!=marker.root_original_digest or root.signed_freeze_digest!=marker.root_freeze_digest
                or raw['root_original_digest']!=root.original_digest or raw['root_freeze_digest']!=root.signed_freeze_digest):
            raise AuthorityUnavailable('numeric topology actual root/freeze identity differs')
        members,current_members=yield from _source_numeric_members_v1(task,root,candidate,initial_rows)
        if(marker.member_refs!=tuple(sorted(ref for ref,_ in members.values()))
                or marker.coefficient!=policy['coefficient']or marker.effective_from!=candidate.cursor):
            raise AuthorityUnavailable('numeric topology current member/root interval differs')
        edges=_topology_edges(policy,preset,members,key.token,marker.effective_from,marker.effective_until)
        writes=sorted(edges+[(key.token,1,raw['marker_value'])],key=lambda item:item[0])
        if(canonical_digest(edges)!=marker.edge_write_set_digest
                or json.loads(canonical_serialize(writes))!=raw['write_rows']):
            raise AuthorityUnavailable('numeric topology exact 48-edge original differs')
        event_key=(*ns.as_tuple,TOPOLOGY_ACTIVITY,marker.operation_id)
        event_columns={}
        for name in('revisions','reads','epoch_reads','invalidated'):
            value,h,_,_,_=yield _src_col('graph_events',name,('bot','persona','session','event_id'),event_key,('digest','epoch_revision'))
            event_columns[name]=value
            if name=='revisions':event_header=h
            elif h!=event_header:raise AuthorityUnavailable('numeric topology event changed across canonical EOF')
        receipt={'status':'committed','revisions':event_columns['revisions'],'invalidated':[],
            'epoch':{'bot':ns.bot_id,'persona':ns.persona_id,'revision':event_header[1]}}
        if(event_header[0]!=raw['event_digest']or event_columns['revisions']!=[[ref,rev]for ref,rev,_ in writes]
                or raw['graph_receipt']!=receipt or event_columns['invalidated']!=[]):
            raise AuthorityUnavailable('numeric topology genuine event/receipt differs')
        for ref,revision,value in writes:yield('history',ref,revision,canonical_digest(value),event_key)
        admission=raw['owner_admission']
        expected_admission={'actor','activation_generation','grant_id','grant_revision','grant_digest','authorization_head',
            'authorization_revision','principal','graph_incarnation','request_digest','permit_digest','owner_session_binding_digest'}
        if(set(admission)!=expected_admission or admission['request_digest']!=raw['request_digest']
                or type(admission['actor'])is not str or not admission['actor']):
            raise AuthorityUnavailable('numeric topology historical Owner admission shape differs')
        request=canonical_digest((TOPOLOGY_SCHEMA,ns,marker.operation_id,marker.root_operation_id,float(marker.effective_until)))
        attempt=yield _src_row('graph_owner_domain_attempts_v3',('request_digest','attempt_id','graph_revision','graph_epoch'),
            ('bot','persona','operation_id'),(*ns.as_tuple,marker.operation_id))
        attempt_id='owner-domain-'+canonical_digest((ns,marker.operation_id,request))[:48]
        if attempt is None or attempt[:2]!=(request,attempt_id)or request!=raw['request_digest']:
            raise AuthorityUnavailable('numeric topology historical actual Owner attempt differs')
        attempt_json={}
        for name in('anchor_json','permit_json','receipt_json'):
            v,_,_,_,_=yield _src_col('graph_owner_domain_attempts_v3',name,('bot','persona','operation_id'),
                (*ns.as_tuple,marker.operation_id),('request_digest','attempt_id','graph_revision','graph_epoch'))
            attempt_json[name]=v
        permit=from_wire(attempt_json['permit_json']);anchor=RestoreAnchor(**attempt_json['anchor_json'])
        if(type(permit)is not FencePermitV2 or permit.operation!='write'or permit.operation_id!=attempt_id
                or permit.pinned_anchor!=anchor or permit.generation!=admission['activation_generation']
                or canonical_digest(permit)!=admission['permit_digest']):
            raise AuthorityUnavailable('numeric topology actual retained permit/anchor differs')
        requirements=r.graph_stamp[0].requirements
        if(requirements.authority_namespace!=permit.namespace or requirements.authority_id!=permit.authority_id):
            raise AuthorityUnavailable('numeric topology historical permit namespace differs')
        saved_receipt=attempt_json['receipt_json']
        if(saved_receipt.get('original_digest')!=whole or saved_receipt.get('marker_ref')!=key.token
                or saved_receipt.get('graph_receipt')!=receipt or saved_receipt.get('operation_id')!=marker.operation_id):
            raise AuthorityUnavailable('numeric topology retained Owner receipt lost original whole digest')
        prerequisites=[]
        projected=raw['prerequisite_rows']
        if len(projected)!=10:raise AuthorityUnavailable('numeric topology exact ten prerequisites are incomplete')
        for index,row in enumerate(projected):
            if(len(row)not in(3,4)or type(row[0])is not str or type(row[1])is not int or row[1]<1 or row[-1]is not True):
                raise AuthorityUnavailable('numeric topology prerequisite metadata shape differs')
            ref,revision=row[:2];digest=commits.get(('prerequisite_rows',index,2))
            if type(digest)is not str:raise AuthorityUnavailable('numeric topology prerequisite has no whole canonical value commitment')
            if NamespaceId.from_key(AtomKey.from_token(ref))!=ns:raise AuthorityUnavailable('numeric topology prerequisite crosses namespace')
            hist=yield _src_row('graph_history',('valid','event_bot','event_persona','event_session','event_id'),('token','revision'),(ref,revision))
            if hist is None or hist[0]!=1 or hist[1:3]!=ns.as_tuple:raise AuthorityUnavailable('numeric topology prerequisite historical validity differs')
            yield('history',ref,revision,digest,tuple(hist[1:]))
            control=row[2]if len(row)==4 else None
            if control is not None and canonical_digest(control)!=digest:
                raise AuthorityUnavailable('numeric topology control projection is not its complete canonical value')
            prerequisites.append((ref,revision,digest,control))
        expected_keys={ref for ref,_,_ in initial_rows}|{active_scheme_head_key(ns).token,character_draft_key(ns).token,
            owner_grant_key(*ns.as_tuple).token,_activation_key(ns).token}
        reads=sorted([[ref,rev]for ref,rev,_,_ in prerequisites]+[[ref,0]for ref,_,_ in writes])
        if({p[0]for p in prerequisites}!=expected_keys or len({p[0]for p in prerequisites})!=10
                or len({p[0]for p in reads})!=len(reads)or event_columns['reads']!=reads
                or event_columns['epoch_reads']!=[[*ns.as_tuple,attempt[3]]]
                or event_header[1]!=attempt[3]+1):
            raise AuthorityUnavailable('numeric topology historical complete read set/epoch differs')
        owner_row=next(p for p in prerequisites if p[0]==owner_grant_key(*ns.as_tuple).token)
        owner_value=owner_row[3]
        validate_owner_grant_v1(owner_value)
        issue=yield _src_row('graph_owner_issue_operations_v1',('operation_id','request_digest','grant_id','grant_digest',
            'graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest'),('bot','persona'),ns.as_tuple)
        issue_json,issue_head,_,_,_=yield _src_col('graph_owner_issue_operations_v1','proof_json',('bot','persona'),ns.as_tuple,
            ('operation_id','request_digest','grant_id','grant_digest','graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest'))
        if issue is None or issue!=issue_head:raise AuthorityUnavailable('numeric topology actual Owner issue changed')
        owner_proof=OwnerGraphCommitProofV1(ns,*issue[:5],owner_row[1],*issue[5:])
        if(issue_json!=json.loads(canonical_serialize(asdict(owner_proof)))or owner_row[1]!=1
                or owner_value['grant_revision']!=1 or owner_value['issue_operation_id']!=owner_proof.operation_id
                or owner_value['scope']!='/'.join(ns.as_tuple)or owner_value['authority_id']!=permit.authority_id
                or owner_value['graph_incarnation']!=owner_proof.graph_incarnation or owner_value['principal']!=admission['principal']
                or owner_value['grant_id']!=owner_proof.grant_id or admission['grant_id']!=owner_proof.grant_id
                or 'sha256:'+canonical_digest(owner_value)!=owner_proof.grant_digest
                or admission['grant_digest']!=owner_proof.grant_digest or admission['grant_revision']!=owner_proof.grant_revision
                or admission['authorization_revision']!=1 or admission['authorization_head']!=owner_digest(owner_proof)
                or 'workbench.activate'not in owner_value['capabilities']):
            raise AuthorityUnavailable('numeric topology original Owner issue proof/permit differs')
        from .d04_source_work_v3 import _d04_source_atom_from_eof_v3
        meter=task.meter
        current=[]
        actual_refs=sorted(t for t in r.namespace_reader.heads if AtomKey.from_token(t).type_name in {TYPE_NAME,'d04.numeric_coupling.v1'})
        if actual_refs!=[ref for ref,_,_ in writes]:raise AuthorityUnavailable('numeric topology complete edge/marker census differs')
        for ref,revision,value in writes:
            atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(ref),meter)
            if(atom.revision,atom.valid,atom.value)!=(revision,True,value):raise AuthorityUnavailable('numeric topology selected current edge/marker differs')
            current.append((ref,revision,atom.value,True))
        stable=[]
        for ref,revision,digest,control in prerequisites:
            if AtomKey.from_token(ref).type_name not in {'d12.active_scheme_head.v1','d01.persona_activation.v1'}:continue
            atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(ref),meter)
            if(atom.revision!=revision or not atom.valid or canonical_digest(atom.value)!=digest):
                raise AuthorityUnavailable('numeric topology current stable control changed')
            stable.append((ref,revision,atom.value,True))
        if(len(stable)!=2 or not any(ref==marker.active_scheme_ref and revision==marker.active_scheme_revision
                and canonical_digest(value)==marker.active_scheme_digest for ref,revision,value,_ in stable)):
            raise AuthorityUnavailable('numeric topology actual active scheme commitment differs')
        result[key.token]=(tuple(sorted(current+current_members+stable,key=lambda row:row[0])),raw,admission,permit,owner_proof,owner_value)
    if not markers:
        checkpoints=tuple(a for a in r.snapshot.atoms if a.key.type_name=='d04.numeric_checkpoint.v2'and a.valid)
        if checkpoints:
            from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2
            cp=decode_authored_numeric_checkpoint_v2(checkpoints[0].value)
            state=r.snapshot.get(AtomKey.from_token(cp.graph_state.ref))
            if state is None or not state.valid:raise AuthorityUnavailable('numeric actual authored root state is absent')
            root,freeze,candidate,initial_rows=yield from _source_signed_root_v1(task,state.value['root_operation_id'],preset)
            yield from _source_numeric_members_v1(task,root,candidate,initial_rows)
    return result


def _source_signed_root_v1(task,root_operation_id,preset):
    from .d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3
    from .issuers import _decode_grant
    r=task.reader;ns=r.namespace
    root_raw,root_header,root_sha,_,_=yield _src_col('graph_d04_root_originals_v3','original_json',
        ('bot','persona','operation_id'),(*ns.as_tuple,root_operation_id),('original_digest',))
    freeze_raw,freeze_header,_,_,_=yield _src_col('runtime_d11_d04_root_freezes_v3','original_json',
        ('bot','persona','operation_id'),(*ns.as_tuple,root_operation_id),('signature',))
    root,freeze,candidate,initial_rows,freeze_read=_decode_signed_root_v1(ns,root_operation_id,preset,
        r.graph._GraphCoordinator__d11_issuer,root_raw,root_header[0],root_sha,freeze_raw,freeze_header[0])
    grant_raw,grant_header,_,_,_=yield _src_col('runtime_budget_grants','grant_json',('lease_id','version'),
        (freeze.parent_budget_lease_ref,freeze.grant_version),('signature',))
    payload=canonical_serialize(grant_raw)
    r.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1',payload,grant_header[0])
    grant=_decode_grant(payload)
    reserve,reserve_header,_,_,_=yield _src_col('runtime_budget_operations','receipt_json',
        ('bot_id','persona_id','operation_id','phase'),(*ns.as_tuple,freeze.reserve_operation_id,'reserve'),('digest','lease_id'))
    quote,quote_header,_,_,_=yield _src_col('runtime_budget_reservations','ceiling_json',
        ('lease_id','operation_id'),(freeze.parent_budget_lease_ref,freeze.reserve_operation_id),('digest',))
    if((grant.lease_id,grant.version)!=(freeze.parent_budget_lease_ref,freeze.grant_version)
            or grant_header[0]!=freeze.grant_signature or canonical_digest(asdict(grant))!=freeze.grant_digest
            or grant.allowed_work_kinds!=(ROOT_WORK_KIND_V3,)or tuple(sorted(grant.max_ceiling.items()))!=freeze.quote_ceiling
            or reserve_header!=(freeze.reserve_digest,freeze.parent_budget_lease_ref)
            or canonical_digest(reserve)!=freeze.reserve_receipt_digest or quote_header!=(freeze.reserve_digest,)
            or tuple(sorted(quote.items()))!=freeze.quote_ceiling):
        raise AuthorityUnavailable('numeric topology historical signed budget/receipt differs')
    root_event=(*ns.as_tuple,'d04.authored_root.v3',root_operation_id)
    root_revisions,root_event_header,_,_,_=yield _src_col('graph_events','revisions',
        ('bot','persona','session','event_id'),root_event,('digest','epoch_revision'))
    if(root_event_header[0]!=root.graph_event_digest or root_revisions!=[[ref,1]for ref,_,_ in initial_rows]
            or canonical_digest({'status':'committed','revisions':root_revisions,'invalidated':[],
                'epoch':{'bot':ns.bot_id,'persona':ns.persona_id,'revision':root_event_header[1]}})!=root.graph_receipt_digest):
        raise AuthorityUnavailable('numeric topology root GraphReceipt membership differs')
    for ref,revision,value in initial_rows:
        yield('history',ref,revision,canonical_digest(value),root_event)
    return root,freeze,candidate,initial_rows


def _source_bundle_receipt_v1(task,operation):
    r=task.reader;ns=r.namespace
    bundle=yield _src_row('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        ('bot','persona','operation_id'),(*ns.as_tuple,operation))
    if bundle is None:raise AuthorityUnavailable('numeric ancestry actual committed bundle is absent')
    receipt,header,_,_,_=yield _src_col('graph_bundle_operations','receipt_json',('bot','persona','operation_id'),
        (*ns.as_tuple,operation),('digest','activity_id','effect_id','commit_seq'))
    if header!=bundle:raise AuthorityUnavailable('numeric ancestry bundle header changed')
    event=(*ns.as_tuple,bundle[1],operation);event_values=[];epoch=None
    for column in('reads','revisions','invalidated'):
        value,h,_,_,_=yield _src_col('graph_events',column,('bot','persona','session','event_id'),event,('digest','epoch_revision'))
        if epoch is None:epoch=h
        elif h!=epoch:raise AuthorityUnavailable('numeric ancestry actual event changed')
        event_values.append(value)
    from ..runtime_contracts import CommitReceipt
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt,NamespaceEpoch
    if(type(receipt)is not dict or type(receipt.get('ledger_refs'))is not list or type(receipt.get('outbox_refs'))is not list):
        raise AuthorityUnavailable('numeric ancestry actual bundle receipt metadata is malformed')
    result=CommitReceipt('committed',operation,*bundle,GraphStore._version_rows(canonical_serialize(event_values[0])),
        GraphStore._version_rows(canonical_serialize(event_values[1])),(NamespaceEpoch(*ns.as_tuple,epoch[1]),),
        tuple(receipt['ledger_refs']),tuple(receipt['outbox_refs']))
    graph_receipt=GraphReceipt('committed',GraphStore._version_rows(canonical_serialize(event_values[1])),
        GraphStore._version_rows(canonical_serialize(event_values[2])),NamespaceEpoch(*ns.as_tuple,epoch[1]))
    return result,graph_receipt


def _source_numeric_operation_v1(task,operation):
    cached=task.numeric_operations.get(operation)
    if cached is not None:return cached
    from .d04_joint_advance_v2 import ProductAdvanceEvidenceV2,ProductAdvanceMemberV2
    from .d04_numeric_artifact_v3 import _typed
    from ..domains.d04.joint_state_output_v1 import JointStateOutputOriginalV1,_write_set,joint_checkpoint_payload_v1,joint_state_payload_v1
    ns=task.reader.namespace
    raw,header,_,_,_=yield _src_col('graph_d04_joint_advances_v2','evidence_json',('bot','persona','operation_id'),
        (*ns.as_tuple,operation),('evidence_digest','bundle_digest'))
    data=dict(raw);data['namespace']=NamespaceId(**data['namespace'])
    data['members']=tuple(ProductAdvanceMemberV2(**m)for m in data['members'])
    data['family_loo_transcripts']=tuple(tuple(p)for p in data['family_loo_transcripts'])
    evidence=ProductAdvanceEvidenceV2(**data)
    if(evidence.namespace!=ns or evidence.operation_id!=operation or evidence.schema!='d11.product_advance_evidence.v3'
            or(evidence.digest,evidence.bundle_digest)!=header):
        raise AuthorityUnavailable('numeric ancestry committed advance identity differs')
    cursor='';indexed=[]
    while True:
        row=yield('next','graph_d04_joint_advance_members_v2',('checkpoint_ref','process_id','role_start','role_end'),
            ('bot','persona','operation_id'),(*ns.as_tuple,operation),'checkpoint_ref',cursor)
        if row is None:break
        indexed.append(row);cursor=row[0]
    if indexed!=[(m.checkpoint_ref,evidence.process_id,evidence.role_start,evidence.role_end)for m in evidence.members]:
        raise AuthorityUnavailable('numeric ancestry complete member index differs')
    out_raw,out_header,_,_,_=yield _src_col('graph_d04_joint_output_originals_v1','original_json',
        ('bot','persona','operation_id'),(*ns.as_tuple,operation),('evidence_digest','original_digest','write_set_digest'))
    output=_typed(JointStateOutputOriginalV1,out_raw)
    content={f.name:getattr(output,f.name)for f in fields(output)if f.name not in {'original_digest','status'}}
    if(output.namespace!=ns or output.operation_id!=operation or output.schema!='d04.joint-state-output.v2'
            or out_header!=(evidence.digest,output.original_digest,output.write_set_digest)
            or canonical_digest(content)!=output.original_digest
            or canonical_serialize(asdict(output))!=canonical_serialize(out_raw)
            or canonical_digest(_write_set(output.members))!=output.write_set_digest):
        raise AuthorityUnavailable('numeric ancestry complete output original differs')
    receipt,graph_receipt=yield from _source_bundle_receipt_v1(task,operation)
    if receipt.operation_digest!=evidence.bundle_digest:raise AuthorityUnavailable('numeric ancestry bundle differs from evidence')
    for member in output.members:
        matches=tuple(m for m in evidence.members if m.checkpoint_ref==member.checkpoint_ref)
        if len(matches)!=1:raise AuthorityUnavailable('numeric ancestry output omits its unique evidence member')
        m=matches[0];event=(*ns.as_tuple,receipt.activity_id,operation)
        yield('history',m.checkpoint_ref,m.next_revision,m.next_value_digest,event)
        yield('history',m.output_state_ref,m.output_state_revision,m.output_state_digest,event)
        if(canonical_digest(joint_checkpoint_payload_v1(member.next_checkpoint))!=m.next_value_digest
                or canonical_digest(joint_state_payload_v1(member.next_state))!=m.output_state_digest):
            raise AuthorityUnavailable('numeric ancestry actual historical output commitments differ')
    result=(evidence,output,receipt,graph_receipt)
    task.numeric_operations[operation]=result
    return result


def _source_predecessor_v1(task,root,candidate,initial_rows,ref,revision,checkpoint,state):
    from ..domains.d04.authored_lineage_v3 import validate_authored_joint_predecessor_v3
    from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1,joint_state_payload_v1
    identity=(ref,revision,canonical_digest(joint_checkpoint_payload_v1(checkpoint)),canonical_digest(joint_state_payload_v1(state)))
    cached=task.ancestry.get(identity)
    if cached is not None:return cached
    if identity in task.visiting:raise AuthorityUnavailable('numeric ancestry is cyclic')
    task.visiting.add(identity)
    try:
        validate_authored_joint_predecessor_v3(checkpoint,state,revision)
        if revision==1:
            originals={r:(v,value)for r,v,value in initial_rows}
            if(checkpoint.commit_operation_id!=root.operation_id or checkpoint.root_candidate_digest!=candidate.digest
                    or state.owner_draft_id!=candidate.draft_id or state.preset_digest!=candidate.preset.digest
                    or originals.get(ref)!=(1,joint_checkpoint_payload_v1(checkpoint))
                    or originals.get(checkpoint.graph_state.ref)!=(1,joint_state_payload_v1(state))):
                raise AuthorityUnavailable('numeric ancestry initial member differs from actual signed root')
            result=(root.original_digest,root.graph_receipt_digest)
        else:
            operation=checkpoint.commit_operation_id
            evidence,output,receipt,graph_receipt=yield from _source_numeric_operation_v1(task,operation)
            selected=tuple(m for m in evidence.members if m.checkpoint_ref==ref)
            emitted=tuple(m for m in output.members if m.checkpoint_ref==ref)
            if len(selected)!=1 or len(emitted)!=1:raise AuthorityUnavailable('numeric ancestry unique continuation member is absent')
            member,value=selected[0],emitted[0]
            if(output.member_refs!=tuple(m.checkpoint_ref for m in evidence.members)
                    or output.write_set_digest!=evidence.output_write_set_digest
                    or output.role_start!=evidence.role_start or output.role_end!=evidence.role_end
                    or evidence.role_end!=checkpoint.cursor or member.next_revision!=revision
                    or member.output_state_ref!=checkpoint.graph_state.ref or member.output_state_revision!=state.revision
                    or member.next_value_digest!=canonical_digest(joint_checkpoint_payload_v1(checkpoint))
                    or member.output_state_digest!=canonical_digest(joint_state_payload_v1(state))
                    or member.next_error_bound!=checkpoint.numeric_error_bound
                    or value.next_checkpoint!=checkpoint or value.next_state!=state
                    or value.predecessor_checkpoint_revision!=member.predecessor_revision
                    or value.predecessor_checkpoint_digest!=member.predecessor_value_digest
                    or value.predecessor_state_ref!=member.predecessor_state_ref
                    or value.predecessor_state_revision!=member.predecessor_state_revision
                    or value.predecessor_state_digest!=member.predecessor_state_value_digest
                    or canonical_digest(value.axes)!=checkpoint.readout_proof_digest
                    or tuple((a.axis_id,a.representative)for a in value.axes)!=state.coordinates):
                raise AuthorityUnavailable('numeric ancestry continuation value/output proof differs')
            if member.predecessor_operation_id==root.operation_id:
                originals={r:value for r,_,value in initial_rows}
                from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2,decode_authored_feeling_state_v1,decode_authored_mood_state_v1
                prior=decode_authored_numeric_checkpoint_v2(originals[ref])
                prior_state=(decode_authored_feeling_state_v1(originals[member.predecessor_state_ref])if prior.block.kind=='feeling'
                    else decode_authored_mood_state_v1(originals[member.predecessor_state_ref]))
            else:
                _,previous,_,_=yield from _source_numeric_operation_v1(task,member.predecessor_operation_id)
                prior_member=tuple(m for m in previous.members if m.checkpoint_ref==ref)
                if len(prior_member)!=1:raise AuthorityUnavailable('numeric ancestry actual predecessor output is ambiguous')
                prior,prior_state=prior_member[0].next_checkpoint,prior_member[0].next_state
            prior_identity=yield from _source_predecessor_v1(task,root,candidate,initial_rows,ref,
                member.predecessor_revision,prior,prior_state)
            reads,writes=set(receipt.read_versions),set(receipt.write_versions)
            required_reads={GraphVersion(AtomKey.from_token(ref),member.predecessor_revision),
                GraphVersion(AtomKey.from_token(member.predecessor_state_ref),member.predecessor_state_revision)}
            required_writes={GraphVersion(AtomKey.from_token(ref),member.next_revision),
                GraphVersion(AtomKey.from_token(member.output_state_ref),member.output_state_revision)}
            if(not required_reads<=reads or not required_writes<=writes or member.predecessor_revision!=revision-1
                    or member.predecessor_state_revision!=state.revision-1
                    or member.predecessor_value_digest!=canonical_digest(joint_checkpoint_payload_v1(prior))
                    or member.predecessor_state_value_digest!=canonical_digest(joint_state_payload_v1(prior_state))
                    or member.predecessor_operation_id!=prior.commit_operation_id
                    or member.initial_box_digest!=prior.certificate_digest or member.inherited_error_bound!=prior.numeric_error_bound
                    or evidence.role_start!=prior.cursor or checkpoint.predecessor_receipt_digest!=prior_identity[1]
                    or checkpoint.block!=prior.block or checkpoint.assets!=prior.assets
                    or checkpoint.root_candidate_digest!=prior.root_candidate_digest):
                raise AuthorityUnavailable('numeric ancestry exact CAS/interval/error/root continuation differs')
            fixed=set(asdict(state))-{'coordinates','readout_proof_digest','cursor','revision','status',
                'active_driver_refs','historical_source_refs','source_refs'}
            if any(getattr(state,n)!=getattr(prior_state,n)for n in fixed):
                raise AuthorityUnavailable('numeric ancestry changes authored identity')
            old_sources=prior_state.historical_source_refs if prior.block.kind=='feeling'else prior_state.source_refs
            sources=state.historical_source_refs if prior.block.kind=='feeling'else state.source_refs
            if not set(old_sources)<=set(sources):raise AuthorityUnavailable('numeric ancestry drops inherited Source provenance')
            task.source_roots.update(sources)
            yield from _source_series_original_v1(task,root,candidate,initial_rows,operation,
                evidence,output,receipt,graph_receipt)
            result=(root.original_digest,canonical_digest(asdict(receipt)))
        task.ancestry[identity]=result
        return result
    finally:task.visiting.remove(identity)


def _source_numeric_members_v1(task,root,candidate,initial_rows):
    from .d04_source_work_v3 import _d04_source_atom_from_eof_v3
    from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2,decode_authored_feeling_state_v1,decode_authored_mood_state_v1
    r=task.reader;refs=sorted(t for t in r.namespace_reader.heads if AtomKey.from_token(t).type_name in _CHECKPOINT_TYPES)
    if len(refs)!=3:raise AuthorityUnavailable('numeric topology complete three-checkpoint census differs')
    current=[];members={}
    for ref in refs:
        atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(ref),task.meter)
        if not atom.valid or atom.revision<1 or atom.key.type_name!='d04.numeric_checkpoint.v2':
            raise AuthorityUnavailable('numeric topology current authored checkpoint is retired/unsupported')
        cp=decode_authored_numeric_checkpoint_v2(atom.value)
        state_atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(cp.graph_state.ref),task.meter)
        state=(decode_authored_feeling_state_v1(state_atom.value)if cp.block.kind=='feeling'else decode_authored_mood_state_v1(state_atom.value))
        if(atom.key.name!=cp.block.block_id or cp.namespace!=r.namespace.as_tuple or not state_atom.valid
                or state_atom.revision!=atom.revision or cp.graph_state.revision!=state_atom.revision
                or state.root_operation_id!=root.operation_id or cp.block.template_id in members):
            raise AuthorityUnavailable('numeric topology actual current member address/root differs')
        yield from _source_predecessor_v1(task,root,candidate,initial_rows,ref,atom.revision,cp,state)
        members[cp.block.template_id]=(ref,cp)
        current.extend(((ref,atom.revision,atom.value,True),(state_atom.key.token,state_atom.revision,state_atom.value,True)))
    templates={m.template_id:m.kind for m in candidate.preset.block_templates}
    if set(members)!=set(templates)or any(members[n][1].block.kind!=kind for n,kind in templates.items()):
        raise AuthorityUnavailable('numeric topology preset members differ')
    return members,current


def _source_d04_original_v1(task,kind,ref,*,profile='numeric'):
    ns=task.reader.namespace.as_tuple;key=(*ns,kind,ref)
    header=yield _src_row('graph_d04_originals_v3',('payload_digest',),('bot','persona','kind','original_ref'),key)
    if header is None:return None
    raw,actual,whole,_,_=yield _src_col('graph_d04_originals_v3','payload_json',('bot','persona','kind','original_ref'),key,
        ('payload_digest',),profile)
    if actual!=header or whole!=header[0]:raise AuthorityUnavailable('numeric ancestry original whole canonical EOF differs')
    return raw,whole


def _source_series_original_v1(task,authored_root,candidate,initial_rows,operation,evidence,output,receipt,graph_receipt):
    if operation in task.series_operations:return task.series_operations[operation]
    ns=task.reader.namespace
    prefix=yield from _source_d04_original_v1(task,'series_final_native_prefix',operation)
    cursor='';selected=[]
    while True:
        row=yield('next','graph_d04_originals_v3',('original_ref',),('bot','persona','kind'),(*ns.as_tuple,'series_root'),'original_ref',cursor)
        if row is None:break
        cursor=row[0];original=yield from _source_d04_original_v1(task,'series_root',cursor)
        if original[0]['numeric_operation_id']==operation:selected.append((cursor,original))
    ref='d04-series-root:'+canonical_digest((ns,operation))[:48]
    adopted=yield from _source_d04_original_v1(task,'series_adoption',ref)
    if not selected:
        if prefix is not None or adopted is not None:raise AuthorityUnavailable('numeric ancestry series identity lost its exact root')
        task.series_operations[operation]=None
        return None
    if len(selected)!=1 or selected[0][0]!=ref:raise AuthorityUnavailable('numeric ancestry series root is ambiguous')
    root_value,root_digest=selected[0][1]
    prepared=yield from _source_d04_original_v1(task,'numeric_prepared',operation,profile='prepared')
    if prepared is None or prefix is None or adopted is None:
        raise AuthorityUnavailable('numeric ancestry series root/prepared/prefix/adoption is incomplete')
    from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3,from_wire
    from .d04_numeric_artifact_v3 import decode_historical_d04_numeric_metadata_v1
    from .d04_series_original_v1 import decode_historical_d04_series_root_v1,verify_historical_d04_series_values_v1
    raw,digest=prepared
    outer=task.prepared_metadata[operation]
    if(outer[2].get(())!={'binding','input_payload_json','quote_payload_json','reserve_receipt_json',
            'job_payload_json','original_ref','schema'}or set(raw)!={'binding','original_ref','schema'}):
        raise AuthorityUnavailable('numeric ancestry prepared complete original fieldset differs')
    binding=from_wire(raw['binding'],D04NumericBindingV3)
    wire,string_digests,_=outer
    input_raw,_,_,input_fields,input_eof=wire
    model=decode_historical_d04_numeric_metadata_v1(binding,digest,input_raw,input_eof.sha256,string_digests,input_fields)
    if(binding.namespace!=ns or binding.operation_id!=operation or raw.get('schema')!='d04.numeric_prepared_original.v3'
            or raw.get('original_ref')!=binding.input_original_ref):
        raise AuthorityUnavailable('numeric ancestry actual prepared binding differs')
    for row in model.read_rows:
        if row.revision==0:
            if row.valid or row.value_digest!=canonical_digest({}):
                raise AuthorityUnavailable('numeric ancestry historical negative read commitment differs')
            continue
        actual=yield _src_row('graph_history',('valid','event_bot','event_persona','event_session','event_id'),
            ('token','revision'),(row.ref,row.revision))
        if actual is None or bool(actual[0])!=row.valid or actual[1:3]!=ns.as_tuple:
            raise AuthorityUnavailable('numeric ancestry complete historical readset membership differs')
        yield('read_history',row.ref,row.revision,row.valid,row.value_digest,tuple(actual[1:]))
    root=decode_historical_d04_series_root_v1(root_value,root_digest,model)
    task.source_roots.update(d.source_ref for d in model.current.drives)
    for member in model.predecessors.members:
        previous=yield from _source_predecessor_v1(task,authored_root,candidate,initial_rows,
            member.checkpoint_ref,member.checkpoint_revision,member.checkpoint,member.state)
        if(previous[0]!=model.current.component.root_original_digest or previous[1]!=member.predecessor_receipt_digest):
            raise AuthorityUnavailable('numeric ancestry frozen series initial root/receipt differs')
    bindings=[];chunks=[];terminals=[]
    from ..authority_service.d04_series_contract_v1 import D04SeriesChunkBindingV1,D04SeriesTerminalV1,D04SeriesGateV1,from_wire as series_from_wire
    from .d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
    for op,chunk_digest,terminal_digest in prefix[0]['chunks']:
        saved=yield from _source_d04_original_v1(task,'series_chunk_prepared',op)
        math=yield from _source_d04_original_v1(task,'series_chunk_math',op)
        terminal=yield from _source_d04_original_v1(task,'series_chunk_terminal',op)
        if saved is None or math is None or terminal is None:raise AuthorityUnavailable('numeric ancestry complete series packet is absent')
        chunk_binding=series_from_wire(saved[0]['binding'],D04SeriesChunkBindingV1)
        if chunk_binding.numeric.namespace!=ns or chunk_binding.numeric.operation_id!=op:
            raise AuthorityUnavailable('numeric ancestry exact historical chunk binding differs')
        bindings.append(chunk_binding);chunks.append(_decode_series_chunk_for_final_verifier_v1(math[0]))
        terminals.append(series_from_wire(terminal[0],D04SeriesTerminalV1))
    gate=yield from _source_d04_original_v1(task,'series_adoption_gate',root.root_ref)
    if gate is None:raise AuthorityUnavailable('numeric ancestry series final gate is absent')
    numeric=[]
    numeric_headers=None
    for column in('numeric_receipt_json','verification_json'):
        value,header,_,_,_=yield _src_col('graph_d04_joint_numeric_originals_v1',column,('bot','persona','operation_id'),
            (*ns.as_tuple,operation),('numeric_receipt_digest','verification_digest','evidence_digest'))
        if numeric_headers is None:numeric_headers=header
        elif numeric_headers!=header:raise AuthorityUnavailable('numeric ancestry original numeric verification header changed')
        numeric.append(value)
    contributions=[]
    from ..graph_types import GraphWrite
    from .d11_types import runtime_job_key
    for ledger_ref in receipt.ledger_refs:
        version=tuple(v for v in receipt.write_versions if v.key.token==ledger_ref)
        if len(version)!=1:raise AuthorityUnavailable('numeric ancestry actual contribution membership is absent')
        value,header,_,_,_=yield _src_col('graph_history','value',('token','revision'),(ledger_ref,version[0].revision),
            ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),'historical_numeric')
        if header[:5]!=(1,*ns.as_tuple,receipt.activity_id,operation):
            raise AuthorityUnavailable('numeric ancestry actual contribution event differs')
        contributions.append(GraphWrite(AtomKey.from_token(ledger_ref),value))
    job_ref=runtime_job_key(*binding.namespace.as_tuple,binding.activity_id,binding.job_id).token
    job_version=tuple(v for v in receipt.write_versions if v.key.token==job_ref)
    if len(job_version)!=1:raise AuthorityUnavailable('numeric ancestry exact final job write is absent')
    job,job_header,_,_,_=yield _src_col('graph_history','value',('token','revision'),(job_ref,job_version[0].revision),
        ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),'historical_job')
    if job_header[:5]!=(1,*ns.as_tuple,receipt.activity_id,operation):
        raise AuthorityUnavailable('numeric ancestry actual completed worker is not its event member')
    result=verify_historical_d04_series_values_v1(root,model,prefix=prefix[0],adopted=adopted[0],
        bindings=tuple(bindings),chunks=tuple(chunks),terminals=tuple(terminals),
        gate=series_from_wire(gate[0],D04SeriesGateV1),receipt=receipt,
        numeric_row=(numeric[0],numeric_headers[0],numeric[1],numeric_headers[1],numeric_headers[2]),
        evidence=evidence,persisted_output=output,contributions=tuple(contributions),graph_receipt=graph_receipt,job=job)
    task.series_operations[operation]=result
    return result


def _source_topology_sources_v1(task):
    from ..memory_types import source_key,access_key,validate_access
    from ..domains.d06 import source_correction_head_key
    from ..domains.d04.numeric_drive import decode_sourced_numeric_drive
    r=task.reader;ns=r.namespace;audiences=(r.route_identity['conversation_ref'],)
    current_roots=set()
    for atom in r.snapshot.atoms:
        if atom.key.type_name=='d04.sourced_numeric_drive.v1'and atom.valid:
            drive=decode_sourced_numeric_drive(atom.value)
            current_roots.add(drive.source_ref)
    task.source_roots.update(current_roots)
    roots=set(task.source_roots)|{r.selector.source_ref}
    if len(roots)>32:raise AuthorityUnavailable('numeric topology direct Source roots exceed the original bound')
    owner=r.owner_entry.require_for_v3(r)
    if 'expression'not in owner.purposes or not set(audiences)<=set(owner.audiences):
        raise AuthorityUnavailable('numeric topology original sources are outside current Owner permission')
    controls={a.key.token:a for a in r.namespace_reader.atoms}
    active=set();done=set();versions={};body=set()
    def visit(ref,body_required):
        if ref in active:raise AuthorityUnavailable('numeric topology Source ancestry is cyclic')
        if ref in done and(not body_required or ref in body):return
        if ref not in done and len(active)+len(done)>=256:
            raise AuthorityUnavailable('numeric topology Source closure exceeds its original bound')
        key=AtomKey.from_token(ref);source=r.namespace_reader.sources.get(ref)
        if(NamespaceId.from_key(key)!=ns or key!=source_key(*ns.as_tuple,key.owner.subject or'')
                or source is None or not source.valid):
            raise AuthorityUnavailable('numeric topology historical Source has no actual current inspection EOF')
        ak,ck=access_key(*ns.as_tuple,key.owner.subject),source_correction_head_key(ns,key.owner.subject)
        access=controls.get(ak.token);value=source.metadata
        if access is None or not access.valid or ck.token in r.namespace_reader.heads:
            raise AuthorityUnavailable('numeric topology historical Source is corrected or inaccessible')
        validate_access(access.value)
        if(value['source_id']!=key.owner.subject or access.value['source_id']!=value['source_id']
                or access.value['status']!='active' or 'expression'not in value['purposes']
                or 'expression'not in access.value['purposes']or not set(audiences)<=set(value['audiences'])
                or not set(audiences)<=set(access.value['audiences'])):
            raise AuthorityUnavailable('numeric topology historical Source lacks actual expression/recipient permission')
        active.add(ref)
        for parent in value['parent_source_ids']:visit(source_key(*ns.as_tuple,parent).token,body_required)
        active.remove(ref);done.add(ref)
        if body_required:body.add(ref)
        versions.update({key:GraphVersion(key,source.revision),ak:GraphVersion(ak,access.revision),ck:GraphVersion(ck,0)})
    for ref in sorted(roots):visit(ref,ref in current_roots)
    task.body_source_roots=body
    task.source_versions=tuple(versions.values())


class _SourceTopologyFactV1:
    def __init__(self,key,task):
        if key is not _KEY:raise TypeError('numeric topology fact has only its actual completed Task issuer')
        self.task=task;self.reader=task.reader;self.identity=task.identity
        self.rows=task.rows;self.ancestry=dict(task.ancestry)
        self.source_versions=task.source_versions
        _SOURCE_TOPOLOGY_FACTS[self]=(task,self.reader,self.identity,self.rows,self.ancestry,self.source_versions)
    def require_current_v1(self,db,namespace,meter):
        from .d04_source_work_v3 import require_installed_d04_source_reader_v3,_require_d04_eof_head_v3
        r=require_installed_d04_source_reader_v3(self.reader);task=self.task
        if(_SOURCE_TOPOLOGY_FACTS.get(self)!=(task,r,self.identity,self.rows,self.ancestry,self.source_versions)
                or _SOURCE_TOPOLOGY_TASKS.get(r)is not task or not task.complete or task.fact is not self
                or self.identity!=_source_topology_identity_v1(r)or r.db is not db or r.namespace!=namespace
                or r.selector.stage!='numeric_prepare'or r.phase not in {'numeric_topology_body','current','write'}
                or not db.in_transaction):
            raise AuthorityUnavailable('numeric topology fact left its actual Source Work/READ-to-WRITE handoff')
        r.require_current(meter=meter)
        if r.phase=='write':
            if(r.write_scope is None or r.write_scope.operation!='write'or not r.read_finished
                    or r.write_scope.namespace!=namespace or r.write_scope.graph_revision!=r.graph_stamp[0].graph_revision
                    or r.write_scope.graph_epoch!=r.graph_stamp[1]):
                raise AuthorityUnavailable('numeric topology fact lacks its actual fresh paired WRITE')
        elif r.read_finished:raise AuthorityUnavailable('numeric topology completed READ cannot be reopened')
        if _SOURCE_TOPOLOGY_WRITE.get()==(self,r.write_scope):return r
        for version in self.source_versions:
            expected=r.namespace_reader.canonical_eofs.get(version.key.token)
            if version.revision==0:
                if version.key.token in r.namespace_reader.heads:raise AuthorityUnavailable('numeric topology Source negative census changed')
            elif expected is None or expected[:2]!=(version.revision,True):
                raise AuthorityUnavailable('numeric topology Source/Access lost its completed canonical EOF')
            _require_d04_eof_head_v3(r,version.key,expected,meter)
        return r


def _bound_source_topology_fact_v1(db,namespace):
    from .d04_source_work_v3 import _BOUND,require_installed_d04_source_reader_v3
    r=_BOUND.get()
    if r is None:return None
    r=require_installed_d04_source_reader_v3(r)
    if not source_topology_required_v1(r):return None
    task=_SOURCE_TOPOLOGY_TASKS.get(r)
    if task is None or not task.complete or task.fact is None:
        raise AuthorityUnavailable('numeric topology requires its complete actual READ metadata Task before WRITE')
    with runtime_storage_quantum_v3(db)as meter:task.fact.require_current_v1(db,namespace,meter)
    return task.fact


def read_bound_source_authored_predecessor_v1(db,namespace,checkpoint_ref,checkpoint_revision,checkpoint,state):
    fact=_bound_source_topology_fact_v1(db,namespace)
    if fact is None:return False,None
    from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1,joint_state_payload_v1
    identity=(checkpoint_ref,checkpoint_revision,canonical_digest(joint_checkpoint_payload_v1(checkpoint)),
        canonical_digest(joint_state_payload_v1(state)))
    result=fact.ancestry.get(identity)
    if result is None:raise AuthorityUnavailable('numeric topology current member lacks its authenticated gap-free READ ancestry')
    return True,result


def read_bound_source_topology_v1(verifier,db,namespace,edge):
    fact=_bound_source_topology_fact_v1(db,namespace)
    if fact is None:return False,None
    from .d04_owner_initialization_v3 import InstalledD04AuthoredTopologyVerifierV3
    from ..domains.d04.numeric_coupling import NumericCoupling
    r=fact.reader;assembly=r.graph._GraphCoordinator__d04_installed_joint_assembly
    if(type(verifier)is not InstalledD04AuthoredTopologyVerifierV3 or type(edge)is not NumericCoupling
            or verifier.namespace!=namespace or verifier.installation_id!=assembly.installation_policy.installation_id
            or verifier.trusted_manifest_sha256!=assembly.installation_policy.manifest_digest):
        raise AuthorityUnavailable('numeric topology fact crossed its actual installed verifier/selection')
    entry=fact.rows.get(edge.source_ref)
    if entry is None:raise AuthorityUnavailable('numeric topology selected edge lacks its actual original metadata fact')
    rows,original,admission,permit,proof,grant=entry
    if not any(canonical_serialize(value)==canonical_serialize(asdict(edge))for _,_,value in original['write_rows']):
        raise AuthorityUnavailable('numeric topology edge differs from its exact authenticated 48-edge set')
    verifier._require_current_location(db,namespace,original,admission,permit,proof,grant)
    return True,rows


@contextmanager
def bind_source_topology_write_v1(reader,db):
    task=_SOURCE_TOPOLOGY_TASKS.get(reader)
    if task is None:
        yield
        return
    if not task.complete or task.fact is None:raise AuthorityUnavailable('numeric topology WRITE preceded its complete READ Task')
    fact=task.fact
    from .d04_source_work_v3 import _d04_source_atom_from_eof_v3
    with runtime_storage_quantum_v3(db)as meter:
        r=fact.require_current_v1(db,reader.namespace,meter)
        seen={}
        for entry in fact.rows.values():
            for ref,revision,value,valid in entry[0]:
                previous=seen.get(ref)
                if previous is not None and previous!=(revision,value,valid):
                    raise AuthorityUnavailable('numeric topology selected current readsets conflict')
                seen[ref]=(revision,value,valid)
        for ref,(revision,value,valid)in seen.items():
            atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(ref),meter)
            if(atom.revision,atom.value,atom.valid)!=(revision,value,valid):
                raise AuthorityUnavailable('numeric topology current member/control changed before actual W01 callback')
    token=_SOURCE_TOPOLOGY_WRITE.set((fact,reader.write_scope))
    try:yield
    finally:_SOURCE_TOPOLOGY_WRITE.reset(token)
