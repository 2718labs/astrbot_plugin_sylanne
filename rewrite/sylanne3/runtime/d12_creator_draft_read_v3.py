"""Two administrative Creator keys on their actual signed Owner READ Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from uuid import UUID

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,GraphReceipt,NamespaceEpoch
from ..runtime_contracts import AuthorityContext,FenceScope,NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from ..domains.d12.types import character_draft_key,active_scheme_head_key,CharacterDraft,ActiveSchemeHeadV1

_CREATOR_STATES=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()
_WRITE=ContextVar('sylanne_creator_draft_write_v3',default=None)
_COMMANDS={'root_draft':('workbench.create',frozenset({'d04','d12'})),
    'root_topology':('workbench.activate',frozenset({'d04','d11','d12'}))}


def _digest(value):return type(value)is str and len(value)==64 and all(c in '0123456789abcdef'for c in value)


@dataclass(frozen=True,slots=True)
class CreatorDraftReadRequestV3:
    consumer:str
    draft_ref:str
    required_capability:str
    allow_missing:bool
    command_kind:str|None=None
    command_operation_id:str|None=None
    command_input_digest:str|None=None
    def __post_init__(self):
        key=AtomKey.from_token(self.draft_ref)
        ns=NamespaceId.from_key(key)
        if(key!=character_draft_key(ns)or type(self.allow_missing)is not bool):
            raise ValueError('Creator READ has only its backend-derived current draft')
        if self.consumer=='configuration_view':
            if(self.required_capability!='workbench.create'or not self.allow_missing
                    or any(v is not None for v in(self.command_kind,self.command_operation_id,self.command_input_digest))):
                raise ValueError('configuration view retains its original fixed Owner READ recipe')
        elif self.consumer=='d04_root_initialization':
            if(self.command_kind not in _COMMANDS or self.required_capability!=_COMMANDS[self.command_kind][0]
                    or type(self.command_operation_id)is not str or not _digest(self.command_input_digest)):
                raise ValueError('D04 Creator READ requires its original exact named command')
            parsed=UUID(self.command_operation_id)
            if parsed.version!=4 or str(parsed)!=self.command_operation_id:
                raise ValueError('D04 Creator command requires its actual UUID4')
        else:raise ValueError('Creator READ has only its two fixed internal consumers')
    @property
    def domain(self):return 'creator_draft'
    @property
    def refs(self):
        ns=NamespaceId.from_key(AtomKey.from_token(self.draft_ref))
        return(character_draft_key(ns).token,active_scheme_head_key(ns).token)


def creator_draft_request_v3(request):return type(request)is CreatorDraftReadRequestV3


def creator_draft_required_domains_v3(request):
    if not creator_draft_request_v3(request):raise AuthorityUnavailable('exact Creator request required')
    return frozenset({'d12'})if request.consumer=='configuration_view'else _COMMANDS[request.command_kind][1]


def require_creator_draft_factory_v3(graph,authority,lease,request):
    if(not creator_draft_request_v3(request)or type(authority)is not AuthorityContext
            or authority.issuer_domain!='d12'or 'persona'not in authority.owner_scope
            or request.refs!=(character_draft_key(authority.namespace).token,active_scheme_head_key(authority.namespace).token)):
        raise AuthorityUnavailable('Creator READ cannot borrow another domain or namespace')
    graph._authorize(lease,authority,creator_draft_required_domains_v3(request),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if(owner is None or session is None or request.required_capability not in owner.capabilities
            or owner.actor!=authority.actor or owner.namespace!=authority.namespace
            or session[1].principal!=owner.principal):
        raise AuthorityUnavailable('Creator READ requires its actual current signed Owner and original capability')
    return owner,session


def _identity(reader):
    return(reader.graph,reader.work,reader.operation,reader.fence,reader.authority,reader.lease,
        reader.session_proof,reader.request,reader.selection_digest,reader.graph_stamp,reader.catalogue_hash)


class _CreatorStateV3:
    def __init__(self,reader):
        self.reader,self.identity=reader,_identity(reader)
        self.owner=None;self.records={};self.event_headers={};self.complete=False;self.carrier=None;self.owner_eof=None;self.write_observation=None
    def require_v3(self):
        from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
        r=self.reader;require_owner_state_reader_v3(r)
        if(_CREATOR_STATES.get(r)is not self or self.identity!=_identity(r)
                or self.owner is not None and r.owner_binding is not self.owner):
            raise AuthorityUnavailable('Creator READ changed its actual Work/Owner/selection')
        return self


def register_creator_draft_reader_v3(reader):
    if reader in _CREATOR_STATES:raise AuthorityUnavailable('Creator READ may register once')
    require_creator_draft_factory_v3(reader.graph,reader.authority,reader.lease,reader.request)
    _CREATOR_STATES[reader]=_CreatorStateV3(reader)


def pin_creator_draft_owner_v3(reader):
    state=_CREATOR_STATES[reader].require_v3()
    binding=reader.general_owner_entry.require_for_v3(reader)
    if(reader.request.required_capability not in binding.capabilities
            or reader.authority.purpose not in binding.purposes
            or not set(reader.authority.audience)<=set(binding.audiences)):
        raise AuthorityUnavailable('Creator READ original purpose/audience/capability exceeds its actual Owner EOF')
    state.owner=reader.owner_binding
    if state.owner_eof is None and reader.request.consumer=='d04_root_initialization':
        from ..authority_service.owner_location_read_v3 import freeze_current_creator_owner_eof_v3
        state.owner_eof=freeze_current_creator_owner_eof_v3(reader)


def creator_draft_source_groups_v3(reader,roots):
    state=_CREATOR_STATES[reader].require_v3()
    if(not state.complete or roots or reader.selected_plan.source_roots or state.owner is None):
        raise AuthorityUnavailable('Creator administrative empty Source recipe is not its exact completed Owner READ')
    reader.general_owner_entry.require_for_v3(reader)
    return()


def creator_draft_metadata_spec_v3(reader,identity):
    state=_CREATOR_STATES[reader].require_v3()
    if(type(identity)is not tuple or len(identity)!=3 or identity[0]!='creator_event'
            or identity[1]not in state.event_headers
            or identity[2]not in {'reads','epoch_reads','revisions','invalidated'}):
        raise AuthorityUnavailable('Creator metadata has no arbitrary table, original or field selector')
    return('graph_events',identity[2],('bot','persona','session','event_id'),identity[1],
        ('digest','epoch_revision'),((),),None)


def finish_creator_draft_metadata_v3(task,value):
    state=_CREATOR_STATES[task.reader].require_v3()
    if task.metadata!=state.event_headers[task.identity[1]]or type(value)is not list:
        raise AuthorityUnavailable('Creator producing event changed after complete canonical metadata EOF')
    return value


def creator_draft_metadata_plan_v3(reader):
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from ..runtime_storage_v3 import read_runtime_cell_origin_v3,CODECS
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state=_CREATOR_STATES[reader].require_v3();outer=require_owner_state_reader_v3(reader)
    if state.owner is None:raise AuthorityUnavailable('Creator keys cannot open before actual Owner EOF')
    refs=reader.request.refs;heads=tuple(reader.heads.get(ref)for ref in refs)
    if heads[0]is None:
        if heads[1]is not None or not reader.request.allow_missing:
            raise AuthorityUnavailable('Creator draft is missing or only its active head exists')
    elif heads[0][0]<1 or heads[0][1]!=1 or heads[1]is not None and(heads[1][0]<1 or heads[1][1]!=1):
        raise AuthorityUnavailable('Creator current administrative head is invalid')
    for ref,head in zip(refs,heads):
        if head is None:continue
        if ref in state.records:
            with runtime_storage_quantum_v3(reader.db)as meter:
                actual=_beta1_metadata_row_v3(reader,meter,'segmented_cells_v1',
                    ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                        'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(state.records[ref][1],))
            if actual!=state.records[ref][2]:raise AuthorityUnavailable('Creator sealed current cell header changed')
            continue
        with runtime_storage_quantum_v3(reader.db)as meter:
            history=_beta1_metadata_row_v3(reader,meter,'graph_history',
                ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
                'token=? AND revision=?',(ref,head[0]))
            if(history is None or history[:3]!=(1,*reader.namespace.as_tuple)
                    or head[2]is None or history[5]!=head[2]):
                raise AuthorityUnavailable('Creator key lacks its actual current history/cell member')
            header=_beta1_metadata_row_v3(reader,meter,'segmented_cells_v1',
                ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                    'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(head[2],))
            if(header is None or header[0]not in CODECS or header[1]!=ref or header[3]<0 or header[4]<0):
                raise AuthorityUnavailable('Creator current sealed cell header is absent or foreign')
            origin=read_runtime_cell_origin_v3(reader.db,head[2],header=header,meter=meter)
            event_key=tuple(history[1:5])
            event=_beta1_metadata_row_v3(reader,meter,'graph_events',('digest','epoch_revision'),
                'bot=? AND persona=? AND session=? AND event_id=?',event_key)
        if event is None or type(event[1])is not int or event[1]<1:
            raise AuthorityUnavailable('Creator current cell has no actual committed Graph event')
        if origin is not None and(origin['locator']!={'table':'graph_atoms','token':ref,'revision':head[0]}
                or origin['operation_id']!=history[4]or origin['event_digest']!=event[0]
                or tuple(origin['namespace'])!=reader.namespace.as_tuple
                or tuple(origin['read_proof']['event_scope'])!=event_key):
            raise AuthorityUnavailable('Creator cell differs from its actual verified producer origin')
        # None is recorded only after the official selected/capture verifier above succeeds.
        state.records[ref]=(history,head[2],header,origin,event_key)
        from .dispatch_current_inventory_v3 import _heap
        reader.operation.retain(_heap(state.records[ref])+1024)
        state.event_headers[event_key]=event
    outer.roots=set();outer.metadata_complete=True;state.complete=True
    return ProductionReadPlanV1((),tuple(AtomKey.from_token(ref)for ref in refs),(),())


def require_creator_draft_body_v3(reader,table,key):
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    state=_CREATOR_STATES[reader].require_v3();outer=require_owner_state_reader_v3(reader)
    if(table!='graph_atoms'or tuple(key[1:])!=reader.namespace.as_tuple or len(key)!=3
            or key[0]not in reader.request.refs or not state.complete or state.owner is None
            or outer.source_permission is None or reader.selected_plan.source_roots):
        raise AuthorityUnavailable('Creator Body admission permits only its two administrative current keys')
    outer.source_permission.require_for_v3(reader)
    return True


def _versions(value,namespace):
    if type(value)is not list:raise AuthorityUnavailable('Creator Graph receipt vector has no canonical EOF')
    result=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in value)
    if(any(NamespaceId.from_key(v.key)!=namespace for v in result)or len({v.key for v in result})!=len(result)):
        raise AuthorityUnavailable('Creator Graph receipt has foreign or duplicate members')
    return result


def _producer_receipts_v3(reader,state):
    from .beta1_owner_state_read_v3 import _metadata
    receipts={}
    for event_key,event in state.event_headers.items():
        reads=_versions(_metadata(reader,('creator_event',event_key,'reads')),reader.namespace)
        writes=_versions(_metadata(reader,('creator_event',event_key,'revisions')),reader.namespace)
        invalidated=_versions(_metadata(reader,('creator_event',event_key,'invalidated')),reader.namespace)
        epochs=_metadata(reader,('creator_event',event_key,'epoch_reads'))
        if(type(epochs)is not list or len(epochs)>1 or any(type(v)is not list or len(v)!=3
                or tuple(v[:2])!=reader.namespace.as_tuple or type(v[2])is not int or v[2]<0 or v[2]>=event[1] for v in epochs)):
            raise AuthorityUnavailable('Creator producer original namespace CAS metadata differs')
        for ref,(history,cell_id,header,origin,key)in state.records.items():
            if key!=event_key:continue
            if GraphVersion(AtomKey.from_token(ref),reader.heads[ref][0])not in writes:
                raise AuthorityUnavailable('Creator current key is not a member of its actual GraphReceipt')
            if origin is not None and(origin['read_proof']['reads']!=[[v.key.token,v.revision]for v in reads]
                    or origin['read_proof']['epochs']!=epochs):
                raise AuthorityUnavailable('Creator official origin differs from its complete producing receipt')
        receipts[event_key]=GraphReceipt('committed',writes,invalidated,NamespaceEpoch(*reader.namespace.as_tuple,event[1]))
    return receipts


def creator_draft_projection_v3(reader):
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    state=_CREATOR_STATES[reader].require_v3();outer=require_owner_state_reader_v3(reader)
    outer.source_permission.require_for_v3(reader)
    receipts=_producer_receipts_v3(reader,state)
    atoms=tuple(method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(ref))for ref in reader.request.refs)
    draft_atom,head_atom=atoms
    draft=_decode_draft_v3(reader.namespace,draft_atom,head_atom,reader.request.allow_missing)
    columns={}
    for atom in atoms:
        if atom.revision==0:continue
        point=next((p for p in reader.points.values()if p.complete and p.table=='graph_atoms'and p.key[0]==atom.key.token),None)
        column=None if point is None else point.values.get('value')
        record=state.records[atom.key.token]
        if(column is None or not column.complete or column.cell is None
                or column.cell.cell_id!=record[1] or column.cell.header!=record[2]or column.sha256!=record[2][5]):
            raise AuthorityUnavailable('Creator complete Body differs from its metadata-selected canonical cell')
        columns[atom.key.token]=column
    carrier=PreparedCurrentCreatorDraftV3(reader,atoms,columns,receipts)
    state.carrier=carrier
    return carrier


def _decode_draft_v3(namespace,draft_atom,head_atom,allow_missing):
    if draft_atom.revision==0:
        if head_atom.revision!=0 or not allow_missing:raise AuthorityUnavailable('actual absent Creator pair required')
        return CharacterDraft(namespace.persona_id,0,{},{})
    value=dict(draft_atom.value)
    if value.pop('schema')!=draft_atom.key.type_name:raise AuthorityUnavailable('Creator draft schema differs')
    draft=CharacterDraft(**value)
    if draft.scope!=namespace.persona_id or draft.revision!=draft_atom.revision:
        raise AuthorityUnavailable('Creator draft typed scope/revision differs from its complete current value')
    if head_atom.revision:
        raw=dict(head_atom.value)
        if raw.pop('schema')!=head_atom.key.type_name:raise AuthorityUnavailable('Creator active head schema differs')
        head=ActiveSchemeHeadV1(**raw)
        if(head.scope!=namespace.persona_id or head.generation!=head_atom.revision
                or head.draft_ref!=draft_atom.key.token or head.draft_revision>draft.revision):
            raise AuthorityUnavailable('Creator active pointer differs from its real namespace/draft history')
    return draft


class PreparedCurrentCreatorDraftV3:
    def __init__(self,reader,atoms,columns,receipts):
        state=_CREATOR_STATES[reader]
        if not state.complete or state.carrier is not None:raise AuthorityUnavailable('Creator result may issue once')
        self.reader,self.atoms,self.columns,self.receipts=reader,atoms,columns,receipts
        self.versions=tuple(GraphVersion(a.key,a.revision)for a in atoms)
        self.commitments=tuple((ref,c.sha256,c.canonical_digest,c.cell.header)for ref,c in columns.items())
        _PREPARED[self]=(reader,reader.work,reader.operation,reader.selection_digest,reader.graph_stamp,
            state.owner,reader.session_proof,reader.request,self.versions,self.commitments,False,atoms,columns,receipts)
    def require_result_v3(self,work):
        record=_PREPARED.get(self)
        if(record is None or record[1]is not work or work.state is not self.reader
                or not self.reader.complete or not self.reader.read_finished or self.reader.inputs_sealed
                or self.reader.business_started or record[11]is not self.atoms
                or record[12]is not self.columns or record[13]is not self.receipts):
            raise AuthorityUnavailable('Creator result is not its actual completed readonly Work')
        return self
    @property
    def draft_atom(self):
        _prepared_v3(self);return self.atoms[0]
    @property
    def head_atom(self):
        _prepared_v3(self);return self.atoms[1]
    @property
    def draft(self):
        _prepared_v3(self)
        return _decode_draft_v3(self.reader.namespace,*self.atoms,self.reader.request.allow_missing)
    @property
    def head(self):
        if self.head_atom.revision==0:return None
        raw=dict(self.head_atom.value);raw.pop('schema');return ActiveSchemeHeadV1(**raw)
    def frame_v3(self):
        _prepared_v3(self)
        from ..domains.d12.scheme_command import D12CurrentCreatorDraftV1
        r=self.reader;record=_PREPARED[self]
        return D12CurrentCreatorDraftV1(r.namespace,r.request.draft_ref,self.draft_atom.revision,self.draft,
            self.head_atom.key.token,self.head_atom.revision,record[4][0].graph_revision,
            record[5].access_epoch,record[5].delete_epoch,True)
    def release_payload_v3(self):
        record=_PREPARED.get(self)
        if record is None:return
        r=self.reader
        from .current_method_learning_read_v3 import _release_method_registered_payloads_v3,_clear_method_selected_payloads_v3
        _release_method_registered_payloads_v3(r);_clear_method_selected_payloads_v3(r)
        self.atoms=();self.columns.clear();self.receipts.clear();self.reader=None


def require_creator_draft_terminal_v3(value,work):
    if type(value)is not PreparedCurrentCreatorDraftV3:raise AuthorityUnavailable('actual private Creator carrier required')
    return value.require_result_v3(work)


def release_creator_draft_reader_v3(reader):
    state=_CREATOR_STATES.pop(reader,None)
    if state is not None:
        if state.carrier is not None:_PREPARED.pop(state.carrier,None)
        if state.owner_eof is not None:
            from ..authority_service.owner_location_read_v3 import release_current_creator_owner_eof_v3
            release_current_creator_owner_eof_v3(state.owner_eof)
        state.owner_eof=state.write_observation=None
        state.records.clear();state.event_headers.clear();state.carrier=None


def prepare_current_creator_draft_read_v3(graph,authority,lease,*,consumer,draft_ref,
        required_capability,allow_missing=False,command_kind=None,command_operation_id=None,command_input_digest=None):
    from .beta1_owner_state_read_v3 import prepare_owner_state_read_v3
    request=CreatorDraftReadRequestV3(consumer,draft_ref,required_capability,allow_missing,
        command_kind,command_operation_id,command_input_digest)
    require_creator_draft_factory_v3(graph,authority,lease,request)
    return prepare_owner_state_read_v3(graph,authority,lease,request=request)


def _prepared_v3(value):
    if type(value)is not PreparedCurrentCreatorDraftV3 or value not in _PREPARED:
        raise AuthorityUnavailable('actual private Creator READ carrier required')
    record=_PREPARED[value];r=record[0]
    if(value.reader is not r or record[1]is not r.work or record[2]is not r.operation
            or record[3]!=r.selection_digest or record[4]!=r.graph_stamp or record[6]!=r.session_proof
            or record[7]is not r.request or record[8]!=value.versions or record[9]!=value.commitments
            or record[11]is not value.atoms or record[12]is not value.columns or record[13]is not value.receipts
            or r.operation.closed or not r.complete or not r.read_finished or r.inputs_sealed or r.business_started):
        raise AuthorityUnavailable('Creator carrier lost its original completed READ/lifetime')
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from .first_ingress_v2 import trusted_upper
    if type(r.initial_clock)is not VerifiedIngressClockV2 or trusted_upper(r.initial_clock)>=r.operation.deadline_utc:
        raise AuthorityUnavailable('Creator carrier exceeded its original paired-clock deadline')
    return record


def _require_creator_headers_v3(value,meter):
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    record=_prepared_v3(value);r=record[0]
    r.operation.handle.require_current(meter)
    if(r.graph._v2_graph_stamp(r.namespace)!=record[4]or r.store._registry.catalogue_hash!=r.catalogue_hash):
        raise AuthorityUnavailable('Creator current namespace/codec changed before consumption')
    for atom in value.atoms:
        head=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(atom.key.token,*r.namespace.as_tuple))
        if atom.revision==0:
            if head is not None:raise AuthorityUnavailable('Creator negative current key appeared')
            continue
        column=value.columns[atom.key.token]
        if(head!=(atom.revision,1,column.cell.cell_id)or _freeze_value_v3(atom.value)!=column.frozen):
            raise AuthorityUnavailable('Creator current value differs from its completed canonical EOF')
        header=meter.read_fixed_row(r.db,'segmented_cells_v1',
            ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(column.cell.cell_id,))
        if header!=column.cell.header:raise AuthorityUnavailable('Creator sealed cell changed before consumption')
    return record


def consume_current_creator_draft_read_v3(value,*,graph,work,consumer,command_operation_id=None,command_input_digest=None):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    record=_prepared_v3(value);r=record[0];request=r.request
    value.require_result_v3(work);work._require_invocation(graph)
    if(r.graph is not graph or record[10]or(request.consumer,request.command_operation_id,request.command_input_digest)
            !=(consumer,command_operation_id,command_input_digest)):
        raise AuthorityUnavailable('Creator carrier may be consumed once only by its actual fixed caller')
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
        _require_creator_headers_v3(value,meter)
    _PREPARED[value]=(*record[:10],True,*record[11:])
    return value


def require_current_creator_draft_invocation_v3(value,graph,authority,lease,*,consumer,command_kind,
        command_operation_id,command_input_digest,domains,capability):
    from ..graph_coordinator import OwnerLeaseBindingV1
    record=_prepared_v3(value);r=record[0];request=r.request
    if(request.consumer!='d04_root_initialization'or not record[10]or r.graph is not graph
            or r.authority is not authority or r.lease is not lease
            or(request.consumer,request.command_kind,request.command_operation_id,request.command_input_digest,
                request.required_capability)!=(consumer,command_kind,command_operation_id,command_input_digest,capability)
            or _COMMANDS[command_kind]!=(capability,frozenset(domains))
            or type(record[5])is not OwnerLeaseBindingV1
            or graph._GraphCoordinator__owner_session_proofs.get(lease)!=record[6]):
        raise AuthorityUnavailable('Creator retained READ differs from its exact named Owner WRITE invocation')
    current=graph._GraphCoordinator__owner_leases.get(lease)
    if(type(current)is not OwnerLeaseBindingV1 or current.principal!=record[5].principal
            or current.actor!=authority.actor or current.namespace!=r.namespace
            or capability not in current.capabilities):
        raise AuthorityUnavailable('Creator retained command no longer has its actual signed Owner lease')
    return value


@contextmanager
def bind_current_creator_draft_write_v3(value,graph,authority,lease,*,issuer,consumer,command_kind,
        command_operation_id,command_input_digest,domains,capability,scope,guard,current_owner):
    from ..graph_coordinator import OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    require_current_creator_draft_invocation_v3(value,graph,authority,lease,consumer=consumer,command_kind=command_kind,
        command_operation_id=command_operation_id,command_input_digest=command_input_digest,domains=domains,capability=capability)
    record=_prepared_v3(value);r=record[0]
    attempt_id='owner-domain-'+canonical_digest((r.namespace,command_operation_id,command_input_digest))[:48]
    state=_CREATOR_STATES[r]
    observation=state.write_observation
    fields=('principal','actor','namespace','grant_id','scope','issuer_ref','capabilities','purposes','audiences',
        'grant_digest','grant_revision','access_epoch','delete_epoch','graph_incarnation',
        'authorization_head','authorization_revision','revocation_epoch')
    if(issuer is not graph._GraphCoordinator__graph_capability or _WRITE.get()is not None
            or type(scope)is not FenceScope or scope.operation!='write' or scope is r.fence.scope
            or scope.namespace!=r.namespace or scope.operation_id!=attempt_id or scope.permit.operation_id!=attempt_id
            or(scope.graph_revision,scope.graph_epoch)!=(record[4][0].graph_revision,record[4][1])
            or type(current_owner)is not OwnerLeaseBindingV1
            or tuple(getattr(current_owner,k)for k in fields)!=tuple(getattr(record[5],k)for k in fields)
            or observation is None or observation[0]is not scope or observation[2:]!=(guard,current_owner)
            or type(guard)is not OwnerAuthorizationGuardV1 or guard!=r.owner_guard
            or guard.namespace!=r.namespace or current_owner.authorization_head!=guard.authorization_head):
        raise AuthorityUnavailable('Creator WRITE requires Root private issuance and the same actual current Owner/fresh Scope')
    binding=(value,graph,authority,lease,scope,guard,current_owner,command_operation_id,command_input_digest)
    token=_WRITE.set(binding)
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):yield value
    finally:_WRITE.reset(token)


def require_current_creator_draft_write_v3(value,graph,authority,lease,*,consumer,command_operation_id,
        command_input_digest,db,scope,current_owner):
    binding=_WRITE.get();record=_prepared_v3(value);r=record[0]
    if(binding is None or binding[0]is not value or binding[1]is not graph or binding[2]is not authority
            or binding[3]is not lease or binding[4]is not scope or binding[6]is not current_owner
            or binding!=(value,graph,authority,lease,scope,binding[5],current_owner,
            command_operation_id,command_input_digest)or db is not r.db or not db.in_transaction
            or not r.store._lock._is_owned()or r.request.consumer!=consumer):
        raise AuthorityUnavailable('Creator WRITE consumer left its actual Root-issued same-transaction binding')
    state=_CREATOR_STATES[r]
    with runtime_storage_quantum_v3(db)as meter:
        _require_creator_headers_v3(value,meter)
        if _qualify_creator_owner_write_v3(value,state.write_observation[1],scope,meter)!=(binding[5],current_owner):
            raise AuthorityUnavailable('Creator current Owner changed inside its actual WRITE transaction')
    return value


def creator_draft_retained_heap_v3(value):
    record=_PREPARED.get(value)
    if(type(value)is not PreparedCurrentCreatorDraftV3 or record is None
            or _CREATOR_STATES[record[0]].carrier is not value):
        raise AuthorityUnavailable('Creator result retention needs its actual issued READ carrier')
    return 4096+len(record[8])*256+sum((len(r.revisions)+len(r.invalidated))*256+256 for r in value.receipts.values())


def require_current_creator_draft_metadata_owner_v3(reader):
    state=_CREATOR_STATES.get(reader)
    if(state is None or state.reader is not reader or reader.read_finished or reader.complete
            or state.owner is None or reader.general_owner_entry is None
            or reader.request.consumer!='d04_root_initialization'):
        raise AuthorityUnavailable('Creator Owner EOF freeze requires its actual administrative READ before terminal')
    state.require_v3()
    return reader


def require_current_creator_draft_owner_write_metadata_v3(value,reader,scope):
    record=_prepared_v3(value);request=record[7]
    attempt_id='owner-domain-'+canonical_digest((reader.namespace,request.command_operation_id,
        request.command_input_digest))[:48]
    state=_CREATOR_STATES.get(reader)
    if(record[0]is not reader or not record[10]or request.consumer!='d04_root_initialization'
            or state is None or state.carrier is not value or state.identity!=_identity(reader)
            or type(scope)is not FenceScope or scope is reader.fence.scope or scope.operation!='write'
            or scope.namespace!=reader.namespace or scope.generation!=reader.authority.activation_generation
            or scope.operation_id!=attempt_id or scope.permit.operation_id!=attempt_id
            or(scope.graph_revision,scope.graph_epoch)!=(record[4][0].graph_revision,record[4][1])):
        raise AuthorityUnavailable('Creator retained Owner metadata is not its exact private fresh WRITE command')
    return reader


def _qualify_creator_owner_write_v3(value,observation,scope,meter):
    record=_prepared_v3(value);r=record[0];state=_CREATOR_STATES[r]
    if state.owner_eof is None:raise AuthorityUnavailable('Creator fresh WRITE lacks its actual retained Owner EOF')
    atom,proof_row,epochs=state.owner_eof.require_for_write_v3(r,creator_prepare=value,scope=scope,
        metadata=record[4][0],epoch=record[4][1],meter=meter)
    with state.owner_eof.decode_peak_v3(meter,len(atom[1])+len(proof_row[-1])):
        owner=r.graph._owner_graph_binding_from_current_metadata_v3(r.authority,record[5].principal,
            metadata=record[4][0],graph_epoch=record[4][1],atom=atom,proof_row=proof_row,epochs=epochs,
            target_admission=observation.target_admission,storage_admission=observation.storage_admission,
            current_guard=observation.guard)
    guard=observation.guard
    if(owner!=record[5]or r.request.required_capability not in owner.capabilities
            or r.authority.purpose not in owner.purposes or not set(r.authority.audience)<=set(owner.audiences)
            or guard!=r.owner_guard or guard.authorization_revision!=owner.authorization_revision
            or guard.authorization_head!=owner.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=owner.revocation_epoch or guard.pending_revoke_operation_id is not None
            or(observation.target_admission is None and observation.storage_admission is None
                and guard.installation_id!=r.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id)):
        raise AuthorityUnavailable('Creator fresh WRITE Owner/session/rights differ from the actual completed EOF')
    return guard,owner


def observe_current_creator_draft_owner_write_v3(value,graph,authority,lease,scope,
        original_owner,session_proof,metadata,epoch):
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    record=_prepared_v3(value);r=record[0];request=r.request
    require_current_creator_draft_invocation_v3(value,graph,authority,lease,consumer=request.consumer,
        command_kind=request.command_kind,command_operation_id=request.command_operation_id,
        command_input_digest=request.command_input_digest,domains=_COMMANDS[request.command_kind][1],
        capability=request.required_capability)
    require_current_creator_draft_owner_write_metadata_v3(value,r,scope)
    state=_CREATOR_STATES[r];port=graph._GraphCoordinator__content_fence_v2
    if(state.write_observation is not None or r.db.in_transaction or original_owner!=record[5]
            or session_proof!=record[6]or(metadata,epoch)!=record[4]
            or scope.authority_namespace!=metadata.requirements.authority_namespace
            or not graph._anchor_matches(metadata.requirements,scope.pinned_anchor)
            or port.validate_fence(scope)!=scope.permit
            or graph._current_owner_principal(authority.actor,r.namespace)!=record[5].principal):
        raise AuthorityUnavailable('Creator fresh WRITE observation changed its actual session/fence/stamp')
    token,session_request=record[6]
    if session_request.principal!=record[5].principal:
        raise AuthorityUnavailable('Creator actual signed Owner session principal differs')
    current,permit=port.get_current_owner_authority_for_fence_v1(namespace=r.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,owner_actor_id=authority.actor,
        owner_session_token=token,owner_session_request=session_request)
    if(type(current)is not D12CurrentOwnerAuthorityV1 or permit!=scope.permit
            or current.guard.namespace!=r.namespace or current.guard.authority_id!=scope.pinned_anchor.authority_id
            or port.validate_fence(scope)!=scope.permit):
        raise AuthorityUnavailable('Creator actual current Owner Authority differs from its fresh WRITE permit')
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
        _require_creator_headers_v3(value,meter)
        guard,owner=_qualify_creator_owner_write_v3(value,current,scope,meter)
    state.write_observation=(scope,current,guard,owner)
    return guard,owner
