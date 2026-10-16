"""Fixed installed Contact Host stage Work over real V3 Scope and Source EOF."""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
from ..graph_types import AtomKey,GraphAtom,GraphVersion,NamespaceEpoch
from ..runtime_contracts import NamespaceId,canonical_digest
from ..graph_worker import GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3
from .contact_host_source_v3 import (register_contact_host_work_v3,require_contact_host_work_v3,
    bind_contact_host_originals_v3,ContactHostSourceMaterialReadV3,release_contact_host_materials_v3)

_HOST_ISSUER = object()
_HOST_IDENTITIES = WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ContactHostStageSelectorV3:
    namespace: NamespaceId
    contact_id: str
    model_phase: str
    stage: str
    result_attempt: int = 1
    seal_intent_digest: str | None = None
    owner_command_digest: str | None = None
    dispatch_request_digest: str | None = None
    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or not self.contact_id.startswith('contact:')
                or self.model_phase not in {'contact_generation','contact_review'}
                or self.stage not in {'preparation','egress','attempts','paid_result','paid_progress','paid_batch',
                    'acquire','paid_cost','result_read','terminal','seal','background_item','joint_contact_preparation','dispatch_text'}
                or type(self.result_attempt) is not int or self.result_attempt < 1
                or (self.owner_command_digest is None) != (self.stage != 'joint_contact_preparation')
                or (self.dispatch_request_digest is None) != (self.stage != 'dispatch_text')):
            raise AuthorityUnavailable('Contact Host requires its exact fixed stage selector')


@dataclass(frozen=True,slots=True)
class ContactHostIssuedScopeV3:
    scope: object
    metadata: object
    epoch: object
    service: object
    def require_for_v3(self,state):
        if (self.service is not state.service or self.scope is not state.borrowed_scope
                or self.scope.operation != 'write' or self.scope.namespace != state.namespace
                or state.service.port.validate_fence(self.scope) != self.scope.permit
                or (self.metadata,self.epoch) != state.graph_stamp):
            raise AuthorityUnavailable('Contact borrowed WRITE Scope lost its actual installed issuer/current permit')
        return self


class ContactHostSourceMetadataV3:
    def __init__(self,issuer,work,original):
        from .dispatch_current_inventory_v3 import VerifiedDispatchSourceMetadataV3,_SOURCE_ISSUED
        if issuer is not _HOST_ISSUER or type(original) is not VerifiedDispatchSourceMetadataV3:
            raise AuthorityUnavailable('Contact Host metadata requires its actual full census Source original')
        require_contact_host_work_v3(work)
        expected = (work.db,original.source_key,original.revision,original.valid,original.cell_id,original.header,
            original.payload_sha256,original.metadata,original.scope,original.graph_stamp,original.query,
            original.operation_id,original.selection_digest)
        if _SOURCE_ISSUED.get(original) != expected or original.scope != work.scope:
            raise AuthorityUnavailable('Contact Host metadata changed its real census/Scope')
        self.work,self.original = work,original
        for name in ('source_key','revision','valid','cell_id','header','payload_sha256','metadata'):
            setattr(self,name,getattr(original,name))
    def require_current_v3(self):
        work = require_contact_host_work_v3(self.work)
        work.require_current_v3()
        original = self.original
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        if (_SOURCE_ISSUED.get(original) != (work.db,self.source_key,self.revision,self.valid,self.cell_id,self.header,
                self.payload_sha256,self.metadata,work.scope,work.graph_stamp,work.query,
                work.operation.operation_id,work.selection_digest)):
            raise AuthorityUnavailable('Contact Host Source metadata lost its actual EOF origin')
        return self


class ContactHostProjectionV3:
    def __init__(self,issuer,work):
        if issuer is not _HOST_ISSUER or not work.graph_eof:
            raise AuthorityUnavailable('Contact Host projection requires actual complete namespace census')
        self.work = work
        self.epochs = (work.graph_stamp[1],)
    @property
    def atoms(self):
        require_contact_host_work_v3(self.work)
        return tuple(self.work.atoms)
    @property
    def versions(self):
        return tuple(GraphVersion(atom.key,atom.revision) for atom in self.atoms)
    def get(self,key):
        work = require_contact_host_work_v3(self.work)
        if NamespaceId.from_key(key) != work.namespace:
            raise AuthorityUnavailable('Contact Host projection crossed namespace')
        if key.type_name == 'memory.source':
            if work.source_material is None or key.token not in work.source_material.source_records:
                raise AuthorityUnavailable('Contact Host body is outside its independently qualified Source material')
            record = work.source_material.source_records[key.token]
            return GraphAtom(key,work.source_material.witnesses[key.token].revision,record.to_dict(),True)
        atom = next((atom for atom in work.atoms if atom.key == key),None)
        if atom is not None:
            return atom
        if key.token not in work.heads:
            return GraphAtom(key,0,{},False)
        return contact_host_original_point_v3(work.db,table='graph_atoms',columns=('revision','value','valid'),
            key_columns=('token',),key=(key.token,),as_atom=key)


class ContactHostPreparedMetadataReadV3:
    def __init__(self,state,model_phase=None):
        from ..authority_service.contact_background_graph_v3 import ContactPlanLocatorEOFV3
        from ..authority_service.contact_model_work_v3 import ContactFrozenMetadataEOFV3
        from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
        from .contact_model_job_v2 import contact_model_ids_v2
        self.state = state
        plan = decode_contact_plan_v2(state.contact_locator.plan_metadata)
        self.model_phase = state.selector.model_phase if model_phase is None else model_phase
        self.ids = contact_model_ids_v2(plan,self.model_phase)
        self.reader = ContactPlanLocatorEOFV3(state)
        self.reader._selected = lambda path: len(path)==1 and path[0] in {
            'namespace','contact_id','phase','activity_id','installation_id','job_id','prepare_operation_id',
            'acquire_operation_id','call_id','plan_original_digest','frozen_digest','quote_id','quote_version',
            'quote_digest','reservation_digest','provider_config_ref','algorithm_build_digest'} or path in {
                ('namespace','bot_id'),('namespace','persona_id')}
        self.frozen = ContactFrozenMetadataEOFV3(state)
        actual_emit = self.reader._emit
        def emit(event):
            if event.path == ('frozen_json',) and event.kind == 'scalar_chunk':
                self.frozen.feed_outer_v3(event.raw)
            else:
                actual_emit(event)
        self.reader._emit = emit
        self.complete = False
        self.values = None
    def advance(self,meter):
        from .contact_paid_original_v2 import TABLE,SIGN_KIND
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..runtime_contracts import canonical_serialize
        state,r = self.state,self.reader
        state.require_current(meter=meter)
        key = (*state.namespace.as_tuple,'prepared',self.ids['job'])
        where = 'bot=? AND persona=? AND kind=? AND original_ref=?'
        if r.phase == 'metadata':
            r.metadata = _runtime_bounded_fixed_row_v3(state.db,meter,TABLE,('payload_digest','signature'),where,key)
            if r.metadata is None:
                from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
                if state.selector.stage == 'background_item' or (type(state) is ContactDomainSourceReadV3
                        and (state.selector.phase=='contact_followup' or state.selector.phase=='contact_generation_preparation' and self.model_phase=='contact_generation')):
                    self.values,self.complete = None,True
                    return
                raise AuthorityUnavailable('Contact Host actual prepared original absent')
            r.total = state.db.execute('SELECT length(CAST(payload_json AS BLOB)) FROM '+TABLE+' WHERE '+where,key).fetchone()[0]
            meter.charge_read(8)
            r.phase = 'body'
            return
        if r.phase == 'body':
            if r.fragment_offset < len(r.fragment):
                end = min(r.fragment_offset+1024,len(r.fragment))
                r.parser.feed(r.fragment[r.fragment_offset:end],r._emit)
                r.fragment_offset = end
                return
            if r.offset == r.total:
                r.phase = 'eof'
                return
            fragment,total,kind = read_legacy_sql_cell_fragment_v2(state.db,table=TABLE,column='payload_json',
                where=where,parameters=key,start=r.offset,length=min(16384,r.total-r.offset),meter=meter)
            if total != r.total or kind != 'text' or not fragment:
                raise AuthorityUnavailable('Contact Host prepared metadata EOF changed')
            r._reserve(len(fragment)+1024)
            r.fragment,r.fragment_offset = fragment,0
            r.offset += len(fragment)
            return
        result = r.parser.finish()
        frozen = self.frozen.finish_v3()
        state.contact_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((state.namespace,'prepared',self.ids['job'],result.sha256)),r.metadata[1])
        if result.sha256 != r.metadata[0] or frozen.sha256 != r.values[('frozen_digest',)]:
            raise AuthorityUnavailable('Contact Host prepared/frozen actual whole birth EOF differs')
        if (r.values[('job_id',)] != self.ids['job'] or r.values[('contact_id',)] != state.selector.contact_id
                or r.values[('phase',)] != self.model_phase
                or r.values[('installation_id',)] != state.service.port.installation_grant.installation_id
                or r.values[('plan_original_digest',)] != state.contact_locator.digest):
            raise AuthorityUnavailable('Contact Host prepared metadata changed its exact installed phase')
        self.values,self.digest,self.metadata = dict(r.values),result.sha256,r.metadata
        self.complete = True
        r.parser,r.fragment = None,b''


class ContactHostStageReadWorkV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,issuer,service,selector,operation):
        from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
        from .contact_dispatch_host_read_v1 import ContactDispatchIdentitySelectorV3
        if issuer is not _HOST_ISSUER or type(service) is not InstalledContactModelGraphRuntimeV2 or type(selector) not in (ContactHostStageSelectorV3,ContactDispatchIdentitySelectorV3):
            raise AuthorityUnavailable('Contact Host Work requires its actual installed runtime and typed stage')
        service._current()
        if selector.namespace != service.bundle.installation_policy.namespace:
            raise AuthorityUnavailable('Contact Host selector crossed its installed namespace')
        self.service,self.graph,self.store,self.db = service,service.graph,service.store,service.store._db
        self.namespace,self.selector,self.contact_selector,self.operation = selector.namespace,selector,selector,operation
        self.request = selector
        self.handle = operation.handle
        self.prefinal = self
        self.reserved = 0
        self.contact_issuer = service.issuer
        self.work,self.scope,self.fence = None,None,None
        self.graph_stamp = self.graph._v2_graph_stamp(self.namespace)
        self.selection_digest = operation.selection_digest
        self.phase,self.closed,self.complete = 'plan_locator',False,False
        self.contact_policy = None
        self.contact_locator = None
        self.prepared_locator = None
        self.issued_capabilities = []
        self.attachments,self.attachment_pending = {},None
        self.heads,self.sources,self.atoms = {},{},[]
        self.source_selection,self.source_reader,self.source_material = None,None,None
        self.projection,self.prepared,self.result = None,None,None
        self.permit,self.owner,self.current_policy,self.finish_identity = None,None,None,None
        self.policy_lifetime = None
        self.borrowed_scope = None
        self.owner_command = None
        self.owner_entry = None
        self.dispatch_identity_recipe=None
        self.dispatch_text_locator=None
        self.owner_point = None
        self.operation_id = operation.operation_id
        self.now_utc = None
        register_contact_host_work_v3(self)
        _HOST_IDENTITIES[self] = (service,self.graph,self.db,selector,operation,self.selection_digest)
    def require_actual_v3(self):
        self.service._current()
        if (self.closed or _HOST_IDENTITIES.get(self) != (self.service,self.graph,self.db,self.selector,self.operation,self.selection_digest)
                or self.operation.closed or self.work is None or self.work.state is not self
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph):
            raise AuthorityUnavailable('Contact Host stage lost its actual installed Work/storage lease')
        return self
    _actual = require_actual_v3
    def require_current(self,*,meter):
        self.require_actual_v3()
        self.operation.handle.require_current(meter)
        if self.selector.stage=='dispatch_text'and self.scope is not None:
            from .contact_dispatch_host_read_v1 import require_current_contact_dispatch_text_owner_v1
            require_current_contact_dispatch_text_owner_v1(self)
        elif self.owner_command is not None and self.scope is not None:
            if self.owner_entry is None or self.owner_entry.require_for_v3(self)!=(self.owner_guard,self.owner):
                raise AuthorityUnavailable('Contact Owner Source quantum lacks its completed fixed Owner EOF')
        if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
            raise AuthorityUnavailable('Contact Host Source snapshot changed during EOF')
        return self
    def require_current_v3(self):
        self.require_actual_v3()
        if not self.db.in_transaction:
            raise AuthorityUnavailable('Contact Host Source metadata requires its actual SQL quantum')
        with runtime_storage_quantum_v3(self.db) as meter:
            return self.require_current(meter=meter)
    def _next(self,meter):
        super()._next(meter)
        if self.pending is not None:
            key,revision,valid,_type,cell = self.pending
            self.heads[key.token] = (revision,valid,cell)

    def _graph_eof_v3(self):
        self.sources = {ref:ContactHostSourceMetadataV3(_HOST_ISSUER,self,source) for ref,source in self.sources.items()}
        self.projection = ContactHostProjectionV3(_HOST_ISSUER,self)
        self.phase = 'source'
    def release_payload_v3(self):
        if self.owner_entry is not None:
            self.owner_entry.release_v3()
            self.owner_entry = None
        from .contact_dispatch_host_read_v1 import ContactDispatchIdentitySelectorV3
        if type(self.selector)is ContactDispatchIdentitySelectorV3 and self.dispatch_identity_recipe is not None:
            self.dispatch_identity_recipe.release_v3()
            self.dispatch_identity_recipe=None
        if self.selector.stage=='dispatch_text'and self.dispatch_text_locator is not None:
            self.dispatch_text_locator.release_v3()
            self.dispatch_text_locator=None
        release_contact_host_materials_v3(self)
        from .contact_owner_command_source_v3 import release_contact_owner_command_source_v3
        release_contact_owner_command_source_v3(self)
        for registry,original in self.issued_capabilities:
            registry.pop(original,None)
        self.issued_capabilities.clear()
        self.attachments.clear()
        self.source_material = self.source_reader = self.projection = self.result = None
        self.atoms,self.sources,self.heads = [],{},{}
        self.closed = True
        _HOST_IDENTITIES.pop(self,None)


def contact_host_original_point_v3(db,*,table,columns,key_columns,key,as_atom=None):
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    from .natural_producer_qualification_v1 import _HostProducerAttachmentV3,_HOST_ATTACHMENT_SHAPES_V3
    work = contact_host_work_for_db_v3(db)
    if work is None:
        return False,None
    original_columns,original_keys = tuple(columns),dict(zip(key_columns,key))
    if table == 'graph_atoms':
        atom = AtomKey.from_token(original_keys['token'])
        key_columns,key,columns = ('token','bot','persona'),(atom.token,*work.namespace.as_tuple),('revision','value','valid')
        if atom.type_name == 'memory.source' and (work.source_material is None or atom.token not in work.source_material.source_records):
            raise AuthorityUnavailable('Contact Host original body lacks its current Source material')
    elif table == 'graph_history':
        key_columns,key,columns = ('token','revision'),(original_keys['token'],original_keys['revision']),('event_id','value','valid','event_bot','event_persona','event_session','dependencies')
    request = (table,tuple(columns),tuple(key_columns),tuple(key))
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3:
        raise AuthorityUnavailable('Contact Host original has no exact registered table/column/key shape')
    if table in {'graph_atoms','graph_history'}:
        if NamespaceId.from_key(AtomKey.from_token(key[0])) != work.namespace:
            raise AuthorityUnavailable('Contact Host original crossed namespace')
    elif table in {'runtime_resource_quotes','runtime_budget_grants','runtime_budget_reservations'}:
        if table != 'runtime_resource_quotes':
            with runtime_storage_quantum_v3(db) as meter:
                row = meter.read_fixed_row(db,'runtime_budget_leases',('bot_id','persona_id'),'lease_id=?',(key[0],))
            if row != work.namespace.as_tuple:
                raise AuthorityUnavailable('Contact Host parent budget original crossed namespace')
    elif table != 'runtime_jobs' and tuple(key[:2]) != work.namespace.as_tuple:
        raise AuthorityUnavailable('Contact Host ledger original crossed namespace')
    task = work.attachments.get(request)
    if task is None:
        if work.complete:
            raise AuthorityUnavailable('Contact Host original was not prepared by this actual Work')
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
        raise AuthorityGraphAttachmentRequiredV3(request)
    with runtime_storage_quantum_v3(db) as meter:
        row = task.require_row_v3(work,meter)
    if row is None:
        return (None if as_atom is not None else (True,None))
    if table in {'graph_atoms','graph_history'}:
        values = dict(zip(columns,row))
        values.update(zip(key_columns,key))
        if any(values.get(name) != value for name,value in original_keys.items()):
            raise AuthorityUnavailable('Contact Host original full event/key identity differs')
        if as_atom is not None:
            return GraphAtom(as_atom,values['revision'],json.loads(values['value']),bool(values['valid']))
        return True,tuple(values[name] for name in original_columns)
    return True,row


def prepare_contact_host_stage_work_v3(service,*,contact_id,model_phase,stage,result_attempt=1,borrowed_scope=None,seal_intent=None,seal_permit=None,owner_command=None,dispatch_request=None):
    require_graph_storage_work_admission_v3(service.graph)
    service._current()
    selector = ContactHostStageSelectorV3(service.bundle.installation_policy.namespace,contact_id,model_phase,stage,result_attempt,
        canonical_digest(seal_intent) if seal_intent is not None else None,
        owner_command.source_request_digest if owner_command is not None else None,
        canonical_digest(dispatch_request)if dispatch_request is not None else None)
    operation_id = 'contact-host-stage-read:' + canonical_digest((selector,borrowed_scope.operation_id if borrowed_scope is not None else None))[:48]
    operation = begin_runtime_storage_operation_v3(service.store._db,operation_id,None)
    try:
        state = ContactHostStageReadWorkV3(_HOST_ISSUER,service,selector,operation)
        state.borrowed_scope = borrowed_scope
        state.owner_command = owner_command
        if owner_command is not None:
            from .contact_owner_command_source_v3 import require_contact_owner_command_source_v3
            require_contact_owner_command_source_v3(owner_command,state=state)
        state.seal_intent,state.seal_permit = seal_intent,seal_permit
        work = create_graph_storage_work_v3(service.graph,kind='contact_host_stage_read_v3',operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=None,state=state,operation=operation)
        state.work = work
        from ..authority_service.contact_background_graph_v3 import ContactPlanLocatorEOFV3
        state.contact_locator = ContactPlanLocatorEOFV3(state)
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(operation)
        raise


class ContactHostReceiptMetadataEOFV3:
    def __init__(self,state,operation):
        from ..authority_service.contact_background_graph_v3 import ContactPlanLocatorEOFV3
        self.state,self.operation = state,operation
        self.reader = ContactPlanLocatorEOFV3(state)
        self.reader._selected = lambda path: len(path)==1 and path[0] in {'schema','prepared_digest','operation_id','attempt_id'}
        self.complete,self.absent = False,False
    def advance(self,meter):
        from .contact_paid_original_v2 import TABLE,SIGN_KIND
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..runtime_contracts import canonical_serialize
        state,r = self.state,self.reader
        key = (*state.namespace.as_tuple,'stage_receipt',self.operation)
        where = 'bot=? AND persona=? AND kind=? AND original_ref=?'
        state.require_current(meter=meter)
        if r.phase == 'metadata':
            r.metadata = _runtime_bounded_fixed_row_v3(state.db,meter,TABLE,('payload_digest','signature'),where,key)
            if r.metadata is None:
                self.absent,self.complete = True,True
                return
            r.total = state.db.execute('SELECT length(CAST(payload_json AS BLOB)) FROM '+TABLE+' WHERE '+where,key).fetchone()[0]
            meter.charge_read(8)
            r.phase = 'body'
            return
        if r.phase == 'body':
            if r.fragment_offset < len(r.fragment):
                end = min(r.fragment_offset+1024,len(r.fragment))
                r.parser.feed(r.fragment[r.fragment_offset:end],r._emit)
                r.fragment_offset = end
                return
            if r.offset == r.total:
                r.phase = 'eof'
                return
            fragment,total,kind = read_legacy_sql_cell_fragment_v2(state.db,table=TABLE,column='payload_json',
                where=where,parameters=key,start=r.offset,length=min(16384,r.total-r.offset),meter=meter)
            if total != r.total or kind != 'text' or not fragment:
                raise AuthorityUnavailable('Contact stage receipt metadata EOF changed')
            r._reserve(len(fragment)+1024)
            r.fragment,r.fragment_offset = fragment,0
            r.offset += len(fragment)
            return
        result = r.parser.finish()
        state.contact_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((state.namespace,'stage_receipt',self.operation,result.sha256)),r.metadata[1])
        expected = {'schema':'d10.contact-stage-receipt.v2','prepared_digest':state.prepared_locator.digest,
            'operation_id':self.operation,'attempt_id':'contact-stage-fence:'+canonical_digest((self.operation,
                canonical_digest(('d10.contact-installed-stage.v2',state.prepared_locator.digest,state.selector.stage))))[:48]}
        if result.sha256 != r.metadata[0] or {path[0]:value for path,value in r.values.items()} != expected:
            raise AuthorityUnavailable('Contact original receipt EOF/attempt identity differs')
        self.digest,self.complete = result.sha256,True
        r.parser,r.fragment = None,b''


def _open_contact_host_write_scope_v3(state):
    from dataclasses import asdict
    from .contact_paid_original_v2 import TABLE,SIGN_KIND,require_contact_original_schema_v2
    from .c09_contact_originals_v2 import validate_contact_payload_v2
    from ..runtime_contracts import FenceScope,canonical_serialize
    from ..authority_service.v2_contract import from_wire,to_wire
    values = state.prepared_locator.values
    stage = state.selector.stage
    operation = (values[('acquire_operation_id',)] if stage == 'acquire' else
        'contact-'+stage+':'+canonical_digest((state.namespace,values[('job_id',)],stage))[:48])
    if stage == 'result_read':
        operation += ':'+str(state.selector.result_attempt)
    digest = canonical_digest(('d10.contact-installed-stage.v2',state.prepared_locator.digest,stage))
    attempt_id = 'contact-stage-fence:'+canonical_digest((operation,digest))[:48]
    policy = state.service.bundle.installation_policy
    anchor = state.service.port.current_anchor(namespace=state.namespace,authority_namespace=policy.authority_namespace)
    metadata,epoch = state.graph_stamp
    details = {'schema':'d10.contact-stage-attempt.v2','job_id':values[('job_id',)],'phase':stage,
        'request_digest':digest,'attempt_id':attempt_id,'anchor':asdict(anchor),
        'graph_revision':metadata.graph_revision,'graph_epoch':epoch.revision,'prepared_digest':state.prepared_locator.digest}
    if stage == 'seal' and state.stage_receipt_metadata.absent:
        actual,model_state = state.service.port.get_fence_operation(namespace=state.namespace,
            authority_namespace=policy.authority_namespace,operation_id=state.seal_intent.operation_id)
        intent = state.seal_intent
        if (actual != state.seal_permit or model_state != 'active' or actual.operation != 'model_egress'
                or actual.pinned_anchor != anchor or (actual.subject,actual.token,actual.revision,actual.fence_epoch) !=
                (intent.subject,intent.fence_token,intent.fence_revision,intent.fence_epoch)
                or canonical_digest(intent) != state.selector.seal_intent_digest
                or intent.job_id != values[('job_id',)] or intent.binding_digest != state.prepared_locator.digest):
            raise AuthorityUnavailable('Contact seal differs from its actual original model preparation permit')
    state.stage_operation,state.stage_details = operation,details
    state.stage_record_present = False
    # Only these two metadata originals are admissible before protected Source material.
    original_rows = state.stage_metadata_rows
    old_attempt,old_permit = original_rows
    if old_attempt is not None:
        saved = json.loads(old_attempt[0])
        state.contact_issuer._signer.verify(SIGN_KIND,canonical_serialize((state.namespace,'stage_attempt',operation,old_attempt[1])),old_attempt[2])
        if canonical_digest(saved) != old_attempt[1] or any(saved[key] != details[key] for key in
                ('job_id','phase','request_digest','attempt_id','prepared_digest')):
            raise AuthorityUnavailable('Contact durable WRITE attempt differs from its exact original metadata')
        details = saved
        state.stage_details = saved
    else:
        if not state.graph._anchor_matches(metadata.requirements,anchor):
            raise AuthorityUnavailable('Contact new WRITE metadata and actual Core anchor differ')
        wire = canonical_serialize(details)
        validate_contact_payload_v2('stage_attempt',json.loads(wire))
        with state.store._lock:
            state.db.execute('BEGIN IMMEDIATE')
            try:
                require_contact_original_schema_v2(state.db)
                if state.graph._v2_graph_stamp(state.namespace) != state.graph_stamp:
                    raise AuthorityUnavailable('Contact WRITE attempt snapshot changed before durable metadata CAS')
                signed = canonical_digest(details)
                signature = state.contact_issuer._signer.sign(SIGN_KIND,canonical_serialize((state.namespace,'stage_attempt',operation,signed)))
                state.db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?)',
                    (*state.namespace.as_tuple,'stage_attempt',operation,wire,signed,signature))
                state.db.commit()
            except BaseException:
                state.db.rollback()
                raise
    if old_permit is None:
        if details['anchor'] != asdict(anchor) or (details['graph_revision'],details['graph_epoch']) != (metadata.graph_revision,epoch.revision):
            raise AuthorityUnavailable('Contact unresolved original WRITE attempt cannot replace its snapshot')
        permit = state.service.port.begin_fence(namespace=state.namespace,authority_namespace=policy.authority_namespace,
            holder=policy.administrator_holder,generation=anchor.activation_generation,operation='write',
            operation_id=details['attempt_id'],expected_anchor=anchor,retain_on_unknown=True)
        payload = {'schema':'d10.contact-stage-permit.v2','attempt_id':details['attempt_id'],'permit':to_wire(permit)}
        wire = canonical_serialize(payload)
        validate_contact_payload_v2('stage_permit',payload)
        with state.store._lock:
            state.db.execute('BEGIN IMMEDIATE')
            try:
                signed = canonical_digest(payload)
                signature = state.contact_issuer._signer.sign(SIGN_KIND,canonical_serialize((state.namespace,'stage_permit',operation,signed)))
                state.db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?)',
                    (*state.namespace.as_tuple,'stage_permit',operation,wire,signed,signature))
                state.db.commit()
            except BaseException:
                state.db.rollback()
                raise
        fence_state = 'active'
    else:
        payload = json.loads(old_permit[0])
        state.contact_issuer._signer.verify(SIGN_KIND,canonical_serialize((state.namespace,'stage_permit',operation,old_permit[1])),old_permit[2])
        if canonical_digest(payload) != old_permit[1] or payload['attempt_id'] != details['attempt_id']:
            raise AuthorityUnavailable('Contact original WRITE permit metadata differs')
        permit = from_wire(payload['permit'])
        actual,fence_state = state.service.port.get_fence_operation(namespace=state.namespace,
            authority_namespace=policy.authority_namespace,operation_id=details['attempt_id'])
        if actual != permit or fence_state not in {'active','finished'}:
            raise AuthorityUnavailable('Contact original WRITE permit was replaced or retired')
    scope = FenceScope(state.namespace,policy.authority_namespace,permit.generation,'write',details['attempt_id'],permit,
        permit.pinned_anchor,NamespaceEpoch(*state.namespace.as_tuple,details['graph_epoch']),details['graph_revision'])
    if not state.stage_receipt_metadata.absent:
        finish = 'sha256:'+canonical_digest(('d10.contact-stage-finish.v2',operation,digest,permit.token))
        if fence_state == 'active':
            state.service.port.finish_fence(scope,request_id='finish:'+details['attempt_id'],request_digest=finish)
        actual,finished = state.service.port.get_fence_operation(namespace=state.namespace,
            authority_namespace=policy.authority_namespace,operation_id=details['attempt_id'])
        if actual != permit or finished != 'finished':
            raise AuthorityUnavailable('Contact original COMMIT ACK was not durably finished')
        state.replay_operation = operation
        state.borrowed_scope = None
        return
    if fence_state != 'active' or state.service.port.validate_fence(scope) != permit:
        raise AuthorityUnavailable('Contact original WRITE without a receipt cannot be replaced')
    state.borrowed_scope = scope
    state.finish_identity = ('finish:'+details['attempt_id'],
        'sha256:'+canonical_digest(('d10.contact-stage-finish.v2',operation,digest,permit.token)))


def _observe_contact_host_current_v3(state):
    from ..runtime_contracts import AuthorityContext
    from ..graph_types import owner_grant_key,validate_owner_grant_v1
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from .first_ingress_v2 import trusted_upper
    from .domain_followup_consumer_v1 import _observe_owner
    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
    from contextlib import ExitStack
    service,graph = state.service,state.graph
    plan = state.contact_locator.plan_metadata
    if state.selector.stage == 'dispatch_text':
        from .contact_dispatch_host_read_v1 import open_contact_dispatch_text_authority_v1
        authority=open_contact_dispatch_text_authority_v1(state)
    elif state.selector.stage == 'joint_contact_preparation':
        from .contact_owner_command_source_v3 import _open_contact_owner_command_read_v3
        authority=_open_contact_owner_command_read_v3(state)
    else:
        owner_value = state.owner_point.json_columns['value'].require_v3(state)
        validate_owner_grant_v1(owner_value)
        principal = OwnerPrincipalV1(**owner_value['principal'])
        metadata,epoch = state.graph_stamp
        pairing = service.port.current_owner_principal_binding(namespace=state.namespace,
            authority_namespace=metadata.requirements.authority_namespace,principal=principal)
        if pairing is None:
            raise AuthorityUnavailable('Contact Host current Owner principal is not actually paired')
        authority = AuthorityContext(pairing.actor_id,'d11','contact-host:'+state.operation_id,state.namespace,
            ('activity','event','persona','scene'),'proposal',(plan['audience_id'],),
            service.port.installation_grant.publisher_policy_ref,metadata.requirements.activation_generation)
        if state.selector.stage in {'acquire','paid_cost','result_read','terminal','seal'}:
            _open_contact_host_write_scope_v3(state)
        if state.borrowed_scope is None:
            captured = []
            def observe(scope):
                current = _observe_owner(graph,authority,scope)
                captured.append(current)
                return current
            state.fence = graph._begin_read_fence_v3(authority,operation_id=state.operation_id,fence_observer=observe)
            state.scope = state.fence.scope
            state.owner = captured[0][1]
            state.owner_guard = captured[0][0]
        else:
            scope = state.borrowed_scope
            if scope.operation != 'write' or scope.namespace != state.namespace or service.port.validate_fence(scope) != scope.permit:
                raise AuthorityUnavailable('Contact stage cannot borrow a sealed READ to authorize WRITE')
            guard,owner = _observe_owner(graph,authority,scope)
            state.scope,state.owner_guard,state.owner = scope,guard,owner
            state.fence = ContactHostIssuedScopeV3(scope,metadata,epoch,service).require_for_v3(state)
    if (state.fence.metadata,state.fence.epoch) != state.graph_stamp:
        raise AuthorityUnavailable('Contact Host actual fence changed its metadata birth snapshot')
    state.now_utc = trusted_upper(service.port.read_ingress_clock(service.bundle.ingress_clock))
    policy_refs = [row for row in state.contact_locator.versions.values()
        if AtomKey.from_token(row['key']).type_name == 'd10.contact_policy.v1' and row['revision'] > 0]
    if not policy_refs:
        raise AuthorityUnavailable('Contact Host signed Plan has no actual standing-policy locator')
    state.policy_refs = tuple(policy_refs)
    state.authority = authority
    state.phase = 'namespace'
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    from ..domains.d08.contact_plan_v2 import CURRENT_TYPES as PLAN_CURRENT_TYPES
    state._initialize_storage_kernel_v3(state.operation,state.fence,namespace=state.namespace,graph_stamp=state.graph_stamp,
        catalogue_hash=state.store._registry.catalogue_hash,projection_types=(frozenset(CONTACT_CURRENT_TYPES)|PLAN_CURRENT_TYPES)-{'memory.source'},
        selected_tokens=frozenset(),census_schema='sylanne.contact-host-full-inventory.v3',
        leaf_schema='sylanne.contact-host-full-inventory-leaf.v3')
    state.phase = 'namespace'


def _observe_contact_host_policy_v3(state):
    from contextlib import ExitStack
    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
    from .first_ingress_v2 import trusted_upper
    from .domain_followup_consumer_v1 import _observe_owner
    if state.db.in_transaction:
        raise AuthorityUnavailable('Contact Host policy observation must occur outside Graph SQL')
    state.service.port.validate_fence(state.scope)
    if state.selector.stage == 'dispatch_text':
        from .contact_dispatch_host_read_v1 import observe_contact_dispatch_text_owner_v1
        guard,owner=observe_contact_dispatch_text_owner_v1(state)
    elif state.selector.stage == 'joint_contact_preparation':
        from .contact_owner_command_source_v3 import observe_contact_owner_command_read_v3
        guard,owner = observe_contact_owner_command_read_v3(state)
    else:
        guard,owner = _observe_owner(state.graph,state.authority,state.scope)
    if (guard,owner) != (state.owner_guard,state.owner):
        raise AuthorityUnavailable('Contact Host actual Owner changed during Source preparation')
    matched = [atom for atom in state.atoms if atom.key.type_name == 'd10.contact_policy.v1'
        and atom.valid and atom.value['approval_ref'] == state.contact_locator.values[('plan','policy_original_ref')]]
    if len(matched) != 1:
        raise AuthorityUnavailable('Contact Host actual signed standing policy is not uniquely current')
    if state.policy_lifetime is not None:
        state.policy_lifetime.close()
    lifetime = ExitStack()
    issued = lifetime.enter_context(read_installed_current_contact_policy_v1(
        state.graph._GraphCoordinator__c04_authority_port_v3,state.scope,matched[0].value['policy_id']))
    if issued is None or issued.original.digest != state.contact_locator.values[('plan','policy_original_digest')]:
        lifetime.close()
        raise AuthorityUnavailable('Contact Host current Owner standing policy differs from signed Plan')
    if state.selector.stage=='dispatch_text'and (not issued.original.policy.consent or issued.original.policy.quiet):
        lifetime.close()
        raise AuthorityUnavailable('Contact current Owner standing policy refuses proactive expression')
    state.policy_lifetime,state.current_policy,state.contact_policy = lifetime,issued,issued.original
    state.now_utc = trusted_upper(state.service.port.read_ingress_clock(state.service.bundle.ingress_clock))
    deadline = min(state.contact_locator.values[('plan','valid_until_utc')],issued.original.policy.window_end,
        state.parent_deadline,*state.job_deadlines)
    if state.operation.deadline_utc is not None:
        deadline = min(deadline,state.operation.deadline_utc)
    if state.now_utc >= deadline:
        raise AuthorityUnavailable('Contact Host original Plan/policy deadline expired')
    state.operation.deadline_utc = state.work.deadline_utc = float(deadline)


def advance_contact_host_stage_work_v3(graph,work):
    state = require_contact_host_work_v3(work.state)
    if state.graph is not graph:
        raise AuthorityUnavailable('Contact Host Work belongs to another installed Graph')
    from .contact_dispatch_host_read_v1 import ContactDispatchIdentitySelectorV3,advance_contact_dispatch_identity_work_v3
    if type(state.selector)is ContactDispatchIdentitySelectorV3:
        return advance_contact_dispatch_identity_work_v3(graph,work)
    with bind_runtime_storage_operation_v3(state.operation,state.db):
        if state.phase=='dispatch_text_deadline':
            from .contact_dispatch_host_read_v1 import finish_contact_dispatch_text_locator_v1
            finish_contact_dispatch_text_locator_v1(state)
            state.phase='plan_locator'
            return GraphStorageStepV3('progress')
        if state.phase == 'authorize':
            _observe_contact_host_current_v3(state)
            return GraphStorageStepV3('progress')
        if state.phase == 'policy':
            _observe_contact_host_policy_v3(state)
            state.phase = 'source'
            return GraphStorageStepV3('progress')
        if state.phase == 'protected':
            _observe_contact_host_policy_v3(state)
            if state.selector.stage in {'acquire','paid_cost','result_read','terminal','seal'} and not hasattr(state,'replay_operation'):
                state.phase = 'commit'
                return GraphStorageStepV3('progress')
            state.complete = True
            return GraphStorageStepV3('complete',state)
        if state.phase == 'commit':
            return _commit_contact_host_stage_v3(state)
        if state.scope is not None:
            state.service.port.validate_fence(state.scope)
        with state.store._lock,runtime_storage_quantum_v3(state.db) as meter,bind_contact_host_originals_v3(state):
            state.db.execute('BEGIN')
            try:
                state.require_current(meter=meter)
                if state.attachment_pending is not None:
                    state.attachment_pending.advance(meter)
                    if state.attachment_pending.complete:
                        state.attachments[state.attachment_pending.request] = state.attachment_pending
                        state.attachment_pending = None
                elif state.phase=='dispatch_text_locator':
                    state.dispatch_text_locator.advance(meter)
                    if state.dispatch_text_locator.complete:
                        state.phase='dispatch_text_deadline'
                elif state.phase == 'plan_locator':
                    state.contact_locator.advance(meter)
                    if state.contact_locator.complete:
                        state.prepared_locator = ContactHostPreparedMetadataReadV3(state,
                            'contact_generation'if state.selector.stage=='dispatch_text'else None)
                        state.phase = 'prepared_locator'
                elif state.phase == 'prepared_locator':
                    state.prepared_locator.advance(meter)
                    if state.prepared_locator.complete:
                        actual = dict(state.contact_locator.protected_history)
                        if state.contact_locator.original_sign_kind == 'd10.contact-expression-plan-original.v3':
                            actual = {row['key']:row['revision'] for row in state.contact_locator.versions.values()
                                if AtomKey.from_token(row['key']).type_name == 'memory.source' and row['revision']>0}
                        for ref,revision in (() if state.prepared_locator.values is None else state.prepared_locator.frozen.sources):
                            if ref not in actual or actual[ref] != revision:
                                raise AuthorityUnavailable('Contact Host frozen protected Source escapes its signed Plan closure')
                        if state.selector.stage in {'background_item','dispatch_text'} and state.prepared_locator.model_phase == 'contact_generation':
                            state.generation_metadata = state.prepared_locator
                            state.prepared_locator = ContactHostPreparedMetadataReadV3(state,'contact_review')
                        else:
                            state.phase = 'job_metadata'
                elif state.phase == 'job_metadata':
                    readers = tuple(reader for reader in (getattr(state,'generation_metadata',None),state.prepared_locator)
                        if reader is not None and reader.values is not None)
                    try:
                        rows = tuple(contact_host_original_point_v3(state.db,table='runtime_jobs',
                            columns=('job_id','operation_id','activity_id','bot_id','persona_id','work_kind','phase','deadline_utc','lease_expires_utc','budget_ref'),
                            key_columns=('job_id',),key=(reader.ids['job'],))[1] for reader in readers)
                    except AuthorityGraphAttachmentRequiredV3 as needed:
                        state.attachment_pending = _contact_host_attachment_v3(state,needed.request)
                    else:
                        if any(row is None or (row[3],row[4])!=state.namespace.as_tuple or row[0]!=reader.ids['job']
                                or row[1]!=reader.values[('prepare_operation_id',)] or row[2]!=state.contact_locator.plan_metadata['activity_id']
                                or row[5]!=reader.model_phase or row[9]!=state.contact_locator.plan_metadata['parent_budget_lease_id']
                                for row,reader in zip(rows,readers)):
                            raise AuthorityUnavailable('Contact Host actual job metadata crossed its original Plan/phase/parent')
                        from datetime import datetime
                        # Completed paid originals prove an earlier call. Its expired running deadline
                        # cannot become a permanent ban on inspecting the same paid effect.
                        active_stages={'preparation','acquire','egress','seal'}
                        state.job_deadlines = tuple(datetime.fromisoformat(row[7].replace('Z','+00:00')).timestamp()
                            for row in rows if row[6]!='completed' or state.selector.stage in active_stages)
                        if state.selector.stage in {'egress','seal'}:
                            if len(rows)!=1 or rows[0][6]!='running' or rows[0][8] is None:
                                raise AuthorityUnavailable('Contact Host model send requires its actual current running lease')
                            state.job_deadlines += (datetime.fromisoformat(rows[0][8].replace('Z','+00:00')).timestamp(),)
                        state.phase = 'parent_metadata'
                elif state.phase == 'parent_metadata':
                    plan = state.contact_locator.plan_metadata
                    with runtime_storage_quantum_v3(state.db) as current_meter:
                        current = current_meter.read_fixed_row(state.db,'runtime_budget_grants',('version','status'),
                            'lease_id=? AND version=(SELECT MAX(version) FROM runtime_budget_grants WHERE lease_id=?)',
                            (plan['parent_budget_lease_id'],plan['parent_budget_lease_id']))
                    if current != (plan['budget_grant_version'],'active'):
                        raise AuthorityUnavailable('Contact Host original parent grant is no longer current and active')
                    try:
                        _,row = contact_host_original_point_v3(state.db,table='runtime_budget_grants',columns=('grant_json','signature'),
                            key_columns=('lease_id','version'),key=(plan['parent_budget_lease_id'],plan['budget_grant_version']))
                    except AuthorityGraphAttachmentRequiredV3 as needed:
                        state.attachment_pending = _contact_host_attachment_v3(state,needed.request)
                    else:
                        from .issuers import _decode_grant
                        if row is None:
                            raise AuthorityUnavailable('Contact Host parent grant actual signed original is absent')
                        state.contact_issuer._signer.verify('budget-grant.v1',row[0],row[1])
                        grant = _decode_grant(row[0])
                        if grant != state.service.bundle.installation_policy.root_grant or canonical_digest(grant)!=plan['budget_grant_digest']:
                            raise AuthorityUnavailable('Contact Host cannot substitute another parent grant or budget version')
                        state.parent_deadline = grant.valid_until_utc
                        state.phase = ('stage_metadata' if state.selector.stage in {'acquire','paid_cost','result_read','terminal','seal'}
                            else 'authorize' if state.selector.stage == 'joint_contact_preparation' else 'owner_locator')
                elif state.phase == 'stage_metadata':
                    from .contact_paid_original_v2 import TABLE
                    values = state.prepared_locator.values
                    stage = state.selector.stage
                    operation = (values[('acquire_operation_id',)] if stage == 'acquire' else
                        'contact-'+stage+':'+canonical_digest((state.namespace,values[('job_id',)],stage))[:48])
                    if stage == 'result_read':
                        operation += ':'+str(state.selector.result_attempt)
                    try:
                        rows = tuple(contact_host_original_point_v3(state.db,table=TABLE,
                            columns=('payload_json','payload_digest','signature'),key_columns=('bot','persona','kind','original_ref'),
                            key=(*state.namespace.as_tuple,kind,operation))[1] for kind in ('stage_attempt','stage_permit'))
                    except Exception as error:
                        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
                        if type(error) is not AuthorityGraphAttachmentRequiredV3:
                            raise
                        from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
                        state.attachment_pending = _contact_host_attachment_v3(state,error.request)
                    else:
                        state.stage_metadata_rows = rows
                        state.stage_receipt_metadata = ContactHostReceiptMetadataEOFV3(state,operation)
                        state.phase = 'stage_receipt_metadata'
                elif state.phase == 'stage_receipt_metadata':
                    state.stage_receipt_metadata.advance(meter)
                    if state.stage_receipt_metadata.complete:
                        state.phase = 'owner_locator'
                elif state.phase == 'owner_locator':
                    from ..graph_types import owner_grant_key
                    from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
                    request = ('graph_atoms',('revision','value','valid'),('token','bot','persona'),
                        (owner_grant_key(*state.namespace.as_tuple).token,*state.namespace.as_tuple))
                    state.owner_point = state.attachments.get(request)
                    if state.owner_point is None:
                        state.attachment_pending = _HostProducerAttachmentV3(state,request)
                    else:
                        state.phase = 'authorize'
                elif state.phase == 'namespace':
                    if state.authority_epochs is None:
                        state.authority_epochs = state._epochs(meter)
                    if state.cell is None:
                        state._next(meter)
                    else:
                        state._cell(meter)
                    if state.graph_eof:
                        state.phase = 'policy'
                elif state.phase == 'source':
                    if state.source_reader is None:
                        state.source_reader = ContactHostSourceMaterialReadV3(state)
                    state.source_reader.advance_v3(meter)
                    if state.source_reader.complete:
                        state.source_material = state.source_reader.proof
                        state.phase = 'semantic'
                elif state.phase == 'semantic':
                    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
                    try:
                        state.result = state.service._read_contact_host_stage_data_v3(state)
                    except AuthorityGraphAttachmentRequiredV3 as needed:
                        from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
                        state.attachment_pending = _contact_host_attachment_v3(state,needed.request)
                    else:
                        state.phase = 'protected'
                else:
                    raise AuthorityUnavailable('Contact Host fixed Work phase is unregistered')
            finally:
                state.db.rollback()
        if state.scope is not None:
            state.service.port.validate_fence(state.scope)
    return GraphStorageStepV3('progress')


def finish_contact_host_stage_work_v3(graph,work,error):
    state = work.state
    try:
        if state.scope is not None and state.borrowed_scope is None:
            graph._finish_read_fence_v3(state.fence)
        if state.policy_lifetime is not None:
            state.policy_lifetime.close()
            state.policy_lifetime = None
        if error is None:
            work.result_lease = state.operation
    except BaseException:
        state.release_payload_v3()
        finish_runtime_storage_operation_v3(state.operation)
        raise
    if error is not None:
        state.release_payload_v3()
        finish_runtime_storage_operation_v3(state.operation)


def _commit_contact_host_stage_v3(state):
    from contextlib import nullcontext
    from .contact_graph_runtime_v2 import _ContactStageWitnessV2,_ACTIVE
    from .contact_paid_original_v2 import record_contact_original_v2
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    _observe_contact_host_policy_v3(state)
    service,db = state.service,state.db
    actual,permit = service.port.get_current_background_owner_authority_for_fence_v1(namespace=state.namespace,
        authority_namespace=service.bundle.installation_policy.authority_namespace,permit=state.scope.permit)
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    if type(actual) is not D12CurrentOwnerAuthorityV1 or permit != state.scope.permit or actual.guard != state.owner_guard:
        raise AuthorityUnavailable('Contact WRITE lost its actual current Owner before COMMIT')
    witness = _ContactStageWitnessV2(service,state.scope,actual,state.prepared,state.selector.stage,state.stage_operation,state.now_utc,
        state.seal_intent if state.selector.stage == 'seal' else None)
    reader = state.graph._GraphCoordinator__d04_semantic_mapping_reader
    with (reader.current_fence(state.scope) if reader is not None else nullcontext()):
        with state.store._lock,runtime_storage_quantum_v3(db) as meter,bind_contact_host_originals_v3(state):
            db.execute('BEGIN IMMEDIATE')
            try:
                state.require_current(meter=meter)
                state.graph._scene_binding_state_locked(state.namespace,actual.guard)
                value = service._original(db,state.selector.contact_id,state.selector.model_phase)
                service._content(db,value,state.now_utc,actual.guard)
                _ACTIVE[id(witness)] = witness
                result = service._apply(db,witness,value,*state.graph_stamp,state.selector.result_attempt)
                record_contact_original_v2(db,state.contact_issuer,state.namespace,'stage_receipt',state.stage_operation,
                    {'schema':'d10.contact-stage-receipt.v2','prepared_digest':value[0].digest,
                        'operation_id':state.stage_operation,'attempt_id':state.stage_details['attempt_id'],'result':plain_v1(result)})
                db.commit()
            except AuthorityGraphAttachmentRequiredV3 as needed:
                db.rollback()
                from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
                state.attachment_pending = _HostProducerAttachmentV3(state,needed.request)
                state.phase = 'semantic'
                return GraphStorageStepV3('progress')
            except BaseException:
                db.rollback()
                raise
            finally:
                _ACTIVE.pop(id(witness),None)
    service.port.finish_fence(state.scope,request_id=state.finish_identity[0],request_digest=state.finish_identity[1])
    state.result,state.complete = plain_v1(result),True
    return GraphStorageStepV3('complete',state)


def _contact_host_attachment_v3(state,request):
    if request[0] == 'graph_dependencies' and len(request)==5:
        if (request[1],request[2],request[4]) != (('dependency_token','dependency_revision'),('dependent_token',),'dependency_token'):
            raise AuthorityUnavailable('Contact Host dependency scan has another fixed recipe')
        from .natural_producer_qualification_v1 import _HostProducerMetadataScanV3
        return _HostProducerMetadataScanV3(state,request)
    if request[0] == 'contact_plan_physical_payload':
        from .contact_original_read_v3 import ContactPlanPhysicalPayloadReadV3
        return ContactPlanPhysicalPayloadReadV3(state,request)
    if request[0] == 'contact_payload_commitment':
        from .contact_original_read_v3 import ContactPayloadCommitmentEOFV3
        return ContactPayloadCommitmentEOFV3(state,request)
    if request[0] == 'contact_historical_inventory':
        from .contact_original_read_v3 import ContactHistoricalInventoryReadV3
        return ContactHistoricalInventoryReadV3(state,request)
    from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
    return _HostProducerAttachmentV3(state,request)
