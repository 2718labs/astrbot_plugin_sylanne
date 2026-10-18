"""Private ordinary-work full census with a fixed, independently scoped projection."""
from contextlib import ExitStack,asynccontextmanager,contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary
import math
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,owner_grant_key
from ..runtime_contracts import QueryEpoch
from ..graph_worker import GraphStorageStepV3,OwnedGraphStorageResultV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,runtime_storage_v3
from ..domains.d08.natural_plan import NATURAL_PLAN_TYPE_V2
from .dispatch_current_inventory_v3 import (_CurrentNamespaceInventoryKernelV3,_DISPATCH_TYPES,_RUNTIME_JOB_TYPE_V3,
    _FrozenDispatchAtomV3,_freeze_value_v3,_detach_value_v3,_heap,_SOURCE_ISSUED)

CURRENT_DISPATCH_FAMILY_V3='current_dispatch_v3'
NATURAL_PLAN_FAMILY_V3='natural_plan_v2'
SOURCE_METADATA_FAMILY_V3='source_metadata_v3'
RUNTIME_JOB_FAMILY_V3='runtime_job_v3'
ARTIFACT_RECEIPT_CONTROL_FAMILY_V1='artifact_receipt_control_v1'
_FAMILIES=MappingProxyType({CURRENT_DISPATCH_FAMILY_V3:_DISPATCH_TYPES,NATURAL_PLAN_FAMILY_V3:frozenset({NATURAL_PLAN_TYPE_V2}),
    SOURCE_METADATA_FAMILY_V3:frozenset({'memory.source'}),RUNTIME_JOB_FAMILY_V3:frozenset({_RUNTIME_JOB_TYPE_V3}),
    ARTIFACT_RECEIPT_CONTROL_FAMILY_V1:frozenset({'d09.verified_segment_batch.v1','d08.communication_intent_grant.v1'})})
_ISSUER=object()
_ISSUED=WeakKeyDictionary()
_PREFINAL_ISSUED=WeakKeyDictionary()
_WRITE_VIEW_ISSUED=WeakKeyDictionary()
_BOUND=ContextVar('sylanne_current_graph_full_read_v3',default=None)


@dataclass(frozen=True)
class _FixedReadContractV3:
    name:str
    domains:frozenset
    families:frozenset
    owner_read:bool=False
    borrowed_scope:bool=False

_ALL_FAMILIES=frozenset(_FAMILIES)-frozenset({ARTIFACT_RECEIPT_CONTROL_FAMILY_V1})
NATURAL_MODEL_FULL_READ_V3=_FixedReadContractV3('natural_model_full_read_v3',frozenset({'d11'}),_ALL_FAMILIES)
NATURAL_ROUTE_FULL_READ_V3=_FixedReadContractV3('natural_route_full_read_v3',frozenset({'d08','d09','d11'}),_ALL_FAMILIES)
PRIVATE_REPLY_ROUTE_FULL_READ_V3=_FixedReadContractV3('private_reply_route_full_read_v3',frozenset({'d08','d09','d11'}),_ALL_FAMILIES)
NATURAL_ADMIN_PREPARE_FULL_V3=_FixedReadContractV3('natural_admin_prepare_full_v3',frozenset(),_ALL_FAMILIES,borrowed_scope=True)
ARTIFACT_RECEIPT_FULL_READ_V1=_FixedReadContractV3('artifact_receipt_full_read_v1',frozenset({'d08','d09','d11'}),_ALL_FAMILIES|frozenset({ARTIFACT_RECEIPT_CONTROL_FAMILY_V1}))
_CONTRACTS=MappingProxyType({entry.name:entry for entry in (NATURAL_MODEL_FULL_READ_V3,NATURAL_ROUTE_FULL_READ_V3,
    PRIVATE_REPLY_ROUTE_FULL_READ_V3,NATURAL_ADMIN_PREPARE_FULL_V3,ARTIFACT_RECEIPT_FULL_READ_V1)})


def _contract_v3(value):
    if type(value)is not _FixedReadContractV3 or _CONTRACTS.get(value.name)is not value:
        raise AuthorityUnavailable('actual fixed ordinary full-read contract required')
    return value


def _deadline_v3(value):
    if value is not None and (type(value)not in(int,float)or not math.isfinite(value)):
        raise ValueError('ordinary full-read uses its original finite deadline or None')
    return value


@dataclass(frozen=True)
class _FullCensusCoverageV3:
    namespace:object
    query:object
    leaf_count:int
    ordered_root:str
    full_eof:bool


@dataclass(frozen=True,init=False)
class _FixedTypedProjectionV3:
    _types:frozenset
    _operation:object
    _atoms:tuple
    epochs:tuple
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER:raise TypeError('actual fixed full-read projection issuer required')
        object.__setattr__(self,'_types',reader.projection_types)
        object.__setattr__(self,'_operation',reader.operation)
        object.__setattr__(self,'_atoms',tuple(_FrozenDispatchAtomV3(atom.key,atom.revision,_freeze_value_v3(atom.value),atom.valid,_heap(atom.value))for atom in reader.atoms))
        object.__setattr__(self,'epochs',(reader.graph_stamp[1],))
    def _view(self,atom):
        self._operation.retain(atom.retained_bytes*4+512)
        from ..graph_types import GraphAtom
        return GraphAtom(atom.key,atom.revision,_detach_value_v3(atom.value),atom.valid)
    @property
    def atoms(self):
        self._operation.retain(256+len(self._atoms)*16)
        return tuple(self._view(atom)for atom in self._atoms)
    def get(self,key):
        if key.type_name not in self._types:raise AuthorityUnavailable('ordinary projection family was not prepared')
        if key.type_name=='memory.source':raise AuthorityUnavailable('Source material needs its original rights-scoped reader')
        atom=next((atom for atom in self._atoms if atom.key==key),None)
        return None if atom is None else self._view(atom)
    def atoms_for_types_v3(self,types):
        if not set(types)<=self._types:raise AuthorityUnavailable('ordinary projection family was not prepared')
        if 'memory.source'in types:raise AuthorityUnavailable('Source material needs its original rights-scoped reader')
        self._operation.retain(256+len(self._atoms)*16)
        return tuple(self._view(atom)for atom in self._atoms if atom.key.type_name in types)


@dataclass(frozen=True)
class _CurrentSourceEntryLocatorV3:
    c02_operation_id:object
    source_ref:object


class _PrefinalSourceInventoryV3:
    """Actual census EOF for a same-Work Source reader; never a final FULL proof."""
    def __init__(self,issuer,reader):
        if (issuer is not _ISSUER or type(reader)is not _OrdinaryFullReadV3
                or not reader.graph_eof or reader.complete or reader.source_locator is None):
            raise TypeError('actual same-Work prefinal Source census required')
        self.reader=reader
        self.graph,self.db,self.namespace=reader.graph,reader.db,reader.namespace
        self.work,self.operation,self.scope=reader.work,reader.operation,reader.fence.scope
        self.graph_stamp,self.query=reader.graph_stamp,reader.query
        self.selection_digest,self.catalogue_hash=reader.selection_digest,reader.catalogue_hash
        self.prepared_families=reader.contract.families
        self.authority_epochs,self.owner_head=reader.authority_epochs,reader.owner_head
        self.actual_entry=reader.source_locator
        self.projection=_FixedTypedProjectionV3(_ISSUER,reader)
        self.sources,self.heads=MappingProxyType(dict(reader.sources)),MappingProxyType(dict(reader.heads))
        self.coverage=_FullCensusCoverageV3(reader.namespace,reader.query,reader.count,reader.root,True)
        _PREFINAL_ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.reader,self.graph,self.db,self.namespace,self.work,self.operation,self.scope,self.graph_stamp,self.query,
            self.selection_digest,self.catalogue_hash,self.prepared_families,self.authority_epochs,self.owner_head,
            self.actual_entry,self.projection,(self.projection._types,self.projection._atoms,self.projection.epochs),
            self.sources,self.heads,self.coverage)
    def _actual(self):
        expected=_PREFINAL_ISSUED.get(self)
        if (expected is None or expected!=self._identity_v3()or self.operation.closed
                or self.work.state is not self.reader or self.reader.work is not self.work
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph
                or not self.reader.graph_eof or not self.coverage.full_eof):
            raise AuthorityUnavailable('actual prefinal same-Work Source inventory differs')
    def require_current(self,*,meter=None):
        self._actual();store=self.graph._GraphCoordinator__store
        if (not store._lock._is_owned()or runtime_storage_v3(self.db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest
                or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp
                or store._registry.catalogue_hash!=self.catalogue_hash):
            raise AuthorityUnavailable('prefinal Source census selection/query/stamp changed')
        with runtime_storage_quantum_v3(self.db)as current:
            if meter is not None and current is not meter:raise AuthorityUnavailable('prefinal Source reader changed its actual quantum')
            epochs=current.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
                'bot=? AND persona=?',self.namespace.as_tuple)
            owner=current.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,owner_grant_key(*self.namespace.as_tuple).token))
        if epochs!=self.authority_epochs or owner!=self.owner_head:
            raise AuthorityUnavailable('prefinal Source access/deletion/Owner original changed')
        return self
    def source_metadata(self,db,namespace,query,key,*,revision=None,require_grant=False,meter=None):
        if require_grant:raise AuthorityUnavailable('prefinal Source metadata is not a purpose/audience grant')
        self.require_current(meter=meter)
        if db is not self.db or namespace!=self.namespace or query!=self.query:
            raise AuthorityUnavailable('prefinal Source metadata belongs to another inventory')
        source=self.sources.get(key.token)
        actual=None if source is None else (db,source.source_key,source.revision,source.valid,source.cell_id,source.header,
            source.payload_sha256,source.metadata,source.scope,source.graph_stamp,source.query,source.operation_id,source.selection_digest)
        if (source is None or _SOURCE_ISSUED.get(source)!=actual or source.source_key!=key or source.scope is not self.scope
                or source.graph_stamp!=self.graph_stamp or source.query!=self.query
                or source.operation_id!=self.operation.operation_id or revision is not None and source.revision!=revision):
            raise AuthorityUnavailable('prefinal Source metadata lacks its actual complete EOF original')
        with runtime_storage_quantum_v3(db)as current:
            head=current.read_fixed_row(db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token))
        if head is None or tuple(head)!=(source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('prefinal Source head differs from its complete cell')
        return source
    def correction_head(self,db,namespace,query,key,*,meter=None):
        self.require_current(meter=meter)
        if (db is not self.db or namespace!=self.namespace or query!=self.query
                or key.type_name!='d06.source_correction_head.v1'
                or(key.owner.bot,key.owner.persona)!=namespace.as_tuple):
            raise AuthorityUnavailable('prefinal correction head scope differs')
        with runtime_storage_quantum_v3(db)as current:
            head=current.read_fixed_row(db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token))
        expected=self.heads.get(key.token)
        if head is None:
            if expected is not None:raise AuthorityUnavailable('prefinal correction head disappeared')
            return None
        if expected is None or tuple(head)!=expected:raise AuthorityUnavailable('prefinal correction head changed')
        return self.projection.get(key)
    def release_payload_v3(self):
        _PREFINAL_ISSUED.pop(self,None)
        self.projection=self.sources=self.heads=None


class PreparedCurrentGraphFullReadV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.graph_eof or not reader.complete or reader.work is None:
            raise TypeError('actual complete ordinary full-read Work required')
        self.graph,self.db,self.namespace=reader.graph,reader.db,reader.namespace
        self.work,self.ticket,self.operation=reader.work,reader.work.ticket,reader.operation
        self.contract,self.scope,self.graph_stamp=reader.contract,reader.fence.scope,reader.graph_stamp
        self.query,self.selection_digest,self.catalogue_hash=reader.query,reader.selection_digest,reader.catalogue_hash
        self.authority_epochs,self.owner_head=reader.authority_epochs,reader.owner_head
        self.prepared_families=reader.contract.families
        self.coverage=_FullCensusCoverageV3(reader.namespace,reader.query,reader.count,reader.root,True)
        self.artifact_receipt_originals=reader.artifact_receipt_originals
        self.receipt_operation_id=reader.receipt_operation_id
        self.prefinal=reader.prefinal
        self.prepared_producer_members,self.producer_frame=reader.prepared_producer_members,reader.producer_frame
        if self.prepared_producer_members is not None:
            from .natural_producer_qualification_v1 import require_prepared_host_natural_producers_v3
            require_prepared_host_natural_producers_v3(self.prepared_producer_members,reader=reader,scope=reader.fence.scope)
        self.source_material=None if reader.source_material is None else reader.source_material.proof
        if self.source_material is not None:
            from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
            require_prepared_current_source_material_v3(self.source_material,prefinal_inventory=self.prefinal,
                actual_entry=self.prefinal.actual_entry)
        self.projection=_FixedTypedProjectionV3(_ISSUER,reader)if self.prefinal is None else self.prefinal.projection
        self.sources=MappingProxyType(dict(reader.sources))
        self.heads=MappingProxyType(dict(reader.heads))
        _ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.graph,self.db,self.namespace,self.work,self.ticket,self.operation,self.contract,self.scope,self.graph_stamp,
            self.query,self.selection_digest,self.catalogue_hash,self.authority_epochs,self.owner_head,self.prepared_families,
            self.coverage,self.projection,(self.projection._types,self.projection._operation,self.projection._atoms,self.projection.epochs),self.sources,self.heads,self.prefinal,self.source_material,self.prepared_producer_members,self.producer_frame,self.artifact_receipt_originals,self.receipt_operation_id)
    def _actual(self):
        issued=_ISSUED.get(self)
        if issued is None:raise AuthorityUnavailable('ordinary full-read proof was not issued or has been released')
        if (issued!=self._identity_v3()or self.operation.closed or not self.coverage.full_eof
                or self.work.coordinator is not self.graph or self.work.ticket!=self.ticket
                or self.work.operation is not self.operation):
            raise AuthorityUnavailable('actual private originating full-read Work/EOF/retention changed')
        _contract_v3(self.contract)
        if self.prefinal is not None:self.prefinal._actual()
        if self.prepared_producer_members is not None:
            from .natural_producer_qualification_v1 import require_prepared_host_natural_producers_v3
            require_prepared_host_natural_producers_v3(self.prepared_producer_members,reader=self.work.state,scope=self.scope)
        if self.source_material is not None:
            from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
            require_prepared_current_source_material_v3(self.source_material,prefinal_inventory=self.prefinal,
                actual_entry=self.prefinal.actual_entry)
    def require_current(self,graph,db,namespace,*,required_families):
        self._actual();bound=_BOUND.get()
        if bound is None or bound!=(self,graph,db,self.work,self.operation):
            raise AuthorityUnavailable('actual active ordinary full-read Binder required')
        if not set(required_families)<=self.prepared_families:
            raise AuthorityUnavailable('requested ordinary family was not prepared')
        store=graph._GraphCoordinator__store
        if (graph is not self.graph or db is not self.db or namespace!=self.namespace or not db.in_transaction
                or not store._lock._is_owned()or runtime_storage_v3(db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest or graph._v2_graph_stamp(namespace)!=self.graph_stamp
                or store._registry.catalogue_hash!=self.catalogue_hash):
            raise AuthorityUnavailable('ordinary full-read selection/query/stamp/catalogue changed')
        epochs=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',namespace.as_tuple).fetchone()
        owner=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,owner_grant_key(*namespace.as_tuple).token)).fetchone()
        if epochs!=self.authority_epochs or owner!=self.owner_head:
            raise AuthorityUnavailable('ordinary full-read Source/Owner heads changed')
        return self.projection,self.query
    def source_metadata(self,graph,db,namespace,key,*,revision=None):
        self.require_current(graph,db,namespace,required_families=frozenset({SOURCE_METADATA_FAMILY_V3}))
        source=self.sources.get(key.token)
        actual=None if source is None else (db,source.source_key,source.revision,source.valid,source.cell_id,source.header,
            source.payload_sha256,source.metadata,source.scope,source.graph_stamp,source.query,source.operation_id,source.selection_digest)
        if (source is None or _SOURCE_ISSUED.get(source)!=actual or source.source_key!=key or source.scope is not self.scope
                or source.graph_stamp!=self.graph_stamp or source.query!=self.query
                or source.operation_id!=self.operation.operation_id or revision is not None and source.revision!=revision):
            raise AuthorityUnavailable('actual ordinary fulltyped Source metadata witness differs')
        head=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,key.token)).fetchone()
        if head is None or tuple(head)!=(source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('ordinary Source head differs from its full-EOF metadata witness')
        return source
    def release_payload_v3(self):
        if _ISSUED.pop(self,None)is None:return
        if self.prepared_producer_members is not None:
            from .natural_producer_qualification_v1 import release_host_natural_producer_payload_v3
            release_host_natural_producer_payload_v3(self.prepared_producer_members.c04_decoder_owner)
        if self.prefinal is not None:self.prefinal.release_payload_v3()
        self.projection=self.sources=self.heads=self.prefinal=self.source_material=None
        self.work.state.prepared_producer_members=self.work.state.producer_frame=None
        self.work.state.prefinal=None
        self.prepared_producer_members=self.producer_frame=None


class _OrdinaryFullReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,graph,operation,fence,contract,*,authority=None,lease=None,borrowed=None,source_locator=None,request_lifetime=None):
        self.contract,self.authority,self.lease,self.borrowed=contract,authority,lease,borrowed
        self.work,self.owner_head=None,None
        self.artifact_receipt_task,self.artifact_receipt_originals=None,None
        self.receipt_operation_id=None
        self.source_locator,self.request_lifetime=source_locator,request_lifetime
        self.producer_phase=None if source_locator is None or contract in (PRIVATE_REPLY_ROUTE_FULL_READ_V3,ARTIFACT_RECEIPT_FULL_READ_V1) else('prepare'if borrowed is not None else'frozen')
        self.prefinal,self.source_material=None,None
        self.producer_progress,self.prepared_producer_members,self.producer_frame=None,None,None
        types=frozenset().union(*(_FAMILIES[name]for name in contract.families))
        super().__init__(graph,operation,fence,projection_types=types,selected_tokens=frozenset(),
            census_schema='sylanne.current-graph-full-inventory.v3',leaf_schema='sylanne.current-graph-full-inventory-leaf.v3')
    def _require_source_roots_v3(self,roots,purpose,audiences):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        if self.contract is not ARTIFACT_RECEIPT_FULL_READ_V1:
            raise AuthorityUnavailable('Artifact original family belongs to its dedicated full-read contract')
        return _DispatchInventoryReadV3._require_source_roots_v3(self,roots,purpose,audiences)

    def _graph_eof_v3(self):pass
    def advance(self):
        candidate=None;producer_candidate=False
        with bind_runtime_storage_operation_v3(self.operation,self.db),runtime_storage_quantum_v3(self.db)as meter:
            if self.authority_epochs is None:
                self.authority_epochs=self._epochs(meter)
                self.owner_head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,owner_grant_key(*self.namespace.as_tuple).token))
            elif self.graph_eof:
                if self.contract is ARTIFACT_RECEIPT_FULL_READ_V1 and self.artifact_receipt_originals is None:
                    from .artifact_receipt_original_read_v1 import ArtifactReceiptOriginalReadTaskV1
                    if self.artifact_receipt_task is None:
                        self.artifact_receipt_task=ArtifactReceiptOriginalReadTaskV1(self,self.receipt_now_utc)
                    self.db.execute("BEGIN")
                    try:
                        done=self.artifact_receipt_task.advance_v1(meter)
                    finally:self.db.rollback()
                    if not done:return self
                    self.artifact_receipt_originals=self.artifact_receipt_task.seal
                elif self.source_locator is not None and self.prefinal is None:
                    self._reserve(self.reserved+65536)
                    self.prefinal=_PrefinalSourceInventoryV3(_ISSUER,self)
                    self.work.phase='producer_locator'if self.producer_phase is not None else 'source_material'
                elif self.producer_phase is not None and self.producer_progress is None:
                    from .natural_producer_qualification_v1 import begin_host_natural_producer_preparation_v3
                    candidate=begin_host_natural_producer_preparation_v3(self,parent_original_id=self.source_locator.c02_operation_id,phase=self.producer_phase)
                    producer_candidate=True
                elif self.producer_phase is not None and not self.producer_progress.complete:
                    from .natural_producer_qualification_v1 import advance_host_natural_producer_preparation_v3
                    candidate=advance_host_natural_producer_preparation_v3(self.producer_progress,meter=meter)
                    producer_candidate=True
                elif self.prefinal is not None and self.source_material is None:
                    from .current_graph_source_material_v3 import begin_current_graph_source_material_v3
                    candidate=begin_current_graph_source_material_v3(self.prefinal,actual_entry=self.prefinal.actual_entry)
                elif self.source_material is not None and not self.source_material.complete:
                    candidate=self.source_material.advance(meter=meter)
                else:
                    self.complete=True;self._reserve(self.reserved+65536)
                    self.result=PreparedCurrentGraphFullReadV3(_ISSUER,self)
            elif self.cell is None:self._next(meter)
            else:self._cell(meter)
        if candidate is not None:
            if producer_candidate:self.producer_progress=candidate
            else:self.source_material=candidate
        return self
    def advance_producer_outside_quantum_v3(self):
        from .natural_producer_qualification_v1 import advance_host_natural_producer_preparation_v3,bind_prepared_host_natural_producer_context_v3
        if not self.producer_progress.complete:
            self.producer_progress=advance_host_natural_producer_preparation_v3(self.producer_progress,meter=None)
        else:
            prepared=self.producer_progress.prepared
            frame=self.request_lifetime.enter_context(bind_prepared_host_natural_producer_context_v3(
                self.graph,scope=self.fence.scope,prepared=prepared))
            self.prepared_producer_members,self.producer_frame=prepared,frame
            self.work.phase='source_material'
        return self


def _work_v3(graph,reader,deadline):
    work=create_graph_storage_work_v3(graph,kind='current_graph_full_read_v3',operation_id=reader.operation.operation_id,
        selection_digest=reader.selection_digest,deadline_utc=deadline,state=reader,operation=reader.operation)
    reader.work=work
    return work


def prepare_current_graph_full_read_v3(graph,authority,lease,*,read_contract,operation_id,deadline_utc,c02_operation_id=None,source_ref=None,artifact_receipt_operation_id=None,receipt_now_utc=None):
    require_graph_storage_work_admission_v3(graph)
    contract=_contract_v3(read_contract)
    if contract.borrowed_scope:raise AuthorityUnavailable('natural administrator preparation requires its actual existing scope')
    graph._authorize(lease,authority,contract.domains,owner_read=contract.owner_read)
    deadline=_deadline_v3(deadline_utc);db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,operation_id,deadline)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id)
            if contract is ARTIFACT_RECEIPT_FULL_READ_V1:
                if (type(artifact_receipt_operation_id)is not str or not artifact_receipt_operation_id.startswith('artifact-receipt-message:')
                        or type(receipt_now_utc)not in(int,float)or not math.isfinite(receipt_now_utc)):
                    raise AuthorityUnavailable('actual Artifact receipt operation and verified current clock required')
                locator=None
            else:
                if artifact_receipt_operation_id is not None or receipt_now_utc is not None:
                    raise AuthorityUnavailable('Artifact receipt locator cannot enter another full-read family')
                locator=None if c02_operation_id is None and source_ref is None else _CurrentSourceEntryLocatorV3(c02_operation_id,source_ref)
            lifetime=ExitStack()if locator is not None and contract is not PRIVATE_REPLY_ROUTE_FULL_READ_V3 else None
            reader=_OrdinaryFullReadV3(graph,operation,fence,contract,authority=authority,lease=lease,
                source_locator=locator,request_lifetime=lifetime)
            reader.receipt_operation_id=artifact_receipt_operation_id
            reader.receipt_now_utc=receipt_now_utc
        work=_work_v3(graph,reader,deadline)
        if lifetime is not None:work.adopt_request_lifetime_v3(lifetime)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def prepare_current_graph_full_read_in_natural_scope_v3(graph,bootstrap,*,installed_bundle,scope,parent_original_id,source_ref,request_lifetime,deadline_utc=None):
    require_graph_storage_work_admission_v3(graph)
    namespace=graph._require_natural_admin_full_read_scope_v3(bootstrap,installed_bundle=installed_bundle,scope=scope,
        parent_original_id=parent_original_id,source_ref=source_ref)
    if namespace!=scope.namespace:raise AuthorityUnavailable('actual natural administrator scope namespace differs')
    if type(request_lifetime)is not ExitStack:raise AuthorityUnavailable('actual Work request lifetime container required')
    deadline=_deadline_v3(deadline_utc);db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,scope.operation_id,deadline)
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            # The actual bootstrap/installation/write-scope validator returns the existing read stamp.
            borrowed=(bootstrap,installed_bundle,scope,parent_original_id,source_ref)
            fence=graph._validate_natural_admin_full_read_scope_v3(borrowed)
            reader=_OrdinaryFullReadV3(graph,operation,fence,NATURAL_ADMIN_PREPARE_FULL_V3,borrowed=borrowed,
                source_locator=_CurrentSourceEntryLocatorV3(parent_original_id,source_ref),request_lifetime=request_lifetime)
        return _work_v3(graph,reader,deadline)
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise


def advance_current_graph_full_read_v3(graph,work):
    reader=work.state
    if type(reader)is not _OrdinaryFullReadV3 or reader.graph is not graph or reader.work is not work or reader.operation is not work.operation:
        raise AuthorityUnavailable('actual ordinary full-read same Work required')
    with bind_runtime_storage_operation_v3(work.operation,reader.db):
        if reader.borrowed is None:
            graph._authorize(reader.lease,reader.authority,reader.contract.domains,owner_read=reader.contract.owner_read)
            graph._validate_read_fence_v3(reader.fence)
        else:
            if graph._validate_natural_admin_full_read_scope_v3(reader.borrowed)!=reader.fence:
                raise AuthorityUnavailable('actual borrowed natural producer stamp changed')
        outside_producer=(reader.producer_progress is not None and reader.prepared_producer_members is None
            and(reader.producer_progress.complete or reader.producer_progress.phase=='protected_observation'))
        if outside_producer:
            if reader.db.in_transaction:raise AuthorityUnavailable('protected producer observation retained a transaction')
            reader.advance_producer_outside_quantum_v3()
        else:
            with reader.store._lock:
                if reader.db.in_transaction:raise AuthorityUnavailable('ordinary full-read continuation retained a transaction')
                if graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp or reader.store._registry.catalogue_hash!=reader.catalogue_hash:
                    raise AuthorityUnavailable('ordinary full-read original stamp/catalogue changed')
                reader.advance()
        if reader.borrowed is None:graph._validate_read_fence_v3(reader.fence)
        else:graph._validate_natural_admin_full_read_scope_v3(reader.borrowed)
    return GraphStorageStepV3('complete',reader.result)if reader.complete else GraphStorageStepV3('progress')


def finish_current_graph_full_read_v3(graph,work,error):
    reader=work.state
    try:
        if reader.borrowed is None:graph._finish_read_fence_v3(reader.fence)
        if error is None:work.result_lease=work.operation
    except BaseException:
        finish_runtime_storage_operation_v3(work.operation);raise
    finally:
        if error is not None or work.result_lease is None:
            if reader.producer_progress is not None:
                from .natural_producer_qualification_v1 import release_host_natural_producer_payload_v3
                release_host_natural_producer_payload_v3(reader.producer_progress)
            if reader.prefinal is not None:reader.prefinal.release_payload_v3()
            reader.prepared_producer_members=reader.producer_frame=None
            reader.prefinal=None
        reader.cell=reader.parser=reader.pending=reader.body=reader.fragment=reader.result=None
        reader.atoms=reader.sources=reader.heads=reader.source_material=reader.producer_progress=None
    if error is not None:finish_runtime_storage_operation_v3(work.operation)


@dataclass(frozen=True,init=False)
class _ActualWriteTypedProjectionV3(_FixedTypedProjectionV3):
    def __init__(self,issuer,base,atoms,epoch):
        if issuer is not _ISSUER:raise TypeError('actual writer projection issuer required')
        object.__setattr__(self,'_types',base.projection._types)
        object.__setattr__(self,'_operation',base.operation)
        object.__setattr__(self,'_atoms',atoms)
        object.__setattr__(self,'epochs',(epoch,))


class PreparedCurrentGraphFullWriteViewV3:
    """Base FULL EOF plus an independently issued actual transaction delta."""
    def __init__(self,issuer,facts):
        from .current_graph_full_write_v3 import _ActualFullWriteFactsV3
        if issuer is not _ISSUER or type(facts)is not _ActualFullWriteFactsV3:
            raise TypeError('actual private Store writer facts required')
        facts.require_current(facts.graph,facts.db,facts.namespace)
        base=facts.base
        if type(base)is not PreparedCurrentGraphFullReadV3:
            raise AuthorityUnavailable('actual ordinary FULL base required for Store delta')
        base._actual()
        self.base,self.facts=base,facts
        self.graph,self.db,self.namespace=base.graph,base.db,base.namespace
        self.work,self.ticket,self.operation=base.work,base.ticket,base.operation
        self.contract,self.scope=base.contract,base.scope
        self.graph_stamp,self.query=facts.after_stamp,facts.query
        self.selection_digest,self.catalogue_hash=base.selection_digest,base.catalogue_hash
        self.authority_epochs,self.owner_head=facts.authority_epochs,facts.owner_head
        self.prepared_families,self.coverage=base.prepared_families,base.coverage
        self.coverage_kind=facts.coverage_kind
        self.prefinal,self.source_material=base.prefinal,base.source_material
        self.prepared_producer_members,self.producer_frame=base.prepared_producer_members,base.producer_frame
        if facts.before_stamp!=base.graph_stamp or facts.work is not self.work or facts.operation is not self.operation:
            raise AuthorityUnavailable('Store writer delta differs from its actual FULL base')
        frozen={atom.key.token:atom for atom in base.projection._atoms}
        heads=dict(base.heads)
        self.operation.retain(65536+len(frozen)*128+len(heads)*256+sum(0 if row.payload_json is None else len(row.payload_json)*8+32768 for row in facts.rows))
        rights=frozenset({'memory.source','memory.access','d06.source_correction_head.v1',owner_grant_key(*self.namespace.as_tuple).type_name})
        for row in facts.rows:
            if row.key.type_name in rights:raise AuthorityUnavailable('actual Store delta affected Source or Owner rights; new preparation required')
            if row.key.type_name not in base.projection._types:
                if row.key.type_name not in facts.auxiliary_metadata_only_types:
                    raise AuthorityUnavailable('actual Store delta affected an unprepared family')
                heads[row.key.token]=(row.revision,int(row.valid),row.cell_id)
                continue
            if row.payload_json is None:
                prior=frozen.get(row.key.token)
                if prior is None or row.valid:raise AuthorityUnavailable('actual invalidation has no complete prepared logical value')
                frozen[row.key.token]=_FrozenDispatchAtomV3(row.key,row.revision,prior.value,False,prior.retained_bytes)
            else:
                value=json.loads(row.payload_json)
                frozen[row.key.token]=_FrozenDispatchAtomV3(row.key,row.revision,_freeze_value_v3(value),row.valid,_heap(value))
            heads[row.key.token]=(row.revision,int(row.valid),row.cell_id)
        self.projection=_ActualWriteTypedProjectionV3(_ISSUER,base,tuple(frozen[key]for key in sorted(frozen)),facts.after_stamp[1])
        self.sources,self.heads=base.sources,MappingProxyType(heads)
        _WRITE_VIEW_ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.base,self.facts,self.facts._identity_v3(),self.graph,self.db,self.namespace,self.work,self.ticket,
            self.operation,self.contract,self.scope,self.graph_stamp,self.query,self.selection_digest,self.catalogue_hash,
            self.authority_epochs,self.owner_head,self.prepared_families,self.coverage,self.coverage_kind,
            self.projection,(self.projection._types,self.projection._atoms,self.projection.epochs),self.sources,self.heads,
            self.prefinal,self.source_material,self.prepared_producer_members,self.producer_frame)
    def _actual(self):
        issued=_WRITE_VIEW_ISSUED.get(self)
        if issued is None or issued!=self._identity_v3()or self.operation.closed:
            raise AuthorityUnavailable('actual private Store FULL view changed or was invalidated')
        self.base._actual()
    def require_current(self,graph,db,namespace,*,required_families):
        self._actual()
        if (_BOUND.get()!=(self,graph,db,self.work,self.operation)or graph is not self.graph or db is not self.db
                or namespace!=self.namespace or not set(required_families)<=self.prepared_families
                or runtime_storage_v3(db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest
                or graph._GraphCoordinator__store._registry.catalogue_hash!=self.catalogue_hash):
            raise AuthorityUnavailable('actual Store FULL delta Binder/family/selection changed')
        self.facts.require_current(graph,db,namespace)
        return self.projection,self.query
    def source_metadata(self,graph,db,namespace,key,*,revision=None):
        self.require_current(graph,db,namespace,required_families=frozenset({SOURCE_METADATA_FAMILY_V3}))
        source=self.sources.get(key.token)
        actual=None if source is None else (db,source.source_key,source.revision,source.valid,source.cell_id,source.header,
            source.payload_sha256,source.metadata,source.scope,source.graph_stamp,source.query,source.operation_id,source.selection_digest)
        if (source is None or _SOURCE_ISSUED.get(source)!=actual or source.source_key!=key
                or source.scope is not self.scope or source.operation_id!=self.operation.operation_id
                or source.selection_digest!=self.selection_digest or revision is not None and source.revision!=revision):
            raise AuthorityUnavailable('actual unchanged Source EOF witness differs from Store FULL delta base')
        if any(row.key==key for row in self.facts.rows):raise AuthorityUnavailable('actual writer delta affected this Source witness')
        head=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,key.token)).fetchone()
        if head is None or tuple(head)!=(source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('actual Store FULL delta Source head differs from its original EOF')
        return source
    def release_payload_v3(self):
        _WRITE_VIEW_ISSUED.pop(self,None)
        self.projection=self.sources=self.heads=self.prefinal=self.source_material=None
        self.prepared_producer_members=self.producer_frame=self.base=self.facts=None


@contextmanager
def bind_actual_graph_full_write_v3(facts):
    view=PreparedCurrentGraphFullWriteViewV3(_ISSUER,facts)
    token=_BOUND.set((view,view.graph,view.db,view.work,view.operation))
    try:
        with bind_runtime_storage_operation_v3(view.operation,view.db):yield view
    finally:
        _BOUND.reset(token)
        view.release_payload_v3()


@dataclass(frozen=True)
class _DispatchFixedProjectionV3:
    _projection:object
    @property
    def epochs(self):return self._projection.epochs
    @property
    def atoms(self):return self.atoms_for_types_v3(_DISPATCH_TYPES)
    def get(self,key):
        if key.type_name not in _DISPATCH_TYPES or key.type_name=='memory.source':
            raise AuthorityUnavailable('dispatch adapter family or Source material was not prepared')
        return self._projection.get(key)
    def atoms_for_types_v3(self,types):
        if not set(types)<=_DISPATCH_TYPES or 'memory.source'in types:
            raise AuthorityUnavailable('dispatch adapter family or Source material was not prepared')
        operation=self._projection._operation
        operation.retain(256+len(self._projection._atoms)*16)
        return tuple(self._projection._view(atom)for atom in self._projection._atoms if atom.key.type_name in types)


class _DispatchFullReadBindingV3:
    def __init__(self,proof,graph,db):
        self.proof,self.graph,self.db=proof,graph,db
        self.qualification=None
        self.projection=_DispatchFixedProjectionV3(proof.projection)
    def require_current(self,graph,db,namespace,*,required_families):
        if (_BOUND.get()is not self or graph is not self.graph or db is not self.db
                or namespace!=self.proof.namespace or self.qualification is None
                or not set(required_families)<=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3,RUNTIME_JOB_FAMILY_V3})
                or self.projection._projection is not self.proof.projection):
            raise AuthorityUnavailable('actual P1/P2-qualified dispatch adapter family required')
        context,binding,claimed,authority_snapshot=self.qualification
        self.proof.require_for(context,binding,claimed,db,authority_snapshot=authority_snapshot)
        return self.projection,self.proof.query


@contextmanager
def _bind_prepared_dispatch_full_read_v3(proof,graph,db):
    from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3,PreparedCurrentDispatchSuccessorInventoryV3
    if type(proof)not in(PreparedCurrentDispatchInventoryV3,PreparedCurrentDispatchSuccessorInventoryV3):
        raise AuthorityUnavailable('actual private dispatch inventory adapter required')
    proof._actual()
    if proof.graph is not graph or proof.db is not db:raise AuthorityUnavailable('dispatch adapter belongs to another graph')
    binding=_DispatchFullReadBindingV3(proof,graph,db)
    token=_BOUND.set(binding)
    try:
        with bind_runtime_storage_operation_v3(proof.operation,db):yield proof
    finally:
        binding.qualification=None
        _BOUND.reset(token)


def _qualify_bound_dispatch_full_read_v3(proof,db,context,binding,claimed,authority_snapshot):
    adapter=_BOUND.get()
    if type(adapter)is _DispatchFullReadBindingV3 and adapter.proof is proof and adapter.db is db:
        adapter.qualification=(context,binding,claimed,authority_snapshot)


@contextmanager
def bind_prepared_graph_full_read_v3(proof,graph,db):
    if proof is None:
        yield None;return
    if type(proof)is not PreparedCurrentGraphFullReadV3:raise AuthorityUnavailable('actual private ordinary full-read Binder required')
    proof._actual()
    if proof.graph is not graph or proof.db is not db:raise AuthorityUnavailable('ordinary full-read Binder belongs to another graph')
    token=_BOUND.set((proof,graph,db,proof.work,proof.operation))
    try:
        with bind_runtime_storage_operation_v3(proof.operation,db):yield proof
    finally:_BOUND.reset(token)


def require_bound_graph_full_read_v3(graph,db,namespace,*,required_families):
    bound=_BOUND.get()
    if bound is None:raise AuthorityUnavailable('actual prepared ordinary full-read family is unavailable')
    if type(bound)is _DispatchFullReadBindingV3:
        return bound.require_current(graph,db,namespace,required_families=required_families)
    proof=bound[0]
    return proof.require_current(graph,db,namespace,required_families=required_families)


def require_bound_graph_full_read_proof_v3(graph,db,namespace,*,required_families):
    require_bound_graph_full_read_v3(graph,db,namespace,required_families=required_families)
    bound=_BOUND.get()
    return bound.proof if type(bound)is _DispatchFullReadBindingV3 else bound[0]


def require_bound_graph_full_read_proof_for_db_v3(db,namespace,*,required_families):
    bound=_BOUND.get()
    if bound is None:raise AuthorityUnavailable('actual prepared full-read Binder is unavailable')
    graph=bound.graph if type(bound)is _DispatchFullReadBindingV3 else bound[1]
    return require_bound_graph_full_read_proof_v3(graph,db,namespace,required_families=required_families)


def require_bound_graph_full_source_metadata_v3(db,namespace,key,*,revision=None):
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=frozenset({SOURCE_METADATA_FAMILY_V3}))
    if type(proof)in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
        return proof.source_metadata(proof.graph,db,namespace,key,revision=revision)
    return proof.source_metadata(db,namespace,proof.query,key,revision=revision)


def _require_bound_typed_projection_v3(db,namespace,query,type_names):
    types=frozenset(type_names)
    registered=_DISPATCH_TYPES|frozenset({NATURAL_PLAN_TYPE_V2})
    if not types<=registered:raise AuthorityUnavailable('actual fixed typed projection family was not prepared')
    families=frozenset(({CURRENT_DISPATCH_FAMILY_V3}if types&_DISPATCH_TYPES else set())
        |({NATURAL_PLAN_FAMILY_V3}if NATURAL_PLAN_TYPE_V2 in types else set()))
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,required_families=families)
    projection,actual_query=require_bound_graph_full_read_v3(proof.graph,db,namespace,required_families=families)
    if type(query)is not QueryEpoch or query!=actual_query:
        raise AuthorityUnavailable('typed FULL consumer query differs from its actual EOF proof')
    return proof,projection,types


def require_bound_graph_full_atom_rows_v3(db,namespace,query,type_names,columns,*,valid_only=True,name=None):
    if not set(columns)<=frozenset({'token','revision','valid','type_name','value'}):
        raise AuthorityUnavailable('typed FULL rows require their fixed registered columns')
    proof,projection,types=_require_bound_typed_projection_v3(db,namespace,query,type_names)
    atoms=projection.atoms_for_types_v3(types)
    proof.operation.retain(256+len(atoms)*(128+len(columns)*16))
    rows=[]
    for atom in atoms:
        if (valid_only and not atom.valid)or(name is not None and atom.key.name!=name):continue
        head=proof.heads.get(atom.key.token)
        if head is None or head[:2]!=(atom.revision,int(atom.valid)):
            raise AuthorityUnavailable('typed FULL row differs from its complete cell/head original')
        values={'token':atom.key.token,'revision':atom.revision,'valid':int(atom.valid),'type_name':atom.key.type_name,'value':atom.value}
        rows.append(tuple(values[column]for column in columns))
    return tuple(rows)


def require_bound_graph_full_atom_v3(db,namespace,query,key):
    if type(key)is not AtomKey or(key.owner.bot,key.owner.persona)!=namespace.as_tuple:
        raise AuthorityUnavailable('typed FULL head belongs to another canonical namespace')
    proof,projection,_=_require_bound_typed_projection_v3(db,namespace,query,(key.type_name,))
    head=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,key.token)).fetchone()
    expected=proof.heads.get(key.token)
    if head is None:
        if expected is not None:raise AuthorityUnavailable('typed FULL head disappeared after its EOF proof')
        return None
    if expected is None or tuple(head)!=expected:
        raise AuthorityUnavailable('typed FULL current head differs from its complete EOF original')
    atom=projection.get(key)
    if atom is None or(atom.revision,int(atom.valid))!=expected[:2]:
        raise AuthorityUnavailable('typed FULL head has no matching prepared logical value')
    return atom


def require_bound_graph_full_source_metadata_for_barrier_v3(db,namespace,key,*,revision=None):
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=frozenset({SOURCE_METADATA_FAMILY_V3}))
    if type(proof)in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
        return proof.source_metadata(proof.graph,db,namespace,key,revision=revision)
    return proof.source_metadata(db,namespace,proof.query,key,revision=revision,require_grant=False)


@asynccontextmanager
async def prepare_graph_full_read_on_worker_v3(worker,authority,lease,*,read_contract,operation_id,deadline_utc,c02_operation_id=None,source_ref=None):
    owned=await worker.call(lambda graph:prepare_current_graph_full_read_v3(graph,authority,lease,
        read_contract=read_contract,operation_id=operation_id,deadline_utc=deadline_utc,
        c02_operation_id=c02_operation_id,source_ref=source_ref))
    if type(owned)is not OwnedGraphStorageResultV3:raise AuthorityUnavailable('actual retained ordinary full-read result required')
    value,retention=owned.take_value_v3()
    try:
        if type(value)is not PreparedCurrentGraphFullReadV3:raise AuthorityUnavailable('actual private ordinary full-read result required')
        value._actual();yield value
    finally:
        if type(value)is PreparedCurrentGraphFullReadV3:value.release_payload_v3()
        value=None;retention.release()
