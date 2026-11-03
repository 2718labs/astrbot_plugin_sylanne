"""Private ordinary-work full census with a fixed, independently scoped projection."""
from contextlib import ExitStack,asynccontextmanager,contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary,WeakSet
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
_ORDINARY_READERS_V3=WeakSet()
_FULL_SELECTIONS_V3=WeakKeyDictionary()
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
COMMITMENT_COMMUNICATION_FULL_READ_V1=_FixedReadContractV3('commitment_communication_full_read_v1',frozenset({'d08','d09','d11'}),_ALL_FAMILIES)
NATURAL_ADMIN_PREPARE_FULL_V3=_FixedReadContractV3('natural_admin_prepare_full_v3',frozenset(),_ALL_FAMILIES,borrowed_scope=True)
D13_COUNTER_PREPARE_FULL_V1=_FixedReadContractV3('d13_counter_prepare_full_v1',frozenset(),_ALL_FAMILIES,borrowed_scope=True)
NATURAL_SAVED_ORIGINAL_FULL_READ_V3=_FixedReadContractV3('natural_saved_original_full_read_v3',frozenset(),_ALL_FAMILIES,borrowed_scope=True)
ARTIFACT_RECEIPT_FULL_READ_V1=_FixedReadContractV3('artifact_receipt_full_read_v1',frozenset({'d08','d09','d11'}),_ALL_FAMILIES|frozenset({ARTIFACT_RECEIPT_CONTROL_FAMILY_V1}))
_CONTRACTS=MappingProxyType({entry.name:entry for entry in (NATURAL_MODEL_FULL_READ_V3,NATURAL_ROUTE_FULL_READ_V3,
    PRIVATE_REPLY_ROUTE_FULL_READ_V3,COMMITMENT_COMMUNICATION_FULL_READ_V1,NATURAL_ADMIN_PREPARE_FULL_V3,ARTIFACT_RECEIPT_FULL_READ_V1,D13_COUNTER_PREPARE_FULL_V1,NATURAL_SAVED_ORIGINAL_FULL_READ_V3)})


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
    _heads:object
    epochs:tuple
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER:raise TypeError('actual fixed full-read projection issuer required')
        object.__setattr__(self,'_types',reader.projection_types)
        object.__setattr__(self,'_operation',reader.operation)
        object.__setattr__(self,'_heads',MappingProxyType(dict(reader.heads)))
        object.__setattr__(self,'_atoms',tuple(_FrozenDispatchAtomV3(atom.key,atom.revision,_freeze_value_v3(atom.value),atom.valid,_heap(atom.value))for atom in reader.atoms))
        object.__setattr__(self,'epochs',(reader.graph_stamp[1],))
    def _view(self,atom):
        self._operation.retain(atom.retained_bytes*4+512)
        from ..graph_types import GraphAtom
        return GraphAtom(atom.key,atom.revision,_detach_value_v3(atom.value),atom.valid)
    @property
    def versions(self):
        if self._operation.closed:raise AuthorityUnavailable('FULL metadata versions outlived their actual operation')
        from ..graph_types import GraphVersion
        self._operation.retain(256+len(self._heads)*128)
        return tuple(GraphVersion(AtomKey.from_token(token),self._heads[token][0])for token in sorted(self._heads))
    @property
    def atoms(self):
        return self._complete_atoms_for_types_v3(self._types-frozenset({'memory.source'}))
    def get(self,key):
        if key.type_name not in self._types:raise AuthorityUnavailable('ordinary projection family was not prepared')
        if key.type_name=='memory.source':raise AuthorityUnavailable('Source material needs its original rights-scoped reader')
        atom=next((atom for atom in self._atoms if atom.key==key),None)
        if atom is None and key.token in self._heads:
            raise AuthorityUnavailable('existing head was not selected by this actual SourceALL permission')
        return None if atom is None else self._view(atom)
    def _complete_atoms_for_types_v3(self,types,*,valid_only=False,name=None):
        if not set(types)<=self._types or 'memory.source'in types:
            raise AuthorityUnavailable('ordinary projection family or Source Body was not prepared')
        selected={atom.key.token for atom in self._atoms}
        required={token for token,head in self._heads.items()if AtomKey.from_token(token).type_name in types
            and(not valid_only or head[1]==1)and(name is None or AtomKey.from_token(token).name==name)}
        if not required<=selected:
            raise AuthorityUnavailable('selected Body does not establish a complete unscoped type inventory')
        self._operation.retain(256+len(self._atoms)*16)
        return tuple(self._view(atom)for atom in self._atoms if atom.key.type_name in types
            and(not valid_only or atom.valid)and(name is None or atom.key.name==name))
    def atoms_for_types_v3(self,types):
        return self._complete_atoms_for_types_v3(types)



@dataclass(frozen=True)
class _CurrentSourceEntryLocatorV3:
    c02_operation_id:object
    source_ref:object


class _PrefinalSourceInventoryV3:
    """Complete metadata census; it never owns a typed business projection."""
    def __init__(self,issuer,reader):
        if (issuer is not _ISSUER or type(reader)is not _OrdinaryFullReadV3
                or not reader.graph_eof or reader.complete):
            raise TypeError('actual same-Work metadata census required')
        self.reader=reader;self.graph,self.db,self.namespace=reader.graph,reader.db,reader.namespace
        self.work,self.operation,self.scope=reader.work,reader.operation,reader.fence.scope
        self.graph_stamp,self.query=reader.graph_stamp,reader.query
        self.selection_digest,self.catalogue_hash=reader.selection_digest,reader.catalogue_hash
        self.prepared_families=reader.contract.families
        self.authority_epochs,self.owner_head=reader.authority_epochs,reader.owner_head
        self.actual_entry=reader.source_locator
        self.metadata=MappingProxyType(dict(reader.metadata_cells))
        self.sources,self.heads=MappingProxyType(dict(reader.sources)),MappingProxyType(dict(reader.heads))
        self.coverage=_FullCensusCoverageV3(reader.namespace,reader.query,reader.count,reader.root,True)
        _PREFINAL_ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.reader,self.graph,self.db,self.namespace,self.work,self.operation,self.scope,self.graph_stamp,self.query,
            self.selection_digest,self.catalogue_hash,self.prepared_families,self.authority_epochs,self.owner_head,
            self.actual_entry,self.metadata,self.sources,self.heads,self.coverage)
    def _actual(self):
        if (_PREFINAL_ISSUED.get(self)!=self._identity_v3()or self.operation.closed
                or self.work.state is not self.reader or self.reader.work is not self.work
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph
                or not self.reader.graph_eof or not self.coverage.full_eof):
            raise AuthorityUnavailable('actual prefinal metadata Work/EOF changed')
        return self
    def require_current(self,*,meter=None):
        self._actual();store=self.graph._GraphCoordinator__store
        if (not store._lock._is_owned()or runtime_storage_v3(self.db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest
                or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp
                or store._registry.catalogue_hash!=self.catalogue_hash):
            raise AuthorityUnavailable('prefinal metadata selection/query/stamp changed')
        with runtime_storage_quantum_v3(self.db)as current:
            if meter is not None and current is not meter:raise AuthorityUnavailable('metadata reader quantum changed')
            epochs=current.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
                'bot=? AND persona=?',self.namespace.as_tuple)
            owner=current.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,owner_grant_key(*self.namespace.as_tuple).token))
        if epochs!=self.authority_epochs or owner!=self.owner_head:
            raise AuthorityUnavailable('prefinal Source/Owner versions changed')
        return self
    def metadata_value_v3(self,key,*,revision=None,meter=None):
        self.require_current(meter=meter)
        if type(key)is not AtomKey or(key.owner.bot,key.owner.persona)!=self.namespace.as_tuple:
            raise AuthorityUnavailable('metadata selector belongs to another actual namespace')
        original=self.metadata.get(key.token)
        if original is None:
            if key.token in self.heads:raise AuthorityUnavailable('head has no registered fixed metadata selector')
            return None
        original.require_v3(self.reader)
        if revision is not None and original.revision!=revision:
            raise AuthorityUnavailable('metadata selector revision differs from its original')
        with runtime_storage_quantum_v3(self.db)as current:
            head=current.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token))
        if head!=(original.revision,int(original.valid),original.cell_id):
            raise AuthorityUnavailable('metadata selector current head differs from its complete original')
        self.operation.retain(_heap(original.selectors)+1024)
        return _detach_value_v3(original.selectors)
    def control_metadata_v3(self,key,*,revision=None,meter=None):
        value=self.metadata_value_v3(key,revision=revision,meter=meter)
        if value is None:return None
        original=self.metadata[key.token]
        return _FullControlMetadataV3(key,original.revision,original.valid,value)
    def require_body_projection_v3(self):
        self._actual();reader=self.reader
        if not reader.body_eof or reader.projection is None or reader.source_material is None:
            raise AuthorityUnavailable('metadata prefinal has no rights-qualified selected Body EOF')
        reader.source_material.require_rights_seal_v3()
        return reader.projection
    def source_metadata(self,db,namespace,query,key,*,revision=None,require_grant=False,meter=None):
        if require_grant:raise AuthorityUnavailable('inspection metadata grants no purpose/audience rights')
        self.require_current(meter=meter)
        if db is not self.db or namespace!=self.namespace or query!=self.query:
            raise AuthorityUnavailable('prefinal Source metadata belongs to another actual census')
        source=self.sources.get(key.token)
        actual=None if source is None else(db,source.source_key,source.revision,source.valid,source.cell_id,source.header,
            source.payload_sha256,source.metadata,source.scope,source.graph_stamp,source.query,source.operation_id,source.selection_digest)
        if (source is None or _SOURCE_ISSUED.get(source)!=actual or source.source_key!=key or source.scope is not self.scope
                or source.graph_stamp!=self.graph_stamp or source.query!=self.query
                or source.operation_id!=self.operation.operation_id or revision is not None and source.revision!=revision):
            raise AuthorityUnavailable('actual Source inspection/header/EOF metadata required')
        with runtime_storage_quantum_v3(db)as current:
            head=current.read_fixed_row(db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token))
        if head!=(source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('Source metadata head differs from its complete original')
        return source
    def correction_head(self,db,namespace,query,key,*,meter=None):
        if db is not self.db or namespace!=self.namespace or query!=self.query or key.type_name!='d06.source_correction_head.v1':
            raise AuthorityUnavailable('fixed correction metadata scope differs')
        return self.control_metadata_v3(key,meter=meter)
    def release_payload_v3(self):
        _PREFINAL_ISSUED.pop(self,None)
        self.metadata=self.sources=self.heads=None


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
        self.commitment_terms_locator=reader.commitment_terms_locator
        self.commitment_scope_original=reader.commitment_scope_task
        self.commitment_recovery=reader.commitment_recovery_task
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
        self.rights_seal=reader.source_material.require_rights_seal_v3()
        if not reader.body_eof or reader.projection is None:raise AuthorityUnavailable('FULL requires actual rights-qualified selected Body EOF')
        self.projection=reader.projection
        self.sources=MappingProxyType(dict(reader.sources))
        self.heads=MappingProxyType(dict(reader.heads))
        _ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.graph,self.db,self.namespace,self.work,self.ticket,self.operation,self.contract,self.scope,self.graph_stamp,
            self.query,self.selection_digest,self.catalogue_hash,self.authority_epochs,self.owner_head,self.prepared_families,
            self.coverage,self.rights_seal,self.projection,(self.projection._types,self.projection._operation,self.projection._atoms,self.projection._heads,self.projection.epochs),self.sources,self.heads,self.prefinal,self.source_material,self.prepared_producer_members,self.producer_frame,self.artifact_receipt_originals,self.receipt_operation_id,self.commitment_scope_original,self.commitment_recovery,self.commitment_terms_locator)
    def _actual(self):
        issued=_ISSUED.get(self)
        if issued is None:raise AuthorityUnavailable('ordinary full-read proof was not issued or has been released')
        if (issued!=self._identity_v3()or self.operation.closed or not self.coverage.full_eof
                or self.work.coordinator is not self.graph or self.work.ticket!=self.ticket
                or self.work.operation is not self.operation):
            raise AuthorityUnavailable('actual private originating full-read Work/EOF/retention changed')
        _contract_v3(self.contract)
        if self.prefinal is not None:self.prefinal._actual()
        self.rights_seal.require_v3()
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
        self.work.state.sources=self.work.state.heads=self.work.state.source_material=None
        if self.commitment_recovery is not None:
            self.commitment_recovery.release_v1()
            self.work.state.commitment_recovery_task=None
            self.commitment_recovery=None
        if self.commitment_terms_locator is not None:
            self.commitment_terms_locator.release_v3()
            self.work.state.commitment_terms_locator=None
            self.commitment_terms_locator=None
        if self.commitment_scope_original is not None:
            self.commitment_scope_original.release_v1()
            self.work.state.commitment_scope_task=None
            self.commitment_scope_original=None
        self.prepared_producer_members=self.producer_frame=None


class _OrdinaryFullReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,graph,operation,fence,contract,*,authority=None,lease=None,borrowed=None,source_locator=None,request_lifetime=None):
        self.contract,self.authority,self.lease,self.borrowed=contract,authority,lease,borrowed
        self.work,self.owner_head=None,None
        self.metadata_selection=None;self.owner_groups=()
        self.owner_entry=self.owner_binding=self.owner_guard=None;self.owner_task=None
        _ORDINARY_READERS_V3.add(self)
        self.artifact_receipt_task,self.artifact_receipt_originals=None,None
        self.commitment_scope_task=None;self.commitment_scope_ref=None;self.commitment_terms_locator=None
        self.commitment_recovery_task=None;self.commitment_send_deadline=None;self.commitment_recovery_only=False
        self.receipt_operation_id=None
        self.source_locator,self.request_lifetime=source_locator,request_lifetime
        self.producer_phase=None if source_locator is None or contract in (PRIVATE_REPLY_ROUTE_FULL_READ_V3,COMMITMENT_COMMUNICATION_FULL_READ_V1,ARTIFACT_RECEIPT_FULL_READ_V1) else('prepare'if borrowed is not None else'frozen')
        if contract is NATURAL_SAVED_ORIGINAL_FULL_READ_V3:self.producer_phase='frozen'
        self.prefinal,self.source_material=None,None
        self.metadata_cells={};self.selector_value=None;self.metadata_now=None;self.metadata_clock_reading=None;self.policy_context=None;self.policy_keys=();self.policy_requests=();self.policy_request_bases=();self.policy_request_keys=();self.policy_recipe_expiry=None
        self.producer_metadata=self.artifact_metadata=None;self.source_rights_seal=None
        self.role_control_original=None;self.role_control_metadata_ready=False
        self.role_lineage_task=None;self.role_lineage_ready=False
        self.body_eof=False;self.body_keys=None;self.body_position=0;self.projection=None
        self.d13_collection=self.d13_observation=None
        self.producer_progress,self.prepared_producer_members,self.producer_frame=None,None,None
        types=frozenset().union(*(_FAMILIES[name]for name in contract.families))
        super().__init__(graph,operation,fence,projection_types=types,selected_tokens=frozenset(),
            census_schema='sylanne.current-graph-full-inventory.v3',leaf_schema='sylanne.current-graph-full-inventory-leaf.v3')
    def _require_source_roots_v3(self,roots,purpose,audiences):
        if self.contract is not ARTIFACT_RECEIPT_FULL_READ_V1:
            raise AuthorityUnavailable('Artifact original family belongs to its dedicated full-read contract')
        self.source_material.require_rights_seal_v3()
        requested=set(roots);audiences=tuple(audiences)
        qualified={ref for ref,p,a,_ in self.source_material.rights_done if p==purpose
            and all((ref,purpose,required,False)in self.source_material.rights_done
                or(ref,purpose,required,True)in self.source_material.rights_done for required in audiences)}
        if any((ref,purpose,a,False)not in self.source_material.rights_done for ref in requested for a in audiences):
            raise AuthorityUnavailable('Artifact roots were not qualified by all original Source groups')
        return {ref:self.prefinal.sources[ref]for ref in qualified}


    def _start_source_inspection_v3(self,owner,meter):
        key,revision,valid,_,cell=self.pending
        self.heads[key.token]=(revision,valid,cell)
        if valid:return super()._start_source_inspection_v3(owner,meter)
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        self.cell=begin_runtime_cell_read_v3(self.db,cell,erasure_owner_ref=key.token)
        codec=self.cell.header[0]
        if codec not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('negative Source census has no actual canonical value cell')
        self._begin_census_value_v3(codec,meter)
    def _begin_census_value_v3(self,codec,meter):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=codec=='canonical-json.ascii.v1')
        self.selector_value=_FullSelectorValueV3(self,self.pending[3]);self.body=None
        from .d01_ordinary_origin_stream_v3 import _CanonicalRangeHashV3
        self.semantic_hash=_CanonicalRangeHashV3(codec=='canonical-json.ascii.v1')
    def _feed_census_value_v3(self,part):
        self.parser.feed(part,self.selector_value.emit_v3)
        from ..runtime_storage_v3 import _QUANTUM
        self.semantic_hash.update(part,_QUANTUM.get()[2])
    def _finish_census_value_v3(self,key,revision,valid,type_name,cell,digest):
        selectors=self.selector_value.finish_v3();self.selector_value=None
        original=_FullMetadataCellOriginalV3(self,key,revision,bool(valid),cell,tuple(self.cell.header),digest,selectors,self.semantic_hash.finish())
        self.semantic_hash=None
        _FULL_METADATA_CELLS_V3[original]=original._identity_v3()
        self.operation.retain(1024)
        self.metadata_cells[key.token]=original;self.heads[key.token]=(revision,valid,cell)
    def _advance_selected_body_v3(self,meter):
        from ..runtime_storage_v3 import RuntimeCellReadV3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        from ..graph_types import GraphAtom
        self.source_material.require_rights_seal_v3();self.metadata_selection.require_for_v3(self)
        if self.body_position==len(self.body_keys):
            self.body_eof=True;self.projection=_FixedTypedProjectionV3(_ISSUER,self);return
        key=AtomKey.from_token(self.body_keys[self.body_position]);original=self.prefinal.metadata.get(key.token)
        if original is None:raise AuthorityUnavailable('selected Body has no complete metadata original')
        original.require_v3(self)
        if self.cell is None:
            head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token))
            if head!=self.prefinal.heads[key.token]:raise AuthorityUnavailable('selected Body head changed after SourceALL')
            self.cell=RuntimeCellReadV3(self.operation.handle,original.cell_id,erasure_owner_ref=key.token,meter=meter)
            if tuple(self.cell.header)!=original.header:raise AuthorityUnavailable('selected Body header differs from metadata EOF')
            self._reserve(self.cell.header[3]*8+32768)
            self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
            self.selector_value=_FullSelectorValueV3(self,key.type_name);self.body=bytearray();return
        if self.offset<len(self.fragment):
            end=min(self.offset+1024,len(self.fragment));part=self.fragment[self.offset:end]
            self.parser.feed(part,self.selector_value.emit_v3);self.body.extend(part);self.offset=end;return
        fragment=self.cell.read_fragment(meter=meter)
        if fragment is not None:self.fragment,self.offset=fragment,0;return
        parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
        if (parsed.sha256,parsed.byte_count,digest)!=(original.digest,original.header[3],original.digest):
            raise AuthorityUnavailable('selected Body complete canonical EOF differs from metadata seal')
        selectors=self.selector_value.finish_v3()
        if selectors!=original.selectors:raise AuthorityUnavailable('selected Body selector fields differ from metadata census')
        self.atoms.append(GraphAtom(key,original.revision,json.loads(self.body),original.valid))
        self.body_position+=1;self.cell=self.parser=self.selector_value=self.body=None;self.fragment=b'';self.offset=0

    def _graph_eof_v3(self):pass
    def advance(self):
        candidate=None;producer_candidate=False
        with bind_runtime_storage_operation_v3(self.operation,self.db),runtime_storage_quantum_v3(self.db)as meter:
            if self.authority_epochs is None:
                self.authority_epochs=self._epochs(meter)
                self.owner_head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,owner_grant_key(*self.namespace.as_tuple).token))
            elif not self.graph_eof:
                if self.cell is None:self._next(meter)
                else:self._cell(meter)
            elif self.prefinal is None:
                self._reserve(self.reserved+65536);self.prefinal=_PrefinalSourceInventoryV3(_ISSUER,self)
            elif not self.role_control_metadata_ready:
                self.db.execute('BEGIN')
                try:_advance_full_role_control_metadata_v3(self,meter)
                finally:self.db.rollback()
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and (
                    self.commitment_recovery_task is None or not self.commitment_recovery_task.complete):
                from .d08_commitment_recovery_read_v1 import CommitmentCommunicationRecoveryReadV1
                if self.commitment_recovery_task is None:self.commitment_recovery_task=CommitmentCommunicationRecoveryReadV1(self)
                self.db.execute('BEGIN')
                try:self.commitment_recovery_task.advance(meter)
                finally:self.db.rollback()
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and self.commitment_recovery_task.result is not None:
                if self.metadata_selection is None:
                    audiences=tuple(self.authority.audience)
                    self.owner_groups=(('expression',audiences,()),)
                    self.metadata_selection=_FullMetadataSelectionV3(_ISSUER,self,selected_keys=(),groups=self.owner_groups)
                elif self.owner_entry is None:self.work.phase='owner_metadata'
                else:
                    self.owner_entry.require_for_v3(self)
                    self.complete=True;self.result=PreparedCurrentGraphFullMetadataRecoveryV3(_ISSUER,self)
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and self.commitment_recovery_only:
                raise AuthorityUnavailable('expired named selector has no actual committed metadata original')
            elif self.contract is ARTIFACT_RECEIPT_FULL_READ_V1 and(self.artifact_metadata is None or not self.artifact_metadata.complete):
                if self.artifact_metadata is None:self.artifact_metadata=_FullArtifactReceiptMetadataV3(self)
                self.db.execute('BEGIN')
                try:self.artifact_metadata.advance_v3(meter)
                finally:self.db.rollback()
            elif self.source_material is None:
                from .current_graph_source_material_v3 import begin_current_graph_source_material_v3
                candidate=begin_current_graph_source_material_v3(self.prefinal,actual_entry=self.prefinal.actual_entry)
            elif self.source_material.phase not in('metadata_ready','await_owner','rights_sealed','complete')and not self.source_material.complete:
                candidate=self.source_material.advance(meter=meter)
            elif self.source_material.phase=='metadata_ready' and self.metadata_now is None:
                self.work.phase='selector_clock'
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and AtomKey.from_token(self.commitment_scope_ref).type_name=='d08.commitment_communication_intent.v2'and(
                    self.commitment_terms_locator is None or not self.commitment_terms_locator.complete):
                from .current_commitment_fulfillment_source_v3 import begin_named_commitment_terms_locator_metadata_v3
                self.db.execute('BEGIN')
                try:
                    if self.commitment_terms_locator is None:self.commitment_terms_locator=begin_named_commitment_terms_locator_metadata_v3(self)
                    self.commitment_terms_locator.advance_v3(meter)
                finally:self.db.rollback()
            elif self.producer_phase is not None and(self.producer_metadata is None or not self.producer_metadata.complete):
                from .natural_producer_qualification_v1 import begin_host_natural_producer_metadata_v3
                if self.producer_metadata is None:self.producer_metadata=begin_host_natural_producer_metadata_v3(self)
                self.db.execute('BEGIN')
                try:self.producer_metadata.advance_v3(meter)
                finally:self.db.rollback()
            elif self.contract is D13_COUNTER_PREPARE_FULL_V1 and not self.d13_counter_resource_metadata_ready:
                from .d13_counter_prepare_resource_inputs_v1 import advance_d13_counter_prepare_resource_metadata_v1
                self.db.execute('BEGIN')
                try:self.d13_counter_resource_metadata_ready=advance_d13_counter_prepare_resource_metadata_v1(self,meter)
                finally:self.db.rollback()
            elif self.metadata_selection is None:
                self.db.execute('BEGIN')
                try:_select_full_metadata_v3(self,meter)
                finally:self.db.rollback()
                self.work.phase='owner_metadata'
            elif self.owner_entry is None:self.work.phase='owner_metadata'
            elif self.source_material.phase=='await_owner':self.source_material.admit_owner_v3()
            elif not self.role_lineage_ready:
                self.db.execute('BEGIN')
                try:_advance_full_role_lineage_metadata_v4(self,meter)
                finally:self.db.rollback()
            elif not self.body_eof:
                if self.body_keys is None:
                    seal=self.source_material.require_rights_seal_v3()
                    controls={token for token,head in seal.controls if head is not None}
                    selected=set(self.metadata_selection.keys)|controls
                    selected.add(owner_grant_key(*self.namespace.as_tuple).token)
                    self.body_keys=tuple(sorted(token for token in selected if token in self.prefinal.metadata
                        and AtomKey.from_token(token).type_name in self.projection_types))
                self._advance_selected_body_v3(meter)
            elif self.producer_phase is not None and self.producer_progress is None:
                from .natural_producer_qualification_v1 import begin_host_natural_producer_preparation_v3
                candidate=begin_host_natural_producer_preparation_v3(self,parent_original_id=self.source_locator.c02_operation_id,phase=self.producer_phase)
                producer_candidate=True
            elif self.producer_phase is not None and not self.producer_progress.complete:
                from .natural_producer_qualification_v1 import advance_host_natural_producer_preparation_v3
                candidate=advance_host_natural_producer_preparation_v3(self.producer_progress,meter=meter);producer_candidate=True
            elif self.source_material.phase=='rights_sealed':self.source_material.begin_body_entry_v3()
            elif self.contract is ARTIFACT_RECEIPT_FULL_READ_V1 and self.artifact_receipt_originals is None:
                from .artifact_receipt_original_read_v1 import ArtifactReceiptOriginalReadTaskV1
                if self.artifact_receipt_task is None:self.artifact_receipt_task=ArtifactReceiptOriginalReadTaskV1(self,self.receipt_now_utc)
                self.db.execute('BEGIN')
                try:done=self.artifact_receipt_task.advance_v1(meter)
                finally:self.db.rollback()
                if done:self.artifact_receipt_originals=self.artifact_receipt_task.seal
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and(self.commitment_scope_task is None or not self.commitment_scope_task.complete):
                from .d08_commitment_scope_read_v1 import CommitmentScopeOriginalReadTaskV1
                if self.commitment_scope_task is None:self.commitment_scope_task=CommitmentScopeOriginalReadTaskV1(self)
                self.db.execute('BEGIN')
                try:self.commitment_scope_task.advance_v1(meter)
                finally:self.db.rollback()
            elif self.contract is COMMITMENT_COMMUNICATION_FULL_READ_V1 and not self.commitment_scope_task.observed:
                self.work.phase='commitment_scope_observation'
            elif self.contract is D13_COUNTER_PREPARE_FULL_V1 and not self.d13_counter_resource_inputs_ready:
                from .d13_counter_prepare_resource_inputs_v1 import advance_d13_counter_prepare_resources_v1
                self.db.execute('BEGIN')
                try:self.d13_counter_resource_inputs_ready=advance_d13_counter_prepare_resources_v1(self,meter)
                finally:self.db.rollback()
            else:
                from .graph_d13_cache_use_collection_v2 import graph_full_read_needs_d13_collection_v2
                if graph_full_read_needs_d13_collection_v2(self):self.work.phase='d13_collection'
                else:
                    self.complete=True;self._reserve(self.reserved+65536);self.result=PreparedCurrentGraphFullReadV3(_ISSUER,self)
        if candidate is not None:
            if producer_candidate:self.producer_progress=candidate
            else:self.source_material=candidate
        return self
    def advance_producer_outside_quantum_v3(self):
        from .natural_producer_qualification_v1 import advance_host_natural_producer_preparation_v3,bind_prepared_host_natural_producer_context_v3
        if not self.producer_progress.complete:
            self.producer_progress=advance_host_natural_producer_preparation_v3(self.producer_progress,meter=None)
        else:
            self.producer_metadata.require_prepared_v3(self.producer_progress)
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


def prepare_current_graph_full_read_v3(graph,authority,lease,*,read_contract,operation_id,deadline_utc,c02_operation_id=None,source_ref=None,artifact_receipt_operation_id=None,receipt_now_utc=None,commitment_scope_ref=None):
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
                if type(c02_operation_id)is not str or not c02_operation_id:
                    raise AuthorityUnavailable('this FULL contract requires its actual immutable C02 entry locator')
                locator=_CurrentSourceEntryLocatorV3(c02_operation_id,source_ref)
            if contract is COMMITMENT_COMMUNICATION_FULL_READ_V1:
                from ..domains.d08.commitment_communication_v1 import SCOPE_TYPES
                key=AtomKey.from_token(commitment_scope_ref)
                if locator is None or key.type_name not in SCOPE_TYPES or(key.owner.bot,key.owner.persona)!=authority.namespace.as_tuple:
                    raise AuthorityUnavailable('named commitment read requires its exact Source entry and scope locator')
            elif commitment_scope_ref is not None:
                raise AuthorityUnavailable('approved literal selector belongs only to its dedicated Source-qualified contract')
            lifetime=ExitStack()if locator is not None and contract not in (PRIVATE_REPLY_ROUTE_FULL_READ_V3,COMMITMENT_COMMUNICATION_FULL_READ_V1) else None
            reader=_OrdinaryFullReadV3(graph,operation,fence,contract,authority=authority,lease=lease,
                source_locator=locator,request_lifetime=lifetime)
            reader.receipt_operation_id=artifact_receipt_operation_id
            reader.receipt_now_utc=receipt_now_utc
            reader.commitment_scope_ref=commitment_scope_ref
        work=_work_v3(graph,reader,deadline)
        if lifetime is not None:work.adopt_request_lifetime_v3(lifetime)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise



_D13_COUNTER_BORROWED_V1=WeakKeyDictionary()
_D13_COUNTER_FULL_V1=WeakKeyDictionary()


class _D13CounterBorrowedScopeV1:
    def __init__(self,issuer,graph,bootstrap,installed_bundle,scope,owner_issuance,
            owner_guard,current_owner,deadline):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('D13 counter FULL scope requires its private actual factory')
        self.graph,self.bootstrap,self.installed_bundle=graph,bootstrap,installed_bundle
        self.scope,self.owner_issuance=scope,owner_issuance
        self.owner_guard,self.current_owner=owner_guard,current_owner
        self.instruction,self.authority=owner_issuance.instruction,owner_issuance.authority
        self.original_deadline_utc=deadline
        _D13_COUNTER_BORROWED_V1[self]=self._identity_v1()
    def _identity_v1(self):
        return(self.graph,self.bootstrap,self.installed_bundle,self.scope,self.owner_issuance,
            self.owner_guard,self.current_owner,self.instruction,self.authority,self.original_deadline_utc)


def require_actual_d13_counter_borrowed_scope_v1(borrowed,graph):
    from .d13_counter_prepare_owner_v1 import require_actual_d13_counter_owner_issuance_v1
    if (type(borrowed)is not _D13CounterBorrowedScopeV1
            or _D13_COUNTER_BORROWED_V1.get(borrowed)!=borrowed._identity_v1()
            or borrowed.graph is not graph
            or borrowed.owner_issuance.instruction is not borrowed.instruction
            or borrowed.owner_issuance.authority is not borrowed.authority
            or borrowed.owner_issuance.bundle is not borrowed.installed_bundle
            or borrowed.scope.operation!='write'
            or borrowed.scope.namespace!=borrowed.instruction.namespace
            or borrowed.authority.namespace!=borrowed.scope.namespace
            or borrowed.original_deadline_utc>min(borrowed.instruction.expires_at_utc,
                borrowed.instruction.prospective_plan_deadline_utc)):
        raise AuthorityUnavailable('D13 counter FULL borrowed scope left its actual private issuance')
    require_actual_d13_counter_owner_issuance_v1(
        borrowed.owner_issuance,graph,borrowed.authority,borrowed.owner_issuance.operation_id)
    return borrowed


def _validate_borrowed_full_scope_v3(reader):
    if reader.contract is D13_COUNTER_PREPARE_FULL_V1:
        require_actual_d13_counter_borrowed_scope_v1(reader.borrowed,reader.graph)
        return reader.graph._validate_d13_counter_prepare_full_scope_v1(reader.borrowed)
    if reader.contract is NATURAL_ADMIN_PREPARE_FULL_V3:
        return reader.graph._validate_natural_admin_full_read_scope_v3(reader.borrowed)
    if reader.contract is NATURAL_SAVED_ORIGINAL_FULL_READ_V3:
        return reader.graph._validate_natural_saved_full_read_scope_v3(reader.borrowed)
    raise AuthorityUnavailable('FULL borrowed scope has no exact registered private contract')


def _d13_counter_full_identity_v1(reader):
    return(reader.graph,reader.db,reader.work,reader.operation,reader.contract,reader.fence,
        reader.borrowed,reader.authority,reader.d13_counter_owner_issuance,
        reader.d13_counter_instruction,reader.request_lifetime)


def require_actual_d13_counter_prepare_full_reader_v1(reader,*,db=None,meter=None):
    if (type(reader)is not _OrdinaryFullReadV3 or reader not in _ORDINARY_READERS_V3
            or reader.contract is not D13_COUNTER_PREPARE_FULL_V1
            or _D13_COUNTER_FULL_V1.get(reader)!=_d13_counter_full_identity_v1(reader)
            or reader.work is None or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.work.coordinator is not reader.graph
            or reader.operation.closed or db is not None and db is not reader.db
            or reader.producer_phase!='prepare'):
        raise AuthorityUnavailable('actual private D13 counter-prepare FULL Work required')
    borrowed=require_actual_d13_counter_borrowed_scope_v1(reader.borrowed,reader.graph)
    if (reader.d13_counter_owner_issuance is not borrowed.owner_issuance
            or reader.d13_counter_instruction is not borrowed.instruction
            or reader.authority is not borrowed.authority
            or reader.operation.operation_id!=borrowed.scope.operation_id
            or reader.operation.deadline_utc!=borrowed.original_deadline_utc
            or reader.operation.selection_digest!=reader.selection_digest
            or runtime_storage_v3(reader.db)is not reader.operation.handle
            or reader.graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp
            or _validate_borrowed_full_scope_v3(reader)!=reader.fence):
        raise AuthorityUnavailable('D13 counter FULL changed its original Scope/Owner/Self/resource/selection')
    if meter is not None:
        from ..runtime_storage_v3 import _QUANTUM
        current=_QUANTUM.get()
        if current is None or current[2]is not meter:
            raise AuthorityUnavailable('D13 counter FULL metadata changed the actual reserved quantum')
        reader.operation.handle.require_current(meter)
    return reader


def prepare_current_graph_full_read_in_d13_counter_scope_v1(graph,bootstrap,*,
        installed_bundle,scope,owner_issuance,owner_guard,current_owner,
        request_lifetime,deadline_utc):
    require_graph_storage_work_admission_v3(graph)
    from .d13_counter_prepare_owner_v1 import (
        require_actual_d13_counter_owner_issuance_v1,bind_current_d13_counter_owner_child_v1,
        require_d13_counter_owner_child_deadline_v1)
    require_actual_d13_counter_owner_issuance_v1(
        owner_issuance,graph,owner_issuance.authority,owner_issuance.operation_id)
    namespace=graph._require_d13_counter_prepare_full_scope_v1(bootstrap,
        installed_bundle=installed_bundle,scope=scope,owner_issuance=owner_issuance,
        owner_guard=owner_guard,current_owner=current_owner)
    if namespace!=scope.namespace or type(request_lifetime)is not ExitStack:
        raise AuthorityUnavailable('D13 counter FULL requires its actual namespace/request lifetime')
    deadline=_deadline_v3(deadline_utc)
    if deadline is None:
        raise AuthorityUnavailable('D13 counter FULL requires its finite original Root resource deadline')
    instruction=owner_issuance.instruction
    deadline=min(deadline,instruction.expires_at_utc,instruction.prospective_plan_deadline_utc,
        require_d13_counter_owner_child_deadline_v1(owner_issuance,graph))
    borrowed=_D13CounterBorrowedScopeV1(_ISSUER,graph,bootstrap,installed_bundle,
        scope,owner_issuance,owner_guard,current_owner,deadline)
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,scope.operation_id,deadline)
    reader=None
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            fence=graph._validate_d13_counter_prepare_full_scope_v1(borrowed)
            reader=_OrdinaryFullReadV3(graph,operation,fence,D13_COUNTER_PREPARE_FULL_V1,
                authority=owner_issuance.authority,borrowed=borrowed,
                source_locator=_CurrentSourceEntryLocatorV3(instruction.c02_operation_id,instruction.source_ref.ref),
                request_lifetime=request_lifetime)
            reader.owner_binding,reader.owner_guard=current_owner,owner_guard
            reader.d13_counter_owner_issuance=owner_issuance
            reader.d13_counter_instruction=instruction
            reader.d13_counter_resource_metadata_ready=False
            reader.d13_counter_resource_inputs_ready=False
        work=_work_v3(graph,reader,deadline)
        _D13_COUNTER_FULL_V1[reader]=_d13_counter_full_identity_v1(reader)
        work.adopt_request_lifetime_v3(request_lifetime)
        bind_current_d13_counter_owner_child_v1(owner_issuance,work)
        return work
    except BaseException:
        if reader is not None:_D13_COUNTER_FULL_V1.pop(reader,None)
        _D13_COUNTER_BORROWED_V1.pop(borrowed,None)
        try:finish_runtime_storage_operation_v3(operation)
        finally:request_lifetime.close()
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


def prepare_current_graph_full_read_in_saved_natural_scope_v3(graph,bootstrap,*,
        installed_bundle,scope,parent_original_id,source_ref,request_lifetime,deadline_utc):
    """Only Root's independently issued current READ may disclose a saved frozen original."""
    require_graph_storage_work_admission_v3(graph)
    borrowed=(bootstrap,installed_bundle,scope,parent_original_id,source_ref)
    fence=graph._validate_natural_saved_full_read_scope_v3(borrowed)
    deadline=_deadline_v3(deadline_utc)
    if deadline is None or deadline!=fence.deadline_utc or type(request_lifetime)is not ExitStack:
        raise AuthorityUnavailable('saved natural original requires its finite original request lifetime')
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,scope.operation_id,deadline)
    if operation is None:raise AuthorityUnavailable('saved natural original requires installed Source storage')
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            reader=_OrdinaryFullReadV3(graph,operation,fence,NATURAL_SAVED_ORIGINAL_FULL_READ_V3,
                borrowed=borrowed,source_locator=_CurrentSourceEntryLocatorV3(parent_original_id,source_ref),
                request_lifetime=request_lifetime)
        work=_work_v3(graph,reader,deadline)
        work.adopt_request_lifetime_v3(request_lifetime)
        return work
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
            if _validate_borrowed_full_scope_v3(reader)!=reader.fence:
                raise AuthorityUnavailable('actual borrowed natural producer stamp changed')
        if reader.producer_phase is not None:
            from .dispatch_initial_source_read_v3 import prepare_pending_host_natural_roster_metadata_v3
            prepare_pending_host_natural_roster_metadata_v3(reader)
        outside_producer=(reader.producer_progress is not None and reader.prepared_producer_members is None
            and(reader.producer_progress.complete or reader.producer_progress.phase=='protected_observation'))
        if work.phase=='selector_clock':
            if reader.db.in_transaction:raise AuthorityUnavailable('FULL selector clock retained Graph SQL')
            from .first_ingress_v2 import trusted_upper
            from ..host.authority_profile import current_owner_metadata_installation_v3
            bundle=current_owner_metadata_installation_v3(graph)[0]
            policy=graph._GraphCoordinator__scene_clock_policy
            if bundle.ingress_clock!=policy:raise AuthorityUnavailable('FULL selector clock differs from actual installed policy')
            reader.metadata_clock_reading=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(policy)
            reader.metadata_now=trusted_upper(reader.metadata_clock_reading)
            work.phase='metadata_selection'
        elif work.phase=='owner_metadata':
            if reader.db.in_transaction:raise AuthorityUnavailable('FULL Owner pairing retained Graph SQL')
            from ..authority_service.owner_location_read_v3 import prepare_current_host_full_read_owner_entry_v3
            if reader.owner_task is None:reader.owner_task=prepare_current_host_full_read_owner_entry_v3(reader)
            if reader.owner_task.advance():
                entry=reader.owner_task.take_result_v3();reader.owner_task=None
                try:
                    binding=entry.require_permission_v3(reader);reader.owner_entry=entry
                    reader.owner_binding=binding;reader.owner_guard=entry.current_owner_guard
                except BaseException:
                    entry.release_v3();raise
                work.phase='source_material'
        elif work.phase=='commitment_scope_observation':
            if reader.db.in_transaction:raise AuthorityUnavailable('named Scope protected observation retained SQL')
            reader.commitment_scope_task.observe_protected_v1()
            work.phase='source_material'
        elif work.phase=='d13_collection':
            from .graph_d13_cache_use_collection_v2 import advance_graph_full_read_d13_collection_v2
            if advance_graph_full_read_d13_collection_v2(reader):
                with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                    reader.complete=True;reader._reserve(reader.reserved+65536)
                    reader.result=PreparedCurrentGraphFullReadV3(_ISSUER,reader)
        elif outside_producer:
            if reader.db.in_transaction:raise AuthorityUnavailable('protected producer observation retained a transaction')
            reader.advance_producer_outside_quantum_v3()
        else:
            with reader.store._lock:
                if reader.db.in_transaction:raise AuthorityUnavailable('ordinary full-read continuation retained a transaction')
                if graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp or reader.store._registry.catalogue_hash!=reader.catalogue_hash:
                    raise AuthorityUnavailable('ordinary full-read original stamp/catalogue changed')
                reader.advance()
        if reader.borrowed is None:graph._validate_read_fence_v3(reader.fence)
        else:_validate_borrowed_full_scope_v3(reader)
    return GraphStorageStepV3('complete',reader.result)if reader.complete else GraphStorageStepV3('progress')


def finish_current_graph_full_read_v3(graph,work,error):
    reader=work.state
    failure=error
    try:
        if reader.borrowed is None:graph._finish_read_fence_v3(reader.fence)
        if error is None:work.result_lease=work.operation
    except BaseException as finish_error:
        failure=finish_error
        raise
    finally:
        if failure is not None or work.result_lease is None:
            if reader.producer_progress is not None:
                from .natural_producer_qualification_v1 import release_host_natural_producer_payload_v3
                release_host_natural_producer_payload_v3(reader.producer_progress)
            if reader.prefinal is not None:reader.prefinal.release_payload_v3()
            reader.prepared_producer_members=reader.producer_frame=None
            reader.prefinal=None
        reader.cell=reader.parser=reader.pending=reader.body=reader.fragment=reader.result=None
        reader.atoms=reader.producer_progress=None
        # The retained producer and its before-frozen Source ALL still consume
        # these exact original indexes after terminal mappers and before release.
        if failure is not None or work.result_lease is None:
            reader.sources=reader.heads=reader.source_material=None
        if failure is not None:
            try:
                if not work.operation.closed:
                    work.operation.transfer_payload_release_v3(lambda:release_current_graph_full_receiver_v3(work))
                    finish_runtime_storage_operation_v3(work.operation)
                else:release_current_graph_full_receiver_v3(work)
            except BaseException as cleanup_error:
                cleanup_error.__cause__=failure
                raise


def release_current_graph_full_result_v3(work,proof):
    """Actual final result-retention callback; metadata disposal alone never drops pins."""
    if type(work.state)is not _OrdinaryFullReadV3 or proof.work is not work or proof.operation is not work.operation:
        raise AuthorityUnavailable('D13 receiver release changed its original full-read result ownership')
    proof.release_payload_v3()
    if not work.operation.closed:
        work.operation.transfer_payload_release_v3(lambda:release_current_graph_full_receiver_v3(work))
        return
    release_current_graph_full_receiver_v3(work)


def release_current_graph_full_receiver_v3(work):
    if not work.operation.closed:
        raise AuthorityUnavailable('D13 receiver final release requires its actual closed retention operation')
    reader=work.state
    if reader.contract is D13_COUNTER_PREPARE_FULL_V1:
        from .d13_counter_prepare_resource_inputs_v1 import release_d13_counter_prepare_resources_v1
        release_d13_counter_prepare_resources_v1(reader)
        _D13_COUNTER_TERMINALS_V1.pop(reader,None)
        _D13_COUNTER_FULL_V1.pop(reader,None)
        _D13_COUNTER_BORROWED_V1.pop(reader.borrowed,None)
    from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
    release_inspection_metadata_owner_v3(reader)
    if reader.owner_task is not None:reader.owner_task.release_v3();reader.owner_task=None
    if reader.owner_entry is not None:
        reader.owner_entry.release_v3();reader.owner_entry=reader.owner_binding=reader.owner_guard=None
    if reader.producer_metadata is not None:
        reader.producer_metadata.release_v3();reader.producer_metadata=None
    if reader.source_rights_seal is not None:
        reader.source_rights_seal.release_v3();reader.source_rights_seal=None
    if reader.metadata_selection is not None:
        _FULL_SELECTIONS_V3.pop(reader.metadata_selection,None);reader.metadata_selection=None
    if reader.artifact_metadata is not None:
        _ARTIFACT_HISTORY_V3.pop(reader.artifact_metadata,None)
        _ARTIFACT_METADATA_V3.pop(reader.artifact_metadata,None)
        reader.artifact_metadata.history_columns.clear();reader.artifact_metadata=None
    if reader.prefinal is not None:
        reader.prefinal.release_payload_v3();reader.prefinal=None
    from .role_control_lineage_metadata_v4 import release_role_control_lineage_metadata_v4
    release_role_control_lineage_metadata_v4(reader);reader.role_lineage_task=None
    if reader.role_control_original is not None:
        reader.role_control_original._frozen_value=None
        reader.role_control_original.nodes.clear();reader.role_control_original.scalar.clear()
        reader.role_control_original.fragment=b'';reader.role_control_original=None
    reader.metadata_cells.clear();reader.projection=None;reader.body_keys=None;reader.body_eof=False
    reader.sources=reader.heads=reader.source_material=None
    reader.source_inspections.clear();reader.source_inspection_task=None
    _ORDINARY_READERS_V3.discard(reader)
    if reader.artifact_receipt_task is not None:
        from .artifact_receipt_original_read_v1 import release_artifact_receipt_original_task_v3
        release_artifact_receipt_original_task_v3(reader.artifact_receipt_task)
        reader.artifact_receipt_task=reader.artifact_receipt_originals=None
    if reader.commitment_recovery_task is not None:
        reader.commitment_recovery_task.release_v1()
        reader.commitment_recovery_task=None
    if reader.commitment_terms_locator is not None:
        reader.commitment_terms_locator.release_v3()
        reader.commitment_terms_locator=None
    if reader.commitment_scope_task is not None:
        reader.commitment_scope_task.release_v1()
        reader.commitment_scope_task=None
    if reader.d13_collection is not None:
        reader.d13_collection.release_payload_v3()
        reader.d13_collection=None
    from .d13_cache_use_admission_v2 import release_graph_d13_cache_use_v2
    release_graph_d13_cache_use_v2(work)
    from .dispatch_initial_source_read_v3 import release_host_natural_roster_metadata_for_work_v3
    release_host_natural_roster_metadata_for_work_v3(work)
    from .d13_natural_original_use_v3 import request_graph_natural_original_release_v3
    request_graph_natural_original_release_v3(work)


@dataclass(frozen=True,init=False)
class _ActualWriteTypedProjectionV3(_FixedTypedProjectionV3):
    def __init__(self,issuer,base,atoms,epoch,heads):
        if issuer is not _ISSUER:raise TypeError('actual writer projection issuer required')
        object.__setattr__(self,'_types',base.projection._types)
        object.__setattr__(self,'_operation',base.operation)
        object.__setattr__(self,'_heads',MappingProxyType(dict(heads)))
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
        self.projection=_ActualWriteTypedProjectionV3(_ISSUER,base,tuple(frozen[key]for key in sorted(frozen)),facts.after_stamp[1],heads)
        self.sources,self.heads=base.sources,MappingProxyType(heads)
        _WRITE_VIEW_ISSUED[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.base,self.facts,self.facts._identity_v3(),self.graph,self.db,self.namespace,self.work,self.ticket,
            self.operation,self.contract,self.scope,self.graph_stamp,self.query,self.selection_digest,self.catalogue_hash,
            self.authority_epochs,self.owner_head,self.prepared_families,self.coverage,self.coverage_kind,
            self.projection,(self.projection._types,self.projection._atoms,self.projection._heads,self.projection.epochs),self.sources,self.heads,
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


NATURAL_CURRENT_DISPATCH_FAMILY_V1 = "natural-p2.closed-current-read.v1"


@dataclass(frozen=True)
class _NaturalDispatchFixedProjectionV1:
    _projection: object

    @property
    def epochs(self):
        return self._projection.epochs

    @property
    def atoms(self):
        raise AuthorityUnavailable("Natural closed dispatch cannot provide a whole Body snapshot")

    def get(self, key):
        return self._projection.get(key)

    def atoms_for_types_v3(self, types):
        return self._projection.atoms_for_types_v3(types)


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
        return self._projection.atoms_for_types_v3(types)


class _DispatchFullReadBindingV3:
    def __init__(self,proof,graph,db):
        self.proof,self.graph,self.db=proof,graph,db
        self.qualification=None
        if proof.family == 'natural_reply':
            from .natural_dispatch_p2_read_v1 import NaturalP2ClosedProjectionV1
            if (proof.coverage_profile != 'sylanne.natural-p2-closed-source-read.v1'
                    or type(proof.projection) is not NaturalP2ClosedProjectionV1):
                raise AuthorityUnavailable('Natural P2 closed coverage profile is absent')
            self.projection = _NaturalDispatchFixedProjectionV1(proof.projection)
        elif proof.family=='private_reply':
            from .private_dispatch_source_read_v3 import PrivateDispatchProjectionV3
            if (proof.coverage_profile!='sylanne.private-p2-metadata-source-read.v3'
                    or type(proof.projection)is not PrivateDispatchProjectionV3):
                raise AuthorityUnavailable('private P2 exact metadata/Source/selected Body profile is absent')
            self.projection=_DispatchFixedProjectionV3(proof.projection)
        else:
            self.projection=_DispatchFixedProjectionV3(proof.projection)
    def require_current(self,graph,db,namespace,*,required_families):
        families = (frozenset({NATURAL_CURRENT_DISPATCH_FAMILY_V1, SOURCE_METADATA_FAMILY_V3})
            if self.proof.family == 'natural_reply' else
            frozenset({CURRENT_DISPATCH_FAMILY_V3, SOURCE_METADATA_FAMILY_V3, RUNTIME_JOB_FAMILY_V3}))
        if (_BOUND.get()is not self or graph is not self.graph or db is not self.db
                or namespace!=self.proof.namespace or self.qualification is None
                or not set(required_families)<=families
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
        with bind_runtime_storage_operation_v3(proof.operation,db):
            task=proof.named_commitment_task
            if task is None:
                yield proof
            else:
                with task.bind_v1(proof,db):yield proof
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
        from .dispatch_initial_source_read_v3 import bind_host_natural_roster_operation_v3
        with bind_runtime_storage_operation_v3(proof.operation,db),bind_host_natural_roster_operation_v3(proof,db):yield proof
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
    bound = _BOUND.get()
    if type(bound) is _DispatchFullReadBindingV3 and bound.proof.family == 'natural_reply':
        if not types <= bound.proof.projection.complete_control_families:
            raise AuthorityUnavailable('Natural typed consumer requested an unprepared full Body family')
        families = frozenset({NATURAL_CURRENT_DISPATCH_FAMILY_V1})
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,required_families=families)
    projection,actual_query=require_bound_graph_full_read_v3(proof.graph,db,namespace,required_families=families)
    if type(query)is not QueryEpoch or query!=actual_query:
        raise AuthorityUnavailable('typed FULL consumer query differs from its actual EOF proof')
    return proof,projection,types


def require_bound_graph_full_atom_rows_v3(db,namespace,query,type_names,columns,*,valid_only=True,name=None):
    if not set(columns)<=frozenset({'token','revision','valid','type_name','value'}):
        raise AuthorityUnavailable('typed FULL rows require their fixed registered columns')
    proof,projection,types=_require_bound_typed_projection_v3(db,namespace,query,type_names)
    bound=_BOUND.get()
    if type(bound)is _DispatchFullReadBindingV3 and bound.proof is proof and proof.family=='private_reply':
        return proof.atom_rows(db,namespace,query,tuple(types),columns,valid_only=valid_only,name=name)
    if type(projection)in(_FixedTypedProjectionV3,_ActualWriteTypedProjectionV3):
        atoms=projection._complete_atoms_for_types_v3(types,valid_only=valid_only,name=name)
    else:atoms=projection.atoms_for_types_v3(types)
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


class _FullMetadataSelectionV3:
    """One actual metadata EOF chooses exact keys and declares R/P requests."""
    def __init__(self,issuer,reader,*,selected_keys,groups):
        if issuer is not _ISSUER or reader not in _ORDINARY_READERS_V3 or reader.prefinal is None:
            raise AuthorityUnavailable('actual same-Work FULL metadata selection issuer required')
        self.reader,self.prefinal=reader,reader.prefinal
        self.keys=tuple(sorted(set(selected_keys)))
        self.groups=tuple((purpose,tuple(audiences),tuple(dict.fromkeys(roots)))for purpose,audiences,roots in groups)
        allowed={'context','expression'}|({'consolidation'}if reader.contract is ARTIFACT_RECEIPT_FULL_READ_V1 else set())
        if not self.groups or any(not audiences or purpose not in allowed for purpose,audiences,_ in self.groups):
            raise AuthorityUnavailable('FULL selection requires its actual requested R/P purpose/audience groups')
        roots={ref for _,_,refs in self.groups for ref in refs}
        if any(len(refs)>32 for _,_,refs in self.groups):
            raise AuthorityUnavailable('FULL Source group roots exceed the original bound')
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source'or(key.owner.bot,key.owner.persona)!=reader.namespace.as_tuple:
                raise AuthorityUnavailable('FULL metadata Source root belongs to another actual namespace')
        if any(token not in reader.heads for token in self.keys):
            raise AuthorityUnavailable('FULL selected key has no actual complete namespace head')
        self.coverage=(reader.count,reader.root,reader.graph_stamp,reader.selection_digest,reader.owner_head,reader.authority_epochs)
        self.heads=tuple((token,reader.heads[token])for token in self.keys)
        self.clock=reader.metadata_clock_reading;self.policy_before=reader.policy_recipe_expiry;self.policy_context=reader.policy_context;self.policy_keys=reader.policy_keys
        self.policy_requests=reader.policy_requests;self.policy_request_bases=reader.policy_request_bases;self.policy_request_keys=reader.policy_request_keys
        self.ingress_original=None if reader.source_material is None else reader.source_material.ingress_metadata_original
        self.policy_census=tuple(sorted((token,head)for token,head in self.prefinal.heads.items()
            if AtomKey.from_token(token).type_name in _FULL_POLICY_TYPES_V3))
        if self.clock is not None:
            boundaries=[]
            subject,target,route=reader.policy_context
            for original in self.prefinal.metadata.values():
                kind=original.key.type_name
                if kind not in {'d03.account_binding','d03.role_binding','d05.boundary_rule'}or not original.valid:continue
                value=_detach_value_v3(original.selectors);probe=dict(value)
                start,end=('effective_from','effective_until')if kind=='d03.role_binding'else('valid_from','valid_until')
                probe[start]=reader.metadata_now;probe[end]=None
                if not any(_full_policy_decision_v3(kind,probe,subject=subject,target=target,route=route,now=reader.metadata_now,request=request)for request in self.policy_requests):continue
                for name in (start,end):
                    boundary=value[name]
                    if boundary is None:continue
                    inclusive_end=name==end and kind!='d03.account_binding'
                    if boundary>reader.metadata_now or inclusive_end and boundary==reader.metadata_now:
                        boundaries.append(math.nextafter(float(boundary),math.inf)if inclusive_end else float(boundary))
            if boundaries:self.policy_before=min(boundaries+([]if self.policy_before is None else[self.policy_before]))
        _FULL_SELECTIONS_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.reader,self.prefinal,self.keys,self.groups,self.coverage,self.heads,self.clock,self.policy_before,self.policy_context,self.policy_keys,self.policy_census,self.policy_requests,self.policy_request_bases,self.policy_request_keys,self.ingress_original)
    def require_for_v3(self,reader):
        if (_FULL_SELECTIONS_V3.get(self)!=self._identity_v3()or self.reader is not reader
                or reader not in _ORDINARY_READERS_V3 or reader.prefinal is not self.prefinal
                or reader.metadata_selection is not self or reader.owner_groups!=self.groups
                or self.coverage!=(reader.count,reader.root,reader.graph_stamp,reader.selection_digest,reader.owner_head,reader.authority_epochs)
                or self.heads!=tuple((token,self.prefinal.heads.get(token))for token in self.keys)):
            raise AuthorityUnavailable('actual FULL metadata selection changed its original Work/census/requests')
        self.prefinal._actual()
        if self.policy_before is not None:
            from time import monotonic
            from .first_ingress_v2 import trusted_upper_at_v4
            if trusted_upper_at_v4(self.clock,monotonic())>=self.policy_before:
                raise AuthorityUnavailable('actual policy applicability crossed its declared metadata time boundary')
        return self

    @property
    def policy_versions(self):
        from ..graph_types import GraphVersion
        return tuple(GraphVersion(AtomKey.from_token(token),head[0])for token,head in self.policy_census)
    def require_policy_for_v3(self,proof,db,query,*,subject,target,route,now,action_kind,purpose):
        actual=_require_full_policy_selection_v3(proof,db,query)
        request=(action_kind,purpose)
        if (actual is not self or (subject,target,route)!=self.policy_context or request not in self.policy_requests
                or type(now)not in(int,float)or not math.isfinite(now)):
            raise AuthorityUnavailable('policy applicability request differs from its actual metadata Source selector')
        for token,head in self.policy_census:
            original=self.prefinal.metadata[token];original.require_v3(self.reader)
            if not original.valid:continue
            key=original.key;value=_detach_value_v3(original.selectors)
            selected=_full_policy_decision_v3(key.type_name,value,subject=subject,target=target,route=route,now=now,request=request)
            if key.type_name=='d03.account_binding'and value['valid_until']is not None and now>=value['valid_until']:selected=False
            if selected!=(token in dict(self.policy_request_keys)[request]):
                raise AuthorityUnavailable('policy metadata predicate changed from its SourceALL selected keys')
        return self


def require_current_full_owner_reader_v3(reader):
    """Closed OwnerEntry caller; a domain lease alone grants no R/P permission."""
    from ..host.authority_profile import current_owner_metadata_installation_v3
    if (type(reader)is not _OrdinaryFullReadV3 or reader not in _ORDINARY_READERS_V3
            or reader.work is None or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.coordinator is not reader.graph or reader.operation.closed
            or type(reader.metadata_selection)is not _FullMetadataSelectionV3):
        raise AuthorityUnavailable('actual same-Work FULL metadata/selection Owner caller required')
    _contract_v3(reader.contract)
    selection=reader.metadata_selection.require_for_v3(reader)
    graph=reader.graph;scope=reader.fence.scope;port=graph._GraphCoordinator__content_fence_v2
    bundle,_,_=current_owner_metadata_installation_v3(graph)
    if (scope.namespace!=reader.namespace or reader.fence.metadata!=reader.graph_stamp[0]
            or reader.fence.epoch!=reader.graph_stamp[1]or scope.generation!=reader.graph_stamp[0].requirements.activation_generation
            or bundle.installation_policy.namespace!=reader.namespace
            or scope.authority_namespace!=bundle.installation_policy.authority_namespace
            or port.installation_grant.installation_id!=bundle.installation_policy.installation_id):
        raise AuthorityUnavailable('FULL Owner caller changed actual installation/READ scope/Graph stamp')
    if reader.borrowed is None:
        if scope.operation!='read' or reader.fence.authority is not reader.authority:
            raise AuthorityUnavailable('ordinary FULL Owner permission requires its actual original READ')
        graph._authorize(reader.lease,reader.authority,reader.contract.domains,owner_read=reader.contract.owner_read)
    elif _validate_borrowed_full_scope_v3(reader)!=reader.fence:
        raise AuthorityUnavailable('borrowed FULL Owner permission left its exact installed natural scope')
    return graph,port,bundle,scope,selection.groups


_METADATA_RECOVERY_ISSUED_V3=WeakKeyDictionary()


class PreparedCurrentGraphFullMetadataRecoveryV3:
    """An original metadata recovery result, with no FULL or Body capability."""
    def __init__(self,issuer,reader):
        from .d08_commitment_recovery_read_v1 import CommitmentCommunicationRecoveryReadV1
        task=reader.commitment_recovery_task
        if (issuer is not _ISSUER or reader not in _ORDINARY_READERS_V3
                or reader.contract is not COMMITMENT_COMMUNICATION_FULL_READ_V1
                or type(task)is not CommitmentCommunicationRecoveryReadV1 or not task.complete or task.result is None
                or reader.metadata_selection is None or reader.owner_entry is None):
            raise AuthorityUnavailable('actual metadata-only named recovery issuer required')
        reader.metadata_selection.require_for_v3(reader);reader.owner_entry.require_for_v3(reader)
        self.graph,self.namespace,self.work,self.operation=reader.graph,reader.namespace,reader.work,reader.operation
        self.recovery_task=task
        _METADATA_RECOVERY_ISSUED_V3[self]=(self.graph,self.namespace,self.work,self.operation,task)
    def require_current_v3(self,graph,work):
        if (_METADATA_RECOVERY_ISSUED_V3.get(self)!=(self.graph,self.namespace,self.work,self.operation,self.recovery_task)
                or graph is not self.graph or work is not self.work or work.operation is not self.operation
                or work.coordinator is not graph or self.operation.closed or work.state.commitment_recovery_task is not self.recovery_task):
            raise AuthorityUnavailable('actual same-Work metadata recovery result changed')
        work.state.metadata_selection.require_for_v3(work.state)
        work.state.owner_entry.require_for_v3(work.state)
        return self
    def release_payload_v3(self):
        if _METADATA_RECOVERY_ISSUED_V3.pop(self,None)is None:return
        self.recovery_task.release_v1()
        self.work.state.commitment_recovery_task=None
        self.recovery_task=None


_FULL_METADATA_CELLS_V3=WeakKeyDictionary()
_FULL_METADATA_FIELDS_V3=MappingProxyType({
 'd07.current_interpretation.v1':('interpretation_id','source_refs'),
 'd11.life_fact_eligibility.v1':('fact_ref','fact_revision','provenance_ref','provenance_revision'),
 'd11.life_fact_provenance.v1':('binding','fact_ref','reads'),
 'd07.focus.v1':('persona_id','focus_epoch','primary_ticket_ref','auxiliary_ticket_refs'),
 'd07.attention_ticket.v1':('ticket_id','causal_root','source_refs','category','eligible','resources_available','valid_until','cancel_refs'),
 'd03.world_event':('event_id','kind','scene_ref','source_refs','reality'),
 'd08.goal.v1':('goal_id','revision','state','reason_refs','dependency_refs','deadline_ref','progress_refs'),
 'd08.commitment.v1':('commitment_id','revision','subject_ref','counterparty_ref','establishment_kind','establishment_state',
    'fulfillment_state','deadline_ref','communicated_refs','acknowledged_refs','parent_revision_ref','source_refs'),
 'd08.action_schema.v1':('schema_ref','schema_id','action_ref','action_revision','operation','intent_digest','action_kind','purpose','proactive','schema_hash'),
 'd08.action_intent.v1':('action_id','revision','goal_ref','commitment_refs','target_ref','action_kind','purpose',
    'identity','schema_id','effect_scope','compensation_ref','source_refs'),
 'd08.action_outcome.v1':('action_ref','action_revision','operation_id','activity_id','effect_id','status','source_refs','outcome_refs'),
 'd08.action_cancellation.v1':('action_id','action_revision','activity_id','attempt_id','effect_id','cancel_epoch','state','source_refs','operation_id'),
 'd10.contact_policy.v1':('policy_id','subject_persona_ref','target_entity_ref','audience_ref','scene_ref','source_refs','status','valid_from','valid_until'),
 'd10.proactive_opportunity.v1':('opportunity_id','target_entity_ref','scene_ref','source_refs','status','valid_until'),
 'd10.contact_claim.v1':('claim_id','target_entity_ref','conversation_ref','source_refs','action_ref','status','operation_id'),
 'd10.contact_claim.v2':('claim_id','target_entity_ref','conversation_ref','source_refs','action_ref','status','operation_id'),
 'd08.contact_expression_plan.v2':('plan_id','source_refs','action_ref','target_ref','audience_ref','scene_ref','read_versions','valid_until_utc'),
 'd08.contact_expression_plan_provenance.v2':('plan_ref','source_refs','read_versions','operation_id','claim_ref'),
 'd08.contact_expression_plan_eligibility.v2':('plan_ref','source_refs','read_versions','status','valid_until_utc'),
 'd09.verified_segment_batch.v1':('c02_operation_id','source_ref','plan_ref','generation_original_id','review_original_id','segment_count','batch_digest'),
 'd08.communication_intent_grant.v1':('grant_id','action_ref','source_refs','audience_scope','operation_id','effect_id','status'),
})


def _advance_full_role_control_metadata_v3(reader,meter):
    from ..domains.d01 import _activation_key
    from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    reader.prefinal.require_current(meter=meter)
    if reader.role_control_original is None:
        head=reader.prefinal.heads.get(_activation_key(reader.namespace).token)
        exists=None if head is None else meter.read_fixed_row(reader.db,'graph_role_init_receipts_v1',
            ('bot','persona'),'bot=? AND persona=?',reader.namespace.as_tuple)
        if exists is None:
            reader.role_control_metadata_ready=True;return
        reader.role_control_original=DispatchOriginalJSONReadV3(reader,table='graph_role_init_receipts_v1',
            column='receipt_json',key_columns=('bot','persona'),key=reader.namespace.as_tuple)
    if reader.role_control_original.advance(meter):reader.role_control_metadata_ready=True


def _full_role_control_metadata_v4(reader,current_guard,meter):
    from dataclasses import replace
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..domains.d01 import PersonaDomain,_activation_key
    from ..graph_types import GraphAtom,GraphSnapshot,GraphVersion,Owner
    if reader not in _ORDINARY_READERS_V3 or type(current_guard)is not OwnerAuthorizationGuardV1 or current_guard!=reader.owner_guard:
        raise AuthorityUnavailable('D01 control metadata needs its actual FULL Work and Owner guard')
    pre=reader.prefinal;pre.require_current(meter=meter)
    activation_key=_activation_key(reader.namespace);grant_key=owner_grant_key(*reader.namespace.as_tuple)
    activation=pre.metadata_value_v3(activation_key)
    if activation is None or type(activation.get('plan_id'))is not str:
        raise AuthorityUnavailable('D01 activation control is absent from complete metadata EOF')
    plan_key=AtomKey(Owner('persona',*reader.namespace.as_tuple),'d01.persona_plan.v1',activation['plan_id'])
    keys=(activation_key,plan_key,grant_key)
    originals=tuple(pre.metadata.get(key.token)for key in keys)
    if any(original is None or not original.valid for original in originals):
        raise AuthorityUnavailable('D01 current activation/plan/Owner header is incomplete')
    values=[]
    for key,original in zip(keys,originals):
        original.require_v3(reader)
        head=meter.read_fixed_row(reader.db,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*reader.namespace.as_tuple,key.token))
        if head!=(original.revision,1,original.cell_id):
            raise AuthorityUnavailable('D01 control header changed after complete metadata EOF')
        values.append(_detach_value_v3(original.selectors))
    activation,plan,grant=values;epoch=reader.graph_stamp[1]
    control=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(tuple(
        GraphAtom(key,original.revision,value,True)for key,original,value in zip(keys,originals,values)if key!=plan_key),(epoch,)),
        namespace=reader.namespace,current_guard=current_guard)
    if(control.plan_key!=plan_key or plan.get('namespace')!={'bot_id':reader.namespace.bot_id,'persona_id':reader.namespace.persona_id}
            or plan.get('plan_id')!=plan_key.name or plan.get('version')!=control.plan_version
            or type(plan.get('authored'))is not bool):
        raise AuthorityUnavailable('D01 current plan-header identity differs from actual activation')
    control=replace(control,read_versions=tuple(GraphVersion(key,original.revision)for key,original in zip(keys,originals)),
        graph_epoch=epoch.revision)
    return control,epoch,tuple(_FullControlMetadataV3(key,original.revision,True,value,original.semantic_digest)
        for key,original,value in zip(keys,originals,values))


def _advance_full_role_lineage_metadata_v4(reader,meter):
    from ..domains.d01 import _activation_key
    from .role_control_lineage_metadata_v4 import prepare_role_control_lineage_metadata_v4
    reader.source_material.require_rights_seal_v3()
    if reader.prefinal.metadata_value_v3(_activation_key(reader.namespace))is None:
        reader.role_lineage_ready=True;return
    control,_epoch,_rows=_full_role_control_metadata_v4(reader,reader.owner_guard,meter)
    task=prepare_role_control_lineage_metadata_v4(reader,control)
    reader.role_lineage_task=task
    if task.advance(meter):reader.role_lineage_ready=True


def read_bound_graph_full_role_control_v3(db,namespace,query,*,current_guard):
    # Current D01 controls and actual initialized-head lineage; no Plan Body.
    bound=_BOUND.get()
    if type(bound)is not tuple or not bound or type(bound[0])not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
        return None
    from .role_control_lineage_metadata_v4 import require_role_control_lineage_metadata_v4
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    if proof.query!=query:raise AuthorityUnavailable('D01 control metadata query differs from its actual FULL Binder')
    base=proof.base if type(proof)is PreparedCurrentGraphFullWriteViewV3 else proof
    reader=base.work.state;base.rights_seal.require_v3()
    with runtime_storage_quantum_v3(db)as meter:
        control,epoch,rows=_full_role_control_metadata_v4(reader,current_guard,meter)
    if type(proof)is PreparedCurrentGraphFullWriteViewV3 and any(row.key in {v.key for v in control.read_versions}for row in proof.facts.rows):
        raise AuthorityUnavailable('D01 control writer delta requires new metadata preparation')
    lineage=require_role_control_lineage_metadata_v4(reader,control)
    if(lineage.current.plan_ref!=control.read_versions[1]or lineage.current.activation_ref!=control.read_versions[0]
            or lineage.current.plan_value_digest!=rows[1].whole_value_digest
            or lineage.current.activation_value_digest!=rows[0].whole_value_digest):
        raise AuthorityUnavailable('D01 current controls differ from their complete authenticated producer history')
    return control,epoch,rows



def _full_control_value_for_write_v3(prefinal,key):
    prefinal._actual();original=prefinal.metadata.get(key.token)
    if original is None:return None
    original.require_v3(prefinal.reader)
    return _detach_value_v3(original.selectors)


def _full_metadata_paths_v3(type_name):
    from ..graph_types import OWNER_GRANT_TYPE
    from ..memory_types import _ACCESS_FIELDS
    from .current_commitment_input_source_v3 import _SELECTOR_FIELDS
    if type_name==OWNER_GRANT_TYPE:
        fields=('schema','authority_id','installation_id','grant_id','principal','ticket_id','creation_operation_id',
            'creation_digest','issue_operation_id','grant_revision','state','scope','issuer_ref','capabilities','purposes',
            'audiences','activation_generation','graph_incarnation')
    elif type_name=='d01.persona_activation.v1':
        fields=('namespace','plan_id','plan_version','head_id','owner_grant_id','owner_grant_revision',
            'graph_incarnation','activation_generation','authorization_revision','state')
    elif type_name=='d01.persona_plan.v1':fields=('namespace','plan_id','version','authored')
    elif type_name=='memory.access':fields=tuple(_ACCESS_FIELDS)
    elif type_name in _SELECTOR_FIELDS:fields=_SELECTOR_FIELDS[type_name]
    elif type_name==NATURAL_PLAN_TYPE_V2:
        fields=('schema','plan_id','c02_operation_id','source_ref','final_activity_id','final_operation_id','final_effect_id',
            'focus_ref','ticket_ref','scene_id','audience_id','scene_ref','audience_ref','promise_grants','qualification_refs',
            'qualified_read_versions','valid_until_utc','status','version')
    elif type_name==_RUNTIME_JOB_TYPE_V3:
        fields=('schema','job_id','bot_id','persona_id','activity_id','operation_id','work_kind','budget_ref','status')
    elif type_name in {'d08.commitment_communication_intent.v1','d08.commitment_communication_intent.v2',
            'd08.commitment_fulfillment_terms.v1','d08.commitment_terms_acceptance.v1'}:
        from .current_commitment_fulfillment_source_v3 import _METADATA_FIELDS
        fields=(*_METADATA_FIELDS,'subject_ref','scene_ref')
    else:fields=_FULL_METADATA_FIELDS_V3.get(type_name,())
    return tuple((field,)for field in fields)


def _full_metadata_path_matches_v3(pattern,path):
    return len(path)>=len(pattern)and all(a==b or a=='*'and type(b)is int for a,b in zip(pattern,path))


def _full_metadata_event_v3(event,paths):
    if not event.path:return event.kind in ('object_start','object_end','array_start','array_end')
    if any(_full_metadata_path_matches_v3(pattern,event.path)for pattern in paths):return True
    return (event.kind in ('object_start','object_end','array_start','array_end')
        and any(len(pattern)>len(event.path)and all(a==b or a=='*'and type(b)is int
            for a,b in zip(pattern,event.path))for pattern in paths))


class _FullSelectorValueV3:
    def __init__(self,reader,type_name):
        from .c09_canonical_json_stream_v2 import _CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.reader,self.paths=reader,_full_metadata_paths_v3(type_name)
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
    def emit_v3(self,event):
        if _full_metadata_event_v3(event,self.paths):self.builder._emit(event)
    def finish_v3(self):
        if self.builder.nodes:raise AuthorityUnavailable('FULL metadata selector did not reach canonical container EOF')
        return self.builder.value


@dataclass(frozen=True,eq=False)
class _FullMetadataCellOriginalV3:
    reader:object
    key:object
    revision:int
    valid:bool
    cell_id:str
    header:tuple
    digest:str
    selectors:object
    semantic_digest:str
    def _identity_v3(self):
        return(self.reader,self.key,self.revision,self.valid,self.cell_id,self.header,self.digest,self.selectors,self.semantic_digest)
    def require_v3(self,reader):
        if (_FULL_METADATA_CELLS_V3.get(self)!=self._identity_v3()or self.reader is not reader
                or reader.operation.closed or (reader.prefinal.heads if reader.prefinal is not None else reader.heads).get(self.key.token)!=(self.revision,int(self.valid),self.cell_id)):
            raise AuthorityUnavailable('actual FULL metadata cell/head/EOF commitment changed')
        return self


@dataclass(frozen=True)
class _FullControlMetadataV3:
    key:object
    revision:int
    valid:bool
    value:object
    whole_value_digest:str|None=None



def _full_reference_key_v3(raw):
    from ..graph_types import Owner
    if type(raw)is str:return AtomKey.from_token(raw),None
    if type(raw)is not dict:return None
    if set(raw)=={'ref','version'}:return AtomKey.from_token(raw['ref']),raw['version']
    if set(raw)=={'key','revision'}:
        k=raw['key'];key=AtomKey.from_token(k)if type(k)is str else AtomKey(Owner(**k['owner']),k['type_name'],k['name'])
        return key,raw['revision']
    return None


def _full_policy_decision_v3(kind,value,*,subject,target,route,now,request):
    from .current_commitment_input_source_v3 import _policy_decision_v3
    # The shared decoder supplies the complete fixed selector validation. The
    # actual action recipe is separately issued by this FULL metadata census.
    ordinary=_policy_decision_v3(kind,value,subject=subject,target=target,route=route,now=now)
    if request==('message','expression')or kind not in {'d03.role_binding','d05.boundary_rule'}:
        return ordinary
    if request not in (('communication','expression'),('expression','reply')):
        raise AuthorityUnavailable('FULL policy action has no issued actual consumer recipe')
    from types import SimpleNamespace
    from ..domains.d03.context import RoleBinding,RoleBindingRequest
    from ..domains.d05.relationship import BoundaryRule
    projected=SimpleNamespace(**value)
    if route is None:return False
    if kind=='d03.role_binding':
        return RoleBinding.applies_to(projected,RoleBindingRequest(subject,target,None,route[4],request[0],request[1],now,True))
    return BoundaryRule.applies_to(projected,subject_persona_ref=subject,target_entity_ref=target,
        action_kind=request[0],audience_scope=route[1],scene_ref=route[4],at_time=now)


def _full_policy_requests_v3(reader,route):
    requests=[('message','expression')];bases=[];expiry=None
    if reader.contract is NATURAL_ROUTE_FULL_READ_V3:
        from .current_graph_source_material_v3 import require_natural_reply_context_metadata_v3
        reply_request,reply_bases,expiry=require_natural_reply_context_metadata_v3(reader.source_material,now=reader.metadata_now)
        requests.append((reply_request[4],reply_request[5]));bases.extend(reply_bases)
    if (reader.contract not in (NATURAL_MODEL_FULL_READ_V3,NATURAL_ROUTE_FULL_READ_V3,NATURAL_ADMIN_PREPARE_FULL_V3,D13_COUNTER_PREPARE_FULL_V1,NATURAL_SAVED_ORIGINAL_FULL_READ_V3)
            or reader.source_locator is None):
        return tuple(requests),tuple(bases),expiry
    from ..domains.d08.natural_plan import natural_plan_id_v2,natural_plan_key_v2,natural_final_effect_id_v2
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    pre=reader.prefinal;material=reader.source_material;parent=reader.source_locator.c02_operation_id
    plan_id=natural_plan_id_v2(reader.namespace,parent,material.source_ref);plan_basis=None
    for original in pre.metadata.values():
        if original.key.type_name!=NATURAL_PLAN_TYPE_V2 or not original.valid:continue
        value=_detach_value_v3(original.selectors)
        if value.get('c02_operation_id')!=parent:continue
        original.require_v3(reader)
        source=_full_reference_key_v3(value['source_ref']);focus=_full_reference_key_v3(value['focus_ref']);ticket=_full_reference_key_v3(value['ticket_ref'])
        deadline=value['valid_until_utc'];activity=value['final_activity_id']
        if (value['schema']!=NATURAL_PLAN_TYPE_V2 or value['version']!=1
                or value['status']!='scope_adopted_payload_pending' or value['plan_id']!=plan_id
                or type(activity)is not str or not activity
                or original.key!=natural_plan_key_v2(reader.namespace,activity,plan_id)
                or original.revision!=1
                or source is None or source!=(AtomKey.from_token(material.source_ref),pre.heads[material.source_ref][0])
                or focus is None or focus!=(material.focus_key,pre.heads[material.focus_key.token][0])
                or ticket is None or ticket!=(material.ticket_key,pre.heads[material.ticket_key.token][0])
                or(value['scene_id'],value['audience_id'])!=(route[4],route[1])
                or value['final_operation_id']!=post_c02_reply_operation_id(parent,material.source_ref)
                or value['final_effect_id']!=natural_final_effect_id_v2(reader.namespace,parent,material.source_ref)
                or type(deadline)not in(int,float)or not math.isfinite(deadline)or deadline<=reader.metadata_now):
            raise AuthorityUnavailable('natural communication policy recipe differs from its actual current plan metadata')
        if plan_basis is not None:raise AuthorityUnavailable('natural communication policy has more than one actual plan selector')
        plan_basis=(original.key.token,original.revision,original.cell_id,original.header,original.digest)
        bases.append(plan_basis);expiry=deadline if expiry is None else min(expiry,deadline)
    if plan_basis is not None:requests.append(('communication','expression'))
    return tuple(requests),tuple(bases),expiry


def _select_full_metadata_v3(reader,meter):
    from ..graph_types import Owner
    from ..runtime_contracts import NamespaceId,canonical_digest
    from .current_commitment_input_source_v3 import _SELECTOR_FIELDS,_policy_sources_v3
    pre=reader.prefinal;pre.require_current(meter=meter);material=reader.source_material
    if material.phase!='metadata_ready':raise AuthorityUnavailable('Source entry metadata EOF required for FULL selection')
    keys=set();queue=[];seen=set();roots=set(material.entry_roots);policy_roots=set();groups=[];policy_keys=set()
    if reader.contract is D13_COUNTER_PREPARE_FULL_V1:
        from .d13_counter_prepare_resource_inputs_v1 import require_d13_counter_prepare_resource_metadata_v1
        resource=require_d13_counter_prepare_resource_metadata_v1(reader,meter=meter)
        for token,head in resource.heads.items():
            if pre.heads.get(token)!=head:
                raise AuthorityUnavailable('D13 resource metadata differs from complete FULL head census')
        for key,version in resource.versions.items():
            head=pre.heads.get(key.token)
            if version.key!=key or (0 if head is None else head[0])!=version.revision:
                raise AuthorityUnavailable('D13 resource version differs from actual FULL census/absence')
        roots.update(resource.roots)
    requests,request_bases,recipe_expiry=_full_policy_requests_v3(reader,material.route)
    request_keys={request:set()for request in requests}
    route_lineage=set();route_pending=[material.source_ref]
    from ..memory_types import source_key
    while route_pending:
        ref=route_pending.pop()
        if ref in route_lineage:continue
        route_lineage.add(ref);witness=pre.sources.get(ref)
        if witness is not None:route_pending.extend(source_key(*reader.namespace.as_tuple,parent).token for parent in witness.metadata['parent_source_ids'])
    def add(raw,*,required=False,routing=False):
        located=_full_reference_key_v3(raw)
        if located is None:return
        key,revision=located
        if NamespaceId.from_key(key)!=reader.namespace:raise AuthorityUnavailable('FULL fixed metadata reference crossed namespace')
        head=pre.heads.get(key.token)
        if head is None:
            if required or revision not in(None,0):raise AuthorityUnavailable('FULL fixed metadata dependency is absent')
            return
        if revision is not None and revision!=head[0]:raise AuthorityUnavailable('FULL fixed metadata dependency revision differs')
        if key.type_name=='memory.source':
            if key.token in roots or key.token in route_lineage:roots.add(key.token)
            else:policy_roots.add(key.token)
            return
        if key.type_name in _SELECTOR_FIELDS and not routing:
            original=pre.metadata[key.token];value=_detach_value_v3(original.selectors)
            applicable=original.valid and any(_full_policy_decision_v3(key.type_name,value,
                subject='persona:'+reader.namespace.persona_id,target=target,route=route,now=reader.metadata_now,request=request)for request in requests)
            if key.type_name=='d03.account_binding'and value['valid_until']is not None and reader.metadata_now>=value['valid_until']:applicable=False
            if not applicable:
                if required:raise AuthorityUnavailable('required policy reference no longer matches the actual metadata predicate')
                return
        if key.token not in keys:keys.add(key.token);queue.append(key)
    def refs(value):
        if type(value)is dict:
            located=_full_reference_key_v3(value)
            if located is not None:add(value);return
            for part in value.values():refs(part)
        elif type(value)in(tuple,list):
            for part in value:refs(part)
        elif type(value)is str:
            # Only fixed selector ref fields reach this decoder; ordinary IDs
            # are not interpreted as an authority or arbitrary graph selector.
            try:key=AtomKey.from_token(value)
            except ValueError:return
            add(key.token)
    if reader.contract is ARTIFACT_RECEIPT_FULL_READ_V1:
        reader.artifact_metadata.require_metadata_v3(reader)
        receipt=reader.artifact_metadata.receipt
        roots.update(reader.artifact_metadata.roots)
        audiences=tuple(reader.authority.audience)
        groups.append(('consolidation',audiences,tuple(head.key.token for head,_ in receipt.parent_source_heads)))
        selector=receipt.selector
        for ref in (selector.task.cycle_job_ref,selector.decision_ref,selector.plan_ref,selector.method_ref,
                receipt.milestone_ref,receipt.full_check_ref,receipt.file_result_ref):refs(ref)
        from ..domains.d03.self_perspective import self_mapping_key
        add(self_mapping_key(reader.namespace).token,required=True)
        for version in reader.artifact_metadata.current_versions:
            add({'key':version.key.token,'revision':version.revision},required=True)
        for original in pre.metadata.values():
            if original.key.type_name in {'d09.verified_segment_batch.v1','d08.communication_intent_grant.v1'}:
                value=_detach_value_v3(original.selectors)
                if value.get('operation_id')==receipt.message_operation_id or value.get('source_ref')==receipt.source_ref:
                    add(original.key.token)
        route=material.route;target=material.target
    else:
        audiences=(material.conversation_ref,);route=material.route;target=material.target
        if reader.commitment_scope_ref is not None:
            scope=pre.metadata_value_v3(AtomKey.from_token(reader.commitment_scope_ref),revision=1,meter=meter)
            if (scope['subject_ref']!='persona:'+reader.namespace.persona_id
                    or(scope['platform_ref'],scope['conversation_ref'],scope['scene_ref'])!=(route[0],route[1],route[4])
                    or material.source_ref not in scope['source_refs']
                    or scope.get('route_source_ref',material.source_ref)!=material.source_ref):
                raise AuthorityUnavailable('named metadata selector changed its approved subject or actual route')
            target=scope['target_ref']
        add(material.focus_key.token,required=True);add(material.ticket_key.token,required=True)
        platform,conversation,sender,_,_=route
        route_suffix=canonical_digest({'namespace':reader.namespace.as_tuple,'platform_ref':platform,'sender_ref':sender})
        add(AtomKey(Owner('persona',*reader.namespace.as_tuple),'d03.entity_anchor','entity:account-v1:'+route_suffix).token,required=True,routing=True)
        add(AtomKey(Owner('persona',*reader.namespace.as_tuple),'d03.account_binding','account:v1:'+route_suffix).token,required=True,routing=True)
        platform,conversation,sender,message,scene=route
        source_id=AtomKey.from_token(material.source_ref).owner.subject
        event_id='world:message-arrival-v1:'+canonical_digest({'namespace':reader.namespace.as_tuple,
            'platform_ref':platform,'conversation_ref':conversation,'message_id':message,'source_id':source_id})
        add(AtomKey(Owner('event',*reader.namespace.as_tuple,event_id),'d03.world_event','current').token,required=True)
        for original in pre.metadata.values():
            key=original.key;value=_detach_value_v3(original.selectors)
            if key.type_name==NATURAL_PLAN_TYPE_V2 and value.get('c02_operation_id')==reader.source_locator.c02_operation_id:
                source=value.get('source_ref')
                if type(source)is not dict or source.get('ref')!=material.source_ref:
                    raise AuthorityUnavailable('natural plan metadata changed its actual C02 Source')
                add(key.token)
        if reader.producer_metadata is not None:
            metadata=reader.producer_metadata;metadata.require_current_v3()
            if not metadata.complete:raise AuthorityUnavailable('producer metadata did not reach complete EOF')
            roots.update(metadata.roots)
            for key in metadata.keys:add(key.token)
        if reader.commitment_scope_ref is not None:
            add(reader.commitment_scope_ref,required=True)
            if reader.commitment_terms_locator is not None:
                from .current_commitment_fulfillment_source_v3 import require_named_commitment_terms_source_roots_v3,require_named_commitment_policy_context_v3
                roots=set(require_named_commitment_terms_source_roots_v3(reader))
                policy,policy_audiences,versions=require_named_commitment_policy_context_v3(reader)
                for version in versions:add({'key':version.key.token,'revision':version.revision},required=True)
                if policy:groups.append(('context',tuple(policy_audiences),tuple(policy)))
    reader.policy_context=('persona:'+reader.namespace.persona_id,target,route)
    # Complete D03/D05 census is the negative applicability proof. Every actual
    # applicable instance is selected, while unrelated Body remains skipped.
    for token,original in sorted(pre.metadata.items()):
        key=original.key
        if key.type_name not in _SELECTOR_FIELDS or not original.valid:continue
        value=pre.metadata_value_v3(key,meter=meter)
        applicable_requests=tuple(request for request in requests if _full_policy_decision_v3(key.type_name,value,
            subject='persona:'+reader.namespace.persona_id,target=target,route=route,now=reader.metadata_now,request=request))
        applicable=bool(applicable_requests)
        if key.type_name=='d03.account_binding'and value['valid_until']is not None and reader.metadata_now>=value['valid_until']:
            applicable=False
        if applicable:
            add(key.token);policy_keys.add(key.token)
            for request in applicable_requests:request_keys[request].add(key.token)
            declared=_policy_sources_v3(value)
            if key.type_name in {'d03.role_binding','d05.boundary_rule'}:policy_roots.update(declared)
            else:
                for ref in declared:
                    if ref in route_lineage:roots.add(ref)
                    else:policy_roots.add(ref)
    # The existing scope's policy audience is a declared consumer requirement;
    # the actual Owner entry subsequently proves that it permits each group.
    while queue:
        key=queue.pop(0)
        if key.token in seen:continue
        seen.add(key.token)
        original=pre.metadata[key.token];value=_detach_value_v3(original.selectors)
        if key.type_name in _SELECTOR_FIELDS:
            # Applicability was evaluated over every policy head above.
            for name in ('verification_ref','creation_evidence_refs'):
                if name in value:refs(value[name])
        else:
            for name in _FULL_REFERENCE_FIELDS_V3.get(key.type_name,()):
                if name in value:refs(value[name])
    if policy_roots:groups.append(('context',('owner',),tuple(sorted(policy_roots))))
    groups.insert(0,('expression',audiences,tuple(sorted(roots|set(material.attention_roots)))))
    material.roots=tuple(sorted(roots))
    reader.owner_groups=tuple(groups);reader.policy_keys=tuple(sorted(policy_keys))
    reader.policy_requests=requests;reader.policy_request_bases=request_bases;reader.policy_recipe_expiry=recipe_expiry
    reader.policy_request_keys=tuple((request,tuple(sorted(request_keys[request])))for request in requests)
    reader.metadata_selection=_FullMetadataSelectionV3(_ISSUER,reader,selected_keys=keys,groups=reader.owner_groups)
    material.freeze_groups_v3(reader.owner_groups)
    return reader.metadata_selection



_ARTIFACT_METADATA_V3=WeakKeyDictionary()
_ARTIFACT_HISTORY_V3=WeakKeyDictionary()


class _FullArtifactReceiptMetadataV3:
    def __init__(self,reader):
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        if reader.contract is not ARTIFACT_RECEIPT_FULL_READ_V1 or reader.prefinal is None:
            raise AuthorityUnavailable('actual Artifact FULL metadata caller required')
        operation='artifact-completion-source:'+reader.receipt_operation_id[len('artifact-receipt-message:'):]
        paths=(('namespace',),('identity',),('authority','actor'),('provenance','artifact_completion_receipt'))
        class Column(DispatchOriginalJSONReadV3):
            def _emit(self,event):
                if _full_metadata_event_v3(event,paths):super()._emit(event)
            def require_v3(self,owner):raise AuthorityUnavailable('Artifact metadata is not a Body original')
        self.reader,self.operation=reader,operation
        self.column=Column(reader,table='graph_domain_production_originals_v1',column='original_payload_json',
            key_columns=('bot','persona','operation_id'),key=(*reader.namespace.as_tuple,operation))
        self.header=None;self.receipt=None;self.roots=();self.complete=False
        self.phase='receipt';self.settlement_column=None;self.settlement=None;self.settlement_header=None
        self.history_columns={};self.history_queue=[];self.history_current=None;self.current_versions=()
        _ARTIFACT_METADATA_V3[self]=(reader,reader.work,reader.operation,reader.prefinal,operation,self.column)
    def advance_v3(self,meter):
        r=self.reader;r.prefinal.require_current(meter=meter)
        if (_ARTIFACT_METADATA_V3.get(self)!=(r,r.work,r.operation,r.prefinal,self.operation,self.column)):
            raise AuthorityUnavailable('actual Artifact metadata Work changed')
        if self.phase!='receipt':return self._advance_settlement_v3(meter)
        if self.header is None:
            self.header=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',
                ('domain','operation_kind','original_digest','bundle_digest'),'bot=? AND persona=? AND operation_id=?',
                (*r.namespace.as_tuple,self.operation))
            if self.header is None:raise AuthorityUnavailable('Artifact receipt producer metadata is absent')
            bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id'),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.operation))
            if bundle is None or bundle[0]!=self.header[3]:raise AuthorityUnavailable('Artifact metadata lost actual W01 adoption')
            event=meter.read_fixed_row(r.db,'graph_events',('digest',),
                'bot=? AND persona=? AND session=? AND event_id=?',(*r.namespace.as_tuple,bundle[1],self.operation))
            if event is None:raise AuthorityUnavailable('Artifact metadata lost actual W01 event')
            self.event_metadata=event
        if not self.column.advance(meter):return
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        from .artifact_completion_receipt_v1 import receipt_from_wire_v1
        if self.column.sha256!=self.header[2]:raise AuthorityUnavailable('Artifact metadata whole payload SHA differs')
        value=DispatchOriginalJSONReadV3.require_v3(self.column,r)
        receipt=receipt_from_wire_v1(value['provenance']['artifact_completion_receipt'])
        if receipt.namespace!=r.namespace or receipt.message_operation_id!=r.receipt_operation_id or receipt.producer_operation_id!=self.operation:
            raise AuthorityUnavailable('Artifact metadata changed its actual selected receipt identity')
        self.receipt=receipt;self.roots=(receipt.source_ref,*(head.key.token for head,_ in receipt.parent_source_heads))
        self.phase='settlement'



    def _advance_settlement_v3(self,meter):
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        from .d11_artifact_draft_content_v1 import artifact_method_settlement_operation_id_v2,ArtifactDraftMethodSettlementHistoryV2
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        r=self.reader
        if self.phase=='settlement':
            operation=artifact_method_settlement_operation_id_v2(self.receipt.selector)
            if self.settlement_column is None:
                self.settlement_header=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',
                    ('domain','operation_kind','original_digest','bundle_digest'),
                    'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
                if self.settlement_header is None or self.settlement_header[:2]!=('d08','settle_personal_goal'):
                    raise AuthorityUnavailable('Artifact metadata lacks its exact Goal settlement producer')
                bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest',),
                    'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
                if bundle!=(self.settlement_header[3],):raise AuthorityUnavailable('Artifact settlement metadata lost W01 adoption')
                paths=(('provenance','artifact_method_completion'),)
                class Column(DispatchOriginalJSONReadV3):
                    def _emit(self,event):
                        if _full_metadata_event_v3(event,paths):super()._emit(event)
                    def require_v3(self,owner):raise AuthorityUnavailable('settlement metadata is not a Body original')
                self.settlement_column=Column(r,table='graph_domain_production_originals_v1',column='original_payload_json',
                    key_columns=('bot','persona','operation_id'),key=(*r.namespace.as_tuple,operation));return
            if not self.settlement_column.advance(meter):return
            if self.settlement_column.sha256!=self.settlement_header[2]:raise AuthorityUnavailable('settlement metadata whole SHA differs')
            raw=DispatchOriginalJSONReadV3.require_v3(self.settlement_column,r)['provenance']['artifact_method_completion']
            value=decode_typed_production_value_v1(raw,ArtifactDraftMethodSettlementHistoryV2)
            if (value.namespace!=r.namespace or value.selector!=self.receipt.selector or value.settlement_operation_id!=operation
                    or value.state!='satisfied'or value.digest!=self.receipt.completion_digest
                    or value.settlement_operation_id!=self.receipt.completion_operation_id
                    or(value.source_head,value.source_value_digest)not in self.receipt.parent_source_heads):
                raise AuthorityUnavailable('Artifact settlement metadata differs from actual receipt/Source scope')
            self.settlement=value
            self.current_versions=tuple(member.after for member in value.members)
            self.history_queue=list(dict.fromkeys((*[version for member in value.members for version in(member.before,member.after)],value.progress_head)))
            self.phase='history';return
        if self.phase=='history':
            if self.history_current is not None:
                version,column,header=self.history_current
                if not column.advance(meter):return
                self.history_columns[(version.key.token,version.revision)]=(column,header)
                self.history_current=None;return
            if self.history_queue:
                version=self.history_queue.pop(0);key=version.key
                header=meter.read_fixed_row(r.db,'graph_history',('event_id','valid','value_cell_id','event_bot','event_persona'),
                    'token=? AND revision=?',(key.token,version.revision))
                if header is None or header[1]!=1 or header[3:]!=r.namespace.as_tuple:
                    raise AuthorityUnavailable('Artifact exact historical metadata member is absent')
                after=next((member for member in self.settlement.members if member.after==version),None)
                if after is not None and header[0]!=self.settlement.settlement_operation_id:
                    raise AuthorityUnavailable('Artifact after metadata member lost its actual settlement event')
                if version==self.settlement.progress_head and header[0]!=self.settlement.progress_operation_id:
                    raise AuthorityUnavailable('Artifact progress metadata lost its actual W01 event')
                paths=_full_metadata_paths_v3(key.type_name)
                class Column(DispatchOriginalJSONReadV3):
                    def _emit(self,event):
                        if _full_metadata_event_v3(event,paths):super()._emit(event)
                    def require_v3(self,owner):raise AuthorityUnavailable('historical metadata is not a Body original')
                column=Column(r,table='graph_history',column='value',key_columns=('token','revision'),
                    key=(key.token,version.revision),cell_id=header[2])
                if column.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                    raise AuthorityUnavailable('Artifact historical cell has no actual canonical codec')
                column.parser=C09CanonicalJSONStreamV2(ensure_ascii=column.cell.header[0]=='canonical-json.ascii.v1')
                self.history_current=(version,column,header);return
            self.complete=True;self.phase='complete'
            _ARTIFACT_HISTORY_V3[self]=self._history_identity_v3();return
        if self.phase=='complete':return
        raise AuthorityUnavailable('Artifact metadata locator phase differs')
    def _history_identity_v3(self):
        return(self.reader,self.receipt,self.settlement,self.current_versions,
            tuple(sorted((key,column,header,column.sha256,column.byte_count,column._frozen_value)
                for key,(column,header)in self.history_columns.items())))
    def require_metadata_v3(self,reader):
        if (_ARTIFACT_METADATA_V3.get(self)!=(reader,reader.work,reader.operation,reader.prefinal,self.operation,self.column)
                or _ARTIFACT_HISTORY_V3.get(self)!=self._history_identity_v3()or not self.complete):
            raise AuthorityUnavailable('actual complete Artifact metadata receipt/history census required')
        reader.prefinal._actual();return self
    def require_history_body_v3(self,reader,token,revision,integrity):
        if (_ARTIFACT_METADATA_V3.get(self)!=(reader,reader.work,reader.operation,reader.prefinal,self.operation,self.column)
                or reader.artifact_metadata is not self or not self.complete):
            raise AuthorityUnavailable('Artifact historical Body requires its actual completed metadata locator')
        self.require_metadata_v3(reader);reader.source_rights_seal.require_v3()
        entry=self.history_columns.get((token,revision))
        if entry is None:raise AuthorityUnavailable('historical Body was not selected by the exact Artifact metadata scope')
        column,header=entry
        from .dispatch_initial_source_read_v3 import _COLUMNS
        expected=(reader,'graph_history','value',(token,revision),column.sha256,column.byte_count,column._frozen_value)
        if _COLUMNS.get(column)!=expected:raise AuthorityUnavailable('historical metadata canonical EOF issuer changed')
        if(tuple(integrity.get(name)for name in('event_id','valid','value_cell_id','event_bot','event_persona'))!=header
                or not column.complete or column.sha256!=column.cell.header[5]):
            raise AuthorityUnavailable('Artifact historical Body header differs from complete metadata EOF')
        return column


_FULL_REFERENCE_FIELDS_V3=MappingProxyType({
 NATURAL_PLAN_TYPE_V2:('source_ref','focus_ref','ticket_ref','scene_ref','audience_ref','promise_grants','qualification_refs','qualified_read_versions'),
 'd07.focus.v1':('primary_ticket_ref',),
 'd07.attention_ticket.v1':('source_refs','cancel_refs'),
 'd03.world_event':('source_refs',),
 'd08.goal.v1':('reason_refs','dependency_refs','deadline_ref','progress_refs'),
 'd08.commitment.v1':('source_refs',),
 'd08.action_intent.v1':('goal_ref','commitment_refs','compensation_ref','source_refs'),
 'd08.action_schema.v1':('action_ref',),
 'd08.action_outcome.v1':('action_ref','source_refs','outcome_refs'),
 'd08.action_cancellation.v1':('source_refs',),
 'd08.contact_expression_plan.v2':('source_refs','action_ref','read_versions'),
 'd08.contact_expression_plan_provenance.v2':('plan_ref','source_refs','read_versions','claim_ref'),
 'd08.contact_expression_plan_eligibility.v2':('plan_ref','source_refs','read_versions'),
 'd09.verified_segment_batch.v1':('source_ref','plan_ref'),
 'd08.communication_intent_grant.v1':('action_ref','source_refs'),
 'd08.commitment_communication_intent.v1':('route_source_ref','commitment'),
 'd08.commitment_communication_intent.v2':('source_refs','fulfillment_terms','terms_acceptance','route_source_ref','commitment','policy_read_versions'),
 'd08.commitment_fulfillment_terms.v1':('source_refs',),
 'd08.commitment_terms_acceptance.v1':('inbound_source_ref',),
})


_FULL_POLICY_TYPES_V3=frozenset({'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'})


def _require_full_policy_selection_v3(proof,db,query):
    if type(proof)not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
        raise AuthorityUnavailable('actual ordinary FULL policy applicability proof required')
    actual=require_bound_graph_full_read_proof_for_db_v3(db,proof.namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    if actual is not proof or query!=proof.query or db is not proof.db or not db.in_transaction:
        raise AuthorityUnavailable('FULL policy applicability belongs to another actual Binder/query')
    base=proof.base if type(proof)is PreparedCurrentGraphFullWriteViewV3 else proof
    if type(proof)is PreparedCurrentGraphFullWriteViewV3 and any(row.key.type_name in _FULL_POLICY_TYPES_V3 for row in proof.facts.rows):
        raise AuthorityUnavailable('policy writer delta requires new SourceALL applicability')
    selection=base.work.state.metadata_selection;selection.require_for_v3(base.work.state)
    if type(proof)is PreparedCurrentGraphFullWriteViewV3 and any(row.key.token in {basis[0]for basis in selection.policy_request_bases}for row in proof.facts.rows):
        raise AuthorityUnavailable('actual writer changed the issued communication policy recipe; new SourceALL preparation required')
    base.rights_seal.require_v3()
    if selection.policy_context is None:raise AuthorityUnavailable('metadata recovery has no policy Body applicability')
    return selection


def require_bound_current_full_ingress_route_v3(db,namespace,query,*,source_ref,c02_operation_id,
        platform_ref,conversation_ref,sender_ref,scene_ref):
    """Actual fixed ingress metadata, checked against an independent route caller."""
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    selection=_require_full_policy_selection_v3(proof,db,query)
    original=selection.ingress_original
    if original is None or original[:2]!=(source_ref,c02_operation_id):
        raise AuthorityUnavailable('FULL ingress metadata belongs to another actual Source/C02 selector')
    from ..memory_types import source_key
    from .first_ingress_v2 import scene_ref_for_conversation,ingress_ids
    key=AtomKey.from_token(source_ref)
    if (key!=source_key(*namespace.as_tuple,key.owner.subject)or ingress_ids(key.owner.subject)[2]!=c02_operation_id):
        raise AuthorityUnavailable('FULL ingress Source/C02 identity is not its actual committed ingress')
    with runtime_storage_quantum_v3(db)as meter:
        row=meter.read_fixed_row(db,'graph_first_ingress_identity_v1',
            ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','operation_id'),
            'bot=? AND persona=? AND source_ref=? ORDER BY operation_id',(*namespace.as_tuple,key.owner.subject))
        other=meter.read_fixed_row(db,'graph_first_ingress_identity_v1',('operation_id',),
            'bot=? AND persona=? AND source_ref=? AND operation_id>? ORDER BY operation_id',
            (*namespace.as_tuple,key.owner.subject,c02_operation_id))
        business=meter.read_fixed_row(db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,c02_operation_id))
    if row!=original[2]or other is not None or business!=original[3]:
        raise AuthorityUnavailable('FULL ingress fixed metadata/unique EOF/C02 commit changed')
    route=(*row[1:5],scene_ref_for_conversation(namespace,row[1],row[2]))
    if row[5:]!=('private',c02_operation_id)or(row[1],row[2],row[3],route[4])!=(platform_ref,conversation_ref,sender_ref,scene_ref):
        raise AuthorityUnavailable('FULL ingress metadata differs from the actual caller route binding')
    return route


def require_bound_graph_full_policy_projection_v3(proof,db,query):
    """Related Role/Boundary Body with its complete metadata predicate census."""
    bound=_BOUND.get()
    if type(bound)is _DispatchFullReadBindingV3 and bound.proof is proof and proof.family=='private_reply':
        from .private_dispatch_source_read_v3 import require_private_dispatch_policy_projection_v3
        bound.require_current(bound.graph,db,proof.namespace,required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
        return require_private_dispatch_policy_projection_v3(proof,db,query)
    selection=_require_full_policy_selection_v3(proof,db,query)
    projection=proof.projection
    rows=tuple(projection._view(atom)for atom in projection._atoms
        if atom.key.token in selection.policy_keys and atom.key.type_name in {'d03.role_binding','d05.boundary_rule'}and atom.valid)
    return(tuple(atom for atom in rows if atom.key.type_name=='d03.role_binding'),
        tuple(atom for atom in rows if atom.key.type_name=='d05.boundary_rule'),selection)


def require_bound_graph_full_applicable_atom_rows_v3(proof,db,query,type_names,columns,*,subject,target,route,now,action_kind='message',purpose='expression',valid_only=True,name=None):
    selection=_require_full_policy_selection_v3(proof,db,query)
    selection.require_policy_for_v3(proof,db,query,subject=subject,target=target,route=route,now=now,action_kind=action_kind,purpose=purpose)
    types=frozenset(type_names)
    if not types<=_FULL_POLICY_TYPES_V3 or not set(columns)<=frozenset({'token','revision','valid','type_name','value'}):
        raise AuthorityUnavailable('named applicability supports only its actual fixed policy metadata predicate')
    atoms=tuple(proof.projection._view(atom)for atom in proof.projection._atoms
        if atom.key.token in dict(selection.policy_request_keys)[(action_kind,purpose)] and atom.key.type_name in types
        and(not valid_only or atom.valid)and(name is None or atom.key.name==name))
    result=[]
    for atom in atoms:
        values={'token':atom.key.token,'revision':atom.revision,'valid':int(atom.valid),'type_name':atom.key.type_name,'value':atom.value}
        result.append(tuple(values[column]for column in columns))
    return tuple(result)



def require_current_full_reply_account_metadata_census_v3(reader,db,namespace,query,*,platform_ref,sender_ref,now_utc,write_view=None):
    from ..graph_types import GraphVersion
    if(type(reader)is not _OrdinaryFullReadV3 or reader not in _ORDINARY_READERS_V3 or reader.db is not db
            or reader.namespace!=namespace or not db.in_transaction or not reader.body_eof):
        raise AuthorityUnavailable('reply account census requires the actual post-rights FULL reader')
    pre=reader.prefinal
    if write_view is None:
        if reader.query!=query:raise AuthorityUnavailable('reply account census query changed')
        pre.require_current()
    else:
        if(type(write_view)is not PreparedCurrentGraphFullWriteViewV3 or write_view.base.work.state is not reader
                or write_view.query!=query or write_view.db is not db):
            raise AuthorityUnavailable('reply account census requires the actual unchanged-policy Store delta')
        _require_full_policy_selection_v3(write_view,db,query);pre._actual()
    reader.source_rights_seal.require_v3()
    route=reader.metadata_selection.policy_context[2]
    if (platform_ref,sender_ref)!=(route[0],route[2])or type(now_utc)not in(int,float)or not math.isfinite(now_utc):
        raise AuthorityUnavailable('reply account census differs from the actual C02 route')
    from .current_commitment_input_source_v3 import _policy_decision_v3
    versions=[];matches=[]
    for token,head in sorted(pre.heads.items()):
        key=AtomKey.from_token(token)
        if key.type_name!='d03.account_binding'or head[1]!=1:continue
        original=pre.metadata[token];original.require_v3(reader);value=_detach_value_v3(original.selectors)
        # This official validator checks the entire fixed metadata shape. The
        # negative route predicate deliberately has no entity-target filter.
        valid=_policy_decision_v3(key.type_name,value,subject='persona:'+namespace.persona_id,
            target=value['entity_id'],route=route,now=now_utc)
        versions.append(GraphVersion(key,head[0]))
        if valid and(value['valid_until']is None or now_utc<value['valid_until']):matches.append(key)
    return tuple(versions),tuple(matches)


def read_bound_reply_account_metadata_census_v3(db,namespace,query,*,platform_ref,sender_ref,now_utc):
    bound=_BOUND.get()
    if type(bound)is _DispatchFullReadBindingV3 and bound.proof.family=='private_reply':
        from .private_dispatch_source_read_v3 import require_private_dispatch_reply_account_metadata_census_v3
        bound.require_current(bound.graph,db,namespace,required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
        return require_private_dispatch_reply_account_metadata_census_v3(bound.proof,db,query,
            platform_ref=platform_ref,sender_ref=sender_ref,now_utc=now_utc)
    if type(bound)is tuple:
        proof=bound[0]
        if type(proof)in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
            selection=_require_full_policy_selection_v3(proof,db,query)
            base=proof.base if type(proof)is PreparedCurrentGraphFullWriteViewV3 else proof
            # Write deltas which touch Account policy were rejected above.
            return require_current_full_reply_account_metadata_census_v3(base.work.state,db,namespace,query,
                platform_ref=platform_ref,sender_ref=sender_ref,now_utc=now_utc,
                write_view=proof if type(proof)is PreparedCurrentGraphFullWriteViewV3 else None)
    from .artifact_receipt_original_read_v1 import read_artifact_receipt_reply_account_metadata_census_v3
    return read_artifact_receipt_reply_account_metadata_census_v3(db,namespace,query,
        platform_ref=platform_ref,sender_ref=sender_ref,now_utc=now_utc)

_D13_COUNTER_TERMINALS_V1=WeakKeyDictionary()


def record_actual_d13_counter_prepare_terminal_v1(full,*,graph,graph_capability,
        scope,instruction,receipt,finish_ack):
    from ..runtime_contracts import canonical_digest
    from .d13_natural_counter_preflight_v7 import _require_prepare_receipt_v7
    if (graph_capability is not graph._GraphCoordinator__graph_capability
            or type(full)is not _OrdinaryFullReadV3 or full.graph is not graph
            or full.contract is not D13_COUNTER_PREPARE_FULL_V1
            or _D13_COUNTER_FULL_V1.get(full)!=_d13_counter_full_identity_v1(full)
            or full.work.state is not full or full.work.operation is not full.operation
            or not full.work.terminal or full.work.phase!='complete' or not full.complete
            or full.operation.closed or full.work.result_lease is not full.operation
            or instruction is not full.d13_counter_instruction
            or full.borrowed.instruction is not instruction or scope is not full.borrowed.scope
            or finish_ack!=(scope.permit,'finished')):
        raise AuthorityUnavailable('D13 counter terminal requires its actual completed Root commit/finish')
    borrowed=full.borrowed
    if (_D13_COUNTER_BORROWED_V1.get(borrowed)!=borrowed._identity_v1()
            or borrowed.owner_issuance is not full.d13_counter_owner_issuance):
        raise AuthorityUnavailable('D13 counter terminal lost its actual original private scope')
    record=graph._GraphCoordinator__d13_counter_write_scopes.get(id(borrowed.owner_issuance))
    if (type(record)is not tuple or record[:6]!=(borrowed.owner_issuance,scope,
            borrowed.owner_guard,borrowed.current_owner,full.fence.metadata,full.fence.epoch)):
        raise AuthorityUnavailable('D13 counter terminal has no actual Root WRITE registration')
    _require_prepare_receipt_v7(receipt,instruction)
    expected=(full.work,full.operation,scope,instruction,canonical_digest(receipt))
    existing=_D13_COUNTER_TERMINALS_V1.get(full)
    if existing is not None and existing!=expected:
        raise AuthorityUnavailable('D13 counter terminal conflicts with its actual first finished receipt')
    _D13_COUNTER_TERMINALS_V1[full]=expected
    return full.work


def require_actual_d13_counter_prepare_terminal_v1(work,*,instruction,receipt):
    from ..graph_worker import GraphStorageWorkV3
    from ..runtime_contracts import canonical_digest
    from .d13_natural_counter_preflight_v7 import _require_prepare_receipt_v7
    if type(work)is not GraphStorageWorkV3:
        raise AuthorityUnavailable('actual D13 counter FULL terminal Work required')
    full=work.state
    if (type(full)is not _OrdinaryFullReadV3 or full.contract is not D13_COUNTER_PREPARE_FULL_V1
            or _D13_COUNTER_FULL_V1.get(full)!=_d13_counter_full_identity_v1(full)
            or full.work is not work or work.operation is not full.operation
            or work.coordinator is not full.graph or not work.terminal or work.phase!='complete'
            or not full.complete or full.operation.closed
            or instruction is not full.d13_counter_instruction):
        raise AuthorityUnavailable('D13 counter terminal left its retained actual completed Work')
    _require_prepare_receipt_v7(receipt,instruction)
    if _D13_COUNTER_TERMINALS_V1.get(full)!=(work,full.operation,full.borrowed.scope,
            instruction,canonical_digest(receipt)):
        raise AuthorityUnavailable('D13 counter terminal has no actual finished receipt attestation')
    # The worker transfers result_lease into OwnedGraphStorageResultV3 before
    # final mappers. The original operation must remain open; no Owner, Scope,
    # Source or Body permission is renewed by this historical terminal check.
    return work

