"""A closed, independent READ Work for one fixed semantic recovery page."""
from dataclasses import dataclass, replace
import secrets
import time
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..runtime_contracts import (AuthorityContext,CommandEnvelope,OperationIdentity,QueryEpoch,
    RUNTIME_SCHEMA,SourceQualification,VersionGuard,NamespaceId,canonical_digest)
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from ..graph_worker import create_graph_storage_work_v3,require_graph_storage_work_admission_v3,GraphStorageStepV3
from .domain_mesh_continuation_read_v3 import (SemanticRecoveryPageSelectorV1,SemanticRecoveryPageV1,
    SemanticRecoveryObservationV1,begin_semantic_tick_metadata_v3,metadata_recovery_observation_v1)
from .domain_mesh_catalog_v1 import require_semantic_recipe_operation_v1
from .domain_mesh_contract_v1 import SemanticTickV1
from .domain_production_contracts_v1 import (CurrentOperationFrameV1,ProductionOriginalRefV1,
    ProductionOwnerGuardV1,ProductionQueryCoverageV1)
from .domain_background_read_v3 import (BackgroundReadWorkV3,_ISSUER as BACKGROUND_ISSUER,
    require_actual_background_attachment_owner_v3,bind_background_reads_v3,BackgroundReadNeededV3,
    _start_background_request_v3,_advance_background_pending_v3,background_graph_head_v3,
    background_json_loads_v3)
from .first_ingress_v2 import trusted_upper
from .source_correction_read_v3 import SourceCorrectionContextReadV3, _heap
from hashlib import sha256

_KIND = 'semantic_recovery'
_READS = WeakKeyDictionary()
_FACTS = WeakKeyDictionary()
_SOURCE_ROWS = WeakKeyDictionary()
_HISTORY_ROWS = WeakKeyDictionary()
_CENSUS_ROWS_V3 = WeakKeyDictionary()
_COLD_FRAME_READSETS_V3 = {}

def _identity(reader):
    return (reader.graph,reader.context,reader.bundle,reader.selector,reader.operation,reader.work,
        reader.fence,reader.selection_digest,reader.graph_stamp,reader.semantic_metadata)

def _require(reader):
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if (type(reader) is not BackgroundReadWorkV3 or reader.kind != _KIND
            or _READS.get(reader) != _identity(reader)
            or (reader.fence is not None and reader.fence.scope.operation != 'read')
            or time.monotonic() >= reader.initial_monotonic_deadline
            or reader.context._v2_coordinator is not reader.graph
            or reader.context._v2_bootstrap is not reader.bootstrap
            or reader.context._v2_model_bundle is not reader.bundle):
        raise AuthorityUnavailable('Semantic recovery requires its exact independently installed READ Work')
    reader.work._require_invocation(reader.graph)
    return reader

def _source_row_identity(reader):
    return (reader.semantic_row,reader.semantic_profile,reader.fence,reader.read_scope,reader.authority,
        reader.semantic_self_descriptor,reader.semantic_owner_entry,reader.semantic_source_gate)

def require_current_semantic_recovery_work_v3(work,*,db,namespace,producer_operation_id):
    reader = _require(work)
    row = reader.semantic_row
    if (db is not reader.db or namespace != reader.namespace or row is None
            or producer_operation_id != row.tick.producer_operation_id or not reader.semantic_source_complete
            or reader.semantic_profile.operation_kind != reader.semantic_producer_kind
            or reader.phase != 'semantic_observe' or _SOURCE_ROWS.get(reader) != _source_row_identity(reader)
            or reader.fence.authority != reader.authority
            or reader.read_scope.operation_id != reader.operation_id+':source:'+str(reader.semantic_index)
            or (row.tick.source_roots and (type(reader.semantic_source_gate) is not _SemanticRecoverySourcesV3
                or reader.semantic_source_gate.owner is not reader or not reader.semantic_source_gate.complete
                or reader.semantic_source_gate.read_scope is not reader.read_scope))
            or not db.in_transaction
            or not reader.store._lock._is_owned()):
        raise AuthorityUnavailable('Producer locator is outside this actual page row and qualified Source Work')
    return reader

def prepare_current_semantic_recovery_page_v3(graph,context,selector):
    from ..runtime_context import RuntimeContext
    graph._admin(context._v2_bootstrap)
    require_graph_storage_work_admission_v3(graph)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(context) is not RuntimeContext or context._v2_coordinator is not graph
            or assembly is None or context._v2_model_bundle is not assembly.admin_bundle
            or type(selector) is not SemanticRecoveryPageSelectorV1
            or selector.namespace != context._v2_namespace
            or selector.installation_id != assembly.admin_bundle.installation_policy.installation_id):
        raise AuthorityUnavailable('Semantic page selector crossed the actual installed Host namespace')
    policy = assembly.admin_bundle.installation_policy
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id = 'semantic-recovery-read:' + secrets.token_hex(16)
    operation = begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence = None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            # This descriptor admits metadata only. Fresh Owner/Self observation below qualifies each body.
            authority = AuthorityContext('semantic-recovery-metadata','d11','semantic-recovery-metadata',
                selector.namespace,('activity',),'consolidation',('owner',),'semantic-recovery-read.v3',
                graph._v2_graph_stamp(selector.namespace)[0].requirements.activation_generation)
            fence = graph._begin_read_fence_v3(authority,operation_id=operation_id+':metadata:0')
            reader = BackgroundReadWorkV3(BACKGROUND_ISSUER,graph,context._v2_bootstrap,assembly.admin_bundle,
                operation,kind=_KIND,dedupe_key=None,context=context)
            reader.selector,reader.fence,reader.read_scope,reader.authority = selector,fence,fence.scope,authority
            reader.runtime = graph._GraphCoordinator__domain_production_runtime_v1
            reader.lease = reader.owner_binding = reader.owner_guard = reader.session_proof = None
            reader.operation_id = operation_id
            reader.request_digest = canonical_digest(selector)
            reader.read_finished = False
            reader.initial_monotonic_deadline = time.monotonic()+operation.deadline_utc-now
            reader.initial_now_utc = reader.now = now
            reader.semantic_metadata_authority = authority
            reader.semantic_self_descriptor = None
            reader.semantic_rows = reader.semantic_metadata = None
            reader.semantic_index = 0
            reader.semantic_row = reader.semantic_source_gate = reader.semantic_owner_entry = None
            reader.semantic_source_complete = False
            reader.semantic_observations = []
            reader.semantic_original_ops = set()
            reader.semantic_ref_matches = {}
            reader.semantic_ref_cursor = ''
            reader.semantic_allowed_keys = set()
            reader.semantic_allowed_history = set()
            reader.semantic_original_refs = set()
            reader.semantic_frame = reader.semantic_original = reader.semantic_facts = None
            reader.phase = 'semantic_metadata'
            work = create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=reader,operation=operation)
            reader.work = work
            _READS[reader] = _identity(reader)
            reader.semantic_metadata = begin_semantic_tick_metadata_v3(reader,selector)
            _READS[reader] = _identity(reader)
        return work
    except BaseException:
        try:
            if fence is not None:
                graph._finish_read_fence_v3(fence)
        finally:
            finish_runtime_storage_operation_v3(operation)
        raise

def semantic_recovery_require_current_v3(reader,meter):
    _require(reader)
    reader.require_data_current_v3(meter)
    return reader

def _close_row(reader):
    _SOURCE_ROWS.pop(reader,None)
    _HISTORY_ROWS.pop(reader,None)
    census=_CENSUS_ROWS_V3.pop(reader,None)
    if census is not None:reader.operation.unregister_retained_state_v3(census)
    if reader.semantic_frame is not None:_COLD_FRAME_READSETS_V3.pop(id(reader.semantic_frame),None)
    if reader.semantic_owner_entry is not None:
        reader.semantic_owner_entry.release_v3()
    reader.semantic_owner_entry = None
    if reader.semantic_facts is not None:
        _FACTS.pop(reader.semantic_facts,None)
    reader.semantic_facts = None
    reader.semantic_source_gate = reader.semantic_frame = reader.semantic_original = None
    reader.semantic_source_complete = False
    reader.owner_binding = reader.owner_guard = reader.semantic_owner_guard = reader.owner = None
    reader.semantic_original_ops.clear()
    reader.semantic_ref_matches.clear()
    reader.semantic_ref_cursor = ''
    reader.semantic_allowed_keys.clear()
    reader.semantic_allowed_history.clear()
    reader.semantic_original_refs.clear()
    reader.points.clear(); reader.inventories.clear(); reader.scans.clear()
    reader.pending = None
    if reader.fence is not None:
        reader.graph._finish_read_fence_v3(reader.fence)
        reader.fence = reader.read_scope = None
    reader.semantic_self_descriptor = None
    _READS[reader] = _identity(reader)

def release_semantic_recovery_payload_v3(reader):
    if reader.kind != _KIND:
        return
    _close_row(reader)
    _READS.pop(reader,None)
    reader.semantic_metadata = reader.semantic_rows = reader.semantic_row = None
    reader.semantic_observations.clear()

def _observation(reader,status,reason,dependencies=()):
    row = reader.semantic_row
    tick = row.tick
    effects = tuple(item.original_ref for item in tick.pending if item.kind in ('call','effect','financial'))
    return SemanticRecoveryObservationV1(row.ref,row.revision,tick.recipe_version,tick.producer_operation_id,
        tick.causal_original.original_ref,tick.original_deadline_utc,status,reason,tuple(dependencies),effects)

def _finish_row(reader,observation):
    reader.semantic_observations.append(observation)
    _close_row(reader)
    reader.semantic_index += 1
    reader.semantic_row = None
    reader.phase = 'semantic_owner'

def _self_descriptor(current):
    # An immutable locator for a fresh second-Scope observation; never a permit.
    return (current.namespace,current.authority_namespace,current.authority_id,current.installation_id,
        current.manifest_digest,current.activation_generation,current.graph_incarnation,current.role_head_id,
        current.graph_revision,current.graph_epoch,current.origin_graph_incarnation,current.storage_admission_digest,
        current.persona_ref,current.self_entity_ref,current.mapping_id,current.mapping_revision,
        current.mapping_revocation_epoch,current.registration_operation_id,current.registration_digest,
        current.owner_authorization_revision,current.owner_authorization_head,
        current.owner_minimum_revocation_revision,current.owner_revocation_epoch)

def _read_current_self(reader):
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    scope = reader.read_scope
    current = reader.graph._GraphCoordinator__self_identity_port.current_self_identity(namespace=reader.namespace,
        authority_namespace=scope.authority_namespace,request_operation_id=scope.operation_id,permit=scope.permit)
    if (type(current) is not AuthorityCurrentSelfIdentityV1 or current.permit != scope.permit
            or current.namespace != reader.namespace or current.installation_id != reader.selector.installation_id):
        raise AuthorityUnavailable('Semantic recovery lost its same-Scope installed Self observation')
    return current

def _begin_metadata_scope(reader):
    if reader.fence is not None:
        return
    reader.authority = reader.semantic_metadata_authority
    reader.fence = reader.graph._begin_read_fence_v3(reader.authority,
        operation_id=reader.operation_id+':metadata:'+str(reader.semantic_index))
    reader.read_scope = reader.fence.scope
    if (reader.fence.metadata,reader.fence.epoch) != reader.graph_stamp:
        raise AuthorityUnavailable('Semantic page changed after its immutable metadata EOF')
    _READS[reader] = _identity(reader)

def _current_owner(reader):
    from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
    tick = reader.semantic_row.tick
    # The first permit is finished before any authority descriptor changes.
    first_self = _read_current_self(reader)
    reader.semantic_self_descriptor = _self_descriptor(first_self)
    reader.graph._validate_read_fence_v3(reader.fence)
    reader.graph._finish_read_fence_v3(reader.fence)
    reader.fence = reader.read_scope = None
    reader.authority = replace(reader.semantic_metadata_authority,actor=first_self.self_entity_ref,
        issuer_domain=reader.semantic_profile.domain,purpose=tick.purpose,audience=tick.audience)
    reader.fence = reader.graph._begin_read_fence_v3(reader.authority,
        operation_id=reader.operation_id+':source:'+str(reader.semantic_index))
    reader.read_scope = reader.fence.scope
    _READS[reader] = _identity(reader)
    if (reader.fence.metadata,reader.fence.epoch) != reader.graph_stamp:
        raise AuthorityUnavailable('Semantic Source Scope changed the immutable metadata page')
    current = _read_current_self(reader)
    if _self_descriptor(current) != reader.semantic_self_descriptor:
        raise AuthorityUnavailable('Semantic Source Scope has a different current Self descriptor')
    reader.current_self = current
    entry = prepare_current_host_semantic_background_owner_read_entry_v3(reader)
    reader.semantic_owner_entry = entry
    entry.require_permission_v3(reader)
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:
            reader.owner = reader.owner_binding = entry.require_for_v3(reader)
        finally:
            reader.db.rollback()
    guard = ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,reader.owner.grant_revision,
        reader.owner.grant_digest.removeprefix('sha256:'),reader.owner.authorization_head.removeprefix('sha256:'))
    if (tick.purpose not in reader.owner.purposes or not set(tick.audience) <= set(reader.owner.audiences)
            or guard != tick.owner_guard or current.activation_generation != tick.activation_generation
            or current.owner_authorization_head != entry.current_owner_guard.authorization_head
            or (reader.owner.access_epoch,reader.owner.delete_epoch) != (tick.access_epoch,tick.delete_epoch)):
        raise AuthorityUnavailable('Semantic original Owner/Self/access/deletion qualification changed')
    reader.owner_guard = entry.current_owner_guard
    reader.semantic_owner_guard = guard
    reader.phase = 'semantic_sources'
    if tick.source_roots:
        reader.semantic_source_gate = _SemanticRecoverySourcesV3(reader)
    reader.semantic_allowed_keys.add(AtomKey.from_token(reader.semantic_row.ref))
    reader.semantic_original_refs.update(original.original_ref for original in
        (tick.causal_original,*tick.predecessors,*tick.semantic_originals))
    reader.semantic_original_ops.add(tick.producer_operation_id)

class _SemanticRecoverySourcesV3(SourceCorrectionContextReadV3):
    """Mechanical ALL-parent reader owned by this actual row Source Work only."""
    def __init__(self,reader):
        require_semantic_recovery_owner_identity_v3(reader)
        if (reader.semantic_owner_entry is None or reader.phase != 'semantic_sources'
                or reader.fence.authority != reader.authority
                or reader.read_scope.operation_id != reader.operation_id+':source:'+str(reader.semantic_index)):
            raise AuthorityUnavailable('Semantic Sources require the actual second Scope and current Owner17')
        reader.semantic_owner_entry.require_permission_v3(reader)
        self.owner = reader
        self.db,self.namespace,self.storage_lease = reader.db,reader.namespace,reader.operation
        self.read_scope,self.graph_stamp = reader.read_scope,reader.graph_stamp
        self.selection_digest = reader.selection_digest
        tick = reader.semantic_row.tick
        self.purpose,self.audiences = tick.purpose,tick.audience
        self.saved_roots = tick.source_roots
        if not self.saved_roots or len(self.saved_roots)>32:
            raise AuthorityUnavailable('Semantic Sources require their exact finite original roots')
        self.source_ref = self.saved_roots[0]
        self.source_id = AtomKey.from_token(self.source_ref).owner.subject
        self.complete = False
        self.context = self.qualification = None
        self.readset = ()
        self.phase,self.epochs = 'epochs',None
        self.heads,self.sources,self.accesses,self.families = {},{},{},{}
        self.targets = []
        self.jobs,self.active,self.done,self.family_keys = [],set(),set(),set()
        self.family_roots,self.family_after = (),None
        self.cursor,self.pending_target = '',None
        self.scan_count,self.scan_complete = 0,False
        self.scan_root = sha256(b'd12.source-correction-interpretation-scan.v3').hexdigest()
        self._readset_pending = []
        self.cell,self.parser,self.cell_kind,self.cell_token = None,None,None,None
        self.fragment,self.fragment_offset = b'',0
        self.final_tokens,self.final_index = (),0
        self._reserved = 0
        self._reserve(32768)
    def _step(self,meter):
        reader = require_semantic_recovery_owner_identity_v3(self.owner)
        reader.require_data_current_v3(meter)
        if reader.read_scope is not self.read_scope or reader.semantic_source_gate is not self:
            raise AuthorityUnavailable('Semantic Source reader crossed its registered row Scope')
        if self.cell is None and self.phase == 'epochs':
            self.epochs = self._epochs(meter)
            self._family(self.saved_roots,'semantic-recovery')
            return
        if self.cell is None and self.phase == 'scan':
            self.scan_complete = True
            self.final_tokens = tuple(sorted(self.heads))
            self.phase = 'recheck'
            return
        if self.cell is None and self.phase == 'result':
            if self._epochs(meter) != self.epochs:
                raise AuthorityUnavailable('Semantic Source access/deletion changed during ALL-parent EOF')
            self.readset = tuple(self._readset_pending)
            self.complete = True
            self._reserve()
            return
        super()._step(meter)

@dataclass(eq=False,slots=True)
class _SemanticBodyCensusV3:
    identity:tuple
    original_digest:str
    body_pairs:frozenset
    header_versions:tuple
    current_versions:tuple
    header_index:int=0
    current_index:int=0
    complete:bool=False
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.identity,self.original_digest,tuple(self.body_pairs),self.header_versions,self.current_versions))*3+4096
    def require_v3(self,reader):
        if(_CENSUS_ROWS_V3.get(reader)is not self or self.identity!=_source_row_identity(reader)
                or not reader.semantic_source_complete or _SOURCE_ROWS.get(reader)!=self.identity):
            raise AuthorityUnavailable('Semantic body census lost its exact actual Source Scope/Owner/ALL proof')
        return self
    def advance_v3(self,reader,meter):
        self.require_v3(reader)
        if self.header_index<len(self.header_versions):
            version=self.header_versions[self.header_index]
            # Zero is an authenticated absence at this actual Original CAS, never a historical value grant.
            if version.revision:
                head=meter.read_fixed_row(reader.db,'graph_atoms',('revision','valid'),
                    'bot=? AND persona=? AND token=?',(*reader.namespace.as_tuple,version.key.token))
                if head is None or head[0]!=version.revision:
                    head=meter.read_fixed_row(reader.db,'graph_history',('revision','valid','event_bot','event_persona'),
                        'token=? AND revision=?',(version.key.token,version.revision))
                    if head is None or head[0]!=version.revision or head[2:]!=reader.namespace.as_tuple:
                        raise AuthorityUnavailable('Semantic historical header lacks its actual exact immutable original version')
                if head[1]not in(0,1):raise AuthorityUnavailable('Semantic historical header validity differs')
            self.header_index+=1
            return
        if self.current_index<len(self.current_versions):
            version=self.current_versions[self.current_index]
            head=meter.read_fixed_row(reader.db,'graph_atoms',('revision','valid'),
                'bot=? AND persona=? AND token=?',(*reader.namespace.as_tuple,version.key.token))
            if(0 if head is None else head[0])!=version.revision:
                raise AuthorityUnavailable('Semantic dependency changed; a genuine current producer notice is required')
            if head is not None and head[1]not in(0,1):raise AuthorityUnavailable('Semantic current header validity differs')
            self.current_index+=1
            return
        self.complete=True
        reader.semantic_allowed_keys.clear()
        reader.semantic_allowed_keys.update(AtomKey.from_token(token)for token,revision in self.body_pairs)
        allowed=frozenset(pair for pair in self.body_pairs if pair[1]>0)
        reader.semantic_allowed_history=set(allowed)
        _HISTORY_ROWS[reader]=(self.identity,allowed)


def _prepare_semantic_body_census_v3(reader,original):
    cached=_CENSUS_ROWS_V3.get(reader)
    if cached is not None:
        cached.require_v3(reader)
        if cached.original_digest!=original['original_digest']:
            raise AuthorityUnavailable('Semantic body census changed its actual committed producer')
        return cached
    from .habit_census_provenance_v1 import validate_habit_census_original_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    tick=reader.semantic_row.tick
    if(tuple(original['read_versions'])!=tuple(tick.read_versions)):
        raise AuthorityUnavailable('Semantic tick readset differs from its own actual committed producer')
    bodies=set();headers=set()
    qualified=()if reader.semantic_source_gate is None else reader.semantic_source_gate.readset
    qualified_sources={version.key for version in qualified if version.key.type_name=='memory.source'}
    def include(actual):
        parts=validate_habit_census_original_v1(actual)
        body=actual['read_versions']if parts is None else parts[0]
        source_keys={version.key for version in body if version.key.type_name=='memory.source'and version.revision>0}
        if not source_keys<=qualified_sources:
            raise AuthorityUnavailable('Semantic historical Body lacks its own current ALL Source closure')
        bodies.update((version.key.token,version.revision)for version in body)
        headers.update(actual['read_versions'])
    include(original)
    for ref in(tick.causal_original,*tick.predecessors,*tick.semantic_originals):
        operation_id=reader.semantic_ref_matches.get(ref.original_ref)
        if operation_id is None:
            # A Core/Life locator with no graph readset grants no graph Body. Its existing fixed consumer verifies it.
            if ref.read_versions or '.current-'in ref.kind:
                raise AuthorityUnavailable('Semantic predecessor lacks its actual committed graph Original')
            continue
        actual=(original if operation_id==tick.producer_operation_id else
            read_adopted_domain_operation_v1(reader.db,reader.namespace,operation_id))
        if(actual is None or ref.original_ref!=actual['domain']+'-current:'+actual['original_digest'][:48]
                or ref.original_digest!=actual['original_digest']
                or ref.kind!=actual['domain']+'.current-'+actual['operation_kind']
                or ref.read_versions and tuple(ref.read_versions)!=tuple(actual['read_versions'])):
            raise AuthorityUnavailable('Semantic predecessor reference differs from its own actual signed Original')
        include(actual)
    bodies.update((version.key.token,version.revision)for version in(*original['receipt'].write_versions,*qualified))
    bodies.add((reader.semantic_row.ref,reader.semantic_row.revision))
    current={version.key:version.revision for version in tick.read_versions}
    if any(version.key not in current for version in original['receipt'].write_versions):
        raise AuthorityUnavailable('Semantic COMMIT wrote outside its exact original CAS readset')
    current.update((version.key,version.revision)for version in original['receipt'].write_versions)
    current[AtomKey.from_token(reader.semantic_row.ref)]=reader.semantic_row.revision
    if len(current)>1024:raise AuthorityUnavailable('Semantic complete current readset exceeds its original fixed head limit')
    current_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(current.items(),key=lambda item:item[0].token))
    header_versions=tuple(sorted(headers,key=lambda v:(v.key.token,v.revision)))
    census=_SemanticBodyCensusV3(_source_row_identity(reader),original['original_digest'],frozenset(bodies),header_versions,current_versions)
    reader.operation.register_retained_state_v3(census)
    _CENSUS_ROWS_V3[reader]=census
    return census


def current_semantic_recovery_frame_read_versions_v3(frame):
    actual=_COLD_FRAME_READSETS_V3.get(id(frame))
    if actual is None:return None
    if actual[0]is not frame:raise AuthorityUnavailable('Semantic current frame readset identity differs')
    return actual[1]


def read_committed_semantic_producer_v3(work,*,db,namespace,producer_operation_id,issuer):
    reader = require_current_semantic_recovery_work_v3(work,db=db,namespace=namespace,
        producer_operation_id=producer_operation_id)
    if issuer is not reader.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable('Semantic recovery producer crossed its installed verifier')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    original = read_adopted_domain_operation_v1(db,namespace,producer_operation_id)
    tick = reader.semantic_row.tick
    if (original is None or original['domain'] != reader.semantic_profile.domain
            or original['operation_kind'] != reader.semantic_profile.operation_kind):
        raise AuthorityUnavailable('Semantic tick has no exact actual committed installed producer')
    from .domain_mesh_tick_v1 import validate_semantic_mesh_trace_v1
    trace = validate_semantic_mesh_trace_v1(original['payload']['provenance']['semantic_mesh'])
    if trace.after_tick != tick:
        raise AuthorityUnavailable('Semantic recovery tick differs from the actual producer same-CAS trace')
    _prepare_semantic_body_census_v3(reader,original)
    return original

def _frame(reader,original):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    tick = reader.semantic_row.tick
    versions = {version.key:version.revision for version in tick.read_versions}
    # Only this actual COMMIT's independently verified versions justify a successor.
    committed = original['receipt'].write_versions
    if any(version.key not in versions for version in committed):
        raise AuthorityUnavailable('Semantic COMMIT wrote outside its exact signed producer readset')
    versions.update((version.key,version.revision) for version in committed)
    versions[AtomKey.from_token(reader.semantic_row.ref)] = reader.semantic_row.revision
    census=_CENSUS_ROWS_V3[reader].require_v3(reader)
    current_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
    if not census.complete or current_versions!=census.current_versions:
        raise AuthorityUnavailable('Semantic current Frame requires its complete actual header census')
    atoms = []
    for key in sorted(versions,key=lambda value:value.token):
        if(key.token,versions[key])not in census.body_pairs:continue
        row = background_graph_head_v3(reader.db,reader.namespace,key)
        actual = 0 if row is None else row[0]
        if actual != versions[key]:
            raise AuthorityUnavailable('Semantic dependency changed; a genuine current producer notice is required')
        atoms.append(GraphAtom(key,actual,{} if row is None else background_json_loads_v3(row[1]),False if row is None else bool(row[2])))
    coverage = []
    for page in tick.query_coverage:
        expected = {version.key:versions[version.key] for version in page.row_versions}
        for version in committed:
            if version.key.type_name == page.type_id:
                expected[version.key] = version.revision
        cursor, actual = '', []
        with runtime_storage_quantum_v3(reader.db) as meter:
            while True:
                head = meter.read_fixed_row(reader.db,'graph_atoms',('token','revision'),
                    'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',
                    (*reader.namespace.as_tuple,page.type_id,cursor))
                if head is None:
                    break
                cursor = head[0]
                actual.append(GraphVersion(AtomKey.from_token(head[0]),head[1]))
                if len(actual) > 128:
                    raise AuthorityUnavailable('Semantic negative-query metadata exceeded its original finite page')
        expected_rows = tuple(GraphVersion(key,value) for key,value in sorted(expected.items(),key=lambda row:row[0].token))
        if tuple(actual) != expected_rows:
            raise AuthorityUnavailable('Semantic negative-query coverage changed outside the actual producer COMMIT')
        coverage.append(ProductionQueryCoverageV1(QueryEpoch(reader.namespace,'namespace',reader.graph_stamp[1].revision),
            page.type_id,tuple(actual),True,None))
    snapshot = GraphSnapshot(tuple(atoms),(reader.graph_stamp[1],))
    guard = reader.semantic_owner_guard
    with runtime_storage_quantum_v3(reader.db) as meter:
        guards = tuple(meter.read_fixed_row(reader.db,'graph_guard_versions',('version',),
            "bot=? AND persona=? AND kind=? AND ref='current'",(*reader.namespace.as_tuple,kind))
            for kind in ('scheme','operator','policy'))
    if any(row is None for row in guards):
        raise AuthorityUnavailable('Semantic recovery has no actual current installed guard versions')
    version_guard = VersionGuard(current_versions,(QueryEpoch(reader.namespace,'namespace',reader.graph_stamp[1].revision),),
        tick.access_epoch,tick.delete_epoch,reader.store._registry.catalogue_hash,*(row[0] for row in guards),(),(),())
    producer_ref = original['domain']+'-current:'+original['original_digest'][:48]
    inputs = (producer_ref,)
    identity = OperationIdentity(tick.activity_id,None,reader.read_scope.operation_id,'semantic_recovery_read_v3',
        reader.read_scope.operation_id,canonical_digest({'input_refs':list(inputs)}))
    envelope = CommandEnvelope(RUNTIME_SCHEMA,identity,reader.authority,version_guard,
        SourceQualification(tick.source_roots,'derived',None,reader.now,'inference','ineligible',None,'not_applicable'),
        inputs,tick.parent_budget_lease_ref,min(tick.original_deadline_utc,reader.operation.deadline_utc),
        min(reader.initial_monotonic_deadline,
            reader.initial_monotonic_deadline-reader.operation.deadline_utc+tick.original_deadline_utc),
        reader.operation.operation_id,())
    originals = tuple(decode_typed_production_value_v1(raw,ProductionOriginalRefV1) for raw in original['payload']['observed_originals'])
    frame=CurrentOperationFrameV1(envelope,snapshot,reader.now,guard,tick.activation_generation,tuple(coverage),
        tick.provider_policies,originals)
    reader.semantic_frame=frame
    _COLD_FRAME_READSETS_V3[id(frame)]=(frame,current_versions)
    return frame

def _observe(reader):
    issuer = reader.graph._GraphCoordinator__d11_issuer
    tick = reader.semantic_row.tick
    original = read_committed_semantic_producer_v3(reader,db=reader.db,namespace=reader.namespace,
        producer_operation_id=tick.producer_operation_id,issuer=issuer)
    frame = _frame(reader,original)
    reader.semantic_original,reader.semantic_frame = original,frame
    producer = ProductionOriginalRefV1(original['domain']+'.current-'+original['operation_kind'],
        original['domain']+'-current:'+original['original_digest'][:48],original['original_digest'],original['read_versions'])
    closure = () if reader.semantic_source_gate is None else reader.semantic_source_gate.readset
    facts = SemanticRecoveryQualifiedFactsV3(reader.namespace,tick,original['operation_kind'],tick.producer_operation_id,
        producer,canonical_digest(original['receipt']),frame.envelope.version_guard.read_versions,frame.query_coverage,closure,reader.semantic_owner_guard,
        tick.activation_generation,reader.operation.handle.context.storage_generation,tick.access_epoch,tick.delete_epoch)
    _FACTS[facts] = reader
    reader.semantic_facts = facts
    from .domain_mesh_messages_v1 import assemble_current_domain_mesh_message_v1,consume_current_domain_mesh_message_v1
    consume_current_domain_mesh_message_v1(facts,assemble_current_domain_mesh_message_v1(facts))
    if tick.recipe_version == 'prediction-conditioned.v1':
        from .conditioned_self_operations_v1 import read_conditioned_self_recovery_v1
        observed = read_conditioned_self_recovery_v1(reader.db,work=reader,frame=frame,
            producer_operation_id=tick.producer_operation_id,issuer=issuer)
        status = 'observed' if observed.status == 'observed_original' else 'waiting'
        return _observation(reader,status,None if status == 'observed' else 'actual_conditioned_self_dependency',observed.waiting_for)
    if tick.recipe_version == 'joint-habit.v1':
        from .d10_habit_v1 import observe_current_joint_habit_recovery_v1,ObserveCurrentJointHabitRecoveryRequestV1
        producer = ProductionOriginalRefV1(original['domain']+'.current-'+original['operation_kind'],
            original['domain']+'-current:'+original['original_digest'][:48],original['original_digest'],original['read_versions'])
        observed = observe_current_joint_habit_recovery_v1(reader.db,work=reader,frame=frame,
            selector=ObserveCurrentJointHabitRecoveryRequestV1(tick.producer_operation_id),producer_original=producer,issuer=issuer)
        status = 'observed' if observed.coverage == 'complete' else 'waiting'
        return _observation(reader,status,None if status == 'observed' else 'actual_joint_habit_dependency',observed.missing_inputs)
    if tick.recipe_version == 'foreground-projection.v1':
        return observe_current_personal_mesh_recovery_v1(reader,original)
    return observe_committed_world_v1(reader.db,work=reader,frame=frame,producer_operation_id=tick.producer_operation_id,issuer=issuer)

def observe_current_personal_mesh_recovery_v1(reader,original):
    require_current_semantic_recovery_work_v3(reader,db=reader.db,namespace=reader.namespace,
        producer_operation_id=reader.semantic_row.tick.producer_operation_id)
    from .personal_candidate_eligibility_v1 import PREPARE,ADOPT
    if original['operation_kind'] == PREPARE:
        return _observation(reader,'waiting','actual_adopted_personal_projection_result_required',
            (original['receipt'].operation_id.replace('personal-eligibility-prepare:','personal-eligibility-adopt:',1),))
    if original['operation_kind'] != ADOPT:
        raise AuthorityUnavailable('Personal recovery is outside its actual two-W01 recipe')
    return _observation(reader,'observed',None)

def advance_semantic_recovery_read_v3(graph,work):
    reader = _require(work.state)
    if reader.fence is not None:
        graph._validate_read_fence_v3(reader.fence)
    reader.now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    with bind_runtime_storage_operation_v3(reader.operation,reader.db):
        if reader.phase == 'semantic_metadata':
            with reader.store._lock,runtime_storage_quantum_v3(reader.db) as meter:
                reader.db.execute('BEGIN')
                try:reader.semantic_metadata.advance(meter)
                finally:reader.db.rollback()
            if reader.semantic_metadata.complete:
                reader.semantic_rows = reader.semantic_metadata.rows
                reader.phase = 'semantic_owner'
            return GraphStorageStepV3('progress')
        if reader.semantic_index == len(reader.semantic_rows):
            task = reader.semantic_metadata
            page = SemanticRecoveryPageV1(reader.namespace,reader.selector.after_token,task.through_token,
                task.next,task.coverage == 'round_eof',tuple(reader.semantic_observations))
            from .source_correction_read_v3 import _heap
            reader.operation.retain(_heap(page)*3+4096)
            reader.read_finished = True
            reader.result = _SemanticRecoveryResultV3(_TERMINAL_ISSUER,reader,page)
            return GraphStorageStepV3('complete',reader.result)
        reader.semantic_row = reader.semantic_rows[reader.semantic_index]
        row,tick = reader.semantic_row,reader.semantic_row.tick
        if row.disposition != 'current_locator' or reader.now >= tick.original_deadline_utc:
            observed = metadata_recovery_observation_v1(row)
            if reader.now >= tick.original_deadline_utc and observed.status != 'expired':
                observed = _observation(reader,'expired','original_tick_deadline_expired_metadata_only')
            _finish_row(reader,observed)
            return GraphStorageStepV3('progress')
        try:
            if reader.semantic_owner_entry is not None:
                if _self_descriptor(_read_current_self(reader)) != reader.semantic_self_descriptor:
                    raise AuthorityUnavailable('Semantic Source Scope current Self changed before body continuation')
                reader.semantic_owner_entry.require_permission_v3(reader)
            if reader.phase == 'semantic_owner':
                _begin_metadata_scope(reader)
                with reader.store._lock,runtime_storage_quantum_v3(reader.db) as meter:
                    reader.db.execute('BEGIN')
                    try:
                        current_tick = meter.read_fixed_row(reader.db,'graph_atoms',('revision','valid'),
                            'bot=? AND persona=? AND token=?',(*reader.namespace.as_tuple,row.ref))
                        if current_tick != (row.revision,1):
                            raise AuthorityUnavailable('Semantic row changed after the fixed metadata EOF')
                        head = meter.read_fixed_row(reader.db,'graph_domain_production_originals_v1',('domain','operation_kind'),
                            'bot=? AND persona=? AND operation_id=?',(*reader.namespace.as_tuple,tick.producer_operation_id))
                    finally:reader.db.rollback()
                if head is None:
                    raise AuthorityUnavailable('Semantic producer metadata is absent')
                reader.semantic_producer_kind = head[1]
                reader.semantic_profile = require_semantic_recipe_operation_v1(tick.recipe_version,head[1])
                if reader.semantic_profile.domain != head[0]:
                    raise AuthorityUnavailable('Semantic producer metadata crossed its closed installed recipe')
                reader.semantic_original_refs.update(original.original_ref for original in
                    (tick.causal_original,*tick.predecessors,*tick.semantic_originals))
                reader.phase = 'semantic_predecessor_metadata'
                return GraphStorageStepV3('progress')
            if reader.phase == 'semantic_predecessor_metadata':
                with reader.store._lock,runtime_storage_quantum_v3(reader.db) as meter:
                    reader.db.execute('BEGIN')
                    try:
                        entry = meter.read_fixed_row(reader.db,'graph_domain_production_originals_v1',
                            ('operation_id','domain','original_digest'),
                            'bot=? AND persona=? AND operation_id>? ORDER BY operation_id',
                            (*reader.namespace.as_tuple,reader.semantic_ref_cursor))
                    finally:reader.db.rollback()
                if entry is not None:
                    reader.semantic_ref_cursor = entry[0]
                    ref = entry[1]+'-current:'+entry[2][:48]
                    if ref in reader.semantic_original_refs:
                        if ref in reader.semantic_ref_matches:
                            raise AuthorityUnavailable('Semantic predecessor metadata is ambiguous')
                        reader.semantic_ref_matches[ref] = entry[0]
                        reader.semantic_original_ops.add(entry[0])
                    return GraphStorageStepV3('progress')
                reader.phase = 'semantic_owner'
                _current_owner(reader)
                return GraphStorageStepV3('progress')
            if reader.phase == 'semantic_census_headers':
                census=_CENSUS_ROWS_V3[reader].require_v3(reader)
                with reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
                    reader.db.execute('BEGIN')
                    try:
                        reader.require_data_current_v3(meter)
                        census.advance_v3(reader,meter)
                    finally:reader.db.rollback()
                if census.complete:reader.phase='semantic_observe'
                return GraphStorageStepV3('progress')
            if reader.phase == 'semantic_sources':
                gate = reader.semantic_source_gate
                if gate is not None and not gate.complete:
                    with reader.store._lock:gate.advance()
                    return GraphStorageStepV3('progress')
                if gate is not None:
                    reader.semantic_allowed_keys.update(AtomKey.from_token(token) for token in gate.heads)
                reader.semantic_source_complete = True
                _SOURCE_ROWS[reader] = _source_row_identity(reader)
                reader.phase = 'semantic_observe'
                return GraphStorageStepV3('progress')
            with reader.store._lock,runtime_storage_quantum_v3(reader.db) as meter:
                reader.db.execute('BEGIN')
                try:
                    reader.require_data_current_v3(meter)
                    if reader.pending is not None:
                        _advance_background_pending_v3(reader,meter)
                        return GraphStorageStepV3('progress')
                    with bind_background_reads_v3(reader,db=reader.db):
                        try:
                            original=read_committed_semantic_producer_v3(reader,db=reader.db,namespace=reader.namespace,
                                producer_operation_id=tick.producer_operation_id,issuer=graph._GraphCoordinator__d11_issuer)
                            if not _CENSUS_ROWS_V3[reader].require_v3(reader).complete:
                                reader.phase='semantic_census_headers'
                                return GraphStorageStepV3('progress')
                            observed = _observe(reader)
                        except BackgroundReadNeededV3 as needed:
                            _start_background_request_v3(reader,needed.request)
                            return GraphStorageStepV3('progress')
                finally:reader.db.rollback()
            _finish_row(reader,observed)
        except (AuthorityUnavailable,ValueError) as error:
            _finish_row(reader,_observation(reader,'unavailable','current_semantic_dependency_unavailable',
                (type(error).__name__,)))
    if reader.fence is not None:
        graph._validate_read_fence_v3(reader.fence)
    return GraphStorageStepV3('progress')

_SEMANTIC_POINT_SHAPES_V3=frozenset({
    ('graph_atoms',('revision','value','valid'),('token','bot','persona')),
    ('graph_history',('event_id','value','valid'),('token','revision')),
    ('graph_history',('value','valid','event_id'),('token','revision')),
    ('graph_history',('event_bot','event_persona','event_id','valid'),('token','revision')),
    ('graph_history',('event_id','valid'),('token','revision')),
    ('graph_domain_production_originals_v1',
        ('domain','operation_kind','request_digest','original_digest','original_payload_json',
         'read_versions_json','bundle_digest','receipt_json','receipt_digest'),('bot','persona','operation_id')),
    ('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),('bot','persona','operation_id')),
    ('graph_bundle_operations',('digest','receipt_json','commit_seq'),('bot','persona','operation_id')),
    ('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq','receipt_json'),('bot','persona','operation_id')),
    ('graph_bundle_operations',('receipt_json','commit_seq'),('bot','persona','operation_id')),
    ('graph_bundle_operations',('receipt_json',),('bot','persona','operation_id')),
    ('graph_bundle_operations',('commit_seq',),('bot','persona','operation_id')),
    ('graph_d11_life_originals_v1',('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref')),
})

def semantic_recovery_require_request_v3(reader,request):
    require_current_semantic_recovery_work_v3(reader,db=reader.db,namespace=reader.namespace,
        producer_operation_id=reader.semantic_row.tick.producer_operation_id)
    table,columns,keys,key = request
    if ((table,tuple(columns),tuple(keys))not in _SEMANTIC_POINT_SHAPES_V3
            or len(key)!=len(keys)):
        raise AuthorityUnavailable('Semantic point is outside its exact registered columns/PK/arity')
    if table in ('graph_atoms','graph_history'):
        atom = AtomKey.from_token(key[0])
        if atom not in reader.semantic_allowed_keys:
            raise AuthorityUnavailable('Semantic body is outside its actual producer/dependency Source readset')
        census=_CENSUS_ROWS_V3.get(reader)
        if census is None or not census.require_v3(reader).complete:
            raise AuthorityUnavailable('Semantic Body cannot precede actual complete header and Source qualification')
        if table=='graph_atoms':
            with runtime_storage_quantum_v3(reader.db)as meter:
                header=meter.read_fixed_row(reader.db,'graph_atoms',('revision',),
                    'bot=? AND persona=? AND token=?',(*reader.namespace.as_tuple,atom.token))
            revision=0 if header is None else header[0]
            if(atom.token,revision)not in census.body_pairs:
                raise AuthorityUnavailable('Semantic current Body version is classified metadata-only by its own actual Original')
        if table=='graph_history':
            allowed=frozenset(reader.semantic_allowed_history)
            if(_HISTORY_ROWS.get(reader)!=(_source_row_identity(reader),allowed)
                    or type(key[1])is not int or key[1]<1 or (atom.token,key[1])not in allowed):
                raise AuthorityUnavailable('Semantic history requires its exact positive authenticated original version')
    elif table in ('graph_domain_production_originals_v1','graph_bundle_operations'):
        if key[:2] != reader.namespace.as_tuple or key[2] not in reader.semantic_original_ops:
            raise AuthorityUnavailable('Semantic original is outside the exact committed producer')
    elif table == 'graph_d11_life_originals_v1':
        if key[:2] != reader.namespace.as_tuple or key[-1] not in reader.semantic_original_refs:
            raise AuthorityUnavailable('Semantic signed original is outside its exact committed predecessor')
    else:
        raise AuthorityUnavailable('Semantic recovery has no fixed body reader for this family')
    return True

def semantic_recovery_require_family_v3(reader,type_id):
    require_current_semantic_recovery_work_v3(reader,db=reader.db,namespace=reader.namespace,
        producer_operation_id=reader.semantic_row.tick.producer_operation_id)
    if type_id not in {page.type_id for page in reader.semantic_row.tick.query_coverage}:
        raise AuthorityUnavailable('Semantic query has no actual original negative coverage')
    census=_CENSUS_ROWS_V3.get(reader)
    if census is None or not census.require_v3(reader).complete:
        raise AuthorityUnavailable('Semantic family Body cannot precede the actual complete header census')
    if any((version.key.token,version.revision)not in census.body_pairs
            for version in census.current_versions if version.key.type_name==type_id):
        raise AuthorityUnavailable('Semantic family contains metadata-only rows; exact own Source-qualified Body is required')
    return True

@dataclass(frozen=True,slots=True,weakref_slot=True,eq=False)
class SemanticRecoveryQualifiedFactsV3:
    namespace: NamespaceId
    tick: SemanticTickV1
    producer_operation_kind: str
    producer_operation_id: str
    producer_original: ProductionOriginalRefV1
    producer_receipt_digest: str
    read_versions: tuple[GraphVersion,...]
    query_coverage: tuple[ProductionQueryCoverageV1,...]
    source_closure: tuple[GraphVersion,...]
    owner_guard: ProductionOwnerGuardV1
    activation_generation: int
    storage_generation: int
    access_epoch: int
    delete_epoch: int

def require_semantic_recovery_qualified_facts_v3(facts):
    reader = _FACTS.get(facts)
    if reader is None:
        raise AuthorityUnavailable('Mesh envelope facts were not issued by the actual qualified recovery Work')
    require_current_semantic_recovery_work_v3(reader,db=reader.db,namespace=facts.namespace,
        producer_operation_id=facts.producer_operation_id)
    return facts

def semantic_recovery_require_rows_v3(reader,request):
    table,columns,groups,group,order,limit = request
    if (table != 'graph_atoms' or columns != ('token','revision','value','valid')
            or groups != ('bot','persona','type_name') or len(group)!=3
            or group[:2] != reader.namespace.as_tuple or order != ('token',) or limit not in (None,129)):
        raise AuthorityUnavailable('Semantic query is outside its fixed original family')
    return semantic_recovery_require_family_v3(reader,group[2])

def require_semantic_recovery_owner_identity_v3(reader):
    _require(reader)
    task = reader.semantic_metadata
    if (task is None or not task.complete or reader.semantic_rows is not task.rows
            or reader.semantic_row is not reader.semantic_rows[reader.semantic_index]
            or reader.phase not in ('semantic_owner','semantic_sources','semantic_observe')
            or reader.fence is None or reader.fence.authority != reader.authority
            or reader.read_scope.operation_id != reader.operation_id+':source:'+str(reader.semantic_index)
            or reader.semantic_row.disposition != 'current_locator'
            or reader.now >= reader.semantic_row.tick.original_deadline_utc):
        raise AuthorityUnavailable('Semantic Owner entry requires its actual completed fixed metadata page and original TTL')
    return reader

def semantic_recovery_owner_cause_metadata_v3(reader):
    require_semantic_recovery_owner_identity_v3(reader)
    row = reader.semantic_row
    tick = row.tick
    return (reader.selector,reader.semantic_metadata.through_token,
        tuple((item.ref,item.revision) for item in reader.semantic_rows),row.ref,row.revision,
        tick.recipe_version,tick.producer_operation_id,tick.source_roots,tick.purpose,tick.audience,
        tick.original_deadline_utc,reader.operation.deadline_utc)

def observe_committed_world_v1(db,*,work,frame,producer_operation_id,issuer):
    require_current_semantic_recovery_work_v3(work,db=db,namespace=frame.envelope.authority.namespace,
        producer_operation_id=producer_operation_id)
    original = read_committed_semantic_producer_v3(work,db=db,namespace=work.namespace,
        producer_operation_id=producer_operation_id,issuer=issuer)
    kind = original['operation_kind']
    from .d03_world_history_v1 import world_progress_digest_v1
    if kind in ('adopt_world_assertion_v1','relearn_world_assertion_v1'):
        semantic_value = original['payload']['provenance']['world_assertion']
    elif kind == 'project_world_perspective_v1':
        semantic_value = original['payload']['provenance']['world_expression']
    else:
        raise AuthorityUnavailable('World recovery has no fixed observer for this producer')
    if world_progress_digest_v1(kind,semantic_value) != work.semantic_row.tick.semantic_digest:
        raise AuthorityUnavailable('World recovery semantic state differs from its actual producer trace')
    from .d01_production_operations_v1 import CurrentDomainReadV1
    read = CurrentDomainReadV1(frame)
    read.check(db)
    for version in original['receipt'].write_versions:
        if read.head(db,version.key,required=True).revision != version.revision:
            raise AuthorityUnavailable('World recovery lost its exact currently adopted producer version')
    return _observation(work,'observed',None)

_TERMINAL_ISSUER=object()
_TERMINALS=WeakKeyDictionary()

class _SemanticRecoveryResultV3:
    """Owned storage payload: only the fixed public page leaves this Work."""
    def __init__(self,issuer,reader,page):
        if issuer is not _TERMINAL_ISSUER:
            raise AuthorityUnavailable('Semantic result requires its actual completed READ Work')
        _require(reader)
        if(type(page)is not SemanticRecoveryPageV1 or not reader.read_finished
                or page.namespace!=reader.namespace or page.observations!=tuple(reader.semantic_observations)
                or reader.semantic_index!=len(reader.semantic_rows)):
            raise AuthorityUnavailable('Semantic terminal differs from its completed exact page EOF')
        self.reader,self.page=reader,page
        _TERMINALS[self]=(reader,reader.work,reader.operation,page,reader.selector)
    def require_result_v3(self,work):
        record=_TERMINALS.get(self)
        reader=self.reader
        if(record!=(reader,work,reader.operation,self.page,reader.selector)
                or reader.work is not work or work.state is not reader or work.operation is not reader.operation
                or work.kind!='domain_background_read_v3' or reader.kind!=_KIND
                or reader.operation.closed or not reader.read_finished or not work._finish_called):
            raise AuthorityUnavailable('Semantic terminal lost its actual finalized retained READ')
        work._require_invocation(reader.graph)
        return self.page
    def release_payload_v3(self):
        record=_TERMINALS.pop(self,None)
        if record is None:return
        reader=record[0]
        try:reader.release_payload_v3()
        finally:self.page=self.reader=None


def require_semantic_recovery_terminal_value_v3(value,work):
    if type(value)is not _SemanticRecoveryResultV3:
        raise AuthorityUnavailable('Semantic READ returned an unowned public value')
    return value.require_result_v3(work)

