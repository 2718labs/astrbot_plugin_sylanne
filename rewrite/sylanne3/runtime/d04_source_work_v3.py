"""Installed D04 independent Source READ followed by its original fresh WRITE."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from time import monotonic
from uuid import uuid4
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, OWNER_GRANT_TYPE
from ..runtime_contracts import NamespaceId, FenceScope, AuthorityContext, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3)
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_KEY = object()
_READERS = WeakKeyDictionary()
_NUMERIC_ROWS_SEALS = WeakKeyDictionary()
_NUMERIC_PREPARED_ROWS_SEALS = {}
_BOUND = ContextVar('installed_d04_source_work_v3', default=None)
_SERIES_FREEZE = ContextVar('installed_d04_series_freeze_v3',default=None)
_SERIES_FREEZE_WRITE = ContextVar('installed_d04_series_freeze_write_v3',default=None)
_CONTROL_TYPES = frozenset({OWNER_GRANT_TYPE,'d01.persona_activation.v1','d12.active_scheme_head.v1','memory.access',
    'd06.source_correction_head.v1','d03.role_binding','d03.account_binding','d03.entity_anchor','d05.boundary_rule'})
_NATIVE_NUMERIC_TYPES = frozenset({'d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2',
    'd04.feeling_state.v1','d04.authored_feeling_state.v1','d04.authored_mood_state.v1','d04.numeric_coupling.v1',
    'd04.authored_root_topology.v3','d04.sourced_numeric_drive.v1','d04.contribution_ledger.v1'})
_CALLBACK_MODULES = {
    'interpretation':'d04_product_pipeline_v3','prepare':'d04_product_pipeline_v3',
    'acquire':'d04_product_pipeline_v3','seal_call':'d04_series_execution_v1',
    'adopt':'d04_product_pipeline_v3','drive':'d04_installed_drive_v3',
    'numeric_prepare':'d04_installed_numeric_v3','numeric_adopt':'d04_installed_numeric_v3',
    'c04_encoding':'c04_installed_encoding_v3'}


@dataclass(frozen=True,slots=True)
class InstalledD04SourceSelectorV3:
    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    operation_id: str
    stage: str
    request_digest: str


def require_installed_d04_source_reader_v3(reader):
    expected = _READERS.get(reader)
    if type(reader) is not _InstalledD04SourceReadV3 or expected is None or expected != (
            reader.graph,reader.selector,reader.operation,reader.fence,reader.authority,
            reader.lease,reader.graph_stamp,reader.work,reader.commit):
        raise AuthorityUnavailable('D04 Source requires its actual independently registered Work')
    if reader.operation.closed or reader.work.state is not reader or reader.work.operation is not reader.operation:
        raise AuthorityUnavailable('D04 actual Source Work is no longer retained')
    reader.work._require_invocation(reader.graph)
    return reader


def installed_d04_background_owner_identity_v3(reader):
    r = require_installed_d04_source_reader_v3(reader)
    if r.read_finished or r.fence.scope.operation != 'read' or r.write_scope is not None:
        raise AuthorityUnavailable('D04 current Owner READ left its exact Source phase')
    return r,canonical_digest(r.selector)


def require_bound_installed_d04_source_v3(graph,db,namespace,*,c02_operation_id=None,source_ref=None,epoch=None,now_utc=None):
    reader = _BOUND.get()
    if reader is None:
        return None
    require_installed_d04_source_reader_v3(reader)
    if (reader.graph is not graph or reader.db is not db or reader.namespace != namespace
            or c02_operation_id is not None and c02_operation_id != reader.selector.c02_operation_id
            or source_ref is not None and source_ref != reader.selector.source_ref
            or reader.phase not in {'current','write'}):
        raise AuthorityUnavailable('D04 Source binding crossed its actual consumer/namespace/C02')
    if epoch is not None and epoch!=reader.graph_stamp[1]:
        raise AuthorityUnavailable('D04 bound current input epoch changed')
    now=reader.now_utc
    if now_utc is not None and (now_utc<reader.initial_now_utc or now_utc>=reader.operation.deadline_utc):
        raise AuthorityUnavailable('D04 bound current input time left its original deadline')
    if reader.attention is not None and max(now,now if now_utc is None else now_utc)>=reader.attention.ticket.valid_until:
        raise AuthorityUnavailable('D04 bound new-stage live Focus/attention expired')
    return reader


class _D04NamespaceReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,reader):
        self.reader = reader
        self.canonical_eofs = {}
        super().__init__(reader.graph,reader.operation,reader.fence,
            projection_types=_CONTROL_TYPES,selected_tokens=frozenset(),
            census_schema='d04.source-control-census.v3',leaf_schema='d04.source-control-leaf.v3')
    def _next(self,meter):
        super()._next(meter)
        if self.pending is not None:
            key,revision,valid,_kind,cell = self.pending
            self.heads[key.token] = (revision,bool(valid),cell)
    def _remember_eof_v3(self,key,revision,valid,cell,header,digest):
        if key.token not in self.canonical_eofs:
            self.reader.operation.retain(len(key.token)*4+512)
        self.canonical_eofs[key.token]=(revision,bool(valid),cell,tuple(header),digest)
    def _finish_census_value_v3(self,key,revision,valid,type_name,cell,digest):
        self._remember_eof_v3(key,revision,valid,cell,self.cell.header,digest)
        return super()._finish_census_value_v3(key,revision,valid,type_name,cell,digest)
    def _source_from_inspection_v3(self,original):
        self._remember_eof_v3(original.key,original.revision,original.valid,
            original.cell_id,original.header,original.payload_sha256)
        return super()._source_from_inspection_v3(original)
    def _graph_eof_v3(self):
        self.reader.census_digest = self.root


class _InstalledD04SourceReadV3:
    def __init__(self,key,graph,bootstrap,bundle,selector,commit,semantic,fence_observer,
                 operation,fence,authority,lease,initial_reading,initial_now):
        if key is not _KEY:
            raise TypeError('D04 Source has no public issuer')
        self.graph,self.bootstrap,self.bundle,self.selector = graph,bootstrap,bundle,selector
        self.commit,self.semantic,self.fence_observer = commit,semantic,fence_observer
        self.store,self.db = graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.runtime = graph._GraphCoordinator__domain_production_runtime_v1
        self.origin_signer = graph._GraphCoordinator__d11_issuer._signer
        self.namespace,self.operation,self.fence,self.authority,self.lease = selector.namespace,operation,fence,authority,lease
        self.operation_id,self.selection_digest = selector.operation_id,operation.selection_digest
        self.graph_stamp = (fence.metadata,fence.epoch)
        self.initial_reading,self.initial_now_utc = initial_reading,initial_now
        self.initial_monotonic_deadline = monotonic()+operation.deadline_utc-initial_now
        self.work = None
        self.owner_binding = self.owner_guard = self.owner_grant = None
        self.owner_acl_authority = self.owner_principal = self.session_proof = None
        self.owner_entry = self.namespace_reader = None
        self.read_finished = False
        self.write_scope = None
        self.authority_epochs = None
        self.origin_columns,self.origin_support_readsets,self.origin_history = [],{},{}
        self.c02_columns,self.c02_points = {},{}
        self.c02_quote = self.ingress_receipt = None
        self.source_qualification = None
        self.current_control = self.role = self.current = self.snapshot = self.query = None
        self.attention = None
        self.scene_binding_atoms = ()
        self.ordinary_readout = self.role_support_manifest = self.selected_readout = None
        self.head = self.origins = self.route_identity = None
        self.source_versions = ()
        self.numeric_job = self.numeric_job_stamp = self.numeric_rows_seal = None
        self.series_locator=self.series_column=self.series_ready=self.series_existing_root=None
        self.series_root_header=self.series_prepared_header=self.series_origin=None
        self.series_source_refs=()
        self.numeric_job_worker_fence=None
        self.numeric_topology=None
        self.phase,self.complete,self.result = 'owner',False,None

    @property
    def now_utc(self):
        from .first_ingress_v2 import trusted_upper_at_v4
        now = monotonic()
        upper = trusted_upper_at_v4(self.initial_reading,now)
        if upper >= self.operation.deadline_utc or now >= self.initial_monotonic_deadline:
            raise AuthorityUnavailable('D04 Source exceeded its original Root/ingress deadline')
        return upper

    def require_current(self,*,meter):
        require_installed_d04_source_reader_v3(self)
        self.operation.handle.require_current(meter)
        self.now_utc
        expected_stamp=self.graph_stamp if self.numeric_job_stamp is None else self.numeric_job_stamp
        if self.graph._v2_graph_stamp(self.namespace) != expected_stamp:
            raise AuthorityUnavailable('D04 original Graph revision/epoch changed')
        actual = meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',self.namespace.as_tuple)
        if self.authority_epochs is None:
            self.authority_epochs = actual
        elif self.authority_epochs != actual:
            raise AuthorityUnavailable('D04 current Source access/deletion epochs changed')
        return self

    @contextmanager
    def quantum_v3(self):
        require_installed_d04_source_reader_v3(self)
        if self.write_scope is None:
            self.owner_entry.require_permission_v3(self)
        with bind_runtime_storage_operation_v3(self.operation,self.db),self.store._lock,runtime_storage_quantum_v3(self.db) as meter:
            inherited = self.db.in_transaction
            if inherited and self.write_scope is None:
                raise AuthorityUnavailable('D04 Source READ cannot inherit another SQL transaction')
            if not inherited:
                self.db.execute('BEGIN')
            try:
                self.require_current(meter=meter)
                yield meter
                self.require_current(meter=meter)
            finally:
                if not inherited:
                    self.db.rollback()
        if self.write_scope is None:
            self.owner_entry.require_permission_v3(self)

    def _body_atom(self,key):
        head = self.namespace_reader.heads.get(key.token)
        if head is None:
            return GraphAtom(key,0,{},False)
        column = DispatchOriginalJSONReadV3(self,table='graph_atoms',column='value',
            key_columns=('token',),key=(key.token,),cell_id=head[2])
        while not column.complete:
            with self.quantum_v3() as meter:
                column.advance(meter)
        value = column.require_v3(self)
        return GraphAtom(key,head[0],value,head[1])

    def _event_source_all(self):
        from ..memory_types import source_key,access_key,validate_access
        from ..domains.d06 import source_correction_head_key
        ns = self.namespace
        atoms = {a.key.token:a for a in self.namespace_reader.atoms}
        active,done,versions = set(),set(),{}
        audiences = (self.route_identity['conversation_ref'],)
        def visit(ref):
            if ref in active or len(active)+len(done) >= 256:
                raise AuthorityUnavailable('D04 event Source ancestry is cyclic or exceeds its bound')
            if ref in done:
                return
            source = self.namespace_reader.sources.get(ref)
            key = AtomKey.from_token(ref)
            if source is None or not source.valid or key != source_key(*ns.as_tuple,key.owner.subject or ''):
                raise AuthorityUnavailable('D04 event Source metadata original is unavailable')
            ak,ck = access_key(*ns.as_tuple,key.owner.subject),source_correction_head_key(ns,key.owner.subject)
            access = atoms.get(ak.token)
            if access is None or not access.valid or ck.token in self.namespace_reader.heads:
                raise AuthorityUnavailable('D04 event Source access/correction no longer qualifies')
            validate_access(access.value)
            raw = source.metadata
            if (raw['source_id'] != key.owner.subject or access.value['source_id'] != raw['source_id']
                    or access.value['status'] != 'active' or 'expression' not in raw['purposes']
                    or 'expression' not in access.value['purposes']
                    or not set(audiences) <= set(raw['audiences'])
                    or not set(audiences) <= set(access.value['audiences'])):
                raise AuthorityUnavailable('D04 event Source does not permit actual expression audience')
            active.add(ref)
            for parent in raw['parent_source_ids']:
                visit(source_key(*ns.as_tuple,parent).token)
            active.remove(ref)
            done.add(ref)
            versions.update({key:GraphVersion(key,source.revision),
                ak:GraphVersion(ak,access.revision),ck:GraphVersion(ck,0)})
        roots=tuple(sorted({self.selector.source_ref,*self.series_source_refs}))
        if len(roots)>32:raise AuthorityUnavailable("D04 direct Source roots exceed their original bound")
        if self.selector.stage=="series_freeze":
            owner=self.owner_entry.require_for_v3(self)
            if "expression"not in owner.purposes or not set(audiences)<=set(owner.audiences):
                raise AuthorityUnavailable("series read is outside its actual Owner Source permission")
        for ref in roots:visit(ref)
        self.event_source_refs = tuple(sorted(done))
        self.source_versions = tuple(versions.values())


    def _require_prepared_manifest(self):
        if self.selector.stage in {'interpretation','prepare','series_freeze'}:
            return
        from .d04_product_pipeline_v3 import ids
        from .d01_ordinary_origin_read_v3 import _fixed,_column
        from .d04_ordinary_readout_v3 import d04_role_manifest_wire_v3,validate_d04_role_manifest_wire_v3
        job_id=ids(self.namespace,self.selector.c02_operation_id)['job']
        key=(*self.namespace.as_tuple,'appraisal',job_id)
        header=_fixed(self,'graph_d04_originals_v3',('payload_digest',),
            'bot=? AND persona=? AND kind=? AND original_ref=?',key)
        if header is None:
            raise AuthorityUnavailable('D04 continuation has no actual immutable appraisal original')
        column=_column(self,'graph_d04_originals_v3','payload_json',
            ('bot','persona','kind','original_ref'),key,'d04_prepared')
        raw=column.metadata
        manifest=raw.get('role_support_manifest')
        validate_d04_role_manifest_wire_v3(manifest,self.namespace)
        if (column.semantic_digest!=header[0] or manifest!=d04_role_manifest_wire_v3(self.role_support_manifest)
                or raw['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or raw['job_id']!=job_id or tuple(raw['audience'])!=(self.route_identity['conversation_ref'],)
                or raw['purpose']!='expression'):
            raise AuthorityUnavailable('D04 original provider input no longer has the same qualified ordinary role')
        rows={item['ref']:item for item in raw['read_rows']}
        from ..memory_types import access_key
        for ref in self.event_source_refs:
            source_key=AtomKey.from_token(ref)
            for key in (source_key,access_key(*self.namespace.as_tuple,source_key.owner.subject)):
                previous=rows.get(key.token)
                current=self.namespace_reader.heads.get(key.token)
                if (previous is None or current is None or not previous['valid']
                        or current[:2]!=(previous['revision'],True)):
                    raise AuthorityUnavailable('D04 original event Source/access changed before Body readout')

    def _prepare_current(self):
        from .d04_c02_source_originals_v3 import read_d04_c02_inputs_v3
        from .dispatch_current_projection import CurrentDispatchProjectionV1,_derive_verified_current_domain_reads_v1
        from ..domains.d03.context import RoleBindingRequest,ContextProvider
        from ..runtime_contracts import VersionedRef
        inputs,route,binding = read_d04_c02_inputs_v3(self)
        self.source_qualification = inputs.source_qualification
        if self.selector.stage not in {'drive','numeric_prepare','c04_encoding'}:
            from ..domains.d07 import _qualify_focus_attention_values_v3
            from .reply_model_job import CurrentReplyModelInputsV1
            attention = _qualify_focus_attention_values_v3(self.snapshot,self.namespace,
                now=self.now_utc,source_reader=self.snapshot.get)
            if (attention is None or attention.ticket.causal_root != self.selector.source_ref
                    or attention.ticket.source_refs != (self.selector.source_ref,)
                    or attention.ticket.category != 'interaction'
                    or attention.source_versions != (GraphVersion(AtomKey.from_token(self.selector.source_ref),inputs.source.source_revision),)):
                raise AuthorityUnavailable('D04 new stage lacks actual live original C02 Focus/attention')
            self.attention = attention
            inputs = CurrentReplyModelInputsV1(inputs.c02_receipt,inputs.source,attention,
                inputs.conversation_ref,self.snapshot)
        atoms = tuple(self.snapshot.atoms)
        projection = CurrentDispatchProjectionV1(self.namespace,self.graph_stamp[1].revision,
            tuple(a for a in atoms if a.valid and a.key.type_name == 'd03.role_binding'),
            tuple(a for a in atoms if a.valid and a.key.type_name == 'd05.boundary_rule'),
            canonical_digest((self.census_digest,self.query,'d04-current-domains.v3')))
        provider = self.graph._GraphCoordinator__providers.get('d03')
        if provider is None or type(provider[0]) is not ContextProvider:
            raise AuthorityUnavailable('D04 requires its actual D03 context provider')
        request = RoleBindingRequest('persona:'+self.namespace.persona_id,binding.target_entity_ref,
            None,route.scene_ref,'expression','reply',self.now_utc,True)
        with self.quantum_v3():
            role_read,boundary = _derive_verified_current_domain_reads_v1(self.db,projection,request,provider[0])
        if role_read.status != 'complete' or len(role_read.matched_bindings) != 1 or boundary.coverage != 'full':
            raise AuthorityUnavailable('D04 actual complete current role/boundary is unavailable')
        matched = tuple(a for a in projection.role_bindings
            if a.key.name == role_read.matched_bindings[0] and a.value.get('scene_ref') == route.scene_ref)
        if len(matched) != 1:
            raise AuthorityUnavailable('D04 current route role binding is ambiguous')
        scene = VersionedRef(matched[0].key.token,matched[0].revision)
        audience = VersionedRef(binding.binding_version.key.token,binding.binding_version.revision)
        self.scene_binding_atoms=projection.role_bindings
        self.current = (inputs,route,binding,self.snapshot,self.query,role_read,boundary,scene,audience)

    def _observe_write(self,scope):
        if (scope.operation != 'write' or scope.namespace != self.namespace
                or scope.graph_revision != self.graph_stamp[0].graph_revision
                or scope.graph_epoch != self.graph_stamp[1]):
            raise AuthorityUnavailable('D04 fresh WRITE differs from its completed actual Source READ')
        self.write_scope = scope
        if self.fence_observer is not None:
            self.fence_observer(scope)


def prepare_installed_d04_source_work_v3(graph,bootstrap,bundle,*,c02_operation_id,source_ref,
        operation_id,stage,request_digest,commit,semantic=False,fence_observer=None,original_deadline_utc=None):
    from ..graph_coordinator import _V2ReadFenceStateV3
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap)
    require_graph_storage_work_admission_v3(graph)
    module = _CALLBACK_MODULES.get(stage)
    series_chunk = (stage == 'numeric_prepare'
        and commit.__module__ == __package__+'.d04_series_execution_v1'
        and commit.__qualname__ == 'prepare_d04_series_chunk_v1.<locals>.prepare')
    if not series_chunk and (module is None or commit.__module__ != __package__+'.'+module
            or '<locals>.commit' not in commit.__qualname__):
        raise AuthorityUnavailable('D04 Source requires an actual fixed installed W01 stage closure')
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable('D04 Source changed its actual installed assembly')
    ns = bundle.installation_policy.namespace
    selector = InstalledD04SourceSelectorV3(ns,c02_operation_id,source_ref,operation_id,stage,request_digest)
    store,port = graph._GraphCoordinator__store,graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata,epoch = graph._v2_graph_stamp(ns)
        saved = store._db.execute('SELECT stage,c02_operation_id,source_ref,request_digest,attempt_id,permit_json,receipt_json,pre_revision,pre_epoch,anchor_json FROM graph_d04_installed_stage_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id)).fetchone()
    attempt = 'd04-stage:'+canonical_digest((ns,operation_id,stage,request_digest))[:48]
    if saved is not None:
        if saved[:5] != (stage,c02_operation_id,source_ref,request_digest,attempt):
            raise AuthorityUnavailable('D04 saved stage belongs to another actual immutable request')
        if saved[6] is not None:
            if saved[5] is None:
                raise AuthorityUnavailable('D04 saved terminal lost its actual original WRITE permit')
            from .d04_installed_stage_fence_v3 import _run_installed_d04_stage_v3,_D04PhaseTimingsV1
            return _run_installed_d04_stage_v3(graph,bootstrap,bundle,c02_operation_id=c02_operation_id,
                source_ref=source_ref,operation_id=operation_id,stage=stage,request_digest=request_digest,
                commit=commit,semantic=semantic,fence_observer=fence_observer,
                timings=_D04PhaseTimingsV1(operation_id))
    target = metadata.requirements
    anchor = port.current_anchor(namespace=ns,authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target,anchor):
        raise AuthorityUnavailable('D04 Source original Graph/Authority anchor differs')
    if saved is not None and (saved[7:9]!=(metadata.graph_revision,epoch.revision)
            or saved[9]!=canonical_serialize(asdict(anchor))):
        raise AuthorityUnavailable('D04 unresolved original stage cannot change its original snapshot')
    observed = port.observe_content_write_attempt_v1(namespace=ns,
        authority_namespace=target.authority_namespace,operation_id=attempt,expected_anchor=anchor)
    if saved is not None and saved[5] is not None or observed.state != 'absent' or observed.permit is not None:
        raise AuthorityUnavailable('D04 original WRITE must recover without crossing a new Source READ')
    policy = bundle.installation_policy
    reading = port.read_ingress_clock(bundle.ingress_clock)
    now = trusted_upper(reading)
    deadline = policy.root_grant.valid_until_utc
    if original_deadline_utc is not None:
        from math import isfinite
        if type(original_deadline_utc) not in (int,float) or not isfinite(original_deadline_utc):
            raise AuthorityUnavailable('D04 child needs its finite original parent deadline')
        deadline = min(deadline, original_deadline_utc)
    if now >= deadline:
        raise AuthorityUnavailable('D04 original installed Root grant expired')
    read_id = 'd04-source-read:'+uuid4().hex
    permit = port.begin_fence(namespace=ns,authority_namespace=target.authority_namespace,
        holder=policy.administrator_holder,generation=target.activation_generation,operation='read',
        operation_id=read_id,expected_anchor=anchor)
    scope = FenceScope(ns,target.authority_namespace,target.activation_generation,'read',read_id,
        permit,anchor,epoch,metadata.graph_revision)
    operation = lease = None
    try:
        operation = begin_runtime_storage_operation_v3(store._db,operation_id,deadline)
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        lease,capability = graph.grant(bootstrap,actor=policy.administrator_holder,issuer_domain='d04',
            namespace=ns,domains=('d01','d02','d03','d04','d05','d06','d07','d11','d12'),
            activation_generation=target.activation_generation,operation_id=operation_id)
        authority = AuthorityContext(policy.administrator_holder,'d04',capability,ns,
            tuple(sorted(graph._GraphCoordinator__leases[lease][5])),'expression',(),
            policy.root_grant.policy_ref,target.activation_generation)
        fence = _V2ReadFenceStateV3(authority,scope,metadata,epoch,None,None,None,None,None)
        reader = _InstalledD04SourceReadV3(_KEY,graph,bootstrap,bundle,selector,commit,semantic,
            fence_observer,operation,fence,authority,lease,reading,now)
        work = create_graph_storage_work_v3(graph,kind='d04_source_read_v3',operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        reader.work = work
        _READERS[reader] = (graph,selector,operation,fence,authority,lease,reader.graph_stamp,work,commit)
        return work
    except BaseException:
        graph._finish_read_fence_v3(_V2ReadFenceStateV3(None,scope,metadata,epoch,None,None,None,None,None))
        if lease is not None:
            graph.release_authority_lease(bootstrap,lease)
        if operation is not None:
            finish_runtime_storage_operation_v3(operation)
        raise


def advance_installed_d04_source_work_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from ..domains.d01 import PersonaDomain
    r = require_installed_d04_source_reader_v3(work.state)
    if graph is not r.graph:
        raise AuthorityUnavailable('D04 Source Work crossed its actual Graph')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        if r.phase == 'owner':
            from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
            entry = prepare_current_host_semantic_background_owner_read_entry_v3(r)
            r.owner_entry = entry
            r.owner_binding = entry.require_permission_v3(r)
            r.owner_guard = entry.current_owner_guard
            r.owner_grant = entry.grant_value_v3(r)
            r.owner_acl_authority = entry.owner_acl_authority
            r.owner_principal = entry.owner_principal
            r.phase = 'deadline'
        elif r.phase == 'deadline':
            from .d01_ordinary_origin_read_v3 import _column
            # The actual C02 envelope is streamed to EOF without retaining its Body.
            deadline_original = _column(r,'graph_first_ingress_c02_committed_seals_v2','bundle_json',
                ('bot','persona','operation_id'),(*r.namespace.as_tuple,r.selector.c02_operation_id),'c02')
            envelope = deadline_original.metadata['envelope']
            if envelope['parent_budget_lease_ref'] != r.bundle.installation_policy.root_grant.lease_id:
                raise AuthorityUnavailable('D04 actual C02 does not inherit this installed Root')
            if r.selector.stage=='series_freeze':
                with r.quantum_v3()as meter:
                    r.series_root_header=meter.read_fixed_row(r.db,'graph_d04_originals_v3',('payload_digest',),
                        'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,'series_root',_series_root_ref_v3(r)))
                deadline=r.operation.deadline_utc if r.series_root_header is not None else min(r.operation.deadline_utc,envelope['deadline_utc'])
            else:
                deadline = min(r.operation.deadline_utc,envelope['deadline_utc'])
            r.operation.deadline_utc = r.work.deadline_utc = deadline
            r.initial_monotonic_deadline = min(r.initial_monotonic_deadline,
                monotonic()+deadline-r.now_utc)
            if r.selector.stage=='series_freeze':
                r.series_locator=_D04SeriesPreparedLocatorTaskV3(r)
                r.phase='series_locator'
            else:
                r.namespace_reader = _D04NamespaceReadV3(r)
                r.phase = 'census'
        elif r.phase=='series_locator':
            with r.quantum_v3()as meter:r.series_locator.advance(meter)
            if r.series_locator.complete:
                r.series_source_refs=r.series_locator.source_refs
                _require_series_prepared_origin_v3(r)
                if r.series_root_header is None:
                    from datetime import datetime
                    deadline=min(r.operation.deadline_utc,datetime.fromisoformat(r.series_locator.binding.deadline_utc.replace('Z','+00:00')).timestamp())
                    r.operation.deadline_utc=r.work.deadline_utc=deadline
                    r.initial_monotonic_deadline=min(r.initial_monotonic_deadline,monotonic()+deadline-r.now_utc)
                r.namespace_reader=_D04NamespaceReadV3(r)
                r.phase='census'
        elif r.phase == 'census':
            with r.quantum_v3() as meter:
                kernel = r.namespace_reader
                if kernel.authority_epochs is None:
                    kernel.authority_epochs = kernel._epochs(meter)
                if kernel.cell is None:
                    kernel._next(meter)
                else:
                    kernel._cell(meter)
            if r.namespace_reader.graph_eof:
                r.snapshot = GraphSnapshot(tuple(r.namespace_reader.atoms),(r.graph_stamp[1],))
                r.query = QueryEpoch(r.namespace,'all',r.graph_stamp[1].revision)
                r.current_control = PersonaDomain.resolve_active_role_control_v3(r.snapshot,
                    namespace=r.namespace,current_guard=r.owner_guard)
                r.phase = 'origin'
        elif r.phase == 'origin':
            from .d01_ordinary_origin_read_v3 import read_current_ordinary_origins_v3
            r.head,r.origins = read_current_ordinary_origins_v3(r,r.current_control)
            r.current_control = _current_d04_role_control_v4(r)
            from .d04_c02_source_originals_v3 import read_d04_route_metadata_v3
            r.route_identity = read_d04_route_metadata_v3(r)
            r.phase = 'source'
        elif r.phase == 'source':
            from .d04_ordinary_readout_v3 import prepare_d04_ordinary_readout_v3
            r._event_source_all()
            if r.selector.stage!='series_freeze':
                r.ordinary_readout = prepare_d04_ordinary_readout_v3(r,r.head,r.origins,
                    purpose='expression',audience=(r.route_identity['conversation_ref'],))
                r.role_support_manifest = r.ordinary_readout.manifest
                r._require_prepared_manifest()
            r.phase = 'body'
        elif r.phase == 'body' and r.selector.stage=='series_freeze':
            r.series_column=DispatchOriginalJSONReadV3(r,table='graph_d04_originals_v3',column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),
                key=(*r.namespace.as_tuple,'numeric_prepared',_series_numeric_operation_v3(r)))
            r.phase='series_prepared'
        elif r.phase == 'body':
            atoms = {a.key:a for a in r.snapshot.atoms}
            for token in r.namespace_reader.heads:
                key = AtomKey.from_token(token)
                if key.type_name == 'd07.current_interpretation.v1':
                    from .d01_ordinary_origin_read_v3 import _column
                    locator = _column(r,'graph_atoms','value',('token',),(token,),
                        'interpretation',cell_id=r.namespace_reader.heads[token][2])
                    if locator.metadata.get('current') is True and r.selector.source_ref in locator.metadata.get('source_refs',()):
                        atoms[key] = r._body_atom(key)
                elif key.type_name in {'d07.focus.v1','d07.attention_ticket.v1'}:
                    atoms[key] = r._body_atom(key)
                elif key.type_name in _NATIVE_NUMERIC_TYPES and r.selector.stage in {
                        'drive','numeric_prepare','numeric_adopt','c04_encoding'}:
                    atoms[key] = r._body_atom(key)
                elif key.type_name in {'d03.world_event','d04.appraisal_bundle.v1'}:
                    identity = r.route_identity
                    suffix = canonical_digest({'namespace':r.namespace.as_tuple,
                        'platform_ref':identity['platform_ref'],'sender_ref':identity['sender_ref']})
                    account = next((a for a in r.snapshot.atoms if a.key.type_name == 'd03.account_binding'
                        and a.key.name == 'account:v1:'+suffix and a.valid),None)
                    arrival = 'world:message-arrival-v1:'+canonical_digest({'namespace':r.namespace.as_tuple,
                        'platform_ref':identity['platform_ref'],'conversation_ref':identity['conversation_ref'],
                        'message_id':identity['message_id'],'source_id':AtomKey.from_token(r.selector.source_ref).owner.subject})
                    evidence = None if account is None else account.value['verification_ref']
                    if key.owner.subject == arrival or token == evidence:
                        atoms[key] = r._body_atom(key)
            from ..domains.d06 import source_correction_head_key
            for ref in r.event_source_refs:
                key = AtomKey.from_token(ref)
                atoms[key] = r._body_atom(key)
                correction = source_correction_head_key(r.namespace,key.owner.subject)
                atoms[correction] = GraphAtom(correction,0,{},False)
            from .selected_persona_readout_v4 import prepare_selected_persona_readout_v4
            r.selected_readout = prepare_selected_persona_readout_v4(r,r.current_control,r.head,
                actual_scope=None,read_values=True)
            r.snapshot = GraphSnapshot(tuple(atoms.values()),(r.graph_stamp[1],))
            r.role = r.current_control
            r.ordinary_readout.require_current_v3(r)
            r._prepare_current()
            from .d04_root_topology_read_v1 import source_topology_required_v1,prepare_source_topology_metadata_v1
            if source_topology_required_v1(r):
                r.numeric_topology=prepare_source_topology_metadata_v1(r)
                r.phase='numeric_topology'
            else:r.phase='current'
        elif r.phase=='numeric_topology':
            with r.quantum_v3()as meter:r.numeric_topology.advance(meter)
            if r.numeric_topology.complete:
                versions={v.key:v for v in r.source_versions}
                for version in r.numeric_topology.source_versions:
                    previous=versions.get(version.key)
                    if previous is not None and previous!=version:
                        raise AuthorityUnavailable('numeric historical Source readset conflicts with current Source proof')
                    versions[version.key]=version
                r.source_versions=tuple(versions.values())
                r.phase='numeric_topology_body'
        elif r.phase=='numeric_topology_body':
            atoms={a.key:a for a in r.snapshot.atoms}
            for ref in sorted(r.numeric_topology.body_source_roots):
                key=AtomKey.from_token(ref)
                if key not in atoms:atoms[key]=r._body_atom(key)
            r.snapshot=GraphSnapshot(tuple(atoms.values()),(r.graph_stamp[1],))
            r.phase='current'
        elif r.phase=='series_prepared':
            with r.quantum_v3()as meter:r.series_column.advance(meter)
            if r.series_column.complete:
                _finish_series_prepared_read_v3(r)
                r.phase='series_origin'
        elif r.phase=='series_origin':
            if r.series_root_header is None:
                with r.quantum_v3()as meter:
                    token=_BOUND.set(r)
                    try:issue_installed_d04_numeric_rows_seal_v3(graph,r.db,r.series_ready.evidence_inputs.read_rows,prepared=r.series_ready.prepared)
                    finally:_BOUND.reset(token)
                r.result=r.series_ready
                r.phase,r.complete='committed',True
                return GraphStorageStepV3('complete',r.result)
            r.series_column=DispatchOriginalJSONReadV3(r,table='graph_d04_originals_v3',column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),key=(*r.namespace.as_tuple,'series_root',_series_root_ref_v3(r)))
            r.phase='series_existing'
        elif r.phase=='series_existing':
            with r.quantum_v3()as meter:r.series_column.advance(meter)
            if r.series_column.complete:
                r.result=_finish_series_existing_read_v3(r)
                r.phase,r.complete='committed',True
                return GraphStorageStepV3('complete',r.result)
        elif r.phase == 'current':
            graph._validate_read_fence_v3(r.fence)
            r.ordinary_readout.require_current_v3(r)
            graph._finish_read_fence_v3(r.fence)
            r.read_finished = True
            r.phase = 'write'
        elif r.phase == 'write':
            from .d04_installed_stage_fence_v3 import _run_installed_d04_stage_v3,_D04PhaseTimingsV1
            token = _BOUND.set(r)
            def source_commit(db,*args):
                from .d04_root_topology_read_v1 import bind_source_topology_write_v1
                with bind_source_topology_write_v1(r,db):return r.commit(db,*args)
            try:
                r.result = _run_installed_d04_stage_v3(graph,r.bootstrap,r.bundle,
                    c02_operation_id=r.selector.c02_operation_id,source_ref=r.selector.source_ref,
                    operation_id=r.selector.operation_id,stage=r.selector.stage,
                    request_digest=r.selector.request_digest,commit=source_commit if r.numeric_topology is not None else r.commit,semantic=r.semantic,
                    fence_observer=r._observe_write,timings=_D04PhaseTimingsV1(r.selector.operation_id,
                        deadline_utc=r.operation.deadline_utc))
            finally:
                _BOUND.reset(token)
            r.phase,r.complete = 'committed',True
            return GraphStorageStepV3('complete',r.result)
        else:
            raise AuthorityUnavailable('D04 Source Work reached its terminal')
    return GraphStorageStepV3('progress')


def finish_installed_d04_source_work_v3(graph,work,error):
    r=work.state
    if r in _READERS and error is None and (r.numeric_rows_seal is not None or r.selector.stage=='series_freeze'):
        work.result_lease=r.operation
        return
    _release_installed_d04_source_work_v3(graph,work,error)


def release_installed_d04_source_result_v3(work):
    r=work.state
    if r not in _READERS:return
    proof=r.numeric_rows_seal
    if proof is not None:
        proof.closed=True
        _NUMERIC_ROWS_SEALS.pop(proof,None)
        _NUMERIC_PREPARED_ROWS_SEALS.pop(id(proof.prepared),None)
    _release_installed_d04_source_work_v3(r.graph,work,None)


def _release_installed_d04_source_work_v3(graph,work,error):
    r = work.state
    if r not in _READERS:
        return
    try:
        if not r.read_finished:
            graph._finish_read_fence_v3(r.fence)
    finally:
        try:
            if r.owner_entry is not None:
                r.owner_entry.release_v3()
            graph.release_authority_lease(r.bootstrap,r.lease)
        finally:
            from .d04_root_topology_read_v1 import release_source_topology_metadata_v1
            release_source_topology_metadata_v1(r)
            r.numeric_topology=None
            _READERS.pop(r,None)
            if r.numeric_rows_seal is not None:
                r.numeric_rows_seal.closed=True
                _NUMERIC_ROWS_SEALS.pop(r.numeric_rows_seal,None)
                _NUMERIC_PREPARED_ROWS_SEALS.pop(id(r.numeric_rows_seal.prepared),None)
            r.numeric_rows_seal=r.numeric_job=r.numeric_job_stamp=None
            r.origin_columns.clear()
            r.origin_support_readsets.clear()
            r.origin_history.clear()
            r.c02_columns.clear()
            r.c02_points.clear()
            from .d04_ordinary_readout_v3 import release_prepared_d04_ordinary_readout_v3
            release_prepared_d04_ordinary_readout_v3(r.ordinary_readout)
            r.current=r.role=r.snapshot=r.ordinary_readout=r.selected_readout=r.attention=None
            r.series_locator=r.series_column=r.series_ready=r.series_existing_root=None
            r.series_origin=r.series_root_header=r.series_prepared_header=None
            r.series_source_refs=()
            r.result=None
            r.scene_binding_atoms=()
            r.commit=r.fence_observer=None
            if r.namespace_reader is not None:
                r.namespace_reader.canonical_eofs.clear()
                r.namespace_reader.heads.clear()
                r.namespace_reader.sources.clear()
                r.namespace_reader.atoms.clear()
            if error is None:
                work.result_lease = r.operation
            elif not r.operation.closed:
                finish_runtime_storage_operation_v3(r.operation)


def _current_d04_role_control_v4(reader):
    from dataclasses import replace
    from ..domains.d01 import ActiveRoleHeadControlV3,_activation_key
    from ..graph_types import owner_grant_key
    r=require_installed_d04_source_reader_v3(reader);control=r.current_control;head=r.head
    if (type(control)is not ActiveRoleHeadControlV3 or control.namespace!=r.namespace or head is None or head.namespace!=r.namespace
            or head.head_id!=control.head_id or head.version!=control.plan_version
            or head.plan_ref.key!=control.plan_key):
        raise AuthorityUnavailable('D04 role control lacks its actual complete origin head metadata')
    activation_key=_activation_key(r.namespace);grant_key=owner_grant_key(*r.namespace.as_tuple)
    activation=r.snapshot.get(activation_key);grant=r.snapshot.get(grant_key)
    if activation is None or grant is None or not activation.valid or not grant.valid:
        raise AuthorityUnavailable('D04 role control lacks actual activation/Owner metadata')
    versions=(GraphVersion(activation_key,head.activation_ref.revision),head.plan_ref,GraphVersion(grant_key,grant.revision))
    current_versions={version.key:version.revision for version in versions}
    if any(current_versions.get(version.key)!=version.revision for version in control.read_versions):
        raise AuthorityUnavailable('D04 actual D01 control versions differ from the origin metadata head')
    with r.quantum_v3()as meter:
        for version in versions:
            expected=r.namespace_reader.heads.get(version.key.token)
            current=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,version.key.token))
            if expected is None or expected[:2]!=(version.revision,True)or current!=(expected[0],int(expected[1]),expected[2]):
                raise AuthorityUnavailable('D04 role control actual activation/plan/Owner header changed')
    return control if control.read_versions==versions else replace(control,read_versions=versions)


def bound_active_role_control_state_v3(reader,guard):
    r=require_installed_d04_source_reader_v3(reader)
    if (require_bound_installed_d04_source_v3(r.graph,r.db,r.namespace)is not r or guard!=r.owner_guard
            or r.current is None or r.ordinary_readout is None):
        raise AuthorityUnavailable('D04 control read requires its actual bound consumer and current Owner')
    r.ordinary_readout.require_current_v3(r)
    control=_current_d04_role_control_v4(r)
    from ..domains.d01 import _activation_key
    return control,r.graph_stamp[1],r.snapshot.get(_activation_key(r.namespace))


def require_bound_d04_role_header_v4(role,key,revision):
    """Closed metadata header consumption; it grants no PersonaPlan Body."""
    r=_BOUND.get()
    if r is None:return False
    control,_,_=bound_active_role_control_state_v3(r,r.owner_guard)
    if role is not r.role or role!=control or GraphVersion(key,revision)not in control.read_versions:
        raise AuthorityUnavailable('D04 role header belongs to another actual selected readout/control')
    return True


def scene_binding_state_v3(reader,guard,prior=None):
    """The actual complete D03 census contract, after this consumer's role Source ALL."""
    from ..contracts import StaleRead
    r = require_installed_d04_source_reader_v3(reader)
    if guard != r.owner_guard or r.role is None or r.current is None:
        raise AuthorityUnavailable('D04 scene requires the same actual fresh-WRITE Owner and prepared role')
    r.ordinary_readout.require_current_v3(r)
    from ..domains.d03.context import RoleBinding
    bindings,versions = [],[]
    for atom in r.scene_binding_atoms:
        value = atom.value
        binding = RoleBinding(**{**value,'norm_refs':tuple(value['norm_refs']),
            'source_refs':tuple(value['source_refs'])})
        if (atom.key.name != binding.role_binding_id or atom.revision != binding.binding_version
                or binding.subject_persona_ref != 'persona:'+r.namespace.persona_id
                or atom.key.owner.kind == 'scene' and atom.key.owner.subject != binding.scene_ref):
            raise AuthorityUnavailable('D04 actual complete D03 scene binding identity differs')
        bindings.append(binding)
        versions.append(GraphVersion(atom.key,atom.revision))
    query = QueryEpoch(r.namespace,'d03.role_binding',r.graph_stamp[1].revision)
    if prior is not None and (prior.query_epoch != query or len(prior.read_versions) != len(versions)
            or set(prior.read_versions) != set(versions)):
        raise StaleRead('D04 actual D03 negative query versions or epoch changed')
    if prior is not None:
        return r.role,tuple(bindings),r.graph_stamp[1]
    return r.role,tuple(bindings),r.graph_stamp[1],tuple(versions)


def _bound_numeric_source_reader_v3(db,namespace):
    r=_BOUND.get()
    if r is None:return None
    require_installed_d04_source_reader_v3(r)
    normal=r.selector.stage=='numeric_prepare'and r.phase=='write'and r.write_scope is not None
    readonly=r.selector.stage=='series_freeze'and r.phase=='series_origin'and not r.read_finished and r.series_ready is not None
    if(r.db is not db or r.namespace!=namespace or not(normal or readonly)or not db.in_transaction):
        raise AuthorityUnavailable('numeric component requires its actual completed D04 Source W01')
    return r


def _require_d04_eof_head_v3(r,key,expected,meter):
    from ..runtime_storage_v3 import begin_runtime_cell_read_v3,read_runtime_cell_origin_v3
    actual=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
        'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,key.token))
    if expected is None:
        if actual is not None:raise AuthorityUnavailable('D04 complete negative census changed')
        return
    revision,valid,cell,header,digest=expected
    if actual!=(revision,int(valid),cell):
        raise AuthorityUnavailable('D04 full EOF current head changed')
    current=begin_runtime_cell_read_v3(r.db,cell,erasure_owner_ref=key.token)
    if tuple(current.header)!=header or header[5]!=digest:
        raise AuthorityUnavailable('D04 full EOF current header changed')
    read_runtime_cell_origin_v3(r.db,cell,header=header,meter=meter)


def _d04_source_atom_from_eof_v3(r,key,meter):
    if NamespaceId.from_key(key)!=r.namespace:
        raise AuthorityUnavailable('D04 numeric read crosses namespace')
    if r.numeric_job is not None and r.numeric_job[0].key==key:
        atom,expected=r.numeric_job
    else:
        expected=r.namespace_reader.canonical_eofs.get(key.token)
        atom=r.snapshot.get(key)
        if key.token in r.namespace_reader.heads and atom is None:
            raise AuthorityUnavailable('D04 numeric consumer requested an unqualified Body')
        if expected is None:
            if key.token in r.namespace_reader.heads:
                raise AuthorityUnavailable('D04 current head lacks its completed canonical EOF')
            atom=GraphAtom(key,0,{},False)
        elif(atom is None or(atom.revision,atom.valid)!=(expected[0],expected[1])
                or canonical_digest(atom.value)!=expected[4]):
            raise AuthorityUnavailable('D04 selected Body differs from its complete Source EOF')
    _require_d04_eof_head_v3(r,key,expected,meter)
    return atom


def read_bound_installed_d04_component_atom_v3(db,namespace,ref):
    r=_bound_numeric_source_reader_v3(db,namespace)
    if r is None:return False,None
    key=AtomKey.from_token(ref)
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        return True,_d04_source_atom_from_eof_v3(r,key,meter)


def read_bound_installed_d04_component_rows_v3(db,namespace,*,types,limit):
    r=_bound_numeric_source_reader_v3(db,namespace)
    if r is None:return False,None
    if not set(types)<=_NATIVE_NUMERIC_TYPES or type(limit)is not int or limit<1:
        raise AuthorityUnavailable('D04 component requires its exact complete numeric census')
    tokens=sorted(token for token in r.namespace_reader.heads if AtomKey.from_token(token).type_name in types)
    rows=[]
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        for token in tokens[:limit]:
            atom=_d04_source_atom_from_eof_v3(r,AtomKey.from_token(token),meter)
            rows.append((token,atom.revision,canonical_serialize(atom.value),int(atom.valid)))
    return True,rows


class _InstalledD04NumericRowsSealV3:
    def __init__(self,key,reader,rows,seals,stamp,prepared):
        if key is not _KEY:raise TypeError('D04 numeric rows have no public issuer')
        self.reader,self.rows,self.seals,self.stamp=reader,rows,seals,stamp
        self.prepared,self.prepared_digest=prepared,prepared.digest
        self.root_ref="d04-series-root:"+canonical_digest((reader.namespace,prepared.binding.operation_id))[:48]
        self.readonly=reader.selector.stage=="series_freeze"
        self.scope=reader.fence.scope if self.readonly else reader.write_scope
        self.guard,self.worker_fence=reader.owner_guard,reader.numeric_job_worker_fence
        self.closed=False
    def require_current_v3(self,graph,db,rows,*,prepared,root_ref):
        r=self.reader
        if(self.closed or _NUMERIC_ROWS_SEALS.get(self)!=(r,rows,self.seals,self.stamp)
                or graph is not r.graph or db is not r.db or rows is not self.rows
                or r.numeric_rows_seal is not self or r.operation.closed or not db.in_transaction
                or prepared is not self.prepared or prepared.digest!=self.prepared_digest or root_ref!=self.root_ref
                or (r.fence.scope if self.readonly else r.write_scope)is not self.scope or r.owner_guard!=self.guard
                or _SERIES_FREEZE_WRITE.get()is None or _SERIES_FREEZE_WRITE.get()[0]is not self):
            raise AuthorityUnavailable('series freeze requires its actual current D04 EOF capsule')
        require_installed_d04_source_reader_v3(r)
        with bind_runtime_storage_operation_v3(r.operation,db),runtime_storage_quantum_v3(db)as meter:
            r.require_current(meter=meter)
            from .jobs import get_job
            from datetime import datetime
            job=get_job(db,prepared.binding.job_id)
            if(job is None or canonical_serialize(asdict(job))!=prepared.job_payload_json
                    or job.phase!='running'or job.cancel_epoch!=0 or job.fence!=self.worker_fence
                    or datetime.fromisoformat(job.lease_expires_utc.replace('Z','+00:00')).timestamp()<=r.now_utc):
                raise AuthorityUnavailable('series freeze lost its original live numeric job/lease')
            from ..authority_service.v2_contract import to_wire
            saved=meter.read_fixed_row(db,'graph_d04_installed_stage_attempts_v3',
                ('stage','c02_operation_id','source_ref','request_digest','attempt_id','permit_json','receipt_json'),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,'d04-numeric-prepare:'+prepared.binding.operation_id))
            expected_receipt={'status':'numeric_prepared','operation_id':prepared.binding.operation_id,
                'prepared_digest':prepared.digest,'binding_digest':prepared.binding.digest,
                'job_id':prepared.binding.job_id,'worker_fence':self.worker_fence}
            if self.readonly:
                expected_origin=r.series_origin
                if saved!=expected_origin:
                    raise AuthorityUnavailable('series historical W01 metadata changed after actual finished-permit check')
            elif(saved is None or saved[:5]!=(r.selector.stage,r.selector.c02_operation_id,r.selector.source_ref,
                    r.selector.request_digest,self.scope.operation_id)
                    or saved[5]!=canonical_serialize(to_wire(self.scope.permit))):
                raise AuthorityUnavailable('series EOF capsule lost its actual same-operation W01 permit')
            if saved is None or __import__('json').loads(saved[6])!=expected_receipt:
                raise AuthorityUnavailable('series EOF capsule lost its actual same-operation W01 receipt')
            if graph._v2_graph_stamp(r.namespace)!=self.stamp:
                raise AuthorityUnavailable('series EOF capsule Graph stamp changed')
            for token,revision,valid,digest,expected in self.seals:
                _require_d04_eof_head_v3(r,AtomKey.from_token(token),expected,meter)
        return self


def issue_installed_d04_numeric_rows_seal_v3(graph,db,rows,*,prepared):
    r=_bound_numeric_source_reader_v3(db,graph._GraphCoordinator__d04_installed_joint_assembly.installation_policy.namespace)
    if r is None:raise AuthorityUnavailable('D04 numeric EOF capsule needs its actual independent Source Work')
    if r.numeric_rows_seal is not None:raise AuthorityUnavailable('D04 numeric EOF capsule already issued')
    seals=[]
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        for row in rows:
            key=AtomKey.from_token(row.ref)
            expected=(r.numeric_job[1]if r.numeric_job is not None and r.numeric_job[0].key==key
                else r.namespace_reader.canonical_eofs.get(key.token))
            claimed=canonical_digest(__import__('json').loads(row.value_json))
            if r.selector.stage=='series_freeze':
                if prepared is not r.series_ready.prepared or rows is not r.series_ready.evidence_inputs.read_rows:
                    raise AuthorityUnavailable('series readonly capsule requires its actual whole-EOF Prepared')
                if NamespaceId.from_key(key)!=r.namespace or (expected is None and(row.revision!=0 or row.valid or key.token in r.namespace_reader.heads)):
                    raise AuthorityUnavailable('series historical read row is outside current complete census')
                if expected is not None and(expected[:2]!=(row.revision,row.valid)or expected[4]!=claimed):
                    raise AuthorityUnavailable('series historical value differs from current complete canonical EOF')
                _require_d04_eof_head_v3(r,key,expected,meter)
                digest=claimed
            else:
                atom=_d04_source_atom_from_eof_v3(r,key,meter)
                if(atom.revision,atom.valid)!=(row.revision,row.valid)or canonical_digest(atom.value)!=claimed:
                    raise AuthorityUnavailable('D04 expected value differs from its actual Source EOF')
                digest=canonical_digest(atom.value)
            seals.append((row.ref,row.revision,row.valid,digest,expected))
    seen={item[0]for item in seals}
    support=(*r.source_versions,*r.current_control.read_versions,*(r.selected_readout.read_versions if r.selected_readout is not None else()))
    for version in support:
        if version.key.token in seen:continue
        expected=r.namespace_reader.canonical_eofs.get(version.key.token)
        if version.revision==0:
            if version.key.token in r.namespace_reader.heads:
                raise AuthorityUnavailable('D04 Source negative support differs from complete census')
            valid,digest=False,canonical_digest({})
        else:
            if expected is None or expected[0]!=version.revision or not expected[1]:
                raise AuthorityUnavailable('D04 Source support lacks its actual complete EOF')
            valid,digest=True,expected[4]
        seals.append((version.key.token,version.revision,valid,digest,expected));seen.add(version.key.token)
    r.operation.retain(len(seals)*1024+8192)
    stamp=graph._v2_graph_stamp(r.namespace)
    from .d04_numeric_cost_v3 import D04NumericPreparedV3
    from .d04_installed_numeric_v3 import numeric_ids_v3
    if(type(prepared)is not D04NumericPreparedV3 or prepared.binding.namespace!=r.namespace
            or prepared.binding.operation_id!=numeric_ids_v3(r.namespace,r.selector.c02_operation_id)["operation"]):
        raise AuthorityUnavailable("D04 EOF capsule changed its actual prepared numeric operation")
    proof=_InstalledD04NumericRowsSealV3(_KEY,r,rows,tuple(seals),stamp,prepared)
    _NUMERIC_ROWS_SEALS[proof]=(r,rows,proof.seals,stamp)
    _NUMERIC_PREPARED_ROWS_SEALS[id(prepared)]=(prepared,proof)
    r.numeric_rows_seal=proof
    return proof


def record_installed_d04_numeric_job_projection_v3(graph,db,job,*,stamp,header,cell):
    from .d11_types import job_graph_write
    write=job_graph_write(job)
    r=_bound_numeric_source_reader_v3(db,NamespaceId.from_key(write.key))
    if r is None:raise AuthorityUnavailable('numeric job delta needs actual D04 Source W01')
    if write.key.token in r.namespace_reader.heads or r.numeric_job is not None:
        raise AuthorityUnavailable('numeric job delta is not the sole new job')
    if header[5]!=canonical_digest(write.value) or graph._v2_graph_stamp(r.namespace)!=stamp:
        raise AuthorityUnavailable('numeric job delta lost its verified actual current header')
    r.numeric_job=(GraphAtom(write.key,1,write.value,True),(1,True,cell,tuple(header),header[5]))
    r.numeric_job_stamp=stamp
    r.numeric_job_worker_fence=job.fence



def require_installed_d04_series_rows_seal_v3(graph,db,ready,root_ref):
    from .d04_installed_numeric_v3 import D04PreparedExecutionV3
    if type(ready)is not D04PreparedExecutionV3:
        raise AuthorityUnavailable('series freeze requires its actual typed numeric ready result')
    issued=_NUMERIC_PREPARED_ROWS_SEALS.get(id(ready.prepared))
    if issued is None or issued[0]is not ready.prepared:
        raise AuthorityUnavailable('series freeze requires a fresh actual D04 Source EOF qualification')
    return issued[1].require_current_v3(graph,db,ready.evidence_inputs.read_rows,
        prepared=ready.prepared,root_ref=root_ref)


from ..authority_service.d04_numeric_owner_selectors_metadata_v4 import (
    _NumericInputControlsV4,_NumericPreparedControlsV4)


class _SeriesNumericInputLocatorV3(_NumericInputControlsV4):
    def _retains(self,path):
        if not path:return True
        if path[0]=='read_rows':
            return len(path)<=2 or len(path)==3 and path[2]in('ref','revision','valid')
        if path[0]=='numeric_request':
            return len(path)==1 or path[1]=='drives'and(len(path)<=3 or len(path)==4 and path[3]=='source_ref')
        return path==('schema',)


class _SeriesNumericPreparedLocatorV3(_NumericPreparedControlsV4):
    def __init__(self,reserve):
        super().__init__(reserve)
        self.inner=_SeriesNumericInputLocatorV3(reserve)


class _D04SeriesPreparedLocatorTaskV3:
    def __init__(self,reader):
        self.reader,self.parser,self.reserved=reader,None,0
        self.offset,self.total,self.complete=0,None,False
        self.binding=self.source_refs=None
        self.parser=_SeriesNumericPreparedLocatorV3(self._reserve)
        self.header=None
    def _reserve(self,extra=0):
        from .source_correction_read_v3 import _heap
        p=self.parser
        parts=None if p is None else(p.nodes,p.metadata,p.fields,p.scalar,p.active_hashes,p.commitments,p.inner_bytes,
            p.inner.nodes,p.inner.metadata,p.inner.fields,p.inner.scalar,p.inner.active_hashes,p.inner.commitments)
        size=_heap((parts,self.binding,self.source_refs))+extra+65536
        if size>self.reserved:self.reader.operation.retain(size-self.reserved);self.reserved=size
    def advance(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..authority_service.d04_numeric_contract_v3 import from_wire,D04NumericBindingV3
        r=self.reader
        if self.header is None:
            self.header=meter.read_fixed_row(r.db,'graph_d04_originals_v3',('payload_digest',),
                'bot=? AND persona=? AND kind=? AND original_ref=?',
                (*r.namespace.as_tuple,'numeric_prepared',_series_numeric_operation_v3(r)))
            if self.header is None:raise AuthorityUnavailable('series readonly requalification has no actual numeric Prepared')
        raw,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table='graph_d04_originals_v3',column='payload_json',
            where='bot=? AND persona=? AND kind=? AND original_ref=?',
            parameters=(*r.namespace.as_tuple,'numeric_prepared',_series_numeric_operation_v3(r)),
            start=self.offset,length=1024,meter=meter)
        if kind!='text'or self.total is not None and self.total!=total:
            raise AuthorityUnavailable('series prepared locator changed its actual canonical column')
        self.total=total
        if raw:self.parser.advance_fragment_v3(raw,meter);self.offset+=len(raw)
        if self.offset==self.total:
            self.parser.flush_inner_v4()
            metadata,_commits,_ranges,fields,parsed=self.parser.finish_metadata_v3()
            inner,_ic,_ir,_if,inner_parsed=self.parser.inner.finish_metadata_v3()
            if(parsed.byte_count!=self.total or parsed.sha256!=self.header[0]
                    or fields.get(())!=frozenset(('binding','input_payload_json','quote_payload_json',
                        'reserve_receipt_json','job_payload_json','original_ref','schema'))
                    or metadata.get('schema')!='d04.numeric_prepared_original.v3'
                    or inner.get('schema')!='d04.numeric-frozen-work-input.v3'):
                raise AuthorityUnavailable('series Prepared locator whole EOF/schema differs')
            self.binding=from_wire(dict(metadata['binding']),D04NumericBindingV3)
            if(self.binding.namespace!=r.namespace or self.binding.operation_id!=_series_numeric_operation_v3(r)
                    or inner_parsed.sha256!=self.binding.input_digest
                    or metadata.get('original_ref')!=self.binding.input_original_ref):
                raise AuthorityUnavailable('series Prepared locator has no exact namespace/operation/input EOF')
            roots=tuple(sorted({value['source_ref']for value in inner['numeric_request']['drives']}))
            from ..memory_types import source_key
            for ref in roots:
                key=AtomKey.from_token(ref)
                if key!=source_key(*r.namespace.as_tuple,key.owner.subject or ''):
                    raise AuthorityUnavailable('series input Source locator crosses namespace/type')
            self.source_refs=roots
            r.series_prepared_header=self.header
            self.complete=True


def _series_numeric_operation_v3(reader):
    from .d04_installed_numeric_v3 import numeric_ids_v3
    return numeric_ids_v3(reader.namespace,reader.selector.c02_operation_id)['operation']


def _series_root_ref_v3(reader):
    return 'd04-series-root:'+canonical_digest((reader.namespace,_series_numeric_operation_v3(reader)))[:48]


def prepare_current_d04_series_freeze_source_v3(graph,bootstrap,bundle,*,c02_operation_id,source_ref):
    from ..graph_coordinator import _V2ReadFenceStateV3
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable('series readonly qualification needs its actual installed assembly')
    ns=bundle.installation_policy.namespace;store=graph._GraphCoordinator__store
    operation_id='d04-series-source-read:'+uuid4().hex
    selector=InstalledD04SourceSelectorV3(ns,c02_operation_id,source_ref,operation_id,'series_freeze',
        canonical_digest(('d04.series-readonly-source.v3',ns,c02_operation_id,source_ref)))
    with store._lock:metadata,epoch=graph._v2_graph_stamp(ns)
    port=graph._GraphCoordinator__content_fence_v2;policy=bundle.installation_policy;target=metadata.requirements
    anchor=port.current_anchor(namespace=ns,authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target,anchor):raise AuthorityUnavailable('series readonly Root anchor changed')
    reading=port.read_ingress_clock(bundle.ingress_clock);now=trusted_upper(reading)
    deadline=policy.root_grant.valid_until_utc
    if now>=deadline:raise AuthorityUnavailable('series actual read Root grant expired')
    read_id='d04-series-source-fence:'+uuid4().hex
    permit=port.begin_fence(namespace=ns,authority_namespace=target.authority_namespace,holder=policy.administrator_holder,
        generation=target.activation_generation,operation='read',operation_id=read_id,expected_anchor=anchor)
    scope=FenceScope(ns,target.authority_namespace,target.activation_generation,'read',read_id,permit,anchor,epoch,metadata.graph_revision)
    operation=lease=None
    try:
        operation=begin_runtime_storage_operation_v3(store._db,operation_id,deadline)
        lease,capability=graph.grant(bootstrap,actor=policy.administrator_holder,issuer_domain='d04',namespace=ns,
            domains=('d01','d02','d03','d04','d05','d06','d07','d11','d12'),activation_generation=target.activation_generation,operation_id=operation_id)
        authority=AuthorityContext(policy.administrator_holder,'d04',capability,ns,
            tuple(sorted(graph._GraphCoordinator__leases[lease][5])),'expression',(),policy.root_grant.policy_ref,target.activation_generation)
        fence=_V2ReadFenceStateV3(authority,scope,metadata,epoch,None,None,None,None,None)
        r=_InstalledD04SourceReadV3(_KEY,graph,bootstrap,bundle,selector,None,False,None,operation,fence,authority,lease,reading,now)
        work=create_graph_storage_work_v3(graph,kind='d04_source_read_v3',operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=r,operation=operation)
        r.work=work;_READERS[r]=(graph,selector,operation,fence,authority,lease,r.graph_stamp,work,None)
        def completed(value):
            from .d04_installed_numeric_v3 import D04PreparedExecutionV3
            from .d04_series_store_v1 import D04SeriesRootV1
            if value is not r.result or type(value)not in(D04PreparedExecutionV3,D04SeriesRootV1):
                raise AuthorityUnavailable('series readonly result left its actual typed Source producer')
            graph._validate_read_fence_v3(r.fence)
            graph._finish_read_fence_v3(r.fence)
            r.read_finished=True
            return value
        def failed(error):raise error
        return work.map_terminal_v3('issuer',completed,failed)
    except BaseException:
        graph._finish_read_fence_v3(_V2ReadFenceStateV3(None,scope,metadata,epoch,None,None,None,None,None))
        if lease is not None:graph.release_authority_lease(bootstrap,lease)
        if operation is not None:finish_runtime_storage_operation_v3(operation)
        raise


def _require_series_prepared_origin_v3(r):
    from ..authority_service.v2_contract import to_wire
    numeric=_series_numeric_operation_v3(r)
    with r.quantum_v3()as meter:
        saved=meter.read_fixed_row(r.db,'graph_d04_installed_stage_attempts_v3',
            ('stage','c02_operation_id','source_ref','request_digest','attempt_id','permit_json','receipt_json'),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,'d04-numeric-prepare:'+numeric))
    if saved is None or saved[:3]!=('numeric_prepare',r.selector.c02_operation_id,r.selector.source_ref)or saved[5]is None or saved[6]is None:
        raise AuthorityUnavailable('series readonly source has no actual completed numeric W01')
    import json
    receipt=json.loads(saved[6]);binding=r.series_locator.binding
    if(receipt.get('status')!='numeric_prepared'or receipt.get('operation_id')!=numeric
            or receipt.get('prepared_digest')!=r.series_prepared_header[0]
            or receipt.get('binding_digest')!=binding.digest or receipt.get('job_id')!=binding.job_id
            or type(receipt.get('worker_fence'))is not int or receipt['worker_fence']<1):
        raise AuthorityUnavailable('series numeric W01 receipt differs from actual Prepared EOF')
    permit,state=r.graph._GraphCoordinator__content_fence_v2.get_fence_operation(namespace=r.namespace,
        authority_namespace=r.fence.scope.authority_namespace,operation_id=saved[4])
    if state!='finished'or permit is None or canonical_serialize(to_wire(permit))!=saved[5]:
        raise AuthorityUnavailable('series numeric W01 actual original permit is not finished')
    r.series_origin=saved
    r.numeric_job_worker_fence=receipt['worker_fence']


def _finish_series_prepared_read_v3(r):
    from ..authority_service.d04_numeric_contract_v3 import from_wire,D04NumericBindingV3
    from .d04_numeric_cost_v3 import D04NumericPreparedV3
    from .d04_installed_numeric_v3 import _ready_from_original_v3
    import json
    raw=r.series_column.require_v3(r)
    value=D04NumericPreparedV3(**{**raw,'binding':from_wire(dict(raw['binding']),D04NumericBindingV3)})
    if(value.digest!=r.series_prepared_header[0]or value.binding!=r.series_locator.binding
            or canonical_digest(json.loads(value.input_payload_json))!=value.binding.input_digest):
        raise AuthorityUnavailable('series actual numeric Prepared changed after its metadata EOF')
    r.series_ready=_ready_from_original_v3(value)
    if r.series_ready.worker_fence!=r.numeric_job_worker_fence:
        raise AuthorityUnavailable('series actual original worker fence differs')


def _finish_series_existing_read_v3(r):
    from .d04_series_store_v1 import _series_root_from_original_v1
    payload=r.series_column.require_v3(r)
    if(canonical_digest(payload)!=r.series_root_header[0]
            or payload.get('c02_operation_id')!=r.selector.c02_operation_id
            or payload.get('source_ref')!=r.selector.source_ref):
        raise AuthorityUnavailable('existing series root lost its actual whole EOF')
    return _series_root_from_original_v1(payload,r.series_root_header[0],r.series_ready.prepared)


def finish_installed_d04_series_freeze_v3(graph,ready):
    issued=_NUMERIC_PREPARED_ROWS_SEALS.get(id(ready.prepared))
    if issued is None or issued[0]is not ready.prepared:
        raise AuthorityUnavailable('series service lost its actual EOF capsule')
    proof=issued[1];r=proof.reader
    if proof.closed or graph is not r.graph:raise AuthorityUnavailable('series EOF qualification already consumed')
    if not r.read_finished:
        graph._finish_read_fence_v3(r.fence)
        r.read_finished=True
    proof.closed=True
    _NUMERIC_ROWS_SEALS.pop(proof,None)
    _NUMERIC_PREPARED_ROWS_SEALS.pop(id(proof.prepared),None)


def _series_freeze_invocation_v3(graph,db,namespace,*,c02_operation_id,source_ref,operation_id,request_digest,commit):
    actual=_SERIES_FREEZE.get()
    if actual is None:raise AuthorityUnavailable('series append needs its actual private EOF service invocation')
    proof,ready,root_ref,expected_op,expected_digest,expected_commit=actual
    r=require_installed_d04_source_reader_v3(proof.reader)
    if(proof.closed or _NUMERIC_ROWS_SEALS.get(proof)!=(r,proof.rows,proof.seals,proof.stamp)
            or r.graph is not graph or r.db is not db or r.namespace!=namespace or r.numeric_rows_seal is not proof
            or ready.prepared is not proof.prepared or root_ref!=proof.root_ref
            or(c02_operation_id,source_ref,operation_id,request_digest)!=(r.selector.c02_operation_id,
                r.selector.source_ref,expected_op,expected_digest)or commit is not expected_commit
            or not r.read_finished):
        raise AuthorityUnavailable('series append changed its exact actual Source/Prepared/root/command')
    r.now_utc
    return proof


def require_bound_installed_d04_series_freeze_v3(graph,db,namespace,**request):
    return _series_freeze_invocation_v3(graph,db,namespace,**request).reader


@contextmanager
def bind_installed_d04_series_freeze_write_v3(graph,db,*,issuer,scope,guard,current_owner):
    from .d04_installed_stage_fence_v3 import _SERIES_FREEZE_WRITE_ISSUER
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    actual=_SERIES_FREEZE.get()
    if actual is None:raise AuthorityUnavailable('series WRITE has no actual issued EOF service invocation')
    proof,ready,root_ref,operation_id,request_digest,commit=actual
    r=proof.reader
    _series_freeze_invocation_v3(graph,db,r.namespace,c02_operation_id=r.selector.c02_operation_id,
        source_ref=r.selector.source_ref,operation_id=operation_id,request_digest=request_digest,commit=commit)
    if(issuer is not _SERIES_FREEZE_WRITE_ISSUER or _SERIES_FREEZE_WRITE.get()is not None
            or type(scope)is not FenceScope or scope.operation!='write'or scope.namespace!=r.namespace
            or scope.graph_revision!=proof.stamp[0].graph_revision or scope.graph_epoch!=proof.stamp[1]
            or type(current_owner)is not D12CurrentOwnerAuthorityV1 or current_owner.guard!=guard
            or guard!=proof.guard or current_owner.guard.namespace!=r.namespace
            or not db.in_transaction or not r.store._lock._is_owned()):
        raise AuthorityUnavailable('series append requires its actual fresh Root/Owner-qualified WRITE transaction')
    token=_SERIES_FREEZE_WRITE.set((proof,scope,guard,current_owner))
    try:
        proof.require_current_v3(graph,db,ready.evidence_inputs.read_rows,prepared=ready.prepared,root_ref=root_ref)
        yield
        proof.require_current_v3(graph,db,ready.evidence_inputs.read_rows,prepared=ready.prepared,root_ref=root_ref)
    finally:_SERIES_FREEZE_WRITE.reset(token)


def run_installed_d04_series_freeze_v3(graph,ready,root_ref,*,commit):
    issued=_NUMERIC_PREPARED_ROWS_SEALS.get(id(ready.prepared))
    if(issued is None or issued[0]is not ready.prepared
            or commit.__module__!=__package__+'.d04_series_store_v1'
            or commit.__qualname__!='freeze_post_c02_d04_series_v1.<locals>.freeze_current.<locals>.append'):
        raise AuthorityUnavailable('series metadata WRITE has only its fixed actual root-append implementation')
    proof=issued[1];r=proof.reader
    operation_id='d04-series-freeze:'+root_ref
    digest=canonical_digest(('d04.series-freeze.v3',r.namespace,root_ref,ready.prepared.digest))
    token=_SERIES_FREEZE.set((proof,ready,root_ref,operation_id,digest,commit))
    try:
        from .d04_installed_stage_fence_v3 import _run_installed_d04_stage_v3,_D04PhaseTimingsV1
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            return _run_installed_d04_stage_v3(graph,r.bootstrap,r.bundle,c02_operation_id=r.selector.c02_operation_id,
                source_ref=r.selector.source_ref,operation_id=operation_id,stage='series_freeze',request_digest=digest,
                commit=commit,semantic=False,fence_observer=None,
                timings=_D04PhaseTimingsV1(operation_id,deadline_utc=r.operation.deadline_utc))
    finally:_SERIES_FREEZE.reset(token)
