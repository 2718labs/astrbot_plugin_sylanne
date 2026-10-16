"""Private named Joint Host READ and fresh-WRITE on existing World storage Work.

Only this factory issues its metadata/Owner/Source profile. The namespace and
Source parsers are shared mechanics. No Method/Habit/Foreground permission is
borrowed and the registration produces no job, reserve, settlement or provider.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from uuid import uuid4
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,FenceScope,AuthorityContext,canonical_digest
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3)
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3,_SOURCE_ISSUED
from ..authority_service.named_joint_binding_source_read_v3 import (_METADATA_FIELDS,_MetadataStreamV3,
    _metadata_groups,_run,_fixed)
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_KEY=object()
_READERS=WeakKeyDictionary()
_BRIDGES=WeakKeyDictionary()
_RESULTS=WeakKeyDictionary()


class _SourceStream(_MetadataStreamV3):
    def __getattr__(self,name):return getattr(self.parser,name)


class _MetadataColumn(DispatchOriginalJSONReadV3):
    def __init__(self,state,key):
        self.state=state
        head=state.work.heads.get(key.token)
        if head is None or not head[1]:raise AuthorityUnavailable('Named Joint actual required metadata Head is absent')
        self.key,self.head=key,head
        super().__init__(state.work,table='graph_atoms',column='value',key_columns=('token',),key=(key.token,),cell_id=head[2])
        self.stream=_MetadataStreamV3(self,self.cell.header[0]=='canonical-json.ascii.v1');self.parser=self.stream
    def _emit(self,event):
        if not event.path or event.path[0]in _METADATA_FIELDS:super()._emit(event)


class _HostSourceWitness:
    def __init__(self,reader,original,semantic):
        self.reader,self.original,self.canonical_semantic_digest=reader,original,semantic
        self.metadata,self.revision,self.valid=original.metadata,original.revision,original.valid
        self.cell_id,self.header,self.payload_sha256=original.cell_id,original.header,original.payload_sha256
    def require_current_v3(self):
        r=require_named_joint_host_reader_v3(self.reader)
        original=self.original
        if _SOURCE_ISSUED.get(original)!=(r.db,original.source_key,original.revision,original.valid,original.cell_id,
                original.header,original.payload_sha256,original.metadata,original.scope,original.graph_stamp,original.query,
                original.operation_id,original.selection_digest):
            raise AuthorityUnavailable('Named Joint actual Source metadata original lost its canonical complete EOF')
        with runtime_storage_quantum_v3(r.db)as meter:
            r.require_current(meter=meter)
            current=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(original.source_key.token,*r.namespace.as_tuple))
        if current!=(original.revision,int(original.valid),original.cell_id):
            raise AuthorityUnavailable('Named Joint actual qualified Source Head changed')
        return self


class _Namespace(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,reader):
        self.reader=reader;self.source_semantics={}
        super().__init__(reader.graph,reader.operation,reader.fence,
            projection_types=frozenset({'memory.access','d06.source_correction_head.v1'}),selected_tokens=frozenset(),
            census_schema='d10.named-joint-header-census.v1',leaf_schema='d10.named-joint-header-leaf.v1')
    def _next(self,meter):
        super()._next(meter)
        if self.pending is not None:
            key,revision,valid,kind,cell=self.pending
            self.heads[key.token]=(revision,valid,cell)
            if kind=='memory.source':
                stream=_SourceStream(self,self.cell.header[0]=='canonical-json.ascii.v1')
                stream.parser=self.parser;self.parser=stream
    def _cell(self,meter):
        selected=self.pending;stream=self.parser
        super()._cell(meter)
        if self.pending is None and selected[3]=='memory.source'and selected[0].token in self.sources:
            self.source_semantics[selected[0].token]=stream.semantic.hexdigest()
    def _reserve(self,extra=0):
        stream=self.parser
        parser=stream.parser if type(stream)is _SourceStream else stream
        if type(stream)is _SourceStream:self.parser=parser
        try:super()._reserve(extra)
        finally:self.parser=stream
    def _graph_eof_v3(self):self.reader.header_eof_digest=self.root


class _Bridge:
    def __init__(self,key,reader):
        if key is not _KEY:raise TypeError('Named Joint Host bridge requires its private Source factory')
        self.reader=reader;self.db=reader.db;self.operation=reader.operation
        self.namespace=reader.namespace;self.request=reader.selector
        self.scope=reader.fence.scope;self.permit=self.scope.permit;self.now_utc=reader.initial_now_utc
        self.deadline_utc=reader.operation.deadline_utc;self.selection_digest=reader.selection_digest
        self.graph_stamp=(reader.graph_stamp[1].revision,*reader.authority_epochs)
        self.heads=reader.namespace_reader.heads;self.sources={};self.attachments={}
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        runtime=reader.graph._GraphCoordinator__artifact_draft_model_runtime_v1
        if type(runtime)is not InstalledArtifactDraftModelRuntimeV1 or runtime.bundle!=reader.bundle:
            raise AuthorityUnavailable('Named Joint Host lacks its actual same-installation Artifact runtime')
        build=read_installed_d11_life_build_v1(runtime.authority_client._package_root,reader.bundle.installation_policy.manifest_digest,recipe_id='artifact_draft_v1')
        self.service=SimpleNamespace(issuer=reader.graph._GraphCoordinator__d11_issuer,installed_bundle=reader.bundle,artifact_build=build)
        _BRIDGES[self]=reader
    def _actual(self):
        require_named_joint_host_bridge_v3(self)
        return self
    @contextmanager
    def quantum_v3(self):
        r=require_named_joint_host_reader_v3(self.reader)
        entry=r.write_owner_entry if r.write_scope is not None else r.general_owner_entry
        entry.require_permission_v3(r)
        with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
            if r.db.in_transaction:raise AuthorityUnavailable('Named Joint Host quantum cannot inherit Graph SQL')
            r.db.execute('BEGIN')
            try:r.require_current(meter=meter);yield meter;r.require_current(meter=meter)
            finally:r.db.rollback()
        entry.require_permission_v3(r)
    def require_current(self,*,meter):return self.reader.require_current(meter=meter)


class _HostInputs:
    def __init__(self,key,reader,bridge):
        if key is not _KEY:raise TypeError('Named Joint inputs require actual private Host factory')
        self.work,self.reader,self.service=bridge,reader,bridge.service
        self.request=reader.selector;self.current_self=reader.read_evidence.current_self
        self.initial_monotonic_deadline=reader.initial_monotonic_deadline
        guard=reader.owner_guard
        self.owner_entry=SimpleNamespace(grant=reader.owner_grant,head=SimpleNamespace(guard=guard))
        self.metadata_only=True;self.metadata={};self.bodies={};self.originals={}
        self.groups=();self.materials=[];self.roots=();self.guard_inventory=None
        self.complete=False;self.observed=None


def require_named_joint_host_bridge_v3(bridge):
    if type(bridge)is not _Bridge or _BRIDGES.get(bridge)is not bridge.reader:
        raise AuthorityUnavailable('Named Joint Host cannot borrow another private Source bridge')
    r=require_named_joint_host_reader_v3(bridge.reader)
    if r.inputs is None or r.inputs.work is not bridge or r.phase not in {'metadata','source','body','write','committed'}:
        raise AuthorityUnavailable('Named Joint Host bridge left its actual metadata/Source/body lifetime')
    return r.inputs


def require_named_joint_host_reader_v3(reader):
    expected=_READERS.get(reader)
    if type(reader)is not _NamedJointHostReadV3 or expected is None or expected!=(reader.graph,reader.context,reader.selector,
            reader.operation,reader.fence,reader.authority,reader.lease,reader.graph_stamp,reader.work):
        raise AuthorityUnavailable('Named Joint Host requires its exact installed originating Work/command')
    if reader.operation.closed or reader.work.state is not reader or reader.work.operation is not reader.operation:
        raise AuthorityUnavailable('Named Joint Host retained Source Work is no longer current')
    reader.work._require_invocation(reader.graph)
    return reader


def named_joint_host_reader_v3(value):
    return type(value)is _NamedJointHostReadV3 and value in _READERS


class _NamedJointHostReadV3:
    def __init__(self,key,graph,context,selector,operation,fence,authority,lease,evidence,initial_now_utc):
        if key is not _KEY:raise TypeError('Named Joint Host Work has no public issuer')
        self.graph,self.context,self.selector,self.operation,self.fence=graph,context,selector,operation,fence
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.runtime=graph._GraphCoordinator__domain_production_runtime_v1
        self.bundle=context._v2_model_bundle;self.namespace=selector.namespace
        self.authority,self.lease,self.read_evidence=authority,lease,evidence
        self.operation_kind,self.request=selector.operation_kind,selector.command
        self.operation_id,self.activity_id=selector.operation_id,selector.operation_id
        self.parent_budget_lease_ref=evidence.parent_grant.lease_id
        self.graph_stamp=(fence.metadata,fence.epoch);self.selection_digest=operation.selection_digest
        self.initial_now_utc=initial_now_utc
        self.initial_monotonic_deadline=time.monotonic()+operation.deadline_utc-self.initial_now_utc
        self.owner_binding=self.owner_guard=self.owner_grant=None
        self.owner_acl_authority=self.owner_principal=None
        self.material_owner_guard=None;self.session_proof=None
        self.general_owner_entry=self.write_owner_entry=None
        self.write_scope=self.issued=None;self.read_finished=False
        self.work=None;self.inputs=None;self.namespace_reader=None
        self.authority_epochs=None;self.phase='owner';self.complete=False;self.result=None
    def require_current(self,*,meter):
        require_named_joint_host_reader_v3(self)
        self.operation.handle.require_current(meter)
        if time.monotonic()>=self.initial_monotonic_deadline:
            raise AuthorityUnavailable('Named Joint Host exceeded its original READ/Root deadline')
        if self.phase!='committed'and self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise AuthorityUnavailable('Named Joint Host actual Graph revision/epoch changed')
        rights=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',self.namespace.as_tuple)
        if self.authority_epochs is None:self.authority_epochs=rights
        elif rights!=self.authority_epochs:raise AuthorityUnavailable('Named Joint Source access/deletion epochs changed')
        return self


def named_joint_background_owner_identity_v3(reader):
    r=require_named_joint_host_reader_v3(reader)
    if r.read_finished or r.fence.scope.operation!='read' or r.write_scope is not None:
        raise AuthorityUnavailable('Named Joint Owner READ left its actual fixed phase')
    return r,canonical_digest(r.selector)


def _owner(reader):
    from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
    entry=prepare_current_host_semantic_background_owner_read_entry_v3(reader)
    owner=entry.require_permission_v3(reader)
    guard=entry.current_owner_guard
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    reader.owner_binding,reader.owner_guard=owner,guard
    reader.general_owner_entry=entry;reader.owner_acl_authority=entry.owner_acl_authority;reader.owner_principal=entry.owner_principal
    reader.material_owner_guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,
        owner.grant_revision,owner.grant_digest.removeprefix('sha256:'),owner.authorization_head.removeprefix('sha256:'))
    reader.owner_grant=entry.grant_value_v3(reader)
    if 'workbench.create'not in owner.capabilities:raise AuthorityUnavailable('Named Joint current Owner lacks actual create capability')
    return entry


def _metadata(state,ref):
    key=AtomKey.from_token(ref);column=_MetadataColumn(state,key);raw=_run(state.work,column)
    state.metadata[ref]=(column.head[0],column.head[1],column.stream.semantic.hexdigest(),raw)
    return raw


def _prepare_materials(state):
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    from ..memory_types import source_key,access_key
    from ..domains.d06 import source_correction_head_key
    r=state.reader;kernel=r.namespace_reader
    atoms={atom.key:atom for atom in kernel.atoms}
    for purpose,audience,roots in state.groups:
        if purpose not in r.owner_binding.purposes or audience not in r.owner_binding.audiences:
            raise AuthorityUnavailable('Named Joint Host Source group exceeds actual completed Owner EOF')
        material=SimpleNamespace(selection=SimpleNamespace(purpose=purpose,audience=audience,roots=roots),
            witnesses={},versions=[],phase='rights',pending=list(roots))
        active=set();done=set()
        def visit(ref):
            if ref in active:raise AuthorityUnavailable('Named Joint Host Source ancestry contains a cycle')
            if ref in done:return
            if len(active)+len(done)>=256:raise AuthorityUnavailable('Named Joint Host original Source ancestry exceeds its bound')
            original=kernel.sources.get(ref)
            if original is None:raise AuthorityUnavailable('Named Joint Host Source has no actual full metadata EOF')
            witness=_HostSourceWitness(r,original,kernel.source_semantics[ref])
            key=AtomKey.from_token(ref);acl=access_key(*r.namespace.as_tuple,key.owner.subject)
            correction=source_correction_head_key(r.namespace,key.owner.subject)
            access=atoms.get(acl)
            current=atoms.get(correction,GraphAtom(correction,0,{},False))
            if access is None or _qualify_source_rights_values_v3(r.namespace,ref,witness,access,current,
                    purpose=purpose,audience=audience,metadata_only=True)is None:
                raise AuthorityUnavailable('Named Joint Host actual Source/Access/Correction purpose/audience denied')
            active.add(ref)
            for parent in witness.metadata['parent_source_ids']:visit(source_key(*r.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref);material.witnesses[ref]=witness
            material.versions.extend((GraphVersion(key,witness.revision),GraphVersion(acl,access.revision),GraphVersion(correction,current.revision)))
            state.work.sources[ref]=witness
        for ref in roots:visit(ref)
        material.pending=[];material.phase='cell';state.materials.append(material)
    state.roots=tuple(sorted({ref for _,_,roots in state.groups for ref in roots}))
    state.closure_refs=tuple(sorted({ref for material in state.materials for ref in material.witnesses}))
    state.metadata_only=False


def advance_named_joint_host_work_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from ..authority_service.named_joint_binding_body_v1 import qualify_current_named_joint_body_v1
    r=require_named_joint_host_reader_v3(work.state)
    if graph is not r.graph:raise AuthorityUnavailable('Named Joint Work crossed its actual installed coordinator')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        if r.phase=='owner':
            _owner(r)
            r.namespace_reader=_Namespace(r)
            r.phase='census';return GraphStorageStepV3('progress')
        if r.phase=='census':
            r.general_owner_entry.require_permission_v3(r)
            with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
                r.db.execute('BEGIN')
                try:
                    r.require_current(meter=meter)
                    kernel=r.namespace_reader
                    if kernel.authority_epochs is None:kernel.authority_epochs=kernel._epochs(meter)
                    if kernel.cell is None:kernel._next(meter)
                    else:kernel._cell(meter)
                finally:r.db.rollback()
            if r.namespace_reader.graph_eof:
                r.phase='metadata';bridge=_Bridge(_KEY,r);r.inputs=_HostInputs(_KEY,r,bridge)
            return GraphStorageStepV3('progress')
        if r.phase=='metadata':
            state=r.inputs;bridge=state.work
            window=_metadata(state,r.selector.argument.window_ref)
            _metadata(state,window['long_term_plan_ref'])
            if window['prior_window_ref']is not None:_metadata(state,window['prior_window_ref'])
            from .current_joint_window_source_read_v3 import create_joint_guard_inventory_for_work_v3
            state.guard_inventory=create_joint_guard_inventory_for_work_v3(bridge,bridge.service.issuer)
            while not state.guard_inventory.complete:
                with bridge.quantum_v3()as meter:state.guard_inventory.advance(meter)
            state.groups=_metadata_groups(state);r.phase='source'
            return GraphStorageStepV3('progress')
        if r.phase=='source':
            _prepare_materials(r.inputs);r.phase='body'
            return GraphStorageStepV3('progress')
        if r.phase=='body':
            state=r.inputs
            from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,qualify_named_source_note_body_v1
            state.observed=(qualify_named_source_note_body_v1(state,None)if type(r.selector)is NamedJointSourceNoteSelectorV1 else qualify_current_named_joint_body_v1(state))
            state.complete=True
            from .named_joint_binding_issuance_v1 import require_named_joint_same_facts_v1
            require_named_joint_same_facts_v1(r.read_evidence,state.observed)
            r.attempt_snapshot=_read_named_attempt_v3(r)
            graph._validate_read_fence_v3(r.fence);graph._finish_read_fence_v3(r.fence);r.read_finished=True
            r.phase='write';return GraphStorageStepV3('progress')
        if r.phase=='write':
            from .named_joint_binding_write_v1 import run_named_joint_binding_write_v1
            result=run_named_joint_binding_write_v1(r)
            r.phase='committed';r.complete=True;r.result=_NamedResult(_KEY,r,result)
            return GraphStorageStepV3('complete',r.result)
        raise AuthorityUnavailable('Named Joint Host Work has already reached its terminal')


class _NamedResult:
    def __init__(self,key,reader,value):
        if key is not _KEY or reader.phase!='committed':raise AuthorityUnavailable('Named Joint result needs actual same-CAS registration')
        self.reader,self.value=reader,value
        _RESULTS[self]=(reader,reader.work,reader.operation,canonical_digest(value))
    def require_result_v3(self,work):
        if _RESULTS.get(self)!=(self.reader,work,self.reader.operation,canonical_digest(self.value))or work.state is not self.reader:
            raise AuthorityUnavailable('Named Joint terminal lost its actual retained registration Work')
        return self.value
    def release_payload_v3(self):
        _RESULTS.pop(self,None)
        r=self.reader
        if r.inputs is not None:
            r.inputs.metadata.clear();r.inputs.bodies.clear();r.inputs.originals.clear();r.inputs.materials.clear()
            r.inputs.point_rows.clear();r.inputs.original_refs.clear()
        if r.namespace_reader is not None:
            r.namespace_reader.heads.clear();r.namespace_reader.sources.clear();r.namespace_reader.atoms.clear()
        self.value=None


def require_named_joint_terminal_v3(value,work):
    if type(value)is not _NamedResult:raise AuthorityUnavailable('Named Joint returned no actual registration result')
    return value.require_result_v3(work)


def finish_named_joint_host_work_v3(graph,work,error):
    r=work.state
    if r not in _READERS:return
    try:
        if not r.read_finished:graph._finish_read_fence_v3(r.fence)
    finally:
        try:
            if r.write_owner_entry is not None:r.write_owner_entry.release_v3()
            if r.general_owner_entry is not None:r.general_owner_entry.release_v3()
            if r.inputs is not None:_BRIDGES.pop(r.inputs.work,None)
            graph.release_authority_lease(r.runtime._bootstrap,r.lease)
        finally:
            _READERS.pop(r,None)
            if not r.operation.closed:finish_runtime_storage_operation_v3(r.operation)


def prepare_named_joint_host_work_v3(graph,context,argument,request,*,original_selector=None):
    from ..graph_coordinator import GraphCoordinator,_V2ReadFenceStateV3
    from ..runtime_context import RuntimeContext
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..authority_service.current_named_joint_binding_v1 import (NamedJointBindingSelectorV1,OPERATION,
        named_joint_command_digest_v1,named_joint_binding_operation_id_v1)
    from ..host.current_named_joint_binding_port_v1 import installed_named_joint_binding_port_v1
    from .first_ingress_v2 import trusted_upper
    if type(graph)is not GraphCoordinator or type(context)is not RuntimeContext or context._v2_coordinator is not graph:
        raise TypeError('Named Joint requires actual installed RuntimeContext/Graph')
    require_graph_storage_work_admission_v3(graph)
    runtime=graph._GraphCoordinator__domain_production_runtime_v1;runtime._current()
    bundle=context._v2_model_bundle;ns=bundle.installation_policy.namespace
    if original_selector is None:
        selector=NamedJointBindingSelectorV1(ns,bundle.installation_policy.installation_id,
            named_joint_binding_operation_id_v1(ns,argument,request),OPERATION,argument,request,
            named_joint_command_digest_v1(ns,argument,request))
    else:
        from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,named_joint_source_note_digest_v1
        selector=NamedJointSourceNoteSelectorV1(ns,bundle.installation_policy.installation_id,original_selector,
            argument,request,named_joint_source_note_digest_v1(ns,original_selector,argument,request))
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    with store._lock:metadata,epoch=graph._v2_graph_stamp(ns)
    target=metadata.requirements;anchor=port.current_anchor(namespace=ns,authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target,anchor):raise AuthorityUnavailable('Named Joint current recovery anchor differs')
    read_id='named-joint-read:'+uuid4().hex
    permit=port.begin_fence(namespace=ns,authority_namespace=target.authority_namespace,
        holder=graph._GraphCoordinator__holder,generation=target.activation_generation,
        operation='read',operation_id=read_id,expected_anchor=anchor)
    scope=FenceScope(ns,target.authority_namespace,target.activation_generation,'read',read_id,permit,anchor,epoch,metadata.graph_revision)
    operation=reader=None;lease=None
    try:
        evidence,_=installed_named_joint_binding_port_v1(context).current_for_fence_v1(scope=scope,request=selector)
        current=evidence.current_self
        if(current.graph_revision,current.graph_epoch,current.activation_generation)!=(metadata.graph_revision,epoch.revision,target.activation_generation):
            raise AuthorityUnavailable('Named Joint actual paired Self differs from original Host recovery stamp')
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        deadline=min(now+60.0,evidence.valid_until_utc)
        operation=begin_runtime_storage_operation_v3(store._db,selector.operation_id,deadline)
        lease,capability=graph.grant(runtime._bootstrap,actor=current.self_entity_ref,issuer_domain='d10'if original_selector is None else 'd08',namespace=ns,
            domains=(('d01','d02','d03','d05','d06','d07','d08','d10','d11','d12')if original_selector is not None else ('d03','d05','d06','d07','d08','d10','d11','d12')),activation_generation=current.activation_generation,
            operation_id=selector.operation_id)
        audience=request.binding.audience if original_selector is None else evidence.audience
        authority=AuthorityContext(current.self_entity_ref,'d10'if original_selector is None else 'd08',capability,ns,tuple(sorted(graph._GraphCoordinator__leases[lease][5])),
            'context'if original_selector is None else 'consolidation',tuple(sorted(set(audience))),evidence.parent_grant.policy_ref,current.activation_generation)
        fence=_V2ReadFenceStateV3(authority,scope,metadata,epoch,None,None,None,None,None)
        reader=_NamedJointHostReadV3(_KEY,graph,context,selector,operation,fence,authority,lease,evidence,now)
        work=create_graph_storage_work_v3(graph,kind='current_world_source_read_v3',operation_id=selector.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        reader.work=work
        _READERS[reader]=(graph,context,selector,operation,fence,authority,lease,reader.graph_stamp,work)
        work.phase='named_joint_owner_eof'
        return work
    except BaseException:
        port.finish_fence(scope,request_id='finish:'+read_id,request_digest='sha256:'+canonical_digest(('named-joint-read-failed.v1',read_id,permit.token)))
        if lease is not None:graph.release_authority_lease(runtime._bootstrap,lease)
        if operation is not None:finish_runtime_storage_operation_v3(operation)
        raise


def _read_named_attempt_v3(reader):
    from ..authority_service.named_joint_binding_source_read_v3 import _column,_positive
    from ..runtime_contracts import canonical_serialize
    state=reader.inputs;key=(*reader.namespace.as_tuple,reader.operation_id)
    header=_fixed(state.work,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch'),
        'bot=? AND persona=? AND operation_id=?',key)
    reader.replay_original=None
    if header is None:return None
    values=[]
    for name in('anchor_json','permit_json','receipt_json'):
        with state.work.quantum_v3()as meter:
            row=reader.db.execute('SELECT typeof('+name+') FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',key).fetchone()
            meter.charge_read(8)
        values.append(None if row[0]=='null'else canonical_serialize(_column(state,'graph_owner_domain_attempts_v3',name,
            ('bot','persona','operation_id'),key)))
    if values[2]is not None:
        state.producer_ids.add(reader.operation_id)
        reader.replay_original=_positive(state,reader.operation_id,kind=reader.operation_kind)
    return header[0],header[1],values[0],header[2],header[3],values[1],values[2]
