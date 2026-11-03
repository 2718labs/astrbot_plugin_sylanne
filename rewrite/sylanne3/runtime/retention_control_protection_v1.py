"""Private same-Work retention protection from current metadata originals."""
from dataclasses import dataclass
from threading import get_ident
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .domain_production_contracts_v1 import ProductionOriginalRefV1

_ISSUER=object()
_TASKS=WeakKeyDictionary()
_FACTS=WeakKeyDictionary()
_WRITE_OBSERVING=WeakKeyDictionary()
_WRITE_OBSERVATIONS=WeakKeyDictionary()
OPERATION='reconcile_memory_retention_tier_v1'


def _identity(reader):
    return (reader,reader.work,reader.operation,reader.runtime,reader.authority,reader.lease,
        reader.operation_id,reader.operation_kind,reader.request,reader.request_digest,
        reader.selection_digest,reader.graph_stamp,reader.fence,reader.fence.scope,
        reader.owner_binding,reader.session_proof,reader.general_owner_entry)


def _require_retention_control_origin_v1(reader,source_ref):
    from .current_method_learning_read_v3 import (_MethodLearningReadV3,
        require_actual_method_learning_attachment_owner_v3)
    from .d06_retention_v1 import (ReconcileMemoryRetentionTierRequestV1,
        require_current_retention_source_v1)
    from ..memory_types import source_key
    if (type(reader) is not _MethodLearningReadV3 or reader.operation_kind!=OPERATION
            or type(reader.request) is not ReconcileMemoryRetentionTierRequestV1
            or reader.request.source_ref!=source_ref):
        raise AuthorityUnavailable('retention Control metadata requires its actual fixed Method request')
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    state=require_current_retention_source_v1(reader)
    key=AtomKey.from_token(source_ref)
    if (key!=source_key(*reader.namespace.as_tuple,key.owner.subject)
            or reader.fence.scope.operation!='read' or reader.fence.scope.namespace!=reader.namespace
            or reader.general_owner_entry is None or reader.session_proof is None):
        raise AuthorityUnavailable('retention Control metadata left its original Owner Source READ')
    reader.work._require_invocation(reader.graph)
    return state


def require_retention_control_reader_v1(reader,source_ref):
    _require_retention_control_origin_v1(reader,source_ref)
    if reader.read_finished:
        from .d06_retention_v1 import require_current_retention_write_v1
        return require_current_retention_write_v1(reader)[1]
    reader.general_owner_entry.require_for_v3(reader)
    return reader.fence.scope


def retention_control_work_identity_v1(reader):
    return canonical_digest((reader.operation_id,reader.operation_kind,reader.request_digest,
        reader.work.kind,reader.work.operation_id,reader.selection_digest,reader.graph_stamp,
        reader.owner_binding.principal,reader.owner_binding.grant_digest,
        reader.fence.scope.operation_id,reader.operation.deadline_utc))


def _owner_guard_digest_v1(reader):
    from ..authority_service.owner_location_read_v3 import _METHOD_OWNER_READ_ENTRIES_V3
    saved=_METHOD_OWNER_READ_ENTRIES_V3.get(reader.general_owner_entry)
    if saved is None or saved[0].request is not reader:
        raise AuthorityUnavailable('retention metadata needs its original private Owner location proof')
    return canonical_digest(saved[0].current_owner_authority.guard)


@dataclass(frozen=True,eq=False)
class _RetentionControlProtectionV1:
    protected:bool
    read_versions:tuple
    query_epochs:tuple
    originals:tuple
    coverage_digest:str

    def require_current_v1(self,reader):
        task=_FACTS.get(self)
        if task is None or task.fact is not self or _TASKS.get(reader) is not task:
            raise AuthorityUnavailable('retention protection requires its actual private completed issuer')
        scope=task.require_reader_v1(reader)
        if not task.complete or self.query_epochs!=(reader.query,):
            raise AuthorityUnavailable('retention protection changed its complete actual metadata epoch')
        with runtime_storage_quantum_v3(reader.db) as meter:
            source=task.inspection.result.require_v3(reader,meter)
            if (not source.valid or GraphVersion(source.key,source.revision)!=self.read_versions[0]):
                raise AuthorityUnavailable('retention protected Source metadata changed after actual EOF')
            revision=task.correction.require_current_v1(meter)
            if revision!=self.read_versions[1].revision:
                raise AuthorityUnavailable('retention correction metadata changed after actual EOF')
        if task.read_observation!=(task.identity,task.work_identity,task.original,self.coverage_digest):
            raise AuthorityUnavailable('retention protection lost its private admitted READ EOF observation')
        if reader.read_finished:
            from .d06_retention_v1 import require_current_retention_write_v1
            write=require_current_retention_write_v1(reader)
            observation=_WRITE_OBSERVATIONS.get(task)
            if (observation is None or observation[0] is not reader or observation[1] is not scope
                    or observation[2] is not write[2] or observation[3]!=task.identity
                    or observation[4]!=self.read_versions or observation[5]!=self.coverage_digest
                    or observation[6]!=task.original or observation[7]!=reader.graph_stamp
                    or canonical_digest(observation[8])!=task.original['payload']['owner_digest']):
                raise AuthorityUnavailable('retention W01 has no exact fresh WRITE Control/erasure observation')
        return self


class _CorrectionMetadataEOFV1:
    def __init__(self,parent,key):
        self.parent,self.key=parent,key
        self.header=self.column=self.value=None;self.started=self.complete=False

    def require_current_v1(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.parent.reader;self.parent.require_reader_v1(r)
        row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(self.key.token,*r.namespace.as_tuple))
        if not self.started or row!=self.header:
            raise AuthorityUnavailable('retention Correction current metadata/absence changed after its selected read')
        return 0 if row is None else row[0]

    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.parent.reader
        if not self.started:
            self.header=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(self.key.token,*r.namespace.as_tuple))
            self.started=True
            if self.header is None:self.complete=True
            return self.complete
        self.require_current_v1(meter)
        if self.complete:return True
        if self.column is None:
            from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3,_COLUMNS
            parent=self.parent
            class Column(DispatchOriginalJSONReadV3):
                def __init__(self):
                    self.registered=self.growing=False
                    super().__init__(r,table='graph_atoms',column='value',key_columns=('token','bot','persona'),
                        key=(self_key.token,*r.namespace.as_tuple),cell_id=cell_id)
                def _reserve(self,extra=0):
                    if not self.registered:
                        self.operation.register_retained_state_v3(self);self.registered=True
                    if self.growing:self.operation.finish_retained_state_growth_v3(self)
                    self.operation.reserve_retained_state_growth_v3(self,extra);self.growing=True
                def _runtime_retained_heap_bytes_v3(self):
                    from .source_correction_read_v3 import _heap
                    return 65536+self._payload_bytes+_heap((self.scalar,self.fragment))
                def advance(self,meter):
                    parent.require_reader_v1(r)
                    try:return super().advance(meter)
                    finally:
                        if self.growing:
                            self.operation.finish_retained_state_growth_v3(self);self.growing=False
                def release_v1(self):
                    if self.growing:self.operation.finish_retained_state_growth_v3(self);self.growing=False
                    _COLUMNS.pop(self,None)
                    self.value=self._frozen_value=self.parser=self.cell=None
                    self.nodes={};self.scalar=bytearray();self.fragment=b''
                    if self.registered:self.operation.unregister_retained_state_v3(self);self.registered=False
            self_key,cell_id=self.key,self.header[2]
            self.column=Column();return False
        if not self.column.advance(meter):return False
        from ..domains.d06 import validate_source_correction_head
        self.value=self.column.require_v3(r)
        if self.header[1]!=1:
            raise AuthorityUnavailable('retention current Correction metadata is invalid')
        validate_source_correction_head(self.key,self.value)
        if self.value['source_ref']!=self.parent.source_ref:
            raise AuthorityUnavailable('retention current Correction metadata belongs to another Source')
        self.complete=True;return True

    def release_v1(self):
        if self.column is not None:self.column.release_v1();self.column=None
        self.value=None


class CurrentRetentionControlProtectionTaskV1:
    def __init__(self,issuer,reader,source_ref):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('retention Control task requires its actual private factory')
        require_retention_control_reader_v1(reader,source_ref)
        if reader.read_finished or reader.inputs_sealed:
            raise AuthorityUnavailable('retention Control EOF cannot be constructed after its actual READ')
        from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
        from ..domains.d06 import source_correction_head_key
        self.reader,self.source_ref=reader,source_ref
        self.identity=_identity(reader);self.work_identity=retention_control_work_identity_v1(reader)
        self.port=reader.graph._GraphCoordinator__content_fence_v2
        self.inspection=InspectionMetadataReadV3(reader,AtomKey.from_token(source_ref))
        self.correction_key=source_correction_head_key(reader.namespace,AtomKey.from_token(source_ref).owner.subject)
        self.correction=_CorrectionMetadataEOFV1(self,self.correction_key)
        self.original=self.fact=self.read_observation=None
        self.continuation=None;self.phase='source';self.complete=False;self.released=False
        reader.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 8192+_heap((self.source_ref,self.work_identity,self.continuation,self.original,self.fact,
            self.read_observation,_WRITE_OBSERVATIONS.get(self),_WRITE_OBSERVING.get(self)))

    def require_reader_v1(self,reader):
        if (self.released or self.reader is not reader or _TASKS.get(reader) is not self
                or self.identity!=_identity(reader)
                or self.work_identity!=retention_control_work_identity_v1(reader)):
            raise AuthorityUnavailable('retention Control task crossed its original Method/Work/Owner identity')
        observing=_WRITE_OBSERVING.get(self)
        if observing is not None:
            if observing[0] is not reader or observing[-1]!=get_ident():
                raise AuthorityUnavailable('retention fresh WRITE observation crossed its actual caller')
            _require_retention_control_origin_v1(reader,self.source_ref)
            return observing[1]
        return require_retention_control_reader_v1(reader,self.source_ref)

    def advance(self,meter):
        r=self.reader;self.require_reader_v1(r)
        if self.complete:return True
        if self.phase=='source':
            if not self.inspection.advance(meter):return False
            source=self.inspection.result.require_v3(r,meter)
            if not source.valid:raise AuthorityUnavailable('retention Control target has no valid current Source metadata')
            self.phase='correction';return False
        if self.phase=='correction':
            if not self.correction.advance(meter):return False
            self.correction_protected=(self.correction.value is not None
                and self.correction.value['state']=='pending_reevaluation')
            self.correction_version=GraphVersion(self.correction_key,self.correction.require_current_v1(meter))
            self.phase='authority';return False
        if self.phase!='authority':
            raise AuthorityUnavailable('unknown retention Control metadata continuation')
        original=self.port.read_retention_control_metadata_v1(reader=r,task=self,action='advance')
        if original is None:return False
        from ..authority_service.retention_control_metadata_v1 import verify_retention_control_metadata_v1
        from ..authority_service.v2_contract import to_wire
        payload=verify_retention_control_metadata_v1(original,signer=r.graph._GraphCoordinator__d11_issuer._signer)
        if (payload['source_ref']!=self.source_ref or payload['namespace']!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or payload['work_identity']!=self.work_identity or payload['selection_digest']!=r.selection_digest
                or payload['graph_stamp_digest']!=canonical_digest(r.graph_stamp)
                or payload['owner_digest']!=_owner_guard_digest_v1(r)
                or payload['original_permit_digest']!=canonical_digest(to_wire(r.fence.scope.permit))
                or payload['operation_kind']!=OPERATION
                or type(payload['protected']) is not bool):
            raise AuthorityUnavailable('signed retention metadata crossed its actual original Method Source READ')
        source=self.inspection.result.require_v3(r,meter)
        versions=(GraphVersion(source.key,source.revision),self.correction_version)
        original_ref=ProductionOriginalRefV1('authority.retention_control_metadata.v1',
            'retention-control:'+self.continuation,canonical_digest(original),versions)
        coverage=canonical_digest((self.work_identity,r.query,versions,payload['cohort_digest'],
            payload['deletion_count'],payload['deletion_seq'],payload['deletion_digest'],original_ref))
        self.original=original
        self.fact=_RetentionControlProtectionV1(self.correction_protected or payload['protected'],
            versions,(r.query,),(original_ref,),coverage)
        self.read_observation=(self.identity,self.work_identity,self.original,coverage)
        _FACTS[self.fact]=self;self.complete=True
        r.operation.refresh_retained_state_v3(self);return True

    def release_v1(self):
        if self.released:return
        if self.fact is not None:_FACTS.pop(self.fact,None)
        _WRITE_OBSERVING.pop(self,None);_WRITE_OBSERVATIONS.pop(self,None)
        try:
            if self.continuation is not None:
                self.port.read_retention_control_metadata_v1(reader=self.reader,task=self,action='release')
        finally:
            self.released=True;self.inspection.release_v3();self.correction.release_v1()
            self.reader.operation.unregister_retained_state_v3(self)
            if _TASKS.get(self.reader) is self:_TASKS.pop(self.reader,None)
            self.original=self.fact=self.read_observation=None


def create_current_retention_control_protection_task_v1(reader,identity):
    if type(identity) is not tuple or len(identity)!=1:
        raise AuthorityUnavailable('retention Control task needs its exact one-Source locator')
    source_ref=identity[0];require_retention_control_reader_v1(reader,source_ref)
    task=_TASKS.get(reader)
    if task is None:
        task=CurrentRetentionControlProtectionTaskV1(_ISSUER,reader,source_ref);_TASKS[reader]=task
    if task.source_ref!=source_ref:
        raise AuthorityUnavailable('retention Control task cannot replace the actual Source target')
    return task


def require_current_retention_control_protection_v1(reader,*,source_ref):
    require_retention_control_reader_v1(reader,source_ref)
    task=_TASKS.get(reader)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import MethodInputNeededV3
        raise MethodInputNeededV3(('memory_retention_control_protection',(source_ref,)))
    if task.source_ref!=source_ref:
        raise AuthorityUnavailable('retention Control proof belongs to another actual Source')
    return task.fact.require_current_v1(reader)


def release_current_retention_control_protection_v1(reader):
    task=_TASKS.get(reader)
    if task is not None:task.release_v1()


def retention_control_transport_scope_v1(reader,task,action):
    """Only the actual SQL-free fresh-WRITE issuer can transport its recheck."""
    if action=='recheck' and reader.read_finished:
        saved=_WRITE_OBSERVING.get(task)
        if (saved is None or saved[0] is not reader or saved[-1]!=get_ident()
                or saved[2]!=reader.owner_binding or task.identity!=_identity(reader)
                or reader.db.in_transaction or reader.store._lock._is_owned()):
            raise AuthorityUnavailable('retention WRITE observation requires its actual caller outside Graph SQL/lock')
        return saved[1]
    return require_retention_control_reader_v1(reader,task.source_ref)


def observe_current_retention_control_write_v1(graph,*,authority,lease,operation_id,
        scope,guard,current_owner,original_owner,session_proof,metadata,epoch):
    """Observe Core outside SQL; W01 later consumes only this private result."""
    from .current_method_learning_read_v3 import _method_active
    from .d06_retention_v1 import ReconcileMemoryRetentionTierRequestV1
    r=_method_active(graph._GraphCoordinator__store._db)
    if r is None or r.operation_kind!=OPERATION:return None
    task=_TASKS.get(r)
    if (task is None or not task.complete or type(r.request) is not ReconcileMemoryRetentionTierRequestV1
            or r.graph is not graph or r.authority is not authority or r.lease!=lease
            or r.operation_id!=operation_id or not r.read_finished or not r.inputs_sealed
            or not r.business_started or scope is r.fence.scope or scope.operation!='write'
            or scope.namespace!=r.namespace or scope.generation!=authority.activation_generation
            or (scope.graph_revision,scope.graph_epoch)!=(metadata.graph_revision,epoch)
            or (metadata,epoch)!=r.graph_stamp or current_owner!=original_owner
            or original_owner is not r.owner_binding or session_proof is not r.session_proof
            or r.db.in_transaction or r.store._lock._is_owned()):
        raise AuthorityUnavailable('retention Control observation requires its real new Owner WRITE before SQL')
    if canonical_digest(guard)!=task.original['payload']['owner_digest']:
        raise AuthorityUnavailable('retention fresh WRITE Owner guard differs from its original signed cohort')
    r.operation.reserve_retained_state_growth_v3(task,32768)
    _WRITE_OBSERVING[task]=(r,scope,current_owner,guard,get_ident())
    try:
        with r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
            state=_require_retention_control_origin_v1(r,task.source_ref)
            if state.permission is None:
                raise AuthorityUnavailable('retention fresh WRITE requires its original complete Source ALL')
            source=task.inspection.result.require_v3(r,meter)
            local=(GraphVersion(source.key,source.revision),
                GraphVersion(task.correction_key,task.correction.require_current_v1(meter)))
            if local!=task.fact.read_versions:
                raise AuthorityUnavailable('retention Source/Correction changed before its real WRITE observation')
        original=task.port.read_retention_control_metadata_v1(reader=r,task=task,action='recheck')
        if original!=task.original:
            raise AuthorityUnavailable('retention fresh WRITE lost its signed Control/erasure cohort')
        with r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
            task.require_reader_v1(r)
            source=task.inspection.result.require_v3(r,meter)
            after=(GraphVersion(source.key,source.revision),
                GraphVersion(task.correction_key,task.correction.require_current_v1(meter)))
            if after!=local:
                raise AuthorityUnavailable('retention Source/Correction changed across fresh Core WRITE observation')
        observation=(r,scope,current_owner,task.identity,local,task.fact.coverage_digest,
            task.original,r.graph_stamp,guard)
        _WRITE_OBSERVATIONS[task]=observation
        return observation
    finally:
        _WRITE_OBSERVING.pop(task,None)
        r.operation.finish_retained_state_growth_v3(task)
