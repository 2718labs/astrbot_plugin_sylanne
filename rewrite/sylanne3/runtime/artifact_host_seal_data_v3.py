"""Private finalized Host READ data for one existing Core-authorized call seal.

The certificate carries data integrity and lifetime. It carries no READ or MODEL
permission; the actual new seal transaction checks the independently current Core
model permit and every retained positive/negative comparison point.
"""
from __future__ import annotations
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from contextvars import ContextVar
from contextlib import contextmanager
import time
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3

_CERTIFICATES=WeakKeyDictionary()
_KEY=object()
_SEAL_BOUND=ContextVar('artifact_host_actual_model_seal_v3',default=None)

@dataclass(frozen=True,slots=True)
class _PointV3:
    table:str
    columns:tuple
    where:str
    key:tuple
    expected:tuple|None

class _ArtifactHostSealDataV3:
    def __init__(self,key,state):
        if key is not _KEY:raise AuthorityUnavailable('actual completed Host Source READ certificate issuer required')
        r=state.reader
        from .artifact_host_dispatch_source_v3 import _state_v3
        if(_state_v3(r)is not state or state.phase!='complete'or not r.complete or not r.sealed
                or state.result is None or state.frame_facts is None):
            raise AuthorityUnavailable('Artifact seal data requires actual Source EOF and positive prepared restriction')
        self.reader,self.state=r,state
        self.runtime,self.graph,self.store=r.context,r.graph,r.store
        self.operation,self.work=r.operation,r.work
        self.namespace,self.installation_id=r.namespace,r.selector.installation_id
        self.values=state.result
        self.request_digest=self.values[1].digest
        self.graph_stamp=r.graph_stamp
        self.versions=tuple(sorted(state.r_headers.items(),key=lambda item:item[0].token))
        self.coverage=tuple(state.coverage)
        self.acquire_writes=tuple(state.producers[state.prepared.acquire_operation_id].receipt.write_versions)
        self.deadline=min(state.eligibility_deadline,r.operation.deadline_utc)
        self.monotonic_deadline=r.initial_monotonic_deadline
        self.points=tuple(_PointV3(point.table,tuple(point.metadata_columns),point.where,tuple(point.key),
            None if point.metadata is None else tuple(point.metadata))for point in r.points.values())
        ns=r.namespace.as_tuple;originals=[]
        from .d11_life_preparation_v1 import TABLE
        for task in(state.prepared_task,state.frozen_task,state.request_task):
            originals.append(_PointV3(TABLE,('producing_operation_id','payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',(*ns,task.kind,task.ref),tuple(task.header)))
        for operation,task in state.producers.items():
            originals.append(_PointV3('graph_domain_production_originals_v1',
                ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
                'bot=? AND persona=? AND operation_id=?',(*ns,operation),tuple(task.header)))
        from .b3_managed_metadata_v1 import metadata_columns_v1,JOINT_TABLE,HABIT_TABLE
        self.managed=[]
        for table in(JOINT_TABLE,HABIT_TABLE):
            columns=metadata_columns_v1(table);selector=columns[2]
            rows=tuple(state.managed[table]);self.managed.append((table,selector,tuple(row[2]for row in rows)))
            originals.extend(_PointV3(table,columns,'bot=? AND persona=? AND '+selector+'=?',
                (*ns,row[2]),tuple(row))for row in rows)
        grant=state.grant_task
        originals.append(_PointV3('runtime_budget_grants',('lease_id','version','signature','status'),
            'lease_id=? ORDER BY version DESC',(state.prepared.parent_budget_lease_ref,),tuple(grant.header)))
        originals.append(_PointV3('runtime_budget_reservations',('digest','state'),
            'lease_id=? AND operation_id=?',(state.prepared.parent_budget_lease_ref,state.prepared.operation_id),
            tuple(state.reservation_header)))
        self.originals=tuple(originals)
        self.signed_families=tuple(sorted(state.signed_input_families.items()))
        _CERTIFICATES[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.reader,self.state,self.runtime,self.graph,self.store,self.operation,self.work,self.namespace,self.installation_id,
            self.values,self.request_digest,self.graph_stamp,self.versions,self.coverage,self.acquire_writes,
            self.deadline,self.monotonic_deadline,self.points,self.originals,tuple(self.managed),self.signed_families)
    def require_v3(self,graph,runtime,prepared,*,now):
        if(_CERTIFICATES.get(self)!=self._identity_v3() or self.graph is not graph or self.runtime is not runtime
                or runtime.graph is not graph or self.store is not graph._GraphCoordinator__store
                or self.operation.closed or not self.work.terminal or not self.work._finish_called
                or not self.reader.read_finished or self.reader.fence is not None or self.state.fences
                or self.values[0]!=prepared or self.values[1].digest!=self.request_digest
                or prepared.namespace!=self.namespace or prepared.installation_id!=self.installation_id
                or now>=self.deadline or time.monotonic()>=self.monotonic_deadline):
            raise AuthorityUnavailable('Artifact seal data is foreign, changed, released or expired; no old READ authority is reused')
        from .artifact_host_dispatch_source_v3 import _STATES,_identity_v3
        if(_STATES.get(self.reader)is not self.state or self.state.identity!=_identity_v3(self.reader)
                or self.reader.operation is not self.operation or self.reader.work is not self.work
                or runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
                or runtime.worker is not self.state.worker or runtime.client_grant!=self.state.model_grant
                or runtime.bundle is not self.reader.bundle or runtime.bootstrap is not self.reader.bootstrap
                or runtime.issuer is not graph._GraphCoordinator__d11_issuer):
            raise AuthorityUnavailable('Artifact seal data changed its original retained producer identity')
        return self

def issue_artifact_host_seal_data_v3(state):
    return _ArtifactHostSealDataV3(_KEY,state)

def require_artifact_host_seal_data_v3(certificate,graph,runtime,prepared,*,intent,permit,now):
    if type(certificate)is not _ArtifactHostSealDataV3:
        raise AuthorityUnavailable('Artifact call seal requires its actual private retained Host READ data')
    certificate.require_v3(graph,runtime,prepared,now=now)
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1,ModelEgressIntentV1
    from ..authority_service.v2_contract import FencePermitV2
    if(type(intent)is not ModelEgressIntentV1 or type(permit)is not FencePermitV2
            or ModelEgressDraftV1.from_intent(intent)!=certificate.values[2]
            or intent.request_digest!=certificate.request_digest or intent.binding_digest!=prepared.digest
            or intent.job_id!=prepared.job_id or intent.call_id!=prepared.call_id
            or intent.operation_id!=prepared.acquire_operation_id
            or permit.operation!='model_egress'or permit.operation_id!=intent.operation_id):
        raise AuthorityUnavailable('Artifact actual paired Core model intent/permit differs from its retained exact draft')
    return certificate

def _compare_point_v3(db,meter,point):
    actual=meter.read_fixed_row(db,point.table,point.columns,point.where,point.key)
    if actual!=point.expected:
        raise AuthorityUnavailable('Artifact seal retained SQL comparison point changed: '+point.table)

def compare_artifact_host_seal_data_in_transaction_v3(certificate,graph,runtime,prepared,*,intent,permit,now):
    c=require_artifact_host_seal_data_v3(certificate,graph,runtime,prepared,intent=intent,permit=permit,now=now)
    db=c.store._db
    if(_SEAL_BOUND.get()!=(c,graph,runtime,prepared,intent,permit)
            or not db.in_transaction or not c.store._lock._is_owned()):
        raise AuthorityUnavailable('Artifact seal data comparison requires its actual new locked transaction')
    if graph._v2_graph_stamp(c.namespace)!=c.graph_stamp:
        raise AuthorityUnavailable('Artifact Graph/storage stamp changed after actual dispatch READ')
    metadata,epoch=c.graph_stamp
    if(metadata.graph_revision,epoch.revision)!=(intent.graph_revision,intent.graph_epoch):
        raise AuthorityUnavailable('Artifact actual model intent differs from retained Graph revision/epoch')
    with bind_runtime_storage_operation_v3(c.operation,db),runtime_storage_quantum_v3(db)as meter:
        c.operation.handle.require_current(meter)
        rights=meter.read_fixed_row(db,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',c.namespace.as_tuple)
        if rights!=(intent.access_epoch,intent.delete_epoch):
            raise AuthorityUnavailable('Artifact Source access/deletion changed before actual call seal')
        for key,expected in c.versions:
            actual=meter.read_fixed_row(db,'graph_atoms',('revision','valid','type_name'),
                'token=? AND bot=? AND persona=?',(key.token,*c.namespace.as_tuple))
            if actual!=expected:raise AuthorityUnavailable('Artifact actual positive/negative B/C head changed before seal')
        writes={v.key:v for v in c.acquire_writes}
        for page in c.coverage:
            expected={v.key:v for v in page.row_versions}
            expected.update((key,v)for key,v in writes.items()if key.type_name==page.type_id)
            tokens=tuple(key.token for key in sorted(expected,key=lambda k:k.token))
            where='bot=? AND persona=? AND type_name=?'
            if tokens:where+=' AND token NOT IN ('+','.join('?'for _ in tokens)+')'
            extra=meter.read_fixed_row(db,'graph_atoms',('token',),where,(*c.namespace.as_tuple,page.type_id,*tokens))
            if extra is not None:
                raise AuthorityUnavailable('Artifact complete negative query gained a row before actual seal')
        for point in(*c.points,*c.originals):_compare_point_v3(db,meter,point)
        for(table,kind),refs in c.signed_families:
            where='bot=? AND persona=? AND kind=?'
            if refs:where+=' AND original_ref NOT IN ('+','.join('?'for _ in refs)+')'
            if meter.read_fixed_row(db,table,('original_ref',),where,(*c.namespace.as_tuple,kind,*refs))is not None:
                raise AuthorityUnavailable('Artifact signed-input negative family gained an unseen row before seal')
        for table,selector,tokens in c.managed:
            where='bot=? AND persona=?'
            if tokens:where+=' AND '+selector+' NOT IN ('+','.join('?'for _ in tokens)+')'
            extra=meter.read_fixed_row(db,table,(selector,),where,(*c.namespace.as_tuple,*tokens))
            if extra is not None:raise AuthorityUnavailable('Artifact managed metadata acquired an unseen current/retired row')
    return c

def release_artifact_host_seal_data_v3(certificate):
    _CERTIFICATES.pop(certificate,None)


def _require_actual_core_model_seal_v3(certificate,runtime,prepared,intent,permit):
    graph=certificate.graph;port=graph._GraphCoordinator__content_fence_v2;grant=runtime.client_grant
    if graph._GraphCoordinator__artifact_draft_model_runtime_v1 is not runtime:
        raise AuthorityUnavailable('Artifact seal changed its actual installed model runtime')
    import asyncio
    try:running_loop=asyncio.get_running_loop()
    except RuntimeError:running_loop=None
    if running_loop is runtime.owner_loop:
        raise AuthorityUnavailable('Artifact model seal observation must run on its actual Graph worker')
    from .first_ingress_v2 import trusted_upper
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    remaining=min(certificate.deadline-now,certificate.monotonic_deadline-time.monotonic())
    if remaining<=0:raise AuthorityUnavailable('Artifact original seal data deadline expired before MODEL observation')
    pending=asyncio.run_coroutine_threadsafe(runtime.authority_client.model_fence_current_observation_v1(
        runtime.bundle,grant,intent=intent),runtime.owner_loop)
    try:actual,state,anchor=pending.result(timeout=remaining)
    except TimeoutError:
        pending.cancel()
        raise AuthorityUnavailable('Artifact MODEL observation exceeded the unchanged original seal deadline')from None
    if(actual!=permit or state!='active'or permit.operation!='model_egress'
            or(permit.authority_id,permit.namespace,permit.subject,permit.holder,permit.generation,permit.operation_id)!=
              (grant.authority_id,intent.namespace,grant.subject,grant.administrator_holder,
               prepared.activation_generation,intent.operation_id)
            or intent.authority_id!=grant.authority_id or intent.subject!=prepared.worker_subject
            or intent.namespace!=certificate.graph_stamp[0].requirements.authority_namespace
            or permit.token!=intent.fence_token or permit.revision!=intent.fence_revision
            or permit.fence_epoch!=intent.fence_epoch or anchor!=permit.pinned_anchor):
        raise AuthorityUnavailable('Artifact actual paired Core model permit/anchor is no longer current')


@contextmanager
def bind_artifact_host_current_seal_v3(graph,runtime,prepared,*,intent,permit,data_certificate):
    db=graph._GraphCoordinator__store._db
    if db.in_transaction:raise AuthorityUnavailable('Artifact model seal current observations must precede its new transaction')
    from .first_ingress_v2 import trusted_upper
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    certificate=require_artifact_host_seal_data_v3(data_certificate,graph,runtime,prepared,
        intent=intent,permit=permit,now=now)
    _require_actual_core_model_seal_v3(certificate,runtime,prepared,intent,permit)
    token=_SEAL_BOUND.set((certificate,graph,runtime,prepared,intent,permit))
    try:
        with bind_runtime_storage_operation_v3(certificate.operation,db):yield certificate,now
    finally:
        _SEAL_BOUND.reset(token)
    # A committed local call original is preserved if this independent final
    # observation fails; no provider success or replay is inferred.
    _require_actual_core_model_seal_v3(certificate,runtime,prepared,intent,permit)
