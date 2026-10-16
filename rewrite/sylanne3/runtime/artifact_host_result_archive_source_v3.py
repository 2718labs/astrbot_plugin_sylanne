"""Fresh Source-qualified Host archive of one real paid paired Artifact result.

The original delivery READ is history. This exact private profile owns new
Owner/Self/B+C READ scopes until its conditional local Original append.
"""
from dataclasses import dataclass,asdict
from datetime import datetime
from weakref import WeakKeyDictionary
import secrets,time,json
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import FencePermitV2
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import AuthorityContext,NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import(begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from ..graph_worker import(create_graph_storage_work_v3,require_graph_storage_work_admission_v3,GraphStorageStepV3)
from .domain_background_read_v3 import(BackgroundReadWorkV3,_ISSUER as BACKGROUND_ISSUER,
    require_actual_background_attachment_owner_v3,bind_background_reads_v3,BackgroundReadNeededV3,
    _start_background_request_v3,_advance_background_pending_v3)
from .first_ingress_v2 import trusted_upper
from .source_correction_read_v3 import _heap
from . import artifact_host_dispatch_source_v3 as common

_STATES=WeakKeyDictionary()
_TERMINALS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ArtifactHostResultArchiveSelectorV1:
    namespace:NamespaceId
    installation_id:str
    job_id:str
    prepared_digest:str
    paired_result_digest:str
    cost_fact_digest:str
    paid_digest:str
    delivery_request_digest:str
    schema:str='d11.artifact-host-result-archive-read.v1'


def _result_wire_v3(prepared,result):
    from ..authority_service.d11_artifact_draft_model_v1 import(artifact_draft_model_result_to_wire_v1,
        artifact_draft_model_result_to_wire_v2)
    from .d11_artifact_draft_model_v1 import _artifact_model_phase_v2
    return(artifact_draft_model_result_to_wire_v2 if _artifact_model_phase_v2(prepared)else artifact_draft_model_result_to_wire_v1)(result)


def _delivered_v3(runtime,prepared,result):
    graph=runtime.graph;rr=result.request;grant=runtime.client_grant
    port=graph._GraphCoordinator__content_fence_v2;read_grant=port.installation_grant
    if(read_grant.authority_id,read_grant.installation_id,read_grant.manifest_digest,read_grant.administrator_holder)!=(
            grant.authority_id,grant.installation_id,grant.manifest_digest,grant.administrator_holder):
        raise AuthorityUnavailable('Artifact delivery READ and MODEL bindings differ in actual installation identity')
    delivered,state=port.get_fence_operation(namespace=prepared.namespace,
        authority_namespace=rr.authority_namespace,operation_id=rr.read_attempt_id)
    if(type(delivered)is not FencePermitV2 or state!='finished'
            or(delivered.authority_id,delivered.namespace,delivered.subject,delivered.holder,
                delivered.generation,delivered.operation,delivered.operation_id)!=(
                read_grant.authority_id,rr.authority_namespace,read_grant.subject,read_grant.administrator_holder,
                prepared.activation_generation,'read',rr.read_attempt_id)
            or(rr.authority_id,rr.installation_id,rr.namespace)!=(grant.authority_id,grant.installation_id,prepared.namespace)):
        raise AuthorityUnavailable('Artifact result lacks its actual independently finished paired delivery history')
    return delivered


def has_artifact_host_result_archive_work_v3(r):
    return r in _STATES


def archive_state_for_dispatch_v3(r):
    s=_STATES.get(r)
    if s is None:return None
    require_actual_background_attachment_owner_v3(r,db=r.db)
    runtime=r.context
    if(type(r)is not BackgroundReadWorkV3 or type(r.selector)is not ArtifactHostResultArchiveSelectorV1
            or r.kind!='artifact_model_dispatch'or s.reader is not r or s.identity!=common._identity_v3(r)
            or runtime is not r.graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or(runtime.graph,runtime.bootstrap,runtime.bundle,runtime.worker,runtime.issuer,runtime.client_grant)!=(
                r.graph,r.bootstrap,r.bundle,s.worker,r.graph._GraphCoordinator__d11_issuer,s.model_grant)
            or r.operation.closed or r.graph._v2_graph_stamp(r.namespace)!=r.graph_stamp
            or runtime._results.get(r.selector.job_id)is not s.paired_result
            or runtime._paid.get(r.selector.job_id)is not s.paid
            or runtime._cost_facts.get(r.selector.job_id)is not s.fact):
        raise AuthorityUnavailable('Artifact archive lost its exact installed paired cache/selector/Work identity')
    if s.fences and(r.fence is not s.fences[0]or r.read_scope is not r.fence.scope or r.authority!=r.fence.authority):
        raise AuthorityUnavailable('Artifact archive changed its actual primary new READ')
    r.work._require_invocation(r.graph)
    return s


class _ArchiveStateV3(common._DispatchStateV3):
    def __init__(self,r,prepared,result,paid,fact,delivery):
        super().__init__(r)
        self.expected_prepared=prepared;self.paired_result,self.paid,self.fact=result,paid,fact
        self.result_wire=canonical_serialize(_result_wire_v3(prepared,result))
        self.delivery=delivery;self.financial=None;self.call_task=None;self.sealed_intent=None
        self.archive_write=False
    def _runtime_retained_heap_bytes_v3(self):
        return(super()._runtime_retained_heap_bytes_v3()+_heap((self.expected_prepared,self.paired_result,self.paid,
            self.fact,self.result_wire,self.delivery,self.financial,self.call_task,self.sealed_intent))*3+8192)
    def prepared_metadata_v3(self,meter):
        ready=super().prepared_metadata_v3(meter)
        if ready and self.prepared!=self.expected_prepared:
            raise AuthorityUnavailable('Artifact archive signed prepared differs from actual paired runtime original')
        return ready


class _ArchiveFinancialMetadataV3:
    """Exact existing financial ABI; full canonical control EOF, no content Body."""
    def __init__(self,state):
        self.state=state;self.phase='bundle';self.column=None;self.complete=False
        self.bundle=self.event=self.history=self.cost_head=self.budget_header=self.reservation=None
        self.bundle_value=self.event_versions=self.cost_value=self.budget_value=None
        self.cost_versions=();self.snapshot=[]
    def _point(self,meter,table,columns,where,key):
        row=meter.read_fixed_row(self.state.reader.db,table,columns,where,key)
        self.snapshot.append((table,tuple(columns),where,tuple(key),None if row is None else tuple(row)))
        return row
    def _column(self,table,column,keys,key,cell=None):
        self.column=common._DispatchColumnV3(self.state,'archive_financial',table=table,column=column,
            key_columns=keys,key=key,cell_id=cell)
    def advance(self,meter):
        s=self.state;r=s.reader;p=s.prepared;c=s.paid;ns=r.namespace.as_tuple
        common.require_artifact_host_dispatch_current_v3(r,meter)
        if self.column is not None:
            if not self.column.advance(meter):return False
            value=self.column.require_v3(r);digest=self.column.sha256
            if self.phase=='bundle_value':self.bundle_value=value;self.phase='event'
            elif self.phase=='event_versions':self.event_versions=value;self.phase='history'
            elif self.phase=='cost_value':self.cost_value=value;self.phase='budget'
            elif self.phase=='budget_value':
                if digest!=c.budget_receipt_digest:raise AuthorityUnavailable('Artifact archive actual settled receipt canonical EOF differs')
                self.budget_value=value;self.phase='validate'
            else:raise AuthorityUnavailable('Unregistered actual archive financial EOF')
            self.column=None;return False
        if self.phase=='bundle':
            self.bundle=self._point(meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*ns,c.operation_id))
            if self.bundle is None or self.bundle[3]!=c.commit_seq or c.commit_seq<1:
                raise AuthorityUnavailable('Artifact result archive has no actual positive cost CAS bundle')
            self.phase='bundle_value';self._column('graph_bundle_operations','receipt_json',
                ('bot','persona','operation_id'),(*ns,c.operation_id));return False
        if self.phase=='event':
            self.event=self._point(meter,'graph_events',('epoch_revision',),
                'bot=? AND persona=? AND session=? AND event_id=?',(*ns,self.bundle[1],c.operation_id))
            if self.event is None or self.event[0]!=c.graph_epoch:
                raise AuthorityUnavailable('Artifact archive cost CAS lacks its actual Graph event epoch')
            self.phase='event_versions';self._column('graph_events','revisions',
                ('bot','persona','session','event_id'),(*ns,self.bundle[1],c.operation_id));return False
        if self.phase=='history':
            from ..graph_store import GraphStore
            versions=GraphStore._version_rows(canonical_serialize(self.event_versions))
            if len(versions)!=1 or versions[0].key.token!=c.cost_ref:
                raise AuthorityUnavailable('Artifact archive permits only its actual one cost CAS member')
            self.cost_versions=tuple(versions);v=versions[0]
            self.history=self._point(meter,'graph_history',('event_id','valid','value_cell_id'),
                'token=? AND revision=?',(c.cost_ref,v.revision))
            self.cost_head=self._point(meter,'graph_atoms',('revision','valid','type_name'),
                'token=? AND bot=? AND persona=?',(c.cost_ref,*ns))
            if(self.history is None or self.history[:2]!=(c.operation_id,1)
                    or self.cost_head!=(v.revision,1,v.key.type_name)):
                raise AuthorityUnavailable('Artifact archive cost Original lost its exact current/history CAS member')
            self.phase='cost_value';self._column('graph_history','value',('token','revision'),
                (c.cost_ref,v.revision),cell=self.history[2]);return False
        if self.phase=='budget':
            key=(*ns,p.operation_id,'settle')
            self.budget_header=self._point(meter,'runtime_budget_operations',('digest','lease_id'),
                'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',key)
            self.reservation=self._point(meter,'runtime_budget_reservations',('digest','state'),
                'lease_id=? AND operation_id=?',(p.parent_budget_lease_ref,p.operation_id))
            if(self.budget_header!=(p.reservation_digest,p.parent_budget_lease_ref)
                    or self.reservation is None or self.reservation[0]!=p.reservation_digest
                    or self.reservation[1]not in{'settled','overrun','unknown','partial_unknown','partial_overrun'}):
                raise AuthorityUnavailable('Artifact archive lacks its real accounted original reservation')
            self.phase='budget_value';self._column('runtime_budget_operations','receipt_json',
                ('bot_id','persona_id','operation_id','phase'),key);return False
        if self.phase=='validate':
            self._validate();self.complete=True;return True
        return False
    def _validate(self):
        s=self.state;r=s.reader;p=s.prepared;c=s.paid;raw=self.bundle_value
        from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
        if(set(raw)!={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id',
                'quote_version','work_kind','accounting_attempt_id'}or raw['work_kind']!='artifact_draft_v1'
                or decode_artifact_draft_original_v1('c4_paid',raw['original_model_cost'])!=c
                or raw['original_intent_digest']!=canonical_digest(asdict(s.fact.intent))
                or(raw['terminal_receipt_digest'],raw['quote_id'],raw['quote_version'])!=(
                    c.terminal_receipt_digest,p.quote_id,1)):
            raise AuthorityUnavailable('Artifact archive cost ledger differs from actual paired terminal/intent')
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d11_types import RuntimeCostSettlement,runtime_cost_settlement_key
        from .budget import BudgetReceipt
        cost=decode_typed_production_value_v1(self.cost_value,RuntimeCostSettlement)
        receipt=decode_typed_production_value_v1(self.budget_value,BudgetReceipt)
        if((cost.bot_id,cost.persona_id,cost.bundle_operation_id,cost.settlement_id,cost.activity_id,cost.effect_id)!=(
                *r.namespace.as_tuple,c.operation_id,c.operation_id,self.bundle[1],self.bundle[2])
                or c.cost_ref!=runtime_cost_settlement_key(*r.namespace.as_tuple,self.bundle[1],c.operation_id).token
                or(cost.lease_id,cost.cost_operation_id,cost.budget_phase,cost.budget_operation_id)!=(
                    p.parent_budget_lease_ref,p.operation_id,'settle',p.operation_id)
                or cost.budget_receipt_digest!=c.budget_receipt_digest
                or canonical_digest(self.budget_value)!=c.budget_receipt_digest
                or(receipt.operation_id,receipt.lease_id,receipt.status,receipt.digest)!=(
                    p.operation_id,p.parent_budget_lease_ref,cost.status,p.reservation_digest)):
            raise AuthorityUnavailable('Artifact archive actual financial history/settlement receipt identity differs')
        # The cost bundle records its own historical CAS stamp. Unrelated
        # commits may precede or follow it; this fresh READ independently pins
        # its current stamp and every exact B/C head/query/Source comparison.
        # Financial eligibility comes from the complete actual immutable cost
        # bundle/event/history/receipt above, never admission_revision + 1.
    def compare_v3(self,meter):
        if not self.complete:raise AuthorityUnavailable('Artifact archive financial metadata has not reached whole EOF')
        for table,columns,where,key,row in self.snapshot:
            if meter.read_fixed_row(self.state.reader.db,table,columns,where,key)!=row:
                raise AuthorityUnavailable('Artifact archive actual financial header changed before conditional append')


def prepare_current_artifact_host_result_archive_v1(graph,runtime,prepared):
    from .d11_artifact_draft_model_v1 import(InstalledArtifactDraftModelRuntimeV1,
        require_artifact_draft_paid_terminal_identity_v1)
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    graph._admin(runtime.bootstrap);require_graph_storage_work_admission_v3(graph)
    port=graph._GraphCoordinator__content_fence_v2;assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if(type(runtime)is not InstalledArtifactDraftModelRuntimeV1 or runtime.graph is not graph
            or runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or assembly is None or type(runtime.bundle)is not AdminInstallationBundle
            or runtime.bundle is not assembly.admin_bundle or type(port)is not V2FencePort):
        raise AuthorityUnavailable('Artifact archive requires its real installed runtime/Source port')
    result,paid=runtime.read_cached_adoption_originals_v1(prepared);fact=runtime.read_cached_cost_fact_v1(prepared.job_id)
    require_artifact_draft_paid_terminal_identity_v1(prepared=prepared,fact=fact,commit=paid,result=result)
    policy=runtime.bundle.installation_policy;grant=runtime.client_grant
    if(prepared.namespace!=policy.namespace or prepared.installation_id!=policy.installation_id
            or(prepared.installation_id,prepared.manifest_digest)!=(grant.installation_id,grant.manifest_digest)
            or(port.installation_grant.installation_id,port.installation_grant.manifest_digest)!=(grant.installation_id,grant.manifest_digest)
            or grant.administrator_holder!=policy.administrator_holder):
        raise AuthorityUnavailable('Artifact archive exact paired installation differs')
    delivery=_delivered_v3(runtime,prepared,result)
    selector=ArtifactHostResultArchiveSelectorV1(prepared.namespace,prepared.installation_id,prepared.job_id,
        prepared.digest,canonical_digest(_result_wire_v3(prepared,result)),canonical_digest(asdict(fact)),
        canonical_digest(asdict(paid)),result.request.digest)
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline=min(now+60.0,datetime.fromisoformat(prepared.deadline_utc.replace('Z','+00:00')).timestamp())
    operation_id='artifact-result-archive-read:'+secrets.token_hex(16)
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,deadline)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            authority=AuthorityContext('artifact-archive-metadata','d11','artifact-archive-metadata',selector.namespace,
                ('activity',),'consolidation',('owner',),'artifact-result-archive-read.v1',prepared.activation_generation)
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id+':metadata')
            r=BackgroundReadWorkV3(BACKGROUND_ISSUER,graph,runtime.bootstrap,runtime.bundle,operation,
                kind='artifact_model_dispatch',dedupe_key=None,context=runtime)
            r.selector,r.fence,r.read_scope,r.authority=selector,fence,fence.scope,authority
            r.runtime=graph._GraphCoordinator__domain_production_runtime_v1
            r.lease=r.owner_binding=r.owner_guard=r.session_proof=None
            r.operation_id=operation_id;r.request_digest=canonical_digest(selector);r.read_finished=False
            r.initial_monotonic_deadline=time.monotonic()+deadline-now
            r.initial_now_utc=r.now=now;r.phase='artifact_archive_metadata'
            work=create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=deadline,state=r,operation=operation)
            r.work=work;s=_ArchiveStateV3(r,prepared,result,paid,fact,delivery);_STATES[r]=s
            operation.register_retained_state_v3(s)
            def unwrap(value):return value.require_result_v3(work)
            def failed(error):raise error
            work.map_terminal_v3('issuer',unwrap,failed)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def _archive_after_producers_v3(s):
    r=s.reader;f=s.financial
    # The cost CAS adds precisely this authenticated financial member. It does
    # not authorize replacement of any original B/C head or ordinary query row.
    if any(v.key in{q.key for q in(*s.business_versions,*s.control_versions)}for v in f.cost_versions):
        raise AuthorityUnavailable('Artifact cost CAS unexpectedly replaced an original B/C input')
    s.head_metadata.write_versions=(*s.head_metadata.write_versions,*f.cost_versions)
    s.allowed_operations.add(s.paid.operation_id)
    prefix='c4_phase_'if s.phase_variant else'c4_'
    s.allowed_originals.update(((prefix+'paid',s.ids['paid']),(prefix+'result',s.ids['result'])))
    s.call_task=common._DispatchSignedMetadataV3(s,prefix+'call',s.prepared.call_id,'archive_call')
    s.phase='archive_call'


def _archive_snapshot_v3(s,meter,*,after_append=False):
    r=s.reader;common.require_artifact_host_dispatch_current_v3(r,meter)
    s.owner_entry.require_for_v3(r);s.financial.compare_v3(meter)
    from .d11_artifact_draft_model_v1 import _artifact_model_original_kind
    own_originals={(_artifact_model_original_kind(s.prepared,'paid'),s.ids['paid']),
        (_artifact_model_original_kind(s.prepared,'result'),s.ids['result'])}
    for point in tuple(r.points.values()):
        if(after_append and point.table=='graph_d11_life_originals_v1'
                and tuple(point.key[2:])in own_originals):continue
        if not point.complete or any(c is not None and not c.complete for c in point.values.values()):
            raise AuthorityUnavailable('Artifact archive final point lacks actual complete canonical EOF')
        r.require_request_v3(point.request);point.require_row_v3(meter)
    for key,expected in s.r_headers.items():
        row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','type_name'),
            'token=? AND bot=? AND persona=?',(key.token,*r.namespace.as_tuple))
        if row!=expected:raise AuthorityUnavailable('Artifact archive B/C positive/negative current metadata changed')
    for key,revision in s.source_versions.items():
        row=meter.read_fixed_row(r.db,'graph_atoms',('revision',),'token=? AND bot=? AND persona=?',
            (key.token,*r.namespace.as_tuple))
        if(0 if row is None else row[0])!=revision:raise AuthorityUnavailable('Artifact archive Source/Access/ancestor version changed')
    if(s.job_header!=meter.read_fixed_row(r.db,'runtime_jobs',
            ('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','phase','work_kind','deadline_utc',
             'budget_ref','lease_holder','lease_expires_utc','fence','cancel_epoch','result_ref'),'job_id=?',(r.selector.job_id,))
            or s.reservation_header!=meter.read_fixed_row(r.db,'runtime_budget_reservations',('digest','state'),
                'lease_id=? AND operation_id=?',(s.prepared.parent_budget_lease_ref,s.prepared.operation_id))):
        raise AuthorityUnavailable('Artifact archive original worker/lease/cancel/accounted reservation changed')


def require_bound_artifact_result_archive_v3(db,*,prepared,fact,commit,result,issuer):
    from .domain_background_read_v3 import _active_v3
    r=_active_v3(db);s=None if r is None else archive_state_for_dispatch_v3(r)
    if(s is None or not s.archive_write or not db.in_transaction or not s.source_complete or s.phase!='algorithm'
            or(prepared,fact,commit,result)!=(s.prepared,s.fact,s.paid,s.paired_result)or issuer is not r.context.issuer):
        raise AuthorityUnavailable('Artifact result Original append requires its live fresh actual archive READ consumer')
    return s


def append_bound_artifact_paid_result_v3(db,*,prepared,fact,commit,result,issuer):
    s=require_bound_artifact_result_archive_v3(db,prepared=prepared,fact=fact,commit=commit,result=result,issuer=issuer)
    from .d11_artifact_draft_model_v1 import _artifact_model_original_kind
    from .d11_life_preparation_v1 import _record
    original=_record(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,'paid'),
        ref=s.ids['paid'],operation_id=commit.operation_id,value=commit)
    _record(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,'result'),
        ref=s.ids['result'],operation_id=commit.operation_id,value=json.loads(s.result_wire))
    return original


def read_bound_artifact_archive_record_v3(db,*,issuer,namespace,kind,ref,operation_id,value):
    from .domain_background_read_v3 import _active_v3,background_point_v3,background_json_matches_v3
    r=_active_v3(db);s=None if r is None else archive_state_for_dispatch_v3(r)
    if s is None:return False,None
    if not s.archive_write or not db.in_transaction or issuer is not r.context.issuer or namespace!=r.namespace:
        raise AuthorityUnavailable('Artifact archive immutable append has no actual final READ consumer')
    from .d11_artifact_draft_model_v1 import _artifact_model_original_kind
    allowed={(_artifact_model_original_kind(s.prepared,'paid'),s.ids['paid']):asdict(s.paid),
        (_artifact_model_original_kind(s.prepared,'result'),s.ids['result']):json.loads(s.result_wire)}
    if operation_id!=s.paid.operation_id or(kind,ref)not in allowed or canonical_digest(value)!=canonical_digest(allowed[kind,ref]):
        raise AuthorityUnavailable('Artifact archive cannot append any other local immutable Original')
    row=background_point_v3(db,table='graph_d11_life_originals_v1',
        columns=('producing_operation_id','payload_json','payload_digest','signature'),
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,ref),legacy_reader=lambda:None)
    if row is None:return True,None
    if not background_json_matches_v3(row[1],allowed[kind,ref]):raise AuthorityUnavailable('Artifact immutable result replay changed actual retained Body')
    return True,(row[0],canonical_serialize(allowed[kind,ref]),row[2],row[3])


def _conditional_archive_v3(s,meter):
    r=s.reader;runtime=r.context
    from .d11_artifact_draft_model_v1 import(require_artifact_draft_paid_terminal_identity_v1,
        record_artifact_draft_paid_after_cost_cas_v1,_artifact_model_original_kind)
    require_artifact_draft_paid_terminal_identity_v1(prepared=s.prepared,fact=s.fact,commit=s.paid,result=s.paired_result)
    if canonical_serialize(_result_wire_v3(s.prepared,s.paired_result))!=s.result_wire:
        raise AuthorityUnavailable('Artifact paired result full canonical wire changed after actual delivery')
    r.db.execute('BEGIN IMMEDIATE')
    try:
        _archive_snapshot_v3(s,meter)
        with bind_background_reads_v3(r,db=r.db):
            _,quote=common.read_bound_artifact_host_dispatch_quote_v3(r.db,runtime.issuer.resource_issuer,
                s.prepared.quote_id,1)
            from .d11_types import runtime_job_key
            if(quote.work_kind!='artifact_draft_v1'or quote.operation_id!=s.prepared.operation_id
                    or quote.graph_job_ref!=runtime_job_key(*r.namespace.as_tuple,s.prepared.activity_id,s.prepared.job_id).token
                    or dict(quote.ceiling)!=dict(s.fact.intent.budget_ceiling)):
                raise AuthorityUnavailable('Artifact archive signed actual quote escaped original worker/Root ceiling')
            s.archive_write=True
            try:original=record_artifact_draft_paid_after_cost_cas_v1(r.db,prepared=s.prepared,fact=s.fact,
                commit=s.paid,issuer=runtime.issuer,result=s.paired_result)
            finally:s.archive_write=False
        _archive_snapshot_v3(s,meter,after_append=True)
        from .d11_life_preparation_v1 import SIGN_KIND
        for kind,ref,value in((_artifact_model_original_kind(s.prepared,'paid'),s.ids['paid'],asdict(s.paid)),
                (_artifact_model_original_kind(s.prepared,'result'),s.ids['result'],json.loads(s.result_wire))):
            digest=canonical_digest(value)
            header=meter.read_fixed_row(r.db,'graph_d11_life_originals_v1',
                ('producing_operation_id','payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,kind,ref))
            expected=(s.paid.operation_id,digest,runtime.issuer._signer.sign(SIGN_KIND,
                canonical_serialize((r.namespace,kind,ref,digest))))
            if header!=expected:raise AuthorityUnavailable('Artifact archive own conditional immutable append header differs')
        r.db.commit()
    except BaseException:r.db.rollback();raise
    return {'status':'recorded','job_id':s.prepared.job_id,'paid_original_ref':original.original_ref,
        'historical_delivery_read_attempt_id':s.paired_result.request.read_attempt_id,
        'current_archive_read_operation_id':r.read_scope.operation_id,
        'current_archive_read_permit_digest':canonical_digest(r.read_scope.permit)}


class _ArchiveTerminalV3:
    def __init__(self,s,value):
        self.reader=s.reader;self.value=value;_TERMINALS[self]=(s.reader,s.reader.work,s.reader.selection_digest)
    def require_result_v3(self,work):
        r=self.reader
        if(_TERMINALS.get(self)!=(r,work,r.selection_digest)or not r.read_finished or not work._finish_called
                or r.operation.closed):raise AuthorityUnavailable('Artifact archive receipt lost its finalized retained Work')
        work._require_invocation(r.graph);return self.value
    def release_payload_v3(self):
        value=_TERMINALS.pop(self,None)
        if value is not None:value[0].release_payload_v3()
        self.reader=self.value=None


def advance_artifact_host_result_archive_v3(graph,work):
    r=work.state;s=archive_state_for_dispatch_v3(r)
    if s is None or graph is not r.graph or work is not r.work:raise AuthorityUnavailable('Wrong actual Artifact archive Work')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.now=common._observe_v3(r)
        if s.phase=='algorithm'and r.pending is None and _delivered_v3(r.context,s.prepared,s.paired_result)!=s.delivery:
            raise AuthorityUnavailable('Artifact original finished delivery history changed')
        if s.phase=='owner':common._prepare_owner_scopes_v3(s);return GraphStorageStepV3('progress')
        complete=False;receipt=None
        with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
            if r.db.in_transaction:raise AuthorityUnavailable('Artifact archive cannot retain SQL across quanta')
            common.require_artifact_host_dispatch_current_v3(r,meter)
            if s.phase=='algorithm'and r.pending is None:
                try:receipt=_conditional_archive_v3(s,meter);complete=True
                except BackgroundReadNeededV3 as needed:_start_background_request_v3(r,needed.request)
            else:
                r.db.execute('BEGIN')
                try:
                    if r.pending is not None:_advance_background_pending_v3(r,meter)
                    elif s.phase=='job':s.job_metadata_v3(meter)
                    elif s.phase=='prepared':s.prepared_metadata_v3(meter)
                    elif s.phase=='frozen':common._frozen_metadata_v3(s,meter)
                    elif s.phase=='request':common._request_metadata_v3(s,meter)
                    elif s.phase=='producers':
                        if common._producer_metadata_v3(s,meter):
                            s.financial=_ArchiveFinancialMetadataV3(s);s.phase='archive_financial'
                    elif s.phase=='archive_financial':
                        if s.financial.advance(meter):_archive_after_producers_v3(s)
                    elif s.phase=='archive_call':
                        if s.call_task.advance(meter):
                            from ..authority_service.v2_model_egress_wire import from_wire
                            from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
                            s.sealed_intent=from_wire(s.call_task.value,ModelEgressIntentV1)
                            if(s.sealed_intent!=s.fact.intent or s.call_task.header[0]!=s.prepared.acquire_operation_id
                                    or s.request_task.value['request_digest']!=s.fact.intent.request_digest):
                                raise AuthorityUnavailable('Artifact archive signed call/request differs from paired actual cost intent')
                            s.phase='readset_metadata'
                    elif s.phase=='readset_metadata':s.head_metadata.advance(meter)
                    elif s.phase=='job_graph':common._job_graph_metadata_v3(s,meter)
                    elif s.phase=='budget':
                        common._budget_metadata_v3(s,meter)
                        if s.phase=='managed'and s.reservation_header!=s.financial.reservation:
                            raise AuthorityUnavailable('Artifact archive actual accounted reservation changed')
                    elif s.phase=='managed':common._managed_metadata_v3(s,meter)
                    elif s.phase=='joint_metadata':s.joint_metadata.advance(meter)
                    elif s.phase=='habit_metadata':s.habit_metadata.advance(meter)
                    elif s.phase=='sources':common._sources_metadata_v3(s,meter)
                    else:raise AuthorityUnavailable('Artifact archive has no fixed actual next phase')
                    common.require_artifact_host_dispatch_current_v3(r,meter);r.reserve_heap_v3()
                finally:r.db.rollback()
        if complete:
            # A failed postcheck preserves the already committed immutable result.
            common._observe_v3(r)
            s.phase='complete';r.complete=r.sealed=True;r.phase='artifact_archive_complete'
            r.result=_ArchiveTerminalV3(s,receipt);return GraphStorageStepV3('complete',r.result)
    return GraphStorageStepV3('progress')


def finish_artifact_host_result_archive_v3(graph,work,error):
    r=work.state;s=_STATES.get(r)
    if s is None or graph is not r.graph or work is not r.work:raise AuthorityUnavailable('Artifact archive finalization lost its private Work')
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            common._close_artifact_host_dispatch_scopes_v3(r,s);r.read_finished=True
        if error is None:work.result_lease=work.operation
    except BaseException:
        r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation);raise
    if error is not None:r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation)


def release_artifact_host_result_archive_payload_v3(r):
    s=_STATES.pop(r,None)
    if s is None:return False
    if type(r.result)is _ArchiveTerminalV3:
        _TERMINALS.pop(r.result,None);r.result.reader=r.result.value=None
    for task in s.signed_input_metadata.values():task.release_payload_v3()
    for group in s.groups:common._SCOPES.pop(group,None)
    s.groups.clear();s.signed_input_metadata.clear();s.allowed_inputs.clear();s.input_digests.clear()
    s.managed.clear();s.producers.clear();s.producer_tasks.clear();s.original_body_metadata.clear()
    s.source_versions.clear();s.allowed_keys.clear();s.allowed_originals.clear();s.allowed_operations.clear()
    s.allowed_quotes.clear();s.allowed_jobs.clear()
    s.expected_prepared=s.paired_result=s.paid=s.fact=s.delivery=None
    s.result_wire=s.financial=s.call_task=s.sealed_intent=None
    s.prepared_task=s.frozen_task=s.request_task=s.grant_task=None
    s.job_column=s.job_graph_column=s.joint_metadata=s.habit_metadata=s.head_metadata=None
    return True
