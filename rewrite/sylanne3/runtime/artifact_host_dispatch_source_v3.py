"""Closed installed Host Artifact dispatch READ. It grants no model execution."""
from __future__ import annotations
from dataclasses import dataclass,replace
from datetime import datetime
from weakref import WeakKeyDictionary
import secrets,time
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import AuthorityContext,NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from ..graph_worker import (create_graph_storage_work_v3,require_graph_storage_work_admission_v3,GraphStorageStepV3)
from .domain_background_read_v3 import (BackgroundReadWorkV3,_ISSUER as BACKGROUND_ISSUER,
    require_actual_background_attachment_owner_v3,bind_background_reads_v3,
    BackgroundReadNeededV3,_start_background_request_v3,_advance_background_pending_v3,_D07_POINT_COLUMNS)
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
from .source_correction_read_v3 import SourceCorrectionContextReadV3,_heap
from .first_ingress_v2 import trusted_upper
from .b3_managed_metadata_v1 import (HABIT_TABLE,JOINT_TABLE,metadata_columns_v1,validate_managed_metadata_row_v1)

_KIND='artifact_model_dispatch'
_STATES=WeakKeyDictionary()
_SCOPES=WeakKeyDictionary()


@dataclass(frozen=True,slots=True)
class ArtifactHostDispatchReadSelectorV1:
    namespace:NamespaceId
    installation_id:str
    job_id:str
    schema:str='d11.artifact-host-dispatch-read.v1'
    def __post_init__(self):
        from .jobs import _identifier
        if self.schema!='d11.artifact-host-dispatch-read.v1'or type(self.namespace)is not NamespaceId:
            raise ValueError('Exact Artifact Host dispatch namespace/selector required')
        _identifier(self.installation_id,'installation_id');_identifier(self.job_id,'job_id')


def _identity_v3(r):
    return(r.graph,r.bootstrap,r.bundle,r.context,r.selector,r.work,r.operation,r.selection_digest,r.graph_stamp)


def _state_v3(r):
    from .artifact_host_result_archive_source_v3 import archive_state_for_dispatch_v3
    archive=archive_state_for_dispatch_v3(r)
    if archive is not None:return archive
    require_actual_background_attachment_owner_v3(r,db=r.db)
    value=_STATES.get(r)
    if(value is None or type(r)is not BackgroundReadWorkV3 or r.kind!=_KIND
            or value.identity!=_identity_v3(r)or value.reader is not r
            or r.context is not r.graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or r.context.graph is not r.graph or r.context.bundle is not r.bundle
            or r.context.bootstrap is not r.bootstrap or r.context.issuer is not r.graph._GraphCoordinator__d11_issuer
            or r.context.worker is not value.worker or r.context.client_grant!=value.model_grant
            or r.operation.closed or r.graph._v2_graph_stamp(r.namespace)!=r.graph_stamp):
        raise AuthorityUnavailable('Artifact dispatch lost its exact installed retained READ Work')
    if value.fences and(r.fence is not value.fences[0]or r.read_scope is not r.fence.scope or r.authority!=r.fence.authority):
        raise AuthorityUnavailable('Artifact dispatch reader changed its actual primary READ descriptor')
    r.work._require_invocation(r.graph)
    return value


def require_artifact_host_dispatch_current_v3(r,meter):
    s=_state_v3(r);r.require_data_current_v3(meter)
    if time.monotonic()>=r.initial_monotonic_deadline:
        raise AuthorityUnavailable('Artifact dispatch exceeded its original Host READ monotonic deadline')
    return s


def _self_v3(r):
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    scope=r.read_scope
    current=r.graph._GraphCoordinator__self_identity_port.current_self_identity(namespace=r.namespace,
        authority_namespace=scope.authority_namespace,request_operation_id=scope.operation_id,permit=scope.permit)
    if(type(current)is not AuthorityCurrentSelfIdentityV1 or current.permit!=scope.permit
            or current.namespace!=r.namespace or current.installation_id!=r.selector.installation_id):
        raise AuthorityUnavailable('Artifact dispatch has no actual same-READ installed Self')
    return current


def _self_descriptor_v3(value):
    from .semantic_recovery_source_v3 import _self_descriptor
    return _self_descriptor(value)


def _observe_v3(r):
    s=_state_v3(r);port=r.graph._GraphCoordinator__content_fence_v2
    if r.db.in_transaction:raise AuthorityUnavailable('Artifact dispatch current observation must precede SQL')
    now=trusted_upper(port.read_ingress_clock(r.graph._GraphCoordinator__scene_clock_policy))
    if now>=min(r.operation.deadline_utc,s.eligibility_deadline)or time.monotonic()>=r.initial_monotonic_deadline:
        raise AuthorityUnavailable('Artifact dispatch original job/prepared/READ deadline expired')
    for fence in tuple(s.fences):r.graph._validate_read_fence_v3(fence)
    if s.self_descriptor is not None and _self_descriptor_v3(_self_v3(r))!=s.self_descriptor:
        raise AuthorityUnavailable('Artifact dispatch actual current Self/Owner descriptor changed')
    if s.owner_entry is not None:s.owner_entry.require_permission_v3(r)
    return now


def _retains_v3(profile,path):
    if not path:return True
    if profile=='frozen':
        from .artifact_frozen_metadata_v3 import artifact_frozen_metadata_path_v3
        return artifact_frozen_metadata_path_v3(path)
    if profile=='joint_graph':
        from .artifact_joint_source_groups_v3 import artifact_joint_metadata_path_v3
        return artifact_joint_metadata_path_v3(path)
    if profile=='task_scope_joint':return path[0]in {'schema','namespace','c02_operation_id'}
    if profile=='previous_verified':
        if path[0]=='selector':
            from .artifact_frozen_metadata_v3 import artifact_frozen_metadata_path_v3
            return artifact_frozen_metadata_path_v3(path)
        if path[0]=='source_head':return len(path)==1 or len(path)==2 and path[1]in {'key','revision'}
        return len(path)==1 and path[0]in {'schema','source_value_digest','producing_operation_id'}
    if profile in {'habit_policy_graph','habit_policy_producer'}:
        if profile.endswith('producer'):
            if path[0]in {'schema','namespace','identity'}:return True
            if path[0]!='writes':return False
            if len(path)<4 or path[2]!='value':return True
            path=path[3:]
        if path[0]in {'schema','core_original_ref','core_original_digest'}:return True
        return path[0]=='definition'and(len(path)<2 or path[1]in {'source_refs','policy_id','revision'})
    if profile in {'habit_interpretation_graph','habit_interpretation_producer'}:
        if profile.endswith('producer'):
            if path[0]in {'schema','namespace','identity'}:return True
            if path[0]!='writes':return False
            if len(path)<4 or path[2]!='value':return True
            path=path[3:]
        from .artifact_habit_source_groups_v3 import artifact_habit_interpretation_metadata_path_v3
        return artifact_habit_interpretation_metadata_path_v3(path)
    if profile=='joint_producer':
        if path[0]in {'schema','namespace','identity'}:return True
        if path[0]!='writes':return False
        if len(path)<4 or path[2]!='value':return True
        from .artifact_joint_source_groups_v3 import artifact_joint_metadata_path_v3
        return artifact_joint_metadata_path_v3(path[3:])
    if profile=='job':return path[0]in {'schema','selector','prepared_digest'}
    if profile=='producer':
        return path[0]in {'schema','namespace','identity','query_coverage','observed_originals'}or(path[0]=='provenance'and(
            len(path)==1 or path[1]=='artifact_model_control_reads_v1'))
    return True


class _DispatchColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,profile,*,table,column,key_columns,key,cell_id=None):
        self.state,self.profile=state,profile;self.capture=None;self.embedded=None
        self.top_fields=set();self.source_fields={};self.record_fields={};self.object_fields={}
        super().__init__(state.reader,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:_retains_v3(profile,path)
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,
            ensure_ascii=self.cell is None or self.cell.header[0]=='canonical-json.ascii.v1')
    def _actual(self):_state_v3(self.state.reader);return self
    def _emit(self,event):
        if self.profile=='frozen'and event.kind=='key':
            path=event.path
            self.object_fields.setdefault(path[:-1],set()).add(event.key)
            if len(path)==1:self.top_fields.add(event.key)
            elif len(path)==3 and path[0]=='sources':
                self.source_fields.setdefault(path[1],set()).add(event.key)
            elif len(path)==4 and path[0]=='sources'and path[2]=='record':
                self.record_fields.setdefault(path[1],set()).add(event.key)
        self.capture._emit_v3(event);self.value=self.capture.value
    def _reserve(self,extra=0):
        amount=_heap((self.nodes,self.scalar,self.fragment,self.value,
            None if self.capture is None else self.capture.__dict__,
            None if self.embedded is None else self.embedded.__dict__))+extra+131072
        if amount>self.reserved:self.operation.retain(amount-self.reserved);self.reserved=amount


class _DispatchRequestMetadataV3(_DispatchColumnV3):
    def __init__(self,state,kind,ref):
        from .d11_life_preparation_v1 import TABLE
        from ..authority_service.internal_life_model_source_read_v3 import _FilteredMetadataV3,_EmbeddedMetadataStreamV3
        super().__init__(state,'request',table=TABLE,column='payload_json',
            key_columns=('bot','persona','kind','original_ref'),key=(*state.reader.namespace.as_tuple,kind,ref))
        self.embedded_field='request_json';self.fields_seen=set()
        self.embedded=_FilteredMetadataV3(self,lambda path:not path or path[0]!='payload')
        self.parser=_EmbeddedMetadataStreamV3(self)
    def _emit(self,event):
        if event.kind=='key'and len(event.path)==1:self.fields_seen.add(event.key)
        if event.path==('request_json',)and event.kind=='scalar_end':self.embedded.finish()
        if event.path and event.path[0]=='request_json':return
        DispatchOriginalJSONReadV3._emit(self,event)


class _DispatchSignedMetadataV3:
    def __init__(self,state,kind,ref,profile):
        self.state,self.kind,self.ref,self.profile=state,kind,ref,profile
        self.header=self.column=self.value=None;self.complete=False
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE,SIGN_KIND
        r=self.state.reader;require_artifact_host_dispatch_current_v3(r,meter)
        current=meter.read_fixed_row(r.db,TABLE,('producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,self.kind,self.ref))
        if self.header is None:
            if current is None:raise AuthorityUnavailable('Actual signed Artifact dispatch Original is absent')
            self.header=tuple(current)
            self.column=(_DispatchRequestMetadataV3(self.state,self.kind,self.ref)if self.profile=='request'else
                _DispatchColumnV3(self.state,self.profile,table=TABLE,column='payload_json',
                    key_columns=('bot','persona','kind','original_ref'),key=(*r.namespace.as_tuple,self.kind,self.ref)))
            return False
        if current!=self.header:raise AuthorityUnavailable('Artifact signed locator changed during full metadata EOF')
        if not self.column.advance(meter):return False
        if self.column.sha256!=self.header[1]:raise AuthorityUnavailable('Artifact signed locator whole canonical EOF differs')
        r.context.issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,self.kind,self.ref,self.header[1])),self.header[2])
        self.value=self.column.require_v3(r)
        if self.profile=='frozen':
            from .artifact_frozen_metadata_v3 import validate_artifact_frozen_metadata_fields_v3
            validate_artifact_frozen_metadata_fields_v3(self.value,top_fields=self.column.top_fields,
                source_fields=self.column.source_fields,record_fields=self.column.record_fields,
                object_fields=self.column.object_fields)
        self.complete=True
        if self.profile=='request'and not self.column.embedded.complete:
            raise AuthorityUnavailable('Artifact signed embedded request did not reach full EOF')
        return True


class _DispatchStateV3:
    def __init__(self,r):
        self.reader=r;self.identity=_identity_v3(r)
        self.worker,self.model_grant=r.context.worker,r.context.client_grant
        self.eligibility_deadline=r.operation.deadline_utc
        self.fences=[r.fence];self.self_descriptor=None;self.owner_entry=None
        self.job_header=None;self.job_column=None;self.job_locator=None
        self.job_graph_header=self.job_graph_column=None;self.grant_task=None;self.grant=None
        self.prepared_task=self.frozen_task=self.request_task=None
        self.prepared=self.ids=self.phase_selector=None;self.phase_variant=None
        self.producers={};self.producer_tasks={};self.control=None;self.model_envelope=None
        self.business_versions=();self.control_versions=();self.body_control_versions=()
        self.managed={JOINT_TABLE:[],HABIT_TABLE:[]};self.managed_phase=JOINT_TABLE;self.managed_cursor=''
        self.metadata_complete=False;self.source_complete=False;self.joint_inventory=None;self.groups=[];self.group_index=0
        self.source_versions={};self.allowed_keys=set();self.allowed_originals=set();self.allowed_operations=set()
        self.original_body_metadata={};self.expected_life_parents={};self.life_parent_metadata={};self.signed_input_families={};self.actual_joint_plans={};self.expected_qualifications={};self.allowed_inputs={};self.input_digests={};self.signed_input_metadata={};self.r_headers={};self.allowed_quotes=set();self.allowed_jobs={r.selector.job_id};self.frame_facts=None
        self.phase='job';self.result=None;self.point_validation=None;self.validation_point=None;self.coverage=()
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.job_header,self.job_locator,self.prepared,self.ids,self.phase_selector,
            self.producers,self.control,self.managed,self.source_versions,self.allowed_keys,
            self.allowed_originals,self.allowed_operations,self.allowed_quotes,self.allowed_jobs))*3+8192
    def job_metadata_v3(self,meter):
        r=self.reader
        from ..model_broker.artifact_draft_v1 import WORK_KIND
        fields=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','phase','work_kind',
            'deadline_utc','budget_ref','lease_holder','lease_expires_utc','fence','cancel_epoch','result_ref')
        row=meter.read_fixed_row(r.db,'runtime_jobs',fields,'job_id=?',(r.selector.job_id,))
        if row is None:raise AuthorityUnavailable('Artifact dispatch actual once job is absent')
        if self.job_header is None:
            self.job_header=tuple(row)
            if(row[4:6]!=r.namespace.as_tuple or row[6]!='running'or row[7]!=WORK_KIND
                    or row[10]!=self.model_grant.subject or row[12]!=1 or row[13]!=0 or row[14]is not None):
                raise AuthorityUnavailable('Artifact dispatch job namespace/worker/fence/cancel/state differs')
            self.job_column=_DispatchColumnV3(self,'job',table='runtime_jobs',column='continuation_json',
                key_columns=('job_id',),key=(r.selector.job_id,))
            return False
        if tuple(row)!=self.job_header:raise AuthorityUnavailable('Artifact dispatch once job changed during metadata EOF')
        if not self.job_column.advance(meter):return False
        raw=self.job_column.require_v3(r)
        if set(raw)!={'schema','selector','prepared_digest'}:
            raise AuthorityUnavailable('Artifact dispatch job has another exact continuation fieldset')
        from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,
            artifact_draft_from_wire_v1,artifact_draft_from_wire_v2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2)
        self.phase_variant=raw['schema']=='d11.artifact-draft-phase-model-job.v2'
        if raw['schema']not in {'d11.artifact-draft-phase-model-job.v2','d11.artifact-draft-model-job.v1'}:
            raise AuthorityUnavailable('Artifact dispatch job has another model continuation schema')
        selector=(artifact_draft_from_wire_v2(raw['selector'],ArtifactDraftPhaseSelectorV2)if self.phase_variant else
            artifact_draft_from_wire_v1(raw['selector'],ArtifactDraftTaskSelectorV1))
        ns=selector.task.namespace if self.phase_variant else selector.namespace
        self.ids=(artifact_draft_model_ids_v2 if self.phase_variant else artifact_draft_model_ids_v1)(selector)
        if ns!=r.namespace or self.ids['job']!=r.selector.job_id:
            raise AuthorityUnavailable('Artifact dispatch selector crossed actual model job/namespace')
        self.phase_selector=selector;self.job_locator=raw
        prefix='c4_phase_'if self.phase_variant else'c4_'
        self.prepared_task=_DispatchSignedMetadataV3(self,prefix+'prepared',self.ids['job'],'prepared')
        self.phase='prepared';return True
    def prepared_metadata_v3(self,meter):
        if not self.prepared_task.advance(meter):return False
        r=self.reader
        from .d11_artifact_draft_model_v1 import (ArtifactDraftModelPreparedV1,ArtifactDraftModelPreparedV2,
            artifact_draft_model_from_wire_v1,artifact_draft_model_from_wire_v2)
        p=(artifact_draft_model_from_wire_v2(self.prepared_task.value,ArtifactDraftModelPreparedV2)if self.phase_variant else
            artifact_draft_model_from_wire_v1(self.prepared_task.value,ArtifactDraftModelPreparedV1))
        policy=r.bundle.installation_policy
        if(p.selector!=self.phase_selector or p.job_id!=r.selector.job_id or p.digest!=self.job_locator['prepared_digest']
                or p.operation_id!=self.prepared_task.header[0]or p.worker_subject!=self.model_grant.subject
                or p.installation_id!=policy.installation_id or p.manifest_digest!=policy.manifest_digest
                or p.parent_budget_lease_ref!=self.job_header[9]):
            raise AuthorityUnavailable('Artifact dispatch actual signed prepared/job/installation binding changed')
        self.prepared=p
        if self.phase_variant and p.selector.prev_phase_original_ref is not None:
            self.expected_life_parents['c4_phase_verified',p.selector.prev_phase_original_ref]=p.selector.prev_phase_original_digest
        times=(p.deadline_utc,self.job_header[8],self.job_header[11])
        if any(value is None for value in times):raise AuthorityUnavailable('Artifact acquired job has no actual original lease deadline')
        self.eligibility_deadline=min(self.eligibility_deadline,*(datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()for value in times))
        prefix='c4_phase_'if self.phase_variant else'c4_'
        self.frozen_task=_DispatchSignedMetadataV3(self,prefix+'frozen',p.frozen_ref,'frozen')
        self.request_task=_DispatchSignedMetadataV3(self,prefix+'request',self.ids['request'],'request')
        self.allowed_originals.update(((prefix+'prepared',p.job_id),(prefix+'frozen',p.frozen_ref),
            (prefix+'request',self.ids['request']),(prefix+'call',p.call_id)))
        self.allowed_operations.update((p.operation_id,p.acquire_operation_id))
        self.allowed_quotes.add((p.quote_id,1))
        self.phase='frozen';return True


def prepare_current_artifact_host_dispatch_read_v1(graph,runtime,selector):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    graph._admin(runtime.bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    port=graph._GraphCoordinator__content_fence_v2
    if(type(runtime)is not InstalledArtifactDraftModelRuntimeV1 or runtime.graph is not graph
            or runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or assembly is None or type(runtime.bundle)is not AdminInstallationBundle
            or runtime.bundle is not assembly.admin_bundle or type(port)is not V2FencePort
            or type(selector)is not ArtifactHostDispatchReadSelectorV1):
        raise AuthorityUnavailable('Artifact dispatch requires the actual installed Host model runtime')
    policy=runtime.bundle.installation_policy
    if(selector.namespace!=policy.namespace or selector.installation_id!=policy.installation_id
            or port.installation_grant.installation_id!=policy.installation_id
            or port.installation_grant.manifest_digest!=policy.manifest_digest
            or runtime.client_grant.installation_id!=policy.installation_id
            or runtime.client_grant.manifest_digest!=policy.manifest_digest
            or runtime.client_grant.administrator_holder!=policy.administrator_holder):
        raise AuthorityUnavailable('Artifact dispatch READ/model installation identity differs')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id='artifact-dispatch-read:'+secrets.token_hex(16)
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            # These existing metadata ACL labels convey no process or model grant.
            authority=AuthorityContext('artifact-dispatch-metadata','d11','artifact-dispatch-metadata',
                selector.namespace,('activity',),'consolidation',('owner',),'artifact-dispatch-read.v1',
                graph._v2_graph_stamp(selector.namespace)[0].requirements.activation_generation)
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id+':metadata')
            r=BackgroundReadWorkV3(BACKGROUND_ISSUER,graph,runtime.bootstrap,runtime.bundle,operation,
                kind=_KIND,dedupe_key=None,context=runtime)
            r.selector,r.fence,r.read_scope,r.authority=selector,fence,fence.scope,authority
            r.runtime=graph._GraphCoordinator__domain_production_runtime_v1
            r.lease=r.owner_binding=r.owner_guard=r.session_proof=None
            r.operation_id=operation_id;r.request_digest=canonical_digest(selector);r.read_finished=False
            r.initial_monotonic_deadline=time.monotonic()+operation.deadline_utc-now
            r.initial_now_utc=r.now=now;r.phase='artifact_dispatch_metadata'
            work=create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
            r.work=work;state=_DispatchStateV3(r);_STATES[r]=state
            operation.register_retained_state_v3(state)
            def unwrap(value):return value.require_result_v3(work)
            def failed(error):raise error
            work.map_terminal_v3('issuer',unwrap,failed)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


class _DispatchProducerMetadataV3:
    def __init__(self,state,operation_id,kind):
        self.state,self.operation_id,self.kind=state,operation_id,kind
        self.header=None;self.columns=[];self.index=0;self.complete=False
        self.original=self.receipt=self.read_versions=None
    def advance(self,meter):
        r=self.state.reader;require_artifact_host_dispatch_current_v3(r,meter)
        table='graph_domain_production_originals_v1';key=(*r.namespace.as_tuple,self.operation_id)
        names=('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest')
        row=meter.read_fixed_row(r.db,table,names,'bot=? AND persona=? AND operation_id=?',key)
        if self.header is None:
            if row is None or tuple(row[:2])!=('d11',self.kind):
                raise AuthorityUnavailable('Artifact dispatch has no actual named C4 producer Original')
            self.header=tuple(row)
            self.columns=[_DispatchColumnV3(self.state,profile,table=table,column=column,
                key_columns=('bot','persona','operation_id'),key=key)
                for profile,column in(('producer','original_payload_json'),('versions','read_versions_json'),('receipt','receipt_json'))]
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Artifact dispatch producer header changed during EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        original,reads,receipt=(c.require_v3(r)for c in self.columns)
        from .domain_production_originals_v1 import _receipt
        actual=_receipt(receipt)
        if(self.columns[0].sha256!=self.header[3]or actual.status!='committed'
                or actual.operation_id!=self.operation_id or actual.operation_digest!=self.header[4]
                or canonical_digest(actual)!=self.header[5]
                or original.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or original.get('identity',{}).get('operation_id')!=self.operation_id
                or original.get('schema')!='d11.current-'+self.kind+'.v1'):
            raise AuthorityUnavailable('Artifact dispatch lacks complete actual producer/receipt/namespace EOF')
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads)
        if actual.read_versions!=versions or len(versions)>1024:
            raise AuthorityUnavailable('Artifact dispatch producer readset differs from the actual W01 receipt')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        if bundle!=(actual.operation_digest,actual.activity_id,actual.effect_id,actual.commit_seq):
            raise AuthorityUnavailable('Artifact dispatch producer has no actual positive W01 bundle')
        self.original,self.receipt,self.read_versions=original,actual,versions;self.complete=True
        return True


def _frozen_metadata_v3(s,meter):
    if not s.frozen_task.advance(meter):return False
    if s.frozen_task.header[1]!=s.prepared.frozen_digest or s.frozen_task.header[0]!=s.prepared.operation_id:
        raise AuthorityUnavailable('Artifact dispatch frozen Original differs from actual signed prepared')
    frozen=s.frozen_task.value
    if frozen['current_self_ref']!=s.prepared.actor_ref:
        raise AuthorityUnavailable('Artifact frozen current Self differs from actual prepared actor')
    s.eligibility_deadline=min(s.eligibility_deadline,frozen['deadline_utc'])
    s.phase='request';return True


def _request_metadata_v3(s,meter):
    if not s.request_task.advance(meter):return False
    r=s.reader;raw=s.request_task.value;column=s.request_task.column
    expected={'prepared_digest','request_digest','schema'}|({'actual_count_proof'}if s.phase_variant else set())
    if(set(raw)!=expected or column.fields_seen!=expected|{'request_json'}
            or raw['prepared_digest']!=s.prepared.digest or s.request_task.header[0]!=s.prepared.acquire_operation_id):
        raise AuthorityUnavailable('Artifact dispatch request changed actual exact prepared/acquire Original')
    from .c02_bundle_codec import _decode
    from ..runtime_contracts import CommandEnvelope
    envelope=_decode(column.embedded.value['envelope'],CommandEnvelope)
    if(envelope.authority.namespace!=r.namespace or envelope.authority.actor!=s.model_grant.subject
            or envelope.authority.worker_fence!=s.job_header[12]
            or envelope.parent_budget_lease_ref!=s.prepared.parent_budget_lease_ref
            or column.embedded.value['call_id']!=s.prepared.call_id
            or tuple(envelope.authority.audience)!=s.prepared.audiences):
        raise AuthorityUnavailable('Artifact dispatch saved model request changed actual acquired worker/Root/audience')
    s.model_envelope=envelope;s.business_versions=envelope.version_guard.read_versions
    s.eligibility_deadline=min(s.eligibility_deadline,envelope.deadline_utc)
    kinds=('prepare_artifact_draft_model_v2','acquire_artifact_draft_model_v2')if s.phase_variant else(
        'prepare_artifact_draft_model','acquire_artifact_draft_model')
    for op,kind in zip((s.prepared.operation_id,s.prepared.acquire_operation_id),kinds,strict=True):
        s.producer_tasks[op]=_DispatchProducerMetadataV3(s,op,kind)
    s.phase='producers';return True


def _producer_metadata_v3(s,meter):
    for operation,task in s.producer_tasks.items():
        if not task.complete:
            if task.advance(meter):s.producers[operation]=task
            return False
    if s.phase_variant:
        from .artifact_model_control_contract_v1 import (ARTIFACT_MODEL_CONTROL_PROVENANCE_V1,
            artifact_model_control_reads_from_wire_v1)
        acquired=s.producers[s.prepared.acquire_operation_id]
        prepared=s.producers[s.prepared.operation_id]
        control=artifact_model_control_reads_from_wire_v1(acquired.original['provenance'][ARTIFACT_MODEL_CONTROL_PROVENANCE_V1])
        earlier=artifact_model_control_reads_from_wire_v1(prepared.original['provenance'][ARTIFACT_MODEL_CONTROL_PROVENANCE_V1])
        if(control.habit_classification.phase_selector!=s.phase_selector
                or earlier.habit_classification.phase_selector!=s.phase_selector
                or control.operation_kind!='acquire_artifact_draft_model_v2'
                or earlier.operation_kind!='prepare_artifact_draft_model_v2'):
            raise AuthorityUnavailable('Artifact dispatch B/C Original carrier changed the actual phase/operation')
        # Only the actual acquire CAS may account for its own written head successor.
        writes={v.key:v for v in acquired.receipt.write_versions}
        allowed=set()
        from .d11_types import runtime_job_key
        allowed.add(runtime_job_key(*s.reader.namespace.as_tuple,s.prepared.activity_id,s.prepared.job_id))
        if not set(writes)<=allowed:raise AuthorityUnavailable('Artifact acquire producer wrote outside its actual once job')
        def after(values):return tuple(writes.get(v.key,v)for v in values)
        expected=after(control.business_read_versions)
        if expected!=s.business_versions:
            raise AuthorityUnavailable('Artifact dispatch model request is not its actual business-only acquire successor')
        s.control=control;s.control_versions=after(control.control_read_versions)
        s.body_control_versions=after(control.control_body_versions)
        s.allowed_operations.update((control.habit_classification.selection_operation_id,
            control.habit_classification.prepared_candidates_operation_id))
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    acquired=s.producers[s.prepared.acquire_operation_id]
    s.coverage=tuple(decode_typed_production_value_v1(v,ProductionQueryCoverageV1)
        for v in acquired.original['query_coverage'])
    for page in s.coverage:
        if not page.complete or page.continuation_ref is not None or page.epoch.namespace!=s.reader.namespace:
            raise AuthorityUnavailable('Artifact Host original query inventory lacks actual complete namespace coverage')
    s.allowed_keys.update(v.key for v in(*s.business_versions,*s.body_control_versions))
    roots=tuple(sorted(v.key.token for v in s.business_versions if v.key.type_name=='memory.source'and v.revision>0))
    if not roots or len(roots)>32:raise AuthorityUnavailable('Artifact dispatch needs its actual finite B Source family')
    s.group_specs=[('business',roots,s.model_envelope.authority.purpose,s.prepared.audiences)]
    if s.control is not None:
        for name,refs,purposes,audiences in s.control.control_source_purpose_groups:
            for purpose in purposes:s.group_specs.append((name,refs,purpose,audiences))
    task=s.phase_selector.task if s.phase_variant else s.phase_selector
    from .joint_node_execution_v1 import joint_executor_index_ref_v1
    for kind,parts in(('artifact_task',(task.c02_operation_id,task.root_registration_ref)),
            ('artifact',(task.c02_operation_id,task.root_registration_ref,s.phase_selector.identity_digest if s.phase_variant else 'legacy'))):
        ref=joint_executor_index_ref_v1(s.reader.namespace,kind,parts)
        s.allowed_inputs[('graph_d10_production_inputs_v1',ref)]=frozenset({'joint_executor_index_v1'})
    s.head_metadata=_DispatchReadSetMetadataV3(s);s.phase='readset_metadata';return True


def _managed_metadata_v3(s,meter):
    r=s.reader;table=s.managed_phase;columns=metadata_columns_v1(table)
    cursor='selector_digest'if table==JOINT_TABLE else'selector_commitment'
    row=meter.read_fixed_row(r.db,table,columns,
        'bot=? AND persona=? AND '+cursor+'>? ORDER BY '+cursor,(*r.namespace.as_tuple,s.managed_cursor))
    if row is not None:
        ns,_=validate_managed_metadata_row_v1(table,columns,row,issuer=r.context.issuer)
        if ns!=r.namespace:raise AuthorityUnavailable('Artifact dispatch managed metadata crossed namespace')
        r.operation.retain(_heap(tuple(row))+512)
        s.managed[table].append(tuple(row));s.managed_cursor=row[2];return False
    if table==JOINT_TABLE:s.managed_phase=HABIT_TABLE;s.managed_cursor='';return False
    s.metadata_complete=True;s.joint_metadata=_DispatchJointMetadataV3(s);s.phase='joint_metadata';return True


class _DispatchSourcesV3(SourceCorrectionContextReadV3):
    """The existing ALL-parent mechanics, owned by one actual purpose READ."""
    def __init__(self,state,fence,spec):
        r=state.reader;_state_v3(r)
        self.owner,self.spec=r,spec;self.db,self.namespace,self.storage_lease=r.db,r.namespace,r.operation
        self.read_scope,self.graph_stamp=fence.scope,r.graph_stamp;self.selection_digest=r.selection_digest
        name,roots,purpose,audiences=spec
        if not roots or len(roots)>32:raise AuthorityUnavailable('Artifact purpose group has no exact finite original roots')
        self.saved_roots=tuple(roots);self.purpose,self.audiences=purpose,tuple(audiences)
        self.source_ref=roots[0];self.source_id=AtomKey.from_token(self.source_ref).owner.subject
        self.complete=False;self.context=self.qualification=None;self.readset=()
        self.phase,self.epochs='epochs',None;self.heads,self.sources,self.accesses,self.families={},{},{},{}
        self.targets=[];self.jobs,self.active,self.done,self.family_keys=[],set(),set(),set()
        self.family_roots,self.family_after=(),None;self.cursor,self.pending_target='',None
        self.scan_count,self.scan_complete=0,False
        self.scan_root=__import__('hashlib').sha256(b'd12.source-correction-interpretation-scan.v3').hexdigest()
        self._readset_pending=[];self.cell,self.parser,self.cell_kind,self.cell_token=None,None,None,None
        self.fragment,self.fragment_offset=b'',0;self.final_tokens,self.final_index=(),0;self._reserved=0
        _SCOPES[self]=(state,fence,spec,r.operation,r.work,r.graph_stamp);self._reserve(32768)
    def _step(self,meter):
        s=require_artifact_host_dispatch_current_v3(self.owner,meter)
        saved=_SCOPES.get(self)
        if(saved is None or saved!=(s,saved[1],self.spec,self.owner.operation,self.owner.work,self.graph_stamp)
                or saved[1].scope is not self.read_scope or saved[1]not in s.fences):
            raise AuthorityUnavailable('Artifact ALL Source group lost its actual separate purpose READ')
        if self.cell is None and self.phase=='epochs':
            self.epochs=self._epochs(meter);self._family(self.saved_roots,'artifact-dispatch');return
        if self.cell is None and self.phase=='scan':
            self.scan_complete=True;self.final_tokens=tuple(sorted(self.heads));self.phase='recheck';return
        if self.cell is None and self.phase=='result':
            if self._epochs(meter)!=self.epochs:raise AuthorityUnavailable('Artifact Source rights changed before complete ALL EOF')
            self.readset=tuple(self._readset_pending);self.complete=True;self._reserve();return
        super()._step(meter)


def _job_graph_metadata_v3(s,meter):
    from .d11_types import runtime_job_key,RuntimeJobValue
    from dataclasses import fields
    r=s.reader;key=runtime_job_key(*r.namespace.as_tuple,s.job_header[2],r.selector.job_id)
    row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
        'token=? AND bot=? AND persona=?',(key.token,*r.namespace.as_tuple))
    if s.job_graph_header is None:
        if row is None or row[1]!=1 or row[2]is None:
            raise AuthorityUnavailable('Artifact dispatch lacks its actual current Graph job mirror')
        s.job_graph_header=tuple(row)
        s.job_graph_column=_DispatchColumnV3(s,'job_graph',table='graph_atoms',column='value',
            key_columns=('token','bot','persona'),key=(key.token,*r.namespace.as_tuple),cell_id=row[2])
        return False
    if tuple(row or())!=s.job_graph_header:raise AuthorityUnavailable('Artifact Graph job changed during complete metadata EOF')
    if not s.job_graph_column.advance(meter):return False
    raw=s.job_graph_column.require_v3(r)
    if set(raw)!={f.name for f in fields(RuntimeJobValue)}:
        raise AuthorityUnavailable('Artifact Graph job has another actual fixed fieldset')
    job=RuntimeJobValue(**raw)
    for name,index in(('job_id',0),('operation_id',1),('activity_id',2),('effect_id',3),('bot_id',4),
            ('persona_id',5),('phase',6),('work_kind',7),('deadline_utc',8),('parent_budget_lease_ref',9),
            ('lease_holder',10),('lease_expires_utc',11),('fence',12),('cancel_epoch',13),('result_ref',14)):
        if getattr(job,name)!=s.job_header[index]:
            raise AuthorityUnavailable('Artifact SQL/Graph job identity/current worker mirror differs')
    if job.continuation_digest!=s.job_column.sha256:
        raise AuthorityUnavailable('Artifact actual SQL continuation lost its immutable Graph digest')
    receipt=s.producers[s.prepared.acquire_operation_id].receipt
    if GraphVersion(key,s.job_graph_header[0])not in receipt.write_versions:
        raise AuthorityUnavailable('Artifact current job mirror is not its exact acquire CAS member')
    s.grant_task=_DispatchBudgetMetadataV3(s,s.prepared.parent_budget_lease_ref)
    s.phase='budget';return True


class _DispatchBudgetMetadataV3:
    def __init__(self,state,lease):
        self.state,self.lease=state,lease;self.header=self.column=self.grant=None;self.complete=False
    def advance(self,meter):
        r=self.state.reader;require_artifact_host_dispatch_current_v3(r,meter)
        row=meter.read_fixed_row(r.db,'runtime_budget_grants',('lease_id','version','signature','status'),
            'lease_id=? ORDER BY version DESC',(self.lease,))
        if row is None or row[3]!='active':raise AuthorityUnavailable('Artifact original model Root grant is no longer active')
        if self.header is None:
            self.header=tuple(row);self.column=_DispatchColumnV3(self.state,'budget',table='runtime_budget_grants',
                column='grant_json',key_columns=('lease_id','version'),key=(self.lease,row[1]));return False
        if tuple(row)!=self.header:raise AuthorityUnavailable('Artifact actual signed Root grant changed during EOF')
        if not self.column.advance(meter):return False
        raw=self.column.require_v3(r)
        r.context.issuer._signer.verify('budget-grant.v1',canonical_serialize(raw),self.header[2])
        from .issuers import BudgetLeaseGrant
        from ..model_broker.artifact_draft_v1 import WORK_KIND
        actual=BudgetLeaseGrant(**{**raw,'allowed_work_kinds':tuple(raw['allowed_work_kinds'])})
        if((actual.lease_id,actual.version)!=(self.lease,self.header[1])
                or(actual.bot_id,actual.persona_id)!=r.namespace.as_tuple or WORK_KIND not in actual.allowed_work_kinds):
            raise AuthorityUnavailable('Artifact signed Root grant changed its exact model namespace/allowance')
        lease=meter.read_fixed_row(r.db,'runtime_budget_leases',('bot_id','persona_id','currency','state'),
            'lease_id=?',(self.lease,))
        if lease!=(*r.namespace.as_tuple,actual.currency,'active'):
            raise AuthorityUnavailable('Artifact current original budget lease namespace/currency/state differs')
        self.grant=actual;self.complete=True;return True


def _budget_metadata_v3(s,meter):
    if not s.grant_task.advance(meter):return False
    s.grant=s.grant_task.grant;s.eligibility_deadline=min(s.eligibility_deadline,s.grant.valid_until_utc)
    reserved=meter.read_fixed_row(s.reader.db,'runtime_budget_reservations',('digest','state'),
        'lease_id=? AND operation_id=?',(s.prepared.parent_budget_lease_ref,s.prepared.operation_id))
    if reserved is None or reserved[0]!=s.prepared.reservation_digest:
        raise AuthorityUnavailable('Artifact dispatch crossed the actual original reservation/Root identity')
    s.reservation_header=tuple(reserved);s.phase='managed';return True


def require_artifact_host_dispatch_owner_identity_v3(r):
    s=_state_v3(r)
    if(not s.metadata_complete or s.prepared is None or s.model_envelope is None
            or s.phase not in {'owner','sources','algorithm','validate','complete'}
            or r.fence is None or r.read_scope is not r.fence.scope or r.authority!=r.fence.authority
            or r.read_scope.operation_id!=r.operation_id+':business'
            or s.self_descriptor is None or s.prepared.job_id!=r.selector.job_id):
        raise AuthorityUnavailable('Artifact Owner17 requires actual signed dispatch metadata and its real content READ')
    return s


def artifact_host_dispatch_owner_cause_v3(r):
    s=require_artifact_host_dispatch_owner_identity_v3(r)
    return(r.selector,s.job_header,s.prepared.digest,s.prepared_task.header,s.frozen_task.header,s.request_task.header,
        tuple((op,task.header)for op,task in sorted(s.producers.items())),s.eligibility_deadline,
        tuple(s.group_specs),r.read_scope.permit)


def _prepare_owner_scopes_v3(s):
    from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from ..graph_types import owner_grant_key
    r=s.reader;_observe_v3(r)
    first=_self_v3(r);s.self_descriptor=_self_descriptor_v3(first)
    r.graph._finish_read_fence_v3(r.fence);s.fences.clear();r.fence=r.read_scope=None
    name,roots,purpose,audiences=s.group_specs[0]
    r.authority=replace(r.authority,actor=first.self_entity_ref,purpose=purpose,audience=tuple(audiences))
    r.fence=r.graph._begin_read_fence_v3(r.authority,operation_id=r.operation_id+':business')
    r.read_scope=r.fence.scope;s.fences.append(r.fence)
    if(r.fence.metadata,r.fence.epoch)!=r.graph_stamp or _self_descriptor_v3(_self_v3(r))!=s.self_descriptor:
        raise AuthorityUnavailable('Artifact original dispatch stamp/Self changed across its real READ scopes')
    r.current_self=_self_v3(r)
    if r.current_self.self_entity_ref!=s.prepared.actor_ref:
        raise AuthorityUnavailable('Artifact dispatch actual current Self differs from original prepared')
    s.owner_entry=prepare_current_host_semantic_background_owner_read_entry_v3(r)
    s.owner_entry.require_permission_v3(r)
    with r.store._lock:
        r.db.execute('BEGIN')
        try:r.owner=r.owner_binding=s.owner_entry.require_for_v3(r)
        finally:r.db.rollback()
    guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,r.owner.grant_revision,
        r.owner.grant_digest.removeprefix('sha256:'),r.owner.authorization_head.removeprefix('sha256:'))
    if guard!=s.prepared.owner_guard:
        raise AuthorityUnavailable('Artifact dispatch current Owner EOF differs from original prepared guard')
    r.owner_guard=s.owner_entry.current_owner_guard
    for index,spec in enumerate(s.group_specs):
        name,roots,purpose,audiences=spec
        if purpose not in r.owner.purposes or not set(audiences)<=set(r.owner.audiences):
            raise AuthorityUnavailable('Artifact B/C purpose groups exceed actual current Owner intersection')
        fence=r.fence if index==0 else r.graph._begin_read_fence_v3(
            replace(r.authority,purpose=purpose,audience=tuple(audiences)),operation_id=r.operation_id+':control:'+str(index))
        if index:s.fences.append(fence)
        if(fence.metadata,fence.epoch)!=r.graph_stamp:
            raise AuthorityUnavailable('Artifact independent control READ changed the original shared Graph stamp')
        s.groups.append(_DispatchSourcesV3(s,fence,spec))
    s.phase='sources'


def _sources_metadata_v3(s,meter):
    r=s.reader
    if s.group_index<len(s.groups):
        group=s.groups[s.group_index]
        group._step(meter)
        if group.complete:
            if group.epochs!=(s.model_envelope.version_guard.access_epoch,s.model_envelope.version_guard.delete_epoch):
                raise AuthorityUnavailable('Artifact actual B/C ALL rights differ from original acquired request')
            for version in group.readset:
                previous=s.source_versions.get(version.key)
                if previous is not None and previous!=version.revision:
                    raise AuthorityUnavailable('Artifact independently qualified B/C Source revisions conflict')
                s.source_versions[version.key]=version.revision
            s.group_index+=1
        return False
    expected={v.key:v.revision for v in(*s.business_versions,*s.control_versions)
        if v.key.type_name=='memory.source'or v.key in s.source_versions}
    for key,revision in expected.items():
        if s.source_versions.get(key)!=revision:
            raise AuthorityUnavailable('Artifact current Source ALL differs from the actual original B/C Source version')
    actual_r={v.key:v.revision for v in(*s.business_versions,*s.control_versions)}
    if any(actual_r.get(key)!=revision for key,revision in s.source_versions.items()):
        raise AuthorityUnavailable('Artifact complete ALL Source/access/correction closure escapes actual signed B/C R')
    business={v.key.token:v.revision for v in s.business_versions}
    for source in s.frozen_task.value['sources']:
        ref=source['ref'];version=source['revision']
        matches=tuple(group.sources[ref]for group in s.groups if ref in group.sources)
        if(business.get(ref)!=version or s.source_versions.get(AtomKey.from_token(ref))!=version
                or not matches or any(digest!=source['value_digest']for _,digest in matches)):
            raise AuthorityUnavailable('Artifact Host frozen Source bytes/revision lack their actual independently qualified B')
    s.source_complete=True;s.phase='algorithm';r.phase='artifact_dispatch_algorithm';return True


def _bound_state_v3(db):
    from .domain_background_read_v3 import _active_v3
    r=_active_v3(db)
    return None if r is None or r.kind!=_KIND else _state_v3(r)


def require_artifact_host_dispatch_body_v3(r,table,key):
    s=_state_v3(r)
    if not s.source_complete or s.phase not in {'algorithm','validate'}or s.owner_entry is None:
        raise AuthorityUnavailable('Artifact dispatch Body cannot precede its real Owner17 and independent B/C ALL')
    with runtime_storage_quantum_v3(r.db)as meter:
        require_artifact_host_dispatch_current_v3(r,meter)
        s.owner_entry.require_for_v3(r)
        for source_key,revision in s.source_versions.items():
            row=meter.read_fixed_row(r.db,'graph_atoms',('revision',),'token=? AND bot=? AND persona=?',
                (source_key.token,*r.namespace.as_tuple))
            if(0 if row is None else row[0])!=revision:
                raise AuthorityUnavailable('Artifact current complete Source/ancestor rights changed before Body')
    if table=='graph_domain_production_originals_v1':
        require_artifact_host_original_body_metadata_v3(r,key[2])
    if table=='graph_d11_life_originals_v1'and tuple(key[2:])in s.expected_life_parents:
        require_artifact_host_life_parent_metadata_v3(r,*key[2:])
    if table in _SIGNED_METADATA_TABLES_V3:
        require_artifact_host_signed_input_body_metadata_v3(r,table,key[2])
    return s


def require_artifact_host_dispatch_request_v3(r,request):
    s=require_artifact_host_dispatch_body_v3(r,request[0],request[3])
    table,columns,key_columns,key=request
    from .domain_background_read_v3 import _POINT_KEYS,_D07_POINT_COLUMNS
    if(table not in _POINT_KEYS or tuple(key_columns)!=_POINT_KEYS[table]or len(key)!=len(key_columns)):
        raise AuthorityUnavailable('Artifact dispatch requested an unregistered exact SQL shape')
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if atom not in s.allowed_keys or NamespaceId.from_key(atom)!=r.namespace:
            raise AuthorityUnavailable('Artifact dispatch Graph Body is outside its actual signed B/C')
        if table=='graph_history':
            versions={(v.key.token,v.revision)for v in(*s.business_versions,*s.body_control_versions)}
            if tuple(key)not in versions:raise AuthorityUnavailable('Artifact dispatch history is outside its exact signed Body versions')
        if not set(columns)<={'token','revision','value','valid','type_name','event_id','event_bot','event_persona','event_session','dependencies'}:
            raise AuthorityUnavailable('Artifact dispatch Graph columns exceed the actual fixed reader')
        return
    if table=='runtime_jobs':
        if key!=(r.selector.job_id,)or not set(columns)<=_D07_POINT_COLUMNS[table]|{'job_id'}:
            raise AuthorityUnavailable('Artifact dispatch job Body crossed its actual once identity')
        return
    if table=='runtime_resource_quotes':
        if tuple(key)not in s.allowed_quotes or not set(columns)<={'quote_id','version','quote_json','signature'}:
            raise AuthorityUnavailable('Artifact dispatch quote crossed its actual model/selected price')
        return
    if table=='graph_d11_life_originals_v1':
        if tuple(key[:2])!=r.namespace.as_tuple or tuple(key[2:])not in s.allowed_originals:
            raise AuthorityUnavailable('Artifact dispatch signed Original lacks its exact actual parent locator')
        if not set(columns)<={'bot','persona','kind','original_ref','producing_operation_id','payload_json','payload_digest','signature'}:
            raise AuthorityUnavailable('Artifact dispatch signed Original columns differ')
        return
    if table=='graph_owner_goal_cancellation_projections_v1':
        from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
        task=s.phase_selector.task if s.phase_variant else s.phase_selector
        goal=artifact_goal_plan_keys_v1(r.namespace,c02_operation_id=task.c02_operation_id,root_registration_ref=task.root_registration_ref)[0]
        if tuple(key)!=(*r.namespace.as_tuple,goal.token,task.root_registration_ref)or tuple(columns)!=('operation_id',):
            raise AuthorityUnavailable('Artifact Goal barrier is not its exact original task/root metadata')
        return
    if table in _SIGNED_METADATA_TABLES_V3:
        if tuple(key[:2])!=r.namespace.as_tuple or(table,key[2])not in s.allowed_inputs:
            raise AuthorityUnavailable('Artifact signed input has no exact actual parent locator')
        allowed={'kind','producing_operation_id','payload_json','payload_digest','signature','plan_proposal_ref','participant_ref','terms_digest'}
        if not set(columns)<=allowed|set(key_columns):
            raise AuthorityUnavailable('Artifact signed input exceeds its actual fixed SQL columns')
        return
    if table in {'graph_domain_production_originals_v1','graph_bundle_operations'}:
        if tuple(key[:2])!=r.namespace.as_tuple or key[2]not in s.allowed_operations:
            raise AuthorityUnavailable('Artifact dispatch producer is outside its actual signed Original closure')
        allowed=({'domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json',
            'bundle_digest','receipt_json','receipt_digest'}if table=='graph_domain_production_originals_v1'else
            {'digest','activity_id','effect_id','commit_seq','receipt_json'})
        if not set(columns)<=allowed|set(key_columns):
            raise AuthorityUnavailable('Artifact dispatch producer columns exceed their actual fixed shape')
        return
    raise AuthorityUnavailable('Artifact dispatch has no consumer for that exact SQL family')


def read_bound_artifact_host_dispatch_job_v3(db,job_id):
    s=_bound_state_v3(db)
    if s is None:return False,None
    r=s.reader
    from .domain_background_read_v3 import background_point_v3
    from .jobs import _job_from_row
    columns=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref','phase','work_kind',
        'continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref','operator_versions_json',
        'lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref')
    request=('runtime_jobs',columns,('job_id',),(job_id,));require_artifact_host_dispatch_request_v3(r,request)
    row=background_point_v3(db,table=request[0],columns=columns,key_columns=request[2],key=request[3],legacy_reader=lambda:None)
    job=_job_from_row(row)
    from .d11_types import job_graph_write
    expected=job_graph_write(job)
    from .domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3
    head=background_graph_head_v3(db,r.namespace,expected.key)
    if(head is None or head[2]!=1 or canonical_digest(background_json_loads_v3(head[1]))!=canonical_digest(expected.value)
            or job.job_id!=r.selector.job_id or job.phase!='running'or job.fence!=1 or job.cancel_epoch
            or job.lease_holder!=r.context.client_grant.subject):
        raise AuthorityUnavailable('Artifact dispatch real job lost its exact current SQL/Graph/acquired worker')
    return True,job


def read_bound_artifact_host_dispatch_quote_v3(db,issuer,quote_id,version):
    s=_bound_state_v3(db)
    if s is None:return False,None
    r=s.reader
    if issuer is not r.context.issuer.resource_issuer:
        raise AuthorityUnavailable('Artifact dispatch quote issuer crossed its actual installed resource signer')
    from .domain_background_read_v3 import background_point_v3,background_verify_signature_v3
    request=('runtime_resource_quotes',('quote_json','signature'),('quote_id','version'),(quote_id,version))
    require_artifact_host_dispatch_request_v3(r,request)
    row=background_point_v3(db,table=request[0],columns=request[1],key_columns=request[2],key=request[3],legacy_reader=lambda:None)
    if row is None:raise AuthorityUnavailable('Artifact dispatch actual signed quote is absent')
    background_verify_signature_v3(issuer._signer,'resource-quote.v1',row[0],row[1])
    from .issuers import _decode_quote
    quote=_decode_quote(row[0])
    if(quote.quote_id,quote.version)!=(quote_id,version):raise AuthorityUnavailable('Artifact dispatch quote identity changed')
    if quote_id==s.prepared.quote_id and(quote.parent_budget_lease_ref!=s.prepared.parent_budget_lease_ref
            or canonical_digest(quote)!=s.prepared.quote_digest):
        raise AuthorityUnavailable('Artifact dispatch model quote crossed its actual original Root/prepared commitment')
    return True,quote


class _DispatchJointMetadataV3:
    """Authenticate only the actual matched Window and LongPlan inside signed R."""
    def __init__(self,state):
        self.state=state;self.complete=False;self.rows=None;self.items=();self.cursor=0
        self.column=self.producer=None;self.values={};self.header=self.history=self.bundle=None
        r=state.reader
        from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
        task=state.phase_selector.task if state.phase_variant else state.phase_selector
        self.scope=_DispatchSignedMetadataV3(state,'artifact_task_scope',
            task_scope_ref_v1(task.root_registration_ref),'task_scope_joint')
        self.selected={}
        for v in(*state.business_versions,*state.control_versions):
            if v.key.type_name not in {'d08.long_term_plan.v1','d08.joint_window.v1'}:continue
            prior=self.selected.get(v.key.token)
            if prior is not None and prior!=v.revision:
                raise AuthorityUnavailable('Artifact Host Joint metadata has conflicting actual R revisions')
            self.selected[v.key.token]=v.revision
    def advance(self,meter):
        s=self.state;r=s.reader;require_artifact_host_dispatch_current_v3(r,meter)
        if self.rows is None:
            if not self.scope.advance(meter):return False
            from .joint_window_management_v1 import managed_window_selector_digest_v1
            token=managed_window_selector_digest_v1(r.namespace,'draft_file',self.scope.ref,self.scope.header[1])
            columns=metadata_columns_v1(JOINT_TABLE)
            self.rows=tuple(dict(zip(columns,row))for row in s.managed[JOINT_TABLE]
                if dict(zip(columns,row))['selector_digest']==token)
            if len(self.rows)>1 or any(row['retired']for row in self.rows):
                raise AuthorityUnavailable('Artifact Host actual managed selector is ambiguous or retired')
            wanted={ref for row in self.rows for ref in(row['window_ref'],row['plan_ref'])}
            if not wanted<=set(self.selected):
                raise AuthorityUnavailable('Artifact Host matched Window/LongPlan is outside actual signed R')
            self.items=tuple(sorted((ref,self.selected[ref])for ref in wanted))
            s.allowed_originals.add(('artifact_task_scope',self.scope.ref))
            s.allowed_operations.add(self.scope.header[0])
            for row in self.rows:s.allowed_operations.add(row['registration_operation_id'])
            return False
        if self.cursor==len(self.items):
            from .artifact_joint_source_groups_v3 import artifact_joint_source_groups_from_metadata_v3
            groups=artifact_joint_source_groups_from_metadata_v3(namespace=r.namespace,matched_rows=self.rows,metadata=self.values)
            declared=()if s.control is None else tuple(g for g in s.control.control_source_purpose_groups
                if g[0]in {'joint_longterm_plan','joint_window_node'})
            if set(groups)!=set(declared):
                raise AuthorityUnavailable('Artifact Host declared Joint Source purposes differ from real signed R metadata')
            self.complete=True;s.habit_metadata=_DispatchHabitMetadataV3(s);s.phase='habit_metadata';return True
        token,revision=self.items[self.cursor]
        if self.column is None:self.column=_DispatchGraphMetadataV3(s,token,revision,'joint_graph','joint_producer')
        if not self.column.advance(meter):return False
        value=self.column.value
        self.values[token]=(revision,value)
        if value['schema']=='d08.joint-window.v1':
            s.eligibility_deadline=min(s.eligibility_deadline,value['original_deadline_utc'])
        self.cursor+=1;self.column=None;return False


class _DispatchGraphMetadataV3:
    def __init__(self,state,token,revision,profile,producer_profile):
        self.state,self.token,self.revision=state,token,revision
        self.profile,self.producer_profile=profile,producer_profile
        self.column=self.producer=self.receipt=None;self.header=self.history=self.bundle=None
        self.complete=False;self.value=None
    def advance(self,meter):
        s=self.state;r=s.reader;token,revision=self.token,self.revision
        require_artifact_host_dispatch_current_v3(r,meter)
        head=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(token,*r.namespace.as_tuple))
        if head is None or head[:2]!=(revision,1)or head[2]is None:
            raise AuthorityUnavailable('Artifact Host Joint metadata lost its exact positive current R head')
        if self.column is None:
            self.head=tuple(head)
            self.history=meter.read_fixed_row(r.db,'graph_history',('event_bot','event_persona','event_id','valid'),
                'token=? AND revision=?',(token,revision))
            if self.history is None or self.history[:2]!=r.namespace.as_tuple or self.history[3]!=1:
                raise AuthorityUnavailable('Artifact Host Joint metadata has no actual namespace history')
            self.column=_DispatchColumnV3(s,self.profile,table='graph_atoms',column='value',
                key_columns=('token','bot','persona'),key=(token,*r.namespace.as_tuple),cell_id=head[2]);return False
        if tuple(head)!=self.head:
            raise AuthorityUnavailable('Artifact Host Joint metadata current head changed during EOF')
        if not self.column.advance(meter):return False
        operation=self.history[2]
        names=('domain','operation_kind','original_digest','bundle_digest','receipt_digest')
        header=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',names,
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
        if self.producer is None:
            if header is None or bundle is None or bundle[0]!=header[3]or type(bundle[1])is not int or bundle[1]<1:
                raise AuthorityUnavailable('Artifact Host Joint metadata lacks its actual positive W01 producer')
            from .domain_production_registry_v1 import installed_operation_v1
            registered=installed_operation_v1(header[1])
            if registered.domain!=header[0]:
                raise AuthorityUnavailable('Artifact Host Joint producer differs from its formal operation domain')
            self.header,self.bundle=tuple(header),tuple(bundle)
            self.producer=_DispatchColumnV3(s,self.producer_profile,table='graph_domain_production_originals_v1',
                column='original_payload_json',key_columns=('bot','persona','operation_id'),key=(*r.namespace.as_tuple,operation))
            self.receipt=_DispatchColumnV3(s,'receipt',table='graph_domain_production_originals_v1',
                column='receipt_json',key_columns=('bot','persona','operation_id'),key=(*r.namespace.as_tuple,operation));return False
        if tuple(header or())!=self.header or tuple(bundle or())!=self.bundle:
            raise AuthorityUnavailable('Artifact Host Joint producer changed during canonical EOF')
        if not self.producer.advance(meter):return False
        if not self.receipt.advance(meter):return False
        raw=self.producer.require_v3(r);value=self.column.require_v3(r)
        from .domain_production_originals_v1 import _receipt
        receipt=_receipt(self.receipt.require_v3(r))
        writes=tuple(item for item in raw['writes']if item['key']==token)
        if(self.producer.sha256!=self.header[2]or canonical_digest(receipt)!=self.header[4]
                or receipt.operation_id!=operation or receipt.status!='committed'
                or receipt.operation_digest!=self.header[3]or receipt.commit_seq!=self.bundle[1]
                or GraphVersion(AtomKey.from_token(token),revision)not in receipt.write_versions
                or raw['schema']!=self.header[0]+'.current-'+self.header[1]+'.v1'
                or raw['namespace']!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or(raw['identity']['operation_id'],raw['identity']['phase'])!=(operation,self.header[1])
                or len(writes)!=1 or writes[0]['value']!=value or not writes[0]['valid']):
            raise AuthorityUnavailable('Artifact Host Joint fixed metadata is not its actual complete COMMIT write')
        s.allowed_operations.add(operation)
        self.value=value;self.complete=True;return True


class _DispatchHabitMetadataV3:
    def __init__(self,state):
        self.state=state;self.complete=False;self.column=None;self.cursor=0;self.values={}
        self.classification=None if state.control is None else state.control.habit_classification
        self.items=[];self.definition=None
        if self.classification is None or self.classification.kind=='ordinary':return
        h=self.classification;current=h.core_current
        self.policy_original=current.policy_original;self.definition=self.policy_original.definition
        state.eligibility_deadline=min(state.eligibility_deadline,
            h.qualification_original.original_deadline_utc,self.definition.original_valid_until_utc)
        from .d10_habit_v1 import habit_policy_key_v1
        ref=habit_policy_key_v1(state.reader.namespace,self.definition.policy_id).token
        self.items.append((ref,'habit_policy_graph','habit_policy_producer'))
        definition=self.definition
        if definition.cue_predicate.observation_provider=='d07.habit-cue.v1':
            self.items.append((h.qualification_original.selector.cue_original_ref,'habit_interpretation_graph','habit_interpretation_producer'))
        if definition.stop_predicate.observation_provider=='d07.habit-stop.v1':
            self.items.append((dict(definition.stop_predicate.parameters)['interpretation_ref'],'habit_interpretation_graph','habit_interpretation_producer'))
        self.versions={v.key.token:v.revision for v in(*state.business_versions,*state.control_versions)}
        if any(ref not in self.versions or self.versions[ref]<1 for ref,_,_ in self.items):
            raise AuthorityUnavailable('Artifact Host actual Habit policy/cue/stop metadata is outside signed R')
    def advance(self,meter):
        s=self.state;r=s.reader;require_artifact_host_dispatch_current_v3(r,meter)
        if self.cursor==len(self.items):
            if self.definition is not None:
                from .artifact_habit_source_groups_v3 import artifact_habit_context_source_recipe_v3
                recipe=artifact_habit_context_source_recipe_v3(definition=self.definition,
                    cue_original_ref=self.classification.qualification_original.selector.cue_original_ref,
                    interpretation_metadata=self.values)
                groups=tuple(g for g in s.control.control_source_purpose_groups if g[0]=='habit_context')
                if(len(groups)!=1 or not set(recipe[1])<=set(groups[0][1])
                        or not set(s.prepared.audiences)<=set(groups[0][3])
                        or not set(s.prepared.audiences)<=set(recipe[3])):
                    raise AuthorityUnavailable('Artifact Host actual policy/cue/stop roots lack independent context ALL')
            self.complete=True;s.phase='owner';return True
        ref,profile,producer=self.items[self.cursor]
        if self.column is None:self.column=_DispatchGraphMetadataV3(s,ref,self.versions[ref],profile,producer)
        if not self.column.advance(meter):return False
        value=self.column.value
        if profile=='habit_policy_graph':
            if(value['core_original_ref'],value['core_original_digest'])!=(self.policy_original.original_ref,self.policy_original.digest):
                raise AuthorityUnavailable('Artifact Host actual R policy changed its original paired Core commitment')
            expected={'policy_id':self.definition.policy_id,'revision':self.definition.revision,
                'source_refs':list(self.definition.source_refs)}
            if value['definition']!=expected:
                raise AuthorityUnavailable('Artifact Host actual R policy Source metadata differs from its committed definition')
        else:self.values[ref]=value
        self.cursor+=1;self.column=None;return False


_TERMINALS=WeakKeyDictionary()

class _ArtifactHostDispatchResultV3:
    def __init__(self,state):
        r=state.reader
        if state.phase!='complete'or state.result is None or not r.sealed or not r.complete:
            raise AuthorityUnavailable('Artifact Host result requires its actual completed Source-bound READ')
        from .artifact_host_seal_data_v3 import issue_artifact_host_seal_data_v3
        self.reader=r;self.value=(*state.result,issue_artifact_host_seal_data_v3(state))
        _TERMINALS[self]=(r,r.work,r.selection_digest)
    def require_result_v3(self,work):
        r=self.reader
        if(_TERMINALS.get(self)!=(r,work,r.selection_digest)or not r.read_finished
                or work.state is not r or not work._finish_called or r.operation.closed):
            raise AuthorityUnavailable('Artifact Host result lost its actual finalized retained READ Work')
        work._require_invocation(r.graph)
        return self.value
    def release_payload_v3(self):
        record=_TERMINALS.pop(self,None)
        if record is None:return
        r=record[0]
        try:r.release_payload_v3()
        finally:self.reader=self.value=None


def require_artifact_host_dispatch_family_v3(r,type_id):
    s=_state_v3(r)
    if not s.source_complete:
        raise AuthorityUnavailable('Artifact Host inventory precedes its actual independent Source ALL')
    pages=tuple(page for page in s.coverage if page.type_id==type_id)
    if len(pages)!=1:
        raise AuthorityUnavailable('Artifact Host inventory has no single actual complete signed query family')
    expected={v.key:v.revision for v in(*s.business_versions,*s.control_versions)}
    writes={v.key:v for v in s.producers[s.prepared.acquire_operation_id].receipt.write_versions}
    if any(expected.get(v.key)!=(writes[v.key].revision if v.key in writes else v.revision)for v in pages[0].row_versions):
        raise AuthorityUnavailable('Artifact Host inventory includes Body outside its actual signed B/C')
    return pages[0]


def advance_artifact_host_dispatch_read_v3(graph,work):
    from .artifact_host_result_archive_source_v3 import has_artifact_host_result_archive_work_v3,advance_artifact_host_result_archive_v3
    if has_artifact_host_result_archive_work_v3(work.state):return advance_artifact_host_result_archive_v3(graph,work)
    r=work.state;s=_state_v3(r)
    if graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable('Artifact Host continuation belongs to another actual Work')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.now=_observe_v3(r)
        if s.phase=='owner':
            _prepare_owner_scopes_v3(s)
            return GraphStorageStepV3('progress')
        complete=False
        with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
            if r.db.in_transaction:raise AuthorityUnavailable('Artifact Host READ cannot retain a transaction across quanta')
            require_artifact_host_dispatch_current_v3(r,meter)
            # The original read-only algorithm owns its BEGIN/rollback. Metadata and
            # individual fixed-point reads use this Work's independent quantum snapshot.
            if s.phase=='algorithm'and r.pending is None:
                try:
                    with bind_background_reads_v3(r,db=r.db):
                        s.result=r.context._read_dispatch_original_v1(graph,r.selector.job_id)
                    s.point_validation=iter(r.points.values());s.phase='validate'
                except BackgroundReadNeededV3 as needed:_start_background_request_v3(r,needed.request)
            else:
                r.db.execute('BEGIN')
                try:
                    if r.pending is not None:_advance_background_pending_v3(r,meter)
                    elif s.phase=='job':s.job_metadata_v3(meter)
                    elif s.phase=='prepared':s.prepared_metadata_v3(meter)
                    elif s.phase=='frozen':_frozen_metadata_v3(s,meter)
                    elif s.phase=='request':_request_metadata_v3(s,meter)
                    elif s.phase=='producers':_producer_metadata_v3(s,meter)
                    elif s.phase=='readset_metadata':s.head_metadata.advance(meter)
                    elif s.phase=='job_graph':_job_graph_metadata_v3(s,meter)
                    elif s.phase=='budget':_budget_metadata_v3(s,meter)
                    elif s.phase=='managed':_managed_metadata_v3(s,meter)
                    elif s.phase=='joint_metadata':s.joint_metadata.advance(meter)
                    elif s.phase=='habit_metadata':s.habit_metadata.advance(meter)
                    elif s.phase=='sources':_sources_metadata_v3(s,meter)
                    elif s.phase=='validate':
                        if s.validation_point is None:s.validation_point=next(s.point_validation,None)
                        point=s.validation_point
                        if point is None:complete=True
                        else:
                            if not point.complete or any(c is not None and not c.complete for c in point.values.values()):
                                raise AuthorityUnavailable('Artifact Host final point lacks complete actual canonical EOF')
                            r.require_request_v3(point.request);point.require_row_v3(meter);s.validation_point=None
                    else:raise AuthorityUnavailable('Artifact Host READ has no registered next phase')
                    require_artifact_host_dispatch_current_v3(r,meter)
                    r.reserve_heap_v3()
                finally:r.db.rollback()
        if complete:
            _observe_v3(r)
            s.phase='complete';r.complete=r.sealed=True;r.phase='artifact_dispatch_complete'
            r.result=_ArtifactHostDispatchResultV3(s)
            return GraphStorageStepV3('complete',r.result)
    return GraphStorageStepV3('progress')


def _close_artifact_host_dispatch_scopes_v3(r,s):
    first_error=None
    for fence in reversed(tuple(s.fences)):
        try:r.graph._finish_read_fence_v3(fence)
        except BaseException as error:
            if first_error is None:first_error=error
    s.fences.clear();r.fence=r.read_scope=None
    if s.owner_entry is not None:
        try:s.owner_entry.release_v3()
        except BaseException as error:
            if first_error is None:first_error=error
        finally:s.owner_entry=None
    if first_error is not None:raise first_error


def finish_artifact_host_dispatch_read_v3(graph,work,error):
    from .artifact_host_result_archive_source_v3 import has_artifact_host_result_archive_work_v3,finish_artifact_host_result_archive_v3
    if has_artifact_host_result_archive_work_v3(work.state):return finish_artifact_host_result_archive_v3(graph,work,error)
    r=work.state;s=_STATES.get(r)
    if s is None or graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable('Artifact Host finalization lost its actual private Work')
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            _close_artifact_host_dispatch_scopes_v3(r,s)
            r.read_finished=True
        if error is None:work.result_lease=work.operation
    except BaseException:
        r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation);raise
    if error is not None:
        r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation)


def release_artifact_host_dispatch_payload_v3(r):
    from .artifact_host_result_archive_source_v3 import release_artifact_host_result_archive_payload_v3
    if release_artifact_host_result_archive_payload_v3(r):return
    s=_STATES.pop(r,None)
    if s is None:return
    terminal=r.result
    if type(terminal)is _ArtifactHostDispatchResultV3:
        _TERMINALS.pop(terminal,None)
        from .artifact_host_seal_data_v3 import release_artifact_host_seal_data_v3
        release_artifact_host_seal_data_v3(terminal.value[-1])
        terminal.reader=terminal.value=None
    for task in s.signed_input_metadata.values():task.release_payload_v3()
    s.signed_input_metadata.clear();s.allowed_inputs.clear();s.input_digests.clear()
    for group in s.groups:_SCOPES.pop(group,None)
    # Scopes are closed by actual Work finalization before data ownership moves.
    s.groups.clear();s.managed.clear();s.producers.clear();s.producer_tasks.clear()
    s.expected_life_parents.clear();s.life_parent_metadata.clear()
    s.signed_input_families.clear();s.actual_joint_plans.clear();s.expected_qualifications.clear()
    s.original_body_metadata.clear();s.source_versions.clear();s.allowed_keys.clear();s.allowed_originals.clear();s.allowed_operations.clear()
    s.allowed_quotes.clear();s.allowed_jobs.clear()
    s.prepared_task=s.frozen_task=s.request_task=s.grant_task=None
    s.job_column=s.job_graph_column=s.joint_metadata=s.habit_metadata=s.head_metadata=None
    s.result=s.prepared=s.model_envelope=s.control=s.frame_facts=s.joint_inventory=None
    s.point_validation=s.validation_point=None


class _DispatchReadSetMetadataV3:
    """Exact current R heads and full query metadata, including authenticated absences."""
    def __init__(self,state):
        self.state=state;self.cursor=0;self.page_index=0;self.after='';self.rows=[];self.complete=False
        versions={}
        for v in(*state.business_versions,*state.control_versions):
            if v.key in versions and versions[v.key]!=v.revision:
                raise AuthorityUnavailable('Artifact Host actual business/control R versions conflict')
            versions[v.key]=v.revision
        self.items=tuple(sorted(versions.items(),key=lambda item:item[0].token))
        self.write_versions=state.producers[state.prepared.acquire_operation_id].receipt.write_versions
    def advance(self,meter):
        s=self.state;r=s.reader;require_artifact_host_dispatch_current_v3(r,meter)
        if self.cursor<len(self.items):
            key,revision=self.items[self.cursor]
            head=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','type_name'),
                'token=? AND bot=? AND persona=?',(key.token,*r.namespace.as_tuple))
            if (head is not None and head[2]!=key.type_name)or(0 if head is None else head[0])!=revision:
                raise AuthorityUnavailable('Artifact Host actual signed R current/negative head changed')
            s.r_headers[key]=None if head is None else tuple(head)
            self.cursor+=1;return False
        if self.page_index==len(s.coverage):
            self.complete=True;s.phase='job_graph';return True
        page=s.coverage[self.page_index]
        row=meter.read_fixed_row(r.db,'graph_atoms',('token','revision'),
            'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',
            (*r.namespace.as_tuple,page.type_id,self.after))
        if row is not None:
            if len(self.rows)>=128:raise AuthorityUnavailable('Artifact Host actual query family exceeds its original finite contract')
            self.rows.append(GraphVersion(AtomKey.from_token(row[0]),row[1]));self.after=row[0]
            r.operation.retain(_heap(row)+1024);return False
        expected={v.key:v for v in page.row_versions}
        for written in self.write_versions:
            if written.key.type_name==page.type_id:expected[written.key]=written
        if tuple(self.rows)!=tuple(sorted(expected.values(),key=lambda v:v.key.token)):
            raise AuthorityUnavailable('Artifact Host actual query family differs from signed original plus its exact own acquire CAS')
        self.page_index+=1;self.after='';self.rows=[];return False


class _DispatchOriginalBodyMetadataV3:
    """Original Source references are metadata; whole Original Body stays unopened."""
    def __init__(self,state,operation):
        self.state,self.operation=state,operation;self.header=None;self.columns=();self.index=0;self.complete=False
    def advance(self,meter):
        s=self.state;r=s.reader;require_artifact_host_dispatch_current_v3(r,meter)
        if not s.source_complete or self.operation not in s.allowed_operations:
            raise AuthorityUnavailable('Artifact Host Original metadata lacks its exact qualified actual parent')
        key=(*r.namespace.as_tuple,self.operation);table='graph_domain_production_originals_v1'
        row=meter.read_fixed_row(r.db,table,('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',key)
        if self.header is None:
            if row is None:raise AuthorityUnavailable('Artifact Host selected Original is absent')
            from .domain_production_registry_v1 import installed_operation_v1
            operation=installed_operation_v1(row[1])
            if operation.domain!=row[0]:raise AuthorityUnavailable('Artifact Host selected Original has another formal domain')
            self.header=tuple(row)
            self.columns=tuple(_DispatchColumnV3(s,profile,table=table,column=column,
                key_columns=('bot','persona','operation_id'),key=key)
                for profile,column in(('versions','read_versions_json'),('receipt','receipt_json')))
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Artifact Host selected Original header changed during EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in self.columns[0].require_v3(r))
        from .domain_production_originals_v1 import _receipt
        receipt=_receipt(self.columns[1].require_v3(r))
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        if(receipt.status!='committed'or receipt.operation_id!=self.operation or receipt.read_versions!=versions
                or canonical_digest(receipt)!=self.header[4]or receipt.operation_digest!=self.header[3]
                or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
            raise AuthorityUnavailable('Artifact Host selected Original lacks its actual complete positive W01 receipt')
        actual={v.key:v.revision for v in(*s.business_versions,*s.control_versions)}
        for v in versions:
            if NamespaceId.from_key(v.key)!=r.namespace:
                raise AuthorityUnavailable('Artifact Host Original evidence crossed namespace')
            if v.key.type_name=='memory.source':
                if actual.get(v.key)!=v.revision or s.source_versions.get(v.key)!=v.revision:
                    raise AuthorityUnavailable('Artifact Host control Original Body Source is outside independently qualified actual B/C')
            elif v.key not in actual:
                raise AuthorityUnavailable('Artifact Host Original Body escaped its exact actual signed R family')
        self.complete=True;return True


def require_artifact_host_original_body_metadata_v3(r,operation):
    s=_state_v3(r)
    if not s.source_complete or operation not in s.allowed_operations:
        raise AuthorityUnavailable('Artifact Host Original Body has no exact actual qualified parent')
    task=s.original_body_metadata.get(operation)
    if task is None or not task.complete:
        raise BackgroundReadNeededV3(('artifact_host_original_metadata',operation))
    return task


def start_artifact_host_original_metadata_v3(r,request):
    s=_state_v3(r)
    if request[0]!='artifact_host_original_metadata'or len(request)!=2 or request[1]not in s.allowed_operations:
        raise AuthorityUnavailable('Artifact Host cannot expand an unknown Original metadata family')
    task=s.original_body_metadata.get(request[1])
    if task is None:
        task=_DispatchOriginalBodyMetadataV3(s,request[1]);s.original_body_metadata[request[1]]=task
    r.pending=task


@dataclass(frozen=True,slots=True)
class _ArtifactHostPreparedRestrictionV3:
    namespace:NamespaceId
    job_id:str
    prepared_digest:str
    kind:str
    selector_commitment:str|None
    selection_digest:str|None
    prepared_candidates_digest:str|None


def register_artifact_host_selected_price_v3(db,*,prepared,chosen,selected):
    s=_bound_state_v3(db)
    if s is None:return False
    r=s.reader;require_artifact_host_dispatch_body_v3(r,'artifact_selected_price',())
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
    if s.control is None or type(prepared)is not PreparedPersonalCandidateSetV1:
        raise AuthorityUnavailable('Artifact Host selected price requires its actual closed phase candidate family')
    h=s.control.habit_classification
    if(prepared.namespace!=r.namespace or prepared.preparation_operation_id!=h.prepared_candidates_operation_id
            or prepared.future_decision_ref!=s.phase_selector.decision_ref or chosen not in prepared.candidates
            or prepared.selection_operation_id!=h.selection_operation_id
            or selected['receipt'].operation_id!=h.selection_operation_id
            or selected['original_digest']!=h.selection_original_digest
            or canonical_digest(selected['receipt'])!=h.selection_receipt_digest):
        raise AuthorityUnavailable('Artifact Host selected price crossed its actual signed D08 selection/preparation parent')
    actual={v.key:v.revision for v in(*s.business_versions,*s.control_versions)}
    for version in prepared.read_versions:
        if NamespaceId.from_key(version.key)!=r.namespace or version.key not in actual:
            raise AuthorityUnavailable('Artifact Host selected candidate evidence is outside its actual signed R')
        if version.key.type_name=='memory.source'and s.source_versions.get(version.key)!=version.revision:
            raise AuthorityUnavailable('Artifact Host selected candidate Source lacks its independently current ALL proof')
    if chosen.quote_ref is None:raise AuthorityUnavailable('Artifact Host actual selected candidate has no signed price')
    s.allowed_quotes.add((chosen.quote_ref,1));return True


def require_artifact_host_prepared_restriction_v3(db,*,prepared,issuer):
    s=_bound_state_v3(db)
    if s is None:raise AuthorityUnavailable('Artifact Host prepared gate requires its actual independent Source READ')
    r=s.reader
    require_artifact_host_dispatch_body_v3(r,'artifact_prepared_restriction',())
    if(issuer is not r.context.issuer or prepared!=s.prepared or prepared.namespace!=r.namespace
            or prepared.job_id!=r.selector.job_id):
        raise AuthorityUnavailable('Artifact Host prepared gate crossed its actual runtime/job/Original identity')
    if not s.phase_variant:
        from .d11_life_preparation_v1 import _read
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,_decode
        row=_read(db,issuer=issuer,namespace=r.namespace,kind='artifact_task_scope',ref=s.joint_metadata.scope.ref)
        scope=_decode(row[0],IngressArtifactTaskScopeOriginalV1)
        if(scope.namespace!=r.namespace or scope.c02_operation_id!=s.phase_selector.c02_operation_id
                or scope.root.registration_ref!=s.phase_selector.root_registration_ref
                or scope.source_ref!=s.frozen_task.value['task_source_ref']):
            raise AuthorityUnavailable('Artifact Host legacy ordinary request lacks its exact real positive task scope')
        s.frame_facts=_ArtifactHostPreparedRestrictionV3(r.namespace,prepared.job_id,prepared.digest,'ordinary',None,None,None)
        return None
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2,_read_artifact_phase_selected_from_locator_v2
    locator=_artifact_phase_selection_locator_v2(db,s.phase_selector)
    selected=locator[1]
    candidates,chosen,original=_read_artifact_phase_selected_from_locator_v2(db,selector=s.phase_selector,issuer=issuer,locator=locator)
    h=s.control.habit_classification
    if(original['receipt'].operation_id!=h.prepared_candidates_operation_id
            or original['original_digest']!=h.prepared_candidates_original_digest
            or canonical_digest(original['receipt'])!=h.prepared_candidates_receipt_digest):
        raise AuthorityUnavailable('Artifact Host actual candidate preparation changed its signed carrier commitment')
    from .d10_habit_v1 import habit_draft_selector_commitment_v1
    commitment=habit_draft_selector_commitment_v1(r.namespace,decision_ref=s.phase_selector.decision_ref,
        decision_digest=s.phase_selector.decision_digest,phase_selector=s.phase_selector,
        future_identity=chosen.future_identity,issuer=issuer)
    if commitment!=h.selector_commitment:
        raise AuthorityUnavailable('Artifact Host actual selected future differs from its signed classifier')
    columns=metadata_columns_v1(HABIT_TABLE)
    rows=tuple(dict(zip(columns,row))for row in s.managed[HABIT_TABLE]
        if dict(zip(columns,row))['selector_commitment']==commitment)
    if len(rows)>1 or any(row['retired']for row in rows):
        raise AuthorityUnavailable('Artifact Host selected Habit identity is ambiguous or opaquely retired')
    if h.kind=='ordinary':
        if rows:raise AuthorityUnavailable('Artifact Host managed selector cannot acquire ordinary execution semantics')
    else:
        if len(rows)!=1:raise AuthorityUnavailable('Artifact Host Habit classification lacks its actual positive managed row')
        row=rows[0];current=h.core_current;q=h.qualification_original;policy=current.policy_original;definition=policy.definition
        if((row['policy_ref'],row['policy_revision'],row['core_original_ref'],row['core_original_digest'])!=
                (current.request.qualification_selector.policy_ref,definition.revision,policy.original_ref,policy.digest)
                or row['current_state']!='enabled'or row['decision_ref']!=s.phase_selector.decision_ref
                or row['decision_digest']!=s.phase_selector.decision_digest
                or row['phase_selector_digest']!=canonical_digest(s.phase_selector)
                or row['future_identity_digest']!=canonical_digest(chosen.future_identity)
                or q.selector.parent_root_grant_ref!=prepared.parent_budget_lease_ref
                or q.selector.parent_root_grant_digest!=canonical_digest(s.grant)
                or current.owner_guard!=prepared.owner_guard
                or r.now>=min(q.original_deadline_utc,definition.original_valid_until_utc)):
            raise AuthorityUnavailable('Artifact Host actual managed selector lost its original policy/Owner/Root/generation bounds')
        # This is an independently Source-qualified Host restriction. It does not
        # replay old Core-current evidence or grant MODEL; prepare_once reobserves
        # actual Core policy/cue/stop/Owner/Self before issuing any model permit.
        s.eligibility_deadline=min(s.eligibility_deadline,q.original_deadline_utc,definition.original_valid_until_utc)
    s.frame_facts=_ArtifactHostPreparedRestrictionV3(r.namespace,prepared.job_id,prepared.digest,h.kind,
        commitment,selected['original_digest'],original['original_digest'])
    return None if h.kind=='ordinary'else s.frame_facts


class _ArtifactHostJointInventoryV3:
    def __init__(self,state):
        self.state=state;r=state.reader
        self.namespace=r.namespace;self.operation=r.operation;self.complete=True
        self.epoch=(r.graph_stamp[1].revision,)
        self.rows=tuple(dict(zip(metadata_columns_v1(JOINT_TABLE),row))for row in state.managed[JOINT_TABLE])
        self.digest=canonical_digest(('sylanne.artifact-host-joint-eof.v3',r.namespace,
            tuple(state.managed[JOINT_TABLE]),self.epoch,r.selection_digest))
    def require(self):
        r=self.state.reader;s=_bound_state_v3(r.db)
        if s is not self.state or not s.source_complete or not s.metadata_complete or r.operation.closed:
            raise AuthorityUnavailable('Artifact Host Joint classification lacks its actual complete Source/Owner/metadata Work')
        return self


def current_artifact_host_joint_inventory_v3(db):
    s=_bound_state_v3(db)
    if s is None:return None
    require_artifact_host_dispatch_body_v3(s.reader,'artifact_joint_inventory',())
    if s.joint_inventory is None:s.joint_inventory=_ArtifactHostJointInventoryV3(s)
    return s.joint_inventory.require()


def require_artifact_host_signed_input_metadata_owner_v3(reader,table,ref):
    state=_state_v3(reader)
    if(not state.source_complete or state.phase not in {'algorithm','validate'}or reader.fence is None
            or reader.read_scope is not reader.fence.scope or(table,ref)not in state.allowed_inputs):
        raise AuthorityUnavailable('Artifact signed metadata requires its actual exact parent/Source/READ Work')
    return state


_SIGNED_METADATA_TABLES_V3=frozenset({'graph_d10_production_inputs_v1','graph_d08_joint_node_originals_v1',
    'graph_d08_joint_plan_intents_v1','graph_d08_party_consents_v1'})
_BINDING_INPUT_KINDS_V3=frozenset({'joint_node_execution_binding_v1','joint_artifact_prospective_binding_v1'})


def _register_artifact_host_input_child_v3(s,table,ref,kinds,digest):
    key=(table,ref)
    if type(ref)is not str or not ref or table not in _SIGNED_METADATA_TABLES_V3:
        raise AuthorityUnavailable('Artifact signed child is not an actual fixed parent locator')
    previous=s.allowed_inputs.get(key)
    if previous is not None and previous!=kinds:
        raise AuthorityUnavailable('Artifact actual parent child changes its closed signed input kind')
    if digest is not None:
        previous_digest=s.input_digests.get(key)
        if previous_digest is not None and previous_digest!=digest:
            raise AuthorityUnavailable('Artifact actual parents disagree on one signed child digest')
        s.input_digests[key]=digest
    s.allowed_inputs[key]=kinds


def start_artifact_host_signed_input_metadata_v3(r,request):
    s=_state_v3(r)
    if(len(request)!=3 or request[0]!='artifact_host_signed_input_metadata'
            or(request[1],request[2])not in s.allowed_inputs):
        raise AuthorityUnavailable('Artifact signed metadata request escaped its actual parent registry')
    from .artifact_host_signed_input_metadata_v3 import prepare_artifact_host_signed_input_metadata_task_v3
    key=request[1:];task=s.signed_input_metadata.get(key)
    if task is None:
        task=prepare_artifact_host_signed_input_metadata_task_v3(r,*key);s.signed_input_metadata[key]=task
    r.pending=task


def require_artifact_host_signed_input_body_metadata_v3(r,table,ref):
    s=_state_v3(r);key=(table,ref)
    if not s.source_complete or key not in s.allowed_inputs:
        raise AuthorityUnavailable('Artifact signed input Body has no actual independent Source parent')
    task=s.signed_input_metadata.get(key)
    if task is None or not task.complete:
        raise BackgroundReadNeededV3(('artifact_host_signed_input_metadata',table,ref))
    header=task.header
    if header is None:return task
    s.allowed_operations.add(header.producing_operation_id)
    require_artifact_host_original_body_metadata_v3(r,header.producing_operation_id)
    metadata=task.metadata
    if table=='graph_d10_production_inputs_v1':
        if header.kind=='joint_executor_index_v1':
            _register_artifact_host_input_child_v3(s,table,metadata['binding_ref'],_BINDING_INPUT_KINDS_V3,metadata['binding_digest'])
        elif header.kind in _BINDING_INPUT_KINDS_V3:
            executor=metadata['executor'];selector=s.phase_selector.task if s.phase_variant else s.phase_selector
            if((executor['c02_operation_id'],executor['root_registration_ref'])!=
                    (selector.c02_operation_id,selector.root_registration_ref)
                    or executor['phase_selector']is not None and executor['phase_selector']!=s.job_locator['selector']):
                raise AuthorityUnavailable('Artifact signed binding changed the actual task/root/phase parent')
            task_scope=metadata.get('task_scope_ref')
            if task_scope is not None:
                if(task_scope,metadata['task_scope_digest'])!=(s.joint_metadata.scope.ref,s.joint_metadata.scope.header[1]):
                    raise AuthorityUnavailable('Artifact binding changed its actual signed task scope')
        elif header.kind=='joint_plan_qualification_v1':
            expected=s.expected_qualifications.get(ref)
            if expected is None or(header.producing_operation_id,metadata['plan_ref'],metadata['plan_revision'],metadata['plan_digest'],metadata['result_versions_digest'])!=expected:
                raise AuthorityUnavailable('Artifact qualifier differs from its actual current typed plan/result request')
            for node in metadata['nodes']:
                if node['binding_digest']:
                    _register_artifact_host_input_child_v3(s,table,node['binding_ref'],_BINDING_INPUT_KINDS_V3,node['binding_digest'])
    return task



def register_artifact_host_joint_current_plan_v3(db,*,namespace,binding,plan):
    s=_bound_state_v3(db)
    if s is None:return False
    r=s.reader
    require_artifact_host_dispatch_body_v3(r,'artifact_joint_current_plan',())
    table='graph_d10_production_inputs_v1'
    selected=require_artifact_host_signed_input_body_metadata_v3(r,table,binding.original_ref)
    if(selected.header.payload_digest!=binding.digest or binding.namespace!=namespace or namespace!=r.namespace
            or binding.plan_revision!=plan.revision):
        raise AuthorityUnavailable('Artifact actual Joint plan changed its independently signed selected binding')
    key=AtomKey.from_token(binding.plan_ref);actual={v.key:v.revision for v in(*s.business_versions,*s.body_control_versions)}
    if actual.get(key)!=plan.revision:
        raise AuthorityUnavailable('Artifact actual Joint plan is outside exact signed business/control Body R')
    for ref in plan.source_refs:
        source=AtomKey.from_token(ref)
        if s.source_versions.get(source)!=actual.get(source)or actual.get(source,0)<1:
            raise AuthorityUnavailable('Artifact actual Joint plan Source lacks independent current B/C ALL')
    for node in plan.nodes:
        if node.owner_ref=='persona:'+namespace.persona_id:
            _register_artifact_host_input_child_v3(s,table,node.resource_ref,_BINDING_INPUT_KINDS_V3,None)
        else:
            _register_artifact_host_input_child_v3(s,'graph_d08_joint_node_originals_v1',node.resource_ref,
                frozenset({'external_node_contract_v1'}),None)
    s.actual_joint_plans[binding.plan_ref]=(plan.revision,canonical_digest(plan))
    return True


def register_artifact_host_joint_qualification_v3(db,*,namespace,binding,plan,request,operation_id,ref):
    s=_bound_state_v3(db)
    if s is None:return False
    register_artifact_host_joint_current_plan_v3(db,namespace=namespace,binding=binding,plan=plan)
    from .joint_node_execution_v1 import joint_qualification_operation_id_v1,joint_qualification_ref_v1
    if(operation_id!=joint_qualification_operation_id_v1(namespace,request)
            or ref!=joint_qualification_ref_v1(namespace,operation_id)
            or request.plan_ref!=binding.plan_ref or request.expected_plan_revision!=plan.revision):
        raise AuthorityUnavailable('Artifact Joint qualification is not its actual derived current plan request')
    expected=(operation_id,binding.plan_ref,plan.revision,canonical_digest(plan),request.result_versions_digest)
    previous=s.expected_qualifications.get(ref)
    if previous is not None and previous!=expected:
        raise AuthorityUnavailable('Artifact current qualifier changed its exact derived request')
    s.expected_qualifications[ref]=expected
    _register_artifact_host_input_child_v3(s,'graph_d10_production_inputs_v1',ref,
        frozenset({'joint_plan_qualification_v1'}),None)
    return True


def require_artifact_host_goal_projection_absent_v3(db,*,namespace,goal_ref,root_registration_ref,issuer):
    s=_bound_state_v3(db)
    if s is None:return False
    r=s.reader
    if namespace!=r.namespace or issuer is not r.context.issuer:
        raise AuthorityUnavailable('Artifact Goal metadata barrier changed actual namespace/issuer')
    from .domain_background_read_v3 import background_point_v3
    table='graph_owner_goal_cancellation_projections_v1'
    columns=('operation_id',);keys=('bot','persona','goal_ref','root_registration_ref')
    key=(*namespace.as_tuple,goal_ref,root_registration_ref)
    require_artifact_host_dispatch_request_v3(r,(table,columns,keys,key))
    row=background_point_v3(db,table=table,columns=columns,key_columns=keys,key=key,legacy_reader=lambda:None)
    if row is not None:raise AuthorityUnavailable('actual_goal_metadata_projection_barrier:'+row[0])
    return True



def require_artifact_host_dispatch_rows_v3(r,request):
    s=require_artifact_host_dispatch_body_v3(r,'artifact_signed_metadata_census',())
    table,columns,groups,group,order,limit=request
    if(table!='graph_d08_joint_node_originals_v1'or columns!=('original_ref',)
            or groups!=('bot','persona','kind')or group!=(*r.namespace.as_tuple,'external_node_observation_v1')
            or order!=('original_ref',)or limit!=129 or not s.actual_joint_plans):
        raise AuthorityUnavailable('Artifact Host has no actual closed signed-input metadata census for this request')
    return True


def register_artifact_host_input_census_v3(db,*,table,namespace,kind,keys):
    s=_bound_state_v3(db)
    if s is None:return False
    r=s.reader
    request=(table,('original_ref',),('bot','persona','kind'),(*namespace.as_tuple,kind),('original_ref',),129)
    require_artifact_host_dispatch_rows_v3(r,request)
    census=r.scans.get(request)
    if census is None or not census.complete or tuple(census.rows)!=tuple(keys):
        raise AuthorityUnavailable('Artifact signed-input family has no actual complete same-Work metadata EOF')
    if len(keys)>128:raise AuthorityUnavailable('Artifact actual external observation family exceeds its unchanged finite bound')
    refs=tuple(row[0]for row in keys)
    previous=s.signed_input_families.get((table,kind))
    if previous is not None and previous!=refs:
        raise AuthorityUnavailable('Artifact signed-input family changed its complete actual metadata membership')
    s.signed_input_families[table,kind]=refs
    for ref in refs:_register_artifact_host_input_child_v3(s,table,ref,frozenset({kind}),None)
    return True



class _DispatchPreviousVerifiedMetadataV3:
    """One actual signed selector parent; no historical permission is renewed."""
    def __init__(self,state,kind,ref):
        self.state,self.kind,self.ref=state,kind,ref
        self.signed=_DispatchSignedMetadataV3(state,kind,ref,'previous_verified')
        self.producer=None;self.complete=False
    def advance(self,meter):
        s=self.state;r=s.reader;require_artifact_host_dispatch_current_v3(r,meter)
        if not s.source_complete or(s.expected_life_parents.get((self.kind,self.ref))is None):
            raise AuthorityUnavailable('Artifact phase parent has no actual signed current selector')
        if not self.signed.advance(meter):return False
        raw=self.signed.value
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
        previous=artifact_draft_from_wire_v2(raw['selector'],ArtifactDraftPhaseSelectorV2)
        current=s.phase_selector
        source=GraphVersion(AtomKey.from_token(raw['source_head']['key']),raw['source_head']['revision'])
        actual={v.key:v.revision for v in(*s.business_versions,*s.control_versions)}
        digests=tuple(group.sources[source.key.token][1]for group in s.groups if source.key.token in group.sources)
        if(self.kind!='c4_phase_verified'or self.signed.header[1]!=s.expected_life_parents[self.kind,self.ref]
                or raw['schema']!='d11.artifact-draft-phase-verified-original.v2'
                or raw['producing_operation_id']!=self.signed.header[0]
                or(previous.task,previous.method_ref,previous.phase_index)!=(current.task,current.method_ref,current.phase_index-1)
                or NamespaceId.from_key(source.key)!=r.namespace or source.key.type_name!='memory.source'
                or source.revision<1 or actual.get(source.key)!=source.revision
                or s.source_versions.get(source.key)!=source.revision
                or not digests or any(digest!=raw['source_value_digest']for digest in digests)):
            raise AuthorityUnavailable('Artifact previous verified parent differs from real selector/current qualified Source')
        if self.producer is None:
            s.allowed_operations.add(self.signed.header[0])
            self.producer=_DispatchOriginalBodyMetadataV3(s,self.signed.header[0])
        if not self.producer.advance(meter):return False
        if self.producer.header[:2]!=('d11','verify_artifact_draft_phase_v2'):
            raise AuthorityUnavailable('Artifact previous verification lost its actual positive W01 producer')
        s.allowed_originals.add((self.kind,self.ref));self.complete=True;return True


def require_artifact_host_life_parent_metadata_v3(r,kind,ref):
    s=_state_v3(r);key=(kind,ref)
    if key not in s.expected_life_parents or not s.source_complete:
        raise AuthorityUnavailable('Artifact parent Original has no exact current signed selector/Source family')
    task=s.life_parent_metadata.get(key)
    if task is None or not task.complete:
        raise BackgroundReadNeededV3(('artifact_host_life_parent_metadata',kind,ref))
    return task


def start_artifact_host_life_parent_metadata_v3(r,request):
    s=_state_v3(r)
    if len(request)!=3 or request[0]!='artifact_host_life_parent_metadata'or request[1:]not in s.expected_life_parents:
        raise AuthorityUnavailable('Artifact previous parent metadata request crossed its actual signed selector')
    key=request[1:];task=s.life_parent_metadata.get(key)
    if task is None:
        task=_DispatchPreviousVerifiedMetadataV3(s,*key);s.life_parent_metadata[key]=task
    r.pending=task
