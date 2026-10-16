"""Two exact Host Numeric READ recipes over the actual selected Method kernel."""
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3)
from ..graph_worker import (GraphStorageStepV3,GraphStorageWorkV3,create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from .current_method_learning_read_v3 import (_ISSUER,_READERS,_READING,_MethodLearningReadV3,
    _MethodPointReadV3,_MethodBudgetGrantReadV3,_GeneralMethodSourceMetadataEOFV1,
    _GENERAL_METHOD_SOURCE_ISSUER_V1,_GENERAL_METHOD_SOURCE_TASKS_V1,
    _NUMERIC_READ_ONLY_OPERATIONS_V3,begin_current_method_learning_read_v3,
    bind_prepared_method_learning_read_v3,_prepare_current_general_method_owner_entry_v1,
    read_bound_method_learning_attachment_v3,read_bound_method_budget_grant_v3,
    _release_method_registered_payloads_v3,MethodInputNeededV3,_method_active,_need_method_input)
from .current_life_numeric_metadata_v1 import (_NumericMetadataColumnV1,_metadata,
    NumericMetadataTaskV1,require_numeric_method_sources_v1,prepare_numeric_metadata_plan_v1)
from .dispatch_current_inventory_v3 import _heap,_freeze_value_v3,_detach_value_v3
from ..model_broker.internal_life_numeric_v1 import (InternalLifeNumericIdentityV1,
    internal_life_numeric_ids_v1,WORK_KIND,TEMPLATE_VERSION)

NUMERIC_READ_WORK_KIND_V3="current_life_numeric_read_v3"
IDENTITY_READ_V3="read_current_life_numeric_identity_v3"
DRAFT_READ_V3="read_current_life_numeric_model_draft_v3"
CANDIDATE_READ_V3="qualify_current_life_numeric_candidate_v3"
JOINT_PREPARED_READ_V3="read_current_life_numeric_joint_prepared_v3"
TRACE_READ_V3="read_current_life_numeric_trace_v3"
NATIVE_READ_OPERATIONS_V3=frozenset({JOINT_PREPARED_READ_V3,TRACE_READ_V3})
_CANDIDATE_FACTS=WeakKeyDictionary()
_READ_STATE=WeakKeyDictionary()
_CONTROLS=WeakKeyDictionary()
_RESULTS=WeakKeyDictionary()
_OBSERVATIONS=WeakKeyDictionary()
_JOB_COLUMNS=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref","phase","work_kind",
    "continuation_json","wake_condition_json","deadline_utc","budget_ref","resource_ref","operator_versions_json",
    "lease_holder","lease_expires_utc","fence","cancel_epoch","usage_json","result_ref")
_LEASE_COLUMNS=("lease_id","parent_id","bot_id","persona_id","currency","limits_json","used_json",
    "reserved_json","unconfirmed_json","version","state")
_JOB_METADATA=("operation_id","activity_id","bot_id","persona_id","phase","work_kind","deadline_utc",
    "budget_ref","resource_ref","lease_holder","lease_expires_utc","fence","cancel_epoch","result_ref")
_LEASE_METADATA=("parent_id","bot_id","persona_id","currency","version","state")
_WIRE_PATHS=(("call_id",),("provider_id",),("model_id",),("max_output_tokens",),("prompt_template_digest",),
    ("envelope","identity"),("envelope","authority"),("envelope","version_guard","read_versions"),
    ("envelope","parent_budget_lease_ref"),("envelope","deadline_utc"))

@dataclass(frozen=True,slots=True)
class ReadCurrentLifeNumericIdentityRequestV3:
    episode_ref:str
    causal_operation_id:str

    def __post_init__(self):
        from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
        EncodeInternalLifeRequestV1(self.episode_ref,self.causal_operation_id)

@dataclass(frozen=True,slots=True)
class ReadCurrentLifeNumericModelDraftRequestV3:
    episode_ref:str
    causal_operation_id:str
    job_id:str

    def __post_init__(self):
        ReadCurrentLifeNumericIdentityRequestV3(self.episode_ref,self.causal_operation_id)
        if type(self.job_id)is not str or not self.job_id or len(self.job_id)>4096:
            raise ValueError("Numeric draft READ requires its actual once job locator")


@dataclass(frozen=True,slots=True)
class QualifyCurrentLifeNumericCandidateRequestV3:
    episode_ref:str
    causal_operation_id:str
    job_id:str
    candidate:object
    installed_reader:object

    def __post_init__(self):
        from ..authority_service.current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        ReadCurrentLifeNumericModelDraftRequestV3(self.episode_ref,self.causal_operation_id,self.job_id)
        if type(self.candidate)is not ModelEgressIntentV1 or type(self.installed_reader)is not InstalledLifeNumericModelGraphReaderV1:
            raise TypeError("Numeric current candidate requires its actual installed reader/intent")

@dataclass(frozen=True,slots=True)
class CurrentLifeNumericCandidateQualificationV3:
    job_id:str
    request_digest:str
    binding_digest:str
    current_scope_digest:str
    valid_until_utc:float
    current_now_utc:float
    deadline_bounds:tuple
    occurrence_bounds:tuple

@dataclass(frozen=True,slots=True)
class CurrentLifeNumericModelDraftV3:
    prepared:object
    binding:object
    model:object
    draft:object
    expected_anchor:object

def _state_identity(reader):
    return (reader.graph,reader.runtime,reader.authority,reader.lease,reader.fence,reader.operation,
        reader.request,reader.request_digest,reader.operation_kind,reader.work,reader.selection_digest,
        reader.operation_id,reader.parent_budget_lease_ref,reader.session_proof,reader.numeric_native_activity_id)

def require_numeric_read_work_v3(reader):
    if (type(reader)is not _MethodLearningReadV3 or reader not in _READERS
            or reader.operation_kind not in _NUMERIC_READ_ONLY_OPERATIONS_V3
            or _READ_STATE.get(reader)!=_state_identity(reader)
            or type(reader.work)is not GraphStorageWorkV3 or reader.work.kind!=NUMERIC_READ_WORK_KIND_V3
            or reader.work.state is not reader or reader.work.coordinator is not reader.graph
            or reader.work.operation is not reader.operation or reader.operation.closed
            or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or reader.fence.scope.operation!="read" or reader.session_proof is None
            or any((reader.background_followup,reader.background_host_lifecycle,reader.background_offline))):
        raise AuthorityUnavailable("Numeric Host READ requires its exact private two-recipe Work/Owner/session")
    reader.work._require_invocation(reader.graph)
    return reader

def prepare_current_life_numeric_read_v3(graph,authority,lease,*,operation_kind,request,activity_id=None):
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    from .d06_life_numeric_joint_v1 import PrepareLifeNumericJointRequestV1
    from .d06_life_numeric_trace_v1 import AdoptLifeNumericTraceRequestV1
    expected={IDENTITY_READ_V3:ReadCurrentLifeNumericIdentityRequestV3,DRAFT_READ_V3:ReadCurrentLifeNumericModelDraftRequestV3,
        CANDIDATE_READ_V3:QualifyCurrentLifeNumericCandidateRequestV3,
        JOINT_PREPARED_READ_V3:PrepareLifeNumericJointRequestV1,TRACE_READ_V3:AdoptLifeNumericTraceRequestV1}
    if operation_kind==TRACE_READ_V3:
        from ..authority_service.contract import identifier
        identifier(activity_id,"activity_id")
    elif activity_id is not None:raise TypeError("Numeric activity selector belongs only to its named trace READ")
    if operation_kind not in expected or type(request)is not expected[operation_kind]:
        raise TypeError("Numeric Host READ requires its exact named typed locator")
    if operation_kind==TRACE_READ_V3 and (authority.purpose!="consolidation"
            or len(authority.audience)!=1 or authority.audience[0]=="*"):
        raise AuthorityUnavailable("Native trace READ retains its actual consolidation/single audience recipe")
    graph._authorize(lease,authority,frozenset({"d06"} if operation_kind==TRACE_READ_V3 else {"d11"}),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or "workbench.create"not in owner.capabilities:
        raise AuthorityUnavailable("Numeric Host READ requires its actual installed Owner capability/session")
    bundle=assembly.admin_bundle
    if bundle.installation_policy.namespace!=authority.namespace:
        raise AuthorityUnavailable("Numeric Host READ crossed its actual installation namespace")
    if operation_kind==CANDIDATE_READ_V3:
        installed=request.installed_reader
        if (installed.bundle is not bundle or installed.readers.issuer is not graph._GraphCoordinator__d11_issuer
                or installed.readers.resource_issuer is not graph._GraphCoordinator__d02_issuer
                or installed.owner_storage.namespace_id!=authority.namespace):
            raise AuthorityUnavailable("Numeric candidate reader differs from actual installed components")
    workflow=bundle.model_workflows.life_numeric
    if (workflow is None or workflow.work_kind!=WORK_KIND or workflow.template_version!=TEMPLATE_VERSION
            or workflow.purpose!="consolidation"or authority.purpose not in {"context","consolidation"}
            or not set(authority.audience)<=set(workflow.audiences)):
        raise AuthorityUnavailable("Numeric Host READ changed its actual installed workflow/purpose/audience")
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id="life-numeric-read:"+uuid4().hex
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id,owner_session_proof=session)
            reader=begin_current_method_learning_read_v3(graph,operation,fence,
                runtime=graph._GraphCoordinator__domain_production_runtime_v1,authority=authority,lease=lease,
                operation_kind=operation_kind,request=request,operation_id=operation_id,activity_id=operation_id,
                audience_ref=authority.audience[0],parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id,
                request_digest=canonical_digest((operation_kind,request.episode_ref,request.causal_operation_id,
                    request.job_id,canonical_digest(request.candidate))) if operation_kind==CANDIDATE_READ_V3 else canonical_digest((operation_kind,request)),owner_binding=owner,owner_guard=None,
                session_proof=session,initial_now_utc=now)
            reader.initial_monotonic_deadline=time.monotonic()+60.0
            reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
            reader.numeric_read_value=None
            reader.numeric_native_activity_id=activity_id
            reader.numeric_native_environment_ready=False
        work=create_graph_storage_work_v3(graph,kind=NUMERIC_READ_WORK_KIND_V3,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=reader,operation=operation)
        work._require_invocation(graph,initial=True)
        reader.work=work
        _READ_STATE[reader]=_state_identity(reader)
        work.phase="numeric_owner_eof"
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise

class _NumericWireProjectionV3:
    def __init__(self,column,*,field_path=("wire",),paths=_WIRE_PATHS):
        self.column=column;self.field_path=tuple(field_path);self.paths=tuple(paths)
        self.nodes={};self.value=None;self.scalar=bytearray()
        self.text_parts=[];self.text_chars=[];self.text_high=None
        self.general_metadata_profile=None;self.general_metadata_fields_seen=set()
        self.buffer=bytearray();self.complete=False;self.frozen=None;self.reserved=0
        from .current_method_learning_read_v3 import _MethodJSONStreamV3
        self.parser=_MethodJSONStreamV3(self,ensure_ascii=True)

    def _actual(self):
        self.column._actual()
        if (self.column.profile=="request" and (self.field_path!=("wire",) or self.column.wire_projection is not self)
                or self.column.profile not in {"request","native_prepared"}):
            raise AuthorityUnavailable("Numeric opaque-original locator changed its actual issued metadata profile")
        return self

    def retain_path_v3(self,path):
        if not path:return True
        return any(selected[:len(path)]==path or path[:len(selected)]==selected for selected in self.paths)

    def _reserve_v3(self,extra=0):
        size=_heap((self.nodes,self.value,self.scalar,self.text_parts,self.text_chars,self.buffer))+extra+1024
        if size>self.reserved:self.column.operation.retain(size-self.reserved);self.reserved=size

    def _flush_text_v3(self):
        if self.text_chars:self.text_parts.append("".join(self.text_chars));self.text_chars=[]

    def _put_v3(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:parent.append(value)
            else:parent[path[-1]]=value

    def _emit_v3(self,event):
        if not self.retain_path_v3(event.path):return
        from .current_method_learning_read_v3 import MethodJSONColumnV3
        MethodJSONColumnV3._emit_v3(self,event)

    def consume_codepoint_v3(self,path,codepoint):
        if path!=self.field_path:return False
        self._actual()
        self.buffer.extend(chr(codepoint).encode("utf8"))
        if len(self.buffer)>=1024:self._feed_v3()
        return True

    def _feed_v3(self):
        raw=bytes(self.buffer);self.buffer.clear()
        self.parser.feed(raw,self._emit_v3);self._flush_text_v3()

    def finish_v3(self):
        self._actual()
        if self.buffer:self._feed_v3()
        self.parser.finish()
        self.column.operation.retain(_heap(self.value)*2+1024)
        self.frozen=_freeze_value_v3(self.value)
        self.nodes={};self.value=None;self.scalar=bytearray();self.text_parts=[];self.text_chars=[]
        self.parser=None;self.complete=True
        return _detach_value_v3(self.frozen)

class NumericRequestEnvelopeMetadataColumnV3(_NumericMetadataColumnV1):
    def __init__(self,task,*,cell=None):
        super().__init__(task,cell=cell)
        self.wire_projection=_NumericWireProjectionV3(self)
        from .current_method_learning_read_v3 import _MethodJSONStreamV3
        self.parser=_MethodJSONStreamV3(self,ensure_ascii=cell is None or cell.header[0]!="canonical-json.utf8.v1",
            wire_metadata=self.wire_projection)

    def advance(self,meter):
        complete=super().advance(meter)
        if complete and not self.wire_projection.complete:
            self.envelope_metadata=self.wire_projection.finish_v3()
        return complete

def current_numeric_read_identity_v3(reader):
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    context,task=_metadata(reader,"life","context",life_numeric_context_ids_v1(reader.namespace,reader.request.episode_ref)["original"])
    return InternalLifeNumericIdentityV1(reader.namespace,reader.request.episode_ref,context["execution_id"],
        context["source_ref"],context["occurrence_digest"],context["before_digest"],task.column.canonical_digest)

def _version_key(raw):
    value=raw["key"]
    return AtomKey(Owner(**value["owner"]),value["type_name"],value["name"])

def prepare_numeric_draft_metadata_v3(reader,identity,prepared,prepared_task):
    from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
    r=require_numeric_read_work_v3(reader)
    ids=internal_life_numeric_ids_v1(identity)
    if r.request.job_id!=ids["job"]:
        raise AuthorityUnavailable("Numeric draft READ job differs from its signed actual occurrence/context identity")
    binding_raw,binding_task=_metadata(r,"life","binding",ids["job"])
    request_raw,request_task=_metadata(r,"life","request",ids["job"])
    committed,commit_task=_metadata(r,"life","acquire_commit",ids["job"])
    quote_raw,quote_task=_metadata(r,"quote","quote",prepared["quote_id"])
    binding=decode_life_numeric_worker_binding_v1(binding_raw)
    envelope=request_task.column.envelope_metadata
    handled,grant=read_bound_method_budget_grant_v3(r.db,r.parent_budget_lease_ref)
    if not handled:raise AuthorityUnavailable("Numeric Host READ lacks its actual current signed parent grant EOF")
    if (binding.namespace!=r.namespace or binding.job_id!=ids["job"]
            or binding.prepared_digest!=prepared_task.column.canonical_digest
            or binding.owner_principal!=r.owner_binding.principal or binding.owner_actor!=r.owner_binding.actor
            or binding.owner_guard!=r.material_owner_guard
            or request_raw["prepared_digest"]!=binding.prepared_digest or request_raw["binding_digest"]!=binding.digest
            or committed["prepared_digest"]!=binding.prepared_digest or committed["binding_digest"]!=binding.digest
            or committed["request_digest"]!=request_raw["request_digest"]):
        raise AuthorityUnavailable("Numeric candidate signed acquisition/actual Owner metadata differs")
    with runtime_storage_quantum_v3(r.db)as meter:
        job=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",_JOB_METADATA,"job_id=?",(ids["job"],))
        lease=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_leases",_LEASE_METADATA,
            "lease_id=?",(r.parent_budget_lease_ref,))
        reservation=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_reservations",("state","digest","ceiling_json"),
            "lease_id=? AND operation_id=?",(r.parent_budget_lease_ref,ids["prepare"]))
    if job is None or lease is None or reservation is None:
        raise AuthorityUnavailable("Numeric actual acquired job/root lease/reservation metadata unavailable")
    j=dict(zip(_JOB_METADATA,job))
    if r.operation_kind==CANDIDATE_READ_V3:
        from ..authority_service.current_life_numeric_v1 import _qualify_numeric_worker_state_v3
        candidate=r.request.candidate
        if candidate.job_id!=ids["job"]:
            raise ValueError('Life model selected installation/namespace differs')
        _qualify_numeric_worker_state_v3(phase=j["phase"],job_operation_id=j["operation_id"],
            prepared_operation_id=prepared["operation_id"],job_fence=j["fence"],
            candidate_fence=candidate.worker_fence,request_fence=envelope["envelope"]["authority"]["worker_fence"],
            cancel_epoch=j["cancel_epoch"],lease_holder=j["lease_holder"],candidate_subject=candidate.subject,
            binding_subject=binding.worker_subject,result_ref=j["result_ref"],lease_expires_utc=j["lease_expires_utc"])
    now=_current_read_now(r)
    from .issuers import _decode_quote
    quote=_decode_quote(canonical_serialize(quote_raw))
    current_owner=r.owner_binding
    actual_grant=_OBSERVATIONS[r][4]
    workflow=r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.model_workflows.life_numeric
    from ..model_broker.internal_life_numeric_v1 import TEMPLATE_DIGEST
    if ((binding.installation_id,binding.manifest_digest,binding.worker_subject,binding.installation_grant_digest)!=
            (actual_grant.installation_id,actual_grant.manifest_digest,actual_grant.subject,canonical_digest(actual_grant))
            or (envelope["provider_id"],envelope["model_id"],envelope["prompt_template_digest"],envelope["max_output_tokens"])!=
                (workflow.provider_id,workflow.model_id,TEMPLATE_DIGEST,workflow.max_output_tokens)
            or binding.namespace!=r.namespace or binding.job_id!=ids["job"]or binding.call_id!=ids["call"]
            or binding.acquire_operation_id!=ids["acquire"]or binding.prepared_digest!=prepared_task.column.canonical_digest
            or binding.owner_principal!=current_owner.principal or binding.owner_actor!=current_owner.actor
            or binding.owner_guard!=r.material_owner_guard
            or binding.graph_incarnation!=current_owner.graph_incarnation
            or request_raw["prepared_digest"]!=binding.prepared_digest or request_raw["binding_digest"]!=binding.digest
            or committed["prepared_digest"]!=binding.prepared_digest or committed["binding_digest"]!=binding.digest
            or committed["request_digest"]!=request_raw["request_digest"]
            or (envelope["call_id"],envelope["envelope"]["identity"]["phase"],envelope["envelope"]["authority"]["actor"])!=
                (ids["call"],"internal_life_numeric_v1",binding.worker_subject)
            or envelope["envelope"]["parent_budget_lease_ref"]!=r.parent_budget_lease_ref
            or (j["operation_id"],j["activity_id"],j["bot_id"],j["persona_id"],j["phase"],j["work_kind"],j["lease_holder"],j["fence"],j["cancel_epoch"])!=
                (ids["prepare"],r.activity_id,*r.namespace.as_tuple,"running",WORK_KIND,binding.worker_subject,1,0)
            or j["budget_ref"]!=r.parent_budget_lease_ref or j["lease_expires_utc"]is None
            or lease[0]is not None or lease[1:3]!=r.namespace.as_tuple or lease[3]!=grant.currency or lease[5]!="active"
            or grant.lease_id!=r.parent_budget_lease_ref or WORK_KIND not in grant.allowed_work_kinds
            or reservation!=("reserved",prepared["reservation_digest"],canonical_serialize(dict(quote.ceiling)))
            or (quote.quote_id,quote.version,quote.bot_id,quote.persona_id,quote.activity_id,quote.operation_id,
                quote.parent_budget_lease_ref,quote.work_kind)!=
                (prepared["quote_id"],1,*r.namespace.as_tuple,r.activity_id,ids["prepare"],r.parent_budget_lease_ref,WORK_KIND)
            or canonical_digest(quote)!=prepared["quote_digest"]):
        raise AuthorityUnavailable("Numeric draft actual signed acquisition/current Owner/job/grant/quote/reservation differs")
    with runtime_storage_quantum_v3(r.db)as meter:
        debt=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_debt_blocks",("lease_id",),
            "lease_id=? LIMIT 1",(r.parent_budget_lease_ref,))
    if debt is not None:raise AuthorityUnavailable("Numeric actual parent budget has unresolved debt")
    deadline=min(r.operation.deadline_utc,binding.deadline_utc,_utc_seconds(j["deadline_utc"]),
        _utc_seconds(j["lease_expires_utc"]),quote.deadline_utc,quote.valid_until_utc,grant.valid_until_utc,
        envelope["envelope"]["deadline_utc"])
    if now>=deadline:raise AuthorityUnavailable("Numeric draft actual original job/worker/quote/root deadline expired")
    roots=set();expectations={};version_headers=[]
    for version in envelope["envelope"]["version_guard"]["read_versions"]:
        key=_version_key(version)
        if NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("Numeric signed request-envelope version crossed namespace")
        with runtime_storage_quantum_v3(r.db)as meter:
            actual=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(key.token,*r.namespace.as_tuple))
        if (0 if actual is None else actual[0])!=version["revision"]:
            raise AuthorityUnavailable("Numeric actual acquired read-version metadata changed")
        version_headers.append((key,actual))
        if key.type_name in {"memory.source","memory.access"}:
            expectations[key.token]=version["revision"]
            if key.type_name=="memory.source":roots.add(key.token)
    record=(r.work,r.operation,r.selection_digest,r.fence.scope,r.request,identity,binding,
        prepared_task,request_task,commit_task,binding_task,quote_task,job,lease,reservation,quote,tuple(version_headers),deadline)
    _CONTROLS[r]=record
    return roots,expectations,(binding_task,request_task,commit_task,quote_task)

def _utc_seconds(value):
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

def _observe_numeric_read_clock_v3(reader):
    from .first_ingress_v2 import trusted_upper
    r=require_numeric_read_work_v3(reader)
    if r.db.in_transaction or r.store._lock._is_owned():
        raise AuthorityUnavailable("Numeric real clock observation must precede the Graph lock/SQL snapshot")
    port=r.graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(r.graph._GraphCoordinator__scene_clock_policy))
    observed=time.monotonic()
    if now>=r.operation.deadline_utc or observed>=r.initial_monotonic_deadline:
        raise AuthorityUnavailable("Numeric Host READ exceeded its original retained deadline")
    _OBSERVATIONS[r]=(r.work,r.operation,now,observed,port.installation_grant)
    return now

def _current_read_now(reader):
    observed=_OBSERVATIONS.get(reader)
    if observed is None or observed[:2]!=(reader.work,reader.operation):
        raise AuthorityUnavailable("Numeric READ needs its actual same-Work clock observation before SQL")
    monotonic_now=time.monotonic()
    now=observed[2]+max(0.0,monotonic_now-observed[3])
    if now>=reader.operation.deadline_utc or monotonic_now>=reader.initial_monotonic_deadline:
        raise AuthorityUnavailable("Numeric Host READ exceeded its original retained deadline")
    return now

def require_numeric_draft_control_v3(reader,*,sources=True):
    r=require_numeric_read_work_v3(reader)
    record=_CONTROLS.get(r)
    if record is None or record[:5]!=(r.work,r.operation,r.selection_digest,r.fence.scope,r.request):
        raise AuthorityUnavailable("Numeric draft original point lacks its exact signed metadata recipe")
    if sources:
        if r.numeric_source_permission is None:
            raise AuthorityUnavailable("Numeric draft body requires ALL actual Source/ancestor metadata EOF")
        r.numeric_source_permission.require_for_v1(r)
    with runtime_storage_quantum_v3(r.db)as meter:
        reader.budget_task.require_metadata_v3(meter)
        for key,expected in record[16]:
            current=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(key.token,*r.namespace.as_tuple))
            if current!=expected:raise AuthorityUnavailable("Numeric actual acquired current head metadata changed")
        for task in record[7:12]:task.require_header_v1(meter)
        current=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",_JOB_METADATA,"job_id=?",(record[6].job_id,))
        lease=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_leases",_LEASE_METADATA,
            "lease_id=?",(r.parent_budget_lease_ref,))
        reservation=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_reservations",("state","digest","ceiling_json"),
            "lease_id=? AND operation_id=?",(r.parent_budget_lease_ref,internal_life_numeric_ids_v1(record[5])["prepare"]))
    if (current,lease,reservation)!=(record[12],record[13],record[14])or _current_read_now(r)>=record[-1]:
        raise AuthorityUnavailable("Numeric draft actual worker/root/reservation metadata changed before disclosure")
    return record

def require_numeric_read_point_v3(reader,request):
    r=require_numeric_read_work_v3(reader)
    table,columns,key_columns,key=request
    if table=="graph_atoms" and tuple(columns)==("revision","value","valid") and tuple(key_columns)==("token","bot","persona"):
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)==r.namespace and tuple(key[1:])==r.namespace.as_tuple:
            source=source_key(*r.namespace.as_tuple,atom.owner.subject or "")
            leaf=_GENERAL_METHOD_SOURCE_TASKS_V1.get(r,{}).get(source.token)
            if leaf is not None and leaf.complete and atom in {
                    access_key(*r.namespace.as_tuple,source.owner.subject),
                    source_correction_head_key(r.namespace,source.owner.subject)}:
                with runtime_storage_quantum_v3(r.db)as meter:leaf.require_v1(r,meter)
                return r
    if r.operation_kind in NATIVE_READ_OPERATIONS_V3:
        from .current_life_numeric_native_read_v3 import require_native_numeric_read_point_v3
        return require_native_numeric_read_point_v3(r,request)
    if r.operation_kind not in {DRAFT_READ_V3,CANDIDATE_READ_V3}:
        raise AuthorityUnavailable("Numeric identity READ exposes no protected original point")
    record=require_numeric_draft_control_v3(r)
    ids=internal_life_numeric_ids_v1(record[5])
    if table=="runtime_jobs":
        allowed=(tuple(columns),tuple(key_columns),tuple(key))==(_JOB_COLUMNS,("job_id",),(ids["job"],))
    elif table=="runtime_budget_leases":
        allowed=(tuple(columns),tuple(key_columns),tuple(key))==(_LEASE_COLUMNS,("lease_id",),(r.parent_budget_lease_ref,))
    elif table=="graph_d11_life_originals_v1":
        kinds={"numeric_prepared_v1","numeric_binding_v1","numeric_request_v1","numeric_acquire_commit_v1"}
        allowed=(tuple(columns)in {("producing_operation_id","payload_json","payload_digest","signature"),
            ("payload_json","payload_digest","producing_operation_id")}and tuple(key_columns)==("bot","persona","kind","original_ref")
            and tuple(key[:2])==r.namespace.as_tuple and len(key)==4 and key[2]in kinds and key[3]==ids["job"])
    elif table in {"graph_domain_production_originals_v1","graph_bundle_operations"}:
        allowed=(tuple(key_columns)==("bot","persona","operation_id")and tuple(key[:2])==r.namespace.as_tuple
            and len(key)==3 and key[2]in {ids["prepare"],ids["acquire"]})
        from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
        allowed=allowed and request[:3]in _HOST_ATTACHMENT_SHAPES_V3
    elif table=="graph_history":
        from .d11_types import runtime_job_key
        job_key=runtime_job_key(*r.namespace.as_tuple,r.activity_id,ids["job"])
        allowed=(tuple(key_columns)==("token","revision")and len(key)==2 and key[0]==job_key.token and key[1]in {1,2}
            and tuple(columns)==("event_id","value","valid"))
    elif table=="graph_atoms":
        from .d11_types import runtime_job_key
        allowed=(tuple(key_columns)==("token","bot","persona")and tuple(key)==
            (runtime_job_key(*r.namespace.as_tuple,r.activity_id,ids["job"]).token,*r.namespace.as_tuple)
            and tuple(columns)==("revision","value","valid"))
    else:allowed=False
    if not allowed:raise AuthorityUnavailable("Numeric Host READ point escaped its exact selected job/original/quote recipe")
    return r

def read_bound_numeric_host_job_v3(db,job_id):
    owner=_method_active(db)
    if owner is None or owner.operation_kind not in _NUMERIC_READ_ONLY_OPERATIONS_V3:return False,None
    handled,row=read_bound_method_learning_attachment_v3(db,table="runtime_jobs",columns=_JOB_COLUMNS,key_columns=("job_id",),key=(job_id,))
    from .jobs import _job_from_row
    if row is None:raise AuthorityUnavailable("Numeric Host READ actual job disappeared")
    return handled,_job_from_row(row)

def read_bound_numeric_host_lease_v3(db,lease_id):
    owner=_method_active(db)
    if owner is None or owner.operation_kind not in _NUMERIC_READ_ONLY_OPERATIONS_V3:return False,None
    handled,row=read_bound_method_learning_attachment_v3(db,table="runtime_budget_leases",columns=_LEASE_COLUMNS,key_columns=("lease_id",),key=(lease_id,))
    from .budget import _lease_from_row
    if row is None:raise AuthorityUnavailable("Numeric Host READ actual parent lease disappeared")
    return handled,_lease_from_row(row)

def read_bound_numeric_host_quote_v3(db,issuer,quote_id,version):
    owner=_method_active(db)
    if owner is None or owner.operation_kind not in _NUMERIC_READ_ONLY_OPERATIONS_V3:return False,None
    if owner.operation_kind in NATIVE_READ_OPERATIONS_V3:
        from .current_life_numeric_native_read_v3 import require_native_numeric_read_quote_v3
        return require_native_numeric_read_quote_v3(owner,db,issuer,quote_id,version)
    record=require_numeric_draft_control_v3(owner)
    quote=record[15]
    if issuer is not owner.graph._GraphCoordinator__d02_issuer or (quote_id,version)!=(quote.quote_id,1):
        raise AuthorityUnavailable("Numeric Host READ quote differs from its actual signed selected original")
    return True,quote

class _NumericReadResultV3:
    def __init__(self,reader,value):
        self.reader,self.value=reader,value
        _RESULTS[self]=(reader,reader.work,reader.operation,reader.selection_digest,value)

    def require_result_v3(self,work):
        r=self.reader
        if (_RESULTS.get(self)!=(r,work,r.operation,r.selection_digest,self.value)
                or work.state is not r or not r.complete or not r.read_finished):
            raise AuthorityUnavailable("Numeric Host READ result changed its exact completed Work/EOF")
        return self.value

    def release_payload_v3(self):
        if _RESULTS.pop(self,None)is None:return
        r=self.reader
        if r.operation_kind in NATIVE_READ_OPERATIONS_V3:
            from .current_life_numeric_native_read_v3 import release_native_numeric_read_payloads_v3
            release_native_numeric_read_payloads_v3(r)
        _CONTROLS.pop(r,None);_READ_STATE.pop(r,None);_OBSERVATIONS.pop(r,None)
        _release_method_registered_payloads_v3(r)
        if r.inventory is not None:r.inventory.release_payload_v3()
        r.points.clear();r.inventories.clear();r.input_heads.clear()
        r.numeric_read_value=None;r.result=None;self.value=None


class _NumericCandidateFactsV3:
    def __init__(self,reader,prepared,binding,request,job,draft):
        self.reader=reader
        self.prepared,self.binding,self.request,self.job,self.draft=prepared,binding,request,job,draft
        control=require_numeric_draft_control_v3(reader)
        self.quote=control[15]
        with runtime_storage_quantum_v3(reader.db)as meter:
            self.reserve=_runtime_bounded_fixed_row_v3(reader.db,meter,"runtime_budget_operations",("digest",),
                "bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                (*reader.namespace.as_tuple,prepared.prepare_operation_id))
        self.reservation=(control[14][1],control[14][2],control[14][0])
        from ..authority_service.current_life_numeric_v1 import life_numeric_deadline_bounds_v3
        _,parent=read_bound_method_budget_grant_v3(reader.db,reader.parent_budget_lease_ref)
        self.deadline_bounds=life_numeric_deadline_bounds_v3(prepared,binding,request,job,quote=self.quote,parent=parent)
        self.deadline_bounds+=(("read",reader.operation.deadline_utc),)
        actual=prepared.frozen.appraisal.input
        self.occurrence_bounds=(("occurrence_completed_at",actual.event.occurred_until),
            ("source_recorded_at",actual.sources[0].record.recorded_at))
        from .d06_life_numeric_context_v1 import require_life_numeric_occurrence_time_v3
        require_life_numeric_occurrence_time_v3(_current_read_now(reader),**dict(self.occurrence_bounds))
        self.scope_digest=canonical_digest(
                ("numeric-current-host-candidate.v3",reader.fence.scope.pinned_anchor,
                reader.material_owner_guard,reader.selection_digest,request.digest,binding.digest,
                tuple(control[16]),reader.authority.purpose,reader.authority.audience))
        _CANDIDATE_FACTS[self]=(reader,reader.work,reader.operation,reader.selection_digest,
            prepared,binding,request,job,draft,self.quote,self.reservation,self.reserve,self.deadline_bounds,self.occurrence_bounds,self.scope_digest)

    def qualification_v3(self,now):
        return CurrentLifeNumericCandidateQualificationV3(self.job.job_id,self.request.digest,self.binding.digest,
            self.scope_digest,min(value for _,value in self.deadline_bounds),now,self.deadline_bounds,self.occurrence_bounds)

def require_numeric_candidate_facts_v3(facts,*,installed_reader):
    if type(facts)is not _NumericCandidateFactsV3:
        raise AuthorityUnavailable("Numeric current candidate requires privately issued same-Work facts")
    r=require_numeric_read_work_v3(facts.reader)
    control=require_numeric_draft_control_v3(r)
    expected=(r,r.work,r.operation,r.selection_digest,facts.prepared,facts.binding,facts.request,
        facts.job,facts.draft,facts.quote,facts.reservation,facts.reserve,facts.deadline_bounds,facts.occurrence_bounds,facts.scope_digest)
    if (_CANDIDATE_FACTS.get(facts)!=expected or r.operation_kind!=CANDIDATE_READ_V3
            or installed_reader is not r.request.installed_reader
            or installed_reader.bundle is not r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
            or installed_reader.readers.issuer is not r.graph._GraphCoordinator__d11_issuer
            or installed_reader.read_subject!=facts.binding.worker_subject
            or facts.job.job_id!=r.request.job_id or facts.binding!=control[6]):
        raise AuthorityUnavailable("Numeric candidate facts changed actual installed reader/selected job/Owner/Source EOF")
    return (facts.prepared,facts.binding,facts.request,facts.job,facts.draft,facts.quote,
        facts.reservation,facts.reserve,_current_read_now(r))

def _read_final_value_v3(reader):
    r=require_numeric_read_work_v3(reader)
    if r.operation_kind in NATIVE_READ_OPERATIONS_V3:
        from .current_life_numeric_native_read_v3 import read_native_numeric_read_result_v3
        return read_native_numeric_read_result_v3(r)
    identity=current_numeric_read_identity_v3(r)
    if r.operation_kind==IDENTITY_READ_V3:return identity
    control=require_numeric_draft_control_v3(r)
    from .d06_life_numeric_paid_v1 import life_numeric_model_draft_v1
    metadata,epoch=r.graph._v2_graph_stamp(r.namespace)
    p,b,model,draft=life_numeric_model_draft_v1(r.db,namespace=r.namespace,
        issuer=r.graph._GraphCoordinator__d11_issuer,job_id=r.request.job_id,metadata=metadata,epoch=epoch)
    if (p.frozen.identity!=identity or b!=control[6]or model.digest!=_detach_value_v3(control[8].result)["request_digest"]
            or p.owner_head_digest!=r.material_owner_guard.owner_head_digest
            or (metadata,epoch)!=r.graph_stamp):
        raise AuthorityUnavailable("Numeric current draft differs from its actual signed selected metadata/Owner/Graph")
    r.operation.retain(_heap((p,b,model,draft))*2+65536)
    if r.operation_kind==CANDIDATE_READ_V3:
        from .jobs import get_job
        facts=_NumericCandidateFactsV3(r,p,b,model,get_job(r.db,r.request.job_id),draft)
        try:return r.request.installed_reader.qualify_current_host_candidate_v3(facts=facts,candidate=r.request.candidate)
        finally:_CANDIDATE_FACTS.pop(facts)
    return CurrentLifeNumericModelDraftV3(p,b,model,draft,r.fence.scope.pinned_anchor)

def advance_current_life_numeric_read_v3(graph,work):
    r=require_numeric_read_work_v3(work.state)
    if graph is not r.graph or r.read_finished:raise AuthorityUnavailable("Numeric Host READ advanced after its terminal")
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        _observe_numeric_read_clock_v3(r)
        _prepare_current_general_method_owner_entry_v1(r)
        graph._validate_read_fence_v3(r.fence)
        if r.operation_kind in NATIVE_READ_OPERATIONS_V3 and r.numeric_source_permission is not None and not r.numeric_native_environment_ready:
            from .current_life_numeric_native_read_v3 import observe_native_numeric_read_environment_v3
            observe_native_numeric_read_environment_v3(r)
            r.numeric_native_environment_ready=True
        if not r.inventory_sealed:
            with r.store._lock:r.advance()
            return GraphStorageStepV3("progress")
        if r.pending_input is not None:
            with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
                r.require_current(meter=meter);r.pending_input.advance(meter)
                if r.pending_input.complete:r.pending_input=None
            return GraphStorageStepV3("progress")
        token=_READING.set(r)
        try:
            with bind_prepared_method_learning_read_v3(r.inventory,graph,r.db),r.store._lock:
                r.db.execute("BEGIN")
                try:
                    prepare_numeric_metadata_plan_v1(r)
                    require_numeric_method_sources_v1(r)
                    if r.operation_kind in NATIVE_READ_OPERATIONS_V3 and not r.numeric_native_environment_ready:
                        return GraphStorageStepV3("progress")
                    r.numeric_read_value=_read_final_value_v3(r)
                    _current_read_now(r)
                    r.require_current()
                    r.result=_NumericReadResultV3(r,r.numeric_read_value)
                    r.complete=True
                finally:r.db.rollback()
            _observe_numeric_read_clock_v3(r)
            if r.operation_kind in {DRAFT_READ_V3,CANDIDATE_READ_V3} and _current_read_now(r)>=_CONTROLS[r][-1]:
                raise AuthorityUnavailable("Numeric draft original deadline expired before READ terminal")
            graph._validate_read_fence_v3(r.fence)
            graph._finish_read_fence_v3(r.fence);r.read_finished=True
            return GraphStorageStepV3("complete",r.result)
        except MethodInputNeededV3 as needed:
            kind,actual=needed.request
            with r.store._lock,runtime_storage_quantum_v3(r.db):
                if kind=="numeric_owner_metadata":
                    identity_key=(kind,actual);task=r.attachments.get(identity_key)
                    if task is None:task=NumericMetadataTaskV1(r,actual);r.attachments[identity_key]=task
                elif kind=="general_method_source_metadata":
                    tasks=_GENERAL_METHOD_SOURCE_TASKS_V1.setdefault(r,{})
                    task=tasks.get(actual)
                    if task is None:task=_GeneralMethodSourceMetadataEOFV1(_GENERAL_METHOD_SOURCE_ISSUER_V1,r,actual);tasks[actual]=task
                elif kind=="native_nonseries_metadata":
                    if r.operation_kind not in {JOINT_PREPARED_READ_V3,TRACE_READ_V3}:
                        raise AuthorityUnavailable("Nonseries metadata belongs only to the named Native numeric READ")
                    from .current_life_numeric_native_read_v3 import NativeNonSeriesMetadataTaskV3
                    identity_key=(kind,actual);task=r.attachments.get(identity_key)
                    if task is None:task=NativeNonSeriesMetadataTaskV3(r,actual);r.attachments[identity_key]=task
                elif kind=="native_life_artifact":
                    if r.operation_kind!=TRACE_READ_V3:
                        raise AuthorityUnavailable("Life artifact body belongs only to the named Native trace READ")
                    from .current_life_numeric_native_read_v3 import NativeLifeArtifactTaskV3
                    identity_key=(kind,actual);task=r.attachments.get(identity_key)
                    if task is None:task=NativeLifeArtifactTaskV3(r,actual);r.attachments[identity_key]=task
                elif kind=="native_numeric_trace_dependencies":
                    if r.operation_kind!=TRACE_READ_V3:
                        raise AuthorityUnavailable("Numeric dependencies belong only to the named trace READ")
                    from .current_life_numeric_native_read_v3 import NativeTraceDependenciesTaskV3
                    identity_key=(kind,actual);task=r.attachments.get(identity_key)
                    if task is None:task=NativeTraceDependenciesTaskV3(r,actual);r.attachments[identity_key]=task
                elif kind=="inventory":
                    if r.operation_kind!=TRACE_READ_V3 or r.selected_plan is None or actual not in r.selected_plan.fixed_type_ids:
                        raise AuthorityUnavailable("Numeric inventory lacks its exact current trace plan")
                    from .current_life_numeric_native_read_v3 import require_native_numeric_read_inventory_v3
                    from .current_method_learning_read_v3 import _MethodInventoryReadV3
                    require_native_numeric_read_inventory_v3(r,actual)
                    task=r.inventories.get(actual)
                    if task is None:task=_MethodInventoryReadV3(r,actual);r.inventories[actual]=task
                elif kind=="budget_grant":
                    if actual!=r.parent_budget_lease_ref:raise AuthorityUnavailable("Numeric READ parent grant locator changed")
                    if r.budget_task is None:r.budget_task=_MethodBudgetGrantReadV3(r,actual)
                    task=r.budget_task
                elif kind=="point":
                    require_numeric_read_point_v3(r,actual)
                    task=r.points.get(actual)
                    if task is None:task=_MethodPointReadV3(r,actual);r.points[actual]=task
                else:raise AuthorityUnavailable("unregistered Numeric Host READ selected dependency")
                r.pending_input=task
            return GraphStorageStepV3("progress")
        finally:_READING.reset(token)

def finish_current_life_numeric_read_v3(graph,work,error):
    r=work.state
    try:
        if not r.read_finished:graph._finish_read_fence_v3(r.fence);r.read_finished=True
        if error is None:work.result_lease=work.operation
    finally:
        if error is not None:
            if r.operation_kind in NATIVE_READ_OPERATIONS_V3:
                from .current_life_numeric_native_read_v3 import release_native_numeric_read_payloads_v3
                release_native_numeric_read_payloads_v3(r)
            _CONTROLS.pop(r,None);_READ_STATE.pop(r,None);_OBSERVATIONS.pop(r,None)
            _release_method_registered_payloads_v3(r)
            if r.inventory is not None:r.inventory.release_payload_v3()
            finish_runtime_storage_operation_v3(work.operation)
