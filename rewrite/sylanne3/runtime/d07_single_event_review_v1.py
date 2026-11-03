"""Named actual post-adoption review on the original generic C3 workflow."""
from __future__ import annotations
from dataclasses import dataclass,fields,replace
from weakref import WeakKeyDictionary
from ..graph_types import AtomKey,GraphVersion,GraphWrite,Owner,owner_grant_key
from ..runtime_contracts import NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d01.single_event_review_case_v1 import RegisteredSingleEventReviewCaseV1,CASE_KIND,CASE_SCHEMA
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import MissingProductionOriginalV1
from .d07_execution_v1 import D07PreparedExecutionV1,D07SemanticQuestionV1

REGISTER_OPERATION="register_single_event_review_attention_v1"
ATTENTION_KIND="single_event_review_attention_v1"
QUESTION_PREFIX="single-event-review-question:"
_FIXED_QUESTION=("Review this exact adopted claim only against its authenticated post-adoption observations, "
    "original finite scope, trials and current counterevidence. Use proposition accepted only for sufficient "
    "support without material uncertainty; preserve actual opposition, insufficient evidence and meaningful unknowns. "
    "Repeating the original event or further reflections is not new post-adoption evidence. "
    "Return exactly one continuity finding; when evidence is insufficient, return one unknown judgment.")
_REVIEW_ISSUER=object()
_REVIEW_METADATA=WeakKeyDictionary()
_REVIEW_SOURCE_PROOFS=WeakKeyDictionary()
_CASE_PARENT_COLUMNS=WeakKeyDictionary()

def single_event_review_attention_ids_v1(namespace,case_original):
    if type(case_original)is not ProductionOriginalRefV1 or case_original.kind!="d01."+CASE_KIND:
        raise TypeError("single-event review needs its actual registered Case original")
    tag=canonical_digest((namespace,case_original.kind,case_original.original_ref,case_original.original_digest))[:48]
    return {"question":QUESTION_PREFIX+tag,"attention":"single-event-review-attention:"+tag,
        "ticket":"attention:single-event-review:"+tag,"activity":"single-event-review-cognition:"+tag}

@dataclass(frozen=True,slots=True)
class RegisterSingleEventReviewAttentionRequestV1:
    case_original:ProductionOriginalRefV1
    def __post_init__(self):
        if type(self.case_original)is not ProductionOriginalRefV1 or self.case_original.kind!="d01."+CASE_KIND:
            raise ValueError("review attention accepts only its actual registered Case locator")

@dataclass(frozen=True,slots=True)
class SingleEventReviewAttentionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    registration_operation_id:str
    registration_receipt_digest:str
    semantic_question_ref:str
    semantic_question_digest:str
    question_key:str
    case_original:ProductionOriginalRefV1
    policy_original:ProductionOriginalRefV1
    adoption_original:ProductionOriginalRefV1
    adoption_version:GraphVersion
    review_version:GraphVersion
    ticket_ref:GraphVersion
    ticket_value_digest:str
    context_source_refs:tuple[str,...]
    consolidation_source_refs:tuple[str,...]
    case_source_versions:tuple[GraphVersion,...]
    causal_original:ProductionOriginalRefV1
    causal_operation_id:str
    causal_receipt_digest:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    review_not_before_utc:float
    review_due_utc:float
    readout_valid_until_utc:float
    causal_depth:int
    depth_basis:str
    schema:str="d07.single-event-review-attention.v1"
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _digest
        ids=single_event_review_attention_ids_v1(self.namespace,self.case_original)
        if(self.schema!="d07.single-event-review-attention.v1"or self.original_ref!=ids["attention"]
                or self.semantic_question_ref!=ids["question"]or self.ticket_ref.key.name!=ids["ticket"]
                or self.ticket_ref.key.type_name!="d07.attention_ticket.v1"or self.ticket_ref.revision!=1
                or NamespaceId.from_key(self.ticket_ref.key)!=self.namespace
                or type(self.causal_depth)is not int or not 0<=self.causal_depth<2
                or self.depth_basis!="actual_registered_post_adoption_experience_v1"):
            raise ValueError("review attention lost its actual registered Case, ticket or causal stage")
        roots=tuple(dict.fromkeys((*self.context_source_refs,*self.consolidation_source_refs)))
        if not roots or len(roots)>16:
            raise ValueError("review attention retains the original bounded context/consolidation Source groups")
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!="memory.source"or NamespaceId.from_key(key)!=self.namespace:
                raise ValueError("review attention changed its actual Source namespace")
        for value in (self.registration_receipt_digest,self.semantic_question_digest,self.ticket_value_digest,
                self.causal_receipt_digest,self.original_parent_grant_digest):_digest(value)
        if not self.review_not_before_utc<min(self.review_due_utc,self.original_deadline_utc)<=self.readout_valid_until_utc:
            raise ValueError("review attention cannot renew the original review window")

@dataclass(frozen=True,slots=True,kw_only=True)
class D07SingleEventReviewPreparedV1(D07PreparedExecutionV1):
    semantic_question_ref:str
    semantic_question_digest:str
    review_attention_ref:str
    review_attention_digest:str
    review_case_original:ProductionOriginalRefV1
    policy_original:ProductionOriginalRefV1
    adoption_original:ProductionOriginalRefV1
    adoption_version:GraphVersion
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    review_not_before_utc:float
    review_due_utc:float
    readout_valid_until_utc:float
    causal_original:ProductionOriginalRefV1
    causal_operation_id:str
    causal_receipt_digest:str
    causal_depth:int
    depth_basis:str
    context_source_refs:tuple[str,...]
    consolidation_source_refs:tuple[str,...]
    case_source_versions:tuple[GraphVersion,...]
    case_control_heads:tuple[tuple[GraphVersion,bool],...]
    schema:str="d07.single-event-review-prepared.v1"
    @property
    def digest(self):return canonical_digest(plain_v1(self))
    def __post_init__(self):
        from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
        from .domain_background_read_v3 import background_json_loads_v3
        frozen=thaw_d07_cognition_request_v1(background_json_loads_v3(self.frozen_json));value=frozen.input
        ids=single_event_review_attention_ids_v1(self.namespace,self.review_case_original)
        if(self.schema!="d07.single-event-review-prepared.v1"or self.work_kind!="concern"or self.purpose!="context"
                or self.semantic_question_ref!=ids["question"]or self.review_attention_ref!=ids["attention"]
                or type(self.causal_depth)is not int or not 0<=self.causal_depth<2
                or value.causal_depth!=self.causal_depth
                or value.target_original_kind!=CASE_KIND
                or value.target_ref!=self.review_case_original.original_ref
                or value.target_original_digest!=self.review_case_original.original_digest
                or self.depth_basis!="actual_registered_post_adoption_experience_v1"
                or tuple(item.source_ref.ref for item in value.sources)!=self.context_source_refs):
            raise ValueError("review preparation differs from its actual generic frozen Case or original depth cap")
        if(type(self.case_control_heads)is not tuple or len(self.case_control_heads)>1024
                or any(type(v)is not GraphVersion or v.revision<0 or NamespaceId.from_key(v.key)!=self.namespace
                    or type(valid)is not bool or v.key.type_name.startswith(("runtime.","d02.","d07."))
                    for v,valid in self.case_control_heads)):
            raise ValueError("review preparation lost its exact current metadata control readset")
        case=_case_from_wire_v1(background_json_loads_v3(value.target_original_json))
        if(case.policy_original!=self.policy_original or case.adoption_original!=self.adoption_original
                or case.adoption_version!=self.adoption_version or case.source_versions!=self.case_source_versions
                or case.causal_original!=self.causal_original or case.causal_operation_id!=self.causal_operation_id
                or case.causal_receipt_digest!=self.causal_receipt_digest
                or case.original_parent_budget_lease_ref!=self.original_parent_budget_lease_ref
                or case.original_parent_grant_digest!=self.original_parent_grant_digest
                or self.original_deadline_utc>case.original_deadline_utc
                or self.review_not_before_utc!=case.review_not_before_utc or self.review_due_utc!=case.review_due_utc
                or self.readout_valid_until_utc!=case.readout_valid_until_utc):
            raise ValueError("review preparation changed the actual signed policy/adoption/cause/resource window")

def _case_from_wire_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,RegisteredSingleEventReviewCaseV1)

def _actual_review_method_v1(reader,meter=None):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    if(type(reader)is not _MethodLearningReadV3 or reader.fence.scope.operation!="read"
            or reader.authority.purpose!="context"):
        raise ValueError("review metadata requires its actual same-command context Method READ Work")
    if reader.operation_kind==REGISTER_OPERATION:
        if type(reader.request)is not RegisterSingleEventReviewAttentionRequestV1:
            raise TypeError("exact installed review registration request required")
    elif(reader.operation_kind!="serve_concern"or type(reader.request)is not ServeCurrentConcernRequestV1
            or reader.request.category!="background"):
        raise ValueError("review metadata is outside its two installed operations")
    reader.require_current(meter=meter)
    return reader

def require_actual_single_event_review_case_metadata_work_v1(reader):
    _actual_review_method_v1(reader)
    if reader.operation_kind==REGISTER_OPERATION:return reader
    task=_REVIEW_METADATA.get(reader)
    if task is None or not task.complete:
        raise ValueError("generic Serve has no actual signed named review Question/Attention/ticket")
    task.require_current_v1()
    return reader

class _SingleEventReviewSourcePermissionV1:
    def __init__(self,issuer,reader,roots,records,versions):
        if issuer is not _REVIEW_ISSUER:raise TypeError("actual same-Work review Source issuer required")
        self.reader,self.roots=reader,roots
        self.source_refs=tuple(sorted(records));self.versions=tuple(sorted(versions.values(),key=lambda v:v.key.token))
        self.owner_entry=reader.general_owner_entry
        _REVIEW_SOURCE_PROOFS[self]=(reader,reader.work,reader.operation,reader.graph_stamp,
            reader.fence.scope,reader.authority,reader.operation.selection_digest,self.owner_entry,roots,self.source_refs,self.versions)
    def require_for_v1(self,reader,roots):
        require_actual_single_event_review_case_metadata_work_v1(reader)
        if _REVIEW_SOURCE_PROOFS.get(self)!=(reader,reader.work,reader.operation,reader.graph_stamp,
                reader.fence.scope,reader.authority,reader.operation.selection_digest,reader.general_owner_entry,
                tuple(sorted(set(roots))),self.source_refs,self.versions):
            raise ValueError("review Source capability left its actual Method Work, Owner or group roots")
        _require_review_owner_groups_v1(reader)
        from .current_method_learning_read_v3 import qualify_method_source_metadata_kernel_v1
        records,versions=qualify_method_source_metadata_kernel_v1(reader,self.roots,purposes=("context","consolidation"))
        if(tuple(sorted(records)),tuple(sorted(versions.values(),key=lambda v:v.key.token)))!=(self.source_refs,self.versions):
            raise ValueError("review context/consolidation Source closure changed before actual Body")
        return self

_REVIEW_SOURCES=WeakKeyDictionary()
def require_current_single_event_review_case_sources_v1(reader,roots):
    require_actual_single_event_review_case_metadata_work_v1(reader)
    roots=tuple(sorted(set(roots)))
    if reader.general_owner_entry is None or reader.selected_plan is None or not set(roots)<=set(reader.selected_plan.source_roots):
        raise ValueError("review Source groups have no actual selected plan and independent current MetaOwner")
    if reader.operation_kind==REGISTER_OPERATION:case_original=reader.request.case_original
    else:case_original=_REVIEW_METADATA[reader].attention.case_original
    from .d01_single_event_review_case_v1 import read_registered_single_event_review_case_metadata_v1
    metadata,original=read_registered_single_event_review_case_metadata_v1(reader.db,namespace=reader.namespace,
        case_original=case_original,issuer=reader.graph._GraphCoordinator__d11_issuer)
    if roots!=tuple(sorted(set((*metadata["support_source_refs"],*metadata["context_source_refs"])))):
        raise ValueError("review Source roots differ from its exact actual signed Case metadata")
    prior=_REVIEW_SOURCES.get(reader)
    if prior is not None:return prior.require_for_v1(reader,roots)
    from .current_method_learning_read_v3 import qualify_method_source_metadata_kernel_v1
    _require_review_owner_groups_v1(reader)
    records,versions=qualify_method_source_metadata_kernel_v1(reader,roots,purposes=("context","consolidation"))
    proof=_SingleEventReviewSourcePermissionV1(_REVIEW_ISSUER,reader,roots,records,versions)
    _REVIEW_SOURCES[reader]=proof
    return proof.require_for_v1(reader,roots)



class _SingleEventCaseParentColumnV1:
    """Complete D01 raw HMAC and canonical EOF, retaining only registered Case controls."""
    def __init__(self,task,*,side):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.task,self.side=task,side;self.reader,self.work=task.reader,task.work
        raw=task.raw;original=_decode_original_v1(raw["review_case_original"])
        self.original,self.namespace=original,self.work.namespace
        self.table="graph_d01_production_inputs_v1";self.column="payload_json"
        self.key_columns=("bot","persona","original_ref");self.key=(*self.namespace.as_tuple,original.original_ref)
        self.phase="header";self.metadata=None;self.verifier=None;self.total=None;self.offset=0
        self.parser=C09CanonicalJSONStreamV2();self.builder=_CanonicalJSONValueBuilderV3()
        self.builder.operation=self.work.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.fields_seen=set();self.fragment=b"";self.fragment_offset=0
        self.value=None;self.sha256=None;self.eof=False;self.complete=False
        _CASE_PARENT_COLUMNS[self]=(task,self.reader,self.work,self.namespace,original,self.work.operation)
        self.require_current_v1()
    def require_current_v1(self,meter=None):
        if _CASE_PARENT_COLUMNS.get(self)!=(self.task,self.reader,self.work,self.namespace,self.original,self.work.operation):
            raise ValueError("review Case signature column has no actual private parent-task identity")
        _require_single_event_parent_task_v1(self.task,self.side,meter)
        if(self.task.raw["schema"]!="d07.single-event-review-prepared.v1"
                or _decode_original_v1(self.task.raw["review_case_original"])!=self.original
                or getattr(self.task,"single_event_review_phase",None)!="case"):
            raise ValueError("review Case parent is outside its exact signed prepared selector phase")
        return self
    def _emit(self,event):
        from .d01_single_event_growth_v1 import single_event_metadata_paths_v1
        if len(event.path)==1:self.fields_seen.add(event.path[0])
        if single_event_metadata_paths_v1(self.table,CASE_KIND,event.path):
            self.builder._emit(event)
    def _header_v1(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        self.require_current_v1(meter)
        header=_runtime_bounded_fixed_row_v3(self.work.db,meter,self.table,
            ("kind","producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND original_ref=?",self.key)
        if(header is None or header[0]!=CASE_KIND or header[2]!=self.original.original_digest
                or self.metadata is not None and header!=self.metadata):
            raise ValueError("review Case signed metadata pointer changed before complete EOF")
        return header
    def advance_v3(self,meter):
        from .d01_production_operations_v1 import SIGN_KIND
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        self.metadata=self._header_v1(meter)
        if self.complete:return
        signer=_single_event_parent_signer_v1(self.task,self.side)
        if self.phase=="header":
            self.verifier=signer.begin_original_stream_verification_v3(SIGN_KIND,self)
            self.phase="bytes";return
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            part=self.fragment[self.fragment_offset:end]
            self.verifier.update(part);self.parser.feed(part,self._emit);self.fragment_offset=end;return
        with legacy_cell_read_transaction_v2(self.work.db):
            if self.total is None:
                row=self.work.db.execute("SELECT length(CAST(payload_json AS BLOB)) FROM graph_d01_production_inputs_v1 "
                    "WHERE bot=? AND persona=? AND original_ref=?",self.key).fetchone()
                meter.charge_read(16);self.total=row[0]
                if self.total>8192:raise MissingProductionOriginalV1("original_generic_single_event_target_bytes")
            if self.offset<self.total:
                part,total,kind=read_legacy_sql_cell_fragment_v2(self.work.db,table=self.table,column=self.column,
                    where="bot=? AND persona=? AND original_ref=?",parameters=self.key,start=self.offset,
                    length=min(16384,self.total-self.offset),meter=meter)
                if (total,kind)!=(self.total,"text"):raise ValueError("review Case signature column changed")
                self.offset+=len(part);self.fragment=part;self.fragment_offset=0;return
        parsed=self.parser.finish();self.sha256=parsed.sha256;self.eof=True
        if(parsed.sha256,parsed.byte_count)!=(self.metadata[2],self.total)or self.builder.nodes:
            raise ValueError("review Case signature column failed whole canonical EOF")
        if self.fields_seen!={field.name for field in fields(RegisteredSingleEventReviewCaseV1)}:
            raise ValueError("review Case signature column has an unknown closed payload field")
        signer.finish_original_stream_verification_v3(SIGN_KIND,self.metadata[3],self,self.verifier)
        value=_detach_value_v3(self.builder.value)
        if(value["schema"]!=CASE_SCHEMA or value["namespace"]!=plain_v1(self.namespace)
                or value["registration_operation_id"]!=self.metadata[1]):
            raise ValueError("review Case signed controls changed the registered W01 producer")
        self.value=value;self.complete=True
        self.fragment=b"";self.parser=self.builder=self.verifier=None
    def require_v3(self,work):
        self.require_current_v1()
        if work is not self.work or not self.complete:
            raise ValueError("review Case controls have no complete actual parent-column proof")
        return self.value

def _decode_original_v1(value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(value,ProductionOriginalRefV1)

def _require_single_event_parent_task_v1(task,side,meter=None):
    if side=="host":
        from .d07_stage_content_scope_v3 import _HostSpecialParentMetadataReadV3
        if type(task)is not _HostSpecialParentMetadataReadV3:
            raise TypeError("actual Host review parent task required")
    elif side=="authority":
        from ..authority_service.d07_authority_model_source_read_v3 import _D07SpecialParentMetadataReadV3
        if type(task)is not _D07SpecialParentMetadataReadV3:
            raise TypeError("actual Authority review parent task required")
    else:raise ValueError("unregistered single-event review parent side")
    task.reader.require_registered_v3()
    if meter is not None:task.reader.require_current_v3(meter)
    task.header.require_v3(task.reader)
    return task

def _single_event_parent_signer_v1(task,side):
    _require_single_event_parent_task_v1(task,side)
    return(task.work.d07_service.d11_issuer._signer if side=="host"else
        task.work.controller.verifier._issuer._signer)

def require_single_event_case_parent_signature_column_v1(column,*,signer,kind,signature=None,verifier=None,complete=False):
    from .d01_production_operations_v1 import SIGN_KIND
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if type(column)is not _SingleEventCaseParentColumnV1 or kind!=SIGN_KIND:
        raise ValueError("review Case signature needs its exact actual fixed parent column")
    column.require_current_v1()
    if signer is not _single_event_parent_signer_v1(column.task,column.side):
        raise ValueError("review Case signature crossed its actual installed Host/Authority issuer")
    with runtime_storage_quantum_v3(column.work.db)as meter:column._header_v1(meter)
    if complete and(not column.eof or signature!=column.metadata[3]or verifier is not column.verifier):
        raise ValueError("review Case signature terminal has no same-column complete EOF/verifier")
    return column



class _ReviewSignedMetadataV1:
    def __init__(self,task,kind,ref):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.task,self.reader,self.kind,self.ref=task,task.reader,kind,ref
        if kind=="adopted":
            if(type(task)is not _SingleEventReviewInterpretationCaseMetadataV1
                    or _REVIEW_INTERPRETATION_CASE_TASKS_V1.get(task.reader)is not task):
                raise ValueError("adopted controls require the actual private Owner Review selector task")
        elif kind not in {"semantic_question",ATTENTION_KIND,"prepared"}:
            raise ValueError("unknown review metadata family")
        self.parser=C09CanonicalJSONStreamV2();self.builder=_CanonicalJSONValueBuilderV3()
        self.builder.operation=self.reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.header=None;self.total=None;self.offset=0;self.fragment=b"";self.fragment_offset=0
        self.fields_seen=set();self.value=None;self.complete=False
    def _emit(self,event):
        if len(event.path)==1:self.fields_seen.add(event.path[0])
        keep=not event.path or self.kind==ATTENTION_KIND
        if self.kind=="semantic_question":keep=not event.path or event.path[0]in {"schema","question_key","target_ref","source_refs"}
        if self.kind=="prepared":
            keep=not event.path or event.path[0]in {"schema","namespace","operation_id","activity_id","job_id","call_id","execution_id",
                "semantic_question_ref","semantic_question_digest","review_case_original"}
        if self.kind=="adopted":
            keep=not event.path or event.path[0]in (_REVIEW_ADOPTED_CONTROL_FIELDS_V1-{"meaningful_unknowns"})
        if keep:self.builder._emit(event)
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from .d07_execution_v1 import SIGN_KIND
        self.task.require_current_v1();r=self.reader
        header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",("payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,self.kind,self.ref))
        if header is None:raise MissingProductionOriginalV1("actual_signed_single_event_review_metadata")
        if self.header is not None and self.header!=header:raise ValueError("review signed metadata changed across EOF")
        self.header=header
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.fragment_offset:end],self._emit);self.fragment_offset=end;return False
        with legacy_cell_read_transaction_v2(r.db):
            if self.total is None:
                row=r.db.execute("SELECT length(CAST(payload_json AS BLOB)) FROM graph_d07_execution_originals_v1 "
                    "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,self.kind,self.ref)).fetchone()
                meter.charge_read(16);self.total=row[0]
            if self.offset<self.total:
                part,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_d07_execution_originals_v1",
                    column="payload_json",where="bot=? AND persona=? AND kind=? AND original_ref=?",
                    parameters=(*r.namespace.as_tuple,self.kind,self.ref),start=self.offset,
                    length=min(16384,self.total-self.offset),meter=meter)
                if(total,kind)!=(self.total,"text"):raise ValueError("review original column changed before EOF")
                self.offset+=len(part);self.fragment=part;self.fragment_offset=0;return False
        parsed=self.parser.finish()
        if (parsed.sha256,parsed.byte_count)!=(header[0],self.total)or self.builder.nodes:
            raise ValueError("review signed control metadata failed whole canonical EOF")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,self.kind,self.ref,header[0])),header[1])
        value=_detach_value_v3(self.builder.value)
        if self.kind=="prepared":
            from .d07_stage_content_scope_v3 import _host_prepared_class_v3
            from .d07_execution_v1 import D07IngressRecallPreparedV1
            cls=(D07IngressRecallPreparedV1 if value["schema"]=="d07.ingress-recall-prepared.v1"
                else _host_prepared_class_v3(value["schema"]))
        elif self.kind=="adopted":cls=None
        else:cls=D07SemanticQuestionV1 if self.kind=="semantic_question"else SingleEventReviewAttentionOriginalV1
        expected=(_REVIEW_ADOPTED_CONTROL_FIELDS_V1 if cls is None else {f.name for f in fields(cls)})
        if self.fields_seen!=expected:
            raise ValueError("review signed control original has another closed field set")
        self.value=value;self.complete=True;self.fragment=b"";self.parser=self.builder=None
        return True

class _SingleEventReviewConcernMetadataV1:
    def __init__(self,reader,identity):
        _actual_review_method_v1(reader)
        if reader.operation_kind!="serve_concern"or identity!=(reader.request.trigger_original_ref,):
            raise ValueError("review metadata task differs from its actual Serve command")
        self.reader,self.identity=reader,identity
        self.census=(reader.work,reader.operation,reader.graph_stamp,reader.authority_epochs,reader.fence.scope,
            reader.request,reader.operation.selection_digest)
        self.phase="question";self.complete=False;self.question=None;self.attention=None
        self.leaf=_ReviewSignedMetadataV1(self,"semantic_question",identity[0])
        self.prepared_after="";self.prepared_count=0;self.prepared_originals=()
        self.prior_case_originals=();self.prepared_fingerprints=()
        self.fair_heads=();self.fair_tickets=();self.fair_index=0;self.fair_task=None
    def require_current_v1(self):
        r=_actual_review_method_v1(self.reader)
        if self.census!=(r.work,r.operation,r.graph_stamp,r.authority_epochs,r.fence.scope,r.request,r.operation.selection_digest):
            raise ValueError("review metadata left its actual same-command Method census")
        return r
    def advance(self,meter):
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.require_current_v1()
        if self.complete:return True
        if self.phase in {"question","attention","prepared"}:
            if not self.leaf.advance(meter):return False
            value=self.leaf.value
            if self.phase=="question":
                if value["schema"]!="d07.registered-semantic-question.v1"or not self.identity[0].startswith(QUESTION_PREFIX):
                    raise ValueError("review Serve has no actual named generic Question")
                self.question=(value,self.leaf.header[0])
                attention_ref="single-event-review-attention:"+self.identity[0].removeprefix(QUESTION_PREFIX)
                self.leaf=_ReviewSignedMetadataV1(self,ATTENTION_KIND,attention_ref);self.phase="attention";return False
            if self.phase=="attention":
                a=decode_typed_production_value_v1(value,SingleEventReviewAttentionOriginalV1);q,qdigest=self.question
                if(a.namespace!=r.namespace or a.semantic_question_ref!=self.identity[0]or a.semantic_question_digest!=qdigest
                        or a.question_key!=q["question_key"]or q["target_ref"]!={"ref":a.case_original.original_ref,"version":1}
                        or tuple(q["source_refs"])!=a.context_source_refs):
                    raise ValueError("review Question/Attention/case/Source columns are not its actual signed pair")
                self.attention=a;self.attention_digest=self.leaf.header[0];self.phase="ticket";self.leaf=None;return False
            self.prepared_fingerprints+=((self.leaf.ref,*self.leaf.header),)
            if value["schema"]=="d07.single-event-review-prepared.v1":
                if value["namespace"]!=plain_v1(r.namespace)or value["job_id"]!=self.leaf.ref:
                    raise ValueError("review Prepared census has another actual namespace or job")
                original=_decode_original_v1(value["review_case_original"])
                if original not in self.prior_case_originals:self.prior_case_originals+=(original,)
                if (original.kind,original.original_ref,original.original_digest)==(self.attention.case_original.kind,
                        self.attention.case_original.original_ref,self.attention.case_original.original_digest):
                    if(value["semantic_question_ref"],value["semantic_question_digest"])!=(self.identity[0],self.question[1]):
                        raise ValueError("review Case was prepared from another actual signed Question")
                    self.prepared_originals+=((value,self.leaf.ref,self.leaf.header),)
            self.prepared_after=self.leaf.ref;self.prepared_count+=1;self.leaf=None;self.phase="prepared_census";return False
        if self.phase=="ticket":
            a=self.attention
            head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(a.ticket_ref.key.token,*r.namespace.as_tuple))
            history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",(a.ticket_ref.key.token,a.ticket_ref.revision))
            producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,a.registration_operation_id))
            if(head is None or head[:2]!=(a.ticket_ref.revision,1)
                    or history!=(*r.namespace.as_tuple,a.registration_operation_id,1)
                    or producer is None or type(producer[3])is not int or producer[3]<1):
                raise ValueError("review named ticket has no actual current same-W01 registered producer")
            self.ticket_head=head
            self.fair_heads=tuple((AtomKey.from_token(token),value)for token,value in sorted(r.heads.items())
                if value[1]and AtomKey.from_token(token).type_name=="d07.attention_ticket.v1")
            if len(self.fair_heads)>128:raise MissingProductionOriginalV1("bounded_complete_review_fair_ticket_metadata")
            self.phase="fair_tickets";return False
        if self.phase=="fair_tickets":
            if self.fair_index<len(self.fair_heads):
                if self.fair_task is None:self.fair_task=_ReviewFairTicketMetadataV1(r,*self.fair_heads[self.fair_index])
                if self.fair_task.advance(meter):
                    self.fair_tickets+=(self.fair_task.result,);self.fair_index+=1;self.fair_task=None
                return False
            own=next((atom for atom in self.fair_tickets if atom.key==self.attention.ticket_ref.key),None)
            if own is None or canonical_digest(own.value)!=self.attention.ticket_value_digest:
                raise ValueError("review fair ticket metadata changed its actual signed member")
            self.phase="prepared_census";return False
        if self.phase=="prepared_census":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",("original_ref",),
                "bot=? AND persona=? AND kind='prepared' AND original_ref>? ORDER BY original_ref",
                (*r.namespace.as_tuple,self.prepared_after))
            if row is not None:
                if self.prepared_count>=128:raise MissingProductionOriginalV1("bounded_complete_review_prepared_census")
                self.leaf=_ReviewSignedMetadataV1(self,"prepared",row[0]);self.phase="prepared";return False
            self.complete=True;_REVIEW_METADATA[r]=self
            return True
        raise ValueError("unregistered review metadata phase")

def create_single_event_review_concern_metadata_task_v1(reader,identity):
    return _SingleEventReviewConcernMetadataV1(reader,identity)

def prepare_single_event_review_concern_metadata_v1(reader):
    _actual_review_method_v1(reader)
    task=_REVIEW_METADATA.get(reader)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(reader,("single_event_review_concern_metadata",(reader.request.trigger_original_ref,)))
    task.require_current_v1();return task

def release_single_event_review_concern_metadata_v1(reader):
    release_current_single_event_review_cause_history_v1(reader)
    task=_REVIEW_METADATA.pop(reader,None)
    if task is not None:
        task.question=task.attention=task.leaf=task.fair_task=None
        task.prepared_originals=task.fair_heads=task.fair_tickets=()
        task.prior_case_originals=task.prepared_fingerprints=()
    proof=_REVIEW_SOURCES.pop(reader,None)
    if proof is not None:_REVIEW_SOURCE_PROOFS.pop(proof,None)



class InstalledD07SingleEventReviewReadersV1:
    def __init__(self,*,issuer,bundle,graph):
        from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
        service=graph._GraphCoordinator__d07_execution_service_v1
        if(type(service)is not InstalledD07ExecutionServiceV1 or service.bundle is not bundle
                or issuer is not service.d11_issuer):
            raise TypeError("review attention needs this actual installed generic cognition service")
        self.issuer,self.bundle,self.graph=issuer,bundle,graph
        self.execution_reader=service

def read_plan_register_single_event_review_attention_v1(db,*,namespace,request,installed_readers):
    from .d01_single_event_review_case_v1 import read_plan_registered_single_event_review_case_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d07 import attention_ticket_key
    if type(request)is not RegisterSingleEventReviewAttentionRequestV1 or type(installed_readers)is not InstalledD07SingleEventReviewReadersV1:
        raise TypeError("exact installed review registration plan required")
    from .current_method_learning_read_v3 import _method_active
    prepare_current_single_event_review_novelty_v1(_method_active(db),request.case_original)
    plan=read_plan_registered_single_event_review_case_v1(db,namespace=namespace,
        case_original=request.case_original,issuer=installed_readers.issuer)
    ids=single_event_review_attention_ids_v1(namespace,request.case_original)
    return production_read_plan_v1(plan.fixed_type_ids,(*plan.exact_keys,attention_ticket_key(namespace,ids["ticket"])),
        plan.source_roots,plan.required_original_refs)

def _current_review_case_v1(db,*,frame,case_original,issuer):
    from .d01_single_event_review_case_v1 import (read_registered_single_event_review_case_metadata_v1,
        require_registered_single_event_review_case_target_v1)
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db);require_actual_single_event_review_case_metadata_work_v1(reader)
    metadata,original=read_registered_single_event_review_case_metadata_v1(db,namespace=reader.namespace,
        case_original=case_original,issuer=issuer)
    roots=tuple(dict.fromkeys((*metadata["support_source_refs"],*metadata["context_source_refs"])))
    require_current_single_event_review_case_sources_v1(reader,roots)
    case,actual,versions=require_registered_single_event_review_case_target_v1(db,frame=frame,
        case_ref=original.original_ref,issuer=issuer)
    if (actual.kind,actual.original_ref,actual.original_digest)!=(original.kind,original.original_ref,original.original_digest) or (actual.kind,actual.original_ref,actual.original_digest)!=(case_original.kind,
            case_original.original_ref,case_original.original_digest):
        raise ValueError("review Case Body differs from its independently selected signed original")
    return case,actual,versions

def _review_question_key_v1(db,frame,case):
    from .d01_single_event_growth_v1 import single_event_review_question_v1
    from ..domains.d01.single_event_growth_v1 import SingleEventGrowthAdoptionV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    atom=CurrentDomainReadV1(frame).head(db,case.adoption_version.key,required=True)
    if atom.revision!=case.adoption_version.revision or canonical_digest(atom.value)!=case.adoption_value_digest:
        raise ValueError("review Question lost its exact adopted single event")
    adoption=decode_typed_production_value_v1(atom.value,SingleEventGrowthAdoptionV1)
    return single_event_review_question_v1(adoption,case.input_original.original_digest)

def _review_independent_depth_v1(case):
    # Structural check only. New depth-zero issuance also requires the actual READ novelty proof.
    matches=tuple(row for row in case.post_adoption_scope_bindings if row.producer_original==case.causal_original)
    if not any(row.observer_originals and row.occurred_at_utc>case.adoption_recorded_at_utc
            and row.outcome_version in case.post_adoption_evidence_versions
            and case.post_adoption_evidence_originals[case.post_adoption_evidence_versions.index(row.outcome_version)].original_ref==row.outcome_version.key.token
            for row in matches):
        raise MissingProductionOriginalV1("actual_independent_post_adoption_experience_cause")
    return 0,"actual_registered_post_adoption_experience_v1"

def stage_register_single_event_review_attention_v1(db,*,frame,request,installed_readers):
    from .d01_production_operations_v1 import CurrentDomainReadV1,waiting_stage_v1
    from ..domains.d01.production_operations_v1 import stage_result_v1
    from ..domains.d07 import AttentionTicket,attention_ticket_key
    from .budget import get_budget_lease,require_budget_family_admissible
    if type(request)is not RegisterSingleEventReviewAttentionRequestV1 or type(installed_readers)is not InstalledD07SingleEventReviewReadersV1:
        raise TypeError("review attention requires its actual closed installed producer")
    try:
        read=CurrentDomainReadV1(frame);read.check(db)
        case,original,_=_current_review_case_v1(db,frame=frame,case_original=request.case_original,issuer=installed_readers.issuer)
        if(frame.envelope.authority.purpose!="context"or frame.envelope.authority.namespace!=case.namespace
                or frame.envelope.parent_budget_lease_ref!=case.original_parent_budget_lease_ref):
            raise ValueError("review registration cannot change its original Source purpose/namespace/parent")
        from .current_method_learning_read_v3 import _method_active
        novelty=require_current_single_event_review_novelty_v1(_method_active(db),original)
        depth,basis=novelty.independent_depth_v1(_method_active(db),case)
        workflow=installed_readers.execution_reader._configured()
        from ..model_broker.d07_cognition_v1 import TEMPLATE_VERSION
        if(workflow.template_version!=TEMPLATE_VERSION
                or workflow.work_kind!="d07.cognition"or workflow.purpose!="proposal"
                or not set(frame.envelope.authority.audience)<=set(workflow.audiences)):
            raise MissingProductionOriginalV1("actual_generic_single_event_review_workflow")
        lease=get_budget_lease(db,case.original_parent_budget_lease_ref);require_budget_family_admissible(db,lease.lease_id)
        grant=installed_readers.issuer.current_budget_grant(db,lease.lease_id)
        if(canonical_digest(grant)!=case.original_parent_grant_digest or "d07.cognition"not in grant.allowed_work_kinds
                or any(v>min(lease.available(k),grant.max_ceiling.get(k,0))for k,v in workflow.quote_ceiling.items())):
            raise MissingProductionOriginalV1("actual_original_single_event_review_resources")
        deadline=min(frame.envelope.deadline_utc,case.original_deadline_utc,case.review_due_utc,
            case.readout_valid_until_utc,grant.valid_until_utc)
        if not case.review_not_before_utc<=frame.now_utc<deadline:
            raise MissingProductionOriginalV1("actual_original_single_event_review_window")
        ids=single_event_review_attention_ids_v1(case.namespace,original);key=attention_ticket_key(case.namespace,ids["ticket"])
        if read.head(db,key).revision:raise MissingProductionOriginalV1("actual_single_event_review_attention_already_registered")
        roots=tuple(dict.fromkeys((*case.support_source_refs,*case.context_source_refs)))
        question=D07SemanticQuestionV1(_review_question_key_v1(db,frame,case),_FIXED_QUESTION,VersionedRef(case.case_ref,1),roots)
        ticket=AttentionTicket(ids["ticket"],question.question_key,None,roots[0],"background",
            0.,0.,0.,0.,0.,0.,0.,0.,0.,frame.snapshot.epochs[0].revision,deadline,True,True,(),roots)
        write=GraphWrite(key,{"schema":key.type_name,**plain_v1(ticket)},
            tuple(AtomKey.from_token(ref)for ref in roots))
        return stage_result_v1(frame,"d07",REGISTER_OPERATION,request,writes=(write,),provenance={
            "single_event_review_case":case,"single_event_review_case_original":original,
            "single_event_review_question":question,"single_event_review_ticket":ticket,
            "causal_depth":depth,"depth_basis":basis},
            receiver_events=(("d07","single_event_review_attention_available_for_service"),))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame,"d07",REGISTER_OPERATION,request,missing)

def record_single_event_review_attention_after_cas_v1(db,issuer,stage,receipt):
    from .d07_execution_v1 import record_d07_original_in_transaction_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_background_read_v3 import background_json_loads_v3
    from ..domains.d07 import AttentionTicket
    if stage.operation_kind!=REGISTER_OPERATION:return None
    if stage.coverage!="complete":return None
    from ..runtime_contracts import CommitReceipt
    if(type(receipt)is not CommitReceipt or receipt.status!="committed"or receipt.operation_id!=stage.operation_id):
        raise ValueError("review attention needs its actual same-W01 CAS receipt")
    payload=background_json_loads_v3(stage.original_payload_json)["provenance"]
    case=_case_from_wire_v1(payload["single_event_review_case"])
    original=decode_typed_production_value_v1(payload["single_event_review_case_original"],ProductionOriginalRefV1)
    question=decode_typed_production_value_v1(payload["single_event_review_question"],D07SemanticQuestionV1)
    ticket=decode_typed_production_value_v1(payload["single_event_review_ticket"],AttentionTicket)
    ids=single_event_review_attention_ids_v1(case.namespace,original)
    writes=tuple(w for p in stage.proposals for w in p.typed_writes)
    if len(writes)!=1 or len(receipt.write_versions)!=1 or receipt.write_versions[0].key!=writes[0].key or receipt.write_versions[0].revision!=1:
        raise ValueError("review attention has no exact first actual ticket member")
    history=db.execute("SELECT event_bot,event_persona,event_id,valid FROM graph_history WHERE token=? AND revision=?",
        (writes[0].key.token,1)).fetchone()
    if history!=(*case.namespace.as_tuple,stage.operation_id,1):
        raise ValueError("review attention ticket lacks its actual same-event history")
    qdigest=record_d07_original_in_transaction_v1(db,issuer,case.namespace,"semantic_question",ids["question"],plain_v1(question))
    value=SingleEventReviewAttentionOriginalV1(case.namespace,ids["attention"],stage.operation_id,canonical_digest(receipt),
        ids["question"],qdigest,question.question_key,original,case.policy_original,case.adoption_original,
        case.adoption_version,case.review_version,receipt.write_versions[0],canonical_digest(writes[0].value),
        question.source_refs,question.source_refs,case.source_versions,case.causal_original,case.causal_operation_id,
        case.causal_receipt_digest,case.original_parent_budget_lease_ref,case.original_parent_grant_digest,
        ticket.valid_until,case.review_not_before_utc,case.review_due_utc,case.readout_valid_until_utc,
        payload["causal_depth"],payload["depth_basis"])
    digest=record_d07_original_in_transaction_v1(db,issuer,case.namespace,ATTENTION_KIND,ids["attention"],plain_v1(value))
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,ids["attention"],digest,(value.ticket_ref,))



def freeze_current_single_event_review_stage_v1(frame,stage,workflow,installation_id):
    from ..model_broker.d07_cognition_v1 import (D07CognitionInputV1,D07CognitionInstallationV1,
        freeze_d07_cognition_request_v1,TEMPLATE_VERSION)
    from .d07_execution_v1 import _source_input,D07SemanticTargetOriginalV1
    from .domain_background_read_v3 import background_json_loads_v3
    q=stage.provenance["semantic_question"];target=stage.provenance["semantic_target"]
    if(type(q)is not D07SemanticQuestionV1 or type(target)is not D07SemanticTargetOriginalV1
            or target.kind!=CASE_KIND or stage.status!="queued"or stage.work_kind!="concern"
            or(workflow.work_kind,workflow.purpose,workflow.template_version)!=("d07.cognition","proposal",TEMPLATE_VERSION)):
        raise ValueError("named review freeze requires its exact generic workflow and actual Case target")
    case=_case_from_wire_v1(background_json_loads_v3(target.value_json))
    novelty=require_bound_single_event_review_novelty_stage_v1(frame,stage,case)
    depth,_=novelty.independent_depth_v1(_REVIEW_NOVELTY_FACTS_V1[novelty][0],case)
    selected=tuple(t for t in stage.provenance["tickets"]if t.ticket_id==stage.provenance["choice"].ticket_id)
    ids=single_event_review_attention_ids_v1(case.namespace,
        ProductionOriginalRefV1("d01."+CASE_KIND,target.original_ref,target.original_digest))
    if(len(selected)!=1 or selected[0].ticket_id!=ids["ticket"]or selected[0].source_refs!=q.source_refs
            or target.original_ref!=q.target_ref.ref or target.revision!=q.target_ref.version
            or q.question!=_FIXED_QUESTION or q.source_refs!=target.source_refs
            or frame.envelope.authority.purpose!="context"):
        raise ValueError("named review changed its actual fair ticket, fixed question or Source context")
    value=D07CognitionInputV1(case.namespace,frame.envelope.identity.activity_id,"concern",q.question_key,q.question,
        q.target_ref.ref,_source_input(frame,q.source_refs),causal_depth=depth,
        target_original_json=target.value_json,target_original_kind=CASE_KIND,target_original_digest=target.original_digest)
    installation=D07CognitionInstallationV1(installation_id,workflow.provider_id,workflow.model_id,
        workflow.provider_config_ref,workflow.provider_config_digest,workflow.max_output_tokens)
    return freeze_d07_cognition_request_v1(value,installation)

def prepare_single_event_review_execution_in_transaction_v1(db,*,frame,stage,workflow,installation_id,
        d11_issuer,resource_issuer,body_authority,clock_mapping,body_policy_id,body_policy_version):
    from .current_method_learning_read_v3 import _method_active
    from .d07_execution_v1 import (D07PreparationStageV1,d07_execution_ids_v1,_prepare_d07_resources_in_transaction_v1,
        _clock_original,record_d07_original_in_transaction_v1,D07_ACCOUNTING_FIELDS,_json)
    from .budget import get_budget_lease,require_budget_family_admissible
    from .jobs import create_job
    from .domain_background_read_v3 import background_json_loads_v3
    from datetime import datetime,timezone
    import time
    r=_method_active(db);task=prepare_single_event_review_concern_metadata_v1(r)
    q=stage.provenance["semantic_question"];target=stage.provenance["semantic_target"]
    case,original,case_guards=_current_review_case_v1(db,frame=frame,case_original=task.attention.case_original,issuer=d11_issuer)
    if(task.attention.semantic_question_ref!=stage.request.trigger_original_ref
            or task.question[1]!=canonical_digest(plain_v1(q))or original.original_digest!=target.original_digest
            or case.case_ref!=target.original_ref or frame.envelope.parent_budget_lease_ref!=case.original_parent_budget_lease_ref):
        raise ValueError("review preparation lost its actual signed Case/question or original parent")
    novelty=require_bound_single_event_review_novelty_stage_v1(frame,stage,case)
    for prior,ref,header in task.prepared_originals:
        if prior["operation_id"]!=frame.envelope.identity.operation_id:
            raise MissingProductionOriginalV1("actual_review_case_already_prepared")
    lease=get_budget_lease(db,case.original_parent_budget_lease_ref);require_budget_family_admissible(db,lease.lease_id)
    grant=d11_issuer.current_budget_grant(db,lease.lease_id)
    if(canonical_digest(grant)!=case.original_parent_grant_digest or "d07.cognition"not in grant.allowed_work_kinds
            or any(v>grant.max_ceiling.get(k,0)for k,v in workflow.quote_ceiling.items())):
        raise MissingProductionOriginalV1("original_single_event_review_parent_resources")
    frozen=freeze_current_single_event_review_stage_v1(frame,stage,workflow,installation_id)
    clock_digest=_clock_original(db,d11_issuer,case.namespace,clock_mapping)
    if(clock_digest!=case.clock_original.original_digest
            or (clock_mapping.mapping_id,clock_mapping.version)!=(case.clock_mapping_id,case.clock_mapping_version)):
        raise ValueError("review preparation changed its actual paired D11 clock")
    policy=body_authority.policy(db,case.namespace,body_policy_id,body_policy_version)
    selected=next(t for t in stage.provenance["tickets"]if t.ticket_id==stage.provenance["choice"].ticket_id)
    deadline=min(frame.envelope.deadline_utc,case.original_deadline_utc,case.review_due_utc,case.readout_valid_until_utc,
        task.attention.original_deadline_utc,selected.valid_until,policy.valid_until,grant.valid_until_utc,
        datetime.fromisoformat(clock_mapping.valid_until_utc.replace("Z","+00:00")).timestamp())
    if not case.review_not_before_utc<=frame.now_utc<deadline:raise MissingProductionOriginalV1("original_review_window_exhausted")
    envelope=replace(frame.envelope,deadline_utc=deadline,
        monotonic_deadline=min(frame.envelope.monotonic_deadline,time.monotonic()+deadline-frame.now_utc))
    frame=replace(frame,envelope=envelope);stage=replace(stage,envelope=envelope,proposal=replace(stage.proposal,envelope=envelope))
    ids=d07_execution_ids_v1(case.namespace,envelope.identity.operation_id,"concern")
    original_ref="d07-prepared:"+envelope.identity.operation_id
    continuation={"request":_json(stage.request),"input_digest":stage.input_digest,"choice":_json(stage.provenance["choice"]),
        "original_ref":original_ref,"prepared_job_id":ids["job"],"quote_id":ids["quote"],"quote_version":1,
        "call_id":ids["call"],"work_kind":"concern"}
    resources=_prepare_d07_resources_in_transaction_v1(db,frame=frame,ids=ids,work_kind="concern",frozen=frozen,
        stage_input_digest=stage.input_digest,job_continuation=continuation,original_ref=original_ref,workflow=workflow,lease=lease,
        resource_issuer=resource_issuer,body_authority=body_authority,clock_mapping=clock_mapping,
        clock_digest=clock_digest,policy=policy,body_policy_id=body_policy_id,body_policy_version=body_policy_version)
    job,quote,body=resources.job,resources.resource_quote,resources.body_reservation
    identity=envelope.identity
    from dataclasses import asdict
    base=D07PreparedExecutionV1(case.namespace,identity.operation_id,identity.activity_id,identity.effect_id,identity.attempt_id,
        job.job_id,ids["call"],ids["execution"],"concern",stage.input_digest,canonical_serialize(plain_v1(frozen)),
        resources.content_read_rows,resources.query_inventory_json,canonical_serialize(()),envelope.authority.audience,
        envelope.authority.purpose,canonical_serialize(asdict(frame.owner_guard)),canonical_serialize(asdict(envelope.authority)),
        quote.quote_id,quote.version,canonical_digest(quote),resources.reservation_digest,body_policy_id,body_policy_version,
        body.body_quote.quote_id,body.body_quote_version,canonical_digest(body.body_quote),body.reservation_write.key.token,
        resources.body_state_ref,resources.body_profile_ref,resources.component_id,resources.clock_mapping_json,clock_digest,
        frame.activation_generation,frame.snapshot.epochs[0].revision,envelope.version_guard.access_epoch,envelope.version_guard.delete_epoch)
    values={f.name:getattr(base,f.name)for f in fields(base)if f.name!="schema"}
    a=task.attention;depth,depth_basis=novelty.independent_depth_v1(r,case)
    prepared=D07SingleEventReviewPreparedV1(**values,semantic_question_ref=a.semantic_question_ref,
        semantic_question_digest=a.semantic_question_digest,review_attention_ref=a.original_ref,
        review_attention_digest=task.attention_digest,review_case_original=original,policy_original=case.policy_original,
        adoption_original=case.adoption_original,adoption_version=case.adoption_version,
        original_parent_budget_lease_ref=case.original_parent_budget_lease_ref,original_parent_grant_digest=case.original_parent_grant_digest,
        original_deadline_utc=deadline,review_not_before_utc=case.review_not_before_utc,review_due_utc=case.review_due_utc,
        readout_valid_until_utc=case.readout_valid_until_utc,causal_original=case.causal_original,
        causal_operation_id=case.causal_operation_id,causal_receipt_digest=case.causal_receipt_digest,causal_depth=depth,
        depth_basis=depth_basis,context_source_refs=q.source_refs,consolidation_source_refs=q.source_refs,case_source_versions=case.source_versions,
        case_control_heads=_actual_review_control_heads_v1(r,case_guards))
    novelty.require_new_case_v1(r,case)
    record_d07_original_in_transaction_v1(db,d11_issuer,case.namespace,"prepared",job.job_id,plain_v1(prepared))
    record_d07_original_in_transaction_v1(db,d11_issuer,case.namespace,"accounting_prepared",job.job_id,
        {"schema":"d07.accounting-prepared.v1","prepared_digest":prepared.digest,**{name:_json(getattr(prepared,name))for name in D07_ACCOUNTING_FIELDS}})
    create_job(db,job,job.operation_id,resources.reservation_digest)
    updated=replace(stage,envelope=resources.frame.envelope,proposal=replace(stage.proposal,envelope=resources.frame.envelope,
        required_bundle_parts=("persistent_job",)),read_versions=resources.read_versions)
    bind_current_single_event_review_novelty_stage_v1(db,resources.frame,updated)
    return D07PreparationStageV1(resources.frame,updated,prepared,job,resources.writes,resources.read_versions)

def resolve_current_single_event_review_target_v1(db,*,frame,question,issuer):
    from .current_method_learning_read_v3 import _method_active
    from .d07_execution_v1 import D07SemanticTargetOriginalV1
    reader=_method_active(db)
    if reader is not None:
        task=prepare_single_event_review_concern_metadata_v1(reader)
        if(task.attention.semantic_question_ref!=reader.request.trigger_original_ref
                or task.question[1]!=canonical_digest(plain_v1(question))):
            raise ValueError("review semantic target has no exact actual signed named Question")
        case,original,versions=_current_review_case_v1(db,frame=frame,case_original=task.attention.case_original,issuer=issuer)
    else:
        from .domain_background_read_v3 import _active_v3
        from .d07_stage_content_scope_v3 import require_current_host_d07_stage_source_permission_v3
        from .d07_execution_v1 import read_prepared_d07_execution_v1
        from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
        from .domain_background_read_v3 import background_json_loads_v3
        owner=_active_v3(db)
        if owner is None or owner.kind!="d07_stage":
            raise ValueError("review Case target requires its actual Method or separate Source-qualified Host stage")
        require_current_host_d07_stage_source_permission_v3(owner)
        prepared=read_prepared_d07_execution_v1(db,issuer,owner.namespace,owner.d07_selector.parent_job_id)
        if(type(prepared)is not D07SingleEventReviewPreparedV1
                or prepared.semantic_question_digest!=canonical_digest(plain_v1(question))):
            raise ValueError("review Host target is outside its exact signed prepared Case")
        frozen=thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))
        case=_case_from_wire_v1(background_json_loads_v3(frozen.input.target_original_json))
        original=prepared.review_case_original;versions=prepared.case_source_versions
    roots=tuple(dict.fromkeys((*case.support_source_refs,*case.context_source_refs)))
    encoded=canonical_serialize(plain_v1(case))
    if(question.target_ref!=VersionedRef(case.case_ref,1)or question.source_refs!=roots
            or question.question!=_FIXED_QUESTION or canonical_digest(plain_v1(case))!=original.original_digest):
        raise ValueError("review semantic target differs from its actual registered complete Case")
    return D07SemanticTargetOriginalV1(CASE_KIND,case.case_ref,1,original.original_digest,encoded,roots,versions)



class _ReviewFairTicketMetadataV1:
    def __init__(self,reader,key,head):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        self.reader,self.key,self.head=reader,key,head
        self.cell=None if head[2]is None else begin_runtime_cell_read_v3(reader.db,head[2],erasure_owner_ref=key.token)
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell is None or self.cell.header[0]=="canonical-json.ascii.v1")
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.fragment=b"";self.fragment_offset=0;self.offset=0;self.total=None;self.complete=False;self.result=None
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from ..graph_types import GraphAtom
        from ..domains.d07 import D07DomainProvider
        r=_actual_review_method_v1(self.reader,meter)
        actual=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
            "token=? AND bot=? AND persona=?",(self.key.token,*r.namespace.as_tuple))
        if actual!=self.head:raise ValueError("ordinary fair ticket metadata changed across canonical EOF")
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.fragment_offset:end],self.builder._emit)
            self.fragment_offset=end;return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(r.db):
                if self.total is None:
                    row=r.db.execute("SELECT length(CAST(value AS BLOB)) FROM graph_atoms WHERE token=?",(self.key.token,)).fetchone()
                    meter.charge_read(16);self.total=row[0]
                chunk=None
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_atoms",column="value",
                        where="token=?",parameters=(self.key.token,),start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("ordinary fair metadata legacy column changed")
                    self.offset+=len(chunk)
        if chunk is not None:self.fragment=chunk;self.fragment_offset=0;return False
        parsed=self.parser.finish()
        if self.cell is not None:
            digest=self.cell.finish(meter=meter)
            if(parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]):
                raise ValueError("ordinary fair ticket failed its actual cell complete EOF")
        elif parsed.byte_count!=self.total:raise ValueError("ordinary fair ticket failed complete legacy EOF")
        value=_detach_value_v3(self.builder.value)
        next(spec for spec in D07DomainProvider.type_specs()if spec.name==self.key.type_name).validator(value)
        self.result=GraphAtom(self.key,self.head[0],value,True);self.complete=True
        self.fragment=b"";self.parser=self.builder=self.cell=None
        return True


class _SingleEventReviewClassifiedAttentionV1:
    def __init__(self,reader,question_task):
        from .d07_source_dispatch_read_v3 import require_d07_dispatch_read_v3
        record=require_d07_dispatch_read_v3(reader)
        if record["tasks"].get(question_task.identity)is not question_task or not question_task.complete:
            raise ValueError("review classifier requires its actual whole-EOF signed Question task")
        locator=question_task.result
        if(locator[0]!="semantic_question"or locator[4]!="d07.registered-semantic-question.v1"
                or not locator[1].startswith(QUESTION_PREFIX)or locator[5]!="registered_joint_plan"):
            raise ValueError("review classifier candidate is outside its actual signed generic Case target")
        self.reader,self.question_task=reader,question_task
        self.census=(reader.work,reader.operation,reader.graph_stamp,reader.fence.scope,reader.owner_binding)
        ref="single-event-review-attention:"+locator[1].removeprefix(QUESTION_PREFIX)
        self.leaf=_ReviewSignedMetadataV1(self,ATTENTION_KIND,ref);self.attention=None
        self.complete=False;self.result=None
    def require_current_v1(self):
        from .d07_source_dispatch_read_v3 import require_d07_dispatch_read_v3
        r=self.reader;record=require_d07_dispatch_read_v3(r)
        if(self.census!=(r.work,r.operation,r.graph_stamp,r.fence.scope,r.owner_binding)
                or record["tasks"].get(self.question_task.identity)is not self.question_task):
            raise ValueError("review classifier left its actual selected READ/Owner and signed Question")
        r.require_current();return r
    def advance(self,meter):
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .dispatch_current_inventory_v3 import _detach_value_v3
        r=self.require_current_v1()
        if self.complete:return True
        if self.attention is None:
            if not self.leaf.advance(meter):return False
            a=decode_typed_production_value_v1(self.leaf.value,SingleEventReviewAttentionOriginalV1)
            target=_detach_value_v3(self.question_task.column.frozen)["target_ref"]
            locator=self.question_task.result
            if(a.namespace!=r.namespace or (a.semantic_question_ref,a.semantic_question_digest)!=(locator[1],locator[2])
                    or target!={"ref":a.case_original.original_ref,"version":1}):
                raise ValueError("review classifier has no exact actual signed Case/Question/Attention identity")
            self.attention=a;return False
        a=self.attention
        head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
            "token=? AND bot=? AND persona=?",(a.ticket_ref.key.token,*r.namespace.as_tuple))
        history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
            "token=? AND revision=?",(a.ticket_ref.key.token,a.ticket_ref.revision))
        producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,a.registration_operation_id))
        if(head is None or head[:2]!=(a.ticket_ref.revision,1)or history!=(*r.namespace.as_tuple,a.registration_operation_id,1)
                or producer is None or type(producer[3])is not int or producer[3]<1):
            raise ValueError("review classifier lost the actual current same-event ticket registration")
        self.result=(*self.question_task.result[:5],"single_event_review_owner");self.complete=True
        return True

def create_single_event_review_classifier_metadata_v1(reader,question_task):
    return _SingleEventReviewClassifiedAttentionV1(reader,question_task)

def read_bound_single_event_review_concern_metadata_v1(db,*,namespace,request,issuer):
    from .current_method_learning_read_v3 import _method_active
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    if(type(request)is not ServeCurrentConcernRequestV1 or not request.trigger_original_ref.startswith(QUESTION_PREFIX)):return None
    reader=_method_active(db)
    if(reader is None or reader.namespace!=namespace or reader.request!=request
            or issuer is not reader.graph._GraphCoordinator__d11_issuer):
        raise ValueError("named review plan requires its actual same-command Method Work")
    return prepare_single_event_review_concern_metadata_v1(reader)

def read_plan_bound_single_event_review_concern_v1(db,*,namespace,activity_id,request,issuer):
    from .d01_single_event_review_case_v1 import read_plan_registered_single_event_review_case_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d07.concern_round import concern_round_key
    from ..domains.d12.types import active_scheme_head_key
    task=read_bound_single_event_review_concern_metadata_v1(db,namespace=namespace,request=request,issuer=issuer)
    if task is None:return None
    if activity_id!=task.reader.activity_id:raise ValueError("review plan changed its actual selected activity")
    a=task.attention
    prepare_current_single_event_review_novelty_v1(task.reader,a.case_original)
    plan=read_plan_registered_single_event_review_case_v1(db,namespace=namespace,case_original=a.case_original,issuer=issuer)
    types=(*plan.fixed_type_ids,"d07.attention_ticket.v1","d07.focus.v1","d07.concern_round.v1",
        "d07.reflection_checkpoint.v1","d07.working_set.v1","d02.body_profile.v1","d02.body_state.v1","d02.reservation.v1")
    keys=(*plan.exact_keys,owner_grant_key(*namespace.as_tuple),active_scheme_head_key(namespace),
        concern_round_key(namespace,"background"),a.ticket_ref.key,
        AtomKey(Owner("activity",*namespace.as_tuple,activity_id),"d07.cognitive_activity.v1",activity_id))
    roots=(*plan.source_roots,*(ref for atom in task.fair_tickets for ref in atom.value["source_refs"]))
    return production_read_plan_v1(types,keys,roots,(*plan.required_original_refs,a.semantic_question_ref,a.original_ref))

def single_event_review_adoption_read_plan_v1(prepared,versions):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .domain_background_read_v3 import background_json_loads_v3
    if type(prepared)is not D07SingleEventReviewPreparedV1:raise TypeError("actual exact review preparation required")
    return production_read_plan_v1(tuple(page["type_id"]for page in background_json_loads_v3(prepared.query_inventory_json)),
        tuple(v.key for v in versions),prepared.context_source_refs,(prepared.semantic_question_ref,))

def read_current_single_event_review_ticket_v1(db,read,*,ticket,issuer):
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if not ticket.ticket_id.startswith("attention:single-event-review:"):return None
    ref="single-event-review-attention:"+ticket.ticket_id.removeprefix("attention:single-event-review:")
    row=read_d07_original_v1(db,issuer,read.frame.envelope.authority.namespace,ATTENTION_KIND,ref)
    if row is None:raise MissingProductionOriginalV1("actual_signed_single_event_review_ticket")
    a=decode_typed_production_value_v1(row[0],SingleEventReviewAttentionOriginalV1)
    if a.question_key!=ticket.question_key or a.context_source_refs!=ticket.source_refs:
        raise ValueError("review fair ticket differs from its actual signed Question/case/Source/window")
    head=read.head(db,a.ticket_ref.key,required=True)
    if head.revision!=a.ticket_ref.revision or canonical_digest(head.value)!=a.ticket_value_digest:
        if len(ticket.cancel_refs)!=1:
            raise ValueError("review terminal ticket has no exact signed rejection locator")
        ref=ticket.cancel_refs[0]
        rejected=read_d07_original_v1(db,issuer,a.namespace,_REVIEW_CARDINALITY_KIND_V1,ref)
        if rejected is None:raise ValueError("review fair ticket has no actual terminal rejection original")
        terminal=decode_typed_production_value_v1(rejected[0],D07SingleEventReviewCardinalityRejectionOriginalV1)
        if(ticket.eligible or ticket.resources_available or terminal.case_original!=a.case_original
                or terminal.question_original.original_ref!=a.semantic_question_ref
                or terminal.ticket_version!=GraphVersion(head.key,head.revision)
                or terminal.ticket_value_digest!=canonical_digest(head.value)):
            raise ValueError("review fair ticket no longer has its exact actual terminal head")
        return ProductionOriginalRefV1("d07."+_REVIEW_CARDINALITY_KIND_V1,ref,rejected[1],(terminal.ticket_version,))
    if read.frame.now_utc>=min(a.original_deadline_utc,ticket.valid_until):
        raise ValueError("review fair ticket exceeded its original registered window")
    read.committed_operation(db,a.registration_operation_id)
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,a.original_ref,row[1],(a.ticket_ref,))



def single_event_review_parent_metadata_retains_path_v1(mode,path):
    if mode=="single_event_review_question":
        return not path or path[0]in {"schema","question_key","target_ref","source_refs"}
    if mode not in {"single_event_review_registration","single_event_review_case_registration"}:return None
    if not path:return True
    if path[0]in {"schema","namespace","identity","authority","parent_budget","coverage","now_utc"}:return True
    if path[0]!="provenance":return False
    if len(path)==1:return True
    if mode=="single_event_review_registration":
        if path[1]in {"single_event_review_ticket","single_event_review_case_original","causal_depth","depth_basis"}:return True
        if path[1]=="single_event_review_question":
            return single_event_review_parent_metadata_retains_path_v1("single_event_review_question",path[2:])
        return False
    if path[1]!="single_event_review_case":return False
    from .d01_single_event_growth_v1 import single_event_metadata_paths_v1
    return single_event_metadata_paths_v1("graph_d01_production_inputs_v1",CASE_KIND,path[2:])

def advance_single_event_review_parent_metadata_v3(task,meter,*,side):
    _require_single_event_parent_task_v1(task,side,meter)
    if side=="host":
        from .d07_stage_content_scope_v3 import (_HostSignedParentMetadataReadV3 as Signed,
            _HostAdoptedParentMetadataReadV3 as Adopted,_HostHistoryParentMetadataReadV3 as History,
            _HostParentBudgetMetadataReadV3 as Budget)
    else:
        from ..authority_service.d07_authority_model_source_read_v3 import (_D07SignedParentMetadataReadV3 as Signed,
            _D07AdoptedParentMetadataReadV3 as Adopted,_D07HistoryParentMetadataReadV3 as History,
            _D07ParentBudgetMetadataReadV3 as Budget)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    raw,r,w,header=task.raw,task.reader,task.work,task.header
    stage=getattr(task,"single_event_review_phase","question")
    if stage=="question":
        leaf=task._leaf_v3(("single-event-question",header.job_id),Signed(r,family="d07",kind="semantic_question",
            ref=raw["semantic_question_ref"],expected_digest=raw["semantic_question_digest"],mode="single_event_review_question"))
        if leaf is None:return
        q=leaf.value;case_original=_decode_original_v1(raw["review_case_original"])
        ids=single_event_review_attention_ids_v1(w.namespace,case_original)
        frozen=header.column.frozen_metadata.value["input"]
        roots=tuple(raw["context_source_refs"])
        if(q["schema"]!="d07.registered-semantic-question.v1"or raw["semantic_question_ref"]!=ids["question"]
                or raw["review_attention_ref"]!=ids["attention"]or q["target_ref"]!={"ref":case_original.original_ref,"version":1}
                or tuple(q["source_refs"])!=roots or raw["purpose"]!="context"or task.source.purpose!="context"
                or frozen["target_ref"]!=case_original.original_ref or frozen["target_original_kind"]!=CASE_KIND
                or frozen["target_original_digest"]!=case_original.original_digest
                or frozen["causal_depth"]!=raw["causal_depth"]or raw["causal_depth"]!=0
                or raw["depth_basis"]!="actual_registered_post_adoption_experience_v1"
                or {v["source_ref"]["ref"]for v in frozen["sources"]}!=set(roots)
                or not set(roots)<={row["ref"]for row in header.source_rows}):
            raise ValueError("review parent changed its exact generic frozen Case, Question, Sources or depth")
        task.single_event_review_question=q
        task.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
        task.single_event_review_phase="attention";return
    if stage=="attention":
        leaf=task._leaf_v3(("single-event-attention",header.job_id),Signed(r,family="d07",kind=ATTENTION_KIND,
            ref=raw["review_attention_ref"],expected_digest=raw["review_attention_digest"]))
        if leaf is None:return
        a=decode_typed_production_value_v1(leaf.value,SingleEventReviewAttentionOriginalV1)
        q=task.single_event_review_question
        names=("semantic_question_ref","semantic_question_digest","original_parent_budget_lease_ref",
            "original_parent_grant_digest","review_not_before_utc","review_due_utc","readout_valid_until_utc",
            "causal_operation_id","causal_receipt_digest","causal_depth","depth_basis")
        if(a.namespace!=w.namespace or a.case_original!=_decode_original_v1(raw["review_case_original"])
                or a.question_key!=q["question_key"]or any(getattr(a,name)!=raw[name]for name in names)
                or plain_v1(a.policy_original)!=raw["policy_original"]or plain_v1(a.adoption_original)!=raw["adoption_original"]
                or plain_v1(a.adoption_version)!=raw["adoption_version"]or plain_v1(a.causal_original)!=raw["causal_original"]
                or a.context_source_refs!=tuple(raw["context_source_refs"])
                or a.consolidation_source_refs!=tuple(raw["consolidation_source_refs"])
                or plain_v1(a.case_source_versions)!=raw["case_source_versions"]
                or raw["original_deadline_utc"]>a.original_deadline_utc):
            raise ValueError("review parent has no exact actual signed Attention control binding")
        task.single_event_review_attention=a
        task.originals.append(("d07."+ATTENTION_KIND,a.original_ref,leaf.metadata[0]))
        task.single_event_review_phase="registration";return
    a=task.single_event_review_attention
    if stage=="registration":
        leaf=task._leaf_v3(("single-event-registration",header.job_id),Adopted(r,a.registration_operation_id,
            mode="single_event_review_registration"))
        if leaf is None:return
        if(leaf.metadata[:2]!=("d07",REGISTER_OPERATION)or canonical_digest(leaf.receipt)!=a.registration_receipt_digest
                or a.ticket_ref not in leaf.receipt.write_versions):
            raise ValueError("review parent lacks the actual same-W01 attention registration receipt")
        task.single_event_review_phase="ticket";return
    if stage=="ticket":
        leaf=task._leaf_v3(("single-event-ticket",header.job_id),History(r,a.ticket_ref.key.token,a.ticket_ref.revision,
            expected_operation=a.registration_operation_id,expected_digest=a.ticket_value_digest))
        if leaf is None:return
        if(leaf.value["ticket_id"]!=a.ticket_ref.key.name or leaf.value["category"]!="background"
                or leaf.value["question_key"]!=a.question_key or tuple(leaf.value["source_refs"])!=a.context_source_refs):
            raise ValueError("review parent lost its actual registered fair background ticket")
        task.single_event_review_phase="case";return
    if stage=="case":
        leaf=task._leaf_v3(("single-event-case",header.job_id),_SingleEventCaseParentColumnV1(task,side=side))
        if leaf is None:return
        c=leaf.value
        roots=tuple(dict.fromkeys((*c["support_source_refs"],*c["context_source_refs"])))
        names=("policy_original","adoption_original","adoption_version","causal_original","causal_operation_id",
            "causal_receipt_digest","original_parent_budget_lease_ref","original_parent_grant_digest",
            "review_not_before_utc","review_due_utc","readout_valid_until_utc")
        if(any(c[name]!=raw[name]for name in names)or tuple(raw["context_source_refs"])!=roots
                or tuple(raw["consolidation_source_refs"])!=roots or c["source_versions"]!=raw["case_source_versions"]
                or raw["original_deadline_utc"]>c["original_deadline_utc"]
                or not any(row["producer_original"]==raw["causal_original"]
                    and row["occurred_at_utc"]>c["adoption_recorded_at_utc"]
                    and row["observer_originals"]for row in c["post_adoption_scope_bindings"])):
            raise ValueError("review Case metadata changed its actual policy/adoption/outcome/Source/resource basis")
        task.single_event_review_case=c
        task.originals.append(("d01."+CASE_KIND,a.case_original.original_ref,leaf.metadata[2]))
        task.deadlines.extend((raw["original_deadline_utc"],c["original_deadline_utc"],c["review_due_utc"],c["readout_valid_until_utc"]))
        task.single_event_review_phase="case_registration";return
    if stage=="case_registration":
        c=task.single_event_review_case
        leaf=task._leaf_v3(("single-event-case-registration",header.job_id),Adopted(r,c["registration_operation_id"],
            mode="single_event_review_case_registration"))
        if leaf is None:return
        if(leaf.metadata[:2]!=("d01","review_single_event_growth_v1")
                or leaf.value["provenance"]["single_event_review_case"]!=c):
            raise ValueError("review Case lost its actual signed same-W01 registered producer metadata")
        task.single_event_review_control_index=0;task.single_event_review_phase="controls";return
    if stage=="controls":
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        controls=raw["case_control_heads"];index=task.single_event_review_control_index
        if index<len(controls):
            encoded,valid=controls[index]
            version=decode_typed_production_value_v1(encoded,GraphVersion)
            if NamespaceId.from_key(version.key)!=w.namespace:
                raise ValueError("review protected current control crossed actual namespace")
            current=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_atoms",("revision","valid"),
                "token=? AND bot=? AND persona=?",(version.key.token,*w.namespace.as_tuple))
            if(0 if current is None else current[0],False if current is None else bool(current[1]))!=(version.revision,valid):
                raise ValueError("review protected metadata head changed before actual Source Body")
            task.single_event_review_control_index+=1;return
        task.single_event_review_phase="budget";return
    if stage=="budget":
        leaf=task._leaf_v3(("single-event-original-parent",header.job_id),Budget(r,raw["original_parent_budget_lease_ref"]))
        if leaf is None:return
        workflow=task.reader.bundle.model_workflows.d07_cognition
        frozen=header.column.frozen_metadata.value["installation"]
        if(workflow is None or canonical_digest(leaf.grant)!=raw["original_parent_grant_digest"]
                or "d07.cognition"not in leaf.grant.allowed_work_kinds or workflow.purpose!="proposal"
                or any(frozen[name]!=getattr(workflow,name)for name in
                    ("provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
            raise ValueError("review Case cannot replace its original grant or installed generic model")
        task.deadlines.append(leaf.grant.valid_until_utc);task.phase="ordinary_job";return
    raise ValueError("unregistered named single-event review parent phase")

def release_single_event_review_parent_metadata_v1(work):
    for column,state in tuple(_CASE_PARENT_COLUMNS.items()):
        if state[2]is work:
            _CASE_PARENT_COLUMNS.pop(column,None)
            column.verifier=column.parser=column.builder=column.value=None;column.fragment=b""


def _require_review_owner_groups_v1(reader):
    if reader.read_finished:
        from .current_method_learning_read_v3 import _require_current_general_method_source_write_phase_v1
        _require_current_general_method_source_write_phase_v1(reader)
        binding=reader.owner_binding
    else:binding=reader.general_owner_entry.require_for_v3(reader)
    if not {"context","consolidation"}<=set(binding.purposes)or not set(reader.authority.audience)<=set(binding.audiences):
        raise ValueError("review Source groups exceed the actual current Owner purposes or audiences")
    return binding

def require_current_single_event_review_prepared_v1(db,*,issuer,prepared,installed_bundle,now,frozen=None):
    from .d07_execution_v1 import read_current_d07_semantic_question_v1,read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_background_read_v3 import background_json_loads_v3
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1,TEMPLATE_VERSION
    if type(prepared)is not D07SingleEventReviewPreparedV1:
        raise TypeError("exact independent single-event review preparation required")
    q=read_current_d07_semantic_question_v1(db,issuer,prepared.namespace,prepared.semantic_question_ref)
    row=read_d07_original_v1(db,issuer,prepared.namespace,ATTENTION_KIND,prepared.review_attention_ref)
    if row is None:raise MissingProductionOriginalV1("actual_single_event_review_attention")
    a=decode_typed_production_value_v1(row[0],SingleEventReviewAttentionOriginalV1)
    frozen=thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))if frozen is None else frozen
    case=_case_from_wire_v1(background_json_loads_v3(frozen.input.target_original_json))
    workflow=installed_bundle.model_workflows.d07_cognition
    if(type(q)is not D07SemanticQuestionV1 or canonical_digest(plain_v1(q))!=prepared.semantic_question_digest
            or row[1]!=prepared.review_attention_digest or a.case_original!=prepared.review_case_original
            or a.semantic_question_ref!=prepared.semantic_question_ref or a.semantic_question_digest!=prepared.semantic_question_digest
            or q.question_key!=a.question_key or q.question!=_FIXED_QUESTION
            or q.target_ref!=VersionedRef(prepared.review_case_original.original_ref,1)
            or frozen.input.target_original_kind!=CASE_KIND or frozen.input.target_ref!=q.target_ref.ref
            or frozen.input.target_original_digest!=prepared.review_case_original.original_digest
            or canonical_digest(plain_v1(case))!=prepared.review_case_original.original_digest
            or frozen.input.question_key!=q.question_key or frozen.input.question!=q.question
            or q.source_refs!=prepared.context_source_refs or q.source_refs!=a.context_source_refs
            or workflow is None or (workflow.work_kind,workflow.purpose,workflow.template_version)!=("d07.cognition","proposal",TEMPLATE_VERSION)
            or any(getattr(frozen.installation,name)!=getattr(workflow,name)for name in
                ("provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))
            or not prepared.review_not_before_utc<=now<min(prepared.original_deadline_utc,prepared.review_due_utc,prepared.readout_valid_until_utc)):
        raise ValueError("review preparation changed its actual generic Question/Case/Source/model/original window")
    return q,(a,row[1]),frozen

def single_event_review_metadata_retains_path_v1(kind,path):
    if kind=="semantic_question":return single_event_review_parent_metadata_retains_path_v1("single_event_review_question",path)
    if kind==ATTENTION_KIND:return not path or path[0]in {f.name for f in fields(SingleEventReviewAttentionOriginalV1)}
    if kind=="prepared":
        names={f.name for f in fields(D07SingleEventReviewPreparedV1)}-{
            "frozen_json","read_rows","query_inventory_json","external_content_originals_json","clock_mapping_json"}
        return not path or path[0]in names
    return None


def _actual_review_control_heads_v1(reader,guards):
    require_actual_single_event_review_case_metadata_work_v1(reader)
    result=[]
    for version in guards:
        if version.key.type_name.startswith(("runtime.","d02.","d07.")):continue
        head=reader.heads.get(version.key.token,(0,0,None))
        if head[0]!=version.revision:
            raise ValueError("review current metadata guard differs from its actual complete namespace census")
        result.append((version,bool(head[1])))
    return tuple(result)

def validate_single_event_review_registration_provenance_v1(provenance):
    """Closed data codec; this does not issue Source or model permissions."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d07 import AttentionTicket
    expected={"single_event_review_case","single_event_review_case_original",
        "single_event_review_question","single_event_review_ticket","causal_depth","depth_basis"}
    if type(provenance)is not dict or set(provenance)!=expected:
        raise ValueError("review registration provenance has another closed field set")
    case=_case_from_wire_v1(provenance["single_event_review_case"])
    original=_decode_original_v1(provenance["single_event_review_case_original"])
    question=decode_typed_production_value_v1(provenance["single_event_review_question"],D07SemanticQuestionV1)
    ticket=decode_typed_production_value_v1(provenance["single_event_review_ticket"],AttentionTicket)
    ids=single_event_review_attention_ids_v1(case.namespace,original)
    roots=tuple(dict.fromkeys((*case.support_source_refs,*case.context_source_refs)))
    depth,basis=_review_independent_depth_v1(case)
    if(original.kind!="d01."+CASE_KIND or original.original_ref!=case.case_ref
            or original.original_digest!=canonical_digest(plain_v1(case))
            or question.question!=_FIXED_QUESTION or question.target_ref!=VersionedRef(case.case_ref,1)
            or question.source_refs!=roots or ticket.ticket_id!=ids["ticket"]
            or ticket.question_key!=question.question_key or ticket.source_refs!=roots
            or ticket.category!="background"or provenance["causal_depth"]!=depth or provenance["depth_basis"]!=basis):
        raise ValueError("review registration changed its actual closed Case/question/ticket")
    return tuple(dict.fromkeys((*roots,case.adoption_version.key.token,case.review_version.key.token,
        *(v.key.token for v in case.source_versions))))


_REVIEW_INTERPRETATIONS=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class _ActualSingleEventReviewInterpretationV1:
    case_original:ProductionOriginalRefV1
    case:object
    prepared:D07SingleEventReviewPreparedV1
    question:D07SemanticQuestionV1
    execution:object
    semantic:object
    originals:tuple[ProductionOriginalRefV1,...]
    read_versions:tuple[GraphVersion,...]
    valid_until_utc:float
    call_id:str

    def require_current_v1(self,readers,read):
        from .d01_single_event_review_case_v1 import require_single_event_review_case_fact_owner_v1
        state=_REVIEW_INTERPRETATIONS.get(self)
        if state is None or state[:3]!=(readers,read,read.frame.envelope.identity.operation_id):
            raise ValueError("review interpretation left its actual consuming Source Work")
        db,case_fact,digest=state[3:]
        if canonical_digest(self.semantic.value)!=digest:
            raise ValueError("review interpretation changed its actual sealed adopted decision")
        read.check(db)
        require_single_event_review_case_fact_owner_v1(case_fact,db)
        if read.frame.now_utc>=self.valid_until_utc:
            raise MissingProductionOriginalV1("single_event_review_interpretation_original_deadline")
        return self

def require_actual_single_event_review_interpretation_v1(readers,db,read,*,case_original,interpretation_ref,case_fact):
    """Bind a paid generic C3 adoption to this exact independently qualified Case."""
    from .d01_production_operations_v1 import CurrentDomainReadV1,InstalledD01ProductionReadersV1
    from .d01_single_event_review_case_v1 import (
        SingleEventReviewCaseFactV1,require_single_event_review_case_fact_owner_v1)
    from .d07_execution_v1 import (TABLE,read_d07_original_v1,read_prepared_d07_execution_v1,
        D07ExecutionOriginalV1)
    from .d07_ordinary_continuity_cognition_v1 import _paid_c3_originals_v1
    from .domain_background_read_v3 import background_json_loads_v3
    from ..model_broker.d07_cognition_v1 import parse_d07_cognition_output_v1
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1,from_wire
    if(type(readers)is not InstalledD01ProductionReadersV1 or type(read)is not CurrentDomainReadV1
            or type(case_fact)is not SingleEventReviewCaseFactV1):
        raise TypeError("review interpretation requires the actual installed D01 and private current Case fact")
    read.check(db);owner=require_single_event_review_case_fact_owner_v1(case_fact,db)
    dependencies=prepare_single_event_review_interpretation_dependencies_v1(owner,case_original)
    case=case_fact.case;namespace=read.frame.envelope.authority.namespace
    if(case_fact.original!=case_original or case.namespace!=namespace):
        raise ValueError("review interpretation selected another actual registered Case")
    # CaseFact has already completed both Source groups and the exact signed Body EOF.
    roots=tuple(dict.fromkeys((*case.support_source_refs,*case.context_source_refs)))
    adopted=read_d07_original_v1(db,readers.issuer,namespace,"adopted",interpretation_ref)
    if adopted is None:raise MissingProductionOriginalV1("actual_single_event_review_adopted_interpretation")
    value=adopted[0]
    prepared=dependencies.prepared
    if prepared.digest!=value["prepared_digest"]:
        raise ValueError("review interpretation changed its presealed unique actual Prepared")
    if(type(prepared)is not D07SingleEventReviewPreparedV1 or prepared.review_case_original!=case_original
            or prepared.policy_original!=case.policy_original or prepared.adoption_original!=case.adoption_original
            or prepared.adoption_version!=case.adoption_version):
        raise ValueError("review interpretation was not produced by this registered Case")
    from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    service=owner.graph._GraphCoordinator__d07_execution_service_v1
    if type(service)is not InstalledD07ExecutionServiceV1 or service._db is not db:
        raise ValueError("review interpretation requires its actual installed D07 service")
    bundle=service.bundle
    question,attention,frozen=require_current_single_event_review_prepared_v1(db,issuer=readers.issuer,
        prepared=prepared,installed_bundle=bundle,now=read.frame.now_utc)
    if(frozen.input.target_original_json!=canonical_serialize(plain_v1(case))
            or prepared.context_source_refs!=roots or prepared.consolidation_source_refs!=roots
            or prepared.case_source_versions!=case.source_versions):
        raise ValueError("review C3 did not inspect the exact complete adopted Case and evidence")
    head=read.head(db,interpretation_ref,required=True)
    if(head.key.type_name!="d07.current_interpretation.v1"or not head.valid
            or head.revision!=value["interpretation_revision"]
            or canonical_digest(head.value)!=value["interpretation_value_digest"]
            or value["question_scope"]!=question.question_key or head.value["question_key"]!=question.question_key
            or head.value["current"]is not True):
        raise ValueError("review adopted interpretation differs from its exact actual current producer")
    _require_single_event_review_adoption_receipts_v1(db,owner=owner,case_fact=case_fact,
        prepared=prepared,interpretation=head,adopted=value)
    originals,execution=_paid_c3_originals_v1(readers,db,read,prepared,interpretation_ref)
    if(type(execution)is not D07ExecutionOriginalV1 or execution.causal_depth!=prepared.causal_depth
            or execution.source_refs!=roots):
        raise ValueError("review cannot borrow a different C3 execution or reset its actual depth")
    result=read_d07_original_v1(db,readers.issuer,namespace,"result","d07-result:"+prepared.call_id)
    if result is None or result[1]!=value["actual_result_digest"]:
        raise ValueError("review adopted interpretation lost its actual paid provider output")
    parsed=from_wire(result[0],D07CognitionResultReadV1)
    output=background_json_loads_v3(parsed.observation.result_json)
    suggestion=parse_current_single_event_review_output_v1(prepared,output["text"],frozen)
    findings=tuple(f for f in suggestion.findings if f.proposition==head.value["proposition"]
        and f.source_refs==tuple(head.value["source_refs"])and f.stance==head.value["stance"]
        and f.evidence_status==head.value["evidence_status"])
    if len(findings)!=1 or tuple(head.value["meaningful_unknowns"])!=suggestion.unknowns:
        raise ValueError("review current finding is not the exact actual model decision")
    until=min(case_fact.valid_until_utc,prepared.original_deadline_utc)
    fact=_ActualSingleEventReviewInterpretationV1(case_original,case,prepared,question,execution,head,originals,
        tuple(dict.fromkeys((*case_fact.read_versions,GraphVersion(head.key,head.revision)))),until,prepared.call_id)
    _REVIEW_INTERPRETATIONS[fact]=(readers,read,read.frame.envelope.identity.operation_id,db,case_fact,canonical_digest(head.value))
    return fact.require_current_v1(readers,read)


_CASE_REGISTERED_EVENT_V1="d01.single_event_review_case_registered_v1"
_REVIEW_ATTENTION_EVENT_V1="single_event_review_attention_available_for_service"
_REVIEW_FOLLOWUP_CAUSES=WeakKeyDictionary()

def single_event_review_followup_cause_locator_path_v1(owner,column,path):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3:return None
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    task=owner.entry_column
    if(task is None or task.column is not column or task.entry is None or task.entry[1]!="d07"
            or task.entry[2]not in {_CASE_REGISTERED_EVENT_V1,_REVIEW_ATTENTION_EVENT_V1}):return None
    expected=("d01","review_single_event_growth_v1")if task.entry[2]==_CASE_REGISTERED_EVENT_V1 else("d07",REGISTER_OPERATION)
    if task.metadata[:2]!=expected:raise ValueError("review followup has another actual registered producer")
    if not path:return True
    if path[0]in {"schema","namespace","identity","authority","parent_budget","coverage","now_utc"}:return True
    if path[0]!="provenance":return False
    if len(path)==1:return True
    if task.entry[2]==_CASE_REGISTERED_EVENT_V1:
        if path[1]!="single_event_review_case":return False
        from .d01_single_event_growth_v1 import single_event_metadata_paths_v1
        return single_event_metadata_paths_v1("graph_d01_production_inputs_v1",CASE_KIND,path[2:])
    if path[1]in {"single_event_review_case_original","single_event_review_ticket","causal_depth","depth_basis"}:return True
    if path[1]=="single_event_review_question":
        return single_event_review_parent_metadata_retains_path_v1("single_event_review_question",path[2:])
    return False

def _require_review_followup_owner_v1(owner,db,event_kind=None):
    from .domain_background_read_v3 import (BackgroundReadWorkV3,_BackgroundEntryLocatorV3,
        require_actual_background_attachment_owner_v3)
    if type(owner)is not BackgroundReadWorkV3:raise TypeError("review followup metadata requires actual Background Work")
    require_actual_background_attachment_owner_v3(owner,db=owner.db if db is None else db)
    task=owner.entry_column
    if(type(task)is not _BackgroundEntryLocatorV3 or task.owner is not owner or not task.complete
            or task.entry!=owner.entry or task.column is None or not task.column.complete
            or task.column.sha256!=task.metadata[2]or owner.entry[1]!="d07"
            or owner.entry[2]not in {_CASE_REGISTERED_EVENT_V1,_REVIEW_ATTENTION_EVENT_V1}
            or event_kind is not None and owner.entry[2]!=event_kind
            or owner.entry_metadata is None or owner.entry_metadata[0]!=task.metadata):
        raise ValueError("review followup has no actual same-Work outbox and complete producer metadata")
    metadata,payload=owner.entry_metadata
    operation="review_single_event_growth_v1"if owner.entry[2]==_CASE_REGISTERED_EVENT_V1 else REGISTER_OPERATION
    domain="d01"if owner.entry[2]==_CASE_REGISTERED_EVENT_V1 else"d07"
    if(metadata[:2]!=(domain,operation)or payload["schema"]!=domain+".current-"+operation+".v1"
            or payload["identity"]["operation_id"]!=owner.entry[0]or payload["coverage"]!="complete"):
        raise ValueError("review followup changed its actual complete registered same-W01 producer")
    return owner

def require_actual_single_event_review_attention_case_metadata_owner_v1(owner,db=None):
    owner=_require_review_followup_owner_v1(owner,db,_CASE_REGISTERED_EVENT_V1)
    case=owner.entry_metadata[1]["provenance"]["single_event_review_case"]
    if(case["namespace"]!={"bot_id":owner.namespace.bot_id,"persona_id":owner.namespace.persona_id}
            or case["case_revision"]!=1 or case["registration_operation_id"]!=owner.entry[0]):
        raise ValueError("Case attention metadata crossed its actual same-W01 native Case selector")
    return owner

def single_event_review_followup_metadata_request_allowed_v1(owner,request):
    if len(request)!=4:return False
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if(type(owner)is not BackgroundReadWorkV3 or owner.entry is None
            or owner.entry[1]!="d07"or owner.entry[2]not in {_CASE_REGISTERED_EVENT_V1,_REVIEW_ATTENTION_EVENT_V1}):
        return False
    _require_review_followup_owner_v1(owner,owner.db)
    if owner.entry[2]!=_REVIEW_ATTENTION_EVENT_V1:return False
    from .d07_execution_v1 import TABLE
    original=_decode_original_v1(owner.entry_metadata[1]["provenance"]["single_event_review_case_original"])
    ref=single_event_review_attention_ids_v1(owner.namespace,original)["attention"]
    return request==(TABLE,("payload_json","payload_digest","signature"),
        ("bot","persona","kind","original_ref"),(*owner.namespace.as_tuple,ATTENTION_KIND,ref))

def read_single_event_review_followup_cause_v1(db,*,namespace,event_kind,causal_operation_id,original_ref,issuer):
    if event_kind not in {_CASE_REGISTERED_EVENT_V1,_REVIEW_ATTENTION_EVENT_V1}:return None
    from .domain_background_read_v3 import (_active_v3,background_point_v3,background_json_loads_v3,
        background_typed_original_digest_v3)
    from .domain_production_originals_v1 import TABLE,_receipt,reconstruct_graph_bundle_commit_receipt_v1
    owner=_require_review_followup_owner_v1(_active_v3(db),db,event_kind)
    if(namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer
            or owner.entry[:4]!=(causal_operation_id,"d07",event_kind,original_ref)):
        raise ValueError("review followup selected another actual native outbox")
    metadata,payload=owner.entry_metadata
    row=background_point_v3(db,table=TABLE,columns=("domain","operation_kind","request_digest","original_digest",
        "read_versions_json","bundle_digest","receipt_json","receipt_digest"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    if row is None or row[:2]!=metadata[:2]or row[3]!=metadata[2]:
        raise ValueError("review followup lost its actual complete producer header")
    receipt=_receipt(background_json_loads_v3(row[6]))
    bundle=background_point_v3(db,table="graph_bundle_operations",columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    event=background_point_v3(db,table="graph_events",columns=("reads","revisions","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,receipt.activity_id,causal_operation_id),
        legacy_reader=lambda:None)
    if(bundle is None or event is None or receipt.status!="committed"or receipt.operation_id!=causal_operation_id
            or receipt.operation_digest!=row[5]or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or background_typed_original_digest_v3(db,row[6],receipt)!=row[7]
            or reconstruct_graph_bundle_commit_receipt_v1(namespace,causal_operation_id,(*bundle,row[6]),event)!=receipt):
        raise ValueError("review followup has no exact actual W01 receipt/bundle/event closure")
    if event_kind==_CASE_REGISTERED_EVENT_V1:
        from .d01_single_event_review_case_v1 import read_registered_single_event_review_case_metadata_v1
        requested=ProductionOriginalRefV1("d01."+CASE_KIND,original_ref,owner.entry[4])
        controls,native=read_registered_single_event_review_case_metadata_v1(db,namespace=namespace,
            case_original=requested,issuer=issuer)
        if(controls["registration_operation_id"]!=causal_operation_id
                or payload["provenance"]["single_event_review_case"]!=controls):
            raise ValueError("review Case attention lost its actual signed native registration metadata")
        parent=_SingleEventReviewFollowupParentV1(native,controls["original_parent_budget_lease_ref"],
            controls["original_parent_grant_digest"],controls["original_deadline_utc"])
    else:
        from .d07_execution_v1 import read_d07_original_v1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        actual=read_d07_original_v1(db,issuer,namespace,ATTENTION_KIND,original_ref)
        if actual is None:raise ValueError("review followup has no actual signed attention native original")
        attention=decode_typed_production_value_v1(actual[0],SingleEventReviewAttentionOriginalV1)
        q=payload["provenance"]["single_event_review_question"]
        if(attention.registration_operation_id!=causal_operation_id
                or attention.registration_receipt_digest!=canonical_digest(receipt)
                or attention.ticket_ref not in receipt.write_versions
                or q["question_key"]!=attention.question_key or q["target_ref"]["ref"]!=attention.case_original.original_ref
                or tuple(q["source_refs"])!=attention.context_source_refs
                or payload["provenance"]["single_event_review_case_original"]!=plain_v1(attention.case_original)):
            raise ValueError("review native attention differs from its actual registered Question/ticket/Case")
        native=ProductionOriginalRefV1("d07."+ATTENTION_KIND,original_ref,actual[1],(attention.ticket_ref,))
        parent=attention
    if native.original_digest!=owner.entry[4]:
        raise ValueError("review followup outbox changed its actual native original digest")
    value={"domain":row[0],"operation_kind":row[1],"request_digest":row[2],"original_digest":native.original_digest,
        "domain_original_digest":row[3],"read_versions":receipt.read_versions,"receipt":receipt,"payload":payload,
        "single_event_review_parent":parent,"single_event_review_native":native}
    _REVIEW_FOLLOWUP_CAUSES[owner]=(value,owner.entry_column,owner.operation,owner.graph_stamp)
    return value

@dataclass(frozen=True)
class _SingleEventReviewFollowupParentV1:
    case_original:ProductionOriginalRefV1
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float

def single_event_review_followup_plan_v1(db,*,namespace,event):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    owner=_active_v3(db)
    original=read_single_event_review_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if(original is None or event.receiver_domain!="d07"or event.trigger_original.original_digest!=original["original_digest"]):
        raise ValueError("review followup plan differs from its actual signed native event")
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),())

def resolve_single_event_review_followup_v1(db,*,frame,event,original):
    from .domain_background_read_v3 import _active_v3
    from .domain_production_followups_v1 import DomainFollowupResolutionV1,DomainFollowupCommandV1
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    owner=_require_review_followup_owner_v1(_active_v3(db),db,event.event_kind)
    if(_REVIEW_FOLLOWUP_CAUSES.get(owner)!=(original,owner.entry_column,owner.operation,owner.graph_stamp)
            or event.receiver_domain!="d07"):
        raise ValueError("review followup resolution left its retained actual native cause")
    CurrentDomainReadV1(frame).check(db)
    parent=original["single_event_review_parent"]
    if frame.now_utc>=parent.original_deadline_utc:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),("single_event_review_original_parent_expired",))
    native=original["single_event_review_native"]
    if event.event_kind==_CASE_REGISTERED_EVENT_V1:
        request=RegisterSingleEventReviewAttentionRequestV1(native);operation=REGISTER_OPERATION
        activity="single-event-review-register:"+native.original_ref.removeprefix("single-event-review-case:")
    else:
        request=ServeCurrentConcernRequestV1("background",parent.semantic_question_ref);operation="serve_concern"
        activity=single_event_review_attention_ids_v1(owner.namespace,parent.case_original)["activity"]
    command=DomainFollowupCommandV1("d07",operation,request,activity,
        frame.envelope.authority.audience[0],frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready",(command,),(),())

def single_event_review_followup_parent_from_prepared_v1(prepared,event,command):
    prepared.require_v3(prepared.graph);owner=prepared.owner
    state=_REVIEW_FOLLOWUP_CAUSES.get(owner)
    if state is None:return None
    original,task,operation,stamp=state
    if(task is not owner.entry_column or operation is not owner.operation or stamp!=owner.graph_stamp
            or event.event_kind not in {_CASE_REGISTERED_EVENT_V1,_REVIEW_ATTENTION_EVENT_V1}
            or event.causal_operation_id!=original["receipt"].operation_id
            or command is not None and command not in prepared.local_result[5].commands):
        raise ValueError("review parent budget left its actual prepared same-Work native followup")
    if event.event_kind==_REVIEW_ATTENTION_EVENT_V1:
        census=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
        located=None if census is None or not census.complete else census.result
        if located is not None:return located.require_current_v1(owner)
    return original["single_event_review_parent"]

def release_single_event_review_followup_metadata_v1(owner):
    _REVIEW_FOLLOWUP_CAUSES.pop(owner,None)


def parse_current_single_event_review_output_v1(prepared,text,frozen):
    from ..model_broker.d07_cognition_v1 import parse_d07_cognition_output_v1,FrozenD07CognitionRequestV1
    if(type(prepared)is not D07SingleEventReviewPreparedV1 or type(frozen)is not FrozenD07CognitionRequestV1
            or frozen.input.target_original_kind!=CASE_KIND
            or frozen.input.target_ref!=prepared.review_case_original.original_ref
            or frozen.input.target_original_digest!=prepared.review_case_original.original_digest
            or frozen.input.question!=_FIXED_QUESTION or frozen.input.causal_depth!=prepared.causal_depth):
        raise ValueError("review output needs its exact authenticated dedicated Prepared/Frozen Case binding")
    suggestion=parse_d07_cognition_output_v1(text,frozen)
    if len(suggestion.findings)!=1:
        raise SingleEventReviewCardinalityRejectedV1(_REVIEW_ISSUER,prepared,frozen,suggestion,text)
    return suggestion


_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1="single_event_review_adoption_v1"
_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1="single_event_review_cognition_adopted_v1"
_REVIEW_COMPLETION_SELECTIONS=WeakKeyDictionary()
_REVIEW_COMPLETION_FACTS=WeakKeyDictionary()
_REVIEW_COMPLETION_CAUSES=WeakKeyDictionary()

def single_event_review_adoption_original_ref_v1(namespace,job_id):
    return "single-event-review-adoption:"+canonical_digest((namespace,job_id))[:48]

def single_event_review_service_operation_id_v1(attention):
    if type(attention)is not SingleEventReviewAttentionOriginalV1:
        raise TypeError("actual typed review attention required for its deterministic service identity")
    return "single-event-review-serve:"+attention.semantic_question_ref.removeprefix(QUESTION_PREFIX)

@dataclass(frozen=True,slots=True)
class D07SingleEventReviewAdoptionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    operation_id:str
    job_id:str
    call_id:str
    case_original:ProductionOriginalRefV1
    question_original:ProductionOriginalRefV1
    prepared_original:ProductionOriginalRefV1
    adopted_original:ProductionOriginalRefV1
    adoption_version:GraphVersion
    review_version:GraphVersion
    interpretation_version:GraphVersion
    interpretation_value_digest:str
    graph_receipt_digest:str
    commit_receipt_digest:str
    domain_original_digest:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    schema:str="d07.single-event-review-adoption.v1"

    def __post_init__(self):
        from .d07_execution_v1 import d07_execution_ids_v1
        from ..domains.d01.identity_v3 import _digest
        from ..domains.d01.single_event_growth_v1 import REVIEW_TYPE_V2
        ids=d07_execution_ids_v1(self.namespace,self.operation_id,"concern")
        if(self.schema!="d07.single-event-review-adoption.v1"
                or(self.job_id,self.call_id)!=(ids["job"],ids["call"])
                or self.original_ref!=single_event_review_adoption_original_ref_v1(self.namespace,self.job_id)):
            raise ValueError("review completion changed its exact actual C3 identity")
        for original,kind in ((self.case_original,"d01."+CASE_KIND),(self.question_original,"d07.semantic_question"),
                (self.prepared_original,"d07.prepared"),(self.adopted_original,"d07.adopted")):
            if type(original)is not ProductionOriginalRefV1 or original.kind!=kind:
                raise ValueError("review completion has an unregistered actual original kind")
        if(self.prepared_original.original_ref!=self.job_id
                or self.adopted_original.original_ref!=self.interpretation_version.key.token
                or self.review_version.key.type_name!=REVIEW_TYPE_V2
                or self.interpretation_version.key.type_name!="d07.current_interpretation.v1"):
            raise ValueError("review completion lost its actual Case/review/interpretation locators")
        for v in(self.adoption_version,self.review_version,self.interpretation_version):
            if type(v)is not GraphVersion or v.revision<1 or NamespaceId.from_key(v.key)!=self.namespace:
                raise ValueError("review completion crossed an actual namespace or revision")
        for digest in(self.interpretation_value_digest,self.graph_receipt_digest,self.commit_receipt_digest,
                self.domain_original_digest,self.original_parent_grant_digest):_digest(digest)
        if(not self.original_parent_budget_lease_ref or type(self.original_deadline_utc)not in(int,float)
                or not __import__("math").isfinite(self.original_deadline_utc)):
            raise ValueError("review completion lost its original finite parent resources")

def record_actual_single_event_review_adoption_v1(db,*,issuer,prepared,execution,writes,receipt,commit_receipt,domain_original):
    from .d07_execution_v1 import D07ExecutionOriginalV1,read_d07_original_v1,record_d07_original_in_transaction_v1
    if type(prepared)is not D07SingleEventReviewPreparedV1:return None
    from .d07_graph_stages_v1 import _D07AuthoredSuccessorV3
    from .domain_background_read_v3 import _active_v3
    from ..runtime_contracts import CommitReceipt
    owner=_active_v3(db);proof=None if owner is None else getattr(owner,"d07_authored_successor",None)
    if(type(proof)is not _D07AuthoredSuccessorV3 or proof.db is not db or proof.prepared is not prepared
            or proof.receipt is not receipt or type(execution)is not D07ExecutionOriginalV1
            or type(commit_receipt)is not CommitReceipt or commit_receipt.status!="committed"
            or commit_receipt.operation_id!=prepared.operation_id or type(domain_original)is not ProductionOriginalRefV1):
        raise ValueError("review completion requires its actual same-transaction paid adoption successor")
    proof.require_current()
    selected=tuple(w for w in writes if w.key.type_name=="d07.current_interpretation.v1")
    if len(selected)!=1:raise ValueError("review must adopt its one exact actual continuity interpretation")
    write=selected[0];version=next(v for v in receipt.revisions if v.key==write.key)
    adopted=read_d07_original_v1(db,issuer,prepared.namespace,"adopted",write.key.token)
    if(adopted is None or adopted[0]["prepared_digest"]!=prepared.digest
            or adopted[0]["graph_receipt_digest"]!=canonical_digest(receipt)
            or adopted[0]["interpretation_revision"]!=version.revision
            or adopted[0]["interpretation_value_digest"]!=canonical_digest(write.value)
            or(execution.operation_id,execution.execution_id,execution.causal_depth)!=
                (prepared.operation_id,prepared.execution_id,prepared.causal_depth)):
        raise ValueError("review completion differs from the actual paid C3 Graph adoption")
    from .domain_background_read_v3 import background_json_loads_v3
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
    frozen=thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))
    case=_case_from_wire_v1(background_json_loads_v3(frozen.input.target_original_json))
    if(canonical_digest(plain_v1(case))!=prepared.review_case_original.original_digest
            or write.value["question_key"]!=frozen.input.question_key
            or case.adoption_version!=prepared.adoption_version):
        raise ValueError("review completion changed its actual complete inspected Case")
    value=D07SingleEventReviewAdoptionOriginalV1(prepared.namespace,
        single_event_review_adoption_original_ref_v1(prepared.namespace,prepared.job_id),
        prepared.operation_id,prepared.job_id,prepared.call_id,prepared.review_case_original,
        ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,prepared.semantic_question_digest),
        ProductionOriginalRefV1("d07.prepared",prepared.job_id,prepared.digest),
        ProductionOriginalRefV1("d07.adopted",write.key.token,adopted[1],(version,)),
        case.adoption_version,case.review_version,version,canonical_digest(write.value),canonical_digest(receipt),
        canonical_digest(commit_receipt),domain_original.original_digest,prepared.original_parent_budget_lease_ref,
        prepared.original_parent_grant_digest,prepared.original_deadline_utc)
    digest=record_d07_original_in_transaction_v1(db,issuer,prepared.namespace,
        _SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,value.original_ref,plain_v1(value))
    dedupe="domain-event:"+canonical_digest((prepared.namespace,prepared.operation_id,"d01",
        _SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1,value.original_ref))[:48]
    row=(*prepared.namespace.as_tuple,dedupe,prepared.operation_id,"d01",_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1,
        value.original_ref,digest,"pending",None,None)
    old=db.execute("SELECT * FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",row[:3]).fetchone()
    if old is not None and old!=row:raise ValueError("review completion changed its actual durable event identity")
    if old is None:db.execute("INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",row)
    return ProductionOriginalRefV1("d07."+_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,value.original_ref,digest,(version,))

def single_event_review_completion_metadata_retains_path_v1(path):
    return not path or path[0]in {f.name for f in fields(D07SingleEventReviewAdoptionOriginalV1)}

def single_event_review_completion_cause_locator_path_v1(owner,column,path):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3:return None
    require_actual_background_attachment_owner_v3(owner,db=owner.db);task=owner.entry_column
    if(task is None or task.column is not column or task.entry is None
            or task.entry[1:3]!=("d01",_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1)):return None
    if task.metadata[:2]!=("d07","serve_concern"):
        raise ValueError("review completion event has another actual business producer")
    return not path or path[0]in {"schema","namespace","identity","authority","parent_budget","coverage","now_utc"}

def single_event_review_completion_metadata_request_allowed_v1(owner,request):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3 or owner.entry is None:return False
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    from .d07_execution_v1 import TABLE,d07_execution_ids_v1
    namespace=owner.namespace;ref=None
    state=_REVIEW_FOLLOWUP_CAUSES.get(owner)
    if(state is not None and state[1:] ==(owner.entry_column,owner.operation,owner.graph_stamp)
            and owner.entry[1:3]==("d07",_REVIEW_ATTENTION_EVENT_V1)):
        attention=state[0]["single_event_review_parent"]
        located=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
        fact=None if located is None or not located.complete else located.result
        if fact is not None:fact.require_current_v1(owner)
        job=(d07_execution_ids_v1(namespace,single_event_review_service_operation_id_v1(attention),"concern")["job"]
            if fact is None else fact.job_id)
        ref=single_event_review_adoption_original_ref_v1(namespace,job)
    elif(owner.entry[1:3]==("d01",_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1)
            and owner.entry_column is not None and owner.entry_column.metadata[:2]==("d07","serve_concern")):
        ref=owner.entry[3]
    if ref is not None and request==(TABLE,("payload_json","payload_digest","signature"),
            ("bot","persona","kind","original_ref"),(*namespace.as_tuple,_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,ref)):return True
    selected=_REVIEW_COMPLETION_SELECTIONS.get(owner)
    if selected is None or selected[:3]!=(owner.operation,owner.graph_stamp,owner.entry_column):return False
    value,activity=selected[3:]
    from .domain_production_originals_v1 import TABLE as DOMAIN
    if request==(DOMAIN,("domain","operation_kind","original_digest","bundle_digest","receipt_json","receipt_digest"),
            ("bot","persona","operation_id"),(*namespace.as_tuple,value.operation_id)):return True
    if activity is None:return False
    return request in {
        ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            ("bot","persona","operation_id"),(*namespace.as_tuple,value.operation_id)),
        ("graph_events",("reads","revisions","epoch_revision"),
            ("bot","persona","session","event_id"),(*namespace.as_tuple,activity,value.operation_id))}

@dataclass(frozen=True,eq=False)
class _ActualSingleEventReviewCompletionV1:
    value:D07SingleEventReviewAdoptionOriginalV1
    original:ProductionOriginalRefV1
    receipt:object
    @property
    def status(self):return "adopted"
    def require_current_v1(self,owner):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        if _REVIEW_COMPLETION_FACTS.get(self)!=(owner,owner.operation,owner.graph_stamp,owner.entry_column):
            raise ValueError("review completion left its actual current Background Work")
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(owner.db)as meter:owner.require_data_current_v3(meter)
        return self

def _read_actual_single_event_review_completion_v1(db,*,namespace,original_ref,issuer):
    from .domain_background_read_v3 import (_active_v3,require_actual_background_attachment_owner_v3,
        background_point_v3,background_json_loads_v3,background_typed_original_digest_v3)
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import TABLE,_receipt,reconstruct_graph_bundle_commit_receipt_v1
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer:
        raise ValueError("review completion changed its actual namespace or installed issuer")
    row=read_d07_original_v1(db,issuer,namespace,_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,original_ref)
    if row is None:
        _REVIEW_COMPLETION_SELECTIONS.pop(owner,None);return None
    value=decode_typed_production_value_v1(row[0],D07SingleEventReviewAdoptionOriginalV1)
    if value.namespace!=namespace or value.original_ref!=original_ref:
        raise ValueError("review completion selected another actual signed native original")
    _REVIEW_COMPLETION_SELECTIONS[owner]=(owner.operation,owner.graph_stamp,owner.entry_column,value,None)
    business=background_point_v3(db,table=TABLE,
        columns=("domain","operation_kind","original_digest","bundle_digest","receipt_json","receipt_digest"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,value.operation_id),legacy_reader=lambda:None)
    if business is None or business[:2]!=("d07","serve_concern")or business[2]!=value.domain_original_digest:
        raise ValueError("review completion has no actual business DomainOriginal")
    receipt=_receipt(background_json_loads_v3(business[4]))
    if(receipt.status!="committed"or receipt.operation_id!=value.operation_id
            or background_typed_original_digest_v3(db,business[4],receipt)!=value.commit_receipt_digest):
        raise ValueError("review completion changed its actual business receipt")
    _REVIEW_COMPLETION_SELECTIONS[owner]=(owner.operation,owner.graph_stamp,owner.entry_column,value,receipt.activity_id)
    bundle=background_point_v3(db,table="graph_bundle_operations",columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,value.operation_id),legacy_reader=lambda:None)
    event=background_point_v3(db,table="graph_events",columns=("reads","revisions","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,receipt.activity_id,value.operation_id),
        legacy_reader=lambda:None)
    if(bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or business[3]!=receipt.operation_digest or business[5]!=value.commit_receipt_digest
            or value.interpretation_version not in receipt.write_versions or event is None
            or reconstruct_graph_bundle_commit_receipt_v1(namespace,value.operation_id,(*bundle,business[4]),event)!=receipt):
        raise ValueError("review completion lost actual bundle/event/receipt membership")
    fact=_ActualSingleEventReviewCompletionV1(value,
        ProductionOriginalRefV1("d07."+_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,original_ref,row[1],(value.interpretation_version,)),receipt)
    _REVIEW_COMPLETION_FACTS[fact]=(owner,owner.operation,owner.graph_stamp,owner.entry_column)
    return fact.require_current_v1(owner)

def read_single_event_review_service_completion_v1(db,*,namespace,job_id,issuer):
    from .domain_background_read_v3 import _active_v3
    from .d07_execution_v1 import d07_execution_ids_v1
    owner=_active_v3(db);state=_REVIEW_FOLLOWUP_CAUSES.get(owner)
    if(state is None or state[1:]!=(owner.entry_column,owner.operation,owner.graph_stamp)
            or owner.entry[1:3]!=("d07",_REVIEW_ATTENTION_EVENT_V1)):
        raise ValueError("review service completion requires its actual attention Background cause")
    attention=state[0]["single_event_review_parent"]
    located=read_current_d07_attention_prepared_job_metadata_v1(db,namespace=namespace,issuer=issuer)
    expected=(d07_execution_ids_v1(namespace,single_event_review_service_operation_id_v1(attention),"concern")["job"]
        if located is None else located.job_id)
    if job_id!=expected:
        raise ValueError("review completion selected another actual signed prepared continuation")
    fact=_read_actual_single_event_review_completion_v1(db,namespace=namespace,
        original_ref=single_event_review_adoption_original_ref_v1(namespace,job_id),issuer=issuer)
    if fact is not None and(fact.value.case_original!=attention.case_original
            or fact.value.question_original.original_ref!=attention.semantic_question_ref):
        raise ValueError("review completed call differs from its exact registered attention/Case")
    return fact

def read_single_event_review_completion_followup_cause_v1(db,*,namespace,event_kind,causal_operation_id,original_ref,issuer):
    if event_kind!=_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1:return None
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if(owner.entry is None or owner.entry[:4]!=(causal_operation_id,"d01",event_kind,original_ref)
            or owner.entry_column is None or not owner.entry_column.complete):
        raise ValueError("review completion cause needs its actual same-Work native outbox EOF")
    fact=_read_actual_single_event_review_completion_v1(db,namespace=namespace,original_ref=original_ref,issuer=issuer)
    if fact is None or fact.value.operation_id!=causal_operation_id or fact.original.original_digest!=owner.entry[4]:
        raise ValueError("review completion outbox changed its actual signed native original")
    metadata,payload=owner.entry_metadata
    if(metadata[:2]!=("d07","serve_concern")or metadata[2]!=fact.value.domain_original_digest
            or payload["identity"]["operation_id"]!=causal_operation_id or payload["coverage"]!="complete"):
        raise ValueError("review completion changed its actual complete business producer")
    original={"domain":"d07","operation_kind":"serve_concern","original_digest":fact.original.original_digest,
        "domain_original_digest":fact.value.domain_original_digest,"read_versions":fact.receipt.read_versions,
        "receipt":fact.receipt,"payload":payload,"single_event_review_completion":fact}
    _REVIEW_COMPLETION_CAUSES[owner]=(original,fact,owner.operation,owner.graph_stamp)
    return original

def single_event_review_completion_followup_plan_v1(db,*,namespace,event):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    owner=_active_v3(db)
    cause=read_single_event_review_completion_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if cause is None or event.receiver_domain!="d01"or cause["original_digest"]!=event.trigger_original.original_digest:
        raise ValueError("review completion plan changed its actual native event")
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),())

def resolve_single_event_review_completion_followup_v1(db,*,frame,event,original):
    from .domain_background_read_v3 import _active_v3
    from .domain_production_followups_v1 import DomainFollowupResolutionV1,DomainFollowupCommandV1
    from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    owner=_active_v3(db);state=_REVIEW_COMPLETION_CAUSES.get(owner)
    if state is None or state[0]is not original or state[2:]!=(owner.operation,owner.graph_stamp):
        raise ValueError("review final child left its actual retained completion metadata")
    fact=state[1];fact.require_current_v1(owner)
    CurrentDomainReadV1(frame).check(db);v=fact.value
    if frame.now_utc>=v.original_deadline_utc:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),("single_event_review_original_parent_expired",))
    if event.event_kind!=_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1 or event.receiver_domain!="d01":
        raise ValueError("review final child changed its actual adopted cognition receiver")
    request=ReviewSingleEventGrowthRequestV1(v.adoption_version.key.token,v.review_version.revision,v.interpretation_version.key.token)
    command=DomainFollowupCommandV1("d01","review_single_event_growth_v1",request,
        "single-event-review-final:"+v.case_original.original_ref.removeprefix("single-event-review-case:"),
        frame.envelope.authority.audience[0],frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready",(command,),(),())

def single_event_review_completion_parent_from_prepared_v1(prepared,event,command):
    prepared.require_v3(prepared.graph);owner=prepared.owner
    result=prepared.local_result[5]
    if event.event_kind!=_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1:return None
    if command is not None and command not in result.commands:
        raise ValueError("review final budget parent has another actual child command")
    state=_REVIEW_COMPLETION_CAUSES.get(owner)
    if state is None or state[2:]!=(owner.operation,owner.graph_stamp):
        raise ValueError("review final parent left its actual retained completion metadata")
    state[1].require_current_v1(owner)
    return state[1].value

def release_single_event_review_completion_metadata_v1(owner):
    release_single_event_review_interpretation_case_metadata_v1(owner)
    _REVIEW_COMPLETION_SELECTIONS.pop(owner,None)
    _REVIEW_REJECTION_SELECTIONS.pop(owner,None)
    for fact,state in tuple(_REVIEW_REJECTION_FACTS.items()):
        if state[0]is owner:_REVIEW_REJECTION_FACTS.pop(fact,None)
    _REVIEW_COMPLETION_CAUSES.pop(owner,None)
    for fact,state in tuple(_REVIEW_COMPLETION_FACTS.items()):
        if state[0]is owner:_REVIEW_COMPLETION_FACTS.pop(fact,None)


_REVIEW_CARDINALITY_ERRORS=WeakKeyDictionary()
_REVIEW_REJECTION_STAGES=WeakKeyDictionary()
_REVIEW_REJECTION_SELECTIONS=WeakKeyDictionary()
_REVIEW_REJECTION_FACTS=WeakKeyDictionary()
_REVIEW_CARDINALITY_KIND_V1="single_event_review_cardinality_rejected_v1"

class SingleEventReviewCardinalityRejectedV1(ValueError):
    def __init__(self,issuer,prepared,frozen,suggestion,text):
        if issuer is not _REVIEW_ISSUER:raise TypeError("actual Case parser issuer required")
        super().__init__("single-event review requires exactly one continuity finding")
        from hashlib import sha256
        _REVIEW_CARDINALITY_ERRORS[self]=(prepared,frozen.input_digest,suggestion.output_digest,
            len(suggestion.findings),sha256(text.encode()).hexdigest())

def single_event_review_cardinality_rejection_ref_v1(namespace,job_id):
    return "single-event-review-parse-rejected:"+canonical_digest((namespace,job_id))[:48]

@dataclass(frozen=True,slots=True)
class D07SingleEventReviewCardinalityRejectionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    operation_id:str
    rejection_operation_id:str
    activity_id:str
    job_id:str
    call_id:str
    worker_fence:int
    case_original:ProductionOriginalRefV1
    question_original:ProductionOriginalRefV1
    prepared_original:ProductionOriginalRefV1
    result_original:ProductionOriginalRefV1
    paid_original:ProductionOriginalRefV1
    body_original:ProductionOriginalRefV1
    frozen_input_digest:str
    output_digest:str
    finding_count:int
    job_version:GraphVersion
    job_value_digest:str
    ticket_version:GraphVersion
    ticket_value_digest:str
    graph_receipt_digest:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    reason:str="finding_cardinality"
    frozen_contract_schema:str="sylanne.d07.cognition_input.v1"
    schema:str="d07.single-event-review-cardinality-rejected.v1"

    def __post_init__(self):
        from .d07_execution_v1 import d07_execution_ids_v1
        from ..domains.d01.identity_v3 import _digest
        from ..model_broker.d07_cognition_v1 import INPUT_SCHEMA
        ids=d07_execution_ids_v1(self.namespace,self.operation_id,"concern")
        if(self.schema!="d07.single-event-review-cardinality-rejected.v1"or self.reason!="finding_cardinality"
                or self.frozen_contract_schema!=INPUT_SCHEMA
                or(self.job_id,self.call_id)!=(ids["job"],ids["call"])
                or self.original_ref!=single_event_review_cardinality_rejection_ref_v1(self.namespace,self.job_id)
                or type(self.finding_count)is not int or self.finding_count not in {0,2,3,4}
                or type(self.worker_fence)is not int or self.worker_fence<1):
            raise ValueError("Case cardinality rejection has another exact typed terminal identity")
        for original,kind in ((self.case_original,"d01."+CASE_KIND),(self.question_original,"d07.semantic_question"),
                (self.prepared_original,"d07.prepared"),(self.result_original,"d07.result"),
                (self.paid_original,"d07.paid_cost"),(self.body_original,"d07.body_cost")):
            if type(original)is not ProductionOriginalRefV1 or original.kind!=kind:
                raise ValueError("Case cardinality rejection has another actual original kind")
        if(self.prepared_original.original_ref!=self.job_id or self.paid_original.original_ref!=self.job_id
                or self.body_original.original_ref!=self.job_id
                or self.job_version.key.type_name!="runtime.job"
                or self.ticket_version.key.type_name!="d07.attention_ticket.v1"):
            raise ValueError("Case cardinality rejection lost its actual job/ticket/paid members")
        for v in(self.job_version,self.ticket_version):
            if type(v)is not GraphVersion or v.revision<1 or NamespaceId.from_key(v.key)!=self.namespace:
                raise ValueError("Case rejection terminal members crossed their actual namespace")
        for v in(self.frozen_input_digest,self.output_digest,self.job_value_digest,self.ticket_value_digest,
                self.graph_receipt_digest,self.original_parent_grant_digest):_digest(v)
        if(not self.rejection_operation_id or not self.activity_id or not self.original_parent_budget_lease_ref
                or type(self.original_deadline_utc)not in(int,float)
                or not __import__("math").isfinite(self.original_deadline_utc)):
            raise ValueError("Case rejection lost its actual finite resources")

@dataclass(eq=False)
class _SingleEventReviewRejectionStageV1:
    prepared:D07SingleEventReviewPreparedV1
    error:SingleEventReviewCardinalityRejectedV1
    result:ProductionOriginalRefV1
    paid:ProductionOriginalRefV1
    body:ProductionOriginalRefV1
    job:object
    writes:tuple
    reads:tuple
    rejection_operation_id:str
    original_ref:str

def stage_single_event_review_cardinality_rejection_v1(db,*,prepared,error,issuer,holder,fence):
    from .domain_background_read_v3 import _active_v3,require_bound_d07_write_data_v3,background_json_loads_v3
    from .d07_execution_v1 import read_d07_original_v1
    from .jobs import get_job,transition_job
    from .d11_types import job_graph_write
    from ..runtime_storage_v3 import read_graph_row_v3
    from ..domains.d07 import AttentionTicket
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    owner=_active_v3(db)
    if(type(prepared)is not D07SingleEventReviewPreparedV1 or type(error)is not SingleEventReviewCardinalityRejectedV1
            or owner is None or owner.kind!="d07_stage"or owner.d07_selector.stage!="complete"
            or owner.namespace!=prepared.namespace or owner.d07_selector.parent_job_id!=prepared.job_id):
        raise ValueError("Case rejection requires the actual same private terminal Stage")
    proof=getattr(owner,"d07_authored_successor",None)
    if proof is None:require_bound_d07_write_data_v3(db)
    else:proof.require_current()
    parser=_REVIEW_CARDINALITY_ERRORS.get(error)
    if parser is None or parser[0]is not prepared:
        raise ValueError("Case rejection is not the exact dedicated parser's typed cardinality result")
    paid=read_d07_original_v1(db,issuer,prepared.namespace,"paid_cost",prepared.job_id)
    body=read_d07_original_v1(db,issuer,prepared.namespace,"body_cost",prepared.job_id)
    result=read_d07_original_v1(db,issuer,prepared.namespace,"result","d07-result:"+prepared.call_id)
    if(paid is None or body is None or result is None or paid[0]["paid"]is not True or paid[0]["unknown_dimensions"]
            or body[0]["unpaid_cost"]or paid[0]["prepared_digest"]!=prepared.digest or body[0]["prepared_digest"]!=prepared.digest
            or paid[0]["result_ref"]!="d07-result:"+prepared.call_id
            or paid[0]["result_digest"]!=body[0]["result_digest"]or paid[0]["terminal_digest"]!=body[0]["terminal_digest"]):
        raise ValueError("Case rejection has no exact actual paid/result/body originals")
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1,from_wire
    from hashlib import sha256
    result_read=from_wire(result[0],D07CognitionResultReadV1)
    text=background_json_loads_v3(result_read.observation.result_json)
    if(set(text)!={"text"}or sha256(text["text"].encode()).hexdigest()!=parser[4]
            or result_read.observation.digest!=paid[0]["result_digest"]):
        raise ValueError("Case rejection differs from the original actual provider output")
    job=get_job(db,prepared.job_id)
    if(job.phase!="running"or job.fence!=fence or job.lease_holder!=holder or job.cancel_epoch
            or job.operation_id!=prepared.operation_id or job.activity_id!=prepared.activity_id):
        raise ValueError("Case rejection lost its actual current running worker fence")
    ref=single_event_review_cardinality_rejection_ref_v1(prepared.namespace,prepared.job_id)
    attention=read_d07_original_v1(db,issuer,prepared.namespace,ATTENTION_KIND,prepared.review_attention_ref)
    if attention is None or attention[1]!=prepared.review_attention_digest:
        raise ValueError("Case rejection lost its actual registered fair Attention")
    a=decode_typed_production_value_v1(attention[0],SingleEventReviewAttentionOriginalV1)
    key=a.ticket_ref.key
    row=read_graph_row_v3(db,("revision","value","valid"),where="token=?",parameters=(key.token,))
    if row is None or not row[2]or row[0]!=a.ticket_ref.revision:
        raise ValueError("Case rejection fair ticket changed before terminal CAS")
    raw=background_json_loads_v3(row[1])
    if canonical_digest(raw)!=a.ticket_value_digest:raise ValueError("Case rejection fair ticket changed its exact registered values")
    ticket=decode_typed_production_value_v1({k:v for k,v in raw.items()if k!="schema"},AttentionTicket)
    terminal=replace(ticket,eligible=False,resources_available=False,cancel_refs=(ref,))
    ticket_write=GraphWrite(key,{"schema":key.type_name,**plain_v1(terminal)},tuple(AtomKey.from_token(r)for r in ticket.source_refs))
    failed=transition_job(db,prepared.job_id,holder,fence,target_phase="failed",result_ref=ref)
    job_write=job_graph_write(failed)
    job_row=db.execute("SELECT revision FROM graph_atoms WHERE token=?",(job_write.key.token,)).fetchone()
    if job_row is None:raise ValueError("Case rejection has no current actual RuntimeJob projection")
    value=_SingleEventReviewRejectionStageV1(prepared,error,
        ProductionOriginalRefV1("d07.result","d07-result:"+prepared.call_id,result[1]),
        ProductionOriginalRefV1("d07.paid_cost",prepared.job_id,paid[1]),
        ProductionOriginalRefV1("d07.body_cost",prepared.job_id,body[1]),failed,(job_write,ticket_write),
        (GraphVersion(job_write.key,job_row[0]),GraphVersion(key,row[0])),
        "d07-case-parse-reject:"+canonical_digest((prepared.namespace,prepared.call_id))[:48],ref)
    _REVIEW_REJECTION_STAGES[value]=(owner,owner.operation,prepared,error,parser,
        canonical_digest(value.writes),(value.result,value.paid,value.body),value.job,
        value.rejection_operation_id,value.original_ref)
    return value

def record_single_event_review_cardinality_rejection_after_cas_v1(db,*,stage,receipt,issuer):
    from .domain_background_read_v3 import _active_v3
    from .d07_graph_stages_v1 import _D07AuthoredSuccessorV3
    from .d07_execution_v1 import record_d07_original_in_transaction_v1
    owner=_active_v3(db);state=_REVIEW_REJECTION_STAGES.get(stage);p=stage.prepared
    proof=None if owner is None else getattr(owner,"d07_authored_successor",None)
    if(state is None or state[:4]!=(owner,owner.operation,p,stage.error)or type(proof)is not _D07AuthoredSuccessorV3
            or proof.prepared is not p or proof.receipt is not receipt or proof.candidate.event.event_id!=stage.rejection_operation_id):
        raise ValueError("Case rejection needs its actual same-W01 terminal Graph CAS successor")
    proof.require_current();parser=state[4]
    if(canonical_digest(stage.writes)!=state[5]or canonical_digest(proof.candidate.writes)!=state[5]
            or(stage.result,stage.paid,stage.body)!=state[6]or stage.job is not state[7]
            or(stage.rejection_operation_id,stage.original_ref)!=state[8:]):
        raise ValueError("Case rejection changed its exact private terminal Stage members")
    versions={v.key:v for v in receipt.revisions}
    if set(versions)!={w.key for w in stage.writes}:raise ValueError("Case rejection terminal CAS changed its exact members")
    job,ticket=stage.writes
    value=D07SingleEventReviewCardinalityRejectionOriginalV1(p.namespace,stage.original_ref,p.operation_id,
        stage.rejection_operation_id,p.activity_id,p.job_id,p.call_id,stage.job.fence,p.review_case_original,
        ProductionOriginalRefV1("d07.semantic_question",p.semantic_question_ref,p.semantic_question_digest),
        ProductionOriginalRefV1("d07.prepared",p.job_id,p.digest),stage.result,stage.paid,stage.body,
        parser[1],parser[2],parser[3],versions[job.key],canonical_digest(job.value),
        versions[ticket.key],canonical_digest(ticket.value),canonical_digest(receipt),
        p.original_parent_budget_lease_ref,p.original_parent_grant_digest,p.original_deadline_utc)
    digest=record_d07_original_in_transaction_v1(db,issuer,p.namespace,_REVIEW_CARDINALITY_KIND_V1,
        value.original_ref,plain_v1(value))
    _REVIEW_REJECTION_STAGES.pop(stage,None);_REVIEW_CARDINALITY_ERRORS.pop(stage.error,None)
    return ProductionOriginalRefV1("d07."+_REVIEW_CARDINALITY_KIND_V1,value.original_ref,digest,
        (value.job_version,value.ticket_version))


@dataclass(frozen=True,eq=False)
class _ActualSingleEventReviewRejectedDispositionV1:
    value:D07SingleEventReviewCardinalityRejectionOriginalV1
    original:ProductionOriginalRefV1
    status:str="parse_rejected"
    def require_current_v1(self,owner):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        if _REVIEW_REJECTION_FACTS.get(self)!=(owner,owner.operation,owner.graph_stamp,owner.entry_column):
            raise ValueError("Case parse rejection left its actual current attention metadata Work")
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(owner.db)as meter:owner.require_data_current_v3(meter)
        return self

def single_event_review_rejection_metadata_request_allowed_v1(owner,request):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3 or owner.entry is None:return False
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    state=_REVIEW_FOLLOWUP_CAUSES.get(owner)
    if(state is None or state[1:]!=(owner.entry_column,owner.operation,owner.graph_stamp)
            or owner.entry[1:3]!=("d07",_REVIEW_ATTENTION_EVENT_V1)):return False
    from .d07_execution_v1 import TABLE,d07_execution_ids_v1
    namespace=owner.namespace;attention=state[0]["single_event_review_parent"]
    located=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
    fact=None if located is None or not located.complete else located.result
    if fact is not None:fact.require_current_v1(owner)
    job_id=(d07_execution_ids_v1(namespace,single_event_review_service_operation_id_v1(attention),"concern")["job"]
        if fact is None else fact.job_id)
    ref=single_event_review_cardinality_rejection_ref_v1(namespace,job_id)
    if request==(TABLE,("payload_json","payload_digest","signature"),("bot","persona","kind","original_ref"),
            (*namespace.as_tuple,_REVIEW_CARDINALITY_KIND_V1,ref)):return True
    selected=_REVIEW_REJECTION_SELECTIONS.get(owner)
    if selected is None or selected[:3]!=(owner.operation,owner.graph_stamp,owner.entry_column):return False
    v=selected[3]
    if request==("runtime_jobs",("operation_id","activity_id","bot_id","persona_id","phase","work_kind","fence",
            "cancel_epoch","result_ref","lease_holder","lease_expires_utc"),("job_id",),(v.job_id,)):return True
    if request==("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),
            ("bot","persona","operation_id"),(*namespace.as_tuple,v.rejection_operation_id)):return True
    if request==("graph_events",("digest","reads","revisions","invalidated","epoch_revision"),
            ("bot","persona","session","event_id"),(*namespace.as_tuple,v.activity_id,v.rejection_operation_id)):return True
    for version in(v.job_version,v.ticket_version):
        if request==("graph_atoms",("revision","value","valid"),("token",),(version.key.token,)):return True
        if request==("graph_history",("value","valid","event_bot","event_persona","event_id"),
                ("token","revision"),(version.key.token,version.revision)):return True
    return False

def single_event_review_rejection_control_retains_path_v1(owner,column,path):
    selected=_REVIEW_REJECTION_SELECTIONS.get(owner)
    if selected is None or selected[:3]!=(owner.operation,owner.graph_stamp,owner.entry_column):return None
    v=selected[3];request=(column.table,column.column,column.key_columns,column.key)
    if request==("graph_bundle_operations","receipt_json",("bot","persona","operation_id"),
            (*owner.namespace.as_tuple,v.rejection_operation_id)):
        return not path or path[0]in {"schema","status","commit_seq","phase","prepared_digest","graph_receipt_digest"}
    for version in(v.job_version,v.ticket_version):
        if request in {
                ("graph_atoms","value",("token",),(version.key.token,)),
                ("graph_history","value",("token","revision"),(version.key.token,version.revision))}:
            if not path:return True
            if version.key.type_name=="d07.attention_ticket.v1":
                from ..domains.d07 import AttentionTicket
                return path[0]in {"schema",*(f.name for f in fields(AttentionTicket))}
            from .d11_types import RuntimeJobValue
            return path[0]in {f.name for f in fields(RuntimeJobValue)}
    return None

def single_event_review_rejection_metadata_retains_path_v1(path):
    return not path or path[0]in {f.name for f in fields(D07SingleEventReviewCardinalityRejectionOriginalV1)}

def read_single_event_review_service_disposition_v1(db,*,namespace,job_id,issuer):
    adopted=read_single_event_review_service_completion_v1(db,namespace=namespace,job_id=job_id,issuer=issuer)
    if adopted is not None:return adopted
    from .domain_background_read_v3 import (_active_v3,background_point_v3,background_json_loads_v3,background_json_digest_v3)
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..graph_types import GraphReceipt,NamespaceEpoch
    from ..graph_store import GraphStore
    owner=_active_v3(db);state=_REVIEW_FOLLOWUP_CAUSES[owner];attention=state[0]["single_event_review_parent"]
    ref=single_event_review_cardinality_rejection_ref_v1(namespace,job_id)
    row=read_d07_original_v1(db,issuer,namespace,_REVIEW_CARDINALITY_KIND_V1,ref)
    if row is None:
        _REVIEW_REJECTION_SELECTIONS.pop(owner,None);return None
    v=decode_typed_production_value_v1(row[0],D07SingleEventReviewCardinalityRejectionOriginalV1)
    if(v.namespace!=namespace or v.job_id!=job_id or v.case_original!=attention.case_original
            or v.question_original.original_ref!=attention.semantic_question_ref
            or v.question_original.original_digest!=attention.semantic_question_digest):
        raise ValueError("Case parse rejection selected another actual attention/Case/question/call")
    _REVIEW_REJECTION_SELECTIONS[owner]=(owner.operation,owner.graph_stamp,owner.entry_column,v)
    job=background_point_v3(db,table="runtime_jobs",columns=("operation_id","activity_id","bot_id","persona_id",
        "phase","work_kind","fence","cancel_epoch","result_ref","lease_holder","lease_expires_utc"),
        key_columns=("job_id",),key=(job_id,),legacy_reader=lambda:None)
    if job!=(v.operation_id,v.activity_id,*namespace.as_tuple,"failed","d07.concern",v.worker_fence,0,v.original_ref,None,None):
        raise ValueError("Case rejection has no exact actual failed terminal job")
    values={}
    for version,digest in((v.job_version,v.job_value_digest),(v.ticket_version,v.ticket_value_digest)):
        current=background_point_v3(db,table="graph_atoms",columns=("revision","value","valid"),
            key_columns=("token",),key=(version.key.token,),legacy_reader=lambda:None)
        history=background_point_v3(db,table="graph_history",columns=("value","valid","event_bot","event_persona","event_id"),
            key_columns=("token","revision"),key=(version.key.token,version.revision),legacy_reader=lambda:None)
        if(current is None or history is None or current[0]!=version.revision or current[2]!=1 or history[1]!=1
                or history[2:]!=(*namespace.as_tuple,v.rejection_operation_id)):
            raise ValueError("Case rejection lost its exact actual terminal job/ticket history")
        value=background_json_loads_v3(current[1]);old=background_json_loads_v3(history[0])
        if(background_json_digest_v3(current[1],value)!=digest
                or background_json_digest_v3(history[0],old)!=digest or value!=old):
            raise ValueError("Case rejection terminal head differs from its actual same-W01 history")
        values[version.key.type_name]=value
    job_value=values["runtime.job"];ticket=values["d07.attention_ticket.v1"]
    if(job_value["job_id"]!=job_id or job_value["phase"]!="failed"or job_value["result_ref"]!=v.original_ref
            or job_value["operation_id"]!=v.operation_id or job_value["fence"]!=v.worker_fence
            or ticket["eligible"]is not False or ticket["resources_available"]is not False
            or tuple(ticket["cancel_refs"])!=(v.original_ref,)or ticket["question_key"]!=attention.question_key
            or tuple(ticket["source_refs"])!=attention.context_source_refs):
        raise ValueError("Case rejection has no exact typed negative concern/job disposition")
    bundle=background_point_v3(db,table="graph_bundle_operations",
        columns=("digest","activity_id","effect_id","commit_seq","receipt_json"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,v.rejection_operation_id),legacy_reader=lambda:None)
    event=background_point_v3(db,table="graph_events",columns=("digest","reads","revisions","invalidated","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,v.activity_id,v.rejection_operation_id),
        legacy_reader=lambda:None)
    if bundle is None or event is None:raise ValueError("Case rejection lacks its actual terminal Graph bundle/event")
    receipt=GraphReceipt("committed",GraphStore._version_rows(event[2]),GraphStore._version_rows(event[3]),
        NamespaceEpoch(*namespace.as_tuple,event[4]))
    payload=background_json_loads_v3(bundle[4])
    if(set(payload)!={"schema","status","commit_seq","phase","prepared_digest","graph_receipt_digest"}
            or payload["schema"]!="d07.actual-graph-stage.v1"or payload["status"]!="committed"
            or payload["phase"]!="case_parse_rejected"or payload["prepared_digest"]!=v.prepared_original.original_digest
            or payload["graph_receipt_digest"]!=v.graph_receipt_digest or canonical_digest(receipt)!=v.graph_receipt_digest
            or set(receipt.revisions)!={v.job_version,v.ticket_version}
            or bundle[0]!=event[0]or bundle[1:3]!=(v.activity_id,None)or payload["commit_seq"]!=bundle[3]):
        raise ValueError("Case rejection has no exact actual terminal Graph receipt membership")
    fact=_ActualSingleEventReviewRejectedDispositionV1(v,
        ProductionOriginalRefV1("d07."+_REVIEW_CARDINALITY_KIND_V1,ref,row[1],(v.job_version,v.ticket_version)))
    _REVIEW_REJECTION_FACTS[fact]=(owner,owner.operation,owner.graph_stamp,owner.entry_column)
    return fact.require_current_v1(owner)


_ATTENTION_PREPARED_CENSUS_V1=WeakKeyDictionary()
_ATTENTION_PREPARED_FACTS_V1=WeakKeyDictionary()

def _actual_attention_prepared_profile_v1(owner):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    state=_REVIEW_FOLLOWUP_CAUSES.get(owner)
    if(state is not None and state[1:] ==(owner.entry_column,owner.operation,owner.graph_stamp)
            and owner.entry[1:3]==("d07",_REVIEW_ATTENTION_EVENT_V1)):
        a=state[0]["single_event_review_parent"]
        if type(a)is not SingleEventReviewAttentionOriginalV1:raise TypeError("actual signed Case attention required")
        return("single_event_review",a,"d07.single-event-review-prepared.v1",a.case_original,None)
    from .d07_ordinary_continuity_attention_v1 import (
        _ATTENTION_FOLLOWUP_CAUSES,ATTENTION_SERVICE_EVENT,D07OrdinaryContinuityAttentionOriginalV1)
    state=_ATTENTION_FOLLOWUP_CAUSES.get(owner)
    if(state is not None and state[1:] ==(owner.entry_column,owner.operation,owner.graph_stamp)
            and owner.entry[1:3]==("d07",ATTENTION_SERVICE_EVENT)):
        a=state[0]["ordinary_continuity_attention"]
        if type(a)is not D07OrdinaryContinuityAttentionOriginalV1:raise TypeError("actual signed ordinary attention required")
        return("ordinary_continuity",a,"d07.ordinary-continuity-prepared.v1",a.basis_original,a.phase)
    raise ValueError("prepared metadata census requires this actual signed attention Background cause")

def _attention_prepared_census_identity_v1(owner):
    family,a,schema,original,phase=_actual_attention_prepared_profile_v1(owner)
    return(family,a.original_ref,a.semantic_question_ref,original.kind,original.original_ref,original.original_digest,phase)

class _AttentionPreparedMetadataColumnV1:
    def __new__(cls,task,*,table,column,key_columns,key,mode):
        from .domain_background_read_v3 import BackgroundJSONColumnV3,_ISSUER as COLUMN_ISSUER
        class Column(BackgroundJSONColumnV3):
            def __init__(self):
                self.fields_seen=set()
                super().__init__(COLUMN_ISSUER,task.owner,table=table,column=column,
                    key_columns=key_columns,key=key,locator=True)
            def retain_path_v3(self,path):
                if not path:return True
                if mode=="versions":return True
                if mode=="receipt":
                    return path[0]in {"status","operation_id","operation_digest","activity_id","effect_id","commit_seq",
                        "read_versions","write_versions","invalidated_epochs","ledger_refs","outbox_refs"}
                if mode=="runtime_job":
                    from .d11_types import RuntimeJobValue
                    return path[0]in {f.name for f in fields(RuntimeJobValue)}
                if mode=="prepare_commit":
                    return path[0]in {"schema","prepared_digest","prepare_operation_id","graph_receipt_digest","writes_digest"}
                return path[0]in {"schema","namespace","operation_id","activity_id","job_id","call_id",
                    "semantic_question_ref","semantic_question_digest","review_case_original","basis_original","phase",
                    "original_parent_budget_lease_ref","original_parent_grant_digest","original_deadline_utc"}
            def _emit_v3(self,event):
                if event.kind=="key"and len(event.path)==1:self.fields_seen.add(event.key)
                super()._emit_v3(event)
        return Column()

@dataclass(frozen=True,eq=False)
class _ActualAttentionPreparedJobMetadataV1:
    family:str
    prepared_schema:str
    phase:str|None
    operation_id:str
    activity_id:str
    job_id:str
    call_id:str
    prepared_original:ProductionOriginalRefV1
    prepare_commit_original:ProductionOriginalRefV1
    question_original:ProductionOriginalRefV1
    subject_original:ProductionOriginalRefV1
    birth_job_version:GraphVersion
    prepare_receipt:object
    job_phase:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    def require_current_v1(self,owner):
        profile=_actual_attention_prepared_profile_v1(owner)
        task=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
        if(_ATTENTION_PREPARED_FACTS_V1.get(self)!=(owner,task,owner.operation,owner.graph_stamp,owner.entry_column)
                or task is None or not task.complete or task.result is not self
                or self.family!=profile[0]or self.subject_original!=profile[3]or self.phase!=profile[4]):
            raise ValueError("prepared job locator left its actual complete signed attention metadata Work")
        task.require_current_v1()
        return self

class _D07AttentionPreparedMetadataCensusV1:
    def __init__(self,owner,identity):
        if identity!=_attention_prepared_census_identity_v1(owner):
            raise ValueError("prepared job metadata selector differs from its actual signed attention")
        self.owner,self.identity=owner,identity
        self.binding=(owner.work,owner.operation,owner.read_scope,owner.graph_stamp,owner.entry_column)
        self.profile=_actual_attention_prepared_profile_v1(owner)
        self.after="";self.count=0;self.column=None;self.selected=None;self.header=None;self.columns={}
        self.phase="census";self.complete=False;self.result=None
        owner.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.identity,self.profile,self.after,self.selected,self.header,self.columns))
    def require_current_v1(self,meter=None):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        owner=self.owner
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        if(self.binding!=(owner.work,owner.operation,owner.read_scope,owner.graph_stamp,owner.entry_column)
                or self.identity!=_attention_prepared_census_identity_v1(owner)):
            raise ValueError("prepared metadata census lost its actual Work/selection/stamp")
        if meter is None:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with runtime_storage_quantum_v3(owner.db)as current:owner.require_data_current_v3(current)
        else:owner.require_data_current_v3(meter)
        return self
    def _column_v1(self,*,table,column,key_columns,key,mode):
        return _AttentionPreparedMetadataColumnV1(self,table=table,column=column,key_columns=key_columns,key=key,mode=mode)
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d07_execution_v1 import TABLE,SIGN_KIND,d07_execution_ids_v1
        from .domain_background_read_v3 import _detach_value_v3,background_json_loads_v3
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d07_stage_content_scope_v3 import _host_prepared_class_v3
        self.require_current_v1(meter);o=self.owner;ns=o.namespace;family,a,schema,subject,phase=self.profile
        issuer=o.graph._GraphCoordinator__d11_issuer
        if self.complete:return
        if self.phase=="census":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,TABLE,("original_ref","payload_digest","signature"),
                "bot=? AND persona=? AND kind='prepared' AND original_ref>? ORDER BY original_ref LIMIT 1",
                (*ns.as_tuple,self.after))
            if row is None:
                if self.selected is None:self.complete=True;return
                self.phase="commit_header";return
            if self.count>=128:raise MissingProductionOriginalV1("complete_bounded_actual_attention_prepared_census")
            self.count+=1;self.header=row;self.after=row[0]
            self.column=self._column_v1(table=TABLE,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*ns.as_tuple,"prepared",row[0]),mode="prepared")
            self.phase="prepared";return
        if self.phase=="prepared":
            if not self.column.advance(meter):return
            value=_detach_value_v3(self.column.frozen);ref,digest,signature=self.header
            if self.column.sha256!=digest:raise ValueError("prepared metadata census failed whole canonical EOF")
            issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,"prepared",ref,digest)),signature)
            from .d07_execution_v1 import D07IngressRecallPreparedV1
            cls=(D07IngressRecallPreparedV1 if value["schema"]=="d07.ingress-recall-prepared.v1"
                else _host_prepared_class_v3(value["schema"]))
            if(self.column.fields_seen!={f.name for f in fields(cls)}or value["namespace"]!=plain_v1(ns)
                    or value["job_id"]!=ref):
                raise ValueError("prepared metadata census has an unknown or cross-namespace exact schema")
            if value["schema"]==schema:
                selected=_decode_original_v1(value["review_case_original"]if family=="single_event_review"else value["basis_original"])
                if(selected.kind,selected.original_ref,selected.original_digest)==(subject.kind,subject.original_ref,subject.original_digest)and(
                        family=="single_event_review"or value["phase"]==phase):
                    if(self.selected is not None or value["semantic_question_ref"]!=a.semantic_question_ref
                            or value["semantic_question_digest"]!=a.semantic_question_digest
                            or value["original_parent_budget_lease_ref"]!=a.original_parent_budget_lease_ref
                            or value["original_parent_grant_digest"]!=a.original_parent_grant_digest
                            or value["original_deadline_utc"]>a.original_deadline_utc):
                        raise ValueError("attention has conflicting actual Case/phase preparations or parent resources")
                    ids=d07_execution_ids_v1(ns,value["operation_id"],"concern")
                    if(value["job_id"],value["call_id"])!=(ids["job"],ids["call"]):
                        raise ValueError("prepared metadata has no exact actual C3 job identity")
                    self.selected=(value,ref,digest)
            self.column=None;self.phase="census";return
        p,ref,digest=self.selected
        if self.phase=="commit_header":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,TABLE,("payload_digest","signature"),
                "bot=? AND persona=? AND kind='prepare_commit' AND original_ref=?",(*ns.as_tuple,ref))
            if row is None:raise MissingProductionOriginalV1("actual_attention_preparation_committed_original")
            self.commit_header=row
            self.column=self._column_v1(table=TABLE,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*ns.as_tuple,"prepare_commit",ref),mode="prepare_commit")
            self.phase="commit";return
        if self.phase=="commit":
            if not self.column.advance(meter):return
            commit=_detach_value_v3(self.column.frozen)
            if(self.column.sha256!=self.commit_header[0]or self.column.fields_seen!={
                    "schema","prepared_digest","prepare_operation_id","graph_receipt_digest","writes_digest",
                    "post_read_rows","post_query_inventory_json"}):
                raise ValueError("prepared commit metadata failed its whole exact canonical EOF")
            issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,"prepare_commit",ref,self.commit_header[0])),self.commit_header[1])
            if(commit["schema"]!="d07.preparation-commit.v1"or commit["prepared_digest"]!=digest
                    or commit["prepare_operation_id"]!="d07-prepare:"+p["operation_id"]):
                raise ValueError("prepared locator has no actual signed preparation Graph commit")
            self.commit=commit;self.column=None;self.phase="bundle";return
        if self.phase=="bundle":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
                (*ns.as_tuple,self.commit["prepare_operation_id"]))
            if row is None or row[1:3]!=(p["activity_id"],None):
                raise ValueError("prepared locator has no actual exact preparation bundle")
            self.bundle=row
            self.column=self._column_v1(table="graph_bundle_operations",column="receipt_json",
                key_columns=("bot","persona","operation_id"),key=(*ns.as_tuple,self.commit["prepare_operation_id"]),mode="receipt")
            self.phase="bundle_receipt";return
        if self.phase=="bundle_receipt":
            if not self.column.advance(meter):return
            self.columns["receipt"]=self.column;self.column=None;self.phase="event_epoch";return
        if self.phase=="event_epoch":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,"graph_events",("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",
                (*ns.as_tuple,p["activity_id"],self.commit["prepare_operation_id"]))
            if row is None:raise MissingProductionOriginalV1("actual_attention_preparation_event")
            self.event_epoch=row[0]
            for name in("reads","revisions"):
                self.columns[name]=self._column_v1(table="graph_events",column=name,
                    key_columns=("bot","persona","session","event_id"),
                    key=(*ns.as_tuple,p["activity_id"],self.commit["prepare_operation_id"]),mode="versions")
            self.phase="reads";return
        if self.phase in {"reads","revisions"}:
            column=self.columns[self.phase]
            if not column.advance(meter):return
            if self.phase=="reads":self.phase="revisions";return
            from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
            receipt=reconstruct_graph_bundle_commit_receipt_v1(ns,self.commit["prepare_operation_id"],
                (*self.bundle,self.columns["receipt"].json_v3()),
                (self.columns["reads"].json_v3(),self.columns["revisions"].json_v3(),self.event_epoch))
            if canonical_digest(receipt)!=self.commit["graph_receipt_digest"]:
                raise ValueError("prepared metadata differs from its actual official typed CommitReceipt")
            jobs=tuple(v for v in receipt.write_versions if v.key.type_name=="runtime.job"and v.key.name==p["job_id"])
            if len(jobs)!=1:raise ValueError("prepared metadata has no unique actual job birth member")
            self.birth=jobs[0];self.receipt=receipt;self.phase="birth_header";return
        if self.phase=="birth_header":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,"graph_history",
                ("valid","event_bot","event_persona","event_id"),"token=? AND revision=?",(self.birth.key.token,self.birth.revision))
            if row!=(1,*ns.as_tuple,self.commit["prepare_operation_id"]):
                raise ValueError("prepared job lacks its actual same-event birth history")
            self.column=self._column_v1(table="graph_history",column="value",key_columns=("token","revision"),
                key=(self.birth.key.token,self.birth.revision),mode="runtime_job")
            self.phase="birth";return
        if self.phase=="birth":
            if not self.column.advance(meter):return
            from .d11_types import RuntimeJobValue
            value=_detach_value_v3(self.column.frozen)
            if self.column.fields_seen!={f.name for f in fields(RuntimeJobValue)}:
                raise ValueError("prepared job birth has another closed metadata schema")
            born=decode_typed_production_value_v1(value,RuntimeJobValue)
            if((born.bot_id,born.persona_id,born.operation_id,born.activity_id,born.job_id,born.phase,born.work_kind,
                    born.parent_budget_lease_ref,born.fence,born.cancel_epoch)!=
                    (*ns.as_tuple,p["operation_id"],p["activity_id"],p["job_id"],"queued","d07.concern",
                    p["original_parent_budget_lease_ref"],0,0)):
                raise ValueError("prepared job birth differs from its actual signed Case/phase parent")
            self.birth_value=born;self.column=None;self.phase="current_job";return
        if self.phase=="current_job":
            row=_runtime_bounded_fixed_row_v3(o.db,meter,"runtime_jobs",
                ("operation_id","activity_id","bot_id","persona_id","work_kind","budget_ref","deadline_utc","phase"),
                "job_id=?",(p["job_id"],))
            if(row is None or row[:7]!=(p["operation_id"],p["activity_id"],*ns.as_tuple,"d07.concern",
                    p["original_parent_budget_lease_ref"],self.birth_value.deadline_utc)
                    or row[7]not in {"queued","running","completed","failed","waiting","deferred","pending_confirmation","cancelled"}):
                raise ValueError("prepared metadata locator lost its actual current job identity")
            fact=_ActualAttentionPreparedJobMetadataV1(family,schema,phase,p["operation_id"],p["activity_id"],
                p["job_id"],p["call_id"],ProductionOriginalRefV1("d07.prepared",ref,digest),
                ProductionOriginalRefV1("d07.prepare_commit",ref,self.commit_header[0]),
                ProductionOriginalRefV1("d07.semantic_question",p["semantic_question_ref"],p["semantic_question_digest"]),
                subject,self.birth,self.receipt,row[7],p["original_parent_budget_lease_ref"],p["original_parent_grant_digest"],
                p["original_deadline_utc"])
            self.result=fact;self.complete=True
            _ATTENTION_PREPARED_FACTS_V1[fact]=(o,self,o.operation,o.graph_stamp,o.entry_column)
            return
        raise ValueError("unregistered actual attention prepared metadata phase")
    def release_v1(self):
        self.owner.operation.unregister_retained_state_v3(self)
        if self.result is not None:_ATTENTION_PREPARED_FACTS_V1.pop(self.result,None)
        self.column=self.result=self.selected=None;self.columns.clear()

def create_current_d07_attention_prepared_metadata_census_v1(owner,identity):
    if tuple(identity)!=_attention_prepared_census_identity_v1(owner):
        raise ValueError("prepared census task has another actual attention selector")
    task=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
    if task is None:
        task=_D07AttentionPreparedMetadataCensusV1(owner,tuple(identity));_ATTENTION_PREPARED_CENSUS_V1[owner]=task
    return task.require_current_v1()

def read_current_d07_attention_prepared_job_metadata_v1(db,*,namespace,issuer):
    from .domain_background_read_v3 import _active_v3,BackgroundReadNeededV3
    owner=_active_v3(db)
    _actual_attention_prepared_profile_v1(owner)
    if namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer:
        raise ValueError("prepared job locator crossed the actual namespace or installed issuer")
    task=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
    if task is None or not task.complete:
        raise BackgroundReadNeededV3(("d07_attention_prepared_metadata_census_v1",_attention_prepared_census_identity_v1(owner)))
    task.require_current_v1()
    return None if task.result is None else task.result.require_current_v1(owner)

def release_current_d07_attention_prepared_metadata_v1(owner):
    task=_ATTENTION_PREPARED_CENSUS_V1.pop(owner,None)
    if task is not None:task.release_v1()


# Pre-Source selector for an Owner-issued D01 review, independently of background service.
_REVIEW_INTERPRETATION_CASE_TASKS_V1=WeakKeyDictionary()
_REVIEW_ADOPTED_CONTROL_FIELDS_V1=frozenset({
    "schema","interpretation_ref","interpretation_revision","interpretation_value_digest",
    "adoption_operation_id","graph_receipt_digest","prepared_digest","actual_result_digest",
    "question_scope","supporting_refs","meaningful_unknowns"})

def _require_review_interpretation_case_method_v1(reader,interpretation_ref):
    from .current_method_learning_read_v3 import (
        _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3,
        _require_current_general_method_source_write_phase_v1)
    from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1
    if(type(reader)is not _MethodLearningReadV3 or reader.operation_kind!="review_single_event_growth_v1"
            or type(reader.request)is not ReviewSingleEventGrowthRequestV1
            or reader.request.continuity_interpretation_ref!=interpretation_ref):
        raise ValueError("Case selector requires the exact actual Owner Review command")
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    if reader.read_finished:
        _require_current_general_method_source_write_phase_v1(reader)
    else:
        if reader.general_owner_entry is None:
            raise ValueError("Case selector has no completed actual Method metadata Owner")
        reader.general_owner_entry.require_for_v3(reader)
    key=AtomKey.from_token(interpretation_ref)
    if NamespaceId.from_key(key)!=reader.namespace or key.type_name!="d07.current_interpretation.v1":
        raise ValueError("Case selector interpretation belongs to another namespace or Graph type")
    return reader

class _SingleEventReviewInterpretationCaseMetadataV1:
    def __init__(self,reader,identity):
        if type(identity)is not tuple or len(identity)!=1:
            raise ValueError("Case selector needs its single actual interpretation identity")
        _review_interpretation_metadata_owner_v1(reader,identity[0])
        if _review_interpretation_read_finished_v1(reader):
            raise ValueError("new Case metadata may only be read in the original READ phase")
        self.reader,self.identity=reader,identity
        self.binding=_review_interpretation_metadata_binding_v1(reader)
        self.phase="head";self.complete=False;self.result=None
        self.leaf=None;self.adopted=None;self.prepared=None;self.head=None
        self.prepared_after="";self.prepared_refs=()
        self.receipt_points={};self.receipt_header=None;self.receipt_event_columns=()
        self.receipt_event_epoch=None;self.metadata_digest=None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.identity,self.binding,self.leaf,self.adopted,self.prepared,self.head,
            self.prepared_refs,self.receipt_points,self.receipt_header,self.receipt_event_columns))
    def require_current_v1(self):
        r=_review_interpretation_metadata_owner_v1(self.reader,self.identity[0])
        if(_REVIEW_INTERPRETATION_CASE_TASKS_V1.get(r)is not self
                or self.binding!=_review_interpretation_metadata_binding_v1(r)):
            raise ValueError("Case selector left its actual Work, Owner or selection")
        if self.complete and self.metadata_digest!=canonical_digest((
                self.adopted,self.prepared,self.head,tuple(sorted(self.receipt_points.items())),self.result)):
            raise ValueError("Case selector changed its complete sealed receipt metadata commitments")
        return r
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.require_current_v1()
        if self.complete:return True
        if _review_interpretation_read_finished_v1(r):
            raise ValueError("Case selector cannot read new metadata in business WRITE")
        if self.phase.startswith("receipt_"):return _advance_single_event_review_receipt_controls_v1(self,meter)
        ns=r.namespace
        if self.phase=="head":
            self.head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",
                ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",
                (self.identity[0],*ns.as_tuple))
            if self.head is None or self.head[1]!=1:
                raise MissingProductionOriginalV1("current_single_event_review_interpretation_metadata")
            self.leaf=_ReviewSignedMetadataV1(self,"adopted",self.identity[0])
            self.phase="adopted";return False
        if self.phase=="prepared_locator":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",
                ("original_ref",),"bot=? AND persona=? AND kind='prepared' AND payload_digest=? "
                "AND original_ref>? ORDER BY original_ref LIMIT 1",
                (*ns.as_tuple,self.adopted["prepared_digest"],self.prepared_after))
            if row is not None:
                if self.prepared_refs:raise ValueError("adopted interpretation has ambiguous signed Prepared identity")
                self.prepared_refs=(row[0],);self.prepared_after=row[0];return False
            if not self.prepared_refs:
                raise MissingProductionOriginalV1("actual_single_event_review_interpretation_prepared_metadata")
            self.leaf=_ReviewSignedMetadataV1(self,"prepared",self.prepared_refs[0])
            self.phase="prepared";return False
        if not self.leaf.advance(meter):return False
        v=self.leaf.value
        if self.phase=="adopted":
            if(v["schema"]!="d07.actual-cognition-adoption.v1"or v["interpretation_ref"]!=self.identity[0]
                    or v["interpretation_revision"]!=self.head[0]):
                raise ValueError("signed adopted controls differ from the actual current interpretation head")
            self.adopted=v;self.leaf=None;self.phase="prepared_locator";return False
        if self.phase=="prepared":
            if(v["schema"]!="d07.single-event-review-prepared.v1"
                    or self.leaf.header[0]!=self.adopted["prepared_digest"]
                    or v["namespace"]!=plain_v1(ns)or v["job_id"]!=self.prepared_refs[0]):
                raise ValueError("interpretation did not originate from its exact dedicated Case Prepared")
            original=_decode_original_v1(v["review_case_original"])
            ids=single_event_review_attention_ids_v1(ns,original)
            if(v["semantic_question_ref"]!=ids["question"]):
                raise ValueError("Case Prepared changed its registered immutable Question identity")
            self.prepared=v;self.result=original
            self.leaf=_ReviewSignedMetadataV1(self,"semantic_question",v["semantic_question_ref"])
            self.phase="question";return False
        if(v["schema"]!="d07.registered-semantic-question.v1"
                or self.leaf.header[0]!=self.prepared["semantic_question_digest"]
                or v["question_key"]!=self.adopted["question_scope"]
                or v["target_ref"]!={"ref":self.result.original_ref,"version":1}
                or not set(self.adopted["supporting_refs"])<=set(v["source_refs"])):
            raise ValueError("Case locator lost its signed Question, adopted scope or Source binding")
        self.leaf=None;self.phase="receipt_business_header";return False

def create_single_event_review_interpretation_case_metadata_task_v1(reader,identity):
    task=_REVIEW_INTERPRETATION_CASE_TASKS_V1.get(reader)
    if task is None:
        task=_SingleEventReviewInterpretationCaseMetadataV1(reader,identity)
        _REVIEW_INTERPRETATION_CASE_TASKS_V1[reader]=task
    if task.identity!=identity:raise ValueError("Review command changed its actual interpretation selector")
    task.require_current_v1()
    return task

def read_actual_single_event_review_interpretation_case_original_v1(db,*,read,interpretation_ref):
    from .current_method_learning_read_v3 import _method_active,_MethodLearningReadV3,MethodInputNeededV3
    from .d01_production_operations_v1 import CurrentDomainReadV1
    if type(read)is _MethodLearningReadV3:
        reader=read
        if _method_active(db)is not reader:raise ValueError("Case selector has another actual Method binder")
    elif type(read)is CurrentDomainReadV1:
        read.check(db);reader=_method_active(db)
        if reader is None or read.frame.envelope.identity.operation_id!=reader.operation.operation_id:
            raise ValueError("Case selector frame differs from the actual current Owner Review")
    else:raise TypeError("Case selector needs the actual Method READ or its current D01 frame")
    if reader.db is not db:raise ValueError("Case selector crossed its actual storage connection")
    _require_review_interpretation_case_method_v1(reader,interpretation_ref)
    task=_REVIEW_INTERPRETATION_CASE_TASKS_V1.get(reader)
    if task is None or not task.complete:
        raise MethodInputNeededV3(("single_event_review_interpretation_case_metadata",(interpretation_ref,)))
    task.require_current_v1()
    return task.result

def release_single_event_review_interpretation_case_metadata_v1(reader):
    release_single_event_review_interpretation_dependencies_v1(reader)
    task=_REVIEW_INTERPRETATION_CASE_TASKS_V1.pop(reader,None)
    if task is not None:
        task.leaf=task.adopted=task.prepared=task.result=None
        task.prepared_refs=();task.receipt_points.clear();task.receipt_event_columns=()
        task.metadata_digest=None;task.complete=False


def _require_single_event_review_adoption_receipts_v1(db,*,owner,case_fact,prepared,interpretation,adopted):
    from .d01_single_event_review_case_v1 import require_single_event_review_case_fact_owner_v1
    from .d07_execution_v1 import verify_d07_adoption_receipt_metadata_v1
    if(require_single_event_review_case_fact_owner_v1(case_fact,db)is not owner
            or prepared.review_case_original!=case_fact.original
            or adopted["adoption_operation_id"]!=prepared.operation_id):
        raise ValueError("review receipt selector has another actual Case or adopted operation")
    task=prepare_current_single_event_review_interpretation_metadata_v1(db,reader=owner,
        interpretation_ref=interpretation.key.token)
    if(task.result!=case_fact.original or task.adopted!={name:adopted[name]for name in task.adopted}
            or task.prepared["job_id"]!=prepared.job_id
            or task.adopted["prepared_digest"]!=prepared.digest):
        raise ValueError("review receipts differ from their presealed actual Case/Prepared commitments")
    def point(table,columns,key_columns,key):
        request=(table,columns,key_columns,key)
        if request not in task.receipt_points:
            raise ValueError("review receipt has no exact complete presealed metadata point")
        return task.receipt_points[request]
    return verify_d07_adoption_receipt_metadata_v1(db,prepared=prepared,interpretation=interpretation,
        adopted=adopted,point=point)


def _review_interpretation_metadata_owner_v1(reader,interpretation_ref):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    if type(reader)is _MethodLearningReadV3:
        return _require_review_interpretation_case_method_v1(reader,interpretation_ref)
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(reader)is not BackgroundReadWorkV3:
        raise TypeError("review dependency metadata requires its exact Method or completion Background Work")
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    state=_REVIEW_COMPLETION_CAUSES.get(reader)
    if(state is None or state[2:]!=(reader.operation,reader.graph_stamp)
            or state[1].value.interpretation_version.key.token!=interpretation_ref
            or reader.entry[1:3]!=("d01",_SINGLE_EVENT_REVIEW_ADOPTION_EVENT_V1)):
        raise ValueError("review dependency metadata has no actual unique native completion cause")
    state[1].require_current_v1(reader)
    return reader

def _review_interpretation_metadata_binding_v1(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    if type(reader)is _MethodLearningReadV3:
        return(reader.work,reader.operation,reader.graph_stamp,reader.authority_epochs,
            reader.fence.scope,reader.request,reader.operation.selection_digest)
    return(reader.work,reader.operation,reader.graph_stamp,reader.read_scope,reader.entry_column)

def _review_interpretation_read_finished_v1(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    return reader.read_finished if type(reader)is _MethodLearningReadV3 else reader.sealed

class _ReviewReceiptControlColumnV1:
    def __init__(self,task,table,column,key_columns,key):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.task=task;self.table,self.column,self.key_columns,self.key=table,column,key_columns,key
        self.parser=C09CanonicalJSONStreamV2();self.builder=_CanonicalJSONValueBuilderV3()
        self.builder.operation=task.reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.total=None;self.offset=0;self.fragment=b"";self.fragment_offset=0
        self.complete=False;self.encoded=None
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        r=self.task.require_current_v1()
        if self.complete:return True
        where=" AND ".join(name+"=?"for name in self.key_columns)
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.fragment_offset:end],self.builder._emit)
            self.fragment_offset=end;return False
        with legacy_cell_read_transaction_v2(r.db):
            if self.total is None:
                row=r.db.execute("SELECT length(CAST("+self.column+" AS BLOB)) FROM "+self.table+" WHERE "+where,self.key).fetchone()
                meter.charge_read(16)
                if row is None:raise MissingProductionOriginalV1("actual_single_event_review_receipt_control_column")
                self.total=row[0];return False
            if self.offset<self.total:
                part,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.table,column=self.column,
                    where=where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                if(total,kind)!=(self.total,"text"):raise ValueError("review receipt metadata changed before full EOF")
                self.offset+=len(part);self.fragment=part;self.fragment_offset=0;return False
        parsed=self.parser.finish()
        self.encoded=canonical_serialize(_detach_value_v3(self.builder.value))
        if(self.builder.nodes or parsed.byte_count!=self.total
                or parsed.sha256!=__import__("hashlib").sha256(self.encoded.encode("utf-8")).hexdigest()):
            raise ValueError("review receipt control column has no complete canonical metadata EOF")
        self.complete=True;self.fragment=b"";self.parser=self.builder=None;return True

def _advance_single_event_review_receipt_controls_v1(task,meter):
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from .domain_production_originals_v1 import TABLE
    r=task.require_current_v1();ns=r.namespace;p=task.prepared
    op=p["operation_id"];activity=p["activity_id"];keys=("bot","persona","operation_id");key=(*ns.as_tuple,op)
    if task.phase=="receipt_business_header":
        task.receipt_header=_runtime_bounded_fixed_row_v3(r.db,meter,TABLE,
            ("domain","operation_kind","original_digest","bundle_digest","receipt_digest"),
            "bot=? AND persona=? AND operation_id=?",key)
        if task.receipt_header is None:raise MissingProductionOriginalV1("review_adoption_business_receipt_metadata")
        task.leaf=_ReviewReceiptControlColumnV1(task,TABLE,"receipt_json",keys,key)
        task.phase="receipt_business_json";return False
    if task.phase=="receipt_business_json":
        if not task.leaf.advance(meter):return False
        request=(TABLE,("domain","operation_kind","original_digest","bundle_digest","receipt_json","receipt_digest"),keys,key)
        task.receipt_points[request]=(*task.receipt_header[:4],task.leaf.encoded,task.receipt_header[4])
        task.leaf=None;task.phase="receipt_bundle_header";return False
    if task.phase=="receipt_bundle_header":
        task.receipt_header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
            ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",key)
        if task.receipt_header is None:raise MissingProductionOriginalV1("review_adoption_bundle_receipt_metadata")
        task.leaf=_ReviewReceiptControlColumnV1(task,"graph_bundle_operations","receipt_json",keys,key)
        task.phase="receipt_bundle_json";return False
    if task.phase=="receipt_bundle_json":
        if not task.leaf.advance(meter):return False
        task.receipt_points[("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),keys,key)]=(
            *task.receipt_header,task.leaf.encoded)
        task.leaf=None;task.phase="receipt_event_epoch";return False
    eventkeys=("bot","persona","session","event_id");eventkey=(*ns.as_tuple,activity,op)
    if task.phase=="receipt_event_epoch":
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_events",("epoch_revision",),
            "bot=? AND persona=? AND session=? AND event_id=?",eventkey)
        if row is None:raise MissingProductionOriginalV1("review_adoption_event_receipt_metadata")
        task.receipt_event_epoch=row[0];task.receipt_event_columns=();task.phase="receipt_event_reads";return False
    if task.phase in {"receipt_event_reads","receipt_event_revisions","receipt_event_invalidated"}:
        name=task.phase.removeprefix("receipt_event_")
        if task.leaf is None:
            task.leaf=_ReviewReceiptControlColumnV1(task,"graph_events",name,eventkeys,eventkey);return False
        if not task.leaf.advance(meter):return False
        task.receipt_event_columns+= (task.leaf.encoded,);task.leaf=None
        task.phase={"reads":"receipt_event_revisions","revisions":"receipt_event_invalidated","invalidated":"receipt_history"}[name]
        return False
    if task.phase!="receipt_history":raise ValueError("unregistered review receipt metadata phase")
    task.receipt_points[("graph_events",("reads","revisions","invalidated","epoch_revision"),eventkeys,eventkey)]=(
        *task.receipt_event_columns,task.receipt_event_epoch)
    historykey=(task.identity[0],task.adopted["interpretation_revision"])
    history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",
        ("event_bot","event_persona","event_session","event_id","valid"),"token=? AND revision=?",historykey)
    task.receipt_points[("graph_history",("event_bot","event_persona","event_session","event_id","valid"),
        ("token","revision"),historykey)]=history
    task.complete=True;task.leaf=None
    task.metadata_digest=canonical_digest((task.adopted,task.prepared,task.head,tuple(sorted(task.receipt_points.items())),task.result))
    return True

def prepare_current_single_event_review_interpretation_metadata_v1(db,*,reader,interpretation_ref):
    _review_interpretation_metadata_owner_v1(reader,interpretation_ref)
    if reader.db is not db:raise ValueError("review dependency metadata crossed its actual storage")
    task=_REVIEW_INTERPRETATION_CASE_TASKS_V1.get(reader)
    if task is None or not task.complete:
        if _review_interpretation_read_finished_v1(reader):
            raise MissingProductionOriginalV1("single_event_review_presealed_interpretation_dependencies")
        request=("single_event_review_interpretation_case_metadata",(interpretation_ref,))
        from .current_method_learning_read_v3 import _MethodLearningReadV3,MethodInputNeededV3
        if type(reader)is _MethodLearningReadV3:raise MethodInputNeededV3(request)
        from .domain_background_read_v3 import BackgroundReadNeededV3
        raise BackgroundReadNeededV3(request)
    task.require_current_v1()
    return task


_REVIEW_INTERPRETATION_DEPENDENCIES_V1=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class _ReviewCompletedJobControlV1:
    bot_id:str
    persona_id:str
    job_id:str
    operation_id:str
    activity_id:str
    effect_id:str|None
    phase:str
    result_ref:str|None
    deadline_utc:str
    fence:int
    cancel_epoch:int

class _SingleEventReviewInterpretationDependenciesV1:
    def __init__(self,reader,case_original):
        metadata=prepare_current_single_event_review_interpretation_metadata_v1(reader.db,reader=reader,
            interpretation_ref=_review_dependency_interpretation_ref_v1(reader))
        from .d01_single_event_review_case_v1 import require_prepared_single_event_review_case_body_v1
        case=require_prepared_single_event_review_case_body_v1(reader,case_original)
        if metadata.result!=case_original:
            raise ValueError("review dependency Body differs from the actual signed interpretation Case")
        self.reader,self.case_original,self.case=reader,case_original,case
        self.metadata=metadata;self.binding=_review_interpretation_metadata_binding_v1(reader)
        self.phase="prepared_header";self.leaf=None;self.header=None;self.index=0
        self.rows={};self.prepared=None;self.job=None;self.complete=False;self.seal=None
        self.members=(("prepared",metadata.prepared["job_id"]),)
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.rows,self.leaf,self.prepared,self.case,self.members,self.job))
    def require_current_v1(self):
        from .d01_single_event_review_case_v1 import require_prepared_single_event_review_case_body_v1
        r=self.metadata.require_current_v1()
        if(_REVIEW_INTERPRETATION_DEPENDENCIES_V1.get(r)is not self
                or self.binding!=_review_interpretation_metadata_binding_v1(r)
                or require_prepared_single_event_review_case_body_v1(r,self.case_original)!=self.case):
            raise ValueError("review artifacts left their actual Case Body, Source Work or metadata selection")
        if self.complete and self.seal!=canonical_digest((tuple(sorted(self.rows.items())),self.job,self.case_original)):
            raise ValueError("review artifacts changed their complete canonical EOF commitments")
        return r
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d07_execution_v1 import TABLE,SIGN_KIND,read_prepared_d07_execution_v1
        from .domain_background_read_v3 import background_json_loads_v3
        r=self.require_current_v1()
        if self.complete:return True
        if _review_interpretation_read_finished_v1(r):
            raise ValueError("review immutable artifacts cannot be newly fetched in business WRITE")
        if self.phase=="job":
            p=self.prepared
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",
                ("bot_id","persona_id","job_id","operation_id","activity_id","effect_id","phase","result_ref",
                    "deadline_utc","fence","cancel_epoch"),"job_id=?",(p.job_id,))
            if row is None:raise MissingProductionOriginalV1("actual_review_completed_job_controls")
            self.job=_ReviewCompletedJobControlV1(*row)
            if(row[:8]!=(*p.namespace.as_tuple,p.job_id,p.operation_id,p.activity_id,p.effect_id,"completed","d07-terminal:"+p.call_id)):
                raise ValueError("review paid artifacts have another actual completed job")
            self.complete=True;self.seal=canonical_digest((tuple(sorted(self.rows.items())),self.job,self.case_original))
            return True
        kind,ref=self.members[self.index];key=(*r.namespace.as_tuple,kind,ref)
        if self.leaf is None:
            self.header=_runtime_bounded_fixed_row_v3(r.db,meter,TABLE,("payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",key)
            if self.header is None:raise MissingProductionOriginalV1("actual_single_event_review_"+kind)
            self.leaf=_ReviewReceiptControlColumnV1(self,TABLE,"payload_json",
                ("bot","persona","kind","original_ref"),key)
            return False
        if not self.leaf.advance(meter):return False
        raw=background_json_loads_v3(self.leaf.encoded);digest,signature=self.header
        if canonical_digest(raw)!=digest:
            raise ValueError("review immutable artifact failed its complete canonical payload digest")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,kind,ref,digest)),signature)
        self.rows[(kind,ref)]=(raw,digest);self.leaf=None;self.index+=1
        if kind=="prepared":
            # The native decoder reads only the exact just-authenticated private cache.
            self.prepared=read_prepared_d07_execution_v1(r.db,r.graph._GraphCoordinator__d11_issuer,r.namespace,ref)
            p=self.prepared;roots=tuple(dict.fromkeys((*self.case.support_source_refs,*self.case.context_source_refs)))
            if(type(p)is not D07SingleEventReviewPreparedV1 or p.review_case_original!=self.case_original
                    or p.digest!=self.metadata.adopted["prepared_digest"]
                    or p.context_source_refs!=roots or p.consolidation_source_refs!=roots):
                raise ValueError("review artifact Source scope differs from its actual qualified Case Body")
            self.members+=(
                ("semantic_question",p.semantic_question_ref),(ATTENTION_KIND,p.review_attention_ref),
                ("request",p.job_id),("call",p.job_id),("paid_cost",p.job_id),("body_cost",p.job_id),
                ("execution","d07-terminal:"+p.call_id),("adopted",self.metadata.identity[0]),
                ("result","d07-result:"+p.call_id))
        if self.index==len(self.members):self.phase="job"
        return False

def _review_dependency_interpretation_ref_v1(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    if type(reader)is _MethodLearningReadV3:
        from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1
        if type(reader.request)is not ReviewSingleEventGrowthRequestV1 or reader.request.continuity_interpretation_ref is None:
            raise ValueError("review dependency preparation has no actual requested interpretation")
        return reader.request.continuity_interpretation_ref
    state=_REVIEW_COMPLETION_CAUSES.get(reader)
    if state is None:raise ValueError("review dependency preparation has no actual native completion")
    state[1].require_current_v1(reader)
    return state[1].value.interpretation_version.key.token

def create_single_event_review_interpretation_dependencies_task_v1(reader,identity):
    if type(identity)is not tuple or len(identity)!=1 or type(identity[0])is not ProductionOriginalRefV1:
        raise ValueError("review artifact dependency needs its actual immutable Case locator")
    task=_REVIEW_INTERPRETATION_DEPENDENCIES_V1.get(reader)
    if task is None:
        task=_SingleEventReviewInterpretationDependenciesV1(reader,identity[0])
        _REVIEW_INTERPRETATION_DEPENDENCIES_V1[reader]=task
    if task.case_original!=identity[0]:raise ValueError("review artifact dependency changed its actual Case")
    task.require_current_v1()
    return task

def prepare_single_event_review_interpretation_dependencies_v1(reader,case_original):
    from .d01_single_event_review_case_v1 import require_prepared_single_event_review_case_body_v1
    interpretation_ref=_review_dependency_interpretation_ref_v1(reader)
    _review_interpretation_metadata_owner_v1(reader,interpretation_ref)
    require_prepared_single_event_review_case_body_v1(reader,case_original)
    metadata=prepare_current_single_event_review_interpretation_metadata_v1(reader.db,reader=reader,
        interpretation_ref=interpretation_ref)
    if metadata.result!=case_original:raise ValueError("review paid dependencies selected another actual Case")
    task=_REVIEW_INTERPRETATION_DEPENDENCIES_V1.get(reader)
    if task is None or not task.complete:
        if _review_interpretation_read_finished_v1(reader):
            raise MissingProductionOriginalV1("single_event_review_presealed_paid_dependencies")
        request=("single_event_review_interpretation_dependencies",(case_original,))
        from .current_method_learning_read_v3 import _MethodLearningReadV3,MethodInputNeededV3
        if type(reader)is _MethodLearningReadV3:raise MethodInputNeededV3(request)
        from .domain_background_read_v3 import BackgroundReadNeededV3
        raise BackgroundReadNeededV3(request)
    task.require_current_v1()
    return task

def read_bound_single_event_review_interpretation_original_v1(db,issuer,namespace,kind,ref):
    from .current_method_learning_read_v3 import _method_active
    from .domain_background_read_v3 import _active_v3
    owner=_method_active(db)
    if owner is None:owner=_active_v3(db)
    task=None if owner is None else _REVIEW_INTERPRETATION_DEPENDENCIES_V1.get(owner)
    if task is None:return False,None
    task.require_current_v1()
    if(namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer):
        raise ValueError("review immutable artifact crossed its actual namespace/issuer")
    if(kind,ref)not in task.members:return False,None
    row=task.rows.get((kind,ref))
    if row is None:
        raise MissingProductionOriginalV1("single_event_review_complete_exact_paid_artifact")
    return True,row

def require_current_single_event_review_interpretation_job_v1(db,prepared):
    from .current_method_learning_read_v3 import _method_active
    from .domain_background_read_v3 import _active_v3
    owner=_method_active(db)
    if owner is None:owner=_active_v3(db)
    task=None if owner is None else _REVIEW_INTERPRETATION_DEPENDENCIES_V1.get(owner)
    if task is None or not task.complete or task.prepared!=prepared:
        raise MissingProductionOriginalV1("single_event_review_presealed_completed_job")
    task.require_current_v1()
    return task.job

def release_single_event_review_interpretation_dependencies_v1(reader):
    task=_REVIEW_INTERPRETATION_DEPENDENCIES_V1.pop(reader,None)
    if task is not None:
        task.rows.clear();task.leaf=task.prepared=task.case=task.job=None;task.members=();task.complete=False


_SINGLE_EVENT_HISTORICAL_KINDS_V1=frozenset({
    "adopted","prepared","semantic_question",ATTENTION_KIND,"request","call","paid_cost","body_cost",
    "execution","result",_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1})

def single_event_review_historical_metadata_retains_path_v1(kind,path):
    """Closed metadata paths, authenticated by the independent readout issuer."""
    if kind not in _SINGLE_EVENT_HISTORICAL_KINDS_V1:return False
    if not path:return True
    if kind=="prepared":
        names={f.name for f in fields(D07SingleEventReviewPreparedV1)}-{
            "frozen_json","read_rows","query_inventory_json","external_content_originals_json",
            "clock_mapping_json","owner_guard_json","owner_authority_json"}
    elif kind=="semantic_question":names={"schema","question_key","target_ref","source_refs"}
    elif kind=="request":
        names={"envelope","call_id","provider_id","model_id","required_capabilities","privacy_tier",
            "prompt_template_digest","timeout_seconds","max_output_tokens"}
    elif kind=="result":
        if path[0]=="observation":
            return len(path)==1 or path[1]in {
                "authority_id","namespace","subject","operation_id","call_id","request_digest","status"}
        if path[0]=="schema":return True
        classes={}
        from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1
        from ..authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
        from ..authority_service.d07_model_timing_v1 import D07ModelTimingOriginalV1
        classes={"request":D07CognitionResultReadRequestV1,"terminal_receipt":ModelTerminalReceiptV2,
            "timing":D07ModelTimingOriginalV1}
        return path[0]in classes and(len(path)==1 or path[1]in {f.name for f in fields(classes[path[0]])})
    elif kind=="execution":
        from .d07_current_behavior_v1 import D07ExecutionOriginalV1
        names={f.name for f in fields(D07ExecutionOriginalV1)}-{"resolved_slots","discriminating_refs","predictions"}
    elif kind=="adopted":names=_REVIEW_ADOPTED_CONTROL_FIELDS_V1-{"meaningful_unknowns"}
    elif kind=="call":
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        names={f.name for f in fields(ModelEgressIntentV1)}
    elif kind=="paid_cost":
        names={"schema","prepared_digest","result_ref","result_digest","cost_ref","cost_value",
            "budget_receipt","unknown_dimensions","paid","terminal_digest"}
    elif kind=="body_cost":
        names={"schema","prepared_digest","terminal_digest","result_digest","component_ref",
            "settlement_ref","writes_digest","fixed_cost","overrun","unpaid_cost"}
    elif kind==ATTENTION_KIND:names={f.name for f in fields(SingleEventReviewAttentionOriginalV1)}
    else:names={f.name for f in fields(D07SingleEventReviewAdoptionOriginalV1)}
    return path[0]in names

_HISTORICAL_REVIEW_BINDINGS_V1=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class VerifiedSingleEventHistoricalReviewBindingV1:
    interpretation_ref:str
    read_versions:tuple[GraphVersion,...]
    originals:tuple[ProductionOriginalRefV1,...]
    binding_digest:str
    def require_current_v1(self,proof):
        from .d01_single_event_readout_v4 import require_actual_single_event_readout_review_v4
        owner=require_actual_single_event_readout_review_v4(proof)
        state=_HISTORICAL_REVIEW_BINDINGS_V1.get(self)
        if(state is None or state!=(proof,owner,owner.operation,self.binding_digest)
                or proof.review.continuity_interpretation_ref!=self.interpretation_ref):
            raise ValueError("historical review binding left its independent actual readout proof")
        proof.require_current_v4()
        return self

def require_historical_single_event_review_interpretation_v1(proof):
    """Audit the signed historical C3 chain without reading model or Case Body."""
    from .d01_single_event_readout_v4 import require_actual_single_event_readout_review_v4
    from ..domains.d01.single_event_growth_v1 import SingleEventGrowthReviewV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1,ModelTerminalReceiptV2
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1
    from ..authority_service.d07_model_timing_v1 import D07ModelTimingOriginalV1
    from ..model_broker.d07_cognition_v1 import TEMPLATE_DIGEST
    from dataclasses import asdict
    owner=require_actual_single_event_readout_review_v4(proof)
    proof.require_current_v4()
    review=proof.review;case=proof.case_metadata;case_original=proof.case_original
    if(type(review)is not SingleEventGrowthReviewV2 or review.disposition!="qualified"
            or review.review_case_original!=case_original or review.continuity_interpretation_ref is None):
        raise ValueError("historical C3 review needs its exact current qualified Review V2 Case")
    originals=[]
    def take(kind,ref):
        value,original=proof.read_d07_metadata_v1(kind,ref)
        if(type(value)is not dict or type(original)is not ProductionOriginalRefV1
                or original.kind!="d07."+kind or original.original_ref!=ref):
            raise ValueError("historical C3 metadata has another actual signed kind or locator")
        originals.append(original)
        return value,original
    interpretation=review.continuity_interpretation_ref
    adopted,adopted_original=take("adopted",interpretation)
    version,value_digest,current=proof.read_interpretation_metadata_v1()
    if(version.key.token!=interpretation or version.key.type_name!="d07.current_interpretation.v1"
            or NamespaceId.from_key(version.key)!=review.namespace or version.revision!=adopted["interpretation_revision"]
            or value_digest!=adopted["interpretation_value_digest"]or current["current"]is not True
            or adopted["schema"]!="d07.actual-cognition-adoption.v1"or adopted["interpretation_ref"]!=interpretation):
        raise ValueError("historical review interpretation changed its actual current adopted metadata")
    job_ref=proof.locate_d07_prepared_v1(adopted["prepared_digest"])
    p,p_original=take("prepared",job_ref)
    if(p["schema"]!="d07.single-event-review-prepared.v1"or p_original.original_digest!=adopted["prepared_digest"]
            or p["namespace"]!=plain_v1(review.namespace)or p["job_id"]!=job_ref or p["work_kind"]!="concern"
            or _decode_original_v1(p["review_case_original"])!=case_original
            or _decode_original_v1(p["adoption_original"])!=_decode_original_v1(case["adoption_original"])
            or _decode_original_v1(p["policy_original"])!=_decode_original_v1(case["policy_original"])
            or p["adoption_version"]!=case["adoption_version"]
            or p["original_parent_budget_lease_ref"]!=case["original_parent_budget_lease_ref"]
            or p["original_parent_grant_digest"]!=case["original_parent_grant_digest"]
            or p["original_deadline_utc"]>case["original_deadline_utc"]
            or type(p["causal_depth"])is not int or not 0<=p["causal_depth"]<2
            or p["depth_basis"]!="actual_registered_post_adoption_experience_v1"):
        raise ValueError("historical C3 Prepared lost its exact signed Case, causal depth or original resources")
    roots=tuple(dict.fromkeys((*case["support_source_refs"],*case["context_source_refs"])))
    if(tuple(p["context_source_refs"])!=roots or tuple(p["consolidation_source_refs"])!=roots
            or set(proof.source_refs)!=set(roots)):
        raise ValueError("historical C3 Source bindings differ from the independently qualified Case")
    q,q_original=take("semantic_question",p["semantic_question_ref"])
    expected=D07SemanticQuestionV1(q["question_key"],_FIXED_QUESTION,VersionedRef(**q["target_ref"]),tuple(q["source_refs"]))
    if(q["schema"]!="d07.registered-semantic-question.v1"
            or canonical_digest(plain_v1(expected))!=q_original.original_digest
            or q_original.original_digest!=p["semantic_question_digest"]
            or expected.target_ref!=VersionedRef(case_original.original_ref,1)or expected.source_refs!=roots
            or q["question_key"]!=adopted["question_scope"]or current["question_key"]!=q["question_key"]):
        raise ValueError("historical review lost its exact fixed one-finding Question contract")
    a,a_original=take(ATTENTION_KIND,p["review_attention_ref"])
    attention=decode_typed_production_value_v1(a,SingleEventReviewAttentionOriginalV1)
    if(a_original.original_digest!=p["review_attention_digest"]or attention.case_original!=case_original
            or attention.semantic_question_ref!=q_original.original_ref
            or attention.semantic_question_digest!=q_original.original_digest or attention.question_key!=q["question_key"]
            or attention.causal_depth!=p["causal_depth"]):
        raise ValueError("historical review did not originate from its real registered attention")
    call_raw,call_original=take("call",job_ref)
    call=model_from_wire(call_raw,ModelEgressIntentV1)
    request,request_original=take("request",job_ref)
    if((call.job_id,call.call_id,call.binding_digest,call.budget_reservation_operation_id,call.budget_reservation_digest)!=
                (job_ref,p["call_id"],p_original.original_digest,p["operation_id"],p["reservation_digest"])
            or request["call_id"]!=call.call_id or request["envelope"]["identity"]["operation_id"]!=call.acquire_operation_id
            or request["envelope"]["authority"]["purpose"]!="proposal"
            or (request["provider_id"],request["model_id"],request["max_output_tokens"])!=
                (call.provider_id,call.model_id,call.max_output_tokens)
            or request["prompt_template_digest"]!=TEMPLATE_DIGEST):
        raise ValueError("historical review lost its signed generic model-purpose request/call installation pins")
    paid,paid_original=take("paid_cost",job_ref)
    body,body_original=take("body_cost",job_ref)
    result,result_original=take("result","d07-result:"+p["call_id"])
    if(paid["schema"]!="d07.paid-model-result.v1"or body["schema"]!="d07.fixed-body-cost.v1"
            or paid["paid"]is not True or paid["unknown_dimensions"]or body["unpaid_cost"]
            or paid["prepared_digest"]!=p_original.original_digest or body["prepared_digest"]!=p_original.original_digest
            or paid["result_ref"]!=result_original.original_ref or result_original.original_digest!=adopted["actual_result_digest"]
            or (body["result_digest"],body["terminal_digest"])!=(paid["result_digest"],paid["terminal_digest"])):
        raise ValueError("historical review has no exact paid model and Body accounting chain")
    result_request=decode_typed_production_value_v1(result["request"],D07CognitionResultReadRequestV1)
    terminal=model_from_wire(result["terminal_receipt"],ModelTerminalReceiptV2)
    timing=decode_typed_production_value_v1(result["timing"],D07ModelTimingOriginalV1)
    observation=result["observation"]
    if(result["schema"]!=result_request.schema or (result_request.namespace,result_request.job_id,result_request.call_id,result_request.original_operation_id,
                result_request.binding_digest,result_request.model_request_digest)!=
                (review.namespace,job_ref,p["call_id"],p["operation_id"],p_original.original_digest,call.request_digest)
            or result_request.acquire_operation_id!=call.acquire_operation_id
            or (observation["status"],observation["call_id"],observation["request_digest"])!=
                ("completed",call.call_id,call.request_digest)
            or (terminal.call_id,terminal.request_digest,terminal.observation_digest,terminal.installation_id)!=
                (call.call_id,call.request_digest,paid["result_digest"],result_request.installation_id)
            or canonical_digest(asdict(terminal))!=paid["terminal_digest"]
            or (timing.call_id,timing.admission_id,timing.request_digest,timing.binding_digest,timing.terminal_digest)!=
                (call.call_id,terminal.admission_id,call.request_digest,p_original.original_digest,paid["terminal_digest"])
            or not p["review_not_before_utc"]<=timing.started_at<=timing.ended_at<
                min(p["original_deadline_utc"],p["review_due_utc"],p["readout_valid_until_utc"])
            or not timing.ended_at<=proof.reviewed_at_utc<
                min(p["original_deadline_utc"],p["review_due_utc"],p["readout_valid_until_utc"])):
        raise ValueError("historical review paid result/terminal timing exceeded its original signed execution window")
    execution,execution_original=take("execution","d07-terminal:"+p["call_id"])
    if((execution["terminal_ref"],execution["operation_id"],execution["execution_id"],execution["input_digest"],
                execution["causal_depth"],execution["status"])!=
                ("d07-terminal:"+p["call_id"],p["operation_id"],p["execution_id"],p["stage_input_digest"],p["causal_depth"],"completed")
            or tuple(execution["source_refs"])!=roots):
        raise ValueError("historical review has another actual terminal execution")
    native,native_original=take(_SINGLE_EVENT_REVIEW_ADOPTION_KIND_V1,
        single_event_review_adoption_original_ref_v1(review.namespace,job_ref))
    completion=decode_typed_production_value_v1(native,D07SingleEventReviewAdoptionOriginalV1)
    def same(left,right):
        return(left.kind,left.original_ref,left.original_digest)==(right.kind,right.original_ref,right.original_digest)
    pending_review=decode_typed_production_value_v1(case["review_version"],GraphVersion)
    receipt=proof.producer_receipt
    if(completion.namespace!=review.namespace or completion.case_original!=case_original
            or not same(completion.prepared_original,p_original)or not same(completion.question_original,q_original)
            or not same(completion.adopted_original,adopted_original)
            or completion.interpretation_version!=version or completion.interpretation_value_digest!=value_digest
            or completion.graph_receipt_digest!=adopted["graph_receipt_digest"]
            or completion.review_version!=pending_review or completion.call_id!=p["call_id"]
            or completion.operation_id!=p["operation_id"]or adopted["adoption_operation_id"]!=p["operation_id"]
            or receipt.status!="committed"or pending_review not in receipt.read_versions
            or version not in receipt.read_versions or proof.review_version not in receipt.write_versions
            or proof.review_version.key!=pending_review.key or proof.review_version.revision!=pending_review.revision+1):
        raise ValueError("historical review lacks its actual C3 adoption and first qualified Review V2 producer")
    digest=canonical_digest((proof.case_original,proof.review_version,version,
        tuple(originals),canonical_digest(receipt),p_original.original_digest,timing.started_at,timing.ended_at))
    fact=VerifiedSingleEventHistoricalReviewBindingV1(interpretation,(version,proof.review_version),tuple(originals),digest)
    _HISTORICAL_REVIEW_BINDINGS_V1[fact]=(proof,owner,owner.operation,digest)
    return fact.require_current_v1(proof)


_REVIEW_CAUSE_CENSUS_V1=WeakKeyDictionary()
_REVIEW_CAUSE_HISTORIES_V1=WeakKeyDictionary()
_REVIEW_NOVELTIES_V1=WeakKeyDictionary()
_REVIEW_NOVELTY_FACTS_V1=WeakKeyDictionary()
_REVIEW_NOVELTY_STAGES_V1={}

def _review_cause_history_owner_v1(reader):
    from .current_method_learning_read_v3 import (_MethodLearningReadV3,
        require_actual_method_learning_attachment_owner_v3,_require_current_general_method_source_write_phase_v1)
    from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1,require_single_event_review_target_metadata_work_v1
    from .domain_background_read_v3 import (BackgroundReadWorkV3,require_background_followup_handoff_v3,
        require_actual_background_attachment_owner_v3)
    if type(reader)is _MethodLearningReadV3:
        require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
        if reader.operation_kind in {REGISTER_OPERATION,"serve_concern"}:
            _actual_review_method_v1(reader)
            request=reader.request
        elif(reader.operation_kind=="review_single_event_growth_v1"
                and type(reader.request)is ReviewSingleEventGrowthRequestV1
                and reader.request.continuity_interpretation_ref is None):
            request=reader.request
        else:raise ValueError("experience history needs its exact review registration, concern or D01 Case command")
        if reader.read_finished:_require_current_general_method_source_write_phase_v1(reader)
        elif reader.general_owner_entry is None:raise ValueError("experience history has no completed actual metadata Owner")
        else:reader.general_owner_entry.require_for_v3(reader)
        return (reader.work,reader.operation,reader.graph_stamp,reader.fence.scope,request,reader.operation.selection_digest)
    if type(reader)is not BackgroundReadWorkV3:raise TypeError("actual registered review metadata Work required")
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    require_single_event_review_target_metadata_work_v1(reader)
    command=require_background_followup_handoff_v3(reader.handoff,reader.graph,reader.bundle).command
    if(type(command.request)is not ReviewSingleEventGrowthRequestV1
            or command.request.continuity_interpretation_ref is not None):
        raise ValueError("experience history has another actual Background review command")
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(reader.db)as meter:reader.require_data_current_v3(meter)
    if reader.sealed:
        from .d01_single_event_growth_v1 import require_current_single_event_background_source_v1
        require_current_single_event_background_source_v1(reader)
    return(reader.work,reader.operation,reader.graph_stamp,reader.read_scope,command,reader.entry_column)

def _review_cause_history_identity_v1(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1
    from .domain_background_read_v3 import require_background_followup_handoff_v3
    _review_cause_history_owner_v1(reader)
    request=(reader.request if type(reader)is _MethodLearningReadV3 else
        require_background_followup_handoff_v3(reader.handoff,reader.graph,reader.bundle).command.request)
    if type(request)is ReviewSingleEventGrowthRequestV1:return("d01_review",request.adoption_ref)
    if type(request)is RegisterSingleEventReviewAttentionRequestV1:
        o=request.case_original;return("register",o.kind,o.original_ref,o.original_digest)
    return("concern",request.trigger_original_ref)

class _SingleEventReviewCauseCensusV1:
    def __init__(self,reader,identity):
        if identity!=_review_cause_history_identity_v1(reader)or _review_interpretation_read_finished_v1(reader):
            raise ValueError("experience census must begin in its original selected review READ")
        self.reader,self.identity=reader,identity;self.binding=_review_cause_history_owner_v1(reader)
        self.after="";self.count=0;self.leaf=None;self.complete=False
        self.prior_case_originals=();self.prepared_fingerprints=()
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.after,self.leaf,self.prior_case_originals,self.prepared_fingerprints))
    def require_current_v1(self):
        if(_REVIEW_CAUSE_CENSUS_V1.get(self.reader)is not self
                or _review_cause_history_owner_v1(self.reader)!=self.binding):
            raise ValueError("experience census left its actual metadata Work, Owner or graph stamp")
        return self.reader
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.require_current_v1()
        if self.complete:return True
        if _review_interpretation_read_finished_v1(r):
            raise ValueError("experience census cannot read new columns in business WRITE")
        if self.leaf is None:
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",("original_ref",),
                "bot=? AND persona=? AND kind='prepared' AND original_ref>? ORDER BY original_ref",
                (*r.namespace.as_tuple,self.after))
            if row is None:self.complete=True;return True
            if self.count>=128:raise MissingProductionOriginalV1("bounded_complete_review_cause_prepared_census")
            self.leaf=_ReviewSignedMetadataV1(self,"prepared",row[0]);return False
        if not self.leaf.advance(meter):return False
        v=self.leaf.value;ref=self.leaf.ref
        self.prepared_fingerprints+=((ref,*self.leaf.header),)
        if v["schema"]=="d07.single-event-review-prepared.v1":
            if v["namespace"]!=plain_v1(r.namespace)or v["job_id"]!=ref:
                raise ValueError("experience census Prepared changed its actual namespace/job")
            original=_decode_original_v1(v["review_case_original"])
            if original not in self.prior_case_originals:self.prior_case_originals+=(original,)
        self.after=ref;self.count+=1;self.leaf=None;return False

def create_current_single_event_review_cause_census_task_v1(reader,identity):
    task=_REVIEW_CAUSE_CENSUS_V1.get(reader)
    if task is None:
        task=_SingleEventReviewCauseCensusV1(reader,identity);_REVIEW_CAUSE_CENSUS_V1[reader]=task
    if task.identity!=identity:raise ValueError("experience history changed its actual request selector")
    task.require_current_v1()
    return task

def _review_case_obligation_v1(value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    adoption=decode_typed_production_value_v1(value["adoption_version"],GraphVersion)
    review=decode_typed_production_value_v1(value["review_version"],GraphVersion)
    return(adoption,review.key)

def _review_original_identity_v1(value):
    return(value.kind,value.original_ref,value.original_digest)

def single_event_review_experience_identities_v1(namespace,scope_bindings,evidence_versions,evidence_originals):
    """Pure commitments; caller-created commitments do not issue novelty permission."""
    if(len(evidence_versions)!=len(evidence_originals)
            or len(set(evidence_versions))!=len(evidence_versions)):
        raise ValueError("experience metadata lost its exact outcome/original alignment")
    originals=dict(zip(evidence_versions,evidence_originals));result=[]
    for binding in scope_bindings:
        version=binding.outcome_version
        original=originals.get(version)
        if(original is None or original.original_ref!=version.key.token
                or NamespaceId.from_key(version.key)!=namespace):
            raise ValueError("experience metadata changed its actual typed outcome original")
        identity=canonical_digest((namespace,version,_review_original_identity_v1(original),
            binding.planned_version,binding.scope_version,_review_original_identity_v1(binding.producer_original),
            tuple(sorted({_review_original_identity_v1(o)for o in binding.observer_originals}))))
        result.append((identity,binding))
    if len({identity for identity,_ in result})!=len(result):
        raise ValueError("experience metadata repeats the same actual outcome")
    return tuple(result)

def _review_metadata_experiences_v1(namespace,value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as decode
    from ..domains.d01.single_event_review_case_v1 import SingleEventPostAdoptionScopeBindingV1
    if value["namespace"]!=plain_v1(namespace):raise ValueError("experience Case metadata has another actual namespace")
    return single_event_review_experience_identities_v1(namespace,
        tuple(decode(v,SingleEventPostAdoptionScopeBindingV1)for v in value["post_adoption_scope_bindings"]),
        tuple(decode(v,GraphVersion)for v in value["post_adoption_evidence_versions"]),
        tuple(decode(v,ProductionOriginalRefV1)for v in value["post_adoption_evidence_originals"]))

@dataclass(frozen=True,eq=False)
class _ActualSingleEventReviewCauseHistoryV1:
    prior_cases:tuple
    prepared_fingerprints:tuple
    def require_for_v1(self,reader):
        state=_REVIEW_CAUSE_HISTORIES_V1.get(reader)
        if(state is None or state[0]is not self or state[1]!=_review_cause_history_owner_v1(reader)
                or state[2]!=canonical_digest((self.prior_cases,self.prepared_fingerprints))):
            raise ValueError("experience history left its complete actual READ commitments")
        return self
    def novel_bindings_v1(self,reader,*,adoption_version,review_key,scope_bindings,evidence_versions,evidence_originals):
        self.require_for_v1(reader)
        if NamespaceId.from_key(adoption_version.key)!=reader.namespace:
            raise ValueError("experience history selected another actual adoption namespace")
        old=set()
        from .domain_background_read_v3 import background_json_loads_v3
        for original,encoded in self.prior_cases:
            value=background_json_loads_v3(encoded)
            if _review_case_obligation_v1(value)==(adoption_version,review_key):
                old.update(identity for identity,_ in _review_metadata_experiences_v1(reader.namespace,value))
        return tuple(binding for identity,binding in single_event_review_experience_identities_v1(
            reader.namespace,scope_bindings,evidence_versions,evidence_originals)if identity not in old)

def prepare_current_single_event_review_cause_history_v1(reader):
    from .d01_single_event_review_case_v1 import read_registered_single_event_review_case_metadata_v1
    _review_cause_history_owner_v1(reader)
    prior=_REVIEW_CAUSE_HISTORIES_V1.get(reader)
    if prior is not None:return prior[0].require_for_v1(reader)
    if _review_interpretation_read_finished_v1(reader):
        raise MissingProductionOriginalV1("single_event_review_presealed_cause_history")
    from .current_method_learning_read_v3 import _MethodLearningReadV3,MethodInputNeededV3
    identity=_review_cause_history_identity_v1(reader)
    if identity[0]=="concern":
        census=prepare_single_event_review_concern_metadata_v1(reader)
        refs=census.prior_case_originals;fingerprints=census.prepared_fingerprints
    else:
        census=_REVIEW_CAUSE_CENSUS_V1.get(reader)
        if census is None or not census.complete:
            request=("single_event_review_cause_census",identity)
            if type(reader)is _MethodLearningReadV3:raise MethodInputNeededV3(request)
            from .domain_background_read_v3 import BackgroundReadNeededV3
            raise BackgroundReadNeededV3(request)
        census.require_current_v1();refs=census.prior_case_originals;fingerprints=census.prepared_fingerprints
    cases=[]
    for original in refs:
        value,actual=read_registered_single_event_review_case_metadata_v1(reader.db,namespace=reader.namespace,
            case_original=original,issuer=reader.graph._GraphCoordinator__d11_issuer)
        if _review_original_identity_v1(actual)!=_review_original_identity_v1(original):
            raise ValueError("experience history Case changed its actual signed Prepared locator")
        _review_metadata_experiences_v1(reader.namespace,value)
        cases.append((actual,canonical_serialize(value)))
    fact=_ActualSingleEventReviewCauseHistoryV1(tuple(cases),tuple(fingerprints))
    from .source_correction_read_v3 import _heap
    reader.operation.retain(_heap((fact.prior_cases,fact.prepared_fingerprints))+1024)
    _REVIEW_CAUSE_HISTORIES_V1[reader]=(fact,_review_cause_history_owner_v1(reader),
        canonical_digest((fact.prior_cases,fact.prepared_fingerprints)))
    return fact.require_for_v1(reader)

@dataclass(frozen=True,eq=False)
class _ActualSingleEventReviewNoveltyV1:
    case_original:ProductionOriginalRefV1
    novel_experience_ids:tuple[str,...]
    novel_bindings:tuple
    def require_for_v1(self,reader,*,case_original):
        state=_REVIEW_NOVELTY_FACTS_V1.get(self)
        if(state is None or state[:2]!=(reader,_review_cause_history_owner_v1(reader))
                or _review_original_identity_v1(case_original)!=_review_original_identity_v1(self.case_original)
                or state[2]!=canonical_digest((self.case_original,self.novel_experience_ids,self.novel_bindings))):
            raise ValueError("review novelty lost its actual Case/READ/Owner/namespace commitments")
        if reader.operation_kind=="serve_concern":prepare_single_event_review_concern_metadata_v1(reader).require_current_v1()
        return self
    @property
    def selected_binding(self):
        if not self.novel_bindings:
            raise MissingProductionOriginalV1("single_event_review_no_new_independent_experience")
        return self.novel_bindings[0]
    @property
    def selected_outcome_version(self):
        return self.selected_binding.outcome_version
    def require_new_case_v1(self,reader,case):
        self.require_for_v1(reader,case_original=self.case_original)
        if canonical_digest(plain_v1(case))!=self.case_original.original_digest:
            raise ValueError("review novelty selected another complete actual Case Body")
        selected=self.selected_binding
        experiences=single_event_review_experience_identities_v1(case.namespace,
            case.post_adoption_scope_bindings,case.post_adoption_evidence_versions,
            case.post_adoption_evidence_originals)
        exact=tuple(identity for identity,binding in experiences if binding==selected)
        if(len(exact)!=1 or not self.novel_experience_ids or exact[0]!=self.novel_experience_ids[0]
                or _review_original_identity_v1(selected.producer_original)!=_review_original_identity_v1(case.causal_original)):
            raise MissingProductionOriginalV1("single_event_review_case_cause_is_not_selected_new_experience")
        if(not selected.observer_originals or selected.occurred_at_utc<=case.adoption_recorded_at_utc):
            raise MissingProductionOriginalV1("actual_independent_post_adoption_experience_cause")
        return self
    def independent_depth_v1(self,reader,case):
        self.require_new_case_v1(reader,case)
        return 0,"actual_registered_post_adoption_experience_v1"
    def require_new_stage_v1(self,frame,stage,case):
        state=_REVIEW_NOVELTY_FACTS_V1.get(self)
        if state is None:raise ValueError("actual issued review novelty proof required")
        reader=state[0];self.require_new_case_v1(reader,case)
        if(frame.envelope.identity.operation_id!=reader.operation.operation_id
                or _REVIEW_NOVELTY_STAGES_V1.get(id(stage))!=(stage,self,reader.operation)):
            raise ValueError("review stage changed its originating private novelty/operation identity")
        return self

def prepare_current_single_event_review_novelty_v1(reader,case_original):
    from .d01_single_event_review_case_v1 import read_registered_single_event_review_case_metadata_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as decode
    prior=_REVIEW_NOVELTIES_V1.get(reader)
    if prior is not None:return prior.require_for_v1(reader,case_original=case_original)
    history=prepare_current_single_event_review_cause_history_v1(reader)
    value,actual=read_registered_single_event_review_case_metadata_v1(reader.db,namespace=reader.namespace,
        case_original=case_original,issuer=reader.graph._GraphCoordinator__d11_issuer)
    if _review_original_identity_v1(actual)!=_review_original_identity_v1(case_original):
        raise ValueError("novel experience selected another actual signed Case")
    adoption,review_key=_review_case_obligation_v1(value)
    current=_review_metadata_experiences_v1(reader.namespace,value)
    novel=history.novel_bindings_v1(reader,adoption_version=adoption,review_key=review_key,
        scope_bindings=tuple(binding for _,binding in current),
        evidence_versions=tuple(decode(v,GraphVersion)for v in value["post_adoption_evidence_versions"]),
        evidence_originals=tuple(decode(v,ProductionOriginalRefV1)for v in value["post_adoption_evidence_originals"]))
    novel_set=set(novel)
    fact=_ActualSingleEventReviewNoveltyV1(actual,tuple(identity for identity,b in current if b in novel_set),tuple(novel))
    from .source_correction_read_v3 import _heap
    reader.operation.retain(_heap((fact.case_original,fact.novel_experience_ids,fact.novel_bindings))+1024)
    _REVIEW_NOVELTIES_V1[reader]=fact
    _REVIEW_NOVELTY_FACTS_V1[fact]=(reader,_review_cause_history_owner_v1(reader),
        canonical_digest((fact.case_original,fact.novel_experience_ids,fact.novel_bindings)))
    return fact.require_for_v1(reader,case_original=case_original)

def require_current_single_event_review_novelty_v1(reader,case_original):
    fact=_REVIEW_NOVELTIES_V1.get(reader)
    if fact is None:raise MissingProductionOriginalV1("single_event_review_complete_presealed_novelty")
    return fact.require_for_v1(reader,case_original=case_original)

def release_current_single_event_review_cause_history_v1(reader):
    fact=_REVIEW_NOVELTIES_V1.pop(reader,None)
    if fact is not None:_REVIEW_NOVELTY_FACTS_V1.pop(fact,None)
    for key,value in tuple(_REVIEW_NOVELTY_STAGES_V1.items()):
        if value[1]is fact:_REVIEW_NOVELTY_STAGES_V1.pop(key,None)
    _REVIEW_CAUSE_HISTORIES_V1.pop(reader,None)
    task=_REVIEW_CAUSE_CENSUS_V1.pop(reader,None)
    if task is not None:
        task.prior_case_originals=task.prepared_fingerprints=();task.leaf=None;task.complete=False


def bind_current_single_event_review_novelty_stage_v1(db,frame,stage):
    from .current_method_learning_read_v3 import _method_active
    from .d07_current_behavior_v1 import D07CurrentBehaviorStageV1
    from .domain_background_read_v3 import background_json_loads_v3
    reader=_method_active(db)
    if reader is None or type(stage)is not D07CurrentBehaviorStageV1:
        raise ValueError("review novelty needs its actual same-Work installed stage")
    task=prepare_single_event_review_concern_metadata_v1(reader)
    target=stage.provenance["semantic_target"];q=stage.provenance["semantic_question"]
    fact=require_current_single_event_review_novelty_v1(reader,task.attention.case_original)
    if(frame.envelope.identity.operation_id!=reader.operation.operation_id
            or stage.request is not reader.request and stage.request!=reader.request
            or target.kind!=CASE_KIND or target.original_ref!=fact.case_original.original_ref
            or target.original_digest!=fact.case_original.original_digest
            or canonical_digest(plain_v1(q))!=task.question[1]):
        raise ValueError("review novelty stage changed its actual Question, Case or business operation")
    case=_case_from_wire_v1(background_json_loads_v3(target.value_json))
    fact.require_new_case_v1(reader,case)
    _REVIEW_NOVELTY_STAGES_V1[id(stage)]=(stage,fact,reader.operation)
    return fact.require_new_stage_v1(frame,stage,case)


def require_bound_single_event_review_novelty_stage_v1(frame,stage,case):
    binding=_REVIEW_NOVELTY_STAGES_V1.get(id(stage))
    if binding is None or binding[0]is not stage:
        raise MissingProductionOriginalV1("single_event_review_actual_same_read_novelty_stage")
    return binding[1].require_new_stage_v1(frame,stage,case)
