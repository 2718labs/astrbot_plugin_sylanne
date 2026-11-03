"""Signed attention and fair scheduling for the two ordinary continuity C3 phases."""
from __future__ import annotations
from dataclasses import dataclass,asdict
import math

from ..runtime_contracts import NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion,GraphWrite
from ..domains.d01.ordinary_cumulative_growth_v1 import (
    OrdinaryContinuityBasisOriginalV1,ordinary_continuity_question_key_v1)
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d07_execution_v1 import D07SemanticQuestionV1
from .d01_general_growth_v1 import AdoptCurrentGeneralGrowthRequestV1

PHASES=frozenset({"ordinary_screen","deep_review"})
QUESTION_SCHEMA="d07.ordinary-continuity-question.v1"
ATTENTION_KIND="ordinary_continuity_attention_v1"
_FIXED_QUESTION={
    "ordinary_screen":"Screen the complete authenticated ordinary cumulative case for preservation, core shift, opposition or uncertainty.",
    "deep_review":"Independently review the complete authenticated ordinary cumulative case after its committed deep-required assessment."}

def ordinary_continuity_attention_ids_v1(namespace,question_key):
    tag=canonical_digest((namespace,question_key))[:48]
    return {"attention":"ordinary-continuity-attention:"+tag,"question":"ordinary-continuity-question:"+tag,
        "ticket":"attention:ordinary-continuity:"+tag,"activity":"ordinary-continuity-cognition:"+tag}

@dataclass(frozen=True,slots=True,kw_only=True)
class D07OrdinaryContinuityQuestionV1(D07SemanticQuestionV1):
    phase:str
    basis_original:ProductionOriginalRefV1
    basis:OrdinaryContinuityBasisOriginalV1
    trigger_assessment_original:ProductionOriginalRefV1|None
    continuity_attention_ref:str
    assessment_growth_request:AdoptCurrentGeneralGrowthRequestV1
    causal_parent_executions:tuple[tuple[ProductionOriginalRefV1,str,int],...]
    review_step:int
    causal_depth:int
    schema:str=QUESTION_SCHEMA

    def __post_init__(self):
        D07SemanticQuestionV1(self.question_key,self.question,self.target_ref,self.source_refs)
        if type(self.assessment_growth_request)is not AdoptCurrentGeneralGrowthRequestV1:
            raise TypeError("ordinary continuity question requires its actual registered candidate request")
        if type(self.basis)is not OrdinaryContinuityBasisOriginalV1:
            raise TypeError("ordinary continuity question requires its exact signed complete basis")
        key=ordinary_continuity_question_key_v1(self.basis_original,self.basis,self.phase,self.trigger_assessment_original)
        from ..model_broker.ordinary_continuity_cognition_v1 import validate_ordinary_continuity_causal_fields_v1
        validate_ordinary_continuity_causal_fields_v1(self.phase,self.basis_original,self.trigger_assessment_original,
            self.causal_parent_executions,self.review_step,self.causal_depth)
        base=self.basis.base_head.plan_ref
        roots=tuple(dict.fromkeys((*self.basis.context_source_refs,*self.basis.support_source_refs)))
        if (self.schema!=QUESTION_SCHEMA or self.question_key!=key or self.question!=_FIXED_QUESTION[self.phase]
                or self.target_ref!=VersionedRef(base.key.token,base.revision)
                or self.source_refs!=roots or not self.basis.context_source_refs
                or set(self.basis.context_source_refs)&set(self.basis.support_source_refs)
                or self.continuity_attention_ref!=ordinary_continuity_attention_ids_v1(self.basis.namespace,key)["attention"]):
            raise ValueError("ordinary continuity question changed its actual basis, phase, target or Source columns")

    @property
    def context_source_refs(self):return self.basis.context_source_refs
    @property
    def support_source_refs(self):return self.basis.support_source_refs
    @property
    def original_deadline_utc(self):return self.basis.original_deadline_utc
    @property
    def original_parent_budget_lease_ref(self):return self.basis.original_parent_budget_lease_ref
    @property
    def original_parent_grant_digest(self):return self.basis.original_parent_grant_digest

@dataclass(frozen=True,slots=True)
class RegisterOrdinaryContinuityAttentionRequestV1:
    basis_original:ProductionOriginalRefV1
    phase:str
    trigger_assessment_original:ProductionOriginalRefV1|None=None

    def __post_init__(self):
        if (type(self.basis_original)is not ProductionOriginalRefV1
                or self.basis_original.kind!="d01.ordinary_continuity_basis_v1"or self.phase not in PHASES
                or(self.phase=="ordinary_screen"and self.trigger_assessment_original is not None)
                or(self.phase=="deep_review"and(type(self.trigger_assessment_original)is not ProductionOriginalRefV1
                    or self.trigger_assessment_original.kind!="d01.ordinary_continuity_assessment_v1"))):
            raise ValueError("ordinary continuity attention accepts only its actual basis and exact phase trigger")

@dataclass(frozen=True,slots=True)
class D07OrdinaryContinuityAttentionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    registration_operation_id:str
    registration_receipt_digest:str
    semantic_question_ref:str
    semantic_question_digest:str
    ticket_ref:GraphVersion
    ticket_value_digest:str
    basis_original:ProductionOriginalRefV1
    phase:str
    trigger_assessment_original:ProductionOriginalRefV1|None
    original_deadline_utc:float
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    causal_original:ProductionOriginalRefV1
    causal_operation_id:str
    causal_receipt_digest:str
    schema:str="d07.ordinary-continuity-attention.v1"

    def __post_init__(self):
        if (self.schema!="d07.ordinary-continuity-attention.v1"or self.phase not in PHASES
                or type(self.namespace)is not NamespaceId or type(self.ticket_ref)is not GraphVersion
                or self.ticket_ref.key.type_name!="d07.attention_ticket.v1"
                or NamespaceId.from_key(self.ticket_ref.key)!=self.namespace or self.ticket_ref.revision<1
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("ordinary continuity attention lost its actual signed W01 ticket")
        roots=(*self.context_source_refs,*self.support_source_refs)
        if(not self.context_source_refs or len(roots)>16 or len(set(roots))!=len(roots)
                or type(self.causal_original)is not ProductionOriginalRefV1):
            raise ValueError("ordinary attention lost its bounded actual Source roles or immutable cause")
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!="memory.source"or NamespaceId.from_key(key)!=self.namespace:
                raise ValueError("ordinary attention Source metadata crosses namespace or type")
        for name in("original_parent_budget_lease_ref","causal_operation_id"):
            if type(getattr(self,name))is not str or not getattr(self,name):
                raise ValueError("ordinary attention lost its actual original parent identity")
        for name in("original_parent_grant_digest","causal_receipt_digest"):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in"0123456789abcdef"for c in value):
                raise ValueError("ordinary attention lost its actual signed causal commitment")


class InstalledD07OrdinaryContinuityReadersV1:
    def __init__(self,*,graph,issuer,bundle,owner_guard,role_clock_reader=None):
        from ..graph_coordinator import GraphCoordinator
        from ..host.authority_profile import AdminInstallationBundle
        from .d01_production_operations_v1 import InstalledD01ProductionReadersV1
        if (type(graph)is not GraphCoordinator or issuer is not graph._GraphCoordinator__d11_issuer
                or type(bundle)is not AdminInstallationBundle or graph._GraphCoordinator__d04_installed_joint_assembly is None
                or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
            raise TypeError("ordinary continuity requires this actual Graph installation")
        self.graph,self.issuer,self.bundle=graph,issuer,bundle
        self.basis_readers=InstalledD01ProductionReadersV1(issuer=issuer,owner_guard=owner_guard,
            role_clock_reader=role_clock_reader)

def read_plan_register_ordinary_continuity_attention_v1(db,*,namespace,request,issuer):
    from .d01_ordinary_cumulative_growth_v1 import (
        read_plan_current_ordinary_continuity_basis_v1,read_current_ordinary_continuity_basis_metadata_v1)
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d07 import attention_ticket_key
    metadata=read_current_ordinary_continuity_basis_metadata_v1(db,namespace=namespace,basis_original=request.basis_original)
    plan=read_plan_current_ordinary_continuity_basis_v1(db,namespace=namespace,basis_original=request.basis_original)
    key=metadata.question_key_v1(request.phase,request.trigger_assessment_original)
    ids=ordinary_continuity_attention_ids_v1(namespace,key)
    extra=()if request.trigger_assessment_original is None else(request.trigger_assessment_original.original_ref,)
    return production_read_plan_v1(plan.fixed_type_ids,(*plan.exact_keys,attention_ticket_key(namespace,ids["ticket"])),
        plan.source_roots,(*plan.required_original_refs,request.basis_original.original_ref,*extra))

def stage_register_ordinary_continuity_attention_v1(db,*,frame,request,installed_readers):
    from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,waiting_stage_v1
    from .d01_ordinary_cumulative_growth_v1 import require_current_ordinary_continuity_basis_for_cognition_v1
    from ..domains.d01.production_operations_v1 import stage_result_v1,plain_v1
    from ..domains.d07 import AttentionTicket,D07DomainProvider,attention_ticket_key
    from ..host.model_workflows_v10 import is_installed_ordinary_continuity_cognition_slot_v1
    from .d07_ordinary_continuity_cognition_v1 import configured_ordinary_continuity_workflow_v1
    from .budget import get_budget_lease,require_budget_family_admissible
    if (type(request)is not RegisterOrdinaryContinuityAttentionRequestV1
            or type(installed_readers)is not InstalledD07OrdinaryContinuityReadersV1):
        raise TypeError("actual ordinary continuity attention producer required")
    try:
        read=CurrentDomainReadV1(frame);read.check(db)
        actual=require_current_ordinary_continuity_basis_for_cognition_v1(installed_readers.basis_readers,db,read,
            basis_original=request.basis_original,phase=request.phase,
            trigger_assessment_original=request.trigger_assessment_original)
        basis=actual.basis;namespace=basis.namespace
        if (namespace!=frame.envelope.authority.namespace or frame.envelope.authority.purpose!="consolidation"
                or frame.envelope.parent_budget_lease_ref!=basis.original_parent_budget_lease_ref):
            raise ValueError("ordinary continuity cannot replace its actual namespace, purpose or parent budget")
        workflow=configured_ordinary_continuity_workflow_v1(installed_readers.bundle,request.phase)
        if not is_installed_ordinary_continuity_cognition_slot_v1(installed_readers.bundle,workflow,request.phase):
            raise ValueError("ordinary continuity workflow is not this installed exact phase slot")
        lease=get_budget_lease(db,basis.original_parent_budget_lease_ref);require_budget_family_admissible(db,lease.lease_id)
        grant=installed_readers.issuer.current_budget_grant(db,lease.lease_id)
        if (canonical_digest(grant)!=basis.original_parent_grant_digest or "d07.cognition"not in grant.allowed_work_kinds
                or not set(frame.envelope.authority.audience)<=set(workflow.audiences)
                or any(v>min(lease.available(k),grant.max_ceiling.get(k,0))for k,v in workflow.quote_ceiling.items())):
            raise MissingProductionOriginalV1("actual_original_ordinary_continuity_model_resources")
        deadline=min(frame.envelope.deadline_utc,basis.original_deadline_utc,actual.valid_until_utc,grant.valid_until_utc)
        if frame.now_utc>=deadline:raise MissingProductionOriginalV1("actual_ordinary_continuity_original_deadline")
        ids=ordinary_continuity_attention_ids_v1(namespace,actual.question_key)
        ticket_key=attention_ticket_key(namespace,ids["ticket"])
        if read.head(db,ticket_key).revision:
            raise MissingProductionOriginalV1("actual_ordinary_continuity_attention_already_registered")
        base=basis.base_head.plan_ref
        question=D07OrdinaryContinuityQuestionV1(question_key=actual.question_key,
            question=_FIXED_QUESTION[request.phase],target_ref=VersionedRef(base.key.token,base.revision),
            source_refs=tuple(dict.fromkeys((*basis.context_source_refs,*basis.support_source_refs))),
            phase=request.phase,basis_original=request.basis_original,basis=basis,
            trigger_assessment_original=request.trigger_assessment_original,continuity_attention_ref=ids["attention"],
            assessment_growth_request=actual.growth_request,
            causal_parent_executions=actual.causal_parent_executions,review_step=actual.review_step,causal_depth=actual.causal_depth)
        ticket=AttentionTicket(ids["ticket"],question.question_key,base.key.token,basis.context_source_refs[0],
            "background",0.,0.,0.,0.,0.,0.,0.,0.,0.,frame.snapshot.epochs[0].revision,deadline,
            True,True,(),question.source_refs)
        write=GraphWrite(ticket_key,{"schema":ticket_key.type_name,**plain_v1(ticket)},
            tuple(AtomKey.from_token(ref)for ref in question.source_refs)+(base.key,))
        return stage_result_v1(frame,"d07","register_ordinary_continuity_attention_v1",request,writes=(write,),
            provenance={"ordinary_continuity_question":question,"ordinary_continuity_ticket":ticket},
            receiver_events=(("d07","ordinary_continuity_attention_available_for_service"),),
            proposal_schema="d07.proposal.v1",proposal_hash=D07DomainProvider().descriptor.request_schema_hash)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame,"d07","register_ordinary_continuity_attention_v1",request,missing)

def record_ordinary_continuity_attention_after_cas_v1(db,*,frame,stage,receipt,issuer):
    from .d07_execution_v1 import record_d07_original_in_transaction_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d07 import attention_ticket_key
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d07 import AttentionTicket
    from .domain_background_read_v3 import background_json_loads_v3
    if stage.operation_kind!="register_ordinary_continuity_attention_v1"or stage.coverage!="complete":return None
    raw=background_json_loads_v3(stage.original_payload_json)["provenance"]
    question=decode_typed_production_value_v1(raw["ordinary_continuity_question"],D07OrdinaryContinuityQuestionV1)
    ticket=decode_typed_production_value_v1(raw["ordinary_continuity_ticket"],AttentionTicket)
    ids=ordinary_continuity_attention_ids_v1(question.basis.namespace,question.question_key)
    key=attention_ticket_key(question.basis.namespace,ticket.ticket_id)
    versions=tuple(v for v in receipt.write_versions if v.key==key)
    if len(versions)!=1 or versions[0].revision!=1 or receipt.status!="committed"or receipt.operation_id!=stage.operation_id:
        raise ValueError("ordinary continuity ticket has no actual same-W01 birth")
    history=db.execute("SELECT event_bot,event_persona,event_id,valid FROM graph_history WHERE token=? AND revision=?",
        (key.token,versions[0].revision)).fetchone()
    if history!=(*question.basis.namespace.as_tuple,receipt.operation_id,1):
        raise ValueError("ordinary continuity ticket lost its actual producing history")
    qdigest=record_d07_original_in_transaction_v1(db,issuer,question.basis.namespace,"semantic_question",ids["question"],plain_v1(question))
    original=D07OrdinaryContinuityAttentionOriginalV1(question.basis.namespace,ids["attention"],receipt.operation_id,
        canonical_digest(receipt),ids["question"],qdigest,versions[0],canonical_digest({"schema":key.type_name,**plain_v1(ticket)}),
        question.basis_original,question.phase,question.trigger_assessment_original,ticket.valid_until,
        question.context_source_refs,question.support_source_refs,question.original_parent_budget_lease_ref,
        question.original_parent_grant_digest,question.basis.causal_original,question.basis.causal_operation_id,
        question.basis.causal_receipt_digest)
    digest=record_d07_original_in_transaction_v1(db,issuer,original.namespace,ATTENTION_KIND,original.original_ref,plain_v1(original))
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,original.original_ref,digest,(versions[0],))

def read_ordinary_continuity_attention_original_v1(db,*,namespace,original_ref,issuer):
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    row=read_d07_original_v1(db,issuer,namespace,ATTENTION_KIND,original_ref)
    if row is None:return None
    value=decode_typed_production_value_v1(row[0],D07OrdinaryContinuityAttentionOriginalV1)
    if value.namespace!=namespace or value.original_ref!=original_ref:
        raise ValueError("ordinary continuity attention original crossed its actual identity")
    return value,row[1]

def read_ordinary_continuity_ticket_original_v1(db,*,read,ticket,issuer):
    if not ticket.ticket_id.startswith("attention:ordinary-continuity:"):return None
    from .d01_ordinary_cumulative_growth_v1 import read_current_ordinary_d07_metadata_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    namespace=read.frame.envelope.authority.namespace
    tag=ticket.ticket_id.removeprefix("attention:ordinary-continuity:")
    row=read_ordinary_continuity_attention_original_v1(db,namespace=namespace,
        original_ref="ordinary-continuity-attention:"+tag,issuer=issuer)
    if row is None:raise ValueError("ordinary continuity ticket has no actual signed attention")
    attention,digest=row
    question=read_current_ordinary_d07_metadata_v1(db,namespace=namespace,issuer=issuer,
        kind="semantic_question",original_ref=attention.semantic_question_ref)
    if question is None:raise ValueError("ordinary continuity ticket has no actual signed question metadata")
    q,original=question
    basis=decode_typed_production_value_v1(q["basis_original"],ProductionOriginalRefV1)
    trigger=None if q["trigger_assessment_original"]is None else decode_typed_production_value_v1(
        q["trigger_assessment_original"],ProductionOriginalRefV1)
    from ..domains.d01.ordinary_cumulative_growth_v1 import _ordinary_continuity_question_key_fields_v1
    key=_ordinary_continuity_question_key_fields_v1(basis,basis.original_digest,q["phase"],trigger)
    ids=ordinary_continuity_attention_ids_v1(namespace,key)
    if(q["schema"]!=QUESTION_SCHEMA or original.original_digest!=attention.semantic_question_digest
            or q["question_key"]!=key or key!=ticket.question_key or tuple(q["source_refs"])!=ticket.source_refs
            or ids["ticket"]!=ticket.ticket_id or ids["question"]!=attention.semantic_question_ref
            or q["continuity_attention_ref"]!=attention.original_ref or basis!=attention.basis_original
            or read.frame.now_utc>=min(ticket.valid_until,q["basis"]["original_deadline_utc"])):
        raise ValueError("ordinary continuity ticket changed its actual question, Source or deadline")
    head=read.head(db,attention.ticket_ref.key,required=True)
    if head.revision!=attention.ticket_ref.revision or canonical_digest(head.value)!=attention.ticket_value_digest:
        raise ValueError("ordinary continuity actual signed ticket head changed")
    read.committed_operation(db,attention.registration_operation_id)
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,attention.original_ref,digest,(attention.ticket_ref,))

from weakref import WeakKeyDictionary
_ATTENTION_FOLLOWUP_CAUSES=WeakKeyDictionary()
ATTENTION_SERVICE_EVENT="ordinary_continuity_attention_available_for_service"

def ordinary_continuity_attention_cause_locator_path_v1(owner,column,path):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3:return None
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    task=owner.entry_column
    if(task is None or task.column is not column or task.entry is None
            or task.entry[1:3]!=("d07",ATTENTION_SERVICE_EVENT)):return None
    if task.metadata[:2]!=("d07","register_ordinary_continuity_attention_v1"):
        raise ValueError("ordinary attention event has another actual registered producer")
    if not path:return True
    if path[0]in {"schema","namespace","identity","authority","parent_budget","coverage","now_utc"}:return True
    if path[0]!="provenance":return False
    if len(path)==1:return True
    if path[1]=="ordinary_continuity_ticket":return True
    if path[1]!="ordinary_continuity_question":return False
    from .d07_ordinary_continuity_cognition_v1 import ordinary_continuity_metadata_retains_path_v1
    return ordinary_continuity_metadata_retains_path_v1("semantic_question",path[2:])

def read_ordinary_continuity_attention_followup_cause_v1(db,*,namespace,event_kind,
        causal_operation_id,original_ref,issuer):
    if event_kind!=ATTENTION_SERVICE_EVENT:return None
    from .domain_background_read_v3 import (_active_v3,require_actual_background_attachment_owner_v3,
        background_point_v3,background_json_loads_v3,background_typed_original_digest_v3)
    from .domain_production_originals_v1 import TABLE,_receipt,reconstruct_graph_bundle_commit_receipt_v1
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if(namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer
            or owner.entry is None or owner.entry[:3]!=(causal_operation_id,"d07",event_kind)):
        raise ValueError("ordinary attention cause requires its actual outbox Work")
    task=owner.entry_column
    if task is None or not task.complete or task.column.sha256!=task.metadata[2]:
        raise ValueError("ordinary attention cause lacks complete actual producer EOF")
    metadata,payload=owner.entry_metadata
    if(metadata[:2]!=("d07","register_ordinary_continuity_attention_v1")
            or payload["schema"]!="d07.current-register_ordinary_continuity_attention_v1.v1"
            or payload["identity"]["operation_id"]!=causal_operation_id or payload["coverage"]!="complete"):
        raise ValueError("ordinary attention cause changed its actual complete registered producer")
    row=background_point_v3(db,table=TABLE,columns=("domain","operation_kind","request_digest","original_digest",
        "read_versions_json","bundle_digest","receipt_json","receipt_digest"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    if row is None or row[:2]!=metadata[:2]or row[3]!=metadata[2]:
        raise ValueError("ordinary attention producer metadata changed")
    receipt=_receipt(background_json_loads_v3(row[6]))
    actual=background_point_v3(db,table="graph_bundle_operations",columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    event=background_point_v3(db,table="graph_events",columns=("reads","revisions","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,receipt.activity_id,causal_operation_id),
        legacy_reader=lambda:None)
    if(actual is None or event is None or receipt.status!="committed"
            or receipt.operation_id!=causal_operation_id or receipt.operation_digest!=row[5]
            or actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or background_typed_original_digest_v3(db,row[6],receipt)!=row[7]
            or reconstruct_graph_bundle_commit_receipt_v1(namespace,causal_operation_id,(*actual,row[6]),event)!=receipt):
        raise ValueError("ordinary attention cause lost its actual W01 receipt and complete event membership")
    native=read_ordinary_continuity_attention_original_v1(db,namespace=namespace,original_ref=original_ref,issuer=issuer)
    if native is None:raise ValueError("ordinary attention event has no actual signed attention original")
    attention,digest=native;q=payload["provenance"]["ordinary_continuity_question"]
    if(attention.registration_operation_id!=causal_operation_id or canonical_digest(receipt)!=attention.registration_receipt_digest
            or attention.ticket_ref not in receipt.write_versions or attention.semantic_question_ref!=ordinary_continuity_attention_ids_v1(
                namespace,q["question_key"])["question"]
            or q["basis_original"]!={"kind":attention.basis_original.kind,"original_ref":attention.basis_original.original_ref,
                "original_digest":attention.basis_original.original_digest,
                "read_versions":[{"key":v.key.token,"revision":v.revision}for v in attention.basis_original.read_versions]}
            or tuple(q["source_refs"])!=(*attention.context_source_refs,*attention.support_source_refs)
            or q["phase"]!=attention.phase
            or q["basis"]["original_parent_budget_lease_ref"]!=attention.original_parent_budget_lease_ref
            or q["basis"]["original_parent_grant_digest"]!=attention.original_parent_grant_digest):
        raise ValueError("ordinary attention native original differs from its actual registered same-W01 metadata")
    original={"domain":row[0],"operation_kind":row[1],"request_digest":row[2],"original_digest":digest,
        "domain_original_digest":row[3],"read_versions":receipt.read_versions,"receipt":receipt,"payload":payload,
        "ordinary_continuity_attention":attention}
    _ATTENTION_FOLLOWUP_CAUSES[owner]=(original,task,owner.operation,owner.graph_stamp)
    return original

def ordinary_continuity_attention_followup_plan_v1(db,*,namespace,event):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    owner=_active_v3(db)
    original=read_ordinary_continuity_attention_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if(original is None or event.receiver_domain!="d07"or event.trigger_original.original_digest!=original["original_digest"]):
        raise ValueError("ordinary attention service plan has another actual signed event")
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),())

def resolve_ordinary_continuity_attention_followup_v1(db,*,frame,event,original):
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    from .domain_production_followups_v1 import DomainFollowupResolutionV1,DomainFollowupCommandV1
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if(_ATTENTION_FOLLOWUP_CAUSES.get(owner)!=(original,owner.entry_column,owner.operation,owner.graph_stamp)
            or event.receiver_domain!="d07"or event.event_kind!=ATTENTION_SERVICE_EVENT):
        raise ValueError("ordinary attention service left its actual same-Work causal metadata")
    CurrentDomainReadV1(frame).check(db)
    attention=original["ordinary_continuity_attention"]
    if frame.now_utc>=attention.original_deadline_utc:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),("ordinary_original_parent_deadline_exhausted",))
    ids=ordinary_continuity_attention_ids_v1(owner.namespace,original["payload"]["provenance"]["ordinary_continuity_question"]["question_key"])
    command=DomainFollowupCommandV1("d07","serve_concern",ServeCurrentConcernRequestV1("background",attention.semantic_question_ref),
        ids["activity"],frame.envelope.authority.audience[0],frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready",(command,),(),())

def ordinary_continuity_attention_parent_from_prepared_v1(prepared,event,command):
    prepared.require_v3(prepared.graph);owner=prepared.owner
    current=_ATTENTION_FOLLOWUP_CAUSES.get(owner)
    if current is None:return None
    original,task,operation,stamp=current
    if(task is not owner.entry_column or operation is not owner.operation or stamp!=owner.graph_stamp
            or event.event_kind!=ATTENTION_SERVICE_EVENT or event.causal_operation_id!=original["receipt"].operation_id
            or command is not None and command not in prepared.local_result[5].commands):
        raise ValueError("ordinary attention parent left its actual retained event/command Work")
    from .d07_single_event_review_v1 import _ATTENTION_PREPARED_CENSUS_V1
    census=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
    located=None if census is None or not census.complete else census.result
    if located is not None:
        located.require_current_v1(owner)
        if located.family!="ordinary_continuity":
            raise ValueError("ordinary attention parent selected another actual prepared family")
        return located
    return original["ordinary_continuity_attention"]

def release_ordinary_continuity_attention_followup_metadata_v1(owner):
    _ATTENTION_FOLLOWUP_CAUSES.pop(owner,None)

def validate_ordinary_continuity_registration_provenance_v1(provenance):
    """Closed retention codec only; this does not issue Source or Body rights."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1,_references,DomainProductionErasureHold
    from ..domains.d07 import AttentionTicket
    if type(provenance)is not dict or set(provenance)!={"ordinary_continuity_question","ordinary_continuity_ticket"}:
        raise DomainProductionErasureHold("ordinary continuity registration provenance has another exact shape")
    question=decode_typed_production_value_v1(provenance["ordinary_continuity_question"],D07OrdinaryContinuityQuestionV1)
    ticket=decode_typed_production_value_v1(provenance["ordinary_continuity_ticket"],AttentionTicket)
    ids=ordinary_continuity_attention_ids_v1(question.basis.namespace,question.question_key)
    if(ticket.ticket_id!=ids["ticket"]or ticket.question_key!=question.question_key
            or ticket.source_refs!=question.source_refs or ticket.category!="background"
            or ticket.concern_ref!=question.target_ref.ref
            or ticket.causal_root!=question.context_source_refs[0]or ticket.valid_until>question.original_deadline_utc):
        raise ValueError("ordinary continuity retention ticket differs from its actual complete question")
    return tuple(sorted(set(_references(provenance))))
