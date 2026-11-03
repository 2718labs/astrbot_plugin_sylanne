"""Actual signed C3 originals and preparation for ordinary cumulative continuity."""
from __future__ import annotations
from dataclasses import dataclass,fields
from weakref import WeakKeyDictionary
from ..runtime_contracts import canonical_digest
from ..graph_types import AtomKey,GraphVersion
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_general_growth_v1 import AdoptCurrentGeneralGrowthRequestV1
from .d01_production_operations_v1 import MissingProductionOriginalV1

_ISSUER=object()
_CAUSES=WeakKeyDictionary()

def _same_original_v1(first,second):
    return(type(first)is ProductionOriginalRefV1 and type(second)is ProductionOriginalRefV1
        and(first.kind,first.original_ref,first.original_digest)==
           (second.kind,second.original_ref,second.original_digest))

def _paid_c3_originals_v1(readers,db,read,prepared,interpretation_ref):
    from .d07_execution_v1 import (
        read_d07_original_v1,read_original_d07_request_v1,require_actual_d07_execution_wall_deadline_v1,
        decode_d07_execution_original_v1)
    from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1,from_wire
    from .jobs import get_job
    namespace=read.frame.envelope.authority.namespace
    rows={}
    for kind,ref in (("prepared",prepared.job_id),("semantic_question",prepared.semantic_question_ref),
            ("request",prepared.job_id),("call",prepared.job_id),("paid_cost",prepared.job_id),
            ("body_cost",prepared.job_id),("execution","d07-terminal:"+prepared.call_id),
            ("adopted",interpretation_ref)):
        row=read_d07_original_v1(db,readers.issuer,namespace,kind,ref)
        if row is None:raise MissingProductionOriginalV1("actual_ordinary_prior_c3_"+kind)
        rows[kind]=(ref,row)
    paid=rows["paid_cost"][1][0];body=rows["body_cost"][1][0]
    if (paid["paid"]is not True or paid["unknown_dimensions"] or body["unpaid_cost"]
            or paid["prepared_digest"]!=prepared.digest or body["prepared_digest"]!=prepared.digest
            or body["terminal_digest"]!=paid["terminal_digest"] or body["result_digest"]!=paid["result_digest"]):
        raise ValueError("ordinary continuity requires the exact paid model and Body accounting originals")
    result_row=read_d07_original_v1(db,readers.issuer,namespace,"result",paid["result_ref"])
    if result_row is None:raise MissingProductionOriginalV1("actual_ordinary_prior_c3_result")
    result=from_wire(result_row[0],D07CognitionResultReadV1)
    intent=model_from_wire(rows["call"][1][0],ModelEgressIntentV1)
    request=read_original_d07_request_v1(db,readers.issuer,prepared)
    result.require_original(intent,prepared)
    if (request.call_id!=prepared.call_id or request.digest!=intent.request_digest
            or intent.budget_reservation_operation_id!=prepared.operation_id
            or intent.budget_reservation_digest!=prepared.reservation_digest
            or result.observation.digest!=paid["result_digest"]
            or canonical_digest(result.terminal_receipt)!=paid["terminal_digest"]):
        raise ValueError("ordinary continuity prior C3 call, result and measured cost do not match")
    execution=decode_d07_execution_original_v1(rows["execution"][1][0])
    if (execution.terminal_ref!="d07-terminal:"+prepared.call_id
            or execution.operation_id!=prepared.operation_id or execution.execution_id!=prepared.execution_id
            or execution.input_digest!=prepared.stage_input_digest):
        raise ValueError("ordinary continuity prior C3 terminal is not its actual prepared execution")
    from .d07_single_event_review_v1 import (D07SingleEventReviewPreparedV1,
        require_current_single_event_review_interpretation_job_v1)
    job=(require_current_single_event_review_interpretation_job_v1(db,prepared)
        if type(prepared)is D07SingleEventReviewPreparedV1 else get_job(db,prepared.job_id))
    if job.phase!="completed"or job.result_ref!=execution.terminal_ref:
        raise MissingProductionOriginalV1("actual_ordinary_prior_c3_completed_job")
    require_actual_d07_execution_wall_deadline_v1(prepared,result,job)
    rows["result"]=(paid["result_ref"],result_row)
    originals=tuple(ProductionOriginalRefV1("d07."+kind,ref,row[1])for kind,(ref,row)in rows.items())
    return originals,execution

@dataclass(frozen=True,eq=False)
class _ActualOrdinaryProposalCauseV1:
    causal_original:ProductionOriginalRefV1
    causal_operation_id:str
    causal_receipt_digest:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    prior_cognition_originals:tuple[ProductionOriginalRefV1,...]
    prior_c3_call_ids:tuple[str,...]
    prior_causal_depth:int
    causal_parent_executions:tuple[tuple[ProductionOriginalRefV1,str,int],...]

    def require_v1(self,readers,read):
        if _CAUSES.get(self)!=(readers,read,read.frame.envelope.identity.operation_id):
            raise ValueError("ordinary proposal cause left its actual signed input Work")
        return self

def read_actual_ordinary_proposal_cause_v1(readers,db,read,*,proposal_original,general_growth_intent_original):
    from .d01_production_operations_v1 import CurrentDomainReadV1,InstalledD01ProductionReadersV1
    from .d01_general_growth_v1 import GeneralGrowthIntentOriginalV1,_actual_general_cognition_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d07_general_growth_attention_v1 import _actual_general_growth_budget_ancestry_v1
    from .domain_background_read_v3 import background_point_v3,background_json_loads_v3
    if (type(readers)is not InstalledD01ProductionReadersV1 or type(read)is not CurrentDomainReadV1
            or not db.in_transaction or read.frame.envelope.authority.purpose!="consolidation"):
        raise TypeError("ordinary proposal cause requires its actual consolidation input Work")
    read.check(db)
    raw,actual_proposal=readers._read(db,read,proposal_original.original_ref,"growth_proposal")
    wrapper_raw,actual_intent=readers._read(db,read,general_growth_intent_original.original_ref,"general_growth_intent_v1")
    if not _same_original_v1(actual_proposal,proposal_original)or not _same_original_v1(actual_intent,general_growth_intent_original):
        raise ValueError("ordinary cumulative basis changed its actual signed General proposal or intent")
    wrapper=decode_typed_production_value_v1(wrapper_raw,GeneralGrowthIntentOriginalV1)
    if (wrapper.proposal_ref!=actual_proposal.original_ref
            or wrapper.proposal_digest!=actual_proposal.original_digest
            or tuple(raw["evidence_source_refs"])!=wrapper.support_source_refs):
        raise ValueError("ordinary cumulative cause mixed another General candidate")
    interpretations=[]
    for original in wrapper.context_original_refs:
        try:key=AtomKey.from_token(original.original_ref)
        except ValueError:continue
        if key.type_name=="d07.current_interpretation.v1":interpretations.append(original)
    if len(interpretations)!=1:
        raise MissingProductionOriginalV1("unique_actual_ordinary_proposal_cognition")
    prepared,question,semantic,semantic_original=_actual_general_cognition_v1(
        db,readers,read,interpretations[0].original_ref)
    if (not _same_original_v1(semantic_original,interpretations[0])
            or prepared.context_source_refs!=wrapper.context_source_refs
            or semantic.value["proposition"]!=raw["replacement_claim"]
            or not any(v.kind=="d07.prepared"and v.original_ref==prepared.job_id
                and v.original_digest==prepared.digest for v in wrapper.context_original_refs)):
        raise ValueError("ordinary proposal has no exact actual General C3 producer")
    originals,execution=_paid_c3_originals_v1(readers,db,read,prepared,semantic.key.token)
    namespace=read.frame.envelope.authority.namespace
    header=background_point_v3(db,table="graph_d01_production_inputs_v1",
        columns=("kind","producing_operation_id","payload_digest"),
        key_columns=("bot","persona","original_ref"),key=(*namespace.as_tuple,actual_proposal.original_ref),
        legacy_reader=lambda:db.execute("SELECT kind,producing_operation_id,payload_digest FROM graph_d01_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?",(*namespace.as_tuple,actual_proposal.original_ref)).fetchone())
    if header is None or header[0]not in{"growth_proposal","growth_proposal_v2"}or header[2]!=actual_proposal.original_digest:
        raise MissingProductionOriginalV1("actual_committed_ordinary_proposal_cause")
    from .domain_production_originals_v1 import _receipt
    commit=read.committed_operation(db,header[1]);receipt=_receipt(background_json_loads_v3(commit[1]))
    if receipt.operation_id!=header[1]or receipt.operation_digest!=commit[0]or receipt.status!="committed":
        raise ValueError("ordinary proposal cause lacks its actual typed committed Graph receipt")
    lease,grant,_=_actual_general_growth_budget_ancestry_v1(db,question.original_parent_budget_lease_ref,readers.issuer)
    if canonical_digest(grant)!=question.original_parent_grant_digest:
        raise MissingProductionOriginalV1("ordinary_original_parent_grant_changed")
    deadline=min(question.original_deadline_utc,prepared.original_deadline_utc,grant.valid_until_utc)
    if read.frame.now_utc>=deadline:
        raise MissingProductionOriginalV1("ordinary_original_parent_deadline_exhausted")
    value=_ActualOrdinaryProposalCauseV1(actual_proposal,header[1],canonical_digest(receipt),lease.lease_id,
        question.original_parent_grant_digest,deadline,originals,(prepared.call_id,),execution.causal_depth,
        ((next(v for v in originals if v.kind=="d07.execution"),execution.execution_id,execution.causal_depth),))
    _CAUSES[value]=(readers,read,read.frame.envelope.identity.operation_id)
    return value

from .d07_execution_v1 import D07PreparedExecutionV1
from ..runtime_contracts import NamespaceId

def _require_continuity_causality_v1(phase,basis_original,question_original,trigger,parents,review_step,causal_depth):
    from ..model_broker.ordinary_continuity_cognition_v1 import validate_ordinary_continuity_causal_fields_v1
    if type(question_original)is not ProductionOriginalRefV1 or question_original.kind!="d07.semantic_question":
        raise ValueError("ordinary continuity requires its exact signed question original")
    validate_ordinary_continuity_causal_fields_v1(phase,basis_original,trigger,parents,review_step,causal_depth)

@dataclass(frozen=True,slots=True,kw_only=True)
class D07OrdinaryContinuityPreparedV1(D07PreparedExecutionV1):
    semantic_question_ref:str
    semantic_question_digest:str
    continuity_attention_ref:str
    continuity_attention_digest:str
    phase:str
    basis_original:ProductionOriginalRefV1
    trigger_assessment_original:ProductionOriginalRefV1|None
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]
    prior_c3_call_ids:tuple[str,...]
    assessment_policy_ref:str
    assessment_growth_request:AdoptCurrentGeneralGrowthRequestV1
    causal_parent_executions:tuple[tuple[ProductionOriginalRefV1,str,int],...]
    review_step:int
    causal_depth:int
    schema:str="d07.ordinary-continuity-prepared.v1"

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))

    def __post_init__(self):
        from ..model_broker.ordinary_continuity_cognition_v1 import thaw_ordinary_continuity_cognition_request_v1
        from .domain_background_read_v3 import background_json_loads_v3
        if (self.schema!="d07.ordinary-continuity-prepared.v1"or self.work_kind!="concern"
                or self.purpose!="consolidation"or self.call_id in self.prior_c3_call_ids
                or not self.prior_c3_call_ids or len(set(self.prior_c3_call_ids))!=len(self.prior_c3_call_ids)):
            raise ValueError("ordinary continuity preparation requires its distinct actual phase call")
        if(type(self.assessment_growth_request)is not AdoptCurrentGeneralGrowthRequestV1
                or type(self.assessment_policy_ref)is not str or not self.assessment_policy_ref):
            raise ValueError("ordinary preparation lost its actual assessment candidate/policy selectors")
        question=ProductionOriginalRefV1("d07.semantic_question",self.semantic_question_ref,self.semantic_question_digest)
        _require_continuity_causality_v1(self.phase,self.basis_original,question,self.trigger_assessment_original,
            self.causal_parent_executions,self.review_step,self.causal_depth)
        frozen=thaw_ordinary_continuity_cognition_request_v1(background_json_loads_v3(self.frozen_json))
        value=frozen.input
        if (value.namespace!=self.namespace or value.activity_id!=self.activity_id or value.phase!=self.phase
                or value.question_original!=question or value.causal_parent_executions!=self.causal_parent_executions
                or(value.review_step,value.causal_depth)!=(self.review_step,self.causal_depth)
                or tuple(v.source_ref.ref for v in value.context_sources)!=self.context_source_refs
                or tuple(v.source_ref.ref for v in value.support_sources)!=self.support_source_refs):
            raise ValueError("ordinary continuity prepared original differs from its actual frozen model input")

@dataclass(frozen=True,slots=True)
class D07OrdinaryContinuityExecutionOriginalV1:
    terminal_ref:str
    operation_id:str
    activity_id:str
    effect_id:str
    attempt_id:str
    execution_id:str
    input_digest:str
    result_digest:str
    work_kind:str
    started_at:float
    ended_at:float
    time_mapping_ref:str
    time_mapping_version:str
    parent_budget_ref:str
    cost_receipt_refs:tuple[str,...]
    source_refs:tuple[str,...]
    activation_generation:int
    resolved_slots:tuple[str,...]
    discriminating_refs:tuple[str,...]
    predictions:tuple[tuple[str,...],...]
    causal_depth:int
    phase:str
    basis_original:ProductionOriginalRefV1
    question_original:ProductionOriginalRefV1
    trigger_assessment_original:ProductionOriginalRefV1|None
    causal_parent_executions:tuple[tuple[ProductionOriginalRefV1,str,int],...]
    review_step:int
    status:str="completed"
    schema:str="d07.ordinary-continuity-execution.v1"

    def __post_init__(self):
        import math
        if (self.schema!="d07.ordinary-continuity-execution.v1"or self.work_kind!="concern"
                or self.status!="completed"or self.resolved_slots or self.discriminating_refs or self.predictions
                or type(self.activation_generation)is not int or self.activation_generation<1
                or type(self.started_at)not in(int,float)or type(self.ended_at)not in(int,float)
                or not math.isfinite(self.started_at)or not math.isfinite(self.ended_at)or self.ended_at<self.started_at
                or not self.cost_receipt_refs or not self.source_refs):
            raise ValueError("ordinary continuity requires its exact completed paid phase execution")
        for name in ("terminal_ref","operation_id","activity_id","effect_id","attempt_id","execution_id",
                "input_digest","result_digest","time_mapping_ref","time_mapping_version","parent_budget_ref"):
            if type(getattr(self,name))is not str or not getattr(self,name):
                raise ValueError("ordinary continuity execution lost its actual identity or accounting commitment")
        _require_continuity_causality_v1(self.phase,self.basis_original,self.question_original,
            self.trigger_assessment_original,self.causal_parent_executions,self.review_step,self.causal_depth)

def configured_ordinary_continuity_workflow_v1(bundle,phase):
    from ..host.model_workflows_v10 import AdminModelWorkflowsV10,is_installed_ordinary_continuity_cognition_slot_v1
    if type(bundle.model_workflows)is not AdminModelWorkflowsV10 or phase not in {"ordinary_screen","deep_review"}:
        raise MissingProductionOriginalV1("explicit_installed_ordinary_continuity_phase_workflow_v10")
    workflow=getattr(bundle.model_workflows,"ordinary_continuity_screen"if phase=="ordinary_screen"else"ordinary_continuity_deep")
    if workflow is None:raise MissingProductionOriginalV1("explicit_installed_ordinary_continuity_phase_workflow_v10")
    if not is_installed_ordinary_continuity_cognition_slot_v1(bundle,workflow,phase):
        raise ValueError("ordinary continuity model workflow changed its exact installation slot")
    return workflow

def ordinary_continuity_source_operation_v1(kind):
    return kind in {"register_ordinary_cumulative_growth_policy_v1","assess_ordinary_continuity_v1",
        "adopt_ordinary_deep_growth_v1","register_ordinary_continuity_attention_v1","serve_concern"}

def require_actual_ordinary_continuity_metadata_reader_v1(reader):
    if reader.operation_kind=="serve_concern":
        return require_actual_ordinary_continuity_concern_input_work_v1(reader)
    from .current_method_learning_read_v3 import require_actual_method_learning_attachment_owner_v3
    from .d01_ordinary_cumulative_growth_v1 import (
        RegisterOrdinaryCumulativeGrowthPolicyRequestV1,AssessOrdinaryContinuityRequestV1,AdoptOrdinaryDeepGrowthRequestV1)
    from .d07_ordinary_continuity_attention_v1 import RegisterOrdinaryContinuityAttentionRequestV1
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    requests={"register_ordinary_cumulative_growth_policy_v1":RegisterOrdinaryCumulativeGrowthPolicyRequestV1,
        "assess_ordinary_continuity_v1":AssessOrdinaryContinuityRequestV1,
        "adopt_ordinary_deep_growth_v1":AdoptOrdinaryDeepGrowthRequestV1,
        "register_ordinary_continuity_attention_v1":RegisterOrdinaryContinuityAttentionRequestV1}
    if (reader.operation_kind not in requests or type(reader.request)is not requests[reader.operation_kind]
            or reader.authority.namespace!=reader.namespace or reader.fence.scope.operation!="read"):
        raise ValueError("ordinary continuity metadata requires its actual registered Source READ Work")
    return reader

def ordinary_continuity_metadata_retains_path_v1(kind,path):
    common=("schema","namespace","operation_id","activity_id","effect_id","attempt_id","job_id","call_id",
        "execution_id","semantic_question_ref","semantic_question_digest","phase","basis_original",
        "trigger_assessment_original","continuity_attention_ref","continuity_attention_digest",
        "context_source_refs","support_source_refs","original_parent_budget_lease_ref",
        "original_parent_grant_digest","original_deadline_utc","prior_c3_call_ids",
        "causal_parent_executions","review_step","causal_depth","assessment_policy_ref","assessment_growth_request")
    if kind=="prepared":paths=tuple((name,)for name in common)
    elif kind=="adopted":
        paths=tuple((name,)for name in ("schema","interpretation_ref","interpretation_revision",
            "interpretation_value_digest","adoption_operation_id","graph_receipt_digest","prepared_digest",
            "actual_result_digest","question_scope","supporting_refs"))
    elif kind=="semantic_question":
        paths=tuple((name,)for name in ("schema","phase","question_key","target_ref","source_refs","basis_original",
            "trigger_assessment_original","continuity_attention_ref","causal_parent_executions","review_step","causal_depth",
            "assessment_growth_request"))
        paths+=tuple(("basis",name)for name in ("namespace","policy_original","source_versions","support_source_refs","context_source_refs",
            "context_original_refs","prior_cognition_originals","causal_original","causal_operation_id",
            "causal_receipt_digest","original_parent_budget_lease_ref","original_parent_grant_digest",
            "original_deadline_utc","model_content_manifest","model_content_manifest_digest"))
    else:raise ValueError("unregistered ordinary continuity D07 metadata kind")
    return any(path==prefix[:len(path)]or path[:len(prefix)]==prefix for prefix in paths)

_METADATA=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class _OrdinaryContinuityInterpretationMetadataV1:
    basis_original:ProductionOriginalRefV1
    phase:str
    trigger_assessment_original:ProductionOriginalRefV1|None
    prepared_ref:str
    call_id:str
    question_key:str

    def require_v1(self,db,namespace,interpretation_ref):
        if _METADATA.get(self)!=(db,namespace,interpretation_ref):
            raise ValueError("ordinary continuity interpretation metadata left its actual signed input Work")
        return self

def read_ordinary_continuity_interpretation_metadata_v1(db,*,namespace,interpretation_ref,issuer):
    from .d01_ordinary_cumulative_growth_v1 import (
        read_current_ordinary_d07_metadata_v1,locate_current_ordinary_d07_prepared_v1)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    adopted=read_current_ordinary_d07_metadata_v1(db,namespace=namespace,issuer=issuer,kind="adopted",
        original_ref=interpretation_ref)
    if adopted is None:raise MissingProductionOriginalV1("actual_ordinary_continuity_adoption_metadata")
    raw,adopted_original=adopted
    if raw["interpretation_ref"]!=interpretation_ref:
        raise ValueError("ordinary continuity metadata changed its actual interpretation")
    ref=locate_current_ordinary_d07_prepared_v1(db,namespace=namespace,prepared_digest=raw["prepared_digest"])
    prepared=read_current_ordinary_d07_metadata_v1(db,namespace=namespace,issuer=issuer,kind="prepared",original_ref=ref)
    if prepared is None:raise MissingProductionOriginalV1("actual_ordinary_continuity_prepared_metadata")
    p,prepared_original=prepared
    if p["schema"]!="d07.ordinary-continuity-prepared.v1"or prepared_original.original_digest!=raw["prepared_digest"]:
        raise ValueError("ordinary continuity interpretation was not produced by its exact named C3")
    question=read_current_ordinary_d07_metadata_v1(db,namespace=namespace,issuer=issuer,kind="semantic_question",
        original_ref=p["semantic_question_ref"])
    if question is None:raise MissingProductionOriginalV1("actual_ordinary_continuity_question_metadata")
    q,question_original=question
    if (q["schema"]!="d07.ordinary-continuity-question.v1"
            or question_original.original_digest!=p["semantic_question_digest"]
            or(q["phase"],q["basis_original"],q["trigger_assessment_original"])!=
               (p["phase"],p["basis_original"],p["trigger_assessment_original"])
            or q["question_key"]!=raw["question_scope"]):
        raise ValueError("ordinary continuity signed question/prepared/adoption metadata disagree")
    basis=decode_typed_production_value_v1(p["basis_original"],ProductionOriginalRefV1)
    trigger=(None if p["trigger_assessment_original"]is None else
        decode_typed_production_value_v1(p["trigger_assessment_original"],ProductionOriginalRefV1))
    value=_OrdinaryContinuityInterpretationMetadataV1(basis,p["phase"],trigger,ref,p["call_id"],q["question_key"])
    _METADATA[value]=(db,namespace,interpretation_ref)
    return value

from .d07_ordinary_continuity_attention_v1 import (D07OrdinaryContinuityQuestionV1,
    RegisterOrdinaryContinuityAttentionRequestV1,InstalledD07OrdinaryContinuityReadersV1,
    stage_register_ordinary_continuity_attention_v1,read_plan_register_ordinary_continuity_attention_v1,
    record_ordinary_continuity_attention_after_cas_v1)

def current_ordinary_continuity_basis_for_d07_v1(service,db,frame,question):
    from .d01_production_operations_v1 import CurrentDomainReadV1,InstalledD01ProductionReadersV1
    from .d01_ordinary_cumulative_growth_v1 import require_current_ordinary_continuity_basis_for_cognition_v1
    if type(question)is not D07OrdinaryContinuityQuestionV1:
        raise TypeError("actual ordinary continuity question required")
    readers=InstalledD01ProductionReadersV1(issuer=service.d11_issuer,owner_guard=frame.owner_guard,
        role_clock_reader=service.graph._GraphCoordinator__d04_semantic_mapping_reader)
    actual=require_current_ordinary_continuity_basis_for_cognition_v1(readers,db,CurrentDomainReadV1(frame),
        basis_original=question.basis_original,phase=question.phase,
        trigger_assessment_original=question.trigger_assessment_original)
    if (actual.basis!=question.basis or actual.question_key!=question.question_key
            or actual.growth_request!=question.assessment_growth_request
            or actual.causal_parent_executions!=question.causal_parent_executions
            or(actual.review_step,actual.causal_depth)!=(question.review_step,question.causal_depth)):
        raise MissingProductionOriginalV1("stale_actual_ordinary_continuity_question")
    return actual

def freeze_current_ordinary_continuity_stage_v1(frame,stage,workflow,installation_id):
    from ..model_broker.ordinary_continuity_cognition_v1 import (OrdinaryContinuityCognitionInputV1,
        freeze_ordinary_continuity_cognition_request_v1,ordinary_continuity_template_v1,PURPOSE,WORK_KIND)
    from ..model_broker.d07_cognition_v1 import D07CognitionInstallationV1
    from .d07_execution_v1 import _source_input
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.production_operations_v1 import plain_v1
    question=stage.provenance["semantic_question"];actual=stage.provenance["ordinary_continuity_basis"]
    actual.require_current_v1(committed=True)
    selected=tuple(v for v in stage.provenance["tickets"]if v.ticket_id==stage.provenance["choice"].ticket_id)
    version,_,_,_=ordinary_continuity_template_v1(question.phase)
    if (type(question)is not D07OrdinaryContinuityQuestionV1 or actual.basis!=question.basis
            or stage.work_kind!="concern"or stage.status!="queued"or stage.envelope!=frame.envelope
            or len(selected)!=1 or selected[0].question_key!=question.question_key
            or selected[0].source_refs!=question.source_refs
            or(workflow.template_version,workflow.purpose,workflow.work_kind)!=(version,PURPOSE,WORK_KIND)
            or frame.envelope.authority.purpose!=PURPOSE
            or not set(frame.envelope.authority.audience)<=set(workflow.audiences)):
        raise ValueError("ordinary continuity freeze requires its actual basis, fair ticket and exact installed phase")
    payload={"basis_original":plain_v1(question.basis_original),"basis":plain_v1(actual.basis),
        "phase":question.phase,"trigger_assessment_original":plain_v1(question.trigger_assessment_original)}
    value=OrdinaryContinuityCognitionInputV1(frame.envelope.authority.namespace,frame.envelope.identity.activity_id,
        question.phase,question.question_key,
        ProductionOriginalRefV1("d07.semantic_question",stage.request.trigger_original_ref,canonical_digest(plain_v1(question))),
        actual.causal_parent_executions,actual.review_step,actual.causal_depth,canonical_serialize(payload),
        canonical_serialize(actual.content),_source_input(frame,question.context_source_refs),
        _source_input(frame,question.support_source_refs)if question.support_source_refs else())
    installation=D07CognitionInstallationV1(installation_id,workflow.provider_id,workflow.model_id,
        workflow.provider_config_ref,workflow.provider_config_digest,workflow.max_output_tokens)
    return freeze_ordinary_continuity_cognition_request_v1(value,installation)

def thaw_current_ordinary_continuity_prepared_request_v1(prepared):
    from ..model_broker.ordinary_continuity_cognition_v1 import thaw_ordinary_continuity_cognition_request_v1
    from .domain_background_read_v3 import background_json_loads_v3
    if type(prepared)is not D07OrdinaryContinuityPreparedV1:
        raise TypeError("actual exact ordinary continuity preparation required")
    return thaw_ordinary_continuity_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))

def parse_current_ordinary_continuity_output_v1(prepared,text,frozen):
    from ..model_broker.ordinary_continuity_cognition_v1 import parse_ordinary_continuity_cognition_output_v1
    if(type(prepared)is not D07OrdinaryContinuityPreparedV1 or frozen.input.phase!=prepared.phase
            or frozen.input.question_original.original_digest!=prepared.semantic_question_digest
            or frozen.input.causal_parent_executions!=prepared.causal_parent_executions
            or(frozen.input.review_step,frozen.input.causal_depth)!=(prepared.review_step,prepared.causal_depth)):
        raise ValueError("ordinary continuity result left its exact actual prepared phase")
    return parse_ordinary_continuity_cognition_output_v1(text,frozen)

def require_current_ordinary_continuity_prepared_v1(db,*,issuer,prepared,installed_bundle,now,frozen=None):
    from .d07_ordinary_continuity_attention_v1 import read_ordinary_continuity_attention_original_v1
    from .d07_execution_v1 import read_current_d07_semantic_question_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(prepared)is not D07OrdinaryContinuityPreparedV1:
        raise TypeError("actual ordinary continuity prepared original required")
    workflow=configured_ordinary_continuity_workflow_v1(installed_bundle,prepared.phase)
    attention=read_ordinary_continuity_attention_original_v1(db,namespace=prepared.namespace,
        original_ref=prepared.continuity_attention_ref,issuer=issuer)
    question=read_current_d07_semantic_question_v1(db,issuer,prepared.namespace,prepared.semantic_question_ref)
    if(attention is None or attention[1]!=prepared.continuity_attention_digest
            or type(question)is not D07OrdinaryContinuityQuestionV1
            or canonical_digest(plain_v1(question))!=prepared.semantic_question_digest
            or question.basis_original!=prepared.basis_original or question.phase!=prepared.phase
            or question.trigger_assessment_original!=prepared.trigger_assessment_original
            or question.causal_parent_executions!=prepared.causal_parent_executions
            or(question.review_step,question.causal_depth)!=(prepared.review_step,prepared.causal_depth)
            or question.source_refs!=(*prepared.context_source_refs,*prepared.support_source_refs)
            or prepared.assessment_policy_ref!=question.basis.policy_original.original_ref
            or prepared.assessment_growth_request!=question.assessment_growth_request
            or prepared.original_parent_budget_lease_ref!=question.original_parent_budget_lease_ref
            or prepared.original_parent_grant_digest!=question.original_parent_grant_digest
            or prepared.original_deadline_utc>question.original_deadline_utc or now>=prepared.original_deadline_utc):
        raise ValueError("ordinary continuity lost its actual signed phase, sources, budget or deadline")
    frozen=thaw_current_ordinary_continuity_prepared_request_v1(prepared)if frozen is None else frozen
    if(any(getattr(frozen.installation,name)!=getattr(workflow,name)for name in
            ("provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
        raise ValueError("ordinary continuity changed its explicit installed model configuration")
    return question,attention,frozen


def prepare_ordinary_continuity_execution_in_transaction_v1(db,*,frame,stage,workflow,installation_id,
        d11_issuer,resource_issuer,body_authority,clock_mapping,body_policy_id,body_policy_version):
    from .d07_ordinary_continuity_attention_v1 import (D07OrdinaryContinuityQuestionV1,
        ordinary_continuity_attention_ids_v1,read_ordinary_continuity_attention_original_v1)
    from .d07_execution_v1 import (d07_execution_ids_v1,_prepare_d07_resources_in_transaction_v1,
        _clock_original,record_d07_original_in_transaction_v1,_json,D07_ACCOUNTING_FIELDS)
    from .budget import get_budget_lease,require_budget_family_admissible
    from .jobs import create_job
    from ..model_broker.ordinary_continuity_cognition_v1 import WORK_KIND,PURPOSE
    from dataclasses import fields,asdict,replace
    from ..domains.d01.production_operations_v1 import plain_v1
    from datetime import datetime
    import time
    from ..runtime_contracts import canonical_serialize
    from .d07_execution_v1 import D07PreparationStageV1
    question=stage.provenance["semantic_question"]
    if not db.in_transaction or type(question)is not D07OrdinaryContinuityQuestionV1:
        raise ValueError("Ordinary continuity preparation requires actual fixed W01/current semantic original")
    ns=frame.envelope.authority.namespace
    require_unique_ordinary_continuity_phase_preparation_v1(db,frame=frame,question=question,issuer=d11_issuer)
    attention_ref=question.continuity_attention_ref
    if attention_ref!=ordinary_continuity_attention_ids_v1(ns,question.question_key)["attention"]:
        raise ValueError("Ordinary continuity admission differs from its actual outcome/block/scope identity")
    attention=read_ordinary_continuity_attention_original_v1(db,namespace=ns,original_ref=attention_ref,issuer=d11_issuer)
    if attention is None:
        raise ValueError("Ordinary continuity preparation has no actual registered attention original")
    envelope=frame.envelope
    if envelope.authority.purpose!=PURPOSE or envelope.parent_budget_lease_ref!=question.original_parent_budget_lease_ref:
        raise ValueError("Ordinary continuity cannot replace its original parent purpose/root budget")
    lease=get_budget_lease(db,envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db,lease.lease_id)
    grant=d11_issuer.current_budget_grant(db,lease.lease_id)
    if (canonical_digest(grant)!=question.original_parent_grant_digest or WORK_KIND not in grant.allowed_work_kinds
            or (lease.bot_id,lease.persona_id)!=ns.as_tuple
            or any(value>grant.max_ceiling.get(name,0)for name,value in workflow.quote_ceiling.items())):
        raise ValueError("Ordinary continuity current original grant does not cover its installed cognition workflow")
    frozen=freeze_current_ordinary_continuity_stage_v1(frame,stage,workflow,installation_id)
    policy=body_authority.policy(db,ns,body_policy_id,body_policy_version)
    clock_digest=_clock_original(db,d11_issuer,ns,clock_mapping)
    ticket=next(ticket for ticket in stage.provenance["tickets"]if ticket.ticket_id==stage.provenance["choice"].ticket_id)
    deadline=min(envelope.deadline_utc,question.original_deadline_utc,grant.valid_until_utc,
        ticket.valid_until,policy.valid_until,
        datetime.fromisoformat(clock_mapping.valid_until_utc.replace("Z","+00:00")).timestamp())
    if deadline<=frame.now_utc or policy.work_kind!=WORK_KIND:
        raise ValueError("Ordinary continuity original budget/ticket/clock/body deadline is exhausted")
    envelope=replace(envelope,deadline_utc=deadline,
        monotonic_deadline=min(envelope.monotonic_deadline,time.monotonic()+deadline-frame.now_utc))
    frame=replace(frame,envelope=envelope)
    stage=replace(stage,envelope=envelope,proposal=replace(stage.proposal,envelope=envelope))
    ids=d07_execution_ids_v1(ns,envelope.identity.operation_id,"concern")
    original_ref="d07-prepared:"+envelope.identity.operation_id
    continuation={"request":_json(stage.request),"input_digest":stage.input_digest,
        "choice":_json(stage.provenance["choice"]),"original_ref":original_ref,"prepared_job_id":ids["job"],
        "quote_id":ids["quote"],"quote_version":1,"call_id":ids["call"],"work_kind":"concern",
        "ordinary_continuity_attention_ref":attention_ref,"ordinary_continuity_attention_digest":attention[1]}
    resources=_prepare_d07_resources_in_transaction_v1(db,frame=frame,ids=ids,work_kind="concern",frozen=frozen,
        stage_input_digest=stage.input_digest,job_continuation=continuation,original_ref=original_ref,workflow=workflow,
        lease=lease,resource_issuer=resource_issuer,body_authority=body_authority,clock_mapping=clock_mapping,
        clock_digest=clock_digest,policy=policy,body_policy_id=body_policy_id,body_policy_version=body_policy_version)
    job,quote,body=resources.job,resources.resource_quote,resources.body_reservation
    identity=envelope.identity
    base=D07PreparedExecutionV1(ns,identity.operation_id,identity.activity_id,identity.effect_id,identity.attempt_id,
        job.job_id,ids["call"],ids["execution"],"concern",stage.input_digest,canonical_serialize(plain_v1(frozen)),
        resources.content_read_rows,resources.query_inventory_json,canonical_serialize(()),envelope.authority.audience,
        envelope.authority.purpose,canonical_serialize(asdict(frame.owner_guard)),canonical_serialize(asdict(envelope.authority)),
        quote.quote_id,quote.version,canonical_digest(quote),resources.reservation_digest,body_policy_id,body_policy_version,
        body.body_quote.quote_id,body.body_quote_version,canonical_digest(body.body_quote),body.reservation_write.key.token,
        resources.body_state_ref,resources.body_profile_ref,resources.component_id,resources.clock_mapping_json,
        clock_digest,frame.activation_generation,frame.snapshot.epochs[0].revision,
        envelope.version_guard.access_epoch,envelope.version_guard.delete_epoch)
    values={field.name:getattr(base,field.name)for field in fields(base)if field.name!="schema"}
    actual=stage.provenance["ordinary_continuity_basis"]
    prepared=D07OrdinaryContinuityPreparedV1(**values,continuity_attention_ref=attention_ref,
        continuity_attention_digest=attention[1],semantic_question_ref=stage.request.trigger_original_ref,
        semantic_question_digest=attention[0].semantic_question_digest,phase=question.phase,
        basis_original=question.basis_original,trigger_assessment_original=question.trigger_assessment_original,
        original_parent_budget_lease_ref=question.original_parent_budget_lease_ref,
        original_parent_grant_digest=question.original_parent_grant_digest,original_deadline_utc=deadline,
        context_source_refs=question.context_source_refs,support_source_refs=question.support_source_refs,
        prior_c3_call_ids=actual.prior_c3_call_ids,assessment_policy_ref=actual.basis.policy_original.original_ref,
        assessment_growth_request=actual.growth_request,causal_parent_executions=actual.causal_parent_executions,
        review_step=actual.review_step,causal_depth=actual.causal_depth)
    updated_frame=resources.frame
    updated_stage=replace(stage,envelope=updated_frame.envelope,
        proposal=replace(stage.proposal,envelope=updated_frame.envelope,required_bundle_parts=("persistent_job",)),
        read_versions=resources.read_versions)
    record_d07_original_in_transaction_v1(db,d11_issuer,ns,"prepared",job.job_id,plain_v1(prepared))
    record_d07_original_in_transaction_v1(db,d11_issuer,ns,"accounting_prepared",job.job_id,
        {"schema":"d07.accounting-prepared.v1","prepared_digest":prepared.digest,
            **{name:_json(getattr(prepared,name))for name in D07_ACCOUNTING_FIELDS}})
    create_job(db,job,job.operation_id,resources.reservation_digest)
    return D07PreparationStageV1(updated_frame,updated_stage,prepared,job,resources.writes,resources.read_versions)

_CONCERN_METADATA=WeakKeyDictionary()

def _actual_ordinary_concern_reader_v1(reader,meter=None):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    if(type(reader)is not _MethodLearningReadV3 or reader.operation_kind!="serve_concern"
            or type(reader.request)is not ServeCurrentConcernRequestV1 or reader.request.category!="background"
            or reader.fence.scope.operation!="read"or reader.authority.namespace!=reader.namespace):
        raise ValueError("ordinary concern metadata requires its exact actual background Serve READ Work")
    reader.require_current(meter=meter)
    return reader

class _OrdinaryConcernMetadataTaskV1:
    def __init__(self,reader,identity):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        _actual_ordinary_concern_reader_v1(reader)
        if identity!=(reader.request.trigger_original_ref,):
            raise ValueError("ordinary concern metadata selector differs from its actual Serve request")
        self.reader,self.identity=reader,identity
        self.kind,self.ref="semantic_question",identity[0]
        self.phase="header";self.complete=False;self.result=None;self.header=None
        self.offset=0;self.total=None;self.fragment=b"";self.fragment_offset=0
        self.question=None;self.attention=None
        self.fields_seen=set();self.fair_tickets=();self.fair_heads=();self.fair_index=0;self.fair_task=None
        self.phase_prepared_originals=();self.prepared_after="";self.prepared_count=0
        self.parser=C09CanonicalJSONStreamV2()
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.census=(reader.operation,reader.work,reader.graph_stamp,reader.authority_epochs,reader.fence.scope,
            reader.request,reader.operation.selection_digest)
    def require_current_v1(self,meter=None):
        r=_actual_ordinary_concern_reader_v1(self.reader,meter)
        if self.census!=(r.operation,r.work,r.graph_stamp,r.authority_epochs,r.fence.scope,r.request,r.operation.selection_digest):
            raise ValueError("ordinary concern metadata left its actual selected Work or Graph snapshot")
        return r
    def _emit(self,event):
        if len(event.path)==1:self.fields_seen.add(event.path[0])
        if(self.kind not in("semantic_question","prepared")or not event.path
                and event.kind in("object_start","object_end","array_start","array_end")
                or ordinary_continuity_metadata_retains_path_v1(self.kind,event.path)):
            self.builder._emit(event)
    def _reset_v1(self):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.parser=C09CanonicalJSONStreamV2()
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=self.reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.offset=0;self.total=None;self.fragment=b"";self.fragment_offset=0;self.header=None;self.phase="header"
        self.fields_seen=set()
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from ..runtime_contracts import canonical_serialize
        from .d07_execution_v1 import SIGN_KIND
        r=self.require_current_v1(meter);ns=r.namespace
        if self.complete:return True
        if self.phase in("header","bytes"):
            header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",
                ("payload_digest","signature"),"bot=? AND persona=? AND kind=? AND original_ref=?",
                (*ns.as_tuple,self.kind,self.ref))
            if header is None:raise MissingProductionOriginalV1("actual_signed_ordinary_continuity_concern")
            if self.header is None:self.header=header
            elif self.header!=header:raise ValueError("ordinary concern signed metadata changed across EOF")
            self.phase="bytes"
            if self.fragment_offset<len(self.fragment):
                end=min(self.fragment_offset+1024,len(self.fragment))
                self.parser.feed(self.fragment[self.fragment_offset:end],self._emit)
                self.fragment_offset=end;return False
            with legacy_cell_read_transaction_v2(r.db):
                if self.total is None:
                    row=r.db.execute("SELECT length(CAST(payload_json AS BLOB)) FROM graph_d07_execution_originals_v1 "
                        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,self.kind,self.ref)).fetchone()
                    meter.charge_read(16)
                    self.total=row[0]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_d07_execution_originals_v1",
                        column="payload_json",where="bot=? AND persona=? AND kind=? AND original_ref=?",
                        parameters=(*ns.as_tuple,self.kind,self.ref),start=self.offset,
                        length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("ordinary concern metadata column changed")
                    self.offset+=len(chunk);self.fragment=chunk;self.fragment_offset=0;return False
            parsed=self.parser.finish()
            if(parsed.sha256,parsed.byte_count)!=(self.header[0],self.total)or self.builder.nodes:
                raise ValueError("ordinary concern signed metadata failed complete canonical EOF")
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((ns,self.kind,self.ref,self.header[0])),self.header[1])
            value=_detach_value_v3(self.builder.value)
            if self.kind=="semantic_question":
                if value.get("schema")!="d07.ordinary-continuity-question.v1":
                    raise ValueError("ordinary concern metadata requires its exact registered question profile")
                from .d07_ordinary_continuity_attention_v1 import ordinary_continuity_attention_ids_v1
                basis=_decode_metadata_original_v1(value["basis_original"])
                trigger=None if value["trigger_assessment_original"]is None else _decode_metadata_original_v1(value["trigger_assessment_original"])
                from ..domains.d01.ordinary_cumulative_growth_v1 import _ordinary_continuity_question_key_fields_v1
                key=_ordinary_continuity_question_key_fields_v1(basis,basis.original_digest,value["phase"],trigger)
                ids=ordinary_continuity_attention_ids_v1(ns,key)
                if(value["question_key"]!=key or ids["question"]!=self.ref
                        or value["continuity_attention_ref"]!=ids["attention"]
                        or tuple(value["source_refs"])!=tuple(dict.fromkeys((*value["basis"]["context_source_refs"],
                            *value["basis"]["support_source_refs"])))
                        or value["basis"]["namespace"]!={"bot_id":ns.bot_id,"persona_id":ns.persona_id}):
                    raise ValueError("ordinary concern metadata changed its basis, Source or deterministic question identity")
                self.question=(value,self.header[0])
                self.kind,self.ref="ordinary_continuity_attention_v1",ids["attention"];self._reset_v1();return False
            if self.kind=="prepared":
                from dataclasses import fields
                from .d07_stage_content_scope_v3 import _host_prepared_class_v3
                from .d07_execution_v1 import D07IngressRecallPreparedV1
                cls=(D07IngressRecallPreparedV1 if value["schema"]==D07IngressRecallPreparedV1.__dataclass_fields__["schema"].default
                    else _host_prepared_class_v3(value["schema"]))
                if self.fields_seen!={field.name for field in fields(cls)}:
                    raise ValueError("ordinary phase census found an unknown or incomplete signed Prepared schema")
                if cls is D07OrdinaryContinuityPreparedV1:
                    original=_decode_metadata_original_v1(value["basis_original"])
                    if(_same_original_v1(original,self.attention.basis_original)and value["phase"]==self.attention.phase):
                        if(value["semantic_question_ref"],value["semantic_question_digest"])!=(self.identity[0],self.question[1]):
                            raise ValueError("ordinary basis/phase was already prepared from another signed question")
                        self.phase_prepared_originals+=((value,self.ref,*self.header),)
                self.prepared_after=self.ref;self.prepared_count+=1;self.phase="prepared_census"
                self.fragment=b"";self.parser=self.builder=None
                return False
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .d07_ordinary_continuity_attention_v1 import D07OrdinaryContinuityAttentionOriginalV1
            attention=decode_typed_production_value_v1(value,D07OrdinaryContinuityAttentionOriginalV1)
            q,qdigest=self.question
            if(attention.namespace!=ns or attention.original_ref!=self.ref
                    or attention.semantic_question_ref!=self.identity[0]or attention.semantic_question_digest!=qdigest
                    or attention.phase!=q["phase"]or attention.basis_original!=_decode_metadata_original_v1(q["basis_original"])
                    or attention.context_source_refs!=tuple(q["basis"]["context_source_refs"])
                    or attention.support_source_refs!=tuple(q["basis"]["support_source_refs"])
                    or attention.original_parent_budget_lease_ref!=q["basis"]["original_parent_budget_lease_ref"]
                    or attention.original_parent_grant_digest!=q["basis"]["original_parent_grant_digest"]
                    or attention.causal_operation_id!=q["basis"]["causal_operation_id"]
                    or attention.causal_receipt_digest!=q["basis"]["causal_receipt_digest"]):
                raise ValueError("ordinary concern metadata has no exact actual signed question and attention pair")
            self.attention=attention;self.phase="ticket";return False
        attention=self.attention
        if self.phase=="ticket":
            head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(attention.ticket_ref.key.token,*ns.as_tuple))
            history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",(attention.ticket_ref.key.token,attention.ticket_ref.revision))
            if(head is None or head[:2]!=(attention.ticket_ref.revision,1)
                    or history!=(*ns.as_tuple,attention.registration_operation_id,1)):
                raise ValueError("ordinary concern actual signed ticket is no longer the current producing head")
            self.ticket_head=head;self.phase="producer";return False
        if self.phase=="producer":
            producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
                (*ns.as_tuple,attention.registration_operation_id))
            if producer is None or type(producer[3])is not int or producer[3]<1:
                raise ValueError("ordinary concern attention has no actual committed W01 producer")
            self.result=(self.question,attention,self.ticket_head,producer)
            self.fragment=b"";self.parser=self.builder=None
            self.fair_heads=tuple((AtomKey.from_token(token),head)for token,head in sorted(r.heads.items())
                if head[1]and AtomKey.from_token(token).type_name=="d07.attention_ticket.v1")
            if len(self.fair_heads)>128:
                raise MissingProductionOriginalV1("bounded_complete_ordinary_fair_ticket_census")
            self.phase="fair_tickets";return False
        if self.phase=="fair_tickets":
            if self.fair_index<len(self.fair_heads):
                if self.fair_task is None:self.fair_task=_OrdinaryFairTicketMetadataV1(r,*self.fair_heads[self.fair_index])
                if self.fair_task.advance(meter):
                    self.fair_tickets+=(self.fair_task.result,);self.fair_index+=1;self.fair_task=None
                return False
            own=next((atom for atom in self.fair_tickets if atom.key==attention.ticket_ref.key),None)
            if own is None or canonical_digest(own.value)!=attention.ticket_value_digest:
                raise ValueError("ordinary fair census lost the exact signed original ticket")
            self.phase="prepared_census";return False
        if self.phase=="prepared_census":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",
                ("original_ref",),"bot=? AND persona=? AND kind='prepared' AND original_ref>? ORDER BY original_ref",
                (*ns.as_tuple,self.prepared_after))
            if row is not None:
                if self.prepared_count>=128:
                    raise MissingProductionOriginalV1("bounded_complete_ordinary_phase_prepared_census")
                self.kind,self.ref="prepared",row[0];self._reset_v1();return False
            self.complete=True;_CONCERN_METADATA[r]=self
            return True
        raise ValueError("unregistered ordinary concern metadata phase")

def _decode_metadata_original_v1(value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(value,ProductionOriginalRefV1)

def create_ordinary_continuity_concern_metadata_task_v1(reader,identity):
    return _OrdinaryConcernMetadataTaskV1(reader,identity)

def prepare_ordinary_continuity_concern_metadata_v1(reader):
    _actual_ordinary_concern_reader_v1(reader)
    task=_CONCERN_METADATA.get(reader)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(reader,("ordinary_continuity_concern_metadata",(reader.request.trigger_original_ref,)))
    task.require_current_v1()
    return task

def require_actual_ordinary_continuity_concern_input_work_v1(reader):
    return prepare_ordinary_continuity_concern_metadata_v1(reader).require_current_v1()

_COGNITION_FACTS=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class _ActualOrdinaryContinuityCognitionV1:
    originals:tuple[ProductionOriginalRefV1,...]
    call_id:str
    decision:str
    source_refs:tuple[str,...]
    read_versions:tuple
    valid_until_utc:float
    causal_parent_executions:tuple
    prior_c3_call_ids:tuple[str,...]
    prepared:object
    question:object
    execution:object
    def require_v1(self,readers,read):
        state=_COGNITION_FACTS.get(self)
        if state is None or state[:3]!=(readers,read,read.frame.envelope.identity.operation_id):
            raise ValueError("ordinary continuity cognition left its actual adopted Source Work")
        read.check(state[3])
        return self

def require_actual_ordinary_continuity_cognition_v1(readers,db,read,*,phase,question_key,
        proposal_original,excluded_call_ids,interpretation_ref):
    from .d01_production_operations_v1 import CurrentDomainReadV1,InstalledD01ProductionReadersV1
    from .d01_ordinary_cumulative_growth_v1 import require_current_ordinary_continuity_basis_for_cognition_v1
    from .d07_execution_v1 import (read_d07_original_v1,read_prepared_d07_execution_v1,
        read_current_d07_semantic_question_v1)
    from .domain_background_read_v3 import background_json_loads_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..graph_types import GraphVersion
    from ..runtime_contracts import canonical_serialize
    if(type(readers)is not InstalledD01ProductionReadersV1 or type(read)is not CurrentDomainReadV1
            or phase not in("ordinary_screen","deep_review")or type(excluded_call_ids)is not tuple
            or any(type(v)is not str or not v for v in excluded_call_ids)
            or len(set(excluded_call_ids))!=len(excluded_call_ids)):
        raise TypeError("actual ordinary continuity requires its exact typed reader, phase and prior call identities")
    read.check(db)
    namespace=read.frame.envelope.authority.namespace
    metadata=read_ordinary_continuity_interpretation_metadata_v1(db,namespace=namespace,
        interpretation_ref=interpretation_ref,issuer=readers.issuer)
    metadata.require_v1(db,namespace,interpretation_ref)
    if metadata.phase!=phase or metadata.question_key!=question_key:
        raise ValueError("ordinary continuity adopted interpretation belongs to another exact question or phase")
    actual=require_current_ordinary_continuity_basis_for_cognition_v1(readers,db,read,
        basis_original=metadata.basis_original,phase=phase,
        trigger_assessment_original=metadata.trigger_assessment_original)
    if(not _same_original_v1(actual.basis.candidate_proposal_original,proposal_original)
            or actual.question_key!=question_key or not set(actual.prior_c3_call_ids)<=set(excluded_call_ids)):
        raise ValueError("ordinary continuity lost its actual candidate or complete excluded C3 ancestry")
    prepared=read_prepared_d07_execution_v1(db,readers.issuer,namespace,metadata.prepared_ref)
    if type(prepared)is not D07OrdinaryContinuityPreparedV1:
        raise TypeError("ordinary continuity assessment needs its actual independent prepared phase type")
    question=read_current_d07_semantic_question_v1(db,readers.issuer,namespace,prepared.semantic_question_ref)
    if(type(question)is not D07OrdinaryContinuityQuestionV1 or question.phase!=phase
            or question.question_key!=question_key or question.basis!=actual.basis
            or prepared.basis_original!=actual.basis_original or prepared.call_id in excluded_call_ids
            or prepared.causal_parent_executions!=actual.causal_parent_executions
            or(prepared.review_step,prepared.causal_depth)!=(actual.review_step,actual.causal_depth)):
        raise ValueError("ordinary continuity cannot reuse the proposal or another phase's C3 result")
    roots=tuple(dict.fromkeys((*question.context_source_refs,*question.support_source_refs)))
    read.source_family(db,roots,purpose="consolidation")
    frozen=thaw_current_ordinary_continuity_prepared_request_v1(prepared)
    if(frozen.input.content_json!=canonical_serialize(actual.content)
            or canonical_digest(plain_v1(question))!=prepared.semantic_question_digest):
        raise ValueError("ordinary continuity result did not inspect the actual complete current ordinary case")
    adopted=read_d07_original_v1(db,readers.issuer,namespace,"adopted",interpretation_ref)
    if adopted is None:raise MissingProductionOriginalV1("actual_ordinary_adopted_cognition")
    value=adopted[0];head=read.head(db,interpretation_ref,required=True)
    if(head.key.type_name!="d07.current_interpretation.v1"or not head.valid
            or head.revision!=value["interpretation_revision"]
            or canonical_digest(head.value)!=value["interpretation_value_digest"]
            or value["prepared_digest"]!=prepared.digest or value["question_scope"]!=question_key):
        raise ValueError("ordinary continuity adopted current interpretation changed its actual producer")
    _require_actual_ordinary_continuity_adoption_receipts_v1(db,actual=actual,
        prepared=prepared,interpretation=head,adopted=value)
    originals,execution=_paid_c3_originals_v1(readers,db,read,prepared,interpretation_ref)
    if(type(execution)is not D07OrdinaryContinuityExecutionOriginalV1 or execution.phase!=phase
            or execution.basis_original!=actual.basis_original
            or execution.causal_parent_executions!=actual.causal_parent_executions):
        raise ValueError("ordinary continuity execution is not its independent signed actual phase")
    result=read_d07_original_v1(db,readers.issuer,namespace,"result","d07-result:"+prepared.call_id)
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1,from_wire
    if value["actual_result_digest"]!=result[1]:
        raise ValueError("ordinary continuity adoption does not bind its exact actual provider result")
    parsed_result=from_wire(result[0],D07CognitionResultReadV1)
    text=background_json_loads_v3(parsed_result.observation.result_json)
    suggestion=parse_current_ordinary_continuity_output_v1(prepared,text["text"],frozen)
    if(len(suggestion.findings)!=1 or head.value["proposition"]!=suggestion.findings[0].proposition
            or head.value["question_key"]!=question_key
            or tuple(head.value["source_refs"])!=suggestion.findings[0].source_refs
            or tuple(head.value["meaningful_unknowns"])!=suggestion.unknowns):
        raise ValueError("ordinary continuity graph decision differs from the original actual model result")
    deadline=min(actual.valid_until_utc,prepared.original_deadline_utc)
    if read.frame.now_utc>=deadline:raise MissingProductionOriginalV1("actual_ordinary_cognition_original_deadline")
    terminal=next(v for v in originals if v.kind=="d07.execution")
    fact=_ActualOrdinaryContinuityCognitionV1(originals,prepared.call_id,suggestion.findings[0].proposition,
        roots,tuple(dict.fromkeys((*actual.current_read_versions,GraphVersion(head.key,head.revision)))),
        deadline,((terminal,execution.execution_id,execution.causal_depth),),
        (prepared.call_id,),prepared,question,execution)
    _COGNITION_FACTS[fact]=(readers,read,read.frame.envelope.identity.operation_id,db)
    return fact

def read_actual_ordinary_assessment_cause_v1(readers,db,read,*,assessment_original):
    from .d01_ordinary_cumulative_growth_v1 import ASSESSMENT_KIND
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryContinuityAssessmentV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    raw,actual=readers._read(db,read,assessment_original.original_ref,ASSESSMENT_KIND)
    if not _same_original_v1(actual,assessment_original):
        raise ValueError("ordinary deep review trigger differs from its actual signed assessment")
    assessment=decode_typed_production_value_v1(raw,OrdinaryContinuityAssessmentV1)
    if(assessment.decision!="deep_required"or assessment.reason!="core_shift"):
        raise ValueError("ordinary screen parent requires its actual committed core-shift assessment")
    interpretations=tuple(v for v in assessment.cognition_originals
        if v.kind=="d07.adopted")
    if len(interpretations)!=1:
        raise ValueError("ordinary core-shift assessment lacks its unique actual adopted screen cognition")
    metadata=read_ordinary_continuity_interpretation_metadata_v1(db,namespace=read.frame.envelope.authority.namespace,
        interpretation_ref=interpretations[0].original_ref,issuer=readers.issuer)
    from .d01_ordinary_cumulative_growth_v1 import require_current_ordinary_continuity_basis_for_cognition_v1
    basis=require_current_ordinary_continuity_basis_for_cognition_v1(readers,db,read,
        basis_original=metadata.basis_original,phase="ordinary_screen",trigger_assessment_original=None)
    fact=require_actual_ordinary_continuity_cognition_v1(readers,db,read,phase="ordinary_screen",
        question_key=basis.question_key,proposal_original=basis.basis.candidate_proposal_original,
        excluded_call_ids=basis.prior_c3_call_ids,interpretation_ref=interpretations[0].original_ref)
    if fact.decision!="core_shift":
        raise ValueError("ordinary deep review cannot relabel another screen model decision")
    return fact

def advance_ordinary_continuity_parent_metadata_v3(task,meter,*,side):
    """Verify the closed phase's real signed parents before Source Body."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if side=="authority":
        from ..authority_service.d07_authority_model_source_read_v3 import (
            _D07SpecialParentMetadataReadV3,_D07SignedParentMetadataReadV3,
            _D07AdoptedParentMetadataReadV3,_D07HistoryParentMetadataReadV3,_D07ParentBudgetMetadataReadV3)
        if type(task)is not _D07SpecialParentMetadataReadV3:raise TypeError("actual Authority ordinary parent task required")
        Signed,Adopted,History,Budget=(_D07SignedParentMetadataReadV3,_D07AdoptedParentMetadataReadV3,
            _D07HistoryParentMetadataReadV3,_D07ParentBudgetMetadataReadV3)
        bundle=task.reader.bundle
    elif side=="host":
        from .d07_stage_content_scope_v3 import (_HostSpecialParentMetadataReadV3,
            _HostSignedParentMetadataReadV3,_HostAdoptedParentMetadataReadV3,
            _HostHistoryParentMetadataReadV3,_HostParentBudgetMetadataReadV3)
        if type(task)is not _HostSpecialParentMetadataReadV3:raise TypeError("actual Host ordinary parent task required")
        Signed,Adopted,History,Budget=(_HostSignedParentMetadataReadV3,_HostAdoptedParentMetadataReadV3,
            _HostHistoryParentMetadataReadV3,_HostParentBudgetMetadataReadV3)
        bundle=task.reader.bundle
    else:raise ValueError("unregistered ordinary continuity parent side")
    from .d07_ordinary_continuity_attention_v1 import (D07OrdinaryContinuityAttentionOriginalV1,
        ordinary_continuity_attention_ids_v1)
    from ..domains.d01.ordinary_cumulative_growth_v1 import _ordinary_continuity_question_key_fields_v1
    from ..model_broker.ordinary_continuity_cognition_v1 import validate_ordinary_continuity_causal_fields_v1
    r,w,raw,header=task.reader,task.work,task.raw,task.header
    r.require_current_v3(meter);header.require_v3(r)
    stage=getattr(task,"ordinary_continuity_phase","question")
    if stage=="question":
        leaf=task._leaf_v3(("ordinary-continuity-question",header.job_id),Signed(r,family="d07",
            kind="semantic_question",ref=raw["semantic_question_ref"],expected_digest=raw["semantic_question_digest"],
            mode="ordinary_continuity_question"))
        if leaf is None:return
        q=leaf.value
        basis=_decode_metadata_original_v1(q["basis_original"])
        trigger=None if q["trigger_assessment_original"]is None else _decode_metadata_original_v1(q["trigger_assessment_original"])
        parents=tuple((_decode_metadata_original_v1(v[0]),v[1],v[2])for v in q["causal_parent_executions"])
        validate_ordinary_continuity_causal_fields_v1(q["phase"],basis,trigger,parents,q["review_step"],q["causal_depth"])
        key=_ordinary_continuity_question_key_fields_v1(basis,basis.original_digest,q["phase"],trigger)
        ids=ordinary_continuity_attention_ids_v1(w.namespace,key)
        roots=tuple(dict.fromkeys((*q["basis"]["context_source_refs"],*q["basis"]["support_source_refs"])))
        frozen=header.column.frozen_metadata.value["input"]
        matched=("phase","basis_original","trigger_assessment_original","causal_parent_executions","review_step","causal_depth",
            "assessment_growth_request")
        if(q["schema"]!="d07.ordinary-continuity-question.v1"or q["question_key"]!=key
                or raw["semantic_question_ref"]!=ids["question"]or raw["continuity_attention_ref"]!=ids["attention"]
                or q["continuity_attention_ref"]!=ids["attention"]or any(q[name]!=raw[name]for name in matched)
                or any(frozen[name]!=raw[name]for name in("phase","causal_parent_executions","review_step","causal_depth"))
                or frozen["question_original"]!={"kind":"d07.semantic_question","original_ref":raw["semantic_question_ref"],
                    "original_digest":raw["semantic_question_digest"],"read_versions":[]}
                or raw["assessment_policy_ref"]!=q["basis"]["policy_original"]["original_ref"]
                or tuple(q["source_refs"])!=roots
                or tuple(raw["context_source_refs"])!=tuple(q["basis"]["context_source_refs"])
                or tuple(raw["support_source_refs"])!=tuple(q["basis"]["support_source_refs"])
                or raw["original_parent_budget_lease_ref"]!=q["basis"]["original_parent_budget_lease_ref"]
                or raw["original_parent_grant_digest"]!=q["basis"]["original_parent_grant_digest"]
                or raw["original_deadline_utc"]>q["basis"]["original_deadline_utc"]
                or raw["purpose"]!="consolidation"or raw["work_kind"]!="concern"
                or task.source.purpose!="consolidation"
                or {item["source_ref"]["ref"]for name in("context_sources","support_sources")for item in frozen[name]}!=set(roots)
                or not set(roots)<={row["ref"]for row in header.source_rows}):
            raise ValueError("ordinary continuity metadata changed its exact issued phase, ancestry, Sources or original budget")
        task.ordinary_continuity_question=q;task.ordinary_continuity_parent_index=0
        task.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
        task.deadlines.extend((raw["original_deadline_utc"],q["basis"]["original_deadline_utc"]))
        task.ordinary_continuity_phase="attention";return
    if stage=="attention":
        leaf=task._leaf_v3(("ordinary-continuity-attention",header.job_id),Signed(r,family="d07",
            kind="ordinary_continuity_attention_v1",ref=raw["continuity_attention_ref"],
            expected_digest=raw["continuity_attention_digest"]))
        if leaf is None:return
        attention=decode_typed_production_value_v1(leaf.value,D07OrdinaryContinuityAttentionOriginalV1)
        if(attention.namespace!=w.namespace or attention.original_ref!=raw["continuity_attention_ref"]
                or(attention.semantic_question_ref,attention.semantic_question_digest)!=(raw["semantic_question_ref"],raw["semantic_question_digest"])
                or attention.phase!=raw["phase"]or attention.basis_original!=_decode_metadata_original_v1(raw["basis_original"])
                or tuple(raw["context_source_refs"])!=attention.context_source_refs
                or tuple(raw["support_source_refs"])!=attention.support_source_refs
                or raw["original_parent_budget_lease_ref"]!=attention.original_parent_budget_lease_ref
                or raw["original_parent_grant_digest"]!=attention.original_parent_grant_digest
                or raw["original_deadline_utc"]>attention.original_deadline_utc):
            raise ValueError("ordinary continuity actual attention lost its exact signed phase and question")
        task.ordinary_continuity_attention=attention
        task.originals.append(("d07.ordinary_continuity_attention_v1",attention.original_ref,leaf.metadata[0]))
        task.ordinary_continuity_phase="registration";return
    attention=task.ordinary_continuity_attention
    if stage=="registration":
        leaf=task._leaf_v3(("ordinary-continuity-registration",header.job_id),Adopted(r,attention.registration_operation_id))
        if leaf is None:return
        if(leaf.metadata[:2]!=("d07","register_ordinary_continuity_attention_v1")
                or canonical_digest(leaf.receipt)!=attention.registration_receipt_digest
                or attention.ticket_ref not in leaf.receipt.write_versions):
            raise ValueError("ordinary continuity attention lacks its exact real W01 registration")
        task.ordinary_continuity_phase="ticket";return
    if stage=="ticket":
        leaf=task._leaf_v3(("ordinary-continuity-ticket",header.job_id),History(r,
            attention.ticket_ref.key.token,attention.ticket_ref.revision,
            expected_operation=attention.registration_operation_id,expected_digest=attention.ticket_value_digest))
        if leaf is None:return
        q=task.ordinary_continuity_question
        if(leaf.value["ticket_id"]!=attention.ticket_ref.key.name or leaf.value["category"]!="background"
                or leaf.value["question_key"]!=q["question_key"]or leaf.value["source_refs"]!=q["source_refs"]):
            raise ValueError("ordinary continuity ticket is not its actual registered background review")
        task.ordinary_continuity_phase="parents";return
    if stage=="parents":
        parents=raw["causal_parent_executions"];index=task.ordinary_continuity_parent_index
        if index<len(parents):
            parent,execution_id,depth=parents[index]
            leaf=task._leaf_v3(("ordinary-continuity-cause",header.job_id,index),Signed(r,family="d07",
                kind="execution",ref=parent["original_ref"],expected_digest=parent["original_digest"]))
            if leaf is None:return
            if(leaf.value["execution_id"]!=execution_id or leaf.value["causal_depth"]!=depth
                    or leaf.value["status"]!="completed"or parent["kind"]!="d07.execution"
                    or leaf.value["terminal_ref"]!=parent["original_ref"]
                    or parent["original_ref"]=="d07-terminal:"+raw["call_id"]):
                raise ValueError("ordinary continuity direct C3 parent identity or signed depth differs")
            task.originals.append(("d07.execution",parent["original_ref"],parent["original_digest"]))
            task.ordinary_continuity_parent_index+=1;return
        task.ordinary_continuity_phase="budget";return
    if stage=="budget":
        leaf=task._leaf_v3(("ordinary-continuity-budget",header.job_id),Budget(r,raw["original_parent_budget_lease_ref"]))
        if leaf is None:return
        workflow=configured_ordinary_continuity_workflow_v1(bundle,raw["phase"])
        installed=header.column.frozen_metadata.value["installation"]
        if(canonical_digest(leaf.grant)!=raw["original_parent_grant_digest"]
                or "d07.cognition"not in leaf.grant.allowed_work_kinds
                or any(installed[name]!=getattr(workflow,name)for name in
                    ("provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
            raise ValueError("ordinary continuity changed its original parent grant or explicit installed phase workflow")
        task.deadlines.append(leaf.grant.valid_until_utc);task.phase="ordinary_job";return
    raise ValueError("unregistered ordinary continuity parent metadata phase")

def release_ordinary_continuity_concern_metadata_v1(reader):
    task=_CONCERN_METADATA.pop(reader,None)
    if task is not None:
        task.question=task.attention=task.result=task.parser=task.builder=task.fair_task=None
        task.fair_tickets=task.fair_heads=task.phase_prepared_originals=()
        task.fields_seen.clear();task.fragment=b""



class _OrdinaryFairTicketMetadataV1:
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
        r=_actual_ordinary_concern_reader_v1(self.reader,meter)
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

def read_bound_ordinary_continuity_concern_metadata_v1(db,*,namespace,request,issuer):
    from .current_method_learning_read_v3 import _method_active
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    r=_method_active(db)
    if(type(request)is not ServeCurrentConcernRequestV1
            or not request.trigger_original_ref.startswith("ordinary-continuity-question:")):return None
    if r is None or r.db is not db or r.namespace!=namespace or r.request!=request or issuer is not r.graph._GraphCoordinator__d11_issuer:
        raise ValueError("ordinary concern metadata requires its actual same-command Method Work")
    task=prepare_ordinary_continuity_concern_metadata_v1(r)
    task.require_current_v1()
    return task

def read_plan_bound_ordinary_continuity_concern_v1(db,*,namespace,activity_id,request,issuer):
    task=read_bound_ordinary_continuity_concern_metadata_v1(db,namespace=namespace,request=request,issuer=issuer)
    if task is None:return None
    from .d01_ordinary_cumulative_growth_v1 import read_plan_current_ordinary_continuity_basis_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d07.concern_round import concern_round_key
    from ..graph_types import Owner,owner_grant_key
    from ..domains.d12.types import active_scheme_head_key
    r=task.reader;q=task.question[0];attention=task.attention
    from .d07_ordinary_continuity_attention_v1 import ordinary_continuity_attention_ids_v1
    if activity_id!=r.activity_id or activity_id!=ordinary_continuity_attention_ids_v1(namespace,q["question_key"])["activity"]:
        raise ValueError("ordinary concern changed its actual deterministic phase activity")
    basis=read_plan_current_ordinary_continuity_basis_v1(db,namespace=namespace,basis_original=attention.basis_original)
    types=tuple(dict.fromkeys((*basis.fixed_type_ids,"d07.attention_ticket.v1","d07.focus.v1","d07.concern_round.v1",
        "d07.reflection_checkpoint.v1","d07.working_set.v1","d02.body_profile.v1","d02.body_state.v1","d02.reservation.v1")))
    keys=tuple(dict.fromkeys((*basis.exact_keys,owner_grant_key(*namespace.as_tuple),active_scheme_head_key(namespace),
        concern_round_key(namespace,"background"),attention.ticket_ref.key,
        AtomKey(Owner("activity",*namespace.as_tuple,activity_id),"d07.cognitive_activity.v1",activity_id))))
    roots=tuple(dict.fromkeys((*basis.source_roots,*(ref for atom in task.fair_tickets for ref in atom.value["source_refs"]))))
    originals=tuple(dict.fromkeys((*basis.required_original_refs,attention.semantic_question_ref,attention.original_ref,
        *(r.original_ref for r in(attention.trigger_assessment_original,)if r is not None))))
    return production_read_plan_v1(types,keys,roots,originals)

def require_unique_ordinary_continuity_phase_preparation_v1(db,*,frame,question,issuer):
    from .d07_execution_v1 import d07_execution_ids_v1
    r=_actual_ordinary_concern_reader_from_db_v1(db)
    task=read_bound_ordinary_continuity_concern_metadata_v1(db,namespace=frame.envelope.authority.namespace,
        request=r.request,issuer=issuer)
    if task is None or task.question[0]["question_key"]!=question.question_key:
        raise ValueError("ordinary preparation has no complete actual same-phase signed census")
    ids=d07_execution_ids_v1(r.namespace,frame.envelope.identity.operation_id,"concern")
    for raw,ref,digest,signature in task.phase_prepared_originals:
        if raw["operation_id"]!=frame.envelope.identity.operation_id:
            raise MissingProductionOriginalV1("ordinary_continuity_phase_already_prepared")
        if (ref,raw["job_id"],raw["call_id"],raw["execution_id"])!=(ids["job"],ids["job"],ids["call"],ids["execution"]):
            raise ValueError("ordinary phase census changed its actual deterministic native identity")
    return task

def _actual_ordinary_concern_reader_from_db_v1(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None:raise ValueError("ordinary preparation requires its actual live Method Work")
    return _actual_ordinary_concern_reader_v1(r)

def ordinary_continuity_adoption_read_plan_v1(prepared,versions):
    """Rebuild the closed adoption recipe from this Source-qualified prepared original."""
    from .d01_production_operations_v1 import production_read_plan_v1
    from .domain_background_read_v3 import background_json_loads_v3
    if type(prepared)is not D07OrdinaryContinuityPreparedV1:
        raise TypeError("ordinary adoption needs its exact registered preparation")
    queries=background_json_loads_v3(prepared.query_inventory_json)
    return production_read_plan_v1(tuple(page["type_id"]for page in queries),
        tuple(version.key for version in versions),
        (*prepared.context_source_refs,*prepared.support_source_refs),(prepared.semantic_question_ref,))

ORDINARY_CONTINUITY_ADOPTION_KIND_V1="ordinary_continuity_adoption_v1"
ORDINARY_CONTINUITY_ADOPTION_EVENT_V1="ordinary_continuity_cognition_adopted_v1"
_ORDINARY_COMPLETIONS=WeakKeyDictionary()
_ORDINARY_ADOPTION_CAUSES=WeakKeyDictionary()

def ordinary_continuity_adoption_original_ref_v1(namespace,job_id):
    if type(job_id)is not str or not job_id.startswith("d07-job:"):
        raise ValueError("ordinary completion requires its actual prepared job identity")
    return "ordinary-continuity-adoption:"+canonical_digest((namespace,job_id))[:48]

@dataclass(frozen=True,slots=True)
class D07OrdinaryContinuityAdoptionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    operation_id:str
    job_id:str
    call_id:str
    phase:str
    basis_original:ProductionOriginalRefV1
    proposal_original:ProductionOriginalRefV1
    question_original:ProductionOriginalRefV1
    prepared_original:ProductionOriginalRefV1
    adopted_original:ProductionOriginalRefV1
    trigger_assessment_original:ProductionOriginalRefV1|None
    interpretation_version:GraphVersion
    interpretation_value_digest:str
    graph_receipt_digest:str
    commit_receipt_digest:str
    domain_original_digest:str
    assessment_policy_ref:str
    assessment_growth_request:AdoptCurrentGeneralGrowthRequestV1
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    schema:str="d07.ordinary-continuity-adoption.v1"

    def __post_init__(self):
        from .d07_execution_v1 import d07_execution_ids_v1
        from ..domains.d01.identity_v3 import _digest
        ids=d07_execution_ids_v1(self.namespace,self.operation_id,"concern")
        if(self.schema!="d07.ordinary-continuity-adoption.v1"
                or self.phase not in {"ordinary_screen","deep_review"}
                or(self.job_id,self.call_id)!=(ids["job"],ids["call"])
                or self.original_ref!=ordinary_continuity_adoption_original_ref_v1(self.namespace,self.job_id)
                or type(self.assessment_growth_request)is not AdoptCurrentGeneralGrowthRequestV1
                or type(self.interpretation_version)is not GraphVersion or self.interpretation_version.revision<1
                or self.interpretation_version.key.type_name!="d07.current_interpretation.v1"
                or NamespaceId.from_key(self.interpretation_version.key)!=self.namespace):
            raise ValueError("ordinary completion lost its exact actual phase, call or adopted interpretation")
        for original,kind in ((self.basis_original,"d01.ordinary_continuity_basis_v1"),
                (self.proposal_original,"d01.growth_proposal"),(self.question_original,"d07.semantic_question"),
                (self.prepared_original,"d07.prepared"),(self.adopted_original,"d07.adopted")):
            if type(original)is not ProductionOriginalRefV1 or original.kind!=kind:
                raise ValueError("ordinary completion has another actual native original kind")
        if(self.prepared_original.original_ref!=self.job_id
                or self.adopted_original.original_ref!=self.interpretation_version.key.token):
            raise ValueError("ordinary completion changed its native prepared/adopted references")
        if self.phase=="ordinary_screen"and self.trigger_assessment_original is not None:
            raise ValueError("screen completion cannot invent a prior deep trigger")
        if self.phase=="deep_review"and(type(self.trigger_assessment_original)is not ProductionOriginalRefV1
                or self.trigger_assessment_original.kind!="d01.ordinary_continuity_assessment_v1"):
            raise ValueError("deep completion has no actual assessment trigger")
        for value in(self.interpretation_value_digest,self.graph_receipt_digest,self.commit_receipt_digest,
                self.domain_original_digest,self.original_parent_grant_digest):_digest(value)
        if(not self.assessment_policy_ref or not self.original_parent_budget_lease_ref
                or type(self.original_deadline_utc)not in(int,float)
                or not __import__("math").isfinite(self.original_deadline_utc)):
            raise ValueError("ordinary completion lost its actual selectors or original lifetime")

def record_actual_ordinary_continuity_adoption_v1(db,*,issuer,prepared,execution,writes,receipt,commit_receipt,domain_original):
    from .d07_graph_stages_v1 import _D07AuthoredSuccessorV3
    from .domain_background_read_v3 import _active_v3
    from .d07_execution_v1 import read_d07_original_v1,record_d07_original_in_transaction_v1,read_current_d07_semantic_question_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime_contracts import CommitReceipt
    if type(prepared)is not D07OrdinaryContinuityPreparedV1:return None
    owner=_active_v3(db)
    proof=None if owner is None else getattr(owner,"d07_authored_successor",None)
    if(type(proof)is not _D07AuthoredSuccessorV3 or proof.db is not db or proof.prepared is not prepared
            or proof.receipt is not receipt or type(execution)is not D07OrdinaryContinuityExecutionOriginalV1
            or type(commit_receipt)is not CommitReceipt or commit_receipt.status!="committed"
            or commit_receipt.operation_id!=prepared.operation_id or type(domain_original)is not ProductionOriginalRefV1):
        raise ValueError("ordinary completion needs the actual same-transaction paid adoption successor")
    proof.require_current()
    selected=tuple(write for write in writes if write.key.type_name=="d07.current_interpretation.v1")
    if len(selected)!=1:raise ValueError("ordinary phase must adopt exactly one actual interpretation")
    write=selected[0];version=next(v for v in receipt.revisions if v.key==write.key)
    q=read_current_d07_semantic_question_v1(db,issuer,prepared.namespace,prepared.semantic_question_ref)
    adopted=read_d07_original_v1(db,issuer,prepared.namespace,"adopted",write.key.token)
    if(type(q)is not D07OrdinaryContinuityQuestionV1 or adopted is None
            or q.assessment_growth_request!=prepared.assessment_growth_request
            or q.basis.policy_original.original_ref!=prepared.assessment_policy_ref
            or q.basis_original!=prepared.basis_original or q.phase!=prepared.phase
            or adopted[0]["prepared_digest"]!=prepared.digest
            or adopted[0]["graph_receipt_digest"]!=canonical_digest(receipt)
            or adopted[0]["interpretation_revision"]!=version.revision
            or adopted[0]["interpretation_value_digest"]!=canonical_digest(write.value)
            or (execution.operation_id,execution.execution_id,execution.phase)!=(prepared.operation_id,prepared.execution_id,prepared.phase)
            or execution.basis_original!=prepared.basis_original):
        raise ValueError("ordinary completion differs from its actual signed question or adopted C3 interpretation")
    value=D07OrdinaryContinuityAdoptionOriginalV1(prepared.namespace,
        ordinary_continuity_adoption_original_ref_v1(prepared.namespace,prepared.job_id),
        prepared.operation_id,prepared.job_id,prepared.call_id,prepared.phase,prepared.basis_original,
        q.basis.candidate_proposal_original,
        ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,prepared.semantic_question_digest),
        ProductionOriginalRefV1("d07.prepared",prepared.job_id,prepared.digest),
        ProductionOriginalRefV1("d07.adopted",write.key.token,adopted[1],(version,)),
        prepared.trigger_assessment_original,version,canonical_digest(write.value),canonical_digest(receipt),
        canonical_digest(commit_receipt),domain_original.original_digest,prepared.assessment_policy_ref,
        prepared.assessment_growth_request,prepared.original_parent_budget_lease_ref,
        prepared.original_parent_grant_digest,prepared.original_deadline_utc)
    digest=record_d07_original_in_transaction_v1(db,issuer,prepared.namespace,
        ORDINARY_CONTINUITY_ADOPTION_KIND_V1,value.original_ref,plain_v1(value))
    dedupe="domain-event:"+canonical_digest((prepared.namespace,prepared.operation_id,"d01",
        ORDINARY_CONTINUITY_ADOPTION_EVENT_V1,value.original_ref))[:48]
    row=(*prepared.namespace.as_tuple,dedupe,prepared.operation_id,"d01",ORDINARY_CONTINUITY_ADOPTION_EVENT_V1,
        value.original_ref,digest,"pending",None,None)
    old=db.execute("SELECT * FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",row[:3]).fetchone()
    if old is not None and old!=row:raise ValueError("ordinary actual adoption event changed its durable identity")
    if old is None:db.execute("INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",row)
    return ProductionOriginalRefV1("d07."+ORDINARY_CONTINUITY_ADOPTION_KIND_V1,value.original_ref,digest,(version,))

@dataclass(frozen=True,eq=False)
class _ActualOrdinaryContinuityServiceCompletionV1:
    value:D07OrdinaryContinuityAdoptionOriginalV1
    original:ProductionOriginalRefV1
    receipt:object
    def require_current_v1(self,owner):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        if _ORDINARY_COMPLETIONS.get(self)!=(owner,owner.operation,owner.graph_stamp,owner.entry_column):
            raise ValueError("ordinary completion left its actual current Background Work")
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(owner.db)as meter:owner.require_data_current_v3(meter)
        return self

def _read_actual_ordinary_completion_v1(db,*,namespace,job_id,issuer):
    from .domain_background_read_v3 import (_active_v3,require_actual_background_attachment_owner_v3,
        background_point_v3,background_json_loads_v3,background_typed_original_digest_v3)
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import _receipt,TABLE,reconstruct_graph_bundle_commit_receipt_v1
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer:
        raise ValueError("ordinary completion metadata requires its actual namespace and installed issuer")
    row=read_d07_original_v1(db,issuer,namespace,ORDINARY_CONTINUITY_ADOPTION_KIND_V1,
        ordinary_continuity_adoption_original_ref_v1(namespace,job_id))
    if row is None:
        _COMPLETION_METADATA_SELECTIONS.pop(owner,None)
        return None
    value=decode_typed_production_value_v1(row[0],D07OrdinaryContinuityAdoptionOriginalV1)
    if value.job_id!=job_id or value.namespace!=namespace:
        raise ValueError("ordinary completion has another actual current native job")
    _COMPLETION_METADATA_SELECTIONS[owner]=(owner.operation,owner.graph_stamp,owner.entry_column,value,None)
    business=background_point_v3(db,table=TABLE,
        columns=("domain","operation_kind","original_digest","bundle_digest","receipt_json","receipt_digest"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,value.operation_id),legacy_reader=lambda:None)
    if business is None or business[:2]!=("d07","serve_concern")or business[2]!=value.domain_original_digest:
        raise ValueError("ordinary completion has no actual committed business domain original")
    receipt=_receipt(background_json_loads_v3(business[4]))
    if(receipt.status!="committed"or receipt.operation_id!=value.operation_id
            or background_typed_original_digest_v3(db,business[4],receipt)!=value.commit_receipt_digest):
        raise ValueError("ordinary completion selected another actual business receipt")
    _COMPLETION_METADATA_SELECTIONS[owner]=(owner.operation,owner.graph_stamp,owner.entry_column,value,receipt.activity_id)
    bundle=background_point_v3(db,table="graph_bundle_operations",columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,value.operation_id),legacy_reader=lambda:None)
    event=background_point_v3(db,table="graph_events",columns=("reads","revisions","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,receipt.activity_id,value.operation_id),
        legacy_reader=lambda:None)
    if(receipt.status!="committed"or receipt.operation_id!=value.operation_id
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or business[3]!=receipt.operation_digest
            or background_typed_original_digest_v3(db,business[4],receipt)!=business[5]
            or business[5]!=value.commit_receipt_digest or value.interpretation_version not in receipt.write_versions
            or event is None or reconstruct_graph_bundle_commit_receipt_v1(namespace,value.operation_id,(*bundle,business[4]),event)!=receipt):
        raise ValueError("ordinary completion lost its actual business bundle/receipt/event members")
    fact=_ActualOrdinaryContinuityServiceCompletionV1(value,
        ProductionOriginalRefV1("d07."+ORDINARY_CONTINUITY_ADOPTION_KIND_V1,value.original_ref,row[1],
            (value.interpretation_version,)),receipt)
    _ORDINARY_COMPLETIONS[fact]=(owner,owner.operation,owner.graph_stamp,owner.entry_column)
    return fact

def read_ordinary_continuity_service_completion_v1(db,*,namespace,job_id,issuer):
    from .domain_background_read_v3 import _active_v3
    from .d07_ordinary_continuity_attention_v1 import _ATTENTION_FOLLOWUP_CAUSES,ATTENTION_SERVICE_EVENT
    from .d07_execution_v1 import d07_execution_ids_v1
    owner=_active_v3(db);state=_ATTENTION_FOLLOWUP_CAUSES.get(owner)
    if state is None or owner.entry is None or owner.entry[2]!=ATTENTION_SERVICE_EVENT:
        raise ValueError("ordinary service completion requires its exact actual attention Background Work")
    original,task,operation,stamp=state
    if task is not owner.entry_column or operation is not owner.operation or stamp!=owner.graph_stamp:
        raise ValueError("ordinary service completion left its actual retained attention metadata")
    attention=original["ordinary_continuity_attention"]
    operation_id="ordinary-continuity-serve:"+attention.semantic_question_ref.removeprefix("ordinary-continuity-question:")
    from .d07_single_event_review_v1 import read_current_d07_attention_prepared_job_metadata_v1
    located=read_current_d07_attention_prepared_job_metadata_v1(db,namespace=namespace,issuer=issuer)
    if located is not None:
        located.require_current_v1(owner)
        if located.family!="ordinary_continuity"or located.phase!=attention.phase:
            raise ValueError("ordinary attention selected another actual prepared phase")
        operation_id=located.operation_id
    if job_id!=d07_execution_ids_v1(namespace,operation_id,"concern")["job"]:
        raise ValueError("ordinary attention completion selector changed its actual signed prepared continuation")
    fact=_read_actual_ordinary_completion_v1(db,namespace=namespace,job_id=job_id,issuer=issuer)
    if fact is not None:
        v=fact.value
        if(v.question_original.original_ref!=attention.semantic_question_ref or v.basis_original!=attention.basis_original
                or v.phase!=attention.phase or v.operation_id!=operation_id):
            raise ValueError("ordinary completed call differs from its actual attention/basis/phase")
        fact.require_current_v1(owner)
    return fact

def ordinary_continuity_adoption_cause_locator_path_v1(owner,column,path):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is not BackgroundReadWorkV3:return None
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    task=owner.entry_column
    if(task is None or task.column is not column or task.entry is None
            or task.entry[1:3]!=("d01",ORDINARY_CONTINUITY_ADOPTION_EVENT_V1)):return None
    if task.metadata[:2]!=("d07","serve_concern"):
        raise ValueError("ordinary cognition completion event has another actual domain producer")
    return not path or path[0]in {"schema","namespace","identity","authority","parent_budget","coverage","now_utc"}

def read_ordinary_continuity_adoption_followup_cause_v1(db,*,namespace,event_kind,causal_operation_id,original_ref,issuer):
    if event_kind!=ORDINARY_CONTINUITY_ADOPTION_EVENT_V1:return None
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    owner=_active_v3(db);require_actual_background_attachment_owner_v3(owner,db=db)
    if(owner.entry is None or owner.entry[:3]!=(causal_operation_id,"d01",event_kind)
            or owner.entry_column is None or not owner.entry_column.complete):
        raise ValueError("ordinary adopted cognition cause requires its actual outbox metadata Work")
    # The native ref contains no caller-controlled job: derive it from this real producer operation.
    from .d07_execution_v1 import d07_execution_ids_v1
    job_id=d07_execution_ids_v1(namespace,causal_operation_id,"concern")["job"]
    if original_ref!=ordinary_continuity_adoption_original_ref_v1(namespace,job_id):
        raise ValueError("ordinary adopted cognition outbox changed its exact native completion locator")
    fact=_read_actual_ordinary_completion_v1(db,namespace=namespace,job_id=job_id,issuer=issuer)
    if fact is None:raise ValueError("ordinary adopted cognition event has no actual signed native completion")
    fact.require_current_v1(owner)
    metadata,payload=owner.entry_metadata
    if(metadata[:2]!=("d07","serve_concern")or metadata[2]!=fact.value.domain_original_digest
            or payload["identity"]["operation_id"]!=causal_operation_id or payload["coverage"]!="complete"):
        raise ValueError("ordinary adopted cognition event changed its actual complete business producer")
    original={"domain":"d07","operation_kind":"serve_concern","original_digest":fact.original.original_digest,
        "domain_original_digest":fact.value.domain_original_digest,"receipt":fact.receipt,
        "read_versions":fact.receipt.read_versions,"payload":payload,"ordinary_continuity_adoption":fact.value}
    _ORDINARY_ADOPTION_CAUSES[owner]=(original,fact,owner.operation,owner.graph_stamp)
    return original

def ordinary_continuity_adoption_followup_plan_v1(db,*,namespace,event):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    owner=_active_v3(db)
    original=read_ordinary_continuity_adoption_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if original is None or event.trigger_original.original_digest!=original["original_digest"]:
        raise ValueError("ordinary final assessment plan changed its actual completed cognition")
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),())

def resolve_ordinary_continuity_adoption_followup_v1(db,*,frame,event,original):
    from .domain_background_read_v3 import _active_v3
    from .domain_production_followups_v1 import DomainFollowupCommandV1,DomainFollowupResolutionV1
    from .d01_ordinary_cumulative_growth_v1 import AssessOrdinaryContinuityRequestV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    owner=_active_v3(db);state=_ORDINARY_ADOPTION_CAUSES.get(owner)
    if state is None or state[0]is not original or state[2:]!=(owner.operation,owner.graph_stamp):
        raise ValueError("ordinary final assessment left its actual completed cognition metadata Work")
    state[1].require_current_v1(owner);CurrentDomainReadV1(frame).check(db)
    value=state[1].value
    if event.receiver_domain!="d01"or event.event_kind!=ORDINARY_CONTINUITY_ADOPTION_EVENT_V1:
        raise ValueError("ordinary final assessment has another actual receiver event")
    if frame.now_utc>=value.original_deadline_utc:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),("ordinary_original_parent_deadline_exhausted",))
    request=AssessOrdinaryContinuityRequestV1(value.assessment_policy_ref,value.assessment_growth_request,
        value.phase,value.interpretation_version.key.token)
    activity="ordinary-continuity-assess:"+canonical_digest((value.basis_original,value.phase,value.original_ref))[:48]
    command=DomainFollowupCommandV1("d01","assess_ordinary_continuity_v1",request,activity,
        frame.envelope.authority.audience[0],frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready",(command,),(),())

def ordinary_continuity_adoption_parent_from_prepared_v1(prepared,event,command):
    prepared.require_v3(prepared.graph);owner=prepared.owner
    state=_ORDINARY_ADOPTION_CAUSES.get(owner)
    if state is None:return None
    original,fact,operation,stamp=state;fact.require_current_v1(owner)
    if operation is not owner.operation or stamp!=owner.graph_stamp or event.event_kind!=ORDINARY_CONTINUITY_ADOPTION_EVENT_V1:
        raise ValueError("ordinary assessment parent left its actual retained completed cognition Work")
    if command is not None and command not in prepared.local_result[5].commands:
        raise ValueError("ordinary assessment parent has another actual selected child")
    return fact.value

def release_ordinary_continuity_adoption_followup_metadata_v1(owner):
    _ORDINARY_ADOPTION_CAUSES.pop(owner,None)
    _COMPLETION_METADATA_SELECTIONS.pop(owner,None)
    for fact,state in tuple(_ORDINARY_COMPLETIONS.items()):
        if state[0]is owner:_ORDINARY_COMPLETIONS.pop(fact,None)

_COMPLETION_METADATA_SELECTIONS=WeakKeyDictionary()

def ordinary_continuity_completion_metadata_request_allowed_v1(owner,request):
    """Only the real attention continuation or real adopted event selects these controls."""
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    from .d07_ordinary_continuity_attention_v1 import _ATTENTION_FOLLOWUP_CAUSES,ATTENTION_SERVICE_EVENT
    from .d07_execution_v1 import d07_execution_ids_v1,TABLE
    if type(owner)is not BackgroundReadWorkV3:return False
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    entry=owner.entry;task=owner.entry_column
    if entry is None or task is None or not task.complete:return False
    if entry[1:3]==("d07",ATTENTION_SERVICE_EVENT):
        state=_ATTENTION_FOLLOWUP_CAUSES.get(owner)
        if state is None or state[1:]!=(task,owner.operation,owner.graph_stamp):return False
        attention=state[0]["ordinary_continuity_attention"]
        operation_id="ordinary-continuity-serve:"+attention.semantic_question_ref.removeprefix("ordinary-continuity-question:")
        from .d07_single_event_review_v1 import _ATTENTION_PREPARED_CENSUS_V1
        census=_ATTENTION_PREPARED_CENSUS_V1.get(owner)
        located=None if census is None or not census.complete else census.result
        if located is not None:
            located.require_current_v1(owner)
            if located.family!="ordinary_continuity"or located.phase!=attention.phase:
                raise ValueError("ordinary completion metadata selected another actual prepared phase")
            operation_id=located.operation_id
    elif entry[1:3]==("d01",ORDINARY_CONTINUITY_ADOPTION_EVENT_V1):
        if task.metadata[:2]!=("d07","serve_concern"):return False
        operation_id=entry[0]
    else:return False
    job_id=d07_execution_ids_v1(owner.namespace,operation_id,"concern")["job"]
    native=(TABLE,("payload_json","payload_digest","signature"),("bot","persona","kind","original_ref"),
        (*owner.namespace.as_tuple,ORDINARY_CONTINUITY_ADOPTION_KIND_V1,
            ordinary_continuity_adoption_original_ref_v1(owner.namespace,job_id)))
    if request==native:return True
    state=_COMPLETION_METADATA_SELECTIONS.get(owner)
    if state is None or state[:3]!=(owner.operation,owner.graph_stamp,task):return False
    value,activity=state[3:]
    if value.job_id!=job_id or value.operation_id!=operation_id:return False
    domain=("graph_domain_production_originals_v1",
        ("domain","operation_kind","original_digest","bundle_digest","receipt_json","receipt_digest"),
        ("bot","persona","operation_id"),(*owner.namespace.as_tuple,operation_id))
    if request==domain:return True
    if activity is None:return False
    bundle=("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
        ("bot","persona","operation_id"),(*owner.namespace.as_tuple,operation_id))
    event=("graph_events",("reads","revisions","epoch_revision"),("bot","persona","session","event_id"),
        (*owner.namespace.as_tuple,activity,operation_id))
    return request in(bundle,event)

def ordinary_continuity_completion_metadata_retains_path_v1(path):
    return not path or path[0]in {field.name for field in fields(D07OrdinaryContinuityAdoptionOriginalV1)}


_ORDINARY_ADOPTION_RECEIPTS_V1=WeakKeyDictionary()

def _ordinary_adoption_receipt_owner_v1(reader):
    from .d01_ordinary_cumulative_growth_v1 import AssessOrdinaryContinuityRequestV1,_owner_v1
    from .current_method_learning_read_v3 import (
        _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3,
        _require_current_general_method_source_write_phase_v1)
    if(type(reader)is not _MethodLearningReadV3 or reader.operation_kind!="assess_ordinary_continuity_v1"
            or type(reader.request)is not AssessOrdinaryContinuityRequestV1 or reader.request.interpretation_ref is None):
        raise ValueError("ordinary adoption receipts require the exact actual D01 assessment command")
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    origin=_owner_v1(reader.db,reader.namespace)
    if origin.reader is not reader:raise ValueError("ordinary adoption receipts have another actual metadata owner")
    if reader.read_finished:_require_current_general_method_source_write_phase_v1(reader)
    elif reader.general_owner_entry is None:
        raise ValueError("ordinary adoption receipts lack the completed actual Method metadata Owner")
    else:reader.general_owner_entry.require_for_v3(reader)
    return origin

class _OrdinaryContinuityAdoptionReceiptsV1:
    def __init__(self,reader,identity,metadata,adopted,prepared):
        origin=_ordinary_adoption_receipt_owner_v1(reader)
        if reader.read_finished or identity!=(reader.request.interpretation_ref,):
            raise ValueError("ordinary receipts must begin within their original assessment READ")
        self.reader,self.identity,self.origin=reader,identity,origin
        self.metadata,self.adopted,self.prepared=metadata,adopted,prepared
        self.binding=(reader.work,reader.operation,reader.graph_stamp,reader.fence.scope,reader.request)
        self.phase="receipt_business_header";self.complete=False;self.result=metadata.basis_original
        self.head=None;self.leaf=None;self.receipt_points={};self.receipt_header=None
        self.receipt_event_columns=();self.receipt_event_epoch=None;self.metadata_digest=None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.adopted,self.prepared,self.leaf,self.receipt_points,self.receipt_header,self.receipt_event_columns))
    def require_current_v1(self):
        r=self.reader
        if(_ordinary_adoption_receipt_owner_v1(r)is not self.origin
                or _ORDINARY_ADOPTION_RECEIPTS_V1.get(r)is not self
                or self.binding!=(r.work,r.operation,r.graph_stamp,r.fence.scope,r.request)
                or self.identity!=(r.request.interpretation_ref,)):
            raise ValueError("ordinary adoption receipts left their independent actual Basis assessment Work")
        self.metadata.require_v1(r.db,r.namespace,self.identity[0])
        if self.complete and self.metadata_digest!=canonical_digest((
                self.adopted,self.prepared,self.head,tuple(sorted(self.receipt_points.items())),self.result)):
            raise ValueError("ordinary receipt cache changed its complete canonical EOF commitments")
        return r
    def advance(self,meter):
        from .d07_single_event_review_v1 import _advance_single_event_review_receipt_controls_v1
        r=self.require_current_v1()
        if self.complete:return True
        if r.read_finished:raise ValueError("ordinary receipt metadata cannot first read in business WRITE")
        return _advance_single_event_review_receipt_controls_v1(self,meter)

def create_current_ordinary_continuity_adoption_receipts_task_v1(reader,identity):
    _ordinary_adoption_receipt_owner_v1(reader)
    task=_ORDINARY_ADOPTION_RECEIPTS_V1.get(reader)
    if task is None or task.identity!=identity:
        raise ValueError("ordinary receipt task has no actual signed selected assessment metadata")
    task.require_current_v1()
    return task

def prepare_current_ordinary_continuity_adoption_receipts_v1(reader):
    from .d01_ordinary_cumulative_growth_v1 import read_current_ordinary_d07_metadata_v1
    from .current_method_learning_read_v3 import MethodInputNeededV3
    _ordinary_adoption_receipt_owner_v1(reader)
    task=_ORDINARY_ADOPTION_RECEIPTS_V1.get(reader)
    if task is None:
        if reader.read_finished:raise MissingProductionOriginalV1("ordinary_presealed_adoption_receipts")
        ref=reader.request.interpretation_ref;db=reader.db;ns=reader.namespace
        issuer=reader.graph._GraphCoordinator__d11_issuer
        metadata=read_ordinary_continuity_interpretation_metadata_v1(db,namespace=ns,interpretation_ref=ref,issuer=issuer)
        adopted=read_current_ordinary_d07_metadata_v1(db,namespace=ns,issuer=issuer,kind="adopted",original_ref=ref)
        prepared=read_current_ordinary_d07_metadata_v1(db,namespace=ns,issuer=issuer,
            kind="prepared",original_ref=metadata.prepared_ref)
        if adopted is None or prepared is None:
            raise MissingProductionOriginalV1("ordinary_actual_signed_adoption_receipt_selectors")
        if(prepared[0]["schema"]!="d07.ordinary-continuity-prepared.v1"
                or prepared[1].original_digest!=adopted[0]["prepared_digest"]
                or prepared[0]["operation_id"]!=adopted[0]["adoption_operation_id"]):
            raise ValueError("ordinary adoption receipt selector changed its real C3 producer")
        task=_OrdinaryContinuityAdoptionReceiptsV1(reader,(ref,),metadata,adopted[0],prepared[0])
        _ORDINARY_ADOPTION_RECEIPTS_V1[reader]=task
    task.require_current_v1()
    if not task.complete:
        if reader.read_finished:raise MissingProductionOriginalV1("ordinary_complete_presealed_adoption_receipts")
        raise MethodInputNeededV3(("ordinary_continuity_adoption_receipts",task.identity))
    return task

def _require_actual_ordinary_continuity_adoption_receipts_v1(db,*,actual,prepared,interpretation,adopted):
    from .current_method_learning_read_v3 import _method_active
    from .d07_execution_v1 import verify_d07_adoption_receipt_metadata_v1
    actual.require_current_v1(committed=True)
    owner=_method_active(db)
    if owner is None:raise ValueError("ordinary receipt consumer has no actual assessment Work")
    task=prepare_current_ordinary_continuity_adoption_receipts_v1(owner)
    if(task.result!=actual.basis_original or task.identity!=(interpretation.key.token,)
            or task.adopted!={name:adopted[name]for name in task.adopted}
            or task.prepared["job_id"]!=prepared.job_id or task.adopted["prepared_digest"]!=prepared.digest):
        raise ValueError("ordinary receipts differ from the actual Source-qualified Basis and adopted C3")
    def point(table,columns,key_columns,key):
        request=(table,columns,key_columns,key)
        if request not in task.receipt_points:
            raise ValueError("ordinary receipt has no exact complete selected metadata point")
        return task.receipt_points[request]
    return verify_d07_adoption_receipt_metadata_v1(db,prepared=prepared,interpretation=interpretation,
        adopted=adopted,point=point)

def release_current_ordinary_continuity_adoption_receipts_v1(reader):
    task=_ORDINARY_ADOPTION_RECEIPTS_V1.pop(reader,None)
    if task is not None:
        task.leaf=None;task.receipt_points.clear();task.receipt_event_columns=()
        task.prepared=task.adopted=None;task.complete=False
