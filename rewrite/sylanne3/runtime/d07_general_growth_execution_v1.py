"""Actual General Life growth cognition; immutable context and support stay distinct."""
from __future__ import annotations
from dataclasses import dataclass,fields,asdict,replace
from datetime import datetime,timezone
import time
import math
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId
from .d07_execution_v1 import D07PreparedExecutionV1,D07PreparationStageV1

@dataclass(frozen=True,slots=True,kw_only=True)
class D07GeneralGrowthPreparedV1(D07PreparedExecutionV1):
    general_growth_attention_ref:str
    general_growth_attention_digest:str
    semantic_question_ref:str
    semantic_question_digest:str
    original_deadline_utc:float
    depth_basis:str
    stage_causal_depth:int
    outcome_original_ref:str
    outcome_original_digest:str
    outcome_trigger_ref:str
    outcome_trigger_digest:str
    causal_operation_id:str
    causal_receipt_digest:str
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]
    schema:str="d07.general-growth-prepared.v1"
    def __post_init__(self):
        from ..graph_types import AtomKey
        if self.schema!="d07.general-growth-prepared.v1" or self.work_kind!="concern" or self.purpose!="consolidation":
            raise ValueError("General growth requires its exact consolidation prepared schema")
        if self.depth_basis!="independent_outcome_stage.v1" or type(self.stage_causal_depth)is not int or self.stage_causal_depth!=0:
            raise ValueError("General growth requires its signed independent outcome-stage depth basis")
        for name in ("general_growth_attention_ref","semantic_question_ref","outcome_original_ref","outcome_trigger_ref","causal_operation_id"):
            if type(getattr(self,name))is not str or not getattr(self,name):raise ValueError("General growth original identity missing")
        for name in ("general_growth_attention_digest","semantic_question_digest","outcome_original_digest","outcome_trigger_digest","causal_receipt_digest"):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
                raise ValueError("General growth signed original commitment missing")
        if type(self.original_deadline_utc)not in (int,float)or not math.isfinite(self.original_deadline_utc):
            raise ValueError("General growth preserves its actual finite original deadline")
        if not self.context_source_refs or len(self.context_source_refs)+len(self.support_source_refs)>16:
            raise ValueError("General growth requires its bounded actual context/independent Source columns")
        all_refs=(*self.context_source_refs,*self.support_source_refs)
        if len(set(all_refs))!=len(all_refs):raise ValueError("General growth support and context must remain distinct")
        for ref in all_refs:
            key=AtomKey.from_token(ref)
            if key.type_name!="memory.source"or NamespaceId.from_key(key)!=self.namespace:
                raise ValueError("General growth Source columns cross exact namespace/type")
        from ..model_broker.general_growth_cognition_v1 import thaw_general_growth_cognition_request_v1
        from .domain_background_read_v3 import background_json_loads_v3
        frozen=thaw_general_growth_cognition_request_v1(background_json_loads_v3(self.frozen_json))
        if (frozen.input.namespace!=self.namespace or frozen.input.activity_id!=self.activity_id
                or tuple(s.source_ref.ref for s in frozen.input.context_sources)!=self.context_source_refs
                or tuple(s.source_ref.ref for s in frozen.input.support_sources)!=self.support_source_refs):
            raise ValueError("General growth prepared Source columns differ from the actual frozen input")


def freeze_current_general_growth_stage_v1(frame,stage,workflow,installation_id):
    from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
    from ..model_broker.general_growth_cognition_v1 import (GeneralGrowthCognitionInputV1,
        freeze_general_growth_cognition_request_v1,TEMPLATE_VERSION,PURPOSE,WORK_KIND)
    from ..model_broker.d07_cognition_v1 import D07CognitionInstallationV1
    from .d07_execution_v1 import _source_input,D07SemanticTargetOriginalV1
    from ..graph_types import AtomKey
    from .domain_background_read_v3 import background_json_loads_v3
    question=stage.provenance["semantic_question"]
    choice=stage.provenance["choice"]
    selected=tuple(ticket for ticket in stage.provenance["tickets"]if ticket.ticket_id==choice.ticket_id)
    target=stage.provenance["semantic_target"]
    if (type(question)is not D07GeneralGrowthQuestionV1 or stage.work_kind!="concern"or stage.status!="queued"
            or stage.envelope!=frame.envelope or len(selected)!=1
            or (workflow.template_version,workflow.purpose,workflow.work_kind)!=(TEMPLATE_VERSION,PURPOSE,WORK_KIND)
            or frame.envelope.authority.purpose!=PURPOSE
            or not set(frame.envelope.authority.audience)<=set(workflow.audiences)
            or tuple(selected[0].source_refs)!=question.source_refs or selected[0].question_key!=question.question_key
            or type(target)is not D07SemanticTargetOriginalV1 or target.kind!="graph_head"
            or (target.original_ref,target.revision)!=(question.target_ref.ref,question.target_ref.version)):
        raise ValueError("General growth freeze requires its actual fair ticket/named workflow/current target")
    raw=background_json_loads_v3(target.value_json)
    blocks=tuple(block for block in raw["blocks"]if block["block_id"]==question.target_block)
    if len(blocks)!=1 or blocks[0]["plasticity"]!="growth"or canonical_digest(blocks[0])!=question.target_digest:
        raise ValueError("General growth may only interpret the exact current ordinary plastic block")
    input=GeneralGrowthCognitionInputV1(frame.envelope.authority.namespace,frame.envelope.identity.activity_id,
        question.target_block,question.scope,question.target_ref,canonical_serialize(blocks[0]),question.target_digest,
        question.question,tuple(original.original_ref for original in question.context_original_refs),
        _source_input(frame,question.context_source_refs),
        _source_input(frame,question.support_source_refs)if question.support_source_refs else())
    installation=D07CognitionInstallationV1(installation_id,workflow.provider_id,workflow.model_id,
        workflow.provider_config_ref,workflow.provider_config_digest,workflow.max_output_tokens)
    return freeze_general_growth_cognition_request_v1(input,installation)


def prepare_general_growth_execution_in_transaction_v1(db,*,frame,stage,workflow,installation_id,
        d11_issuer,resource_issuer,body_authority,clock_mapping,body_policy_id,body_policy_version):
    from .d07_general_growth_attention_v1 import (D07GeneralGrowthQuestionV1,
        general_growth_attention_original_ref_v1,read_current_general_growth_attention_v1)
    from .d07_execution_v1 import (d07_execution_ids_v1,_prepare_d07_resources_in_transaction_v1,
        _clock_original,record_d07_original_in_transaction_v1,_json,D07_ACCOUNTING_FIELDS)
    from .budget import get_budget_lease,require_budget_family_admissible
    from .jobs import create_job
    from ..model_broker.general_growth_cognition_v1 import WORK_KIND,PURPOSE
    question=stage.provenance["semantic_question"]
    if not db.in_transaction or type(question)is not D07GeneralGrowthQuestionV1:
        raise ValueError("General growth preparation requires actual fixed W01/current semantic original")
    ns=frame.envelope.authority.namespace
    attention_ref=question.general_growth_attention_ref
    if attention_ref!=general_growth_attention_original_ref_v1(ns,question.outcome_original_digest,question.target_block,question.scope):
        raise ValueError("General growth admission differs from its actual outcome/block/scope identity")
    attention=read_current_general_growth_attention_v1(db,d11_issuer,ns,attention_ref)
    if attention is None:
        raise ValueError("General growth preparation has no actual registered attention original")
    envelope=frame.envelope
    if envelope.authority.purpose!=PURPOSE or envelope.parent_budget_lease_ref!=question.original_parent_budget_lease_ref:
        raise ValueError("General growth cannot replace its original parent purpose/root budget")
    lease=get_budget_lease(db,envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db,lease.lease_id)
    grant=d11_issuer.current_budget_grant(db,lease.lease_id)
    if (canonical_digest(grant)!=question.original_parent_grant_digest or WORK_KIND not in grant.allowed_work_kinds
            or (lease.bot_id,lease.persona_id)!=ns.as_tuple
            or any(value>grant.max_ceiling.get(name,0)for name,value in workflow.quote_ceiling.items())):
        raise ValueError("General growth current original grant does not cover its installed cognition workflow")
    frozen=freeze_current_general_growth_stage_v1(frame,stage,workflow,installation_id)
    policy=body_authority.policy(db,ns,body_policy_id,body_policy_version)
    clock_digest=_clock_original(db,d11_issuer,ns,clock_mapping)
    ticket=next(ticket for ticket in stage.provenance["tickets"]if ticket.ticket_id==stage.provenance["choice"].ticket_id)
    deadline=min(envelope.deadline_utc,question.original_deadline_utc,grant.valid_until_utc,
        ticket.valid_until,policy.valid_until,
        datetime.fromisoformat(clock_mapping.valid_until_utc.replace("Z","+00:00")).timestamp())
    if deadline<=frame.now_utc or policy.work_kind!=WORK_KIND:
        raise ValueError("General growth original budget/ticket/clock/body deadline is exhausted")
    envelope=replace(envelope,deadline_utc=deadline,
        monotonic_deadline=min(envelope.monotonic_deadline,time.monotonic()+deadline-frame.now_utc))
    frame=replace(frame,envelope=envelope)
    stage=replace(stage,envelope=envelope,proposal=replace(stage.proposal,envelope=envelope))
    ids=d07_execution_ids_v1(ns,envelope.identity.operation_id,"concern")
    original_ref="d07-prepared:"+envelope.identity.operation_id
    continuation={"request":_json(stage.request),"input_digest":stage.input_digest,
        "choice":_json(stage.provenance["choice"]),"original_ref":original_ref,"prepared_job_id":ids["job"],
        "quote_id":ids["quote"],"quote_version":1,"call_id":ids["call"],"work_kind":"concern",
        "general_growth_attention_ref":attention_ref,"general_growth_attention_digest":attention[1]}
    resources=_prepare_d07_resources_in_transaction_v1(db,frame=frame,ids=ids,work_kind="concern",frozen=frozen,
        stage_input_digest=stage.input_digest,job_continuation=continuation,original_ref=original_ref,workflow=workflow,
        lease=lease,resource_issuer=resource_issuer,body_authority=body_authority,clock_mapping=clock_mapping,
        clock_digest=clock_digest,policy=policy,body_policy_id=body_policy_id,body_policy_version=body_policy_version)
    job,quote,body=resources.job,resources.resource_quote,resources.body_reservation
    identity=envelope.identity
    base=D07PreparedExecutionV1(ns,identity.operation_id,identity.activity_id,identity.effect_id,identity.attempt_id,
        job.job_id,ids["call"],ids["execution"],"concern",stage.input_digest,canonical_serialize(asdict(frozen)),
        resources.content_read_rows,resources.query_inventory_json,canonical_serialize(()),envelope.authority.audience,
        envelope.authority.purpose,canonical_serialize(asdict(frame.owner_guard)),canonical_serialize(asdict(envelope.authority)),
        quote.quote_id,quote.version,canonical_digest(quote),resources.reservation_digest,body_policy_id,body_policy_version,
        body.body_quote.quote_id,body.body_quote_version,canonical_digest(body.body_quote),body.reservation_write.key.token,
        resources.body_state_ref,resources.body_profile_ref,resources.component_id,resources.clock_mapping_json,
        clock_digest,frame.activation_generation,frame.snapshot.epochs[0].revision,
        envelope.version_guard.access_epoch,envelope.version_guard.delete_epoch)
    values={field.name:getattr(base,field.name)for field in fields(base)if field.name!="schema"}
    prepared=D07GeneralGrowthPreparedV1(**values,general_growth_attention_ref=attention_ref,
        general_growth_attention_digest=attention[1],semantic_question_ref=stage.request.trigger_original_ref,
        semantic_question_digest=attention[0].semantic_question_digest,original_deadline_utc=deadline,
        context_source_refs=question.context_source_refs,support_source_refs=question.support_source_refs,
        depth_basis=question.depth_basis,stage_causal_depth=question.stage_causal_depth,
        outcome_original_ref=question.outcome_original_ref,outcome_original_digest=question.outcome_original_digest,
        causal_operation_id=question.causal_operation_id,causal_receipt_digest=question.causal_receipt_digest,
        outcome_trigger_ref=question.outcome_trigger_ref,outcome_trigger_digest=question.outcome_trigger_digest)
    updated_frame=resources.frame
    updated_stage=replace(stage,envelope=updated_frame.envelope,
        proposal=replace(stage.proposal,envelope=updated_frame.envelope,required_bundle_parts=("persistent_job",)),
        read_versions=resources.read_versions)
    record_d07_original_in_transaction_v1(db,d11_issuer,ns,"prepared",job.job_id,asdict(prepared))
    record_d07_original_in_transaction_v1(db,d11_issuer,ns,"accounting_prepared",job.job_id,
        {"schema":"d07.accounting-prepared.v1","prepared_digest":prepared.digest,
            **{name:_json(getattr(prepared,name))for name in D07_ACCOUNTING_FIELDS}})
    create_job(db,job,job.operation_id,resources.reservation_digest)
    return D07PreparationStageV1(updated_frame,updated_stage,prepared,job,resources.writes,resources.read_versions)


def require_current_general_growth_prepared_v1(db,*,issuer,prepared,installed_bundle,now,frozen=None):
    from .d07_general_growth_attention_v1 import read_current_general_growth_attention_v1,D07GeneralGrowthQuestionV1
    from .d07_execution_v1 import read_current_d07_semantic_question_v1
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    from ..host.authority_profile import AdminInstallationBundle
    from ..model_broker.general_growth_cognition_v1 import thaw_general_growth_cognition_request_v1,TEMPLATE_VERSION,PURPOSE
    from .domain_background_read_v3 import background_json_loads_v3
    if (type(prepared)is not D07GeneralGrowthPreparedV1 or type(installed_bundle)is not AdminInstallationBundle
            or type(installed_bundle.model_workflows) not in (AdminModelWorkflowsV8, AdminModelWorkflowsV9)):
        raise TypeError("General growth requires its exact current installed V8 prepared variant")
    from ..domains.d01.production_operations_v1 import plain_v1
    attention=read_current_general_growth_attention_v1(db,issuer,prepared.namespace,prepared.general_growth_attention_ref)
    question=read_current_d07_semantic_question_v1(db,issuer,prepared.namespace,prepared.semantic_question_ref)
    if (attention is None or attention[1]!=prepared.general_growth_attention_digest
            or type(question)is not D07GeneralGrowthQuestionV1
            or canonical_digest(plain_v1(question))!=prepared.semantic_question_digest
            or (question.depth_basis,question.stage_causal_depth,question.outcome_original_ref,question.outcome_original_digest,
                question.causal_operation_id,question.general_growth_attention_ref,question.outcome_trigger_ref,question.outcome_trigger_digest,
                question.causal_receipt_digest)!=(prepared.depth_basis,prepared.stage_causal_depth,
                prepared.outcome_original_ref,prepared.outcome_original_digest,prepared.causal_operation_id,prepared.general_growth_attention_ref,
                prepared.outcome_trigger_ref,prepared.outcome_trigger_digest,prepared.causal_receipt_digest)
            or question.context_source_refs!=prepared.context_source_refs or question.support_source_refs!=prepared.support_source_refs
            or prepared.original_deadline_utc>question.original_deadline_utc or now>=prepared.original_deadline_utc):
        raise ValueError("General growth lost its actual attention/question/source/original deadline binding")
    frozen=thaw_general_growth_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))if frozen is None else frozen
    workflow=installed_bundle.model_workflows.general_growth_cognition
    if workflow is None or (workflow.template_version,workflow.purpose)!=(TEMPLATE_VERSION,PURPOSE):
        raise ValueError("General growth current named workflow is absent or changed")
    if ((frozen.input.ordinary_block_id,frozen.input.scope,frozen.input.target_ref,frozen.input.target_original_digest)!=
            (question.target_block,question.scope,question.target_ref,question.target_digest)
            or any(getattr(frozen.installation,name)!=getattr(workflow,name)for name in(
                "provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
        raise ValueError("General growth frozen actual target/provider configuration changed")
    return question,attention,frozen


def thaw_current_general_growth_prepared_request_v1(prepared):
    from ..model_broker.general_growth_cognition_v1 import thaw_general_growth_cognition_request_v1
    from .domain_background_read_v3 import background_json_loads_v3
    if type(prepared)is not D07GeneralGrowthPreparedV1:
        raise TypeError("actual exact General growth prepared variant required")
    return thaw_general_growth_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))


def parse_current_general_growth_output_v1(prepared,text,frozen):
    from ..model_broker.general_growth_cognition_v1 import parse_general_growth_cognition_output_v1
    if type(prepared)is not D07GeneralGrowthPreparedV1:
        raise TypeError("General output requires its exact signed prepared variant")
    if (prepared.depth_basis!="independent_outcome_stage.v1" or prepared.stage_causal_depth!=0
            or tuple(source.source_ref.ref for source in frozen.input.context_sources)!=prepared.context_source_refs
            or tuple(source.source_ref.ref for source in frozen.input.support_sources)!=prepared.support_source_refs):
        raise ValueError("General output no longer matches its explicit signed depth/Source columns")
    return parse_general_growth_cognition_output_v1(text,frozen)


def general_growth_frozen_sources_v1(frozen):
    from ..model_broker.general_growth_cognition_v1 import FrozenGeneralGrowthCognitionRequestV1
    if type(frozen)is not FrozenGeneralGrowthCognitionRequestV1:
        raise TypeError("actual exact General frozen cognition request required")
    return (*frozen.input.context_sources,*frozen.input.support_sources)
