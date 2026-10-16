"""Separate ordinary growth trial originals, with no Identity/Method alias."""
from __future__ import annotations
from dataclasses import dataclass
import math
from ..runtime_contracts import NamespaceId,canonical_digest
from ..graph_types import GraphVersion
from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionOwnerGuardV1

@dataclass(frozen=True,slots=True)
class GeneralGrowthTrialStartV1:
    namespace:NamespaceId
    start_ref:str
    producing_operation_id:str
    producing_receipt_digest:str
    proposal_ref:str
    proposal_digest:str
    base_persona_head:str
    base_persona_version:GraphVersion
    target_block:str
    completed_trial_ref:str
    planned_head:GraphVersion
    planned_digest:str
    plan_adoption_operation_id:str
    plan_adoption_receipt_digest:str
    action_id:str
    activity_id:str
    effect_id:str
    attempt_id:str
    project_ref:str|None
    recipe_ref:str|None
    step_id:str|None
    planned_life_plan_original:ProductionOriginalRefV1|None
    clock_mapping_ref:str
    clock_mapping_version:int
    clock_original_digest:str
    started_at_utc:float
    started_role_cursor:str
    observation_role_deadline:str
    observation_deadline_utc:float
    parent_budget_lease_ref:str
    original_grant_digest:str
    ancestor_operations:tuple[tuple[str,float],...]
    source_originals:tuple[ProductionOriginalRefV1,...]
    source_versions:tuple[GraphVersion,...]
    owner_guard:ProductionOwnerGuardV1
    cancel_refs:tuple[str,...]
    schema:str="d01.general-growth-trial-start.v1"
    def __post_init__(self):
        from decimal import Decimal
        from ..graph_types import AtomKey
        if (self.schema!="d01.general-growth-trial-start.v1"or type(self.namespace)is not NamespaceId
                or type(self.base_persona_version)is not GraphVersion or type(self.planned_head)is not GraphVersion
                or type(self.owner_guard)is not ProductionOwnerGuardV1):
            raise ValueError("General trial start requires its separate exact original schema")
        for version in (self.base_persona_version,self.planned_head,*self.source_versions):
            if type(version)is not GraphVersion or NamespaceId.from_key(version.key)!=self.namespace or version.revision<1:
                raise ValueError("General trial start original head crosses namespace/positive revision")
        for name in ("start_ref","producing_operation_id","proposal_ref","base_persona_head","target_block",
                "completed_trial_ref","plan_adoption_operation_id","action_id","activity_id","effect_id","attempt_id",
                "clock_mapping_ref","parent_budget_lease_ref"):
            if type(getattr(self,name))is not str or not getattr(self,name):raise ValueError("General trial original identity missing")
        for name in ("producing_receipt_digest","proposal_digest","planned_digest","plan_adoption_receipt_digest",
                "clock_original_digest","original_grant_digest"):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
                raise ValueError("General trial immutable original commitment missing")
        if type(self.clock_mapping_version)is not int or self.clock_mapping_version<1:
            raise ValueError("General trial requires its actual positive clock mapping version")
        group=(self.project_ref,self.recipe_ref,self.step_id,self.planned_life_plan_original)
        if any(value is None for value in group)and not all(value is None for value in group):
            raise ValueError("General D10 trial requires the whole exact project/recipe/step group")
        if all(value is None for value in group):
            if self.planned_head.key.type_name!="d08.action_intent.v1":
                raise ValueError("General D08 trial must bind its exact planned action head")
        else:
            if (any(type(value)is not str or not value for value in group[:3])
                    or type(self.planned_life_plan_original)is not ProductionOriginalRefV1):
                raise ValueError("General D10 trial requires actual signed plan and exact project/recipe/step")
        if (any(type(value)not in (int,float)or not math.isfinite(value)for value in(
                    self.started_at_utc,self.observation_deadline_utc))
                or self.observation_deadline_utc<=self.started_at_utc
                or not Decimal(self.started_role_cursor)<Decimal(self.observation_role_deadline)):
            raise ValueError("General trial start preserves a finite forward original UTC/role window")
        if (type(self.ancestor_operations)is not tuple or not self.ancestor_operations
                or len(self.ancestor_operations)>32
                or any(type(op)is not str or not op or type(deadline)not in (int,float)or not math.isfinite(deadline)
                    or self.observation_deadline_utc>deadline for op,deadline in self.ancestor_operations)):
            raise ValueError("General trial window cannot extend any actual signed ancestor deadline")
        if (not self.source_originals or not self.source_versions or len(self.source_originals)>32
                or any(type(item)is not ProductionOriginalRefV1 for item in self.source_originals)):
            raise ValueError("General trial preserves its actual source-original and current Source closure")


@dataclass(frozen=True,slots=True)
class GeneralGrowthTrialAdmissionV1:
    namespace:NamespaceId
    start_ref:str
    producing_operation_id:str
    proposal_ref:str
    proposal_digest:str
    base_persona_head:str
    base_persona_version:GraphVersion
    target_block:str
    completed_trial_ref:str
    planned_head:GraphVersion
    planned_digest:str
    plan_adoption_operation_id:str
    plan_adoption_receipt_digest:str
    action_id:str
    activity_id:str
    effect_id:str
    attempt_id:str
    project_ref:str|None
    recipe_ref:str|None
    step_id:str|None
    planned_life_plan_original:ProductionOriginalRefV1|None
    clock_mapping_ref:str
    clock_mapping_version:int
    clock_original_digest:str
    started_at_utc:float
    started_role_cursor:str
    observation_role_deadline:str
    observation_deadline_utc:float
    parent_budget_lease_ref:str
    original_grant_digest:str
    ancestor_operations:tuple[tuple[str,float],...]
    source_originals:tuple[ProductionOriginalRefV1,...]
    source_versions:tuple[GraphVersion,...]
    owner_guard:ProductionOwnerGuardV1
    cancel_refs:tuple[str,...]
    schema:str="d01.general-growth-trial-admission.v1"
    def __post_init__(self):
        from decimal import Decimal
        from ..graph_types import AtomKey
        if (self.schema!="d01.general-growth-trial-admission.v1"or type(self.namespace)is not NamespaceId
                or type(self.base_persona_version)is not GraphVersion or type(self.planned_head)is not GraphVersion
                or type(self.owner_guard)is not ProductionOwnerGuardV1):
            raise ValueError("General trial start requires its separate exact original schema")
        for version in (self.base_persona_version,self.planned_head,*self.source_versions):
            if type(version)is not GraphVersion or NamespaceId.from_key(version.key)!=self.namespace or version.revision<1:
                raise ValueError("General trial start original head crosses namespace/positive revision")
        for name in ("start_ref","producing_operation_id","proposal_ref","base_persona_head","target_block",
                "completed_trial_ref","plan_adoption_operation_id","action_id","activity_id","effect_id","attempt_id",
                "clock_mapping_ref","parent_budget_lease_ref"):
            if type(getattr(self,name))is not str or not getattr(self,name):raise ValueError("General trial original identity missing")
        for name in ("proposal_digest","planned_digest","plan_adoption_receipt_digest",
                "clock_original_digest","original_grant_digest"):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
                raise ValueError("General trial immutable original commitment missing")
        if type(self.clock_mapping_version)is not int or self.clock_mapping_version<1:
            raise ValueError("General trial requires its actual positive clock mapping version")
        group=(self.project_ref,self.recipe_ref,self.step_id,self.planned_life_plan_original)
        if any(value is None for value in group)and not all(value is None for value in group):
            raise ValueError("General D10 trial requires the whole exact project/recipe/step group")
        if all(value is None for value in group):
            if self.planned_head.key.type_name!="d08.action_intent.v1":
                raise ValueError("General D08 trial must bind its exact planned action head")
        else:
            if (any(type(value)is not str or not value for value in group[:3])
                    or type(self.planned_life_plan_original)is not ProductionOriginalRefV1):
                raise ValueError("General D10 trial requires actual signed plan and exact project/recipe/step")
        if (any(type(value)not in (int,float)or not math.isfinite(value)for value in(
                    self.started_at_utc,self.observation_deadline_utc))
                or self.observation_deadline_utc<=self.started_at_utc
                or not Decimal(self.started_role_cursor)<Decimal(self.observation_role_deadline)):
            raise ValueError("General trial start preserves a finite forward original UTC/role window")
        if (type(self.ancestor_operations)is not tuple or not self.ancestor_operations
                or len(self.ancestor_operations)>32
                or any(type(op)is not str or not op or type(deadline)not in (int,float)or not math.isfinite(deadline)
                    or self.observation_deadline_utc>deadline for op,deadline in self.ancestor_operations)):
            raise ValueError("General trial window cannot extend any actual signed ancestor deadline")
        if (not self.source_originals or not self.source_versions or len(self.source_originals)>32
                or any(type(item)is not ProductionOriginalRefV1 for item in self.source_originals)):
            raise ValueError("General trial preserves its actual source-original and current Source closure")

@dataclass(frozen=True,slots=True)
class GeneralGrowthTrialOriginalV1:
    growth_proposal_ref:str
    trial_start_ref:str
    settled_outcome_refs:tuple[str,...]
    evidence_source_refs:tuple[str,...]
    actual_observation_refs:tuple[ProductionOriginalRefV1,...]
    actual_cost_refs:tuple[ProductionOriginalRefV1,...]
    completed:bool
    schema:str="d01.general-growth-trial.v1"
    def __post_init__(self):
        if (self.schema!="d01.general-growth-trial.v1"or self.completed is not True
                or not self.growth_proposal_ref or not self.trial_start_ref or not self.settled_outcome_refs
                or not self.evidence_source_refs or not self.actual_observation_refs or not self.actual_cost_refs):
            raise ValueError("General completed trial requires its actual registered start/outcome/observation/cost")
        if any(type(item)is not ProductionOriginalRefV1 for item in (*self.actual_observation_refs,*self.actual_cost_refs)):
            raise ValueError("General completed trial evidence must remain actual original references")

@dataclass(frozen=True,slots=True)
class GeneralGrowthIntentOriginalV1:
    proposal_ref:str
    proposal_digest:str
    required_trial_refs:tuple[str,...]
    trial_start_refs:tuple[str,...]
    context_original_refs:tuple[ProductionOriginalRefV1,...]
    support_source_refs:tuple[str,...]
    context_source_refs:tuple[str,...]
    source_versions:tuple[GraphVersion,...]
    schema:str="d01.general-growth-intent.v1"
    def __post_init__(self):
        if (self.schema!="d01.general-growth-intent.v1"or not self.proposal_ref
                or not self.required_trial_refs or len(self.required_trial_refs)!=len(self.trial_start_refs)
                or len(set(self.required_trial_refs))!=len(self.required_trial_refs)
                or len(set(self.trial_start_refs))!=len(self.trial_start_refs)
                or not self.context_original_refs or not self.support_source_refs or not self.context_source_refs
                or not self.source_versions or any(type(version)is not GraphVersion or version.revision<1
                    or version.key.type_name not in {"memory.source","memory.access","d06.source_correction_head.v1"}
                    for version in self.source_versions)):
            raise ValueError("General growth has an explicit nonempty trial/start set and distinct actual support/context")


@dataclass(frozen=True,slots=True)
class FreezeCurrentGeneralGrowthRequestV1:
    interpretation_ref:str
    trigger_original_ref:str
    general_growth_intent_ref:str
    growth_proposal_ref:str
    counterevidence_query_ref:str
    required_trial_refs:tuple[str,...]
    trial_start_refs:tuple[str,...]
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        for ref in(self.interpretation_ref,self.trigger_original_ref,self.general_growth_intent_ref,
                self.growth_proposal_ref,self.counterevidence_query_ref,*self.required_trial_refs,*self.trial_start_refs):
            require_locator_v1(ref,"actual General original")
        if (not self.required_trial_refs or len(self.required_trial_refs)>16
                or len(self.required_trial_refs)!=len(self.trial_start_refs)
                or len(set(self.required_trial_refs))!=len(self.required_trial_refs)
                or len(set(self.trial_start_refs))!=len(self.trial_start_refs)):
            raise ValueError("General intent requires its explicit nonempty future completed/start set")

@dataclass(frozen=True,slots=True)
class RegisterCurrentGeneralGrowthTrialStartRequestV1:
    original_ref:str
    general_growth_intent_ref:str
    growth_proposal_ref:str
    completed_trial_ref:str
    planned_head:GraphVersion
    project_ref:str|None=None
    recipe_ref:str|None=None
    step_id:str|None=None
    life_plan_original_ref:str|None=None
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        for ref in(self.original_ref,self.general_growth_intent_ref,self.growth_proposal_ref,self.completed_trial_ref):
            require_locator_v1(ref,"General future trial original")
        if type(self.planned_head)is not GraphVersion or self.planned_head.revision<1:
            raise ValueError("General trial requires its actual positive already-approved planned head")
        group=(self.project_ref,self.recipe_ref,self.step_id,self.life_plan_original_ref)
        if any(value is None for value in group)and not all(value is None for value in group):
            raise ValueError("General Life trial requires the whole exact project/recipe/step group")
        if all(value is None for value in group):
            if self.planned_head.key.type_name!="d08.action_intent.v1":
                raise ValueError("General action trial requires its exact actual planned action")
        else:
            for ref in group:require_locator_v1(ref,"actual General Life plan identity")

@dataclass(frozen=True,slots=True)
class DeriveCurrentGeneralGrowthTrialRequestV1:
    original_ref:str
    general_growth_intent_ref:str
    growth_proposal_ref:str
    settled_progress_ref:str
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        for ref in(self.original_ref,self.general_growth_intent_ref,self.growth_proposal_ref,self.settled_progress_ref):
            require_locator_v1(ref,"actual General completed trial original")

@dataclass(frozen=True,slots=True)
class AdoptCurrentGeneralGrowthRequestV1:
    general_growth_intent_ref:str
    growth_proposal_ref:str
    trigger_original_ref:str
    trial_original_refs:tuple[str,...]
    counterevidence_query_ref:str
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        for ref in(self.general_growth_intent_ref,self.growth_proposal_ref,self.trigger_original_ref,
                self.counterevidence_query_ref,*self.trial_original_refs):
            require_locator_v1(ref,"actual General adoption original")
        if not self.trial_original_refs or len(self.trial_original_refs)>16 or len(set(self.trial_original_refs))!=len(self.trial_original_refs):
            raise ValueError("General adoption requires its nonempty exact completed trial set")


def _actual_general_read_v1(db,readers,frame):
    from .d01_production_operations_v1 import CurrentDomainReadV1,InstalledD01ProductionReadersV1
    if type(readers)is not InstalledD01ProductionReadersV1 or frame.envelope.authority.purpose!="consolidation":
        raise TypeError("General growth uses the actual installed D01 reader and consolidation frame")
    read=CurrentDomainReadV1(frame);read.check(db)
    return read


def _actual_general_cognition_v1(db,readers,read,interpretation_ref):
    from .d07_execution_v1 import TABLE,read_d07_original_v1,read_prepared_d07_execution_v1,read_current_d07_semantic_question_v1
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..domains.d01.production_operations_v1 import plain_v1
    namespace=read.frame.envelope.authority.namespace
    atom=read.head(db,interpretation_ref,required=True)
    if atom.key.type_name!="d07.current_interpretation.v1":
        raise ValueError("General growth begins at its actual adopted D07 interpretation")
    adoption=read_d07_original_v1(db,readers.issuer,namespace,"adopted",interpretation_ref)
    if adoption is None:
        raise MissingProductionOriginalV1("actual_signed_general_cognition_adoption")
    raw=adoption[0]
    if (raw["interpretation_ref"]!=atom.key.token or raw["interpretation_revision"]!=atom.revision
            or raw["interpretation_value_digest"]!=canonical_digest(atom.value)):
        raise ValueError("General cognition changed its original exact adopted semantic head")
    locators=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='prepared' AND payload_digest=? LIMIT 2",
        (*namespace.as_tuple,raw["prepared_digest"])).fetchall()
    if len(locators)!=1:
        raise MissingProductionOriginalV1("unique_actual_general_prepared_for_adopted_cognition")
    prepared=read_prepared_d07_execution_v1(db,readers.issuer,namespace,locators[0][0])
    if type(prepared)is not D07GeneralGrowthPreparedV1:
        raise ValueError("General FULL cannot borrow an old generic/Method/Identity cognition producer")
    question=read_current_d07_semantic_question_v1(db,readers.issuer,namespace,prepared.semantic_question_ref)
    if (type(question)is not D07GeneralGrowthQuestionV1
            or canonical_digest(plain_v1(question))!=prepared.semantic_question_digest
            or question.support_source_refs!=prepared.support_source_refs
            or question.context_source_refs!=prepared.context_source_refs):
        raise ValueError("General actual cognition lost its signed distinct support/context question")
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_background_read_v3 import background_json_loads_v3
    from ..domains.d07 import D07DomainProvider
    next(spec for spec in D07DomainProvider.type_specs()if spec.name==atom.key.type_name).validator(atom.value)
    history=read_graph_row_v3(db,("event_id","value","valid"),where="token=? AND revision=?",parameters=(atom.key.token,atom.revision),history=True)
    if (history is None or history[2]!=1 or background_json_loads_v3(history[1])!=atom.value
            or history[0]!=raw["adoption_operation_id"]):
        raise MissingProductionOriginalV1("actual_general_cognition_adoption_history")
    read.committed_operation(db,history[0]);semantic=atom
    if (semantic.value["question_key"]!=question.question_key or semantic.value["stance"]!="support"
            or semantic.value["evidence_status"]!="supported"or semantic.value["meaningful_unknowns"]
            or semantic.value["current"]is not True):
        raise MissingProductionOriginalV1("explicit_current_supported_general_semantic_scope")
    records=read.source_family(db,tuple(semantic.value["source_refs"]),purpose="consolidation")
    semantic_original=read.original(interpretation_ref,digest=canonical_digest(semantic.value))
    roots=tuple(semantic.value["source_refs"])
    if not roots or not set(roots)<=set(question.support_source_refs):
        raise MissingProductionOriginalV1("general_growth_requires_actual_independent_support_not_internal_context")
    for ref in roots:
        record=records[ref]
        if (record.source_kind!="observed" or record.assertion_status!="confirmed"
                or record.independence!="independent" or record.parent_source_ids):
            raise MissingProductionOriginalV1("confirmed_independent_observed_general_growth_support")
    read.source_family(db,question.context_source_refs,purpose="consolidation")
    return prepared,question,semantic,semantic_original



def _general_counter_atoms_from_qualified_metadata_v1(db,read,scope):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    namespace=read.frame.envelope.authority.namespace
    rows,complete=read_bound_current_general_owner_type_metadata_v1(db,namespace=namespace,
        type_id="d07.current_interpretation.v1",limit=129)
    pages=tuple(page for page in read.frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
    versions=tuple(GraphVersion(atom.key,atom.revision)for atom in rows)
    if (not complete or len(rows)>128 or len(pages)!=1 or not pages[0].complete
            or pages[0].row_versions!=versions or pages[0].epoch.revision!=read.frame.snapshot.epochs[0].revision):
        raise MissingProductionOriginalV1("complete_current_general_growth_counter_metadata_scope")
    return tuple(read.head(db,atom.key,required=True)for atom in rows if atom.valid
        and atom.value["question_key"]==scope and atom.value["current"]is True)


def _read_current_general_counter_scope_v1(db,read,scope):
    from ..domains.d07 import D07DomainProvider
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_background_read_v3 import background_json_loads_v3
    atoms=_general_counter_atoms_from_qualified_metadata_v1(db,read,scope)
    spec=next(item for item in D07DomainProvider.type_specs()if item.name=="d07.current_interpretation.v1")
    originals=[];qualification="qualified"if atoms else"unknown"
    for atom in atoms:
        spec.validator(atom.value)
        history=read_graph_row_v3(db,("event_id","value","valid"),where="token=? AND revision=?",parameters=(atom.key.token,atom.revision),history=True)
        if history is None or history[2]!=1 or background_json_loads_v3(history[1])!=atom.value:
            raise MissingProductionOriginalV1("actual_current_general_growth_counter_adoption")
        read.committed_operation(db,history[0]);originals.append(read.original(atom.key.token,digest=canonical_digest(atom.value)))
        refs=tuple(atom.value["source_refs"])
        if not refs:
            if qualification!="opposition":qualification="unknown"
            continue
        read.source_family(db,refs,purpose="consolidation")
        if atom.value["stance"]=="oppose"and atom.value["evidence_status"]=="supported":qualification="opposition"
        elif qualification!="opposition"and(atom.value["stance"]!="support"or atom.value["meaningful_unknowns"]or atom.value["evidence_status"]!="supported"):
            qualification="unknown"
    return qualification=="qualified",qualification=="opposition",tuple(originals)

def validate_current_general_growth_freeze_v1(readers,db,frame,request):
    from .d01_production_operations_v1 import GrowthIntentOriginalV1,GrowthCounterevidenceOriginalV1,MissingProductionOriginalV1
    from ..domains.d01 import PersonaDomain
    from ..domains.d01.production_operations_v1 import plain_v1
    read=_actual_general_read_v1(db,readers,frame)
    if type(request)is not FreezeCurrentGeneralGrowthRequestV1:
        raise TypeError("exact General freeze request required")
    prepared,question,semantic,semantic_original=_actual_general_cognition_v1(db,readers,read,request.interpretation_ref)
    active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=frame.envelope.authority.namespace,
        current_guard=readers.owner_guard)
    target=next((block for block in active.plan.blocks if block.block_id==question.target_block),None)
    if target is None or target.kind=="semantic_identity" or target.plasticity!="growth":
        raise MissingProductionOriginalV1("actual_current_ordinary_general_growth_block")
    roots=tuple(semantic.value["source_refs"])
    read.original(request.trigger_original_ref)
    proposal=GrowthIntentOriginalV1("growth:"+canonical_digest((active.head_id,semantic.key.token,semantic.revision))[:48],
        active.head_id,question.target_block,semantic.value["proposition"],question.scope,roots,
        request.trigger_original_ref,request.required_trial_refs)
    inventory=_general_counter_atoms_from_qualified_metadata_v1(db,read,question.question_key)
    pages=tuple(page for page in frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
    if len(pages)!=1 or not pages[0].complete:
        raise MissingProductionOriginalV1("complete_current_general_growth_counter_inventory")
    counters=tuple(atom for atom in inventory if atom.valid and atom.value.get("question_key")==question.question_key
        and atom.value.get("stance")=="oppose" and atom.value.get("evidence_status")=="supported")
    counter_roots=tuple(dict.fromkeys(ref for atom in counters for ref in atom.value["source_refs"]))
    if counter_roots:read.source_family(db,counter_roots,purpose="consolidation")
    counter=GrowthCounterevidenceOriginalV1(request.growth_proposal_ref,roots,counter_roots,
        pages[0].type_id,pages[0].epoch.revision,True,bool(counters))
    context=(*question.context_original_refs,
        ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,prepared.semantic_question_digest),
        ProductionOriginalRefV1("d07.prepared",prepared.job_id,prepared.digest),semantic_original)
    intent_sources=read.source_family(db,tuple(dict.fromkeys((*roots,*question.context_source_refs))),purpose="consolidation")
    intent_source_ids={record.source_id for record in intent_sources.values()}
    wrapper=GeneralGrowthIntentOriginalV1(request.growth_proposal_ref,canonical_digest(plain_v1(proposal)),
        request.required_trial_refs,request.trial_start_refs,tuple(dict.fromkeys(context)),roots,question.context_source_refs,
        tuple(version for version in frame.snapshot.versions if version.key.type_name in {
            "memory.source","memory.access","d06.source_correction_head.v1"} and version.revision>0 and version.key.owner.subject in intent_source_ids))
    return {"general_growth_intent":wrapper,"growth_proposal":proposal,
        "growth_counterevidence":counter,"semantic_interpretation":semantic_original}


def read_current_general_growth_v1(readers,db,frame,request):
    from .d01_production_operations_v1 import CurrentGrowthInputsV1,MissingProductionOriginalV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01 import PersonaDomain,GrowthProposal
    read=_actual_general_read_v1(db,readers,frame)
    if type(request)is not AdoptCurrentGeneralGrowthRequestV1:
        raise TypeError("exact General adopter request required")
    wrapper_raw,wrapper_original=readers._read(db,read,request.general_growth_intent_ref,"general_growth_intent_v1")
    wrapper=decode_typed_production_value_v1(wrapper_raw,GeneralGrowthIntentOriginalV1)
    raw,proposal_original=readers._read(db,read,request.growth_proposal_ref,"growth_proposal")
    if (set(raw)!={"proposal_id","base_head","target_block","replacement_claim","change_kind",
            "evidence_source_refs","trigger_original_ref","required_trial_refs"} or wrapper.proposal_ref!=request.growth_proposal_ref
            or wrapper.proposal_digest!=proposal_original.original_digest
            or raw["trigger_original_ref"]!=request.trigger_original_ref
            or tuple(raw["required_trial_refs"])!=wrapper.required_trial_refs
            or tuple(request.trial_original_refs)!=wrapper.required_trial_refs
            or tuple(raw["evidence_source_refs"])!=wrapper.support_source_refs):
        raise ValueError("General adoption changed its exact nonempty declared trials/support/base proposal")
    active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=frame.envelope.authority.namespace,
        current_guard=readers.owner_guard)
    target=next((block for block in active.plan.blocks if block.block_id==raw["target_block"]),None)
    if active.head_id!=raw["base_head"] or target is None or target.kind=="semantic_identity" or target.plasticity!="growth":
        raise MissingProductionOriginalV1("general_growth_current_ordinary_base_changed")
    read.source_family(db,wrapper.context_source_refs,purpose="consolidation")
    records=read.source_family(db,wrapper.support_source_refs,purpose="consolidation")
    families=tuple(records[ref].provenance_root for ref in wrapper.support_source_refs)
    if len(set(families))!=len(families)or any(records[ref].source_kind!="observed"
            or records[ref].assertion_status!="confirmed" or records[ref].independence!="independent"
            or records[ref].parent_source_ids for ref in wrapper.support_source_refs):
        raise MissingProductionOriginalV1("general_growth_current_independent_support")
    originals=[wrapper_original,proposal_original,read.original(request.trigger_original_ref)]
    for trial_ref,start_ref in zip(wrapper.required_trial_refs,wrapper.trial_start_refs,strict=True):
        start_raw,start_original=readers._read(db,read,start_ref,"general_growth_trial_start_v1")
        start=decode_typed_production_value_v1(start_raw,GeneralGrowthTrialStartV1)
        trial_raw,trial_original=readers._read(db,read,trial_ref,"general_growth_trial_v1")
        trial=decode_typed_production_value_v1(trial_raw,GeneralGrowthTrialOriginalV1)
        if (start.proposal_ref!=request.growth_proposal_ref or start.proposal_digest!=proposal_original.original_digest
                or start.completed_trial_ref!=trial_ref or trial.growth_proposal_ref!=request.growth_proposal_ref
                or trial.trial_start_ref!=start_ref or trial.completed is not True):
            raise ValueError("General actual completed trial/start belongs to another declared proposal")
        validate_current_general_growth_completed_trial_v1(readers,db,read,start,trial)
        originals.extend((start_original,trial_original,*trial.actual_observation_refs,*trial.actual_cost_refs))
    counter,counter_original=readers._read(db,read,request.counterevidence_query_ref,"growth_counterevidence")
    if (counter["growth_proposal_ref"]!=request.growth_proposal_ref or counter["query_scope_ref"]!="d07.current_interpretation.v1"
            or tuple(counter["evidence_source_refs"])!=wrapper.support_source_refs or counter["coverage_complete"]is not True):
        raise ValueError("General birth counter original differs from its fixed proposal/support scope")
    complete,conflict,current_originals=_read_current_general_counter_scope_v1(db,read,
        "d01.growth:"+raw["target_block"]+":"+raw["change_kind"])
    originals.extend((counter_original,*current_originals))
    proposal=GrowthProposal(raw["proposal_id"],raw["base_head"],raw["target_block"],raw["replacement_claim"],families,
        complete,raw["change_kind"],"external")
    inputs=CurrentGrowthInputsV1(proposal,tuple(records[ref].source_id for ref in wrapper.support_source_refs),
        readers.owner_guard,tuple(dict.fromkeys(originals)),True,complete,conflict)
    return inputs,{"general_growth_intent":wrapper,"trial_start_originals":tuple(
        original for original in originals if original.kind=="d01.general_growth_trial_start_v1"),
        "trial_originals":tuple(original for original in originals if original.kind=="d01.general_growth_trial_v1")}


def _general_operation_receipt_v1(db,namespace,operation_id):
    from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    bundle=_producer_original_point_v3(db,table="graph_bundle_operations",
        columns=("digest","activity_id","effect_id","commit_seq","receipt_json"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,operation_id),
        legacy_reader=lambda:db.execute("SELECT digest,activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation_id)).fetchone())
    if bundle is None:raise ValueError("General trial has no actual committed plan/action producer")
    event=_producer_original_point_v3(db,table="graph_events",columns=("reads","revisions","epoch_revision"),
        key_columns=("bot","persona","session","event_id"),key=(*namespace.as_tuple,bundle[1],operation_id),
        legacy_reader=lambda:db.execute("SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",(*namespace.as_tuple,bundle[1],operation_id)).fetchone())
    if event is None:raise ValueError("General producing receipt lost its actual event member arrays")
    return reconstruct_graph_bundle_commit_receipt_v1(namespace,operation_id,bundle,event)


def _current_general_clock_v1(db,readers,read):
    from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1,TABLE
    from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
    from datetime import datetime,timezone
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    if type(readers.role_clock_reader)is not InstalledD04SemanticMappingReaderV3:
        raise MissingProductionOriginalV1("actual_installed_general_growth_role_clock_reader")
    mapping=read_current_role_clock_installation_v1(readers.role_clock_reader,db,read.frame.envelope.authority.namespace)
    row=db.execute("SELECT original_digest FROM "+TABLE+" WHERE bot=? AND persona=? AND revision=?",
        (*read.frame.envelope.authority.namespace.as_tuple,mapping.version)).fetchone()
    if row is None:raise MissingProductionOriginalV1("actual_signed_general_growth_clock_original")
    now=read.frame.now_utc
    return mapping,row[0],mapping.character_at(datetime.fromtimestamp(now,timezone.utc).isoformat().replace("+00:00","Z"))


def _general_current_budget_ancestors_v1(db,issuer,namespace,lease_id):
    from .budget import get_budget_lease,require_budget_family_admissible
    from ..domains.d01.production_operations_v1 import plain_v1
    family=[];seen=set();current=lease_id
    while current is not None:
        if current in seen or len(seen)>=32:raise ValueError("General actual original budget ancestry is cyclic or exceeds its bound")
        seen.add(current);lease=get_budget_lease(db,current);require_budget_family_admissible(db,current)
        grant=issuer.current_budget_grant(db,current)
        if (lease.bot_id,lease.persona_id)!=(namespace.bot_id,namespace.persona_id):
            raise ValueError("General current budget ancestor crosses actual namespace")
        family.append((lease.lease_id,grant.version,canonical_digest(grant),grant.valid_until_utc))
        current=lease.parent_id
    return tuple(family)



def _require_unique_general_growth_start_v1(db,readers,namespace,proposal_ref,trial_ref,expected_start_ref,*,allow_absent=False):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    rows=read_current_general_growth_start_metadata_inventory_v1(db,namespace=namespace,issuer=readers.issuer)
    matches=[(value,original)for value,original in rows if value["proposal_ref"]==proposal_ref and value["completed_trial_ref"]==trial_ref]
    if len(matches)>1 or matches and matches[0][1].original_ref!=expected_start_ref:
        raise ValueError("General trial declaration has more than one immutable original start")
    if not matches and not allow_absent:raise MissingProductionOriginalV1("actual_registered_unique_general_trial_start")
    return None if not matches else matches[0]


def _general_complete_execution_metadata_v1(db,read,type_id):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    rows,complete=read_bound_current_general_owner_type_metadata_v1(db,namespace=read.frame.envelope.authority.namespace,
        type_id=type_id,limit=129)
    pages=tuple(page for page in read.frame.query_coverage if page.type_id==type_id)
    versions=tuple(GraphVersion(atom.key,atom.revision)for atom in rows)
    if (not complete or len(rows)>128 or len(pages)!=1 or not pages[0].complete or pages[0].row_versions!=versions
            or pages[0].epoch.revision!=read.frame.snapshot.epochs[0].revision):
        raise MissingProductionOriginalV1("complete_general_trial_execution_metadata:"+type_id)
    return rows


def _require_general_action_controls_v1(db,read,planned,action):
    from ..graph_types import AtomKey
    from ..domains.d08.execution import GoalExecutionProvider,ActionCancellationState
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    goal_key=AtomKey(planned.key.owner,"d08.goal.v1",action.goal_ref)
    cancel_key=AtomKey(planned.key.owner,"d08.action_cancellation.v1",action.action_id)
    goal_atom=read.head(db,goal_key,required=True);cancel_atom=read.head(db,cancel_key,required=True)
    types={spec.name:spec for spec in GoalExecutionProvider().register_types()}
    goal=types["d08.goal.v1"].validator(goal_atom.value)
    cancellation=types["d08.action_cancellation.v1"].validator(cancel_atom.value)
    if (goal.goal_id!=action.goal_ref or goal.state!="active"or goal.satisfaction_predicate!=action.success_predicate
            or not set(action.source_refs)<=set(goal.reason_refs)
            or type(cancellation)is not ActionCancellationState or cancellation.state!="active"or cancellation.cancel_epoch!=0
            or(cancellation.action_id,cancellation.action_revision,cancellation.action_digest,cancellation.activity_id,
                cancellation.attempt_id,cancellation.effect_id)!=(action.action_id,action.revision,canonical_digest(action),
                    action.identity.activity_id,action.identity.attempt_id,action.identity.effect_id)):
        raise MissingProductionOriginalV1("actual_current_general_trial_goal_action_cancellation")
    read.source_family(db,tuple(dict.fromkeys((*goal.reason_refs,*cancellation.source_refs))),purpose="consolidation")
    return(cancel_key.token,),tuple(dict.fromkeys((*goal.reason_refs,*cancellation.source_refs)))

def validate_current_general_growth_trial_start_v1(readers,db,frame,request):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01 import PersonaDomain
    from ..domains.d08.execution import _decode
    from ..runtime_storage_v3 import read_graph_row_v3
    from datetime import datetime,timezone
    read=_actual_general_read_v1(db,readers,frame)
    if type(request)is not RegisterCurrentGeneralGrowthTrialStartRequestV1:
        raise TypeError("exact General future trial registration required")
    wrapper_raw,_=readers._read(db,read,request.general_growth_intent_ref,"general_growth_intent_v1")
    wrapper=decode_typed_production_value_v1(wrapper_raw,GeneralGrowthIntentOriginalV1)
    proposal,proposal_original=readers._read(db,read,request.growth_proposal_ref,"growth_proposal")
    if (wrapper.proposal_ref!=request.growth_proposal_ref or wrapper.proposal_digest!=proposal_original.original_digest
            or request.completed_trial_ref not in wrapper.required_trial_refs
            or wrapper.trial_start_refs[wrapper.required_trial_refs.index(request.completed_trial_ref)]!=request.original_ref):
        raise ValueError("General trial start is outside its exact nonempty declaration")
    active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=frame.envelope.authority.namespace,current_guard=readers.owner_guard)
    target=next((block for block in active.plan.blocks if block.block_id==proposal["target_block"]),None)
    if active.head_id!=proposal["base_head"] or target is None or target.kind=="semantic_identity"or target.plasticity!="growth":
        raise MissingProductionOriginalV1("general_trial_start_current_ordinary_base")
    _require_unique_general_growth_start_v1(db,readers,frame.envelope.authority.namespace,request.growth_proposal_ref,
        request.completed_trial_ref,request.original_ref,allow_absent=True)
    planned=read.head(db,request.planned_head.key,required=True)
    if planned.key.type_name!="d08.action_intent.v1" or planned.revision!=request.planned_head.revision:
        raise MissingProductionOriginalV1("actual_approved_unexecuted_general_trial_action")
    action=_decode("d08.action_intent.v1",planned.value)
    cancel_refs,control_source_roots=_require_general_action_controls_v1(db,read,planned,action)
    history=read_graph_row_v3(db,("event_id","valid"),where="token=? AND revision=?",
        parameters=(planned.key.token,planned.revision),history=True)
    if history is None or history[1]!=1:raise MissingProductionOriginalV1("actual_general_trial_plan_adoption_history")
    adoption=_general_operation_receipt_v1(db,frame.envelope.authority.namespace,history[0])
    if request.planned_head not in adoption.write_versions:
        raise ValueError("General planned action is not a real approved producer member")
    for atom in _general_complete_execution_metadata_v1(db,read,"d08.action_outcome.v1"):
        if atom.valid and (atom.value["action_id"],atom.value["effect_id"],atom.value["attempt_id"])==(
                action.action_id,action.identity.effect_id,action.identity.attempt_id):
            raise MissingProductionOriginalV1("general_trial_start_cannot_follow_an_executed_action")
    for job_atom in _general_complete_execution_metadata_v1(db,read,"runtime.job"):
        if (job_atom.valid and(job_atom.value["activity_id"],job_atom.value["effect_id"])==(
                action.identity.activity_id,action.identity.effect_id)
                and(job_atom.value["phase"]!="queued"or job_atom.value["fence"]!=0 or job_atom.value["cancel_epoch"]!=0)):
            raise MissingProductionOriginalV1("general_trial_start_must_precede_actual_job_acquisition_or_cancel")
    namespace=frame.envelope.authority.namespace
    life_original=None;plan_deadline=None
    if request.life_plan_original_ref is not None:
        from .d11_life_preparation_v1 import _read
        from .d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
        from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
        from ..domains.d01.production_operations_v1 import plain_v1
        signed=_read(db,issuer=readers.issuer,namespace=namespace,kind="plan",ref=request.life_plan_original_ref)
        if signed is None:raise MissingProductionOriginalV1("actual_registered_general_trial_life_plan")
        raw,producer=signed
        expected=RegisteredDraftFilePlanV3 if raw["schema"]=="d10.registered-draft-file-plan.v3"else RegisteredLifePlanV2
        plan=life_from_wire_v1(raw,expected)
        if ((plan.project.ref,plan.recipe.ref,plan.step)!=(request.project_ref,request.recipe_ref,request.step_id)
                or (plan.action_intent.ref,plan.action_intent.revision,plan.activity_id,plan.effect_id,plan.attempt_id)!=(
                    planned.key.token,planned.revision,action.identity.activity_id,action.identity.effect_id,action.identity.attempt_id)
                or plan.parent_budget_lease_ref!=frame.envelope.parent_budget_lease_ref):
            raise ValueError("General Life trial must bind exact approved action/project/recipe/step/root")
        for atom in _general_complete_execution_metadata_v1(db,read,"d10.life_progress.v1"):
            if atom.valid and (atom.value["activity_id"],atom.value["effect_id"],atom.value["project_ref"],atom.value["recipe_ref"],atom.value["step"])==(
                    plan.activity_id,plan.effect_id,plan.project.ref,plan.recipe.ref,plan.step):
                raise MissingProductionOriginalV1("general_trial_start_cannot_follow_actual_life_execution")
        life_original=ProductionOriginalRefV1("d11.life_plan",request.life_plan_original_ref,canonical_digest(plain_v1(plan)))
        read.original(life_original.original_ref,kind=life_original.kind,digest=life_original.original_digest)
        plan_deadline=datetime.fromisoformat(plan.deadline_utc.replace("Z","+00:00")).timestamp()
    mapping,clock_digest,role_start=_current_general_clock_v1(db,readers,read)
    ancestors=_general_current_budget_ancestors_v1(db,readers.issuer,namespace,frame.envelope.parent_budget_lease_ref)
    clock_deadline=datetime.fromisoformat(mapping.valid_until_utc.replace("Z","+00:00")).timestamp()
    deadline=min(frame.envelope.deadline_utc,clock_deadline,*(item[3]for item in ancestors),
        *((plan_deadline,)if plan_deadline is not None else()))
    if deadline<=frame.now_utc:raise MissingProductionOriginalV1("general_trial_original_clock_budget_deadline")
    role_deadline=mapping.character_at(datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace("+00:00","Z"))
    action_sources=read.source_family(db,tuple(dict.fromkeys((*action.source_refs,*control_source_roots))),purpose="consolidation")
    source_originals=tuple(read.original(ref)for ref in action_sources)
    source_ids={record.source_id for record in action_sources.values()}
    source_versions=tuple(version for version in frame.snapshot.versions if version.key.type_name in{
        "memory.source","memory.access","d06.source_correction_head.v1"} and version.key.owner.subject in source_ids and version.revision>0)
    base_key=PersonaDomain.plan_write(active.plan).key;base_atom=read.head(db,base_key,required=True)
    return GeneralGrowthTrialAdmissionV1(namespace,request.original_ref,frame.envelope.identity.operation_id,
        request.growth_proposal_ref,proposal_original.original_digest,active.head_id,GraphVersion(base_key,base_atom.revision),
        target.block_id,request.completed_trial_ref,request.planned_head,canonical_digest(planned.value),
        adoption.operation_id,canonical_digest(adoption),action.action_id,action.identity.activity_id,
        action.identity.effect_id,action.identity.attempt_id,request.project_ref,request.recipe_ref,request.step_id,life_original,
        mapping.mapping_id,mapping.version,clock_digest,frame.now_utc,str(role_start),str(role_deadline),deadline,
        frame.envelope.parent_budget_lease_ref,ancestors[0][2],
        ((frame.envelope.identity.operation_id,frame.envelope.deadline_utc),*(("budget:"+item[0],item[3])for item in ancestors)),
        source_originals,source_versions,frame.owner_guard,cancel_refs)



def _require_general_cost_ancestry_v1(db,namespace,cost_lease_ref,parent_lease_ref):
    from .budget import get_budget_lease
    current=cost_lease_ref;seen=set()
    while current is not None:
        if current in seen or len(seen)>=32:raise ValueError("General actual cost ancestry is cyclic or unbounded")
        seen.add(current);lease=get_budget_lease(db,current)
        if (lease.bot_id,lease.persona_id)!=namespace.as_tuple:raise ValueError("General actual paid component crossed namespace")
        if current==parent_lease_ref:return
        current=lease.parent_id
    raise ValueError("General actual paid component does not descend from the registered start parent")

def _general_trial_terminal_evidence_v1(readers,db,read,start,outcome_ref):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..domains.d08.execution import _decode
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from ..runtime_storage_v3 import read_graph_row_v3
    from datetime import datetime
    outcome=read.head(db,outcome_ref,required=True)
    history=read_graph_row_v3(db,("event_id","value","valid"),where="token=? AND revision=?",
        parameters=(outcome.key.token,outcome.revision),history=True)
    from .domain_background_read_v3 import background_json_loads_v3
    if history is None or history[2]!=1 or background_json_loads_v3(history[1])!=outcome.value:
        raise MissingProductionOriginalV1("actual_general_trial_terminal_history")
    adopted=_general_operation_receipt_v1(db,start.namespace,history[0])
    if GraphVersion(outcome.key,outcome.revision)not in adopted.write_versions:
        raise ValueError("General terminal is not its actual immutable producer member")
    observations=[];costs=[]
    if start.project_ref is None:
        if outcome.key.type_name!="d08.action_outcome.v1":
            raise ValueError("General action trial cannot consume another progress kind")
        actual=_decode("d08.action_outcome.v1",outcome.value)
        if ((actual.action_id,actual.effect_id,actual.attempt_id)!=(start.action_id,start.effect_id,start.attempt_id)
                or actual.result_level!="completed_verified" or actual.unknown_effects
                or actual.effect_id not in actual.completed_effects or not actual.observation_refs):
            raise MissingProductionOriginalV1("actual_exact_completed_general_trial_action")
        for ref in actual.observation_refs:
            original=read.original(ref)
            if original.kind not in {"d11.outbound_observation","d11.role_segment_end","d11.actual_artifact"}:
                raise MissingProductionOriginalV1("actual_independent_general_trial_observation")
            observations.append(original)
        timing=db.execute("SELECT occurred_at FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*start.namespace.as_tuple,adopted.activity_id,adopted.operation_id)).fetchone()
        if timing is None:raise MissingProductionOriginalV1("actual_general_trial_observed_event_time")
        completed_utc=timing[0]
        action=read.head(db,start.planned_head.key,required=True)
        roots=tuple(action.value["source_refs"])
    else:
        if outcome.key.type_name!="d10.life_progress.v1":
            raise ValueError("General Life trial cannot consume an action-only progress")
        progress=decode_typed_production_value_v1(outcome.value,LifeProgressHeadV1)
        from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
        prepared,terminal,production=require_current_life_progress_v1(db,namespace=start.namespace,
            progress=progress,issuer=readers.issuer,read=read)
        from ..domains.d01.production_operations_v1 import plain_v1
        plan=prepared.plan;binding=terminal.binding
        if (start.planned_life_plan_original is None
                or binding.plan_original_ref!=start.planned_life_plan_original.original_ref
                or binding.plan_digest!=start.planned_life_plan_original.original_digest
                or canonical_digest(plain_v1(plan))!=start.planned_life_plan_original.original_digest
                or (plan.project.ref,plan.recipe.ref,plan.step)!=(start.project_ref,start.recipe_ref,start.step_id)
                or (progress.project_ref,progress.recipe_ref,progress.step,progress.activity_id,progress.effect_id)!=(
                    start.project_ref,start.recipe_ref,start.step_id,start.activity_id,start.effect_id)
                or (binding.activity_id,binding.effect_id,binding.attempt_id)!=(start.activity_id,start.effect_id,start.attempt_id)
                or terminal.status!="completed"):
            raise MissingProductionOriginalV1("actual_exact_general_trial_life_plan_step_terminal")
        observations.extend((read.original(terminal.original_ref),read.original(binding.artifact_ref)))
        completed_utc=datetime.fromisoformat(terminal.payload.completed_at_utc.replace("Z","+00:00")).timestamp()
        roots=progress.source_refs
    cost_rows,cost_complete=_general_cost_metadata_rows_v1(db,start.namespace)
    pages=tuple(page for page in read.frame.query_coverage if page.type_id=="runtime.cost_settlement")
    if (not cost_complete or len(cost_rows)>128 or len(pages)!=1 or not pages[0].complete
            or pages[0].row_versions!=tuple(GraphVersion(atom.key,atom.revision)for atom in cost_rows)):
        raise MissingProductionOriginalV1("complete_general_trial_actual_cost_inventory")
    for metadata in cost_rows:
        if metadata.valid and (metadata.value["activity_id"],metadata.value["effect_id"])==(start.activity_id,start.effect_id):
            atom=read.head(db,metadata.key,required=True)
        else:continue
        if atom.valid and (atom.value["activity_id"],atom.value["effect_id"])==(start.activity_id,start.effect_id):
            _require_general_cost_ancestry_v1(db,start.namespace,atom.value["lease_id"],start.parent_budget_lease_ref)
            costs.append(read.settled_cost_original(db,atom.key.token,activity_id=start.activity_id,effect_id=start.effect_id))
    if not costs or not observations:
        raise MissingProductionOriginalV1("general_trial_actual_paid_cost_and_independent_observation")
    read.source_family(db,roots,purpose="consolidation")
    return tuple(roots),tuple(observations),tuple(costs),completed_utc


def validate_current_general_growth_completed_trial_v1(readers,db,read,start,trial):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..domains.d08.execution import _decode
    from .d07_execution_v1 import _clock_from_json,_clock_original
    from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE
    from ..runtime_contracts import canonical_serialize
    from datetime import datetime,timezone
    from decimal import Decimal
    if type(start)is not GeneralGrowthTrialStartV1 or type(trial)is not GeneralGrowthTrialOriginalV1:
        raise TypeError("exact General registered start and completed original required")
    planned=read.head(db,start.planned_head.key,required=True)
    if planned.revision!=start.planned_head.revision or canonical_digest(planned.value)!=start.planned_digest:
        raise MissingProductionOriginalV1("general_trial_original_approved_plan_changed")
    action=_decode("d08.action_intent.v1",planned.value)
    if (action.action_id,action.identity.activity_id,action.identity.effect_id,action.identity.attempt_id)!=(
            start.action_id,start.activity_id,start.effect_id,start.attempt_id):
        raise ValueError("General start changed original action/activity/effect/attempt")
    for ref in start.cancel_refs:
        cancel=read.head(db,ref,required=True)
        from ..domains.d08.execution import ActionCancellationState,GoalExecutionProvider
        spec=next(item for item in GoalExecutionProvider().register_types()if item.name=="d08.action_cancellation.v1")
        cancellation=spec.validator(cancel.value)
        if (type(cancellation)is not ActionCancellationState or cancellation.state!="active"or cancellation.cancel_epoch!=0
                or(cancellation.action_id,cancellation.action_revision,cancellation.action_digest,cancellation.activity_id,
                    cancellation.attempt_id,cancellation.effect_id)!=(action.action_id,action.revision,canonical_digest(action),
                        start.activity_id,start.attempt_id,start.effect_id)):
            raise MissingProductionOriginalV1("general_trial_action_cancelled")
    row=db.execute("SELECT original_json FROM "+CLOCK_TABLE+" WHERE bot=? AND persona=? AND revision=?",
        (*start.namespace.as_tuple,start.clock_mapping_version)).fetchone()
    if row is None:raise MissingProductionOriginalV1("actual_original_general_trial_role_clock")
    from .domain_background_read_v3 import background_json_loads_v3
    original=background_json_loads_v3(row[0]);mapping=_clock_from_json(canonical_serialize(original["mapping"]))
    if (_clock_original(db,readers.issuer,start.namespace,mapping)!=start.clock_original_digest
            or (mapping.mapping_id,mapping.version)!=(start.clock_mapping_ref,start.clock_mapping_version)):
        raise ValueError("General completed trial changed its original signed role clock")
    observations=[];costs=[];roots=[]
    for ref in trial.settled_outcome_refs:
        actual_roots,actual_observations,actual_costs,completed=_general_trial_terminal_evidence_v1(readers,db,read,start,ref)
        role=mapping.character_at(datetime.fromtimestamp(completed,timezone.utc).isoformat().replace("+00:00","Z"))
        if (not start.started_at_utc<=completed<start.observation_deadline_utc
                or not Decimal(start.started_role_cursor)<=role<Decimal(start.observation_role_deadline)):
            raise MissingProductionOriginalV1("general_trial_outcome_outside_original_clock_window")
        roots.extend(actual_roots);observations.extend(actual_observations);costs.extend(actual_costs)
    if (trial.evidence_source_refs!=tuple(dict.fromkeys(roots))
            or trial.actual_observation_refs!=tuple(dict.fromkeys(observations))
            or trial.actual_cost_refs!=tuple(dict.fromkeys(costs))):
        raise ValueError("General completed original differs from actual terminal/observation/paid cost evidence")
    read.source_family(db,trial.evidence_source_refs,purpose="consolidation")
    return trial



def _require_general_trial_derivation_budget_v1(db,readers,read,start):
    from .budget import get_budget_lease,require_budget_family_admissible
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    frame=read.frame
    if frame.envelope.parent_budget_lease_ref!=start.parent_budget_lease_ref:
        raise ValueError("General completion cannot borrow another current parent budget")
    lease=get_budget_lease(db,start.parent_budget_lease_ref)
    grant=readers.issuer.current_budget_grant(db,start.parent_budget_lease_ref)
    require_budget_family_admissible(db,start.parent_budget_lease_ref)
    if ((lease.bot_id,lease.persona_id)!=start.namespace.as_tuple or lease.state!="active"
            or canonical_digest(grant)!=start.original_grant_digest):
        raise MissingProductionOriginalV1("general_trial_original_parent_grant_changed_or_closed")
    family=_general_current_budget_ancestors_v1(db,readers.issuer,start.namespace,start.parent_budget_lease_ref)
    original_budget_refs={operation.removeprefix("budget:")for operation,_ in start.ancestor_operations if operation.startswith("budget:")}
    if {item[0]for item in family}!=original_budget_refs:
        raise ValueError("General completed trial changed its actual original parent ancestry")
    deadline=min(start.observation_deadline_utc,*(bound for _,bound in start.ancestor_operations),*(item[3]for item in family))
    if frame.now_utc>=deadline or frame.envelope.deadline_utc>deadline:
        raise MissingProductionOriginalV1("general_trial_original_parent_deadline_expired_or_extended")
    return grant

def derive_current_general_growth_trial_v1(readers,db,frame,request):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    read=_actual_general_read_v1(db,readers,frame)
    if type(request)is not DeriveCurrentGeneralGrowthTrialRequestV1:
        raise TypeError("exact General completed trial derivation request required")
    wrapper_raw,_=readers._read(db,read,request.general_growth_intent_ref,"general_growth_intent_v1")
    wrapper=decode_typed_production_value_v1(wrapper_raw,GeneralGrowthIntentOriginalV1)
    if request.original_ref not in wrapper.required_trial_refs or wrapper.proposal_ref!=request.growth_proposal_ref:
        raise ValueError("General completed trial is outside its actual declared nonempty intent")
    start_ref=wrapper.trial_start_refs[wrapper.required_trial_refs.index(request.original_ref)]
    start_raw,start_original=readers._read(db,read,start_ref,"general_growth_trial_start_v1")
    start=decode_typed_production_value_v1(start_raw,GeneralGrowthTrialStartV1)
    proposal,proposal_original=readers._read(db,read,request.growth_proposal_ref,"growth_proposal")
    _require_unique_general_growth_start_v1(db,readers,frame.envelope.authority.namespace,request.growth_proposal_ref,request.original_ref,start_ref)
    if (start.proposal_ref!=request.growth_proposal_ref or start.proposal_digest!=proposal_original.original_digest
            or start.completed_trial_ref!=request.original_ref or start.start_ref!=start_ref):
        raise ValueError("General trial completion has no unique original proposal/start/completed-ref binding")
    _require_general_trial_derivation_budget_v1(db,readers,read,start)
    roots,observations,costs,_=_general_trial_terminal_evidence_v1(readers,db,read,start,request.settled_progress_ref)
    trial=GeneralGrowthTrialOriginalV1(request.growth_proposal_ref,start_ref,(request.settled_progress_ref,),roots,observations,costs,True)
    validate_current_general_growth_completed_trial_v1(readers,db,read,start,trial)
    return {"general_growth_trial":trial,"trial_start_original":start_original}


def _record_general_verified_input_after_cas_v1(db,*,issuer,namespace,original_ref,producing_operation_id,kind,value):
    from .d01_production_operations_v1 import TABLE,SIGN_KIND,GrowthIntentOriginalV1,GrowthCounterevidenceOriginalV1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime_contracts import canonical_serialize
    kinds={"general_growth_intent_v1":GeneralGrowthIntentOriginalV1,"general_growth_trial_start_v1":GeneralGrowthTrialStartV1,
        "general_growth_trial_v1":GeneralGrowthTrialOriginalV1,"growth_proposal":GrowthIntentOriginalV1,
        "growth_counterevidence":GrowthCounterevidenceOriginalV1}
    if kind not in kinds or type(value)is not kinds[kind] or not db.in_transaction:
        raise TypeError("actual same-CAS General recorder requires its closed verified input kind")
    encoded=canonical_serialize(plain_v1(value));digest=canonical_digest(plain_v1(value))
    if kind in {"general_growth_intent_v1","general_growth_trial_start_v1"}:
        roots=tuple(sorted({version.key.token for version in value.source_versions if version.key.type_name=="memory.source"}))
    elif kind=="general_growth_trial_v1":roots=tuple(sorted(set(value.evidence_source_refs)))
    else:roots=tuple(sorted(set((*value.evidence_source_refs,*(value.counterevidence_source_refs if kind=="growth_counterevidence" else())))))
    source_refs_json=canonical_serialize(roots)
    expected=(kind,producing_operation_id,encoded,digest,issuer._signer.sign(SIGN_KIND,encoded),source_refs_json)
    current=db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM "+TABLE+
        " WHERE bot=? AND persona=? AND original_ref=?",(*namespace.as_tuple,original_ref)).fetchone()
    if current is not None:
        if tuple(current)!=expected:raise ValueError("General immutable original cannot reset its start/intent/trial/producer")
    else:
        db.execute("INSERT INTO "+TABLE+"(bot,persona,original_ref,kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (*namespace.as_tuple,original_ref,*expected))
    return ProductionOriginalRefV1("d01."+kind,original_ref,digest)


def freeze_current_general_growth_after_commit_v1(readers,db,*,frame,producing_operation_id,request,witness,receipt):
    from .domain_production_commit_v1 import require_general_growth_after_cas_witness_v1
    provenance=require_general_growth_after_cas_witness_v1(witness,db=db,frame=frame,
        producing_operation_id=producing_operation_id,request=request,receipt=receipt,
        operation_kind="freeze_general_growth_intent_v1")
    expected={"general_growth_intent","growth_proposal","growth_counterevidence","semantic_interpretation"}
    if set(provenance)!=expected:raise ValueError("General freeze lost its actual pre-CAS verified provenance")
    namespace=frame.envelope.authority.namespace
    outputs=[]
    for kind,ref,key in (("growth_proposal",request.growth_proposal_ref,"growth_proposal"),
            ("growth_counterevidence",request.counterevidence_query_ref,"growth_counterevidence"),
            ("general_growth_intent_v1",request.general_growth_intent_ref,"general_growth_intent")):
        outputs.append(_record_general_verified_input_after_cas_v1(db,issuer=readers.issuer,namespace=namespace,
            original_ref=ref,producing_operation_id=producing_operation_id,kind=kind,value=provenance[key]))
    return tuple(outputs)


def start_current_general_growth_trial_after_commit_v1(readers,db,*,frame,producing_operation_id,request,witness,receipt):
    from .domain_production_commit_v1 import require_general_growth_after_cas_witness_v1
    from dataclasses import fields
    provenance=require_general_growth_after_cas_witness_v1(witness,db=db,frame=frame,
        producing_operation_id=producing_operation_id,request=request,receipt=receipt,
        operation_kind="register_general_growth_trial_start_v1")
    if set(provenance)!={"general_growth_trial_admission"}:
        raise ValueError("General trial start lost its pre-CAS verified admission")
    admission=provenance["general_growth_trial_admission"]
    if type(admission)is not GeneralGrowthTrialAdmissionV1:
        raise TypeError("actual fixed General trial admission required")
    values={field.name:getattr(admission,field.name)for field in fields(admission)if field.name!="schema"}
    if admission.producing_operation_id!=producing_operation_id or admission.start_ref!=request.original_ref:
        raise ValueError("General start cannot borrow another actual W01 producing receipt")
    start=GeneralGrowthTrialStartV1(**values,producing_receipt_digest=canonical_digest(receipt))
    return _record_general_verified_input_after_cas_v1(db,issuer=readers.issuer,namespace=frame.envelope.authority.namespace,
        original_ref=request.original_ref,producing_operation_id=producing_operation_id,
        kind="general_growth_trial_start_v1",value=start)


def derive_current_general_growth_trial_from_adopted_progress_v1(readers,db,*,frame,producing_operation_id,request,witness,receipt):
    from .domain_production_commit_v1 import require_general_growth_after_cas_witness_v1
    provenance=require_general_growth_after_cas_witness_v1(witness,db=db,frame=frame,
        producing_operation_id=producing_operation_id,request=request,receipt=receipt,
        operation_kind="derive_general_growth_trial_v1")
    if set(provenance)!={"general_growth_trial","trial_start_original"}:
        raise ValueError("General trial completion lost exact pre-CAS terminal/cost/clock proof")
    trial=provenance["general_growth_trial"]
    if type(trial)is not GeneralGrowthTrialOriginalV1 or trial.growth_proposal_ref!=request.growth_proposal_ref:
        raise TypeError("actual General completed trial belongs to another declaration")
    return _record_general_verified_input_after_cas_v1(db,issuer=readers.issuer,namespace=frame.envelope.authority.namespace,
        original_ref=request.original_ref,producing_operation_id=producing_operation_id,kind="general_growth_trial_v1",value=trial)


def validate_general_growth_outcome_followup_v1(db,*,frame,request,installed_readers):
    return derive_current_general_growth_trial_v1(installed_readers,db,frame,request)


def stage_freeze_current_general_growth_in_transaction_v1(db,*,frame,request,installed_readers):
    from ..domains.d01.production_operations_v1 import stage_result_v1
    provenance=validate_current_general_growth_freeze_v1(installed_readers,db,frame,request)
    return stage_result_v1(frame,"d01","freeze_general_growth_intent_v1",request,provenance=provenance,
        receiver_events=(("d01","general_growth_intent_available_for_future_trial"),))


def stage_register_current_general_growth_trial_start_in_transaction_v1(db,*,frame,request,installed_readers):
    from ..domains.d01.production_operations_v1 import stage_result_v1
    admission=validate_current_general_growth_trial_start_v1(installed_readers,db,frame,request)
    return stage_result_v1(frame,"d01","register_general_growth_trial_start_v1",request,
        provenance={"general_growth_trial_admission":admission},
        receiver_events=(("d01","general_growth_trial_start_available_for_observation"),))


def stage_derive_current_general_growth_trial_in_transaction_v1(db,*,frame,request,installed_readers):
    from ..domains.d01.production_operations_v1 import stage_result_v1
    provenance=derive_current_general_growth_trial_v1(installed_readers,db,frame,request)
    return stage_result_v1(frame,"d01","derive_general_growth_trial_v1",request,provenance=provenance,
        receiver_events=(("d01","general_growth_trial_completed_for_adoption"),))


def stage_adopt_current_general_growth_in_transaction_v1(db,*,frame,request,installed_readers):
    from ..domains.d01.production_operations_v1 import (AdoptCurrentGrowthRequestV1,compile_adopt_current_growth_v1,
        stage_result_v1,PersonaDomain)
    import json
    from .d01_production_operations_v1 import waiting_stage_v1,MissingProductionOriginalV1
    try:
        inputs,general_provenance=read_current_general_growth_v1(installed_readers,db,frame,request)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame,"d01","adopt_general_growth_v1",request,missing)
    old_request=AdoptCurrentGrowthRequestV1(request.growth_proposal_ref,request.trigger_original_ref,
        request.trial_original_refs,request.counterevidence_query_ref)
    stage=compile_adopt_current_growth_v1(frame,old_request,inputs)
    general_provenance["growth"]=json.loads(stage.original_payload_json)["provenance"]
    writes=tuple(write for proposal in stage.proposals for write in proposal.typed_writes)
    return stage_result_v1(frame,"d01","adopt_general_growth_v1",request,writes=writes,provenance=general_provenance,
        contribution_keys=tuple(key for proposal in stage.proposals for key in proposal.contribution_keys),
        receiver_events=(("d08","persona_growth_requires_commitment_reevaluation"),("d10","persona_growth_requires_life_reevaluation"))if writes else(),
        costs=stage.paid_cost_originals,coverage=stage.coverage,missing=stage.missing_inputs,continuation=stage.continuation_ref,
        jobs=stage.jobs,proposal_schema="d01.proposal.v1"if writes else None,
        proposal_hash=PersonaDomain().descriptor.request_schema_hash if writes else None)


from ..graph_types import AtomKey,owner_grant_key

_GENERAL_OWNER_OPERATIONS_V1=frozenset({"freeze_general_growth_intent_v1","register_general_growth_trial_start_v1",
    "derive_general_growth_trial_v1","adopt_general_growth_v1"})

def general_growth_owner_metadata_retains_path_v1(table,kind,path):
    """Fixed metadata projection used only by the registered General Owner task."""
    if not path:return True
    if table=="graph_d01_production_inputs_v1":
        if kind=="growth_proposal":return path[0]!="replacement_claim"
        if kind in {"growth_counterevidence","general_growth_intent_v1","general_growth_trial_start_v1","general_growth_trial_v1"}:
            return True
        raise ValueError("unregistered General signed D01 metadata kind")
    if table=="graph_d07_execution_originals_v1":
        if kind=="prepared":return path[0]not in {"frozen_json","read_rows","request","choice"}
        if kind=="adopted":return path[0]!="meaningful_unknowns"
        if kind=="semantic_question":return path[0]!="question"
        raise ValueError("unregistered General signed D07 metadata kind")
    if table not in {"graph_atoms","graph_history"}:raise ValueError("unregistered General graph metadata family")
    if kind=="activation":return path[0]in {"schema","plan_id","plan_version","head_id","owner_guard"}
    if kind=="persona_plan":
        if path[0]in {"schema","plan_id","version","owner_guard"}:return True
        return path[0]=="blocks"and(len(path)<=2 or path[2]in {"block_id","kind","plasticity"})
    if kind=="life_progress_provenance":return True
    fields={
        "interpretation":{"schema","interpretation_id","question_key","source_refs","stance","evidence_status","current","observed_at","valid_until"},
        "goal":{"goal_id","revision","state","reason_refs"},
        "cancellation":{"action_id","action_revision","action_digest","activity_id","attempt_id","effect_id","cancel_epoch","state","actor","source_refs","operation_id"},
        "action":{"action_id","revision","goal_ref","commitment_refs","target_ref","action_kind","purpose","identity","source_refs"},
        "outcome":{"action_id","activity_id","effect_id","attempt_id","observation_refs","cost_refs","source_refs","result_level"},
        "life_progress":{"schema","project_ref","recipe_ref","activity_id","effect_id","artifact_ref","terminal_ref","source_refs","receipt_refs","reality","step","role_start","role_end"},
        "cost":{"schema","bot_id","persona_id","activity_id","bundle_operation_id","effect_id","settlement_id","lease_id","cost_operation_id","budget_operation_id","budget_phase","prior_unknown_ref","execution_revoked"},
        "job":{"schema","bot_id","persona_id","activity_id","operation_id","effect_id","job_id","phase","work_kind","deadline_utc","parent_budget_lease_ref","cancel_epoch","lease_holder","lease_expires_utc","fence"}}
    if kind not in fields:raise ValueError("unregistered General graph metadata mode")
    return path[0]in fields[kind]


def validate_general_growth_owner_metadata_fields_v1(table,kind,projection,fields_seen):
    """Validate the actual original field set; its whole digest comes from EOF."""
    from dataclasses import fields
    from .d01_production_operations_v1 import GrowthIntentOriginalV1,GrowthCounterevidenceOriginalV1
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
    types={
        ("graph_d01_production_inputs_v1","growth_proposal"):GrowthIntentOriginalV1,
        ("graph_d01_production_inputs_v1","growth_counterevidence"):GrowthCounterevidenceOriginalV1,
        ("graph_d01_production_inputs_v1","general_growth_intent_v1"):GeneralGrowthIntentOriginalV1,
        ("graph_d01_production_inputs_v1","general_growth_trial_start_v1"):GeneralGrowthTrialStartV1,
        ("graph_d01_production_inputs_v1","general_growth_trial_v1"):GeneralGrowthTrialOriginalV1,
        ("graph_d07_execution_originals_v1","prepared"):D07GeneralGrowthPreparedV1,
        ("graph_d07_execution_originals_v1","semantic_question"):D07GeneralGrowthQuestionV1}
    if (table,kind)in types:
        expected={field.name for field in fields(types[table,kind])}
    elif(table,kind)==("graph_d07_execution_originals_v1","adopted"):
        expected={"schema","interpretation_ref","interpretation_revision","interpretation_value_digest",
            "adoption_operation_id","graph_receipt_digest","prepared_digest","actual_result_digest","question_scope","supporting_refs","meaningful_unknowns"}
        if projection.get("schema")!="d07.actual-cognition-adoption.v1":raise ValueError("General metadata adoption schema differs")
    else:raise ValueError("unregistered General signed metadata schema")
    if set(fields_seen)!=expected:raise ValueError("General metadata original does not match its exact actual writer")
    if table=="graph_d07_execution_originals_v1"and kind=="prepared"and projection.get("schema")!="d07.general-growth-prepared.v1":
        raise ValueError("General metadata cannot borrow a generic/Method/Reflection prepared original")
    return projection


def _general_plan_signed_metadata_v1(db,namespace,issuer,table,ref,kind,originals):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_signed_metadata_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .domain_background_read_v3 import _active_v3
    if _active_v3(db)is not None:
        from .domain_background_read_v3 import read_bound_background_general_growth_input_metadata_v1
        handled,result=read_bound_background_general_growth_input_metadata_v1(db,table=table,namespace=namespace,original_ref=ref,kind=kind)
        if not handled:raise ValueError("actual General derive-child signed metadata binding required")
    else:
        result=read_bound_current_general_owner_signed_metadata_v1(db,namespace=namespace,issuer=issuer,
            table=table,original_ref=ref,kind=kind)
    if result is None:raise MissingProductionOriginalV1("actual_general_metadata_original:"+kind+":"+ref)
    value,original=result;originals.append(original.original_ref)
    return value,original


def _general_plan_head_metadata_v1(db,namespace,key,kind,keys):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_graph_metadata_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..graph_types import AtomKey
    if type(key)is str:key=AtomKey.from_token(key)
    from .domain_background_read_v3 import _active_v3
    if _active_v3(db)is not None:
        from .domain_background_read_v3 import read_bound_background_general_growth_graph_metadata_v1
        handled,result=read_bound_background_general_growth_graph_metadata_v1(db,namespace=namespace,key=key,kind=kind)
        if not handled:raise ValueError("actual General derive-child graph metadata binding required")
    else:result=read_bound_current_general_owner_graph_metadata_v1(db,namespace=namespace,key=key,kind=kind)
    if result is None or not result.valid:raise MissingProductionOriginalV1("actual_general_metadata_head:"+key.token)
    keys.append(key);return result


def _general_plan_counter_metadata_v1(db,namespace,scope,roots,keys,originals):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    rows,complete=read_bound_current_general_owner_type_metadata_v1(db,namespace=namespace,
        type_id="d07.current_interpretation.v1",limit=129)
    if not complete or len(rows)>128:raise MissingProductionOriginalV1("complete_current_general_growth_counter_inventory")
    for atom in rows:
        if atom.valid and atom.value["question_key"]==scope and atom.value["current"]is True:
            roots.extend(atom.value["source_refs"]);keys.append(atom.key);originals.append(atom.key.token)


def _general_plan_declared_start_v1(db,namespace,issuer,start_ref,roots,keys,originals):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_production_operations_v1 import TABLE
    raw,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,start_ref,"general_growth_trial_start_v1",originals)
    start=decode_typed_production_value_v1(raw,GeneralGrowthTrialStartV1)
    keys.extend((start.base_persona_version.key,start.planned_head.key))
    keys.extend(version.key for version in start.source_versions)
    roots.extend(version.key.token for version in start.source_versions if version.key.type_name=="memory.source")
    originals.extend(original.original_ref for original in start.source_originals)
    keys.extend(AtomKey.from_token(ref)for ref in start.cancel_refs)
    if start.planned_life_plan_original is not None:originals.append(start.planned_life_plan_original.original_ref)
    originals.extend((start.producing_operation_id,start.plan_adoption_operation_id))
    return start




def _general_plan_actual_cost_metadata_v1(db,namespace,start,keys,originals):
    rows,complete=_general_cost_metadata_rows_v1(db,namespace)
    if not complete or len(rows)>128:
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1("complete_general_trial_actual_cost_inventory")
    for atom in rows:
        if atom.valid and(atom.value["activity_id"],atom.value["effect_id"])==(start.activity_id,start.effect_id):
            keys.append(atom.key);originals.append(atom.key.token)


def _general_cost_metadata_rows_v1(db,namespace):
    from .domain_background_read_v3 import _active_v3
    if _active_v3(db)is not None:
        from .domain_background_read_v3 import read_bound_background_general_growth_type_metadata_v1
        handled,result=read_bound_background_general_growth_type_metadata_v1(db,namespace=namespace,type_id="runtime.cost_settlement",limit=129)
        if not handled:raise ValueError("actual General derive-child cost metadata binding required")
        return result
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    return read_bound_current_general_owner_type_metadata_v1(db,namespace=namespace,type_id="runtime.cost_settlement",limit=129)


def _general_plan_life_readset_v1(db,namespace,progress_ref,action_ref,roots,keys,originals):
    from .d10_life_progress_provenance_v1 import (LifeProgressProvenanceV1,PROVENANCE_TYPE,
        life_progress_auxiliary_key_v1,life_progress_read_keys_v1)
    from .d11_life_fact_provenance_v1 import (life_fact_auxiliary_key_v1,PROVENANCE_TYPE as END_PROOF,
        ELIGIBILITY_TYPE as END_ELIGIBILITY)
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    from .d11_life_contract_v1 import life_mutation_id_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    fact=AtomKey.from_token(progress_ref)
    proof_key=life_progress_auxiliary_key_v1(fact,PROVENANCE_TYPE)
    metadata=_general_plan_head_metadata_v1(db,namespace,proof_key,"life_progress_provenance",keys)
    proof=decode_typed_production_value_v1(metadata.value,LifeProgressProvenanceV1)
    if proof.fact_ref!=progress_ref:raise ValueError("General Life metadata proof belongs to another actual fact")
    b=proof.terminal_provenance.binding
    facts=(AtomKey.from_token(b.artifact_ref),life_role_segment_key_v1(b,"start"),life_role_segment_key_v1(b,"end"))
    keys.extend((*life_progress_read_keys_v1(b),*facts,*(life_fact_auxiliary_key_v1(item,kind)
        for item in facts for kind in (END_PROOF,END_ELIGIBILITY)),
        *life_outcome_read_keys_v1(b,action_ref),
        *(AtomKey.from_token(row.ref)for row in proof.terminal_provenance.reads)))
    # The signed start pins the exact action; this remains metadata, never an execution grant.
    roots.extend(proof.terminal_provenance.source_family_refs)
    originals.extend((b.prepared_original_ref,b.plan_original_ref,b.artifact_ref,
        life_mutation_id_v1(b,"claim"),life_mutation_id_v1(b,"terminal")))
    return b

def read_plan_freeze_current_general_growth_v1(db,*,namespace,request,issuer):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d07_execution_v1 import TABLE
    from .current_method_learning_read_v3 import read_bound_current_general_owner_prepared_for_adoption_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    if type(request)is not FreezeCurrentGeneralGrowthRequestV1:raise TypeError("exact General freeze plan request required")
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[request.trigger_original_ref]
    semantic=_general_plan_head_metadata_v1(db,namespace,request.interpretation_ref,"interpretation",keys)
    adoption,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.interpretation_ref,"adopted",originals)
    located=read_bound_current_general_owner_prepared_for_adoption_v1(db,namespace=namespace,issuer=issuer,
        prepared_digest=adoption["prepared_digest"])
    if located is None:raise MissingProductionOriginalV1("unique_actual_general_prepared_for_adopted_cognition")
    prepared,prepared_original=located;originals.append(prepared_original.original_ref)
    question,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,prepared["semantic_question_ref"],"semantic_question",originals)
    if (semantic.value["question_key"]!=question["question_key"] or adoption["question_scope"]!=question["question_key"]
            or tuple(question["support_source_refs"])!=tuple(prepared["support_source_refs"])
            or tuple(question["context_source_refs"])!=tuple(prepared["context_source_refs"])):
        raise ValueError("General freeze metadata lost its actual question/support/context scope")
    roots.extend((*question["support_source_refs"],*question["context_source_refs"]))
    originals.extend(item["original_ref"]for item in question["context_original_refs"])
    _general_plan_counter_metadata_v1(db,namespace,question["question_key"],roots,keys,originals)
    return production_read_plan_v1(("d01.persona_activation.v1","d01.persona_plan.v1","d01.persona_revision.v1",
        "d01.growth_contribution.v1","d07.current_interpretation.v1"),keys,roots,originals)


def read_plan_register_current_general_growth_trial_start_v1(db,*,namespace,request,issuer):
    from .d01_production_operations_v1 import TABLE,production_read_plan_v1
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    if type(request)is not RegisterCurrentGeneralGrowthTrialStartRequestV1:raise TypeError("exact General trial start plan request required")
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[]
    wrapper,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.general_growth_intent_ref,"general_growth_intent_v1",originals)
    proposal,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.growth_proposal_ref,"growth_proposal",originals)
    roots.extend((*wrapper["support_source_refs"],*wrapper["context_source_refs"]))
    planned=_general_plan_head_metadata_v1(db,namespace,request.planned_head.key,"action",keys)
    roots.extend(planned.value["source_refs"])
    goal_key=AtomKey(planned.key.owner,"d08.goal.v1",planned.value["goal_ref"])
    cancel_key=AtomKey(planned.key.owner,"d08.action_cancellation.v1",planned.value["action_id"])
    goal=_general_plan_head_metadata_v1(db,namespace,goal_key,"goal",keys)
    cancellation=_general_plan_head_metadata_v1(db,namespace,cancel_key,"cancellation",keys)
    roots.extend((*goal.value["reason_refs"],*cancellation.value["source_refs"]))
    if request.life_plan_original_ref is not None:originals.append(request.life_plan_original_ref)
    # Actual execution metadata is needed to reject a retroactive start.
    types=("d01.persona_activation.v1","d01.persona_plan.v1","d08.action_outcome.v1","d10.life_progress.v1","runtime.job")
    for type_id in("d08.action_outcome.v1","d10.life_progress.v1","runtime.job"):
        rows,complete=read_bound_current_general_owner_type_metadata_v1(db,namespace=namespace,type_id=type_id,limit=129)
        if not complete or len(rows)>128:
            from .d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1("complete_general_trial_start_execution_inventory:"+type_id)
    return production_read_plan_v1(types,keys,roots,originals)


def read_plan_derive_current_general_growth_trial_v1(db,*,namespace,request,issuer):
    from .d01_production_operations_v1 import TABLE,production_read_plan_v1
    if type(request)is not DeriveCurrentGeneralGrowthTrialRequestV1:raise TypeError("exact General trial derive plan request required")
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[]
    wrapper,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.general_growth_intent_ref,"general_growth_intent_v1",originals)
    _general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.growth_proposal_ref,"growth_proposal",originals)
    if request.original_ref not in wrapper["required_trial_refs"]:raise ValueError("General completed trial is outside its original declaration")
    index=wrapper["required_trial_refs"].index(request.original_ref)
    start=_general_plan_declared_start_v1(db,namespace,issuer,wrapper["trial_start_refs"][index],roots,keys,originals)
    _general_plan_actual_cost_metadata_v1(db,namespace,start,keys,originals)
    kind="outcome"if start.project_ref is None else"life_progress"
    outcome=_general_plan_head_metadata_v1(db,namespace,request.settled_progress_ref,kind,keys)
    roots.extend(outcome.value.get("source_refs",()))
    originals.append(outcome.key.token)
    if start.project_ref is None:originals.extend(outcome.value["observation_refs"])
    else:
        originals.extend((outcome.value["artifact_ref"],outcome.value["terminal_ref"],*outcome.value["receipt_refs"]))
        _general_plan_life_readset_v1(db,namespace,outcome.key.token,start.planned_head.key.token,roots,keys,originals)
    return production_read_plan_v1(("d01.persona_activation.v1","d01.persona_plan.v1","runtime.cost_settlement"),keys,roots,originals)


def read_plan_adopt_current_general_growth_v1(db,*,namespace,request,issuer):
    from .d01_production_operations_v1 import TABLE,production_read_plan_v1
    if type(request)is not AdoptCurrentGeneralGrowthRequestV1:raise TypeError("exact General adopter plan request required")
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[request.trigger_original_ref]
    wrapper,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.general_growth_intent_ref,"general_growth_intent_v1",originals)
    proposal,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.growth_proposal_ref,"growth_proposal",originals)
    _general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,request.counterevidence_query_ref,"growth_counterevidence",originals)
    if tuple(wrapper["required_trial_refs"])!=request.trial_original_refs:raise ValueError("General adopter plan requires its full exact nonempty trial declaration")
    roots.extend((*wrapper["support_source_refs"],*wrapper["context_source_refs"]))
    for trial_ref,start_ref in zip(wrapper["required_trial_refs"],wrapper["trial_start_refs"],strict=True):
        start=_general_plan_declared_start_v1(db,namespace,issuer,start_ref,roots,keys,originals)
        _general_plan_actual_cost_metadata_v1(db,namespace,start,keys,originals)
        trial,_=_general_plan_signed_metadata_v1(db,namespace,issuer,TABLE,trial_ref,"general_growth_trial_v1",originals)
        roots.extend(trial["evidence_source_refs"])
        for outcome_ref in trial["settled_outcome_refs"]:
            kind="life_progress"if AtomKey.from_token(outcome_ref).type_name=="d10.life_progress.v1"else"outcome"
            outcome=_general_plan_head_metadata_v1(db,namespace,outcome_ref,kind,keys);originals.append(outcome.key.token)
            if kind=="life_progress":_general_plan_life_readset_v1(db,namespace,outcome.key.token,start.planned_head.key.token,roots,keys,originals)
        originals.extend(item["original_ref"]for item in(*trial["actual_observation_refs"],*trial["actual_cost_refs"]))
    scope="d01.growth:"+proposal["target_block"]+":"+proposal["change_kind"]
    _general_plan_counter_metadata_v1(db,namespace,scope,roots,keys,originals)
    return production_read_plan_v1(("d01.persona_activation.v1","d01.persona_plan.v1","d01.persona_revision.v1",
        "d01.growth_contribution.v1","d07.current_interpretation.v1","runtime.cost_settlement"),keys,roots,originals)


def read_current_general_growth_start_metadata_inventory_v1(db,*,namespace,issuer):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_start_metadata_inventory_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .domain_background_read_v3 import _active_v3
    if _active_v3(db)is not None:
        from .domain_background_read_v3 import read_bound_background_general_growth_start_metadata_inventory_v1
        handled,result=read_bound_background_general_growth_start_metadata_inventory_v1(db,namespace=namespace,issuer=issuer,limit=129)
        if not handled:raise ValueError("actual General derive-child start metadata census binding required")
        rows,complete=result
    else:rows,complete=read_bound_current_general_owner_start_metadata_inventory_v1(db,namespace=namespace,issuer=issuer,limit=129)
    if not complete or len(rows)>128:raise MissingProductionOriginalV1("complete_registered_general_trial_start_inventory")
    return rows


def validate_current_general_owner_metadata_profile_v1(table,column,key_columns,key,profile,namespace):
    if type(profile)is not tuple or len(profile)!=2 or profile[0]!=table:
        raise ValueError("General metadata uses its fixed table/kind profile")
    kind=profile[1]
    if table=="graph_d01_production_inputs_v1":
        if (column!="payload_json"or tuple(key_columns)!=("bot","persona","original_ref")
                or tuple(key)[:2]!=namespace.as_tuple or kind not in {"growth_proposal","growth_counterevidence",
                    "general_growth_intent_v1","general_growth_trial_start_v1","general_growth_trial_v1"}):
            raise ValueError("General D01 metadata full PK/kind differs")
    elif table=="graph_d07_execution_originals_v1":
        if (column!="payload_json"or tuple(key_columns)!=("bot","persona","kind","original_ref")
                or tuple(key)[:2]!=namespace.as_tuple or key[2]!=kind or kind not in {"prepared","adopted","semantic_question"}):
            raise ValueError("General D07 metadata full PK/kind differs")
    elif table=="graph_atoms":
        types={"activation":"d01.persona_activation.v1","persona_plan":"d01.persona_plan.v1",
            "interpretation":"d07.current_interpretation.v1","goal":"d08.goal.v1","cancellation":"d08.action_cancellation.v1","action":"d08.action_intent.v1","outcome":"d08.action_outcome.v1",
            "life_progress":"d10.life_progress.v1","life_progress_provenance":"d10.life_progress_provenance.v1",
            "cost":"runtime.cost_settlement","job":"runtime.job"}
        if column!="value"or tuple(key_columns)!=("token","bot","persona")or tuple(key)[1:]!=namespace.as_tuple:
            raise ValueError("General graph metadata full PK differs")
        atom=AtomKey.from_token(key[0])
        if kind not in types or atom.type_name!=types[kind]or NamespaceId.from_key(atom)!=namespace:
            raise ValueError("General graph metadata profile crossed actual namespace/type")
    else:raise ValueError("unregistered General metadata table")
    return profile

def retain_current_general_owner_metadata_path_v1(profile,path):
    return general_growth_owner_metadata_retains_path_v1(profile[0],profile[1],path)


from weakref import WeakKeyDictionary,ref as weakref_v1
_GENERAL_OWNER_METADATA_ISSUER_V1=object()
_GENERAL_OWNER_METADATA_RECORDS_V1=WeakKeyDictionary()


def _reserve_actual_general_metadata_peak_v1(reader,extra):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,reserve_current_general_owner_metadata_peak_v1
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(reader)is _MethodLearningReadV3:
        reserve_current_general_owner_metadata_peak_v1(reader,extra=extra)
    elif type(reader)is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
        require_current_general_growth_trial_metadata_reader_v1(reader)
        reader.reserve_heap_v3(extra=extra)
    else:raise TypeError("General metadata peak belongs to its exact actual Work")

class GeneralOwnerGraphMetadataV1:
    def __init__(self,issuer,task,key,revision,valid,payload_digest,value):
        if issuer is not _GENERAL_OWNER_METADATA_ISSUER_V1:raise TypeError("actual General metadata task issuer required")
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        _reserve_actual_general_metadata_peak_v1(task.reader,_container_bytes_v3(value))
        self.key,self.revision,self.valid,self.payload_digest=key,revision,bool(valid),payload_digest
        self._frozen_value=_freeze_value_v3(value);self.task=task
        _GENERAL_OWNER_METADATA_RECORDS_V1[self]=(weakref_v1(task),weakref_v1(task.reader),weakref_v1(task.reader.operation),key,revision,bool(valid),payload_digest,self._frozen_value)
    def require_for_v1(self,reader):
        expected=(weakref_v1(self.task),weakref_v1(reader),weakref_v1(reader.operation),self.key,self.revision,self.valid,self.payload_digest,self._frozen_value)
        if _GENERAL_OWNER_METADATA_RECORDS_V1.get(self)!=expected or self.task.reader is not reader:
            raise ValueError("General metadata record crossed its actual originating Work")
        self.task.require_reader_v1();return self
    @property
    def value(self):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        self.require_for_v1(self.task.reader)
        _reserve_actual_general_metadata_peak_v1(self.task.reader,_container_bytes_v3(self._frozen_value))
        return _detach_value_v3(self._frozen_value)

class _GeneralOwnerMetadataTaskV1:
    """One actual Method Work quantum per fixed metadata fragment or row."""
    def __init__(self,reader,identity):
        self.reader,self.identity=reader,identity;self.phase="point";self.complete=False;self.result=None
        self.column=None;self.rows=[];self.cursor=None;self.child=None;self.metadata=None;self.value=None
        self.require_reader_v1()
        if type(identity)is not tuple or not identity:raise ValueError("General metadata requires its closed selector")
        if identity[0]=="signed":
            if len(identity)!=4:raise ValueError("General signed metadata selector differs")
            _,self.table,self.kind,self.original_ref=identity
            allowed={("graph_d01_production_inputs_v1",kind)for kind in("growth_proposal","growth_counterevidence",
                "general_growth_intent_v1","general_growth_trial_start_v1","general_growth_trial_v1")}|{
                ("graph_d07_execution_originals_v1",kind)for kind in("prepared","adopted","semantic_question")}
            if(self.table,self.kind)not in allowed:raise ValueError("General signed metadata escaped the closed input families")
        elif identity[0]=="graph":
            if len(identity)!=3:raise ValueError("General graph metadata selector differs")
            _,self.kind,token=identity;self.key=AtomKey.from_token(token)
            kinds={"activation":"d01.persona_activation.v1","persona_plan":"d01.persona_plan.v1",
                "interpretation":"d07.current_interpretation.v1","goal":"d08.goal.v1","cancellation":"d08.action_cancellation.v1","action":"d08.action_intent.v1",
                "outcome":"d08.action_outcome.v1","life_progress":"d10.life_progress.v1",
                "life_progress_provenance":"d10.life_progress_provenance.v1","cost":"runtime.cost_settlement","job":"runtime.job"}
            if self.kind not in kinds or self.key.type_name!=kinds[self.kind]or NamespaceId.from_key(self.key)!=reader.namespace:
                raise ValueError("General graph metadata type/namespace differs")
        elif identity[0]=="type":
            if len(identity)!=3 or identity[2]!=129:raise ValueError("General type metadata keeps its original 128-row complete bound")
            _,self.type_id,_=identity
            kinds={"d07.current_interpretation.v1":"interpretation","d08.action_outcome.v1":"outcome",
                "d10.life_progress.v1":"life_progress","runtime.job":"job","runtime.cost_settlement":"cost"}
            if self.type_id not in kinds:raise ValueError("unregistered General type metadata inventory")
            self.kind=kinds[self.type_id]
        elif identity[0]=="starts":
            if identity!=("starts",129):raise ValueError("General start census keeps its complete original bound")
        elif identity[0]=="prepared_for_adoption":
            if len(identity)!=2 or len(identity[1])!=64:raise ValueError("General adopted cognition requires its actual prepared digest")
        else:raise ValueError("unregistered General metadata selector")
    def require_reader_v1(self,meter=None):
        from .current_method_learning_read_v3 import _MethodLearningReadV3
        if type(self.reader)is not _MethodLearningReadV3 or self.reader.operation_kind not in _GENERAL_OWNER_OPERATIONS_V1:
            raise ValueError("General metadata only uses its actual registered Owner Method Work")
        self.reader.require_current(meter=meter)
        return self.reader
    def require_signature_v1(self,column,signer,kind):
        from .d01_production_operations_v1 import SIGN_KIND
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        r=self.require_reader_v1()
        if (self.identity[0]!="signed"or self.table!="graph_d01_production_inputs_v1"or kind!=SIGN_KIND
                or signer is not r.graph._GraphCoordinator__d11_issuer._signer
                or column.owner is not r or column.table!=self.table or column.column!="payload_json"
                or column.key_columns!=("bot","persona","original_ref")
                or column.key!=(*r.namespace.as_tuple,self.original_ref)
                or column.signature!=self.metadata[-1]or column.signature_kind!=SIGN_KIND):
            raise ValueError("General raw HMAC column crossed its actual fixed input/task/signer")
        with runtime_storage_quantum_v3(r.db)as meter:self._require_header_v1(meter)
        return column
    def _require_header_v1(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.require_reader_v1(meter);ns=r.namespace
        if self.identity[0]=="signed":
            columns=("kind","producing_operation_id","payload_digest","signature")if self.table=="graph_d01_production_inputs_v1"else("kind","payload_digest","signature")
            where="bot=? AND persona=? AND original_ref=?"if self.table=="graph_d01_production_inputs_v1"else"bot=? AND persona=? AND kind=? AND original_ref=?"
            key=(*ns.as_tuple,self.original_ref)if self.table=="graph_d01_production_inputs_v1"else(*ns.as_tuple,self.kind,self.original_ref)
            current=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,columns,where,key)
        elif self.identity[0]=="graph":
            current=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(self.key.token,*ns.as_tuple))
        else:return
        if current!=self.metadata:raise ValueError("General metadata original head changed across its actual bounded EOF")
    def _child_task_v1(self,reader,identity):
        return _GeneralOwnerMetadataTaskV1(reader,identity)
    def _column_v1(self,*,table,column,key_columns,key,kind,cell_id=None,signature_kind=None,signature=None):
        from .current_method_learning_read_v3 import prepare_current_general_owner_metadata_column_v1
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        cell=None if cell_id is None else begin_runtime_cell_read_v3(self.reader.db,cell_id,erasure_owner_ref=key[0])
        previous=self.reader.general_metadata_issuing_task
        self.reader.general_metadata_issuing_task=self
        try:
            return prepare_current_general_owner_metadata_column_v1(self.reader,table=table,column=column,
                key_columns=key_columns,key=key,profile=(table,kind),cell=cell,
                signer=self.reader.graph._GraphCoordinator__d11_issuer._signer if signature_kind is not None else None,
                signature_kind=signature_kind,signature=signature)
        finally:self.reader.general_metadata_issuing_task=previous
    def _finish_column_v1(self,column,reader,kind):
        from .current_method_learning_read_v3 import current_general_owner_metadata_column_value_v1
        return current_general_owner_metadata_column_value_v1(column)
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime_contracts import canonical_serialize
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        r=self.require_reader_v1(meter);ns=r.namespace;mode=self.identity[0]
        if self.complete:return True
        if mode=="type":
            if self.child is not None:
                if not self.child.advance(meter):return False
                if self.child.result is not None:self.rows.append(self.child.result)
                self.child=None;return False
            if len(self.rows)==129:self.result=(tuple(self.rows),False);self.complete=True;return True
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("token",),
                "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token",
                (*ns.as_tuple,self.type_id,self.cursor or""))
            if row is None:self.result=(tuple(self.rows),True);self.complete=True;return True
            self.cursor=row[0];self.child=self._child_task_v1(r,("graph",self.kind,row[0]));return False
        if mode=="starts":
            if self.child is not None:
                if not self.child.advance(meter):return False
                if self.child.result is not None:self.rows.append(self.child.result)
                self.child=None;return False
            if len(self.rows)==129:self.result=(tuple(self.rows),False);self.complete=True;return True
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d01_production_inputs_v1",("original_ref",),
                "bot=? AND persona=? AND kind='general_growth_trial_start_v1' AND original_ref>? ORDER BY original_ref",
                (*ns.as_tuple,self.cursor or""))
            if row is None:self.result=(tuple(self.rows),True);self.complete=True;return True
            self.cursor=row[0];self.child=self._child_task_v1(r,("signed","graph_d01_production_inputs_v1","general_growth_trial_start_v1",row[0]));return False
        if mode=="prepared_for_adoption":
            if self.child is None:
                matches=[];cursor=""
                for _ in range(2):
                    row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_execution_originals_v1",("original_ref",),
                        "bot=? AND persona=? AND kind='prepared' AND payload_digest=? AND original_ref>? ORDER BY original_ref",
                        (*ns.as_tuple,self.identity[1],cursor))
                    if row is None:break
                    matches.append(row[0]);cursor=row[0]
                if len(matches)!=1:self.complete=True;self.result=None;return True
                self.child=self._child_task_v1(r,("signed","graph_d07_execution_originals_v1","prepared",matches[0]));return False
            if not self.child.advance(meter):return False
            self.result=self.child.result;self.complete=True;return True
        if self.phase=="point":
            if mode=="signed":
                from .d01_production_operations_v1 import SIGN_KIND as D01_KIND
                columns=("kind","producing_operation_id","payload_digest","signature")if self.table=="graph_d01_production_inputs_v1"else("kind","payload_digest","signature")
                key_columns=("bot","persona","original_ref")if self.table=="graph_d01_production_inputs_v1"else("bot","persona","kind","original_ref")
                key=(*ns.as_tuple,self.original_ref)if len(key_columns)==3 else(*ns.as_tuple,self.kind,self.original_ref)
                self.metadata=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,columns,
                    " AND ".join(name+"=?"for name in key_columns),key)
                if self.metadata is None:self.complete=True;self.result=None;return True
                if self.metadata[0]!=self.kind:raise ValueError("General input metadata has another immutable registered kind")
                signature_kind=D01_KIND if self.table=="graph_d01_production_inputs_v1"else None
                self.column=self._column_v1(table=self.table,column="payload_json",key_columns=key_columns,key=key,
                    kind=self.kind,signature_kind=signature_kind,signature=self.metadata[-1])
            else:
                self.metadata=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(self.key.token,*ns.as_tuple))
                if self.metadata is None:self.complete=True;self.result=None;return True
                self.column=self._column_v1(table="graph_atoms",column="value",key_columns=("token","bot","persona"),
                    key=(self.key.token,*ns.as_tuple),kind=self.kind,cell_id=self.metadata[2])
            self.phase="bytes";return False
        if self.phase in {"bytes","producer"}:self._require_header_v1(meter)
        if self.phase=="bytes":
            if not self.column.advance(meter):return False
            value=self._finish_column_v1(self.column,r,self.kind)
            if mode=="signed":
                validate_general_growth_owner_metadata_fields_v1(self.table,self.kind,value,self.column.general_metadata_fields_seen)
                digest=self.metadata[-2]
                if self.column.sha256!=digest:raise ValueError("General signed metadata whole canonical EOF differs")
                if self.table=="graph_d07_execution_originals_v1":
                    from .d07_execution_v1 import SIGN_KIND as D07_KIND
                    r.graph._GraphCoordinator__d11_issuer._signer.verify(D07_KIND,
                        canonical_serialize((ns,self.kind,self.original_ref,digest)),self.metadata[-1])
                    prefix="d07."+self.kind
                else:
                    if self.column.signature_verified is not True:raise ValueError("General D01 metadata lacks original raw HMAC EOF")
                    prefix="d01."+self.kind
                    self.producing_operation_id=self.metadata[1];self.value=value;self.phase="producer";return False
                self.result=(_freeze_value_v3(value),ProductionOriginalRefV1(prefix,self.original_ref,digest));self.complete=True;return True
            self.result=GeneralOwnerGraphMetadataV1(_GENERAL_OWNER_METADATA_ISSUER_V1,self,self.key,
                self.metadata[0],self.metadata[1],self.column.canonical_digest,value)
            self.complete=True;return True
        if self.phase=="producer":
            producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
                (*ns.as_tuple,self.producing_operation_id))
            if producer is None or type(producer[3])is not int or producer[3]<1:
                raise ValueError("General immutable signed input has no actual positive W01 producing receipt")
            digest=self.metadata[-2]
            self.result=(_freeze_value_v3(self.value),ProductionOriginalRefV1("d01."+self.kind,self.original_ref,digest))
            self.value=None
            self.complete=True;return True
        raise ValueError("unregistered General metadata task phase")


def create_current_general_owner_metadata_task_v1(reader,identity):
    return _GeneralOwnerMetadataTaskV1(reader,identity)


class _GeneralBackgroundMetadataTaskV1(_GeneralOwnerMetadataTaskV1):
    def require_reader_v1(self,meter=None):
        from .domain_background_read_v3 import (BackgroundReadWorkV3,require_actual_background_attachment_owner_v3,
            require_current_general_growth_trial_metadata_reader_v1)
        if type(self.reader)is not BackgroundReadWorkV3:
            raise ValueError("General completion metadata requires its actual Background derive-child Work")
        require_actual_background_attachment_owner_v3(self.reader,db=self.reader.db)
        require_current_general_growth_trial_metadata_reader_v1(self.reader)
        if meter is not None:self.reader.require_data_current_v3(meter)
        return self.reader
    def _child_task_v1(self,reader,identity):
        return _GeneralBackgroundMetadataTaskV1(reader,identity)
    def _column_v1(self,*,table,column,key_columns,key,kind,cell_id=None,signature_kind=None,signature=None):
        from .domain_background_read_v3 import prepare_current_general_growth_trial_metadata_column_v1
        return prepare_current_general_growth_trial_metadata_column_v1(self.reader,table=table,column=column,
            key_columns=key_columns,key=key,kind=kind,cell_id=cell_id,signature_kind=signature_kind,signature=signature)
    def _finish_column_v1(self,column,reader,kind):
        from .domain_background_read_v3 import finish_current_general_growth_trial_metadata_column_v1
        return finish_current_general_growth_trial_metadata_column_v1(column,reader=reader,kind=kind)

def create_current_general_background_metadata_task_v1(reader,identity):
    if identity[0]=="prepared_for_adoption"or identity[0]=="type"and identity!=("type","runtime.cost_settlement",129):raise ValueError("General derive-child cannot borrow D07/fair/Owner producer metadata")
    return _GeneralBackgroundMetadataTaskV1(reader,identity)
