"""Pure Artifact locator composition from authenticated metadata projections."""
from dataclasses import dataclass
from ..graph_types import AtomKey,GraphVersion
from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionQueryCoverageV1
from .d01_production_operations_v1 import production_read_plan_v1
from .domain_production_erasure_v1 import decode_typed_production_value_v1

@dataclass(frozen=True,slots=True)
class ArtifactMetadataLocatorV3:
    family:str
    kind:str
    ref:str
    revision:int|None=None

class ArtifactMetadataLocatorNeededV3(Exception):
    def __init__(self,locator):
        if type(locator)is not ArtifactMetadataLocatorV3:raise TypeError("exact pure metadata locator required")
        self.locator=locator
        super().__init__(locator)

@dataclass(frozen=True,slots=True)
class ArtifactRecipeMetadataV3:
    """Values are data only. Each caller authenticates their actual same-Work EOF."""
    values:dict
    def need_v3(self,family,kind,ref,revision=None):
        locator=ArtifactMetadataLocatorV3(family,kind,ref,revision)
        if locator not in self.values:raise ArtifactMetadataLocatorNeededV3(locator)
        return self.values[locator]
    def graph_v3(self,ref):
        return self.need_v3("graph",AtomKey.from_token(ref).type_name,ref)
    def inventory_v3(self,type_name):
        return self.need_v3("inventory",type_name,type_name)
    def life_v3(self,kind,ref):
        return self.need_v3("life",kind,ref)
    def domain_v3(self,operation):
        return self.need_v3("domain","operation",operation)
    def domain_ref_v3(self,ref):
        return self.need_v3("domain","original_ref",ref)
    def job_v3(self,job):
        return self.need_v3("job","continuation",job)

def artifact_candidate_evidence_plan_from_metadata_v3(raw,*,preparation_original_digest):
    """Exact projection: read_versions/query_coverage/future_decision_ref/need/candidates.
    need keeps original/read_versions/query_coverage; every candidate keeps
    eligibility.originals/read_versions/query_coverage and price with those
    same three fields (price.original singular), or its actual null.
    """
    def typed(value,typ):return decode_typed_production_value_v1(value,typ)
    def versions(values):return tuple(typed(value,GraphVersion)for value in values)
    def coverage(values):return tuple(typed(value,ProductionQueryCoverageV1)for value in values)
    def evidence(original,value):
        return typed(original,ProductionOriginalRefV1),versions(value["read_versions"]),coverage(value["query_coverage"])
    need=raw["need"];evidences=[evidence(need["original"],need)]
    for candidate in raw["candidates"]:
        eligibility=candidate["eligibility"]
        evidences.extend(evidence(original,eligibility)for original in eligibility["originals"])
        price=candidate["price"]
        if price is not None:evidences.append(evidence(price["original"],price))
    from .d08_personal_candidate_v1 import personal_candidate_evidence_read_plan_v3
    return personal_candidate_evidence_read_plan_v3(read_versions=versions(raw["read_versions"]),
        query_coverage=coverage(raw["query_coverage"]),future_decision_ref=raw["future_decision_ref"],
        preparation_original_digest=preparation_original_digest,evidences=evidences)

def artifact_trial_plan_from_metadata_v3(trials):
    """Each actual trial/protocol/positive-parent locator is supplied separately."""
    from .d01_method_learning_v1 import method_trial_locator_inputs_v3
    types,keys,roots,originals=method_trial_locator_inputs_v3(trials)
    return production_read_plan_v1(types,keys,roots,originals)

def artifact_capacity_plan_from_metadata_v3(*,checkpoints,jobs):
    from .d10_project_checkpoint_v1 import project_capacity_locator_inputs_v3
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE
    keys,originals=project_capacity_locator_inputs_v3(
        ((version.key.token,valid)for version,valid in checkpoints),
        ((version.key.token,work_kind,job_id)for version,valid,work_kind,job_id in jobs if valid))
    return production_read_plan_v1((CHECKPOINT_TYPE,"runtime.job"),keys,(),originals)

def artifact_pair_plan_from_metadata_v3(*,goal_ref,experiments,shared_inputs):
    """Shared-input values must be the actual independently authenticated typed originals."""
    from ..domains.d01.method_learning_v1 import EXPERIMENT_TYPE
    from .method_pair_shared_input_v1 import MethodPairSharedInputOriginalV1
    keys=[];roots=[];originals=[];matches=[]
    for version,valid,value in experiments:
        if not valid or goal_ref not in(value["treatment_goal_ref"],value["baseline_goal_ref"]):continue
        shared=shared_inputs[version.key.token]
        if shared is None:continue
        if type(shared)is not MethodPairSharedInputOriginalV1:raise TypeError("actual typed method-pair shared input required")
        if shared.experiment_ref!=version.key.token:raise ValueError("actual pair metadata crossed experiment")
        matches.append(version.key.token)
        keys.extend((version.key,shared.common_source_head.key,shared.common_access_head.key))
        roots.append(shared.common_source_head.key.token)
        originals.extend((version.key.token,*(task.objective_ref for task in shared.tasks)))
        keys.extend(task.goal_head.key for task in shared.tasks)
    if len(matches)>1:raise ValueError("conflicting actual method pairs for the same Artifact task")
    return production_read_plan_v1((EXPERIMENT_TYPE,),keys,roots,originals)

def artifact_condition_plan_from_metadata_v3(*,goal_heads,interpretations):
    from ..domains.d07 import decode_method_condition_question_v1
    goals={version.key.token:value["revision"]for version,valid,value in goal_heads if valid}
    keys=[];roots=[];originals=[]
    for version,valid,value in interpretations:
        if not valid:continue
        scope=decode_method_condition_question_v1(value["question_key"])
        if scope is not None and goals.get(scope["goal_ref"])==scope["goal_revision"]:
            keys.append(version.key);roots.extend(value["source_refs"]);originals.append(version.key.token)
    return production_read_plan_v1((),keys,roots,originals)

def _merge_plans_v3(*plans):
    return production_read_plan_v1(tuple(kind for plan in plans for kind in plan.fixed_type_ids),
        tuple(key for plan in plans for key in plan.exact_keys),
        tuple(root for plan in plans for root in plan.source_roots),
        tuple(ref for plan in plans for ref in plan.required_original_refs))

def artifact_eligibility_plan_from_metadata_v3(*,namespace,request,metadata,need_original_digest):
    """Exact fixed InstalledCurrentPersonalEligibilityReaderV1 locator algorithm."""
    from .personal_candidate_eligibility_v1 import _candidate_target_v1,personal_eligibility_operation_id_v1
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from ..domains.d12.types import active_scheme_head_key
    keys=[];roots=[]
    goal=metadata.graph_v3(request.goal_ref)
    if goal is not None and goal[2]["deadline_ref"]is not None:keys.append(AtomKey.from_token(goal[2]["deadline_ref"]))
    targets=tuple(_candidate_target_v1(namespace,binding)for binding in request.bindings)
    for binding,target in zip(request.bindings,targets):
        project,entity,role,_,_,_=target
        keys.extend(AtomKey.from_token(ref)for ref in(entity,role,project))
        if type(binding)is SourceNoteCandidateBindingV1:
            keys.append(AtomKey.from_token(binding.recipe_ref));roots.append(binding.source_ref)
    keys.append(active_scheme_head_key(namespace))
    types=("d02.body_state.v1","d02.body_profile.v1","d02.reservation.v1","d03.role_binding",
        "d05.boundary_rule","d08.commitment.v1","d08.action_intent.v1","d08.action_outcome.v1")
    target_ids=set()
    for target in targets:
        value=metadata.graph_v3(target[1])
        if value is not None and value[1]:target_ids.add(value[2]["entity_id"])
    for kind in("d03.role_binding","d05.boundary_rule","d08.commitment.v1"):
        for _,valid,value in metadata.inventory_v3(kind):
            if not valid:continue
            target=value.get("target_entity_ref")if kind!="d08.commitment.v1"else value["counterparty_ref"]
            if target not in target_ids and not(kind=="d03.role_binding"and target is None):continue
            roots.extend(value.get("source_refs",()))
            if kind=="d08.commitment.v1"and value["deadline_ref"]is not None:keys.append(AtomKey.from_token(value["deadline_ref"]))
    extra=production_read_plan_v1(types,keys,tuple(sorted(set(roots))))
    operation=personal_eligibility_operation_id_v1(namespace,request,need_digest=need_original_digest)
    adopted=metadata.domain_v3(operation)
    if adopted is None:return extra
    prepared_operation=personal_eligibility_operation_id_v1(namespace,request,need_digest=need_original_digest,prepare=True)
    prepared=metadata.domain_v3(prepared_operation)
    if prepared is None:raise ValueError("actual eligibility adoption has no real matching preparation metadata")
    from .personal_candidate_eligibility_v1 import ADOPT,PREPARE
    from ..domains.d01.production_operations_v1 import plain_v1
    if((adopted["domain"],adopted["operation_kind"])!=("d08",ADOPT)
            or(prepared["domain"],prepared["operation_kind"])!=("d08",PREPARE)
            or adopted["payload"]["request"]["candidates"]!=plain_v1(request)
            or prepared["payload"]["request"]["candidates"]!=plain_v1(request)):
        raise ValueError("actual eligibility producer metadata changed its exact candidate request")
    wave=prepared["payload"]["provenance"]["personal_eligibility_inputs"]
    versions=tuple(decode_typed_production_value_v1(value,GraphVersion)for value in wave["read_versions"])
    pages=tuple(decode_typed_production_value_v1(value,ProductionQueryCoverageV1)for value in wave["query_coverage"])
    return _merge_plans_v3(extra,production_read_plan_v1(tuple(page.type_id for page in pages),
        tuple(version.key for version in versions),tuple(wave["source_refs"]),(operation,prepared_operation)))

def artifact_need_reader_plan_from_metadata_v3(*,namespace,request,metadata):
    from .d06_ingress_recall_v1 import NEED_OPERATION,LEDGER_TYPES
    from .d07_task_history_v1 import OPERATION as NO_SEARCH
    from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
    from .d11_types import runtime_job_key
    from ..domains.d03.self_perspective import self_mapping_key
    original=metadata.domain_ref_v3(request.need_qualification_original_ref)
    if original is None:return production_read_plan_v1((),())
    if original["domain"]!="d07"or original["operation_kind"]not in{NEED_OPERATION,NO_SEARCH}:
        raise ValueError("Artifact installed Need metadata is outside its exact ingress reader family")
    provenance=original["payload"]["provenance"]
    need=provenance["need"]if original["operation_kind"]==NEED_OPERATION else provenance["task_no_search"]["need"]
    if need["c02_operation_id"]!=original["payload"]["request"]["c02_operation_id"]:
        raise ValueError("actual Need metadata changed the committed C02 request")
    cycle=metadata.job_v3(AtomKey.from_token(need["cycle_job_ref"]).name)
    if cycle is None:raise ValueError("Artifact Need metadata has no actual current C02 job")
    keys=[version.key for version in original["read_versions"]]
    keys.extend((AtomKey.from_token(need["cycle_job_ref"]),self_mapping_key(namespace)))
    roots=[need["source_ref"]];originals=[request.need_qualification_original_ref,cycle["operation_id"]]
    ids=ingress_recall_model_ids_v1(namespace,need["c02_operation_id"])
    prepared=metadata.need_v3("d07_execution","prepared",ids["job"])
    if prepared is not None:
        keys.append(runtime_job_key(*namespace.as_tuple,prepared["activity_id"],prepared["job_id"]))
        for row in prepared["read_rows"]:
            key=AtomKey.from_token(row["ref"]);keys.append(key)
            if key.type_name=="memory.source":roots.append(key.token)
        originals.append(ids["adopt"])
    return production_read_plan_v1((*LEDGER_TYPES,"d01.persona_activation.v1","d01.persona_plan.v1",
        "d07.current_interpretation.v1"),keys,roots,originals)

def artifact_phase_price_plan_from_metadata_v3(*,namespace,metadata):
    from ..graph_types import owner_grant_key
    refs=metadata.need_v3("policy_index","artifact_phase_price","active")
    if len(refs)>1:raise ValueError("multiple actual Artifact phase price policies")
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),tuple(refs))

def _selected_phase_metadata_v3(metadata,phase):
    from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1,ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
    for ref,revision in((phase.decision_ref,phase.decision_revision),(phase.plan_ref,phase.plan_revision)):
        head=metadata.graph_v3(ref)
        if head is None or not head[1]or head[0].revision!=revision:
            raise ValueError("Artifact fixed metadata phase head differs from actual selected revision")
    history=metadata.need_v3("history","event",phase.decision_ref,phase.decision_revision)
    if history is None:raise ValueError("Artifact actual Decision metadata has no real producing history")
    selected=metadata.domain_v3(history["event_id"])
    if selected is None or(selected["domain"],selected["operation_kind"])!=("d08","select_personal_step_v2"):
        raise ValueError("Artifact phase metadata lost actual positive D08 choice")
    preparation=metadata.domain_v3(selected["payload"]["provenance"]["prepared_candidates_operation_id"])
    if preparation is None or(preparation["domain"],preparation["operation_kind"])!=("d08","prepare_personal_candidates_v1"):
        raise ValueError("Artifact phase metadata lost actual all-candidate preparation")
    prepare=decode_typed_production_value_v1(preparation["payload"]["request"],PrepareCurrentPersonalCandidatesRequestV1)
    raw=preparation["payload"]["provenance"]["prepared_candidates"]
    decision=metadata.graph_v3(phase.decision_ref)[2]
    choices=tuple(candidate for candidate in raw["candidates"]if candidate["future_identity"]["action_ref"]==decision["chosen_action_ref"])
    if len(choices)!=1:raise ValueError("Artifact actual phase has no unique selected future Action")
    from ..domains.d08.personal_candidate_v1 import CandidateBindingV1
    binding=decode_typed_production_value_v1(choices[0]["binding"],CandidateBindingV1)
    if type(binding)not in{ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}or(binding.task,binding.method_ref)!=(phase.task,phase.method_ref):
        raise ValueError("Artifact actual chosen metadata crossed task/method")
    return prepare,raw,choices[0],binding,preparation,selected

def _relationship_plan_from_metadata_v3(*,namespace,bindings,metadata):
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
    matched=tuple(binding for binding in bindings if type(binding)is SourceNoteCandidateBindingV1)
    if not matched:return production_read_plan_v1(())
    keys=[];roots=[];originals=[];subjects={AtomKey.from_token(binding.target_entity_ref).name for binding in matched}
    for binding in matched:
        keys.extend((AtomKey.from_token(binding.target_entity_ref),AtomKey.from_token(binding.role_binding_ref)))
        role=metadata.graph_v3(binding.role_binding_ref)
        if role is not None:roots.extend(role[2]["source_refs"])
    for _,valid,estimate in metadata.inventory_v3(ESTIMATE_TYPE):
        if not valid or estimate["scope"]["subject_entity_ref"]not in subjects:continue
        scope=estimate["scope"]
        subject=decode_typed_production_value_v1(scope["subject_head"],GraphVersion);keys.append(subject.key)
        if scope["context_head"]is not None:
            context=decode_typed_production_value_v1(scope["context_head"],GraphVersion);keys.append(context.key)
            actual=metadata.graph_v3(context.key.token)
            if actual is not None:roots.extend((context.key.token,)if context.key.type_name=="memory.source"else actual[2]["source_refs"])
        keys.extend(AtomKey.from_token(ref)for ref in estimate["interpretation_refs"]);roots.extend(estimate["source_refs"])
        originals.append(estimate["policy_ref"])
        policy=metadata.need_v3("relationship_policy","current",estimate["policy_ref"])
        if policy is not None:roots.extend(policy.get("policy_source_refs",()))
    return production_read_plan_v1((ESTIMATE_TYPE,"d03.entity_anchor","d03.role_binding"),keys,roots,originals)

def _trial_plan_v3(metadata):
    from ..domains.d01.method_learning_v1 import TRIAL_TYPE
    from .d01_method_learning_v1 import REGISTER_TRIAL_V2
    values=[]
    for version,valid,trial in metadata.inventory_v3(TRIAL_TYPE):
        if not valid:continue
        history=metadata.need_v3("history","event",version.key.token,version.revision)
        if history is None:raise ValueError("actual Method trial metadata has no historical producer")
        original=metadata.domain_v3(history["event_id"])
        proposal=original["payload"]["provenance"]["proposal_ref"]if original is not None and original["operation_kind"]==REGISTER_TRIAL_V2 else None
        protocol=metadata.graph_v3(trial["protocol_ref"])
        values.append((version.key.token,trial["source_refs"],trial["protocol_ref"],trial["gp1_interpretation_ref"],
            proposal,protocol[2]["source_refs"]if protocol is not None else()))
    return artifact_trial_plan_from_metadata_v3(values)

def _pair_plan_v3(metadata,goal_ref):
    from ..domains.d01.method_learning_v1 import EXPERIMENT_TYPE
    from .method_pair_shared_input_v1 import MethodPairSharedInputOriginalV1,OPERATION
    experiments=metadata.inventory_v3(EXPERIMENT_TYPE);shared={}
    for version,valid,raw in experiments:
        if not valid or goal_ref not in(raw["treatment_goal_ref"],raw["baseline_goal_ref"]):continue
        history=metadata.need_v3("history","event",version.key.token,version.revision)
        if history is None:raise ValueError("actual method-pair metadata has no historical producer")
        original=metadata.domain_v3(history["event_id"])
        if original is None or original["domain"]!="d01":raise ValueError("actual method-pair metadata has no D01 parent")
        shared[version.key.token]=(None if original["operation_kind"]!=OPERATION else
            decode_typed_production_value_v1(original["payload"]["provenance"]["shared_input"],MethodPairSharedInputOriginalV1))
    return artifact_pair_plan_from_metadata_v3(goal_ref=goal_ref,experiments=experiments,shared_inputs=shared)

def _capacity_plan_v3(metadata,namespace,task):
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE
    from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    checkpoints=tuple((version,valid)for version,valid,_ in metadata.inventory_v3(CHECKPOINT_TYPE))
    jobs=tuple((version,valid,value["work_kind"],value["job_id"])for version,valid,value in metadata.inventory_v3("runtime.job")if valid)
    plan=artifact_capacity_plan_from_metadata_v3(checkpoints=checkpoints,jobs=jobs)
    original=metadata.domain_v3(artifact_continuation_operation_id_v1(task))
    if original is None:return plan
    request=original["payload"]["request"]
    return _merge_plans_v3(plan,production_read_plan_v1((),tuple(AtomKey.from_token(request[name])for name in
        ("goal_ref","plan_ref","project_ref","recipe_ref"))+(project_checkpoint_key_v1(namespace,request["project_ref"]),)))

def _gv_v3(raw):
    return decode_typed_production_value_v1(raw,GraphVersion)

def _scope_plan_v3(metadata,namespace,binding,prepare,consume_phase):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    if type(binding)is not ArtifactPhaseCandidateBindingV3:return production_read_plan_v1(())
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    if binding.activity_scope_ref!=task_scope_ref_v1(binding.task.root_registration_ref):
        raise ValueError("actual candidate metadata changed its immutable task scope locator")
    raw=metadata.life_v3("artifact_task_scope",binding.activity_scope_ref)
    root=metadata.life_v3("draft_root_capability",binding.task.root_registration_ref)
    if raw is None or root is None:return production_read_plan_v1(())
    header=metadata.need_v3("life_header","artifact_task_scope",binding.activity_scope_ref)
    root_header=metadata.need_v3("life_header","draft_root_capability",binding.task.root_registration_ref)
    if header["operation_id"]!=root_header["operation_id"]:raise ValueError("actual task Scope/Root metadata has different producers")
    producer=metadata.domain_v3(header["operation_id"])
    if producer is None:raise ValueError("actual signed task Scope metadata has no positive producer")
    keys=[AtomKey.from_token(raw["source_ref"]),*(version.key for version in producer["read_versions"])]
    roots=[raw["source_ref"]];originals=[raw["c1_intent_ref"],producer["receipt"].operation_id]
    if raw["objective_ref"]is not None:originals.append(raw["objective_ref"])
    if raw["schema"]in{"d11.ingress-artifact-task-scope.v2","d11.ingress-artifact-task-scope.v3"}:originals.append(raw["approval_original_ref"])
    if raw["schema"]=="d11.ingress-artifact-task-scope.v3":originals.append(raw["continuation_authorization"]["original_ref"])
    if raw["task_kind"]=="continue"and consume_phase is not None:
        from .d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v2
        from dataclasses import replace
        initial=replace(consume_phase,phase_index=binding.phase_index,phase_kind=binding.phase_kind,
            prev_phase_original_ref=binding.prev_phase_original_ref,prev_phase_original_digest=binding.prev_phase_original_digest)
        activated=metadata.domain_v3(artifact_task_checkpoint_activation_operation_id_v2(initial))
        if activated is not None:
            originals.append("d10-current:"+activated["original_digest"][:48])
            keys.extend(version.key for version in(*activated["read_versions"],*activated["receipt"].write_versions))
    return production_read_plan_v1((),keys,roots,originals)

def _extent_plan_v3(metadata,namespace,binding):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
    if type(binding)not in{ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:return production_read_plan_v1(())
    keys=[];roots=[];originals=[binding.extent_original_ref]
    if type(binding)is ArtifactPhaseCandidateBindingV3:
        originals.append(binding.postcondition_policy_ref)
        policy=metadata.life_v3("artifact_phase_postcondition_policy",binding.postcondition_policy_ref)
        if policy is not None:
            keys.extend(_gv_v3(policy[name]).key for name in("goal_head","plan_head","source_head"))
            roots.append(_gv_v3(policy["source_head"]).key.token);originals.append(policy["objective_ref"])
    value=metadata.life_v3("artifact_task_text_extent",binding.extent_original_ref)
    if value is not None:
        keys.extend((_gv_v3(value["goal_head"]).key,_gv_v3(value["task_source_head"]).key))
        roots.append(_gv_v3(value["task_source_head"]).key.token)
        originals.extend(value[name]for name in("objective_ref","c1_intent_ref","task_producer_ref","registration_operation_id"))
        if value["schema"]=="d08.artifact-task-text-extent-original.v2":
            extra=_amended_extent_plan_v3(metadata,namespace,value,binding)
            keys.extend(extra.exact_keys);roots.extend(extra.source_roots);originals.extend(extra.required_original_refs)
    return production_read_plan_v1((),keys,roots,originals)

def _amended_extent_plan_v3(metadata,namespace,value,binding):
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from ..graph_types import owner_grant_key
    task=binding.task
    revision=metadata.domain_v3(artifact_task_plan_revision_operation_id_v2(task))
    if revision is None:raise ValueError("actual amended extent metadata has no Plan revision producer")
    provenance=revision["payload"]["provenance"]
    from ..domains.d08.personal_plan_v1 import PLAN_TYPE
    plan_versions=tuple(version for version in revision["receipt"].write_versions if version.key.type_name==PLAN_TYPE)
    if len(plan_versions)!=1:raise ValueError("actual amended Plan metadata lost its unique W01 member")
    pv=plan_versions[0];historical=metadata.need_v3("history","plan_metadata",pv.key.token,pv.revision)
    if historical is None:raise ValueError("actual amended Plan metadata lost its historical Source roots")
    plan=historical["value"]
    previous=metadata.need_v3("artifact_milestone","current",provenance["previous_milestone_ref"])
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
    prior_selector=artifact_draft_from_wire_v2(previous["selector"],ArtifactDraftPhaseSelectorV2)
    _,_,_,prior_binding,_,_=_selected_phase_history_metadata_v3(metadata,prior_selector)
    initial=metadata.life_v3("artifact_task_text_extent",prior_binding.extent_original_ref)
    if initial is None:raise ValueError("actual amended extent has no initial signed extent metadata")
    roots=tuple(dict.fromkeys((*plan["source_refs"],_gv_v3(initial["task_source_head"]).key.token,_gv_v3(previous["source_head"]).key.token)))
    keys=(owner_grant_key(*namespace.as_tuple),_gv_v3(value["goal_head"]).key,AtomKey.from_token(task.cycle_job_ref),
        *(version.key for version in revision["read_versions"]),*(version.key for version in revision["receipt"].write_versions))
    originals=(provenance["amendment_original_ref"],provenance["previous_milestone_ref"],provenance["task_scope_ref"],
        task.root_registration_ref,initial["objective_ref"],initial["c1_intent_ref"],prior_binding.extent_original_ref,
        "d08-current:"+revision["original_digest"][:48],"d08-current:"+provenance["previous_settlement_original_digest"][:48])
    scope=metadata.life_v3("artifact_task_scope",task_scope_ref_v1(task.root_registration_ref))
    return production_read_plan_v1((),keys,roots,(*originals,c1_task_intent_ref_v1(namespace,task.c02_operation_id),scope["approval_original_ref"]))

def _selected_phase_history_metadata_v3(metadata,phase):
    """The same immutable selected-history locator, without requiring old current heads."""
    from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1,CandidateBindingV1
    history=metadata.need_v3("history","phase_decision_metadata",phase.decision_ref,phase.decision_revision)
    if history is None:raise ValueError("actual prior phase lacks its immutable Decision metadata")
    selected=metadata.domain_v3(history["event_id"])
    if selected is None or(selected["domain"],selected["operation_kind"])!=("d08","select_personal_step_v2"):
        raise ValueError("actual prior phase Decision has another producer")
    preparation=metadata.domain_v3(selected["payload"]["provenance"]["prepared_candidates_operation_id"])
    if preparation is None:raise ValueError("actual prior phase Decision lost candidate preparation")
    prepare=decode_typed_production_value_v1(preparation["payload"]["request"],PrepareCurrentPersonalCandidatesRequestV1)
    raw=preparation["payload"]["provenance"]["prepared_candidates"]
    choices=tuple(candidate for candidate in raw["candidates"]if candidate["future_identity"]["action_ref"]==history["value"]["chosen_action_ref"])
    if len(choices)!=1:raise ValueError("actual prior phase has no unique historical chosen Action")
    binding=decode_typed_production_value_v1(choices[0]["binding"],CandidateBindingV1)
    return prepare,raw,choices[0],binding,preparation,selected

def _owner_need_plan_v3(metadata,namespace,original):
    from ..graph_types import Owner,owner_grant_key
    from .d06_ingress_recall_v1 import LEDGER_TYPES
    request=original["payload"]["request"];ref=request["authorization_original_ref"]
    auth=metadata.need_v3("owner_task","authorization",ref)
    if auth is None:return production_read_plan_v1((),(AtomKey.from_token(request["task_job_ref"]),),(),(ref,))
    keys=[owner_grant_key(*namespace.as_tuple),AtomKey.from_token(request["task_job_ref"]),
        AtomKey(Owner("persona",*namespace.as_tuple),"d07.focus.v1",namespace.persona_id)]
    keys.extend(_gv_v3(row[1]).key for row in auth["heads"])
    originals=[auth["original_ref"],auth["cause"]["original_ref"]]
    job=metadata.job_v3(AtomKey.from_token(request["task_job_ref"]).name)
    if job is None:raise ValueError("actual Owner Need metadata lost current task job")
    responsibility_ref=job["continuation"]["responsibility_ref"];originals.append(responsibility_ref)
    responsibility=metadata.need_v3("owner_task","responsibility",responsibility_ref)
    if responsibility is not None:
        keys.append(_gv_v3(responsibility["value"]["self_mapping_head"]).key)
        originals.append(responsibility["producer"]["receipt"].operation_id)
    focus=tuple(value for _,valid,value in metadata.inventory_v3("d07.focus.v1")if valid)
    if len(focus)>1:raise ValueError("actual Owner Need Focus is not unique")
    if focus and focus[0]["primary_ticket_ref"]is not None:keys.append(AtomKey.from_token(focus[0]["primary_ticket_ref"]))
    return production_read_plan_v1((*LEDGER_TYPES,"d07.attention_ticket.v1","d02.body_profile.v1","d02.body_state.v1","d02.reservation.v1"),
        keys,auth["source_refs"],originals)

def _personal_plan_v3(metadata,namespace,activity_id,phase):
    from ..graph_types import owner_grant_key
    from ..domains.d08.personal_candidate_v1 import (ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,
        ArtifactPhaseCandidateBindingV3,SourceNoteCandidateBindingV1)
    from .d08_personal_candidate_v1 import prospective_personal_decision_key_v1
    prepare,raw,_,chosen,preparation,_=_selected_phase_metadata_v3(metadata,phase)
    profile=metadata.need_v3("installation","personal_candidate","current")
    present=profile["reader_present"]
    if type(present)is not bool:raise TypeError("actual fixed installed-reader presence metadata required")
    plans=[_trial_plan_v3(metadata),artifact_candidate_evidence_plan_from_metadata_v3(raw,
        preparation_original_digest=preparation["original_digest"])]
    types=["d01.persona_activation.v1","d01.persona_plan.v1","d07.current_interpretation.v1"]
    keys=[owner_grant_key(*namespace.as_tuple),AtomKey.from_token(prepare.plan_ref),AtomKey.from_token(prepare.goal_ref)]
    roots=[];originals=[prepare.need_qualification_original_ref]
    origin=metadata.domain_ref_v3(prepare.need_qualification_original_ref)
    from .owner_source_note_need_v1 import OPERATION as OWNER_NEED
    owner_need=origin is not None and(origin["domain"],origin["operation_kind"])==("d07",OWNER_NEED)
    if owner_need:
        if not present:raise ValueError("actual Owner Need requires its real installed Owner-task candidate reader")
        plans.append(_owner_need_plan_v3(metadata,namespace,origin))
    if any(type(binding)in{ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}for binding in prepare.bindings):
        plans.append(_pair_plan_v3(metadata,prepare.goal_ref))
    goal=metadata.graph_v3(prepare.goal_ref)
    if goal is not None and goal[2]["deadline_ref"]is not None:keys.append(AtomKey.from_token(goal[2]["deadline_ref"]))
    plan=metadata.graph_v3(prepare.plan_ref)
    if plan is not None:
        roots.extend(plan[2]["source_refs"]);keys.extend(AtomKey.from_token(row["ref"])for row in plan[2]["fact_versions"])
    plans.append(_relationship_plan_from_metadata_v3(namespace=namespace,bindings=prepare.bindings,metadata=metadata))
    keys.append(prospective_personal_decision_key_v1(namespace,activity_id,prepare.selection_operation_id,prepare.plan_ref))
    if origin is not None and not owner_need:
        from .d06_ingress_recall_v1 import NEED_OPERATION
        from .d07_task_history_v1 import OPERATION as NO_SEARCH
        if(origin["domain"],origin["operation_kind"])not in{("d07",NEED_OPERATION),("d07",NO_SEARCH)}:
            raise ValueError("actual Artifact Need original has an unknown fixed reader family")
        data=origin["payload"]["provenance"]
        need=data["need"]if origin["operation_kind"]==NEED_OPERATION else data["task_no_search"]["need"]
        cycle=metadata.job_v3(AtomKey.from_token(need["cycle_job_ref"]).name)
        continuation=cycle["continuation"]
        from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
        from dataclasses import fields
        source_note_schema=next(field.default for field in fields(ForegroundSourceNoteContinuationV1)if field.name=="schema")
        if continuation["schema"]==source_note_schema:
            if not present:raise ValueError("actual SourceNote candidate authorization requires its real installed personal reader")
            auth=metadata.life_v3("source_note_task_authorization",continuation["authorization_original_ref"])
            if auth is None:raise ValueError("actual SourceNote candidate metadata lost signed authorization")
            keys.extend(_gv_v3(row[1]).key for row in auth["heads"]);roots.extend(auth["source_refs"])
            originals.extend((auth["original_ref"],auth["authorization_operation_id"],cycle["operation_id"]))
    evaluation=metadata.domain_v3(prepare.value_evaluation_operation_id)
    if evaluation is not None:keys.extend(version.key for version in evaluation["read_versions"])
    for binding in prepare.bindings:
        if type(binding)in{ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:
            keys.append(AtomKey.from_token(binding.task.cycle_job_ref));originals.extend((binding.activity_scope_ref,binding.task.root_registration_ref))
            if type(binding)in{ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:originals.append(binding.extent_original_ref)
            if type(binding)is ArtifactPhaseCandidateBindingV3:originals.append(binding.postcondition_policy_ref)
            if binding.prev_phase_original_ref is not None:originals.append(binding.prev_phase_original_ref)
            if binding.prior_content is not None:
                key=AtomKey.from_token(binding.prior_content.source_head.ref);keys.append(key);roots.append(key.token)
                originals.append(binding.prior_content.verified_original_ref)
        else:
            if type(binding)is not SourceNoteCandidateBindingV1:raise TypeError("unregistered actual candidate metadata binding")
            keys.extend(AtomKey.from_token(ref)for ref in(binding.project_ref,binding.recipe_ref,binding.source_ref,binding.goal_ref,binding.target_entity_ref,binding.role_binding_ref))
            roots.append(binding.source_ref);originals.extend((binding.project_ref,binding.recipe_ref,binding.target_entity_ref,binding.role_binding_ref))
        if present:
            plans.append(_scope_plan_v3(metadata,namespace,binding,prepare,phase))
            plans.append(_extent_plan_v3(metadata,namespace,binding))
    conditions=metadata.inventory_v3("d07.current_interpretation.v1")
    plans.append(artifact_condition_plan_from_metadata_v3(goal_heads=()if goal is None else(goal,),interpretations=conditions))
    if not present:return _merge_plans_v3(production_read_plan_v1(types,keys,roots,originals),*plans)
    if profile["standing_scope_kind"]=="AdminArtifactStandingScopeV3":
        from .artifact_phase_postconditions_v1 import artifact_candidate_preparation_parent_ref_v1,PREPARATION_PARENT_KIND_V1
        tasks={binding.task for binding in prepare.bindings if type(binding)is ArtifactPhaseCandidateBindingV3}
        if len(tasks)==1:
            ref=artifact_candidate_preparation_parent_ref_v1(next(iter(tasks)),GraphVersion(AtomKey.from_token(prepare.plan_ref),prepare.expected_plan_revision))
            if metadata.life_v3(PREPARATION_PARENT_KIND_V1,ref)is not None:originals.append(ref)
    if not owner_need:plans.append(artifact_need_reader_plan_from_metadata_v3(namespace=namespace,request=prepare,metadata=metadata))
    if origin is None:raise ValueError("actual Artifact candidate metadata has no positive Need Original")
    plans.append(artifact_eligibility_plan_from_metadata_v3(namespace=namespace,request=prepare,metadata=metadata,need_original_digest=origin["original_digest"]))
    if profile["phase_price_kind"]=="InstalledArtifactPhasePriceReaderV1":
        plans.append(artifact_phase_price_plan_from_metadata_v3(namespace=namespace,metadata=metadata))
    elif profile["phase_price_kind"]=="InstalledCurrentSourceNotePriceReaderV1":
        if any(type(binding)is SourceNoteCandidateBindingV1 for binding in prepare.bindings):
            authorization=metadata.need_v3("source_note_authorization","by_need",prepare.need_qualification_original_ref)
            plans.append(production_read_plan_v1((),(),authorization["source_refs"],
                (authorization["original_ref"],authorization["body_policy"]["effect_policy_ref"])))
    else:raise ValueError("actual installed price reader has no registered fixed metadata recipe")
    return _merge_plans_v3(production_read_plan_v1(types,keys,roots,originals),*plans)

def _phase_contract_plan_v3(metadata,namespace,phase):
    from ..graph_types import owner_grant_key
    from .artifact_phase_postconditions_v1 import artifact_phase_postcondition_contract_ref_v1
    _,candidates,_,binding,original,_=_selected_phase_metadata_v3(metadata,phase)
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    if type(binding)is not ArtifactPhaseCandidateBindingV3:raise ValueError("actual C4 phase metadata requires registered V3 postcondition binding")
    keys=[owner_grant_key(*namespace.as_tuple),AtomKey.from_token(phase.decision_ref),_gv_v3(candidates["goal_head"]).key,_gv_v3(candidates["plan_head"]).key]
    originals=[binding.postcondition_policy_ref,"d08-current:"+original["original_digest"][:48]]
    roots=[];policy=metadata.life_v3("artifact_phase_postcondition_policy",binding.postcondition_policy_ref)
    if policy is not None:
        source=_gv_v3(policy["source_head"]).key;keys.append(source);roots.append(source.token)
        originals.extend((policy["objective_ref"],policy["request"]["extent_original_ref"],policy["request"]["task"]["root_registration_ref"]))
    originals.append(artifact_phase_postcondition_contract_ref_v1(phase))
    return production_read_plan_v1((),keys,roots,originals)

def _phase_transition_plan_v3(metadata,namespace,phase):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from .d11_types import runtime_job_key
    ids=artifact_draft_model_ids_v2(phase);prepared=metadata.life_v3("c4_phase_prepared",ids["job"])
    if prepared is None:return production_read_plan_v1((),())
    original=metadata.domain_v3(prepared["operation_id"])
    if original is None:raise ValueError("actual phase transition metadata lost its preparation producer")
    originals=[ids["job"],ids["frozen"],"d11-current:"+original["original_digest"][:48]]
    acquired=metadata.domain_v3(prepared["acquire_operation_id"])
    if acquired is not None:originals.extend(("d11-current:"+acquired["original_digest"][:48],ids["request"]))
    return production_read_plan_v1((),(AtomKey.from_token(phase.task.cycle_job_ref),
        runtime_job_key(*namespace.as_tuple,prepared["activity_id"],prepared["job_id"])),(),originals)

def _legacy_continuation_plan_v3(metadata,namespace,task,cycle):
    from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,WORK_TYPE
    from .d08_personal_plan_v1 import OBLIGATION_TYPES
    from ..domains.d03.self_perspective import self_mapping_key
    from ..graph_types import owner_grant_key
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from ..runtime_contracts import canonical_digest
    original=metadata.domain_v3(artifact_continuation_operation_id_v1(task))
    if original is None:return production_read_plan_v1((),())
    if(original["domain"],original["operation_kind"])!=("d08","select_existing_artifact_continuation_v1"):
        raise ValueError("actual legacy Artifact continuation metadata has another producer")
    request=original["payload"]["request"]
    keys=[AtomKey.from_token(request[name])for name in("project_ref","goal_ref","plan_ref","recipe_ref","correction_head_ref")]
    keys.extend((AtomKey.from_token(task.cycle_job_ref),project_checkpoint_key_v1(namespace,request["project_ref"]),
        self_mapping_key(namespace),owner_grant_key(*namespace.as_tuple)))
    originals=[task.c02_operation_id,task.root_registration_ref,request["predecessor_result_ref"]]
    scope=metadata.life_v3("artifact_task_scope",task_scope_ref_v1(task.root_registration_ref))
    if scope is not None and scope["schema"]=="d11.ingress-artifact-task-scope.v3":
        originals.append(scope["continuation_authorization"]["original_ref"])
    from .artifact_task_amendment_v1 import TYPE as AMENDMENT_TYPE
    if AtomKey.from_token(request["correction_head_ref"]).type_name==AMENDMENT_TYPE:
        amendment=metadata.graph_v3(request["correction_head_ref"])
        if amendment is None:raise ValueError("actual legacy continuation metadata lacks current amendment")
        value=amendment[2]
        originals.append("artifact-task-amendment:"+canonical_digest((namespace,value["root_registration_ref"]))[:48])
    goal=metadata.graph_v3(request["goal_ref"])
    if goal is not None:
        predicate=goal[2]["satisfaction_predicate"]
        if(predicate["kind"],predicate["observation_provider"])==("domain_state","d08.artifact_task_objective.v1"):
            parameters=dict(predicate["parameters"])
            if set(parameters)!={"objective_ref","objective_digest"}:raise ValueError("actual legacy objective predicate has another binding")
            originals.append(parameters["objective_ref"])
    roots=[cycle["continuation"]["source_ref"]];results=[request["predecessor_result_ref"]]
    for version,_,work in metadata.inventory_v3(WORK_TYPE):
        if work["project_ref"]==request["project_ref"]:keys.append(version.key);results.append(work["artifact_ref"])
    for ref in dict.fromkeys(results):
        originals.append(ref);adopted=metadata.life_v3("adopted_life",ref)
        if adopted is not None:originals.append(adopted["terminal"]["binding"]["prepared_original_ref"])
    return production_read_plan_v1((*OBLIGATION_TYPES,"d10.life_project.v1","d08.goal.v1",WORK_TYPE),keys,roots,originals)

def compose_artifact_borrowed_metadata_plan_v3(*,namespace,operation_kind,activity_id,metadata,request=None,actual_selector=None):
    """Fixed metadata recipe for the four actual C4 model commands.

    Callers authenticate every metadata value and each complete EOF in their
    own actual Work. This pure result is neither Source permission nor a
    substitute for the real recipe/body recomputation.
    """
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2
    from .d11_artifact_draft_model_v1 import PrepareArtifactDraftModelRequestV1,AcquireArtifactDraftModelRequestV1,PrepareArtifactDraftModelRequestV2,AcquireArtifactDraftModelRequestV2
    from ..domains.d03.self_perspective import self_mapping_key
    from .d11_types import runtime_job_key
    from ..graph_types import owner_grant_key
    types={"prepare_artifact_draft_model":PrepareArtifactDraftModelRequestV1,"acquire_artifact_draft_model":AcquireArtifactDraftModelRequestV1,
        "prepare_artifact_draft_model_v2":PrepareArtifactDraftModelRequestV2,"acquire_artifact_draft_model_v2":AcquireArtifactDraftModelRequestV2}
    if operation_kind not in types:raise ValueError("unregistered pure C4 model metadata recipe")
    if request is not None:
        if type(request)is not types[operation_kind]:raise TypeError("actual exact typed C4 model command required")
        if actual_selector is not None and actual_selector!=request.selector:raise ValueError("actual command and independent selector differ")
        selector=request.selector
    else:selector=actual_selector
    phase=operation_kind.endswith("_v2")
    if type(selector)is not(ArtifactDraftPhaseSelectorV2 if phase else ArtifactDraftTaskSelectorV1):
        raise TypeError("actual immutable typed C4 task/phase selector metadata required")
    task=selector.task if phase else selector
    if task.namespace!=namespace:raise ValueError("actual pure C4 metadata crossed namespace")
    cycle=metadata.job_v3(AtomKey.from_token(task.cycle_job_ref).name)
    if cycle is None:raise ValueError("actual C4 metadata has no original parent cycle")
    ids=artifact_draft_model_ids_v2(selector)if phase else artifact_draft_model_ids_v1(selector)
    originals=[task.root_registration_ref,task.c02_operation_id]
    if operation_kind.startswith("acquire_"):originals.extend((ids["job"],ids["frozen"]))
    keys=[AtomKey.from_token(task.cycle_job_ref),runtime_job_key(*namespace.as_tuple,cycle["activity_id"],ids["job"]),
        self_mapping_key(namespace),owner_grant_key(*namespace.as_tuple)]
    base=production_read_plan_v1((),keys,(cycle["continuation"]["source_ref"],),originals)
    if not phase:
        extra=_legacy_continuation_plan_v3(metadata,namespace,task,cycle)
        if operation_kind=="prepare_artifact_draft_model":return _merge_plans_v3(base,extra,_capacity_plan_v3(metadata,namespace,task))
        return _merge_plans_v3(base,extra)
    if selector.prev_phase_original_ref is not None:originals.append(selector.prev_phase_original_ref)
    base=production_read_plan_v1((),(*keys,AtomKey.from_token(selector.decision_ref),AtomKey.from_token(selector.plan_ref)),
        (cycle["continuation"]["source_ref"],),originals)
    plan=metadata.graph_v3(selector.plan_ref)
    if plan is None:raise ValueError("actual C4 metadata has no current selected method Plan")
    profile=metadata.need_v3("installation","personal_candidate","current")
    transition=(_phase_transition_plan_v3(metadata,namespace,selector)if profile["reader_present"]else production_read_plan_v1(()))
    return _merge_plans_v3(base,_personal_plan_v3(metadata,namespace,cycle["activity_id"],selector),
        transition,_phase_contract_plan_v3(metadata,namespace,selector),
        _pair_plan_v3(metadata,plan[2]["goal_ref"]),_capacity_plan_v3(metadata,namespace,task))

_WIRE_SHAPES_V3={}
def _wire_shape_v3(typ):
    from dataclasses import fields,is_dataclass
    from typing import get_origin,get_args,get_type_hints,Literal,Union
    from types import UnionType
    from ..graph_types import AtomKey
    from enum import Enum
    if typ is AtomKey:return "scalar"
    if typ in(str,int,float,bool,type(None)):return "scalar"
    origin=get_origin(typ);args=get_args(typ)
    if origin is Literal:return "scalar"
    if origin in(Union,UnionType):
        shapes=tuple(_wire_shape_v3(part)for part in args if part is not type(None))
        objects=tuple(shape for shape in shapes if type(shape)is dict)
        if objects:
            merged={}
            for shape in objects:
                for key,value in shape.items():
                    if key not in merged:merged[key]=value
                    elif type(merged[key])is dict and type(value)is dict:merged[key]={**merged[key],**value}
            return merged
        return shapes[0]if shapes else"scalar"
    if origin in(tuple,list):
        if len(args)==2 and args[1]is Ellipsis:return("array",_wire_shape_v3(args[0]))
        return("fixed",tuple(_wire_shape_v3(part)for part in args))
    if isinstance(typ,type)and issubclass(typ,Enum):return"scalar"
    if isinstance(typ,type)and is_dataclass(typ):
        if typ not in _WIRE_SHAPES_V3:
            hints=get_type_hints(typ);_WIRE_SHAPES_V3[typ]={field.name:_wire_shape_v3(hints[field.name])for field in fields(typ)}
        return _WIRE_SHAPES_V3[typ]
    raise TypeError("unregistered non-locator field in fixed Artifact metadata wire shape: "+str(typ))

def _shape_retains_v3(shape,path):
    for part in path:
        if type(shape)is dict:
            if part not in shape:return False
            shape=shape[part]
        elif type(shape)is tuple:
            if type(part)is not int:return False
            if shape[0]=="array":shape=shape[1]
            elif shape[0]=="fixed"and 0<=part<len(shape[1]):shape=shape[1][part]
            else:return False
        else:return False
    return shape!="body"

def artifact_recipe_metadata_retain_path_v3(locator,path,*,actual_domain_kind=None):
    """Fixed pure projection only; actual_domain_kind is the verified row header tuple.

    Graph/Domain/Life records, negative points and type inventories must still
    originate in the caller's authenticated same-Work metadata EOF registry.
    """
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1,ProductionOriginalRefV1
    from ..runtime_contracts import NamespaceId
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2
    gv=_wire_shape_v3(GraphVersion);namespace=_wire_shape_v3(NamespaceId)
    if locator.family=="graph":
        from ..domains.d01.method_learning_v1 import TRIAL_TYPE,PROTOCOL_TYPE,EXPERIMENT_TYPE
        from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
        from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE,WORK_TYPE
        fields={
            "d08.personal_plan.v1":{"schema":"scalar","goal_ref":"scalar","source_refs":("array","scalar"),
                "fact_versions":("array",{"ref":"scalar","revision":"scalar","digest":"scalar"})},
            "d08.goal.v1":{"schema":"scalar","revision":"scalar","deadline_ref":"scalar",
                "satisfaction_predicate":{"kind":"scalar","observation_provider":"scalar",
                    "parameters":("array",("fixed",("scalar","scalar"))),"valid_from":"scalar","valid_until":"scalar"}},
            "d03.entity_anchor":{"schema":"scalar","entity_id":"scalar"},
            "d03.role_binding":{"schema":"scalar","target_entity_ref":"scalar","source_refs":("array","scalar")},
            "d05.boundary_rule":{"schema":"scalar","target_entity_ref":"scalar","source_refs":("array","scalar")},
            "d08.commitment.v1":{"schema":"scalar","counterparty_ref":"scalar","source_refs":("array","scalar"),"deadline_ref":"scalar"},
            "d07.current_interpretation.v1":{"schema":"scalar","question_key":"scalar","source_refs":("array","scalar")},
            "d07.focus.v1":{"schema":"scalar","primary_ticket_ref":"scalar"},
            "runtime.job":{"schema":"scalar","work_kind":"scalar","job_id":"scalar"},
            "d06.artifact_task_amendment.v1":{"schema":"scalar","namespace":namespace,"root_registration_ref":"scalar"},
            TRIAL_TYPE:{"schema":"scalar","source_refs":("array","scalar"),"protocol_ref":"scalar","gp1_interpretation_ref":"scalar"},
            PROTOCOL_TYPE:{"schema":"scalar","source_refs":("array","scalar")},
            EXPERIMENT_TYPE:{"schema":"scalar","treatment_goal_ref":"scalar","baseline_goal_ref":"scalar"},
            ESTIMATE_TYPE:{"schema":"scalar","scope":{"subject_entity_ref":"scalar","subject_head":gv,"context_head":gv},
                "interpretation_refs":("array","scalar"),"source_refs":("array","scalar"),"policy_ref":"scalar"},
            CHECKPOINT_TYPE:{"schema":"scalar"},
            WORK_TYPE:{"schema":"scalar","project_ref":"scalar","artifact_ref":"scalar"},
            "d08.decision_record.v2":{"schema":"scalar","chosen_action_ref":"scalar"},
        }
        if locator.kind not in fields:raise ValueError("unregistered fixed Artifact Graph metadata profile")
        return _shape_retains_v3(fields[locator.kind],path)
    if locator.family=="history":
        if locator.kind=="event":return not path
        profile=ArtifactMetadataLocatorV3("graph","d08.decision_record.v2"if locator.kind=="phase_decision_metadata"else"d08.personal_plan.v1",locator.ref)
        return artifact_recipe_metadata_retain_path_v3(profile,path)
    if locator.family=="life":
        if locator.kind in{"c4_frozen","c4_phase_frozen"}:
            from .artifact_frozen_metadata_v3 import artifact_frozen_metadata_path_v3
            return artifact_frozen_metadata_path_v3(path)
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV1,ArtifactDraftModelPreparedV2
        if locator.kind=="artifact_task_scope":shape=_wire_shape_v3(IngressArtifactTaskScopeOriginalV3)
        elif locator.kind=="draft_root_capability":shape=_wire_shape_v3(DraftRootCapabilityV1)
        elif locator.kind in{"c4_prepared","c4_phase_prepared"}:
            shape=_wire_shape_v3(ArtifactDraftModelPreparedV2 if locator.kind=="c4_phase_prepared"else ArtifactDraftModelPreparedV1)
        elif locator.kind=="artifact_phase_postcondition_policy":
            shape={"schema":"scalar","goal_head":gv,"plan_head":gv,"source_head":gv,"objective_ref":"scalar",
                "request":{"extent_original_ref":"scalar","task":_wire_shape_v3(ArtifactDraftTaskSelectorV1)}}
        elif locator.kind=="artifact_task_text_extent":
            shape={"schema":"scalar","goal_head":gv,"task_source_head":gv,"objective_ref":"scalar",
                "c1_intent_ref":"scalar","task_producer_ref":"scalar","registration_operation_id":"scalar"}
        elif locator.kind=="adopted_life":shape={"terminal":{"binding":{"prepared_original_ref":"scalar"}}}
        elif locator.kind=="source_note_task_authorization":
            shape={"schema":"scalar","heads":("array",("fixed",("scalar",gv,"scalar"))),"source_refs":("array","scalar"),
                "original_ref":"scalar","authorization_operation_id":"scalar"}
        elif locator.kind=="artifact_candidate_preparation_parent":shape={"schema":"scalar"}
        else:raise ValueError("unregistered fixed Artifact signed-Life metadata profile")
        return _shape_retains_v3(shape,path)
    if locator.family=="domain":
        if actual_domain_kind is None:raise ValueError("actual registered Domain Original header required before metadata projection")
        domain,kind=actual_domain_kind
        shape={"schema":"scalar","namespace":namespace,"identity":{"phase":"scalar","operation_id":"scalar"},"coverage":"scalar"}
        provenance={}
        from .d06_ingress_recall_v1 import NEED_OPERATION
        from .d07_task_history_v1 import OPERATION as NO_SEARCH
        from .d01_method_learning_v1 import REGISTER_TRIAL_V2
        from .method_pair_shared_input_v1 import OPERATION as PAIR,MethodPairSharedInputOriginalV1
        from .d08_personal_plan_v1 import ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2
        from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1,PersonalCandidateFutureIdentityV1,CandidateBindingV1
        evidence={"original":_wire_shape_v3(ProductionOriginalRefV1),"read_versions":("array",gv),
            "query_coverage":("array",_wire_shape_v3(ProductionQueryCoverageV1))}
        if(domain,kind)==("d08","prepare_personal_candidates_v1"):
            shape["request"]=_wire_shape_v3(PrepareCurrentPersonalCandidatesRequestV1)
            eligibility={"originals":("array",_wire_shape_v3(ProductionOriginalRefV1)),"read_versions":("array",gv),
                "query_coverage":("array",_wire_shape_v3(ProductionQueryCoverageV1))}
            candidate={"binding":_wire_shape_v3(CandidateBindingV1),"future_identity":_wire_shape_v3(PersonalCandidateFutureIdentityV1),
                "eligibility":eligibility,"price":evidence,"quote_ref":"scalar","quote_digest":"scalar","quote_ceiling":("array",("fixed",("scalar","scalar")))}
            provenance["prepared_candidates"]={"namespace":namespace,"preparation_operation_id":"scalar","selection_operation_id":"scalar",
                "future_decision_ref":"scalar","plan_head":gv,"goal_head":gv,"source_refs":("array","scalar"),"read_versions":("array",gv),
                "query_coverage":("array",_wire_shape_v3(ProductionQueryCoverageV1)),"need":evidence,"candidates":("array",candidate)}
        elif(domain,kind)==("d08","select_personal_step_v2"):
            provenance["prepared_candidates_operation_id"]="scalar"
        elif domain=="d08"and kind in{"prepare_personal_candidate_eligibility_v1","adopt_personal_candidate_eligibility_v1"}:
            shape["request"]={"candidates":_wire_shape_v3(PrepareCurrentPersonalCandidatesRequestV1)}
            provenance["personal_eligibility_inputs"]={"read_versions":("array",gv),"query_coverage":("array",_wire_shape_v3(ProductionQueryCoverageV1)),
                "source_refs":("array","scalar")}
        elif domain=="d07"and kind in{NEED_OPERATION,NO_SEARCH}:
            shape["request"]={"c02_operation_id":"scalar"}
            need={"c02_operation_id":"scalar","cycle_job_ref":"scalar","source_ref":"scalar"}
            provenance["need"if kind==NEED_OPERATION else"task_no_search"]=need if kind==NEED_OPERATION else{"need":need}
        elif(domain,kind)==("d01",REGISTER_TRIAL_V2):provenance["proposal_ref"]="scalar"
        elif(domain,kind)==("d01",PAIR):provenance["shared_input"]=_wire_shape_v3(MethodPairSharedInputOriginalV1)
        elif(domain,kind)==("d08","select_existing_artifact_continuation_v1"):
            from .artifact_continuation_originals_v1 import ExistingArtifactContinuationRequestV1
            shape["request"]=_wire_shape_v3(ExistingArtifactContinuationRequestV1)
        elif domain=="d08"and kind==ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2:
            for field in("amendment_original_ref","previous_milestone_ref","task_scope_ref","previous_settlement_original_digest"):
                provenance[field]="scalar"
        elif(domain,kind)==("d07","prepare_owner_source_note_need_v1"):
            shape["request"]={"authorization_original_ref":"scalar","task_job_ref":"scalar"}
        shape["provenance"]=provenance
        return _shape_retains_v3(shape,path)
    if locator.family=="job":
        shape={"schema":"scalar","source_ref":"scalar","c02_operation_id":"scalar",
            "authorization_original_ref":"scalar","responsibility_ref":"scalar"}
        return _shape_retains_v3(shape,path)
    if locator.family=="d07_execution":
        shape={"activity_id":"scalar","job_id":"scalar","read_rows":("array",{"ref":"scalar"})}
        return _shape_retains_v3(shape,path)
    if locator.family=="relationship_policy":return _shape_retains_v3({"policy_source_refs":("array","scalar")},path)
    if locator.family=="artifact_milestone":
        return _shape_retains_v3({"selector":_wire_shape_v3(ArtifactDraftPhaseSelectorV2),"source_head":gv},path)
    if locator.family=="owner_task":
        if locator.kind=="authorization":
            shape={"schema":"scalar","heads":("array",("fixed",("scalar",gv,"scalar"))),"source_refs":("array","scalar"),
                "original_ref":"scalar","cause":{"original_ref":"scalar"}}
        elif locator.kind=="responsibility":shape={"self_mapping_head":gv}
        else:raise ValueError("unknown actual Owner-task metadata locator")
        return _shape_retains_v3(shape,path)
    if locator.family=="source_note_authorization":
        return _shape_retains_v3({"original_ref":"scalar","source_refs":("array","scalar"),
            "body_policy":{"effect_policy_ref":"scalar"}},path)
    raise ValueError("unregistered fixed Artifact metadata projection family")
