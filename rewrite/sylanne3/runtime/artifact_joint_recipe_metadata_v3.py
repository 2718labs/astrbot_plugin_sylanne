"""Pure fixed locators for the existing JointPlan Artifact business recipe.

Typed Needed values are authenticated independently by each real Source Work.
This module neither issues a reader nor accepts a permission flag.
"""
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import canonical_digest,NamespaceId
from .artifact_recipe_metadata_v3 import ArtifactRecipeMetadataV3,_merge_plans_v3,_gv_v3
from .d01_production_operations_v1 import production_read_plan_v1

def _registered(metadata,kind,ref):
    row=metadata.need_v3("joint_registered",kind,ref)
    return None if row is None else row["payload"]

def _executor_originals(binding):
    executor=binding["executor"];schema=executor["schema"]
    if schema=="d10.joint-source-note-executor.v1":return(executor["authorization_original_ref"],)
    if schema=="d10.joint-artifact-executor.v1":return(executor["c02_operation_id"],executor["root_registration_ref"])
    if schema=="d10.joint-contact-executor.v1":return(executor["prepare_contact_operation_id"],)
    raise ValueError("unknown actual Joint executor metadata schema")

def _index(metadata,namespace,kind,key):
    from .joint_node_execution_v1 import joint_executor_index_ref_v1
    ref=joint_executor_index_ref_v1(namespace,kind,key);value=_registered(metadata,"executor_index",ref)
    if value is None:return None
    if value["namespace"]!={"bot_id":namespace.bot_id,"persona_id":namespace.persona_id}or(value["selector_kind"],tuple(value["selector_key"]))!=(kind,tuple(key)):
        raise ValueError("actual Joint index metadata crossed exact selector")
    row=metadata.need_v3("joint_registered","binding",value["binding_ref"])
    if row is None or row["payload_digest"]!=value["binding_digest"]:
        raise ValueError("actual Joint index lost its exact positive signed binding")
    binding=row["payload"]
    index_row=metadata.need_v3("joint_registered","executor_index",ref)
    if(index_row["operation_id"]!=row["operation_id"]or value["registration_request_digest"]!=row["request_digest"]):
        raise ValueError("actual Joint index/binding lost the same registration producer")
    if tuple(binding["source_refs"])!=tuple(value["source_refs"]):
        raise ValueError("actual Joint index/binding metadata Source scope differs")
    binding=dict(binding);binding["_original_ref"]=value["binding_ref"]
    return binding

def _binding(metadata,namespace,phase,action_ref=None):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    if action_ref is not None:
        found=_index(metadata,namespace,"action",(action_ref,))
        if found is not None:return found
    task=phase.task if type(phase)is ArtifactDraftPhaseSelectorV2 else phase
    task_binding=_index(metadata,namespace,"artifact_task",(task.c02_operation_id,task.root_registration_ref))
    found=_index(metadata,namespace,"artifact",(task.c02_operation_id,task.root_registration_ref,
        phase.identity_digest if type(phase)is ArtifactDraftPhaseSelectorV2 else"legacy"))
    if task_binding is not None and found is None:
        if task_binding["schema"]!="d10.joint-artifact-prospective-binding.v1"or type(phase)is not ArtifactDraftPhaseSelectorV2:
            raise ValueError("actual separately consented Joint Artifact phase metadata is absent")
        executor=task_binding["executor"]
        if(executor["c02_operation_id"],executor["root_registration_ref"])!=(task.c02_operation_id,task.root_registration_ref):
            raise ValueError("actual Joint task successor crossed Root/C02")
        return task_binding
    return found

def _life_progress(metadata,namespace,progress_ref,*,project_effect=False):
    from .d10_life_progress_provenance_v1 import life_progress_auxiliary_key_v1,PROVENANCE_TYPE,life_progress_read_keys_v1,END_PROOF,END_ELIGIBILITY
    from .d11_life_contract_v1 import D11LifeExecutionBindingV1,D11DraftExecutionBindingV1,life_mutation_id_v1
    from .d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1,SOURCE_FAMILY_TYPES,CURRENT_PERMISSION_TYPES
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    fact=AtomKey.from_token(progress_ref)
    if project_effect:
        progress=metadata.graph_v3(progress_ref)
        if progress is None:return production_read_plan_v1((),(fact,))
        if progress[2]["step"]=="artifact_draft_v1":
            return _artifact_effect(metadata,namespace,progress_ref,progress)
    proof=metadata.graph_v3(life_progress_auxiliary_key_v1(fact,PROVENANCE_TYPE).token)
    if proof is None or not proof[1]:raise ValueError("actual Life progress metadata lost typed current provenance")
    raw=proof[2]["terminal_provenance"]["binding"]
    binding=decode_typed_production_value_v1(raw,D11DraftExecutionBindingV1 if raw["schema"]=="d11.draft-execution-binding.v1"else D11LifeExecutionBindingV1)
    prepared=metadata.life_v3("prepared",binding.prepared_original_ref)
    if prepared is None:raise ValueError("actual Joint Life progress metadata lost signed preparation")
    rows=prepared["read_rows"];owner=owner_grant_key(*namespace.as_tuple).token
    required={owner}
    if prepared["schema"]!="d11.draft-prepared.v1":required.update(prepared["plan"][name]["ref"]for name in("project","recipe","action_intent","input_source","input_access"))
    selected=tuple(row for row in rows if row["ref"]in required or AtomKey.from_token(row["ref"]).type_name in SOURCE_FAMILY_TYPES|CURRENT_PERMISSION_TYPES)
    if owner not in{row["ref"]for row in selected}:raise ValueError("actual Joint Life current eligibility metadata lost original Owner")
    facts=(AtomKey.from_token(binding.artifact_ref),life_role_segment_key_v1(binding,"start"),life_role_segment_key_v1(binding,"end"))
    keys=(*life_progress_read_keys_v1(binding),*facts,
        *(life_fact_auxiliary_key_v1(key,kind)for key in facts for kind in(END_PROOF,END_ELIGIBILITY)),
        *life_outcome_read_keys_v1(binding,prepared["plan"]["action_intent"]["ref"]),*(AtomKey.from_token(row["ref"])for row in selected))
    roots=tuple(row["ref"]for row in selected if AtomKey.from_token(row["ref"]).type_name=="memory.source")
    originals=(binding.prepared_original_ref,binding.plan_original_ref,binding.artifact_ref,life_mutation_id_v1(binding,"claim"),life_mutation_id_v1(binding,"terminal"))
    return production_read_plan_v1((),keys,roots,originals)

def _artifact_effect(metadata,namespace,progress_ref,progress):
    from .d11_life_contract_v1 import D11DraftExecutionBindingV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    value=progress[2]
    if not progress[1]or value["step"]!="artifact_draft_v1":return production_read_plan_v1((),())
    adopted=metadata.life_v3("adopted_life",value["artifact_ref"])
    if adopted is None:return production_read_plan_v1((),(),(),(value["terminal_ref"],))
    terminal=adopted["terminal"];binding=decode_typed_production_value_v1(terminal["binding"],D11DraftExecutionBindingV1)
    prepared=metadata.life_v3("prepared",binding.prepared_original_ref)
    if prepared is None:return production_read_plan_v1((),(),(),(binding.prepared_original_ref,terminal["original_ref"]))
    plan=prepared["plan"]
    keys=[AtomKey.from_token(progress_ref),AtomKey.from_token(binding.artifact_ref),AtomKey.from_token(plan["action_intent"]["ref"]),
        *life_outcome_read_keys_v1(binding,plan["action_intent"]["ref"]),*(AtomKey.from_token(row["ref"])for row in prepared["read_rows"])]
    roots=(plan["input_source"]["ref"],*plan["content"]["source_refs"])
    originals=[binding.plan_original_ref,binding.prepared_original_ref,binding.artifact_ref,terminal["original_ref"],*value["receipt_refs"]]
    if plan["target"]["mode"]=="replace":
        from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
        from ..domains.d10.project_checkpoint_v1 import project_work_version_key_v1
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        scope=metadata.life_v3("activity_scope",plan["activity_scope_ref"])
        if scope is None:raise ValueError("actual replacement metadata lost activity scope")
        task=artifact_draft_task_selector_v1(namespace,c02_operation_id=scope["c02_original_ref"],root_registration_ref=plan["target"]["root_registration_ref"])
        selection=metadata.domain_v3(artifact_continuation_operation_id_v1(task))
        if selection is None:raise ValueError("actual replacement metadata lost positive selected predecessor")
        request=selection["payload"]["request"];basis=selection["payload"]["provenance"]["basis"]
        keys.append(project_work_version_key_v1(namespace,request["project_ref"],basis["predecessor_effect_id"]))
        originals.extend((plan["activity_scope_ref"],request["predecessor_result_ref"],selection["receipt"].operation_id))
        prior=metadata.life_v3("adopted_life",request["predecessor_result_ref"])
        if prior is not None:originals.extend((prior["terminal"]["binding"]["prepared_original_ref"],prior["terminal"]["original_ref"]))
    return production_read_plan_v1((),keys,roots,originals)

def _artifact_observer(metadata,namespace,goal_ref):
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    goal=metadata.graph_v3(goal_ref)
    if goal is None:return production_read_plan_v1((),())
    predicate=goal[2]["satisfaction_predicate"]
    if(predicate["kind"],predicate["observation_provider"])!=("domain_state","d08.artifact_task_objective.v1"):
        return production_read_plan_v1((),())
    ref=dict(predicate["parameters"])["objective_ref"];objective=metadata.life_v3("artifact_task_objective",ref)
    if objective is None:return production_read_plan_v1((),(),(),(ref,))
    checkpoint=project_checkpoint_key_v1(namespace,objective["project_ref"]);keys=[checkpoint];roots=[];originals=[ref];plans=[]
    current=metadata.graph_v3(checkpoint.token)
    if current is not None:
        for work_ref in current[2]["work_version_refs"]:
            keys.append(AtomKey.from_token(work_ref));work=metadata.graph_v3(work_ref)
            if work is None:continue
            plans.append(_life_progress(metadata,namespace,work[2]["progress_ref"],project_effect=True))
            adopted=metadata.life_v3("adopted_life",work[2]["artifact_ref"])
            if adopted is None:continue
            prepared=metadata.life_v3("prepared",adopted["terminal"]["binding"]["prepared_original_ref"])
            if prepared is None:continue
            from .artifact_task_amendment_v1 import amendment_key_v1,amendment_original_ref_v1,decode_amendment_v1
            key=amendment_key_v1(namespace,prepared["plan"]["target"]["root_registration_ref"]);keys.append(key)
            amendment=metadata.graph_v3(key.token)
            if amendment is not None:originals.append(amendment_original_ref_v1(decode_amendment_v1(amendment[2])))
    return _merge_plans_v3(production_read_plan_v1((),keys,roots,originals),*plans)

def _binding_inputs(metadata,namespace,binding,*,prospective=True):
    refs=("action_ref","action_schema_ref","project_ref","recipe_ref","goal_ref","target_entity_ref","role_ref","progress_ref")
    keys=[AtomKey.from_token(binding[name])for name in refs if binding[name]is not None]
    roots=list(binding["source_refs"]);originals=list(_executor_originals(binding));plans=[]
    if prospective and binding["schema"]=="d10.joint-artifact-prospective-binding.v1":
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
        executor=binding["executor"];task=artifact_draft_task_selector_v1(namespace,c02_operation_id=executor["c02_operation_id"],root_registration_ref=executor["root_registration_ref"])
        keys.append(AtomKey.from_token(task.cycle_job_ref));originals.extend((binding["objective_ref"],binding["task_scope_ref"]))
        if executor["phase_selector"]is not None:
            phase=decode_typed_production_value_v1(executor["phase_selector"],ArtifactDraftPhaseSelectorV2)
            keys.extend((AtomKey.from_token(phase.decision_ref),AtomKey.from_token(phase.plan_ref)))
            if phase.prev_phase_original_ref is not None:originals.append(phase.prev_phase_original_ref)
        plans.append(_artifact_observer(metadata,namespace,binding["goal_ref"]))
    elif prospective and binding["schema"]=="d10.joint-contact-prospective-binding.v1":
        originals.append(binding["prospective_original_ref"])
    if binding["progress_ref"]is not None:plans.append(_life_progress(metadata,namespace,binding["progress_ref"]))
    return _merge_plans_v3(production_read_plan_v1((),keys,roots,originals),*plans)

def augment_artifact_joint_business_metadata_plan_v3(*,namespace,phase,plan,metadata,action_ref=None):
    """Exact existing ALL-node JointPlan augment; unrelated managed Windows are excluded."""
    if type(metadata)is not ArtifactRecipeMetadataV3:raise TypeError("exact pure Artifact metadata cache required")
    binding=_binding(metadata,namespace,phase,action_ref)
    if binding is None:return plan
    key=AtomKey.from_token(binding["plan_ref"]);head=metadata.graph_v3(key.token)
    keys=[key,owner_grant_key(*namespace.as_tuple)];roots=[];originals=[binding["_original_ref"]];parts=[]
    if head is not None and head[1]:
        value=head[2];roots.extend(value["source_refs"])
        history=metadata.need_v3("history","event",key.token,binding["plan_revision"])
        adopted=None if history is None else metadata.domain_v3(history["event_id"])
        if adopted is not None:
            request=adopted["payload"]["request"];proposal=request["joint_plan_proposal_ref"];consents=request["party_consent_original_refs"]
            originals.extend((proposal,*consents))
            intent=_registered(metadata,"joint_plan_intent",proposal)
            if intent is not None:
                keys.extend(AtomKey.from_token(ref)for ref in intent["current_goal_refs"]);roots.extend(intent["source_refs"])
            for ref in consents:
                consent=_registered(metadata,"party_consent",ref)
                if consent is not None:
                    keys.append(AtomKey.from_token(consent["acceptance_interpretation_ref"]));roots.append(consent["inbound_source_ref"])
                    originals.extend((consent["acceptance_interpretation_ref"],*consent["outbound_receipt_refs"]))
        from .joint_node_execution_v1 import BINDING_PREFIX
        for node in value["nodes"]:
            if node["owner_ref"]!="persona:"+namespace.persona_id:
                contract=_registered(metadata,"external_contract",node["resource_ref"]);originals.append(node["resource_ref"])
                if contract is not None:roots.extend(contract["source_refs"])
                observations=metadata.need_v3("joint_registered_index","external_observations","all")
                if len(observations)>128:raise ValueError("actual external observation metadata exceeds existing bound")
                for ref,observation in observations:
                    if observation["node_id"]!=node["node_id"]:continue
                    keys.extend((_gv_v3(observation["inbound_source"]).key,_gv_v3(observation["interpretation"]).key,
                        *(_gv_v3(head).key for head in observation["actor_heads"])))
                    roots.extend(observation["source_refs"]);originals.append(ref)
                continue
            current=_registered(metadata,"binding",node["resource_ref"])
            if node["resource_ref"].startswith(BINDING_PREFIX):originals.append(node["resource_ref"])
            if current is None:continue
            if current["schema"]not in{"d10.joint-node-execution-binding.v1","d10.joint-artifact-prospective-binding.v1","d10.joint-contact-prospective-binding.v1"}:
                raise ValueError("actual Joint node has an unknown fixed binding metadata schema")
            parts.append(_binding_inputs(metadata,namespace,current))
            if node["compensation_ref"]is not None:
                compensation=_registered(metadata,"compensation",node["compensation_ref"]);originals.append(node["compensation_ref"])
                if compensation is not None:
                    repair=_registered(metadata,"binding",compensation["repair_binding_ref"])
                    if repair is not None:
                        roots.extend(compensation["source_refs"]);originals.append(compensation["repair_binding_ref"])
                        parts.append(_binding_inputs(metadata,namespace,repair,prospective=False))
    from ..domains.d12.types import active_scheme_head_key
    keys.append(active_scheme_head_key(namespace))
    for _,valid,ticket in metadata.inventory_v3("d07.attention_ticket.v1"):
        if valid:roots.extend(ticket["source_refs"])
    types=("d03.entity_anchor","d03.account_binding","d05.boundary_rule","d07.current_interpretation.v1",
        "d07.attention_ticket.v1","d07.focus.v1","d07.concern_round.v1","d08.goal.v1","d08.action_intent.v1",
        "d08.action_schema.v1","d08.action_cancellation.v1","d08.action_outcome.v1","d10.life_progress.v1","runtime.cost_settlement")
    return _merge_plans_v3(plan,production_read_plan_v1(types,keys,roots,originals),*parts)

_JOINT_REGISTERED_PROFILES_V3={
    "executor_index":("graph_d10_production_inputs_v1",("joint_executor_index_v1",),"d11.d10-production-input.v1","d10","input:register_joint_node_execution_binding_v1"),
    "binding":("graph_d10_production_inputs_v1",("joint_node_execution_binding_v1","joint_artifact_prospective_binding_v1","joint_contact_prospective_binding_v1"),"d11.d10-production-input.v1","d10","input:register_joint_node_execution_binding_v1"),
    "joint_plan_intent":("graph_d08_joint_plan_intents_v1",(),"d11.d08-joint-plan-intent.v1","d08","input:register_joint_plan_intent"),
    "party_consent":("graph_d08_party_consents_v1",(),"d11.d08-party-consent.v1","d08","input:register_party_consent"),
    "external_contract":("graph_d08_joint_node_originals_v1",("external_node_contract_v1",),"d11.d08-joint-node-original.v1","d08","input:register_joint_external_contract_v1"),
    "external_observation":("graph_d08_joint_node_originals_v1",("external_node_observation_v1",),"d11.d08-joint-node-original.v1","d08","input:observe_joint_external_node_v1"),
    "compensation":("graph_d08_joint_node_originals_v1",("compensation_authorization_v1",),"d11.d08-joint-node-original.v1","d08","input:register_joint_compensation_v1"),
}

def artifact_joint_registered_metadata_profile_v3(kind):
    """Fixed actual table, row kinds, signature and registered producer operation."""
    return _JOINT_REGISTERED_PROFILES_V3[kind]

def artifact_joint_business_metadata_path_v3(locator,path,*,actual_domain_kind=None):
    """Closed metadata projection for the ALL-node existing Joint business recipe."""
    from .artifact_recipe_metadata_v3 import _shape_retains_v3,_wire_shape_v3
    if locator.family=="joint_registered":
        scalar="scalar";array=("array",scalar)
        common={"namespace":{"bot_id":scalar,"persona_id":scalar},"schema":scalar,"source_refs":array}
        if locator.kind=="executor_index":
            common.update({name:scalar for name in("selector_kind","binding_ref","binding_digest","registration_request_digest")})
            common["selector_key"]=array
        elif locator.kind=="binding":
            common.update({name:scalar for name in("node_id","plan_ref","plan_revision","action_ref","action_schema_ref","project_ref",
                "recipe_ref","goal_ref","target_entity_ref","role_ref","progress_ref","objective_ref","task_scope_ref","prospective_original_ref")})
            from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
            common["executor"]={name:scalar for name in("schema","authorization_original_ref","c02_operation_id",
                "source_ref","root_registration_ref","prepare_contact_operation_id","qualified_outbox_dedupe_key")}
            common["executor"]["phase_selector"]=_wire_shape_v3(ArtifactDraftPhaseSelectorV2)
        elif locator.kind=="joint_plan_intent":common["current_goal_refs"]=array
        elif locator.kind=="party_consent":
            common.update({"acceptance_interpretation_ref":scalar,"inbound_source_ref":scalar,"outbound_receipt_refs":array})
        elif locator.kind=="external_observation":
            common.update({name:scalar for name in("node_id","plan_ref","plan_revision","terms_digest","party_consent_ref","party_consent_digest","producing_operation_id")})
            common.update({name:_wire_shape_v3(GraphVersion)for name in("inbound_source","interpretation")})
            common["actor_heads"]=("array",_wire_shape_v3(GraphVersion))
        elif locator.kind=="compensation":common["repair_binding_ref"]=scalar
        elif locator.kind!="external_contract":raise ValueError("unknown fixed Joint registered metadata profile")
        return _shape_retains_v3(common,path)
    if locator.family=="graph":
        from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE,WORK_TYPE
        if locator.kind==CHECKPOINT_TYPE and path and path[0]=="work_version_refs":
            return _shape_retains_v3({"work_version_refs":("array","scalar")},path)
        if locator.kind==WORK_TYPE and path and path[0]=="progress_ref":return len(path)==1
        if locator.kind=="d07.attention_ticket.v1":return _shape_retains_v3({"source_refs":("array","scalar")},path)
        if locator.kind=="d08.joint_plan.v1":
            return _shape_retains_v3({"source_refs":("array","scalar"),"nodes":("array",{name:"scalar"for name in("node_id","owner_ref","resource_ref","compensation_ref")})},path)
        if locator.kind=="d10.life_progress.v1":
            return _shape_retains_v3({**{name:"scalar"for name in("step","artifact_ref","terminal_ref","effect_id")},"receipt_refs":("array","scalar")},path)
        from .d10_life_progress_provenance_v1 import PROVENANCE_TYPE
        if locator.kind==PROVENANCE_TYPE:
            from .d11_life_contract_v1 import D11LifeExecutionBindingV1,D11DraftExecutionBindingV1
            binding={**_wire_shape_v3(D11LifeExecutionBindingV1),**_wire_shape_v3(D11DraftExecutionBindingV1)}
            return _shape_retains_v3({"fact_ref":"scalar","terminal_provenance":{"binding":binding,"prepared_digest":"scalar"}},path)
        if locator.kind=="d06.artifact_task_amendment.v1":
            from .artifact_task_amendment_v1 import ArtifactTaskAmendmentV1
            return _shape_retains_v3(_wire_shape_v3(ArtifactTaskAmendmentV1),path)
    if locator.family=="life":
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1,D11DraftExecutionBindingV1
        from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1
        binding={**_wire_shape_v3(D11LifeExecutionBindingV1),**_wire_shape_v3(D11DraftExecutionBindingV1)}
        if locator.kind=="prepared":
            from .d11_life_contract_v1 import LifeInputRefV1
            refs={name:_wire_shape_v3(LifeInputRefV1)for name in("project","recipe","action_intent","input_source","input_access")}
            refs.update(activity_scope_ref="scalar",target={"mode":"scalar","root_registration_ref":"scalar"},content={"source_refs":("array","scalar")})
            shape={"schema":"scalar","binding":binding,"plan":refs,
                "read_rows":("array",{"ref":"scalar","revision":"scalar","valid":"scalar"})}
        elif locator.kind=="adopted_life":
            shape={"terminal":{"binding":binding,"original_ref":"scalar"}}
        elif locator.kind=="activity_scope":shape=_wire_shape_v3(DraftActivityScopeV1)
        elif locator.kind=="artifact_task_objective":
            from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1
            shape=_wire_shape_v3(ArtifactTaskObjectiveV1)
        else:return None
        # Preserve the existing WRITE profile's extra terminal readback/claim fields.
        if locator.kind=="adopted_life"and path and path[0]=="write_commitments":return None
        if locator.kind=="adopted_life"and len(path)>1 and path[1]in{"payload","claim"}:return None
        if locator.kind=="prepared"and path and path[0]=="admission_ref":return None
        return _shape_retains_v3(shape,path)
    if locator.family=="domain"and actual_domain_kind==("d08","adopt_joint_plan")and path and path[0]=="request":
        return _shape_retains_v3({"joint_plan_proposal_ref":"scalar","party_consent_original_refs":("array","scalar")},path[1:])
    if locator.family=="domain"and actual_domain_kind==("d08","select_existing_artifact_continuation_v1")and path and path[0]=="provenance":
        return _shape_retains_v3({"basis":{"predecessor_effect_id":"scalar"}},path[1:])
    return None

def artifact_joint_registration_request_frame_v3(kind,ref):
    """Canonical framing hashes real payload bytes while all Body fields are discarded."""
    from ..runtime_contracts import canonical_serialize
    fields={"binding":"binding","joint_plan_intent":"intent","party_consent":"evidence",
        "external_contract":"contract","compensation":"authorization"}
    if kind not in fields:return None
    prefix=("{"+canonical_serialize(fields[kind])+":").encode("utf-8")
    suffix=(","+canonical_serialize("original_ref")+":"+canonical_serialize(ref)+"}"if kind in{"joint_plan_intent","party_consent"}else"}").encode("utf-8")
    return prefix,suffix

def artifact_joint_registration_request_digest_v3(kind,value):
    """The two fixed profiles whose exact request is already metadata only."""
    if kind=="executor_index":return value["registration_request_digest"]
    if kind=="external_observation":
        from .joint_external_observation_v1 import ObserveJointExternalNodeRequestV1
        request=ObserveJointExternalNodeRequestV1(value["plan_ref"],value["plan_revision"],value["node_id"],
            _gv_v3(value["inbound_source"]),_gv_v3(value["interpretation"]),value["party_consent_ref"],value["party_consent_digest"])
        return canonical_digest(request)
    raise ValueError("actual wrapped canonical registration payload digest required")
