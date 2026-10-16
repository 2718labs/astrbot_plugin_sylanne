"""Pure metadata locator composition of the four existing Artifact WRITE recipes."""
from ..graph_types import AtomKey,Owner,owner_grant_key
from .d01_production_operations_v1 import production_read_plan_v1
from .artifact_recipe_metadata_v3 import (ArtifactRecipeMetadataV3,_merge_plans_v3,
    _personal_plan_v3,compose_artifact_borrowed_metadata_plan_v3)

def _life(metadata,kind,ref):return metadata.life_v3(kind,ref)
def _source_refs(value):
    for ref in(*value.get("source_refs",()),*value.get("creation_evidence_refs",()),*value.get("reason_refs",())):
        try:key=AtomKey.from_token(ref)
        except ValueError:yield False,ref
        else:yield key.type_name=="memory.source",ref

def _predecessor(metadata,target):
    if target["mode"]=="create":return ()
    selected=metadata.need_v3("life_index","adopted_by_marker",target["expected_prior_effect_marker"])
    if len(selected)!=1:raise ValueError("actual signed draft predecessor metadata is not unique")
    ref,value=selected[0]
    return(ref,value["terminal"]["binding"]["prepared_original_ref"])

def _completed(metadata,namespace,phase):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_file_ids_v2
    from .d11_types import runtime_job_key
    from .d08_personal_plan_v1 import artifact_phase_action_keys_v2
    from .d02_life_body_preparation_v1 import _refs
    from ..memory_types import access_key
    model=artifact_draft_model_ids_v2(phase);file=artifact_draft_file_ids_v2(phase)
    prepared=_life(metadata,"c4_phase_prepared",model["job"])
    if prepared is None:raise ValueError("completed phase metadata lacks actual preparation")
    keys=[AtomKey.from_token(phase.task.cycle_job_ref),runtime_job_key(*namespace.as_tuple,prepared["activity_id"],prepared["job_id"]),
        *artifact_phase_action_keys_v2(phase)]
    originals=[model[name]for name in("job","frozen","request","call","paid","result","adopt")]
    operations=[prepared["operation_id"],prepared["acquire_operation_id"],model["adopt"],file["action_operation"],"d02-life-body:"+file["action_operation"]]
    operations.extend(metadata.need_v3("history_index","valid_cycle_events",phase.task.cycle_job_ref))
    for operation in dict.fromkeys(operations):
        producer=metadata.domain_v3(operation)
        if producer is not None:
            originals.append(producer["domain"]+"-current:"+producer["original_digest"][:48])
            keys.extend(version.key for version in(*producer["read_versions"],*producer["receipt"].write_versions))
    roots=[];adoption=_life(metadata,"c4_phase_adopted",model["adopt"])
    if adoption is not None:
        source=AtomKey.from_token(adoption["content"]["content"]["ref"])
        keys.extend((source,access_key(*namespace.as_tuple,source.owner.subject)))
        roots.extend(adoption["content"]["source_refs"]);originals.extend((adoption["activity_scope_ref"],adoption["extent_original_ref"]))
    paid=_life(metadata,"c4_phase_paid",model["paid"])
    if paid is not None:keys.append(AtomKey.from_token(paid["cost_ref"]))
    body_op="d02-life-body:"+file["action_operation"];body=_life(metadata,"life_body_preparation","life-body:"+body_op)
    if body is not None:
        originals.append("life-body:"+body_op);keys.extend(_refs(namespace,prepared["activity_id"],body_op))
    rows=metadata.need_v3("life_index","prepared_by_action",file["action_operation"])
    if len(rows)>1:raise ValueError("phase metadata has conflicting actual Life preparations")
    if rows:
        ref,life=rows[0];binding=life["binding"]
        originals.extend((binding["prepared_original_ref"],binding["plan_original_ref"]))
        if life["admission_ref"]is not None:originals.append(life["admission_ref"])
        keys.extend(AtomKey.from_token(row["ref"])for row in life["read_rows"])
        producer=metadata.domain_v3(binding["prepare_operation_id"])
        if producer is not None:
            originals.append(producer["domain"]+"-current:"+producer["original_digest"][:48]);keys.extend(v.key for v in producer["receipt"].write_versions)
        adopted=_life(metadata,"adopted_life",binding["artifact_ref"])
        if adopted is not None:
            originals.extend((binding["artifact_ref"],adopted["terminal"]["original_ref"],adopted["terminal"]["claim"]["original_ref"]))
            keys.extend(AtomKey.from_token(row["ref"])for row in adopted["write_commitments"])
            import json
            contract=json.loads(life["plan"]["body_effect_request_json"]);settlement=AtomKey.from_token(contract["settlement_ref"]);keys.append(settlement)
            event=metadata.need_v3("history","event",settlement.token,1)
            producer=None if event is None else metadata.domain_v3(event["event_id"])
            if producer is not None:
                originals.append(producer["domain"]+"-current:"+producer["original_digest"][:48])
                keys.extend(v.key for v in(*producer["read_versions"],*producer["receipt"].write_versions))
    return production_read_plan_v1((),keys,roots,originals)

def _action(metadata,namespace,phase):
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2,artifact_draft_model_ids_v2
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from .d08_personal_plan_v1 import artifact_phase_action_keys_v2
    from ..domains.d03.self_perspective import self_mapping_key
    profile=metadata.need_v3("installation","personal_candidate","current")
    if profile["reader_present"]is not True:raise ValueError("actual Artifact Action recipe needs real installed PersonalCandidate readers")
    file=artifact_draft_file_ids_v2(phase);model=artifact_draft_model_ids_v2(phase)
    base=_personal_plan_v3(metadata,namespace,file["activity_id"],phase)
    cycle=metadata.job_v3(AtomKey.from_token(phase.task.cycle_job_ref).name)
    content=compose_artifact_borrowed_metadata_plan_v3(namespace=namespace,operation_kind="acquire_artifact_draft_model_v2",
        activity_id=cycle["activity_id"],metadata=metadata,actual_selector=phase)
    from ..memory_types import source_key,access_key
    content=_merge_plans_v3(content,production_read_plan_v1((),
        (source_key(*namespace.as_tuple,model["source"]),access_key(*namespace.as_tuple,model["source"])),(),(model["paid"],model["result"])))
    completed=_completed(metadata,namespace,phase)
    keys=[self_mapping_key(namespace),*artifact_phase_action_keys_v2(phase)];roots=[];originals=[model["adopt"]]
    plan=metadata.graph_v3(phase.plan_ref)
    if plan is not None:
        goal=metadata.graph_v3(plan[2]["goal_ref"])
        if goal is not None:
            params=dict(goal[2]["satisfaction_predicate"]["parameters"])
            ref=params["objective_ref"];objective=_life(metadata,"artifact_task_objective",ref)
            if objective is None:raise ValueError("actual Artifact Action has no signed objective metadata")
            project,recipe=AtomKey.from_token(objective["project_ref"]),AtomKey.from_token(objective["recipe_ref"])
            context=life_project_context_keys_v1(namespace,project.token);keys.extend((project,recipe,*context))
            originals.extend((ref,project.token,recipe.token,*(key.token for key in context)))
    adoption=_life(metadata,"c4_phase_adopted",model["adopt"])
    if adoption is not None:
        keys.extend((AtomKey.from_token(adoption["task_source"]["ref"]),AtomKey.from_token(adoption["content"]["content"]["ref"])))
        roots.extend(adoption["content"]["source_refs"]);originals.extend((adoption["activity_scope_ref"],adoption["extent_original_ref"]))
    return _merge_plans_v3(base,content,completed,production_read_plan_v1(
        ("d08.action_schema.v1","d12.active_scheme_head.v1","d03.entity_anchor","d03.role_binding"),keys,roots,originals))

def _registration(metadata,namespace,activity_id,phase):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_file_ids_v2
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from ..domains.d03.self_perspective import self_mapping_key
    from ..memory_types import access_key
    action_plan=_action(metadata,namespace,phase);file=artifact_draft_file_ids_v2(phase);model=artifact_draft_model_ids_v2(phase)
    if activity_id!=file["activity_id"]:raise ValueError("Artifact file metadata crossed actual phase activity")
    owner=Owner("activity",*namespace.as_tuple,activity_id)
    project=AtomKey(Owner("persona",*namespace.as_tuple),"d10.life_project.v1",file["project"])
    action=AtomKey(owner,"d08.action_intent.v1",file["action"])
    keys=[owner_grant_key(*namespace.as_tuple),self_mapping_key(namespace),AtomKey.from_token(phase.task.cycle_job_ref),
        AtomKey.from_token(phase.plan_ref),AtomKey.from_token(phase.decision_ref),project,AtomKey.from_token(file["recipe_ref"]),
        action,AtomKey(owner,"d08.action_cancellation.v1",file["action"]),*life_project_context_keys_v1(namespace,project.token)]
    roots=[];body_ref="life-body:d02-life-body:"+file["action_operation"]
    originals=[phase.task.root_registration_ref,*(model[name]for name in("job","frozen","adopt","paid","result")),
        "life-draft-root:"+file["action_operation"],body_ref]
    if phase.prev_phase_original_ref is not None:originals.append(phase.prev_phase_original_ref)
    adoption=_life(metadata,"c4_phase_adopted",model["adopt"])
    if adoption is not None:
        roots.extend(adoption["content"]["source_refs"])
        keys.extend((AtomKey.from_token(adoption["content"]["content"]["ref"]),AtomKey.from_token(adoption["task_source"]["ref"])))
        keys.extend(access_key(*namespace.as_tuple,AtomKey.from_token(ref).owner.subject)for ref in adoption["content"]["source_refs"])
        originals.extend((adoption["activity_scope_ref"],adoption["extent_original_ref"],*_predecessor(metadata,adoption["target"])))
        scope=_life(metadata,"activity_scope",adoption["activity_scope_ref"])
        if scope is not None:originals.extend((scope["ingress_original_ref"],scope["c02_original_ref"]))
    body=_life(metadata,"life_body_preparation",body_ref)
    if body is not None:
        keys.extend(AtomKey.from_token(body[name])for name in("reservation_ref","settlement_ref"))
        originals.extend(body[name]for name in("body_quote_ref","resource_quote_ref","effect_policy_ref"))
    return _merge_plans_v3(action_plan,production_read_plan_v1(LIFE_CURRENT_TYPES,keys,roots,originals))

def _life_inventory(metadata,namespace,action_ref,project_ref,input_source_ref,audiences,now_utc):
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from .d11_life_scope_v1 import DraftLifeSemanticScopeV1
    from .role_resources import role_resources_key
    action=metadata.graph_v3(action_ref)
    if action is None or not action[1]:raise ValueError("Artifact Life metadata requires current actual Action")
    value=action[2]
    if value["action_kind"]!="artifact_draft_v1":raise ValueError("Artifact Life source profile cannot borrow SourceNote Action")
    entities=metadata.inventory_v3("d03.entity_anchor")
    if len(entities)>128:raise ValueError("Artifact Life metadata entity inventory exceeds existing bound")
    matched=tuple(version.key.token for version,valid,entity in entities if valid and entity["entity_id"]==value["target_ref"])
    if len(matched)!=1:raise ValueError("Artifact Life metadata has no unique actual target entity")
    scope=DraftLifeSemanticScopeV1(namespace,project_ref,input_source_ref,matched[0],value["target_ref"],
        value["action_id"],value["goal_ref"],tuple(value["commitment_refs"]),tuple(audiences),now_utc)
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[]
    activation=AtomKey(Owner("persona",*namespace.as_tuple),"d01.persona_activation.v1","current")
    keys.append(activation);head=metadata.graph_v3(activation.token)
    if head is not None and head[1]:
        keys.extend((AtomKey(activation.owner,"d01.persona_plan.v1",head[2]["plan_id"]),role_resources_key(namespace,head[2]["plan_id"])))
    inventory={kind:metadata.inventory_v3(kind)for kind in LIFE_CURRENT_TYPES}
    if any(len(rows)>128 for rows in inventory.values()):raise ValueError("Artifact Life metadata inventory exceeds actual recipe bound")
    action_ids={row["action_id"]for version,valid,row in inventory["d08.action_intent.v1"]if valid and scope.includes("d08.action_intent.v1",version.key,row)}
    for kind,rows in inventory.items():
        for version,valid,row in rows:
            if not valid:continue
            if (row["action_id"]not in action_ids if kind=="d08.action_outcome.v1"else not scope.includes(kind,version.key,row)):continue
            for is_source,ref in _source_refs(row):
                if is_source:roots.append(ref)
                else:
                    try:keys.append(AtomKey.from_token(ref))
                    except ValueError:pass
                    originals.append(ref)
    return production_read_plan_v1((),keys,roots,originals)

def _body(metadata,namespace,activity_id,operation_id,request,now_utc):
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from .d02_life_body_preparation_v1 import _refs
    action=metadata.graph_v3(request.action_intent_ref)
    if action is None or not action[1]:raise ValueError("Artifact Body metadata has no real current Action")
    operation=action[2]["identity"]["operation_id"]
    root=_life(metadata,"draft_action","life-draft-root:"+operation)
    if root is None:raise ValueError("Artifact Body metadata has no actual signed Action root")
    base=_life_inventory(metadata,namespace,request.action_intent_ref,root["project_ref"],root["input_source_ref"],root["audiences"],now_utc)
    return _merge_plans_v3(base,production_read_plan_v1(LIFE_CURRENT_TYPES,
        (AtomKey.from_token(root["project_ref"]),AtomKey.from_token(root["recipe_ref"]),
            AtomKey.from_token(request.action_intent_ref),*_refs(namespace,activity_id,operation_id)),
        (root["input_source_ref"],),(request.action_intent_ref,request.effect_policy_ref)))

def _project_control(metadata,namespace,project_ref):
    project=metadata.graph_v3(project_ref)
    if project is None or not project[1]:raise ValueError("Artifact metadata lost its actual current project")
    history=metadata.need_v3("history","event",project_ref,project[0].revision)
    producer=None if history is None else metadata.domain_v3(history["event_id"])
    if producer is None or(producer["domain"],producer["operation_kind"])not in{
            ("d10","create_artifact_project"),("d10","create_artifact_task_project_v1"),("d08","revise_existing_artifact_v1")}or project[0]not in producer["receipt"].write_versions:
        raise ValueError("Artifact project metadata lost its actual fixed producer")
    provenance=producer["payload"]["provenance"]
    if producer["operation_kind"]=="create_artifact_task_project_v1":
        basis=provenance["task_project_basis"];refs=(basis["plan_head"]["key"],basis["goal_head"]["key"])
    elif producer["operation_kind"]=="revise_existing_artifact_v1":
        basis=provenance["basis"];refs=(basis["plan_ref"],basis["goal_ref"])
    else:refs=(provenance["artifact_plan_ref"],provenance["artifact_goal_ref"])
    for ref in refs:
        head=metadata.graph_v3(ref)
        if head is None or not head[1]:raise ValueError("Artifact current project Plan/Goal metadata unavailable")
    return tuple(AtomKey.from_token(ref)for ref in refs)

def _life_plan(metadata,namespace,activity_id,request,now_utc):
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from .d11_life_contract_v1 import life_from_wire_v1
    from .d11_life_preparation_v1 import life_ids_v1
    from .d11_role_clock_installation_v1 import role_clock_mapping_id_v1
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    raw=_life(metadata,"plan",request.plan_original_ref)
    if raw is None:return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),),(),(request.plan_original_ref,))
    plan=life_from_wire_v1(raw,RegisteredDraftFilePlanV3)
    if type(plan)is not RegisteredDraftFilePlanV3 or plan.activity_id!=activity_id:raise ValueError("Artifact Life metadata changed actual activity/registered plan")
    keys=[owner_grant_key(*namespace.as_tuple)]
    keys.extend(AtomKey.from_token(getattr(plan,name).ref)for name in("project","recipe","action_intent","input_source","input_access"))
    keys.append(AtomKey(Owner("activity",*namespace.as_tuple,activity_id),"runtime.job",life_ids_v1(plan)["job"]))
    keys.extend((*_project_control(metadata,namespace,plan.project.ref),AtomKey.from_token(plan.content.content.ref)))
    roots=[plan.input_source.ref,*plan.content.source_refs]
    originals=[request.plan_original_ref,plan.activity_scope_ref,plan.target.root_registration_ref,
        *_predecessor(metadata,raw["target"]),role_clock_mapping_id_v1(namespace)]
    scope=_life(metadata,"activity_scope",plan.activity_scope_ref)
    if scope is not None:originals.extend((scope["ingress_original_ref"],scope["c02_original_ref"]))
    if plan.body_effect_request_json is not None:
        import json
        contract=json.loads(plan.body_effect_request_json)
        keys.extend(AtomKey.from_token(contract[name])for name in("reservation_ref","settlement_ref"))
        originals.extend(contract[name]for name in("body_quote_ref","resource_quote_ref","effect_policy_ref"))
    inventory=_life_inventory(metadata,namespace,plan.action_intent.ref,plan.project.ref,plan.input_source.ref,plan.audiences,now_utc)
    before=metadata.need_v3("installation","life_before_policy","current")
    extra=production_read_plan_v1((),())
    if before is not None:
        inputs=metadata.need_v3("d04_before","selected_root",before.root_operation_id)
        extra=production_read_plan_v1((),inputs["keys"],inputs["source_roots"])
    return _merge_plans_v3(production_read_plan_v1(LIFE_CURRENT_TYPES,keys,roots,originals),inventory,extra)

def compose_artifact_write_metadata_plan_v3(*,namespace,operation_kind,activity_id,operation_id,request,phase,metadata,now_utc):
    from .domain_production_registry_v1 import installed_operation_v1
    if type(metadata)is not ArtifactRecipeMetadataV3 or type(request)is not installed_operation_v1(operation_kind).request_type:
        raise TypeError("actual fixed typed Artifact WRITE metadata recipe required")
    if operation_kind=="propose_artifact_draft_phase_action_v2":return _action(metadata,namespace,phase)
    if operation_kind=="input:register_artifact_phase_draft_plan_v2":return _registration(metadata,namespace,activity_id,phase)
    if operation_kind=="prepare_artifact_draft_body":return _body(metadata,namespace,activity_id,operation_id,request,now_utc)
    if operation_kind=="prepare_life":return _life_plan(metadata,namespace,activity_id,request,now_utc)
    raise ValueError("unregistered fixed Artifact WRITE metadata recipe")
