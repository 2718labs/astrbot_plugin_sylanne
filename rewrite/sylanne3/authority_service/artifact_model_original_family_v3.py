"""Exact C4 Original locators derived from actual signed business parents."""
from dataclasses import fields
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..graph_types import AtomKey

def _reader_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .artifact_model_source_read_v3 import artifact_model_namespace_recipe_v3
    work=_authority_attachment_owner_v3(db)
    return None if work is None else artifact_model_namespace_recipe_v3(work)

def seed_artifact_original_family_v3(reader):
    task=reader.selector.task if reader.phase_variant else reader.selector
    from ..runtime.ingress_artifact_task_scope_v1 import task_scope_ref_v1
    reader.original_keys.add(("artifact_task_scope",task_scope_ref_v1(task.root_registration_ref)))
    if reader.phase_variant:
        frozen=reader.frozen.value
        reader.original_keys.add(("artifact_phase_postcondition_contract",frozen["postcondition_contract_ref"]))
        if reader.selector.prev_phase_original_ref is not None:
            reader.original_keys.add(("c4_phase_verified",reader.selector.prev_phase_original_ref))
    from ..runtime.joint_node_execution_v1 import joint_executor_index_ref_v1
    reader.proof_original_refs.update((joint_executor_index_ref_v1(reader.work.namespace,"artifact_task",
        (task.c02_operation_id,task.root_registration_ref)),joint_executor_index_ref_v1(reader.work.namespace,"artifact",
        (task.c02_operation_id,task.root_registration_ref,reader.selector.identity_digest if reader.phase_variant else"legacy"))))
    for ref in tuple(reader.proof_original_refs):reader.proof_original_domains[ref]="d10"
    reader.original_keys.update(((reader.prefix+"paid",reader.ids["paid"]),(reader.prefix+"result",reader.ids["result"])))

def _admit_source_versions_v3(reader,versions):
    business={v.key.token:v.revision for v in reader.business_versions}
    for version in versions:
        if version.key.type_name=="memory.source":
            current=reader.qualified.get(version.key.token)
            if current is None or current[0].revision!=version.revision or business.get(version.key.token)!=version.revision:
                raise AuthorityUnavailable("Artifact Original evidence references Source outside actual independently qualified B/C")
        elif version.key.token not in business:
            raise AuthorityUnavailable("Artifact business Original evidence escapes its original exact B recipe")
        else:reader.graph_versions.add((version.key.token,version.revision))

def admit_artifact_candidate_family_v3(db,*,prepared,chosen,selected):
    r=_reader_v3(db)
    if r is None:return
    r.capability.require_v3()
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1,ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
    if(type(prepared)is not PreparedPersonalCandidateSetV1 or prepared.namespace!=r.work.namespace
            or prepared.preparation_operation_id not in r.original_operations
            or selected["receipt"].operation_id not in r.original_operations
            or chosen not in prepared.candidates or prepared.future_decision_ref!=r.selector.decision_ref):
        raise AuthorityUnavailable("Artifact candidate locator family lacks its actual positive selected D08 producer")
    evidences=[(prepared.need.original,prepared.need.read_versions,prepared.need.query_coverage)]
    for candidate in prepared.candidates:
        for original in candidate.eligibility.originals:
            evidences.append((original,candidate.eligibility.read_versions,candidate.eligibility.query_coverage))
        if candidate.price is not None:
            evidences.append((candidate.price.original,candidate.price.read_versions,candidate.price.query_coverage))
        if candidate.quote_ref is not None:r.quote_versions.add((candidate.quote_ref,1))
        binding=candidate.binding
        if type(binding)not in{ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:continue
        if type(binding)in{ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:
            r.original_keys.add(("artifact_task_text_extent",binding.extent_original_ref))
        if type(binding)is ArtifactPhaseCandidateBindingV3:
            r.original_keys.add(("artifact_phase_postcondition_policy",binding.postcondition_policy_ref))
        if binding.activity_scope_ref is not None:r.original_keys.add(("activity_scope",binding.activity_scope_ref))
        if binding.prev_phase_original_ref is not None:r.original_keys.add(("c4_phase_verified",binding.prev_phase_original_ref))
    from ..runtime.d08_personal_candidate_v1 import personal_candidate_evidence_read_plan_v3
    plan=personal_candidate_evidence_read_plan_v3(read_versions=prepared.read_versions,query_coverage=prepared.query_coverage,
        future_decision_ref=prepared.future_decision_ref,preparation_original_digest=r.control.habit_classification.prepared_candidates_original_digest,
        evidences=evidences)
    _admit_source_versions_v3(r,prepared.read_versions)
    for original,versions,_ in evidences:
        _admit_source_versions_v3(r,(*versions,*original.read_versions))
        r.proof_original_refs.add(original.original_ref)
        prior=r.proof_original_digests.get(original.original_ref)
        if prior is not None and prior!=original.original_digest:raise AuthorityUnavailable("Artifact actual all-candidate Original digest conflicts")
        r.proof_original_digests[original.original_ref]=original.original_digest
        r.proof_original_values[original.original_ref]=original
    business={v.key.token:v.revision for v in r.business_versions}
    if(any(key.token not in business for key in plan.exact_keys)
            or any(ref not in business or AtomKey.from_token(ref).type_name!="memory.source"for ref in plan.source_roots)):
        raise AuthorityUnavailable("Artifact actual all-candidate business recipe exceeds exact acquired B")
    r.candidate_family=(prepared,chosen,selected["receipt"].operation_id,plan)

def register_artifact_signed_original_v3(db,kind,ref,raw,producer):
    r=_reader_v3(db)
    if r is None:return False
    r.capability.require_v3()
    if(kind,ref)not in r.original_keys:
        raise AuthorityUnavailable("Artifact signed Original was not derived from an actual exact parent locator")
    # The caller has verified the real whole JSON EOF and signature. Admit its
    # producer locator for the existing positive COMMIT check that immediately follows.
    r.original_operations.add(producer)
    value=None
    if kind=="draft_root_capability":
        from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
        root=draft_from_wire_v1(raw,DraftRootCapabilityV1);value=root
        if root.registration_ref!=(r.selector.task if r.phase_variant else r.selector).root_registration_ref:
            raise AuthorityUnavailable("Artifact actual Root locator crossed task")
    elif kind=="artifact_task_scope":
        from ..runtime.ingress_artifact_task_scope_v1 import _decode,IngressArtifactTaskScopeOriginalV1
        scope=_decode(raw,IngressArtifactTaskScopeOriginalV1);value=scope
        if(scope.namespace!=r.work.namespace or scope.c02_operation_id!=(r.selector.task if r.phase_variant else r.selector).c02_operation_id
                or scope.source_ref not in r.qualified):
            raise AuthorityUnavailable("Artifact actual task scope changed positive task/Source")
        r.original_keys.add(("c1_task_intent",scope.c1_intent_ref))
        if scope.task_kind=="continue":
            task=r.selector.task if r.phase_variant else r.selector
            from ..runtime.d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2
            r.original_operations.add(artifact_task_plan_revision_operation_id_v2(task))
            r.original_keys.add(("artifact_task_amendment","artifact-task-amendment:"+canonical_digest((scope.namespace,task.root_registration_ref))[:48]))
            if r.phase_variant:
                from ..runtime.d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v2
                from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
                from dataclasses import replace
                first=replace(r.selector,phase_index=0,phase_kind=artifact_draft_phase_sequence_v2(r.selector.method_ref)[0],
                    prev_phase_original_ref=None,prev_phase_original_digest=None)
                r.original_operations.add(artifact_task_checkpoint_activation_operation_id_v2(first))
        if scope.objective_ref is not None:r.original_keys.add(("artifact_task_objective",scope.objective_ref))
        if scope.schema=="d11.ingress-artifact-task-scope.v3":
            r.original_keys.add(("artifact_task_continuation_authorization_v2",scope.continuation_authorization.original_ref))
        if scope.schema in{"d11.ingress-artifact-task-scope.v2","d11.ingress-artifact-task-scope.v3"}:
            r.original_keys.add(("artifact_standing_predecision_approval",scope.approval_original_ref))
    elif kind in{"artifact_phase_postcondition_policy","artifact_phase_postcondition_contract","artifact_phase_assessment",
            "artifact_standing_predecision_approval","artifact_candidate_preparation_parent"}:
        from ..runtime.artifact_phase_postconditions_v1 import decode_artifact_phase_postcondition_original_v1
        value=decode_artifact_phase_postcondition_original_v1(kind,raw)
        if kind=="artifact_phase_postcondition_contract":
            if value.selector!=r.selector:raise AuthorityUnavailable("Artifact exact postcondition contract crossed phase")
            r.original_keys.add(("artifact_phase_postcondition_policy",value.policy_ref))
            r.proof_original_refs.add(value.selected_preparation_ref)
        elif kind=="artifact_phase_postcondition_policy":
            r.original_keys.add(("artifact_task_text_extent",value.request.extent_original_ref))
            r.original_keys.add(("artifact_task_objective",value.objective_ref))
            r.original_operations.add(value.registration_operation_id)
        elif kind=="artifact_candidate_preparation_parent":
            r.original_keys.add(("artifact_standing_predecision_approval",value.approval_original_ref))
            r.proof_original_refs.add(value.dependency_contract_ref)
            r.original_operations.add(value.parent_prepare_operation_id)
        elif kind=="artifact_standing_predecision_approval"and value.schema.endswith(".v3"):
            r.proof_original_refs.add(value.preparation_dependency_contract_ref)
    elif kind=="artifact_task_text_extent":
        from ..runtime.artifact_task_text_extent_v1 import decode_artifact_task_text_extent_original_v1
        value=decode_artifact_task_text_extent_original_v1(raw)
        r.original_keys.add(("artifact_task_objective",value.objective_ref))
        r.original_operations.add(value.registration_operation_id)
    elif kind=="c4_phase_adopted":
        from ..runtime.d11_artifact_draft_content_v1 import decode_artifact_draft_phase_content_original_v2
        value=decode_artifact_draft_phase_content_original_v2(kind,raw)
        source=value.content.content.ref
        if source not in r.business_source_versions or source not in r.qualified:
            raise AuthorityUnavailable("Artifact old paid/result Original has no actual current prior-content business Source")
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
        ids=artifact_draft_model_ids_v2(value.selector)
        r.original_keys.update((("c4_phase_paid",value.paid_original_ref),("c4_phase_result",value.result_original_ref),
            ("c4_phase_prepared",ids["job"]),("c4_phase_frozen",ids["frozen"]),("activity_scope",value.activity_scope_ref)))
        r.original_operations.add(value.adoption_operation_id)
        r.job_ids.add(ids["job"])
    elif kind=="c4_phase_verified":
        from ..runtime.d11_artifact_draft_content_v1 import decode_artifact_draft_phase_content_original_v2
        value=decode_artifact_draft_phase_content_original_v2(kind,raw)
        r.original_keys.update((("c4_phase_adopted",value.content_adoption_ref),("artifact_task_text_extent",value.extent_original_ref)))
        r.proof_original_refs.add(value.readback_original_ref)
        if value.prev_verified_original_ref is not None:r.original_keys.add(("c4_phase_verified",value.prev_verified_original_ref))
        r.original_operations.add(value.producing_operation_id)
    if kind=="artifact_task_objective":
        from ..runtime.ingress_artifact_task_scope_v1 import _decode,ArtifactTaskObjectiveV1
        value=_decode(raw,ArtifactTaskObjectiveV1)
        if value.goal_ref in r.body_graph_tokens:r.graph_versions.add((value.goal_ref,1))
    if value is not None:_admit_actual_historical_heads_v3(r,value)
    # Other fixed C4/Activity/Objective originals remain subject to their
    # existing exact codecs and semantic reader; no arbitrary child is admitted.
    return True

def _domain_original_ref_v3(r,ref,expected=None):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(r.work.db)as meter:
        rows=r.work.db.execute("SELECT operation_id,original_digest FROM graph_domain_production_originals_v1 "
            "WHERE bot=? AND persona=? AND(operation_id=? OR domain||'-current:'||substr(original_digest,1,48)=?) LIMIT 2",
            (*r.work.namespace.as_tuple,ref,ref)).fetchall()
        meter.charge_read(sum(sum(len(str(v).encode("utf-8"))for v in row)for row in rows)+32)
    if len(rows)!=1:raise AuthorityUnavailable("Artifact exact business Original locator lacks one actual positive producer")
    operation,digest=rows[0]
    if expected is not None and digest!=expected.original_digest:
        raise AuthorityUnavailable("Artifact actual positive producer digest differs from selected proof")
    r.original_operations.add(operation)
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    actual=read_adopted_domain_operation_v1(r.work.db,r.work.namespace,operation)
    from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    value=ProductionOriginalRefV1(actual["domain"]+".current-"+actual["operation_kind"],ref,actual["original_digest"])
    if expected is not None and value.kind!=expected.kind:
        raise AuthorityUnavailable("Artifact positive Original actual domain/kind differs")
    return value

def artifact_model_frame_original_v3(frame,ref,*,kind=None,digest=None):
    from .artifact_model_graph_v3 import require_artifact_control_frame_v3
    binding=require_artifact_control_frame_v3(frame)
    if binding is None:return False,None
    r=binding[0];r.capability.require_v3()
    cached=r.frame_originals.get(ref)
    if cached is not None:
        if(kind is not None and cached.kind!=kind or digest is not None and cached.original_digest!=digest):
            raise AuthorityUnavailable("Artifact exact frame Original expected identity changed")
        return True,cached
    expected=r.proof_original_values.get(ref)
    life=tuple(k for k,q in r.original_keys if q==ref)
    if len(life)>1:raise AuthorityUnavailable("Artifact actual Original reference collides across kinds")
    if life:
        from ..runtime.d11_life_product_adapter_v1 import read_current_life_original_ref_v1
        value=read_current_life_original_ref_v1(r.work.db,namespace=r.work.namespace,original_ref=ref,issuer=r.installed.issuer)
        if value is None:
            from ..runtime.artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_original_ref_v1
            value=read_current_artifact_phase_postcondition_original_ref_v1(r.work.db,namespace=r.work.namespace,
                original_ref=ref,issuer=r.installed.issuer)
        if value is None:raise AuthorityUnavailable("Artifact exact signed business Original has no installed actual reader")
    elif ref in r.original_operations or expected is not None and ".current-"in expected.kind:
        value=_domain_original_ref_v3(r,ref,expected)
    elif expected is not None or ref in r.proof_original_domains:
        from ..runtime.domain_production_read_plans_v1 import _INPUT_TABLES
        from ..runtime.natural_producer_qualification_v1 import _producer_original_point_v3
        from ..runtime.domain_background_read_v3 import background_json_loads_v3,background_json_digest_v3,background_json_matches_v3,background_verify_signature_v3
        found=[]
        for table,sign_kind,domain,fixed_kind in _INPUT_TABLES:
            if domain!=(expected.kind.split(".",1)[0]if expected is not None else r.proof_original_domains[ref]):continue
            columns=(("kind","producing_operation_id","payload_json","payload_digest","signature")if fixed_kind=="kind"else
                ("producing_operation_id","payload_json","payload_digest","signature"))
            row=_producer_original_point_v3(r.work.db,table=table,columns=columns,
                key_columns=("bot","persona","original_ref"),key=(*r.work.namespace.as_tuple,ref),legacy_reader=None)
            if row is None:continue
            if fixed_kind!="kind":row=(fixed_kind,*row)
            raw=background_json_loads_v3(row[2])
            background_verify_signature_v3(r.installed.issuer._signer,sign_kind,row[2],row[4])
            if(not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]
                    or expected is not None and(row[3]!=expected.original_digest or domain+"."+row[0]!=expected.kind)):
                raise AuthorityUnavailable("Artifact selected proof Original changed actual schema/kind/signature/digest")
            r.original_operations.add(row[1])
            from ..runtime.domain_production_read_plans_v1 import _committed
            _committed(r.work.db,r.work.namespace,row[1])
            from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
            found.append(ProductionOriginalRefV1(domain+"."+row[0],ref,row[3]))
        if len(found)!=1:raise AuthorityUnavailable("Artifact selected exact proof Original is absent or ambiguous")
        value=found[0]
    else:raise AuthorityUnavailable("Artifact frame Original was not derived from actual signed business parent")
    if(kind is not None and value.kind!=kind or digest is not None and value.original_digest!=digest
            or expected is not None and(value.kind,value.original_digest)!=(expected.kind,expected.original_digest)):
        raise AuthorityUnavailable("Artifact actual frame Original differs from exact requested kind/digest")
    r.frame_originals[ref]=value
    return True,value

def _admit_actual_historical_heads_v3(r,value):
    from ..graph_types import GraphVersion
    from ..runtime_contracts import VersionedRef
    for name in ("goal_head","plan_head","source_head","self_mapping_head","task_source_head","rule_source_head"):
        head=getattr(value,name,None)
        if type(head)is GraphVersion:key,revision=head.key,head.revision
        elif type(head)is VersionedRef:key,revision=AtomKey.from_token(head.ref),head.revision
        else:continue
        if key.token not in r.body_graph_tokens:continue
        if key.type_name=="memory.source":
            actual=r.qualified.get(key.token)
            if actual is None or actual[0].revision!=revision:continue
        r.graph_versions.add((key.token,revision))

def register_artifact_model_joint_index_v3(db,index):
    r=_reader_v3(db)
    if r is None:return
    r.capability.require_v3()
    from ..runtime.joint_node_execution_v1 import JointExecutorIndexV1
    if type(index)is not JointExecutorIndexV1 or index.namespace!=r.work.namespace or index.original_ref not in r.proof_original_refs:
        raise AuthorityUnavailable("Artifact Joint index is not the exact signed current task index")
    from ..runtime.artifact_original_child_locators_v3 import artifact_original_child_locators_v3
    children=artifact_original_child_locators_v3(kind="joint_executor_index_v1",value=index)
    for domain,ref in children.production_originals:
        r.proof_original_refs.add(ref);r.proof_original_domains[ref]=domain

def register_artifact_model_positive_parent_v3(db,original):
    r=_reader_v3(db)
    if r is None:return
    r.capability.require_v3()
    operation=original["receipt"].operation_id
    if operation not in r.original_operations or original["receipt"].status!="committed":
        raise AuthorityUnavailable("Artifact business parent is not a real selected positive COMMIT")
    if(original["domain"],original["operation_kind"])==("d08","adopt_joint_plan_v1"):
        from ..domains.d08.production_operations_v1 import AdoptCurrentJointPlanRequestV1
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        command=decode_typed_production_value_v1(original["payload"]["request"],AdoptCurrentJointPlanRequestV1)
        for ref in command.party_consent_original_refs:
            r.proof_original_refs.add(ref);r.proof_original_domains[ref]="d08"

def register_artifact_model_joint_binding_v3(db,value,row):
    r=_reader_v3(db)
    if r is None:return
    r.capability.require_v3()
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    from ..runtime.joint_node_execution_v1 import JointNodeExecutionBindingV1,ArtifactJointExecutorV1,BINDING_KIND
    actual_kind=("joint_artifact_prospective_binding_v1"if type(value)is JointArtifactProspectiveBindingV1
        else BINDING_KIND if type(value)is JointNodeExecutionBindingV1 and type(value.executor)is ArtifactJointExecutorV1 else None)
    if(actual_kind is None or value.namespace!=r.work.namespace
            or value.original_ref not in r.proof_original_refs or value.digest!=row[3]
            or row[0]!=actual_kind):
        raise AuthorityUnavailable("Artifact actual Joint binding is not its signed exact selected index child")
    task=r.selector.task if r.phase_variant else r.selector
    if(type(value.executor)is not ArtifactJointExecutorV1 or(value.executor.c02_operation_id,value.executor.root_registration_ref)!=(
            task.c02_operation_id,task.root_registration_ref)
            or value.executor.phase_selector is not None and value.executor.phase_selector!=r.selector):
        raise AuthorityUnavailable("Artifact actual Joint executor changed original task/root/phase")
    from ..runtime.artifact_original_child_locators_v3 import artifact_original_child_locators_v3
    children=artifact_original_child_locators_v3(kind=actual_kind,value=value)
    r.original_keys.update(children.life_originals)
    r.original_operations.add(row[1])
