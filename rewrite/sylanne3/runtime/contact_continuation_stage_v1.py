"""Actual five-write Contact continuation; original whole members remain READ dependencies."""
from dataclasses import replace
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import (DomainBundle,NamespaceId,DependencySet,DomainProposal,VersionedRef,canonical_digest)
from ..graph_types import AtomKey,Owner
from .contact_final_action_v1 import contact_final_action_ids_v1,contact_action_parameters_digest_v1
from .contact_continuation_v1 import read_contact_segment_original_v1,_prefix


def read_plan_contact_continuation_v1(db,*,namespace,activity_id,request):
    from .contact_final_stage_v3 import _raw_plan,contact_final_runtime_ids_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    from ..domains.d08.contact_plan_v2 import contact_plan_keys_v2
    from ..domains.d08.contact_plan_v3 import contact_plan_keys_v3
    component=require_background_contact_source_component_v3(db,namespace,request.contact_id,'contact_final')
    plan=_raw_plan(db,namespace,request.contact_id)
    issuer=component.graph._GraphCoordinator__d11_issuer
    first=read_contact_segment_original_v1(db,namespace=namespace,contact_id=request.contact_id,segment_index=0,issuer=issuer)
    if first is None or not 0<request.segment_index<first.segment_count or plan.activity_id!=activity_id:
        raise AuthorityUnavailable('Contact continuation has no exact actual first-segment lineage')
    ids=contact_final_action_ids_v1(request.contact_id,request.segment_index)
    owner=Owner('activity',*namespace.as_tuple,activity_id)
    keys={*contact_plan_keys_v2(plan),*contact_plan_keys_v3(plan)[1:],*(AtomKey.from_token(ref)for ref in (
        first.same_goal_ref,first.same_claim_ref,first.parent_grant_ref,first.batch_ref)),
        AtomKey(owner,'d08.action_intent.v1',ids['action']),AtomKey(owner,'d08.action_schema.v1',ids['schema']),
        AtomKey(owner,'d08.action_cancellation.v1',ids['action']),*contact_final_runtime_ids_v3(namespace,request.contact_id,activity_id,request.segment_index)}
    keys.update(version.key for version in plan.qualified_read_versions)
    # Prepare every actual earlier immutable admission/accounting prefix in READ.
    prefix=_prefix(db,first=first,index=request.segment_index,issuer=issuer)
    for prior in prefix:
        original=read_contact_segment_original_v1(db,namespace=namespace,contact_id=request.contact_id,segment_index=prior['segment_index'],issuer=issuer)
        ids0=contact_final_action_ids_v1(request.contact_id,prior['segment_index'])
        keys.update((AtomKey(owner,'d08.action_intent.v1',ids0['action']),AtomKey(owner,'d08.action_schema.v1',ids0['schema']),
            AtomKey(owner,'d08.action_cancellation.v1',ids0['action']),AtomKey.from_token(original.job_ref),AtomKey.from_token(original.outbox_ref)))
    base=production_read_plan_v1(CONTACT_FINAL_QUERY_TYPES_V3,keys,component.source_selection.roots,(first.old_cause_ref,))
    if first.first_prospective is not None:
        from .contact_prospective_v1 import read_contact_prospective_original_v1,contact_prospective_barrier_key_v1
        from .joint_node_execution_v1 import read_joint_executor_index_v1,augment_joint_binding_read_plan_v1
        from .domain_background_read_v3 import background_json_loads_v3
        birth=read_contact_prospective_original_v1(db,issuer,namespace,request.contact_id)
        if birth is None or birth.digest!=first.first_prospective['birth_digest']:
            raise AuthorityUnavailable('Continuation read plan lost its actual first Contact prospective birth')
        born=background_json_loads_v3(birth.payload_json)
        keys.add(contact_prospective_barrier_key_v1(namespace,activity_id,request.contact_id))
        binding=read_joint_executor_index_v1(db,namespace=namespace,selector_kind='contact',
            selector_key=(born['terms']['causal_operation_id'],born['terms']['dedupe_key']),issuer=issuer)
        if binding is None:raise AuthorityUnavailable('Continuation requires actual matching current original Contact Joint binding')
        base=production_read_plan_v1(CONTACT_FINAL_QUERY_TYPES_V3,keys,component.source_selection.roots,
            (first.old_cause_ref,born['joint_preparation']['ref'],first.first_prospective['birth_ref']))
        return augment_joint_binding_read_plan_v1(db,namespace=namespace,plan=base,binding=binding)
    return base


def _require_current_continuation_v1(material,db):
    from .contact_final_stage_v3 import require_installed_contact_material_v3
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1
    from ..runtime_contracts import canonical_serialize
    m=require_installed_contact_material_v3(material);observed=m.continuation_observation
    if type(observed)is not ContactContinuationObservationV1 or observed.selector.segment_index!=m.request.segment_index:
        raise AuthorityUnavailable('Contact continuation has no independent actual typed Core observation')
    first=read_contact_segment_original_v1(db,namespace=m.scope.namespace,contact_id=m.content.contact_id,segment_index=0,
        issuer=m.runtime.graph._GraphCoordinator__d11_issuer)
    prefix=_prefix(db,first=first,index=m.request.segment_index,issuer=m.runtime.graph._GraphCoordinator__d11_issuer)
    import json
    inputs=json.loads(observed.inputs_json)
    if (canonical_serialize(prefix)!=canonical_serialize(inputs['prefix'])
            or len(observed.prefix)!=m.request.segment_index
            or any(not p.accounting_finished or p.budget_status!='settled' or p.observation_outcome!='accepted'for p in observed.prefix)
            or observed.selector.operation_id!=m.frame.envelope.identity.operation_id
            or (observed.same_claim_ref,observed.same_goal_ref,observed.first_admission_ref,observed.whole_manifest_digest)!=(
                first.same_claim_ref,first.same_goal_ref,first.admission_ref,first.whole_manifest_digest)
            or m.frame.now_utc>=first.deadline_utc or m.frame.envelope.deadline_utc>first.deadline_utc):
        raise AuthorityUnavailable('Contact continuation current prefix/claim/Goal/deadline differs from actual originals')
    return first,prefix


def stage_contact_continuation_in_transaction_v1(db,*,frame,request,installed_readers):
    from .contact_final_stage_v3 import (_ContactFinalMaterialV3,_publish_material,_contact_expression_frame_v3,
        _contact_projection_read_v3,_installed_contact_context_v3,_with_actual_absent_keys,_provisional,_qualification,
        ContactFinalStageV3,contact_final_runtime_ids_v3)
    from .domain_production_registry_v1 import installed_operation_v1
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2,require_contact_inventory_current_v2
    from .contact_final_action_v3 import prepare_contact_action_stage_v3
    from .contact_qualification_v3 import read_contact_check_versions_locked_v3
    from .contact_route_binding_v1 import read_current_contact_route_binding_v1
    from .contact_background_invocation_v1 import _CAPTURES,require_contact_background_call_v1
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1
    from .jobs import create_job
    from .budget import reserve_budget
    from ..graph_coordinator import budget_operation_digest
    from .d11_types import RuntimeOutboxValue,job_graph_write,outbox_graph_write,reconcile_runtime_write
    from .contact_dispatch_candidate_v3 import contact_dispatch_segment_payload_ref_v3
    from ..domains.d08.execution import _decode_goal
    from ..domains.d01.production_operations_v1 import stage_result_v1
    import json,time
    graph=installed_readers.role_clock_reader.graph;runtime=graph._GraphCoordinator__domain_production_runtime_v1
    scope=installed_readers.contact_policy_scope;issuer=graph._GraphCoordinator__d11_issuer
    content=read_contact_reviewed_content_original_v2(db,namespace=scope.namespace,contact_id=request.contact_id,issuer=issuer,resource_issuer=issuer._d02)
    first=read_contact_segment_original_v1(db,namespace=scope.namespace,contact_id=request.contact_id,segment_index=0,issuer=issuer)
    if first is None or not 0<request.segment_index<len(content.segments):raise AuthorityUnavailable('Actual Contact continuation first lineage is absent')
    item=content.segments[request.segment_index]
    if (item.operation_id,item.segment.effect_id,content.activity_id)!=(frame.envelope.identity.operation_id,frame.envelope.identity.effect_id,frame.envelope.identity.activity_id):
        raise AuthorityUnavailable('Contact continuation selected another original segment identity')
    plan,_,original,_=read_adopted_contact_plan_v2(db,namespace=scope.namespace,contact_id=request.contact_id,issuer=issuer)
    require_contact_inventory_current_v2(db,scope.namespace,original)
    call=runtime._active_contact_background_call_v1;require_contact_background_call_v1(call)
    capture=_CAPTURES.get(id(call))
    if capture is None or capture[1]is not scope or type(capture[3])is not ContactContinuationObservationV1:
        raise AuthorityUnavailable('Contact continuation requires actual independent Core WRITE capture')
    observed=capture[3]
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    policy=assembly.admin_bundle.private_reply_dispatch
    if policy is None or assembly.admin_bundle.contact_effect_accounting is None:
        raise AuthorityUnavailable('Contact continuation actual message and financial price policies are absent')
    grant=issuer.current_budget_grant(db,first.root_lease_ref)
    if grant!=assembly.installation_policy.root_grant or canonical_digest(grant)!=first.root_grant_digest:
        raise AuthorityUnavailable('Contact continuation cannot replace the original installed root grant')
    frame=_contact_expression_frame_v3(frame,content)
    deadline=min(first.deadline_utc,frame.envelope.deadline_utc,observed.deadline_utc,grant.valid_until_utc,content.valid_until)
    from .first_ingress_v2 import trusted_upper
    upper=trusted_upper(runtime._active_contact_final_clock_v1)
    local=min(frame.envelope.monotonic_deadline,time.monotonic()+deadline-upper)
    if upper>=deadline or time.monotonic()>=local:raise AuthorityUnavailable('Original Contact continuation deadline expired')
    job_key,outbox_key=contact_final_runtime_ids_v3(scope.namespace,content.contact_id,content.activity_id,request.segment_index)
    # New quote and reserve are first born in this same five-member CAS. READ has
    # never demanded an unborn quote. Saved operations take the immutable recovery path.
    quote=issuer.issue_private_reply_dispatch_quote_v2(db,policy=policy,namespace=scope.namespace,identity=frame.envelope.identity,
        parent_grant=grant,deadline_utc=deadline,graph_job_ref=job_key.token,outbox_refs=(outbox_key.token,),now_utc=frame.now_utc)
    envelope=replace(frame.envelope,deadline_utc=deadline,monotonic_deadline=local,
        version_guard=replace(frame.envelope.version_guard,resource_lease_versions=(VersionedRef(quote.quote_id,quote.version),)))
    frame=replace(frame,envelope=envelope)
    job=replace(issuer.job_for(envelope,db,now_utc=frame.now_utc),phase='waiting',
        wake_condition={'kind':'contact_host_takeover','operation_id':envelope.identity.operation_id})
    create_job(db,job,'contact-job-create:'+canonical_digest((scope.namespace,job.job_id))[:48],canonical_digest(job))
    reserve_budget(db,grant.lease_id,envelope.identity.operation_id,budget_operation_digest(envelope,grant.lease_id,dict(quote.ceiling)),dict(quote.ceiling))
    outbox=RuntimeOutboxValue(*scope.namespace.as_tuple,content.activity_id,envelope.identity.operation_id,envelope.identity.effect_id,
        outbox_key.name,job.job_id,job_key.token,contact_dispatch_segment_payload_ref_v3(first.batch_ref,request.segment_index),
        'contact-send:'+canonical_digest((scope.namespace,content.contact_id,request.segment_index)),'pending',scope.generation)
    material=_publish_material(_ContactFinalMaterialV3(runtime,installed_operation_v1('prepare_contact_dispatch_v3'),request,
        frame,scope,runtime._active_contact_final_owner_v1,runtime._active_contact_final_guard_v1,content,
        installed_readers.current_contact_policy,runtime._active_contact_final_effect_v1,runtime._active_contact_final_effect_snapshot_v1,
        runtime._active_contact_final_clock_v1,quote,grant,job,outbox,runtime._active_contact_final_stage_call_v1,
        continuation_observation=observed))
    with _contact_projection_read_v3(material,db,phase='pre_e')as read:
        _require_current_continuation_v1(material,db)
        goal=_decode_goal(read.head(db,first.same_goal_ref,required=True).value)
        route=read_current_contact_route_binding_v1(db,read,account_ref=plan.route_account_ref.ref,target_entity_ref=plan.target_entity_ref,audience=content.audience_id)
        current=read_contact_check_versions_locked_v3(db,read.frame.snapshot,route.query,scope,current_read=read,content=content,
            segment_index=request.segment_index,route=route,context=_installed_contact_context_v3(material,db,read),
            d02_issuer=issuer._d02,d11_issuer=issuer,quote=quote,grant=grant,current_policy=material.current_policy,now_utc=frame.now_utc)
        action=prepare_contact_action_stage_v3(envelope=read.frame.envelope,content=content,index=request.segment_index,current_checks=current,
            route=route,quote=quote,grant=grant,now_utc=frame.now_utc,parent_goal=goal,parent_grant_ref=first.parent_grant_ref,parent_grant_digest=first.parent_grant_digest)
    runtime_writes=(job_graph_write(job),outbox_graph_write(outbox,job_key))
    for write in runtime_writes:reconcile_runtime_write(db,write)
    writes=tuple(('d08',w)for w in action.proposal.typed_writes)+tuple(('d11',w)for w in runtime_writes)
    if len(writes)!=5:raise AuthorityUnavailable('Contact continuation must register only new Action/schema/cancellation/job/outbox')
    material=_with_actual_absent_keys(material,db,tuple(w.key for _,w in writes))
    action=replace(action,proposal=replace(action.proposal,envelope=material.frame.envelope))
    registered=graph._GraphCoordinator__providers['d11']
    dependencies={key for write in runtime_writes for key in write.dependencies}
    runtime_proposal=DomainProposal('d11',registered[1],registered[2],material.frame.envelope,runtime_writes,
        DependencySet(current_invalidation=tuple(v for v in material.frame.envelope.version_guard.read_versions if v.key in dependencies)),(),())
    proposals=(action.proposal,runtime_proposal)
    bundle=DomainBundle(material.frame.envelope,proposals,(),(),(),(),(outbox.idempotency_key,),(job_key.token,),(outbox_key.token,))
    material=_publish_material(replace(material,provisional_writes=writes,final_bundle=bundle))
    with _provisional(material,db,writes)as receipt:
        with _contact_projection_read_v3(material,db,phase='provisional_e_plus_1',receipt=receipt,bundle=bundle)as read:
            qualification,_=_qualification(material,db,read,action)
    stage=stage_result_v1(material.frame,'d08','prepare_contact_dispatch_v3',request,provenance={
        'reviewed_content_digest':content.digest,'qualification_digest':qualification.digest,'job_ref':job_key.token,'outbox_ref':outbox_key.token},jobs=(job,))
    result=ContactFinalStageV3(material,action,qualification,bundle,stage)
    runtime._active_contact_final_stage_v1=result
    return result


def require_contact_continuation_commit_v1(witness,graph,db,bundle,v2_write):
    from .contact_final_stage_v3 import require_installed_contact_material_v3,_contact_projection_read_v3,_installed_contact_context_v3
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    m=require_installed_contact_material_v3(witness.stage.material)
    _require_current_continuation_v1(m,db)
    if not 0<m.request.segment_index<len(m.content.segments) or read_contact_reviewed_content_original_v2(db,
            namespace=m.scope.namespace,contact_id=m.content.contact_id,issuer=graph._GraphCoordinator__d11_issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer)!=m.content:
        raise AuthorityUnavailable('Contact continuation current paid whole content changed')
    evidence=validate_contact_continuation_candidate_v1(tuple((p.domain,w)for p in bundle.proposals for w in p.typed_writes),
        namespace=m.scope.namespace,identity=bundle.envelope.identity,read_versions=bundle.envelope.version_guard.read_versions,
        source_refs=bundle.envelope.source_qualification.source_refs,access_epoch=bundle.envelope.version_guard.access_epoch,
        delete_epoch=bundle.envelope.version_guard.delete_epoch,query_epoch=m.scope.graph_epoch.revision,
        db=db,material=m)
    if (graph._GraphCoordinator__d02_issuer.qualified_quote(bundle.envelope,db,now_utc=m.frame.now_utc)!=m.quote
            or graph._GraphCoordinator__d11_issuer.current_budget_grant(db,m.grant.lease_id)!=m.grant):
        raise AuthorityUnavailable('Continuation actual signed quote/current parent changed')
    version=str(m.quote.version)
    prior=db.execute('SELECT version FROM graph_guard_versions WHERE bot=? AND persona=? AND kind=? AND ref=?',
        (*m.scope.namespace.as_tuple,'resource_lease',m.quote.quote_id)).fetchone()
    if prior is None:
        db.execute('INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)',
            (*m.scope.namespace.as_tuple,'resource_lease',m.quote.quote_id,version))
    elif prior!=(version,):raise AuthorityUnavailable('Continuation original quote guard version changed')
    return evidence


def validate_contact_continuation_candidate_v1(writes,*,namespace,identity,read_versions,source_refs,access_epoch,delete_epoch,query_epoch,db,material):
    from .contact_dispatch_candidate_v3 import ContactDispatchCandidateEvidenceV3
    from ..domains.d08.execution import GoalExecutionProvider,ActionSchemaRecord,ActionSchema
    from ..domains.d01.production_operations_v1 import plain_v1
    m=material;index=m.request.segment_index;first,_=_require_current_continuation_v1(m,db)
    expected={'d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1','runtime.job','runtime.outbox'}
    members={w.key.type_name:(domain,w)for domain,w in writes}
    if len(writes)!=5 or set(members)!=expected:raise AuthorityUnavailable('Continuation candidate cannot rewrite whole Goal/batch/grant/claim')
    specs={s.name:s.validator for s in GoalExecutionProvider().register_types()}
    aw=members['d08.action_intent.v1'][1];sw=members['d08.action_schema.v1'][1]
    action=specs['d08.action_intent.v1'](aw.value);schema=specs['d08.action_schema.v1'](sw.value)
    ids=contact_final_action_ids_v1(m.content.contact_id,index);item=m.content.segments[index]
    reads={v.key:v.revision for v in read_versions}
    if (action.action_id!=ids['action']or action.goal_ref!=ids['goal']or action.schema_id!=ids['schema']
            or action.identity!=identity or action.effect_scope!=(item.segment.effect_id,)
            or tuple(action.source_refs)!=tuple(source_refs)or action.parameters_digest!=contact_action_parameters_digest_v1(m.content,index,
                parent_grant_ref=first.parent_grant_ref,parent_grant_digest=first.parent_grant_digest)
            or ActionSchemaRecord.bind(action,ActionSchema(schema.schema_id,schema.action_kind,schema.proactive,schema.required_checks))!=schema
            or len(action.required_checks)!=6 or any(reads.get(w.key)!=0 for _,w in writes)
            or any(NamespaceId.from_key(w.key)!=namespace or w.key.owner.subject!=identity.activity_id for _,w in writes)):
        raise AuthorityUnavailable('Continuation exact new Action/schema/source/cancellation identity differs')
    if {w.key.token for _,w in writes}&{first.same_goal_ref,first.same_claim_ref,first.batch_ref,first.parent_grant_ref}:
        raise AuthorityUnavailable('Continuation candidate rewrote an original whole member')
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    batch,_,_=require_current_contact_batch_v3(db,namespace=namespace,batch_ref=first.batch_ref,operation_id=first.operation_id,
        generation=m.scope.generation,graph_incarnation=m.runtime.graph._v2_graph_stamp(namespace)[0].requirements.graph_incarnation)
    if batch.content!=m.content or batch.parent_grant_digest!=first.parent_grant_digest:
        raise AuthorityUnavailable('Continuation original whole batch or communication grant changed')
    return ContactDispatchCandidateEvidenceV3(identity.operation_id,identity.effect_id,m.content.contact_id,aw.key.token,sw.key.token,
        first.parent_grant_ref,first.batch_ref,canonical_digest(action),canonical_digest(schema),first.parent_grant_digest,batch.digest,
        m.content.digest,item.segment.segment_id,index,item.payload_digest,tuple(source_refs),
        tuple(v for v in read_versions if v.key not in {w.key for _,w in writes}),access_epoch,delete_epoch,query_epoch)


def capture_contact_continuation_call_v1(call,scope,owner):
    from .contact_background_invocation_v1 import require_contact_background_call_v1,_CAPTURES
    from .contact_owner_invocation_v3 import _owner_storage_wire_v3
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1
    from ..host.contact_continuation_port_v1 import install_contact_continuation_port_v1
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    require_contact_background_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise AuthorityUnavailable('Contact continuation capture must finish outside Graph SQL lock')
    with store._lock:
        store._db.execute('BEGIN')
        try:
            raw=read_adopted_contact_plan_v2(store._db,namespace=scope.namespace,contact_id=call.request.contact_id,
                issuer=graph._GraphCoordinator__d11_issuer)[2]
        finally:store._db.rollback()
    selector=ContactContinuationSelectorV1(scope.namespace,call.request.contact_id,call.request.segment_index,
        call.operation_id,call.request_digest,AtomKey.from_token(raw['policy_ref']).name,call.issued.event.dedupe_key)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    port=install_contact_continuation_port_v1(graph._GraphCoordinator__content_fence_v2,assembly.admin_bundle)
    observed,authority=port.capture_contact_continuation_v1(scope.permit,selector)
    if (observed.owner_actor,observed.owner_head_digest,observed.owner_revision,observed.owner_authority_digest)!=(
            owner.actor,owner.authorization_head,owner.authorization_revision,canonical_digest(authority)):
        raise AuthorityUnavailable('Contact continuation actual current Owner differs from its Core capture')
    _CAPTURES[id(call)]=(call,scope,_owner_storage_wire_v3(owner),observed)
    return observed


def require_contact_continuation_runtime_candidate_v1(db,*,bundle,candidate,qualification):
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    from .contact_final_stage_v3 import require_installed_contact_material_v3,_QUALIFIED
    component=require_background_contact_source_component_v3(db,bundle.envelope.authority.namespace,candidate.contact_id,'contact_final')
    runtime=component.graph._GraphCoordinator__domain_production_runtime_v1
    stage=runtime._active_contact_final_stage_v1
    m=require_installed_contact_material_v3(stage.material)
    if (m.final_bundle is not bundle or m.request.segment_index!=candidate.segment_index
            or stage.qualification!=qualification or _QUALIFIED.get(id(m))!=qualification):
        raise AuthorityUnavailable('Continuation D11 admission lost its actual five-member final issuance')
    first,_=_require_current_continuation_v1(m,db)
    if (candidate.grant_ref,candidate.batch_ref,candidate.reviewed_content_digest)!=(
            first.parent_grant_ref,first.batch_ref,first.reviewed_content_digest):
        raise AuthorityUnavailable('Continuation D11 cannot replace original whole grant/batch')
    return first


def is_actual_contact_prefix_action_v1(db,current_read,intent,other):
    from .contact_final_projection_v3 import _CurrentContactProjectionReadV3,require_contact_projection_read_v3
    from .contact_continuation_p2_v1 import ContactContinuationP2CurrentReadV1,require_current_continuation_p2_prefix_v1
    if type(current_read)is _CurrentContactProjectionReadV3:
        m=current_read._witness.material
        if m.request.segment_index==0:return False
        require_contact_projection_read_v3(current_read,db,phases=('provisional_e_plus_1','post_cas_e_plus_1'))
        first,_=_require_current_continuation_v1(m,db)
        prefix=m.continuation_observation.prefix;content=m.content
    elif type(current_read)is ContactContinuationP2CurrentReadV1:
        prefix=require_current_continuation_p2_prefix_v1(current_read,db);content=current_read.batch.content
        first=read_contact_segment_original_v1(db,namespace=current_read.scope.namespace,contact_id=content.contact_id,segment_index=0,
            issuer=current_read.graph._GraphCoordinator__d11_issuer)
    else:return False
    for part in prefix:
        ids=contact_final_action_ids_v1(content.contact_id,part.segment_index)
        if other.action_id!=ids['action']:continue
        if (other.identity.operation_id,other.identity.effect_id,other.identity.activity_id)!=(part.operation_id,part.effect_id,content.activity_id):
            raise AuthorityUnavailable('Contact prefix action has another actual accepted/settled original identity')
        if (other.goal_ref!=intent.goal_ref or other.target_ref!=intent.target_ref or other.schema_id!=ids['schema']
                or other.effect_scope!=(part.effect_id,)or other.parameters_digest!=contact_action_parameters_digest_v1(content,part.segment_index,
                    parent_grant_ref=first.parent_grant_ref,parent_grant_digest=first.parent_grant_digest)):
            raise AuthorityUnavailable('Contact predecessor action changed original whole grant/Goal/target semantics')
        return True
    return False


def require_current_contact_continuation_joint_gate_v1(db,*,material,read):
    from .contact_final_projection_v3 import require_contact_projection_read_v3
    require_contact_projection_read_v3(read,db,phases=('pre_e','provisional_e_plus_1','post_cas_e_plus_1'))
    first,_=_require_current_continuation_v1(material,db)
    if first.first_prospective is None:return None
    from .contact_prospective_v1 import read_contact_prospective_original_v1,contact_prospective_barrier_key_v1
    from .joint_node_execution_v1 import read_joint_executor_index_v1,require_current_joint_binding_gate_v1
    from .domain_background_read_v3 import background_json_loads_v3
    issuer=material.runtime.graph._GraphCoordinator__d11_issuer
    birth=read_contact_prospective_original_v1(db,issuer,material.scope.namespace,material.content.contact_id)
    if birth is None or birth.digest!=first.first_prospective['birth_digest']:
        raise AuthorityUnavailable('Continuation current Joint gate lost the actual original prospective birth')
    raw=background_json_loads_v3(birth.payload_json)
    barrier=read.head(db,contact_prospective_barrier_key_v1(material.scope.namespace,material.content.activity_id,material.content.contact_id),required=True)
    if (barrier.value['precommit_digest']!=canonical_digest({k:v for k,v in raw.items()if k!='receipt'})
            or barrier.value['birth_operation_id']!=raw['birth_operation_id'] or barrier.value['joint_preparation']!=raw['joint_preparation']
            or (raw['final_operation_id'],raw['effect_id'])!=(first.operation_id,first.effect_id)
            or material.current_policy.original.digest!=raw['observation']['policy_original_digest']):
        raise AuthorityUnavailable('Continuation current Joint gate changed original first binding/Owner policy/birth barrier')
    binding=read_joint_executor_index_v1(db,namespace=material.scope.namespace,selector_kind='contact',
        selector_key=(raw['terms']['causal_operation_id'],raw['terms']['dedupe_key']),issuer=issuer)
    if binding is None:raise AuthorityUnavailable('Continuation is waiting for its exact original matching current Joint binding')
    return require_current_joint_binding_gate_v1(db,frame=read.frame,binding=binding,issuer=issuer)
