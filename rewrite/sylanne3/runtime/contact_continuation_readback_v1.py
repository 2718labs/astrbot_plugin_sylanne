"""Independent five-member Contact COMMIT identity and original-permit recovery."""
import json
from dataclasses import asdict,replace
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..authority_service.contract import AuthorityUnavailable
from .contact_continuation_v1 import read_contact_segment_original_v1,_prefix

def verify_contact_continuation_committed_v1(db,*,namespace,result,issuer,graph,original,proof,qualified,admission,request):
    from .contact_final_stage_v3 import _verify_contact_committed_runtime_v3,contact_final_runtime_ids_v3
    from .dispatch_action_job_binding import load_action_job_binding
    from ..runtime_storage_v3 import read_graph_row_v3
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_from_wire_v1
    receipt=original['receipt']
    segment=read_contact_segment_original_v1(db,namespace=namespace,contact_id=request.footprint.contact_id,segment_index=request.segment_index,issuer=issuer)
    if (segment is None or not 0<request.segment_index<request.segment_count<=3 or request.proactive_contact is not True
            or request.footprint.quota_occupancies or len(request.footprint.object_gate_keys)!=1
            or len(receipt.write_versions)!=5 or len(proof['write_commitments'])!=5
            or (segment.operation_id,segment.effect_id,segment.admission_ref,segment.admission_receipt_digest,segment.dispatch_request_digest)!=(
                result['operation_id'],request.effect_id,admission.admission.admission_ref,admission.receipt_digest,canonical_digest(request))
            or segment.producing_receipt_digest!=canonical_digest(receipt)
            or segment.whole_manifest_digest!=request.segment_manifest_digest
            or request.operation_id!=result['operation_id'] or request.activation_generation!=qualified.activation_generation
            or request.dispatch_generation!=request.activation_generation
            or admission.receipt_digest!=proof['admission_receipt_digest']or canonical_digest(request)!=proof['request_digest']
            or canonical_digest(request.footprint)!=proof['footprint_digest']
            or admission.graph_epoch!=qualified.graph_epoch or qualified.qualification.checks!=admission.admission.check_receipts
            or load_action_job_binding(db,namespace,proof['admission_ref'])is None):
        raise AuthorityUnavailable('Continuation COMMIT lacks its actual immutable five-write admission and qualification')
    observed=contact_continuation_from_wire_v1(segment.core_observation,ContactContinuationObservationV1)
    first=read_contact_segment_original_v1(db,namespace=namespace,contact_id=segment.contact_id,segment_index=0,issuer=issuer)
    prefix=_prefix(db,first=first,index=segment.segment_index,issuer=issuer)
    captured=json.loads(observed.inputs_json)
    if (canonical_serialize(prefix)!=canonical_serialize(captured['prefix'])or observed.selector.operation_id!=request.operation_id
            or observed.selector.request_digest!=segment.request_digest or observed.selector.segment_index!=request.segment_index
            or observed.same_claim_ref!=segment.same_claim_ref or observed.same_goal_ref!=segment.same_goal_ref
            or observed.first_admission_ref!=first.admission_ref or observed.whole_manifest_digest!=segment.whole_manifest_digest
            or any(p.accounting_finished is not True or p.observation_outcome!='accepted' or p.budget_status!='settled'for p in observed.prefix)):
        raise AuthorityUnavailable('Continuation COMMIT original independent Core prefix differs from actual settled originals')
    metadata,fence,parent,lease,job,quote,identity,authority=_verify_contact_committed_runtime_v3(db,namespace=namespace,
        result=result,original=original,proof=proof,request=request,admission=admission,issuer=issuer,graph=graph)
    if (segment.root_lease_ref!=parent.lease_id or canonical_digest(parent)!=segment.root_grant_digest
            or canonical_digest(quote)!=segment.quote_digest or segment.reservation_digest!=admission.admission.budget_reservation_digest
            or segment.job_ref!=proof['job_ref']or segment.outbox_ref!=proof['outbox_ref']):
        raise AuthorityUnavailable('Continuation COMMIT cannot replace its actual same-CAS quote/reserve/root')
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    content=read_contact_reviewed_content_original_v2(db,namespace=namespace,contact_id=segment.contact_id,issuer=issuer,resource_issuer=issuer._d02)
    item=content.segments[segment.segment_index]
    if (content.digest!=segment.reviewed_content_digest or content.digest!=proof['reviewed_content_digest']
            or (item.operation_id,item.segment.effect_id,item.payload_digest)!=(request.operation_id,request.effect_id,request.payload_digest)
            or qualified.audience!=content.audience_id or qualified.current_effect.effect_id!=request.effect_id
            or qualified.qualification.route_semantic_digest!=content.route_semantic_digest
            or qualified.expression_roots!=tuple(sorted({ref for part in content.segments for claim in part.claims for ref in claim.source_refs}))):
        raise AuthorityUnavailable('Continuation COMMIT changed its signed whole paid content and selected segment')
    from ..domains.d08.execution import GoalExecutionProvider,RequiredCheckRegistry,ActionSchema
    from .contact_final_action_v1 import contact_final_action_ids_v1,contact_action_parameters_digest_v1
    validators={spec.name:spec.validator for spec in GoalExecutionProvider().register_types()}
    expected_types={'d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1','runtime.job','runtime.outbox'}
    members={}
    for row in proof['write_commitments']:
        key=AtomKey.from_token(row['ref'])
        if key.type_name not in expected_types or key.type_name in members or row['revision']!=1:
            raise AuthorityUnavailable('Continuation COMMIT must contain only exact new Action/schema/cancellation/job/outbox')
        head=read_graph_row_v3(db,columns=('revision','value','valid'),where='token=? AND bot=? AND persona=?',parameters=(key.token,*namespace.as_tuple))
        history=read_graph_row_v3(db,columns=('event_id','value','valid'),where='token=? AND revision=?',parameters=(key.token,1),history=True)
        if (head is None or head[0]!=1 or head[2]!=1 or history!=(request.operation_id,head[1],1)
                or canonical_digest(json.loads(head[1]))!=row['digest']):
            raise AuthorityUnavailable('Continuation COMMIT current five members differ from exact producing history')
        members[key.type_name]=(key,json.loads(head[1]))
    if set(members)!=expected_types or {(v.key.token,v.revision)for v in receipt.write_versions}!={(row['ref'],row['revision'])for row in proof['write_commitments']}:
        raise AuthorityUnavailable('Continuation COMMIT actual receipt is outside its five-member current inventory')
    action=validators['d08.action_intent.v1'](members['d08.action_intent.v1'][1])
    schema=validators['d08.action_schema.v1'](members['d08.action_schema.v1'][1])
    cancellation=validators['d08.action_cancellation.v1'](members['d08.action_cancellation.v1'][1])
    ids=contact_final_action_ids_v1(segment.contact_id,segment.segment_index)
    if (action.identity!=identity or action.action_id!=ids['action']or action.schema_id!=ids['schema']
            or action.effect_scope!=(request.effect_id,)or action.source_refs!=segment.source_refs
            or action.parameters_digest!=contact_action_parameters_digest_v1(content,segment.segment_index,
                parent_grant_ref=segment.parent_grant_ref,parent_grant_digest=segment.parent_grant_digest)
            or cancellation.state!='active' or cancellation.action_id!=action.action_id
            or cancellation.action_digest!=canonical_digest(action)or cancellation.action_revision!=1):
        raise AuthorityUnavailable('Continuation COMMIT Action/schema/cancellation differ from exact selected original')
    registry=RequiredCheckRegistry();registry.register(ActionSchema(schema.schema_id,schema.action_kind,True,schema.required_checks))
    decision=registry.qualify(action,qualified.qualification.checks,now=qualified.now_utc)
    if decision.status!='qualified' or len(qualified.qualification.checks)!=6:
        raise AuthorityUnavailable('Continuation COMMIT lost its independently fresh six current checks')
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    batch,batch_proof,eligibility=require_current_contact_batch_v3(db,namespace=namespace,batch_ref=segment.batch_ref,
        operation_id=first.operation_id,generation=request.activation_generation,graph_incarnation=metadata.requirements.graph_incarnation)
    if batch.content!=content or batch.parent_grant_digest!=segment.parent_grant_digest:
        raise AuthorityUnavailable('Continuation COMMIT cannot rewrite its original whole batch/proof/eligibility')
    from .contact_final_issuer_v3 import _value
    _,parent_raw=_value(db,namespace,segment.parent_grant_ref,'d08.communication_intent_grant.v1')
    communication=validators['d08.communication_intent_grant.v1'](parent_raw)
    _,goal_raw=_value(db,namespace,segment.same_goal_ref,'d08.goal.v1')
    if (canonical_digest(communication)!=segment.parent_grant_digest or canonical_digest(goal_raw)!=segment.goal_digest
            or communication.segment_manifest_digest!=segment.whole_manifest_digest
            or request.segment_authorization_ref!=communication.segment_authorization_ref(item.segment.segment_id)
            or request.contact_policy_check_ref!=communication.contact_policy_check_ref
            or request.segment_count!=len(communication.segment_grants)):
        raise AuthorityUnavailable('Continuation COMMIT changed original active Goal or whole communication grant')
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2
    _,claim_raw=_value(db,namespace,segment.same_claim_ref,'d10.contact_claim.v2');claim=decode_contact_claim_v2(claim_raw)
    if (canonical_digest(replace(claim,observations=(),status='claimed'))!=segment.original_claim_digest
            or claim.status in {'released','pending_confirmation'}or dict(claim.observations)!={part.segment.effect_id:'accepted'for part in content.segments[:segment.segment_index]}):
        raise AuthorityUnavailable('Continuation COMMIT original whole claim lacks exact accepted predecessor observations')
    bucket=canonical_digest((namespace,claim.subject_ref,claim.channel,claim.category))
    expected_job,expected_outbox=contact_final_runtime_ids_v3(namespace,content.contact_id,content.activity_id,segment.segment_index)
    from .d11_types import RuntimeOutboxValue,job_graph_write
    outbox=RuntimeOutboxValue(**members['runtime.outbox'][1])
    if (proof['job_ref']!=expected_job.token or proof['outbox_ref']!=expected_outbox.token
            or request.footprint.object_gate_keys!=('contact-object:'+bucket,)
            or request.footprint.communication_action!=communication.communication_action_id
            or members['runtime.job'][1]!=job_graph_write(job).value or job.phase!='waiting'
            or outbox.job_ref!=proof['job_ref']or outbox.job_id!=job.job_id or outbox.phase!='pending'
            or (outbox.operation_id,outbox.effect_id,outbox.payload_ref,outbox.idempotency_key)!=(
                request.operation_id,request.effect_id,request.payload_ref,request.footprint.external_idempotency_ref)
            or db.execute('SELECT operation_id,phase FROM graph_bundle_outbox WHERE bot=? AND persona=? AND outbox_ref=?',
                (*namespace.as_tuple,proof['outbox_ref'])).fetchone()!=(request.operation_id,'pending')
            or db.execute('SELECT job_id,operation_id FROM graph_outbox_jobs WHERE bot=? AND persona=? AND outbox_ref=?',
                (*namespace.as_tuple,proof['outbox_ref'])).fetchone()!=(job.job_id,request.operation_id)):
        raise AuthorityUnavailable('Continuation COMMIT same object gate/current job/outbox linkage differs')
    from .contact_dispatch_candidate_v3 import ContactDispatchCandidateEvidenceV3
    written={v.key for v in receipt.write_versions}
    evidence=ContactDispatchCandidateEvidenceV3(request.operation_id,request.effect_id,content.contact_id,
        members['d08.action_intent.v1'][0].token,members['d08.action_schema.v1'][0].token,segment.parent_grant_ref,segment.batch_ref,
        canonical_digest(action),canonical_digest(schema),canonical_digest(communication),batch.digest,content.digest,
        item.segment.segment_id,segment.segment_index,item.payload_digest,action.source_refs,
        tuple(v for v in receipt.read_versions if v.key not in written),admission.admission.access_epoch,admission.admission.delete_epoch,fence[3])
    if evidence.digest!=admission.admission.candidate_digest:
        raise AuthorityUnavailable('Continuation COMMIT exact five-member candidate commitment differs')
    return qualified


def read_contact_continuation_ack_original_v1(db,call):
    from .contact_final_ack_v1 import require_contact_final_call_v1
    from .contact_continuation_v1 import TABLE,COLUMNS,SIGN_KIND,contact_segment_original_from_wire_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    require_contact_final_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    if db is not store._db or not db.in_transaction or not store._lock._is_owned() or call.request.segment_index==0:
        raise AuthorityUnavailable('Continuation ACK metadata requires its actual active call and locked readonly snapshot')
    ns=call.authority.namespace
    with runtime_storage_quantum_v3(db)as meter:
        row=_runtime_bounded_fixed_row_v3(db,meter,TABLE,COLUMNS,'bot=? AND persona=? AND contact_id=? AND segment_index=?',
            (*ns.as_tuple,call.request.contact_id,call.request.segment_index))
    if row is None:raise AuthorityUnavailable('Continuation ACK has no immutable same-CAS segment original')
    value=contact_segment_original_from_wire_v1(json.loads(row[6]))
    if (row[:6]!=(*ns.as_tuple,call.request.contact_id,call.request.segment_index,call.operation_id,value.effect_id)
            or value.namespace!=ns or value.request_digest!=call.request_digest or value.digest!=row[7]):
        raise AuthorityUnavailable('Continuation ACK original differs from exact current call')
    graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,value.contact_id,value.segment_index,value.digest)),row[8])
    return value

def require_contact_continuation_deadline_v1(call,scope,result):
    from .contact_final_ack_v1 import _readonly,require_contact_final_call_v1
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_from_wire_v1
    from ..host.contact_continuation_port_v1 import install_contact_continuation_port_v1
    require_contact_final_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    evidence=_readonly(call,result)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    with store._lock:
        store._db.execute('BEGIN')
        try:segment=read_contact_continuation_ack_original_v1(store._db,call)
        finally:store._db.rollback()
    stored=contact_continuation_from_wire_v1(segment.core_observation,ContactContinuationObservationV1)
    if now>=min(segment.deadline_utc,evidence.deadline_utc,*(check.valid_until for check in evidence.qualification.checks)):
        raise AuthorityUnavailable('Continuation ACK cannot extend its original segment/current qualification deadline')
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    observed,current=install_contact_continuation_port_v1(graph._GraphCoordinator__content_fence_v2,assembly.admin_bundle).read_existing_contact_continuation_v1(scope.permit,stored.selector)
    if observed!=stored:
        raise AuthorityUnavailable('Continuation ACK actual authenticated stored Core observation differs')
    return segment

def record_contact_continuation_background_after_commit_v1(db,call,scope,result,owner,observation):
    from .contact_background_invocation_v1 import require_contact_background_call_v1,_CAPTURES
    from .contact_owner_invocation_v3 import _owner_storage_wire_v3
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_to_wire_v1
    from .contact_final_stage_v3 import verify_contact_final_committed_v3
    require_contact_background_call_v1(call)
    if (type(observation)is not ContactContinuationObservationV1 or not db.in_transaction
            or db is not call.runtime.graph._GraphCoordinator__store._db
            or not call.runtime.graph._GraphCoordinator__store._lock._is_owned()
            or _CAPTURES.get(id(call))!=(call,scope,_owner_storage_wire_v3(owner),observation)):
        raise AuthorityUnavailable('Continuation background requires its actual same-CAS typed beforeWRITE capture')
    segment=read_contact_continuation_ack_original_v1(db,call)
    if segment.core_observation!=contact_continuation_to_wire_v1(observation):
        raise AuthorityUnavailable('Continuation same-CAS original did not retain its actual typed Core capture')
    verify_contact_final_committed_v3(db,namespace=scope.namespace,result=result,issuer=call.runtime.graph._GraphCoordinator__d11_issuer,graph=call.runtime.graph)
    return segment


def recover_contact_continuation_background_saved_v1(call, scope, result, state):
    from .contact_final_ack_v1 import _readonly, require_contact_finish_ack_v1
    from .contact_background_invocation_v1 import require_contact_background_call_v1,require_contact_background_deadline_v1
    require_contact_background_call_v1(call)
    from .domain_followup_consumer_v1 import _observe_owner
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    from .contact_owner_invocation_v3 import owner_binding_from_wire_v3
    graph = call.runtime.graph
    port = graph._GraphCoordinator__content_fence_v2
    store = graph._GraphCoordinator__store
    def snapshot():
        evidence = _readonly(call,result)
        with store._lock:
            store._db.execute('BEGIN')
            try:
                original=read_contact_continuation_ack_original_v1(store._db,call)
                raw={**original.background_invocation,'observation':original.core_observation,'deadline_utc':original.deadline_utc}
                from ..authority_service.v2_contract import to_wire
                expected = asdict(scope)
                expected['permit'] = to_wire(scope.permit)
                if raw['scope'] != expected or raw['result_digest'] != canonical_digest(result) or raw['request'] != asdict(call.request):
                    raise ValueError('Contact background saved invocation original scope/result differs')
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                if canonical_digest(read_adopted_domain_operation_v1(store._db,scope.namespace,
                        call.operation_id)['payload']['provenance']) != raw['provenance_digest']:
                    raise ValueError('Contact background saved eleven-member provenance changed')
                return evidence, raw
            finally:
                store._db.rollback()
    evidence, raw = snapshot()
    if state == 'active':
        guard, owner = _observe_owner(graph,call.authority,scope)
        policy = graph._GraphCoordinator__c04_authority_port_v3.contact_policy(scope.permit,'read_current',
            policy_id=evidence.owner_policy.policy.policy_id)
        if policy != evidence.owner_policy or _owner_binding_wire_v3(owner) != _owner_binding_wire_v3(owner_binding_from_wire_v3(raw['owner'])):
            raise ValueError('Contact background saved current Owner/standing policy differs')
        require_contact_background_deadline_v1(call,scope,result)
        if snapshot() != (evidence,raw):
            raise ValueError('Contact background saved originals changed across current observation')
        finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3','operation_id':call.operation_id,
            'request_digest':call.request_digest,'permit_token':scope.permit.token})
        port.finish_fence(scope,request_id='finish:'+scope.operation_id,request_digest=finish)
    else:
        require_contact_continuation_deadline_v1(call,scope,result)
    require_contact_finish_ack_v1(call,scope)
    if snapshot()!=(evidence,raw):
        raise AuthorityUnavailable('Continuation saved originals changed across its actual current Source/Owner observation')
    from .first_ingress_v2 import trusted_upper
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=raw['deadline_utc']:
        raise AuthorityUnavailable('Continuation finished recovery cannot extend original absolute TTL')
    return result


def recover_contact_continuation_background_dispatch_v1(graph,bootstrap,bundle,*,operation_id):
    from .contact_continuation_v1 import TABLE,COLUMNS,SIGN_KIND,contact_segment_original_from_wire_v1
    from .contact_background_invocation_v1 import _BackgroundContactRecoveryV1,_RECOVERY
    from .contact_owner_invocation_v3 import owner_binding_from_wire_v3
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .contact_followup_v1 import ContactFollowupCommandV1
    from ..runtime_contracts import AuthorityContext
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    graph._admin(bootstrap);assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable('Continuation cold recovery requires its actual installed assembly')
    runtime=graph._GraphCoordinator__domain_production_runtime_v1;runtime._current()
    ns=bundle.installation_policy.namespace;store=graph._GraphCoordinator__store
    with store._lock:
        store._db.execute('BEGIN')
        try:
            with runtime_storage_quantum_v3(store._db)as meter:
                row=_runtime_bounded_fixed_row_v3(store._db,meter,TABLE,COLUMNS,'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id))
            if row is None:return False,None
            segment=contact_segment_original_from_wire_v1(json.loads(row[6]))
            if segment.segment_index==0:return False,None
            if (row[:6]!=(*ns.as_tuple,segment.contact_id,segment.segment_index,operation_id,segment.effect_id)
                    or segment.namespace!=ns or row[7]!=segment.digest or segment.background_invocation is None):
                raise AuthorityUnavailable('Continuation cold recovery has another actual signed metadata locator')
            graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,segment.contact_id,segment.segment_index,segment.digest)),row[8])
            raw=segment.background_invocation;owner=owner_binding_from_wire_v3(raw['owner'])
            from ..contracts import canonical_json
            attempt=store._db.execute('SELECT request_digest,attempt_id,permit_json,receipt_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
                (*ns.as_tuple,operation_id)).fetchone()
            if (attempt is None or attempt[:2]!=(segment.request_digest,raw['scope']['operation_id'])
                    or attempt[2]!=canonical_json(raw['scope']['permit']) or attempt[3]is None
                    or canonical_digest(json.loads(attempt[3]))!=raw['result_digest']):
                raise AuthorityUnavailable('Continuation cold recovery actual durable request/result differs')
        finally:store._db.rollback()
    authority=AuthorityContext(owner.actor,'d12','installed-contact-continuation-recovery:'+operation_id,ns,(owner.scope,),
        'expression',(raw['command']['audience_ref'],),'owner-grant-v1',raw['scope']['generation'])
    # This signed Owner is only the identity of an already committed recovery
    # locator. The saved consumer obtains current Owner/Source under the exact
    # old WRITE or one owned READ before it can return the original result.
    request=PrepareCurrentContactDispatchRequestV3(**raw['request'])
    command=ContactFollowupCommandV1('d08','prepare_contact_dispatch_v3',request,
        raw['command']['activity_id'],raw['command']['audience_ref'],operation_id=operation_id)
    issued=_BackgroundContactRecoveryV1(graph,authority,owner,operation_id,command,segment.digest);_RECOVERY[id(issued)]=issued
    try:
        value=runtime.run_current(authority,None,operation_kind='prepare_contact_dispatch_v3',request=request,operation_id=operation_id,
            activity_id=command.activity_id,audience_ref=command.audience_ref,parent_budget_lease_ref=raw['command']['parent_budget_lease_ref'],
            _background_contact_recovery=issued)
        return True,value
    finally:_RECOVERY.pop(id(issued),None)


def require_contact_continuation_saved_recovery_attempt_v1(graph,issued,authority,*,operation_id,request_digest,saved):
    from .contact_background_invocation_v1 import _BackgroundContactRecoveryV1,require_background_contact_recovery_v1
    from .contact_continuation_v1 import TABLE,COLUMNS,SIGN_KIND,contact_segment_original_from_wire_v1
    from .contact_owner_invocation_v3 import _owner_storage_wire_v3
    from ..contracts import canonical_json
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    if type(issued)is not _BackgroundContactRecoveryV1 or issued.command.request.segment_index==0:
        return
    owner=require_background_contact_recovery_v1(issued,graph,authority,operation_id)
    if saved is None or saved[5]is None or saved[6]is None:
        raise AuthorityUnavailable('Continuation recovery only permits an actual committed attempt with its original WRITE and receipt')
    store=graph._GraphCoordinator__store;ns=authority.namespace
    with store._lock:
        store._db.execute('BEGIN')
        try:
            with runtime_storage_quantum_v3(store._db)as meter:
                row=_runtime_bounded_fixed_row_v3(store._db,meter,TABLE,COLUMNS,'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id))
            if row is None:raise AuthorityUnavailable('Continuation recovery lost its exact signed segment locator')
            segment=contact_segment_original_from_wire_v1(json.loads(row[6]))
            raw=segment.background_invocation
            if (row[:6]!=(*ns.as_tuple,segment.contact_id,segment.segment_index,operation_id,segment.effect_id)
                    or row[7]!=segment.digest or segment.digest!=issued.original_digest or segment.namespace!=ns
                    or segment.request_digest!=request_digest or segment.segment_index!=issued.command.request.segment_index or raw is None):
                raise AuthorityUnavailable('Continuation recovery cannot consume another original segment/attempt')
            graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,segment.contact_id,segment.segment_index,segment.digest)),row[8])
            scope=raw['scope']
            if (saved[:2]!=(request_digest,scope['operation_id']) or saved[2]!=canonical_json(scope['pinned_anchor'])
                    or saved[3:5]!=(scope['graph_revision'],scope['graph_epoch']['revision'])
                    or saved[5]!=canonical_json(scope['permit']) or canonical_digest(json.loads(saved[6]))!=raw['result_digest']
                    or raw['request']!=asdict(issued.command.request) or raw['owner']!=_owner_storage_wire_v3(owner)
                    or scope['namespace']!=asdict(ns) or scope['operation']!='write'):
                raise AuthorityUnavailable('Continuation recovery is only its exact already committed request/permit/receipt and Owner locator')
        finally:store._db.rollback()
