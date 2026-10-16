"""First-only eleven-member Contact P2 metadata Source closure."""
from dataclasses import asdict
from weakref import WeakKeyDictionary
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphWrite
from .contact_continuation_v1 import TABLE,COLUMNS,_point,read_contact_segment_original_v1
_FIRST=WeakKeyDictionary()

def begin_contact_first_p2_locator_source_read_v1(service,*,credential,subject,permit,context,binding,claimed_receipt,location):
    from ..authority_service.v2_contract import ExecutionBindingV2,FencePermitV2,DispatchHandoffContextV1,MutationReceiptV2
    from ..authority_service.current_authority_graph_read_v3 import (require_authority_graph_read_controller_v3,
        AuthorityGraphReadWorkV3,_ISSUER,_track_authority_capability_v3)
    if (type(binding)is not ExecutionBindingV2 or type(permit)is not FencePermitV2 or permit.operation!='read'
            or type(context)is not DispatchHandoffContextV1 or type(claimed_receipt)is not MutationReceiptV2
            or claimed_receipt.pending.binding!=binding or claimed_receipt.pending.phase!='claimed'
            or binding.origin.segment_index!=0 or not 1<=binding.origin.segment_count<=3
            or binding.origin.proactive_contact is not True or len(binding.footprint.quota_occupancies)!=1
            or len(binding.footprint.object_gate_keys)!=1):
        raise AuthorityUnavailable('First Contact P2 requires its exact typed first binding and separate actual READ')
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
    require_exact_reverse_handoff_identity(binding.namespace,context,binding,claimed_receipt)
    controller=require_authority_graph_read_controller_v3(service)
    if controller.kind!='contact' or controller.service is not service or location is None:
        raise AuthorityUnavailable('First Contact P2 locator has another installed Source controller')
    from datetime import datetime
    deadline=datetime.fromisoformat(binding.utc_deadline.replace('Z','+00:00')).timestamp()
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,
        namespace=controller.location.namespace_id,request=binding,deadline_utc=deadline)
    work.first_p2_binding=binding;work.first_p2_context=context;work.first_p2_claimed=claimed_receipt
    work.first_p2_original=None;work.contact_location=location;work.phase='validate'
    _FIRST[work]=(service,binding,context,claimed_receipt,permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_FIRST,work)
    return work

def require_contact_first_p2_locator_attachment_v1(work,request):
    origin=_FIRST.get(work)
    if origin is None:return False
    if origin!=(work.service,work.first_p2_binding,work.first_p2_context,work.first_p2_claimed,work.permit,work.scope,work.operation,work.contact_location):
        raise AuthorityUnavailable('First Contact locator changed its original actual READ')
    expected=(TABLE,COLUMNS,('bot','persona','contact_id','segment_index'),
        (*work.namespace.as_tuple,origin[1].footprint.contact_id,0))
    if request!=expected:raise AuthorityUnavailable('First Contact locator cannot open Source/body or another attachment')
    return True

def read_contact_first_p2_locator_v1(db,*,work,binding,issuer):
    origin=_FIRST.get(work)
    if origin is None or origin[1]is not binding or work.db is not db:
        raise AuthorityUnavailable('First Contact locator lost its exact registered actual Work')
    original=read_contact_segment_original_v1(db,namespace=work.namespace,contact_id=binding.footprint.contact_id,segment_index=0,issuer=issuer)
    if (original is None or original.first_prospective is None or original.operation_id!=binding.operation_id
            or original.effect_id!=binding.origin.effect_id or original.segment_count!=binding.origin.segment_count
            or original.whole_manifest_digest!=binding.origin.segment_manifest_digest.removeprefix('sha256:')
            or original.admission_ref!=binding.origin.admission_ref):
        raise AuthorityUnavailable('First Contact signed locator is outside its actual final admission and whole manifest')
    work.first_p2_original=original
    return original

def promote_contact_first_p2_metadata_source_v1(work,*,binding,selector,policy,location):
    from ..authority_service.contact_prospective_contract_v1 import (ContactProspectiveSelectorV1,ContactProspectiveObservationV1,contact_prospective_from_wire_v1)
    from ..authority_service.contact_background_graph_v3 import (ContactBackgroundSelectorV3,ContactPlanLocatorEOFV3,_BACKGROUND_WORKS)
    from ..authority_service.current_authority_graph_read_v3 import (_AuthorityCatalogueReadV3,_DEADLINES,_track_authority_capability_v3)
    from .contact_continuation_v1 import _PROJECTION_WORKS
    origin=_FIRST.get(work);original=work.first_p2_original
    if origin is None or origin[1]is not binding or original is None or type(selector)is not ContactProspectiveSelectorV1:
        raise AuthorityUnavailable('First Contact rights promotion lost its actual signed first metadata EOF')
    observed=contact_prospective_from_wire_v1(original.first_prospective['observation'],ContactProspectiveObservationV1)
    if (observed.selector!=selector or selector.namespace!=original.namespace or selector.contact_id!=original.contact_id
            or policy.namespace!=selector.namespace or policy.policy.policy_id!=selector.policy_id
            or policy.installation_id!=work.service._installation_id or location is not work.contact_location):
        raise AuthorityUnavailable('First Contact typed birth/current policy/location differs before Source rights')
    selected=ContactBackgroundSelectorV3(original.namespace,original.contact_id,original.operation_id,original.request_digest,
        selector.policy_id,original.old_causal_dedupe_key)
    deadline=min(work.deadline_utc,original.deadline_utc,observed.deadline_utc,policy.policy.window_end)
    if work.service._clock()>=deadline:raise AuthorityUnavailable('First Contact metadata READ cannot extend original deadline')
    work.deadline_utc=work.operation.deadline_utc=float(deadline);work.deadline_original=original
    _DEADLINES[work]=(work.operation,work.deadline_utc,original)
    work.contact_policy,work.contact_selector,work.contact_issuer=policy,selected,work.service._issuer
    work.contact_locator=ContactPlanLocatorEOFV3(work);work.catalogue_reader=_AuthorityCatalogueReadV3(work)
    work.now_utc=work.service._clock();work.parent_original_id=original.operation_id
    work.phase='contact_locator';work.complete=False;work.prepared=None
    _FIRST.pop(work,None)
    _BACKGROUND_WORKS[work]=(work.service,work.controller,work.service._location,work.service._issuer,policy,selected,
        work.operation,work.scope,work.permit,work.credential,work.subject)
    _track_authority_capability_v3(work,_BACKGROUND_WORKS,work)
    _PROJECTION_WORKS[work]=(work.service,selector,binding,work.permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_PROJECTION_WORKS,work)
    return work


def read_contact_first_p2_selector_v1(db,*,work,binding,claim_receipt,expected_capsule,issuer):
    from ..authority_service.v2_contract import ExecutionBindingV2,MutationReceiptV2,DispatchGraphClaimReceiptV1,canonical_digest as authority_digest
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
    from .domain_background_read_v3 import background_json_loads_v3
    from .domain_production_originals_v1 import _receipt
    from .dispatch_admission import load_request
    from .contact_prospective_v1 import (TABLE as BIRTH,COLUMNS as BIRTH_COLUMNS,SIGN_KIND as BIRTH_SIGN,
        SUCCESSOR_TABLE,SUCCESSOR_COLUMNS,SUCCESSOR_SIGN,ContactProspectiveOriginalV1,ContactProspectiveSuccessorV1)
    context=work.first_p2_context;claimed=work.first_p2_claimed
    if (type(binding)is not ExecutionBindingV2 or type(claimed)is not MutationReceiptV2 or work.db is not db
            or work.first_p2_binding is not binding or claimed.pending.binding!=binding
            or binding.origin.segment_index!=0 or not 1<=binding.origin.segment_count<=3
            or (claim_receipt is not None and type(claim_receipt)is not DispatchGraphClaimReceiptV1)):
        raise AuthorityUnavailable('First Contact P2 metadata read lost its actual binding/context/claim tuple')
    require_exact_reverse_handoff_identity(binding.namespace,context,binding,claimed)
    original=read_contact_segment_original_v1(db,namespace=work.namespace,contact_id=binding.footprint.contact_id,segment_index=0,issuer=issuer)
    if original is None or original!=work.first_p2_original or original.first_prospective is None:
        raise AuthorityUnavailable('First Contact P2 actual immutable locator changed')
    p=original.first_prospective
    birth_row=_point(db,table=BIRTH,columns=BIRTH_COLUMNS,key_columns=('bot','persona','contact_id'),
        key=(*work.namespace.as_tuple,original.contact_id))
    successor_row=_point(db,table=SUCCESSOR_TABLE,columns=SUCCESSOR_COLUMNS,key_columns=('bot','persona','final_operation_id'),
        key=(*work.namespace.as_tuple,original.operation_id))
    if birth_row is None or successor_row is None:
        raise AuthorityUnavailable('First Contact P2 lacks its actual signed birth/final successor original')
    birth=ContactProspectiveOriginalV1(birth_row[4]);born=background_json_loads_v3(birth.payload_json)
    successor=ContactProspectiveSuccessorV1(successor_row[5]);after=background_json_loads_v3(successor.payload_json)
    if (birth_row[7]!=p['birth_ref'] or birth.digest!=p['birth_digest'] or birth_row[5]!=birth.digest
            or born['observation']!=p['observation'] or born['final_operation_id']!=original.operation_id
            or successor_row[2]!=p['successor_ref'] or successor.digest!=p['successor_digest']
            or successor_row[3:5]!=(p['birth_ref'],p['birth_digest'])or successor_row[6]!=successor.digest
            or successor_row[8]!=p['final_receipt_digest'] or after['birth_ref']!=p['birth_ref'] or after['birth_digest']!=birth.digest):
        raise AuthorityUnavailable('First Contact P2 birth/successor/final commitment tuple differs')
    issuer._signer.verify(BIRTH_SIGN,canonical_serialize((work.namespace,original.contact_id,birth_row[3],birth.digest)),birth_row[6])
    issuer._signer.verify(SUCCESSOR_SIGN,canonical_serialize((work.namespace,original.operation_id,successor.digest,successor_row[8])),successor_row[7])
    issued=load_request(db,work.namespace,original.admission_ref)
    if issued is None:raise AuthorityUnavailable('First Contact P2 actual first admission is absent')
    admission,request=issued
    if (canonical_digest(request)!=original.dispatch_request_digest or admission.receipt_digest!=original.admission_receipt_digest
            or request.segment_index!=0 or request.segment_count!=original.segment_count or request.effect_id!=original.effect_id
            or request.footprint!=binding.footprint or len(request.footprint.object_gate_keys)!=1
            or len(request.footprint.quota_occupancies)!=1 or request.footprint.quota_occupancies[0].occupied!=1
            or request.segment_manifest_digest!=original.whole_manifest_digest
            or request.payload_digest!=original.payload_digest or request.footprint.contact_id!=original.contact_id):
        raise AuthorityUnavailable('First Contact P2 whole manifest/original footprint or quota occupancy differs')
    committed=_point(db,table='graph_bundle_operations',columns=('digest','activity_id','effect_id','commit_seq','receipt_json'),
        key_columns=('bot','persona','operation_id'),key=(*work.namespace.as_tuple,original.operation_id))
    receipt=None if committed is None else _receipt(background_json_loads_v3(committed[4]))
    if (receipt is None or canonical_digest(receipt)!=original.producing_receipt_digest or len(receipt.write_versions)!=11
            or (receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)!=committed[:4]):
        raise AuthorityUnavailable('First Contact P2 lost its actual eleven-member final Graph COMMIT')
    writes=[];members={}
    from .d11_types import RuntimeOutboxValue
    names={'d08.action_intent.v1':'action','d08.action_schema.v1':'action_schema','d08.action_cancellation.v1':'cancellation',
        'd08.goal.v1':'goal','d08.communication_intent_grant.v1':'communication_grant','d10.contact_claim.v2':'claim',
        'runtime.job':'job','runtime.outbox':'outbox','d09.contact_verified_batch.v3':'batch',
        'd09.contact_batch_provenance.v3':'batch_proof','d09.contact_batch_eligibility.v3':'batch_eligibility'}
    for version in receipt.write_versions:
        key=version.key
        row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),key=(key.token,*work.namespace.as_tuple))
        history=_point(db,table='graph_history',columns=('event_id','value','valid'),key_columns=('token','revision'),key=(key.token,1))
        if (key.type_name not in names or row is None or row[0]!=1 or row[2]!=1 or version.revision!=1
                or history is None or history!=(original.operation_id,row[1],1)):
            raise AuthorityUnavailable('First Contact P2 actual eleven producing members drifted')
        value=background_json_loads_v3(row[1]);name=names[key.type_name]
        if name in members:raise AuthorityUnavailable('First Contact P2 repeated a producing member type')
        members[name]={'ref':key.token,'revision':1,'value':value,'valid':True}
        deps=tuple(AtomKey.from_token(ref)for(ref,)in db.execute('SELECT dependency_token FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',(key.token,)))
        writes.append(('d11'if key.type_name.startswith('runtime.')else key.type_name[:3],GraphWrite(key,value,deps)))
    if set(members)!=set(names.values()):raise AuthorityUnavailable('First Contact P2 eleven-member coverage is incomplete')
    from .contact_dispatch_candidate_v3 import validate_contact_dispatch_candidate_writes_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import OperationIdentity
    identity=decode_typed_production_value_v1(members['action']['value']['identity'],OperationIdentity)
    evidence=validate_contact_dispatch_candidate_writes_v3(tuple(writes),namespace=work.namespace,identity=identity,
        read_versions=receipt.read_versions,source_refs=tuple(members['action']['value']['source_refs']),
        access_epoch=admission.admission.access_epoch,delete_epoch=admission.admission.delete_epoch,query_epoch=admission.admission.query_epoch-1)
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    batch,proof,eligibility=require_current_contact_batch_v3(db,namespace=work.namespace,batch_ref=original.batch_ref,
        operation_id=original.operation_id,generation=request.activation_generation,graph_incarnation=binding.graph_incarnation)
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2,contact_window_id_v2
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    parent=next(s.validator for s in GoalExecutionProvider().register_types()if s.name=='d08.communication_intent_grant.v1')(members['communication_grant']['value'])
    claim=decode_contact_claim_v2(members['claim']['value']);policy=work.contact_policy.policy
    plan,expression,raw,plan_digest=read_adopted_contact_plan_v2(db,namespace=work.namespace,contact_id=original.contact_id,issuer=issuer)
    effects=tuple(part.segment.effect_id for part in batch.content.segments)
    if (len(batch.content.segments)!=request.segment_count or len(parent.segment_grants)!=request.segment_count
            or claim.segment_effects!=effects or claim.status!='claimed' or claim.observations
            or claim.communication_action_id!=parent.communication_action_id or claim.subject_ref!=plan.target_entity_ref
            or (claim.channel,claim.category,claim.window_id,claim.policy_version)!=(policy.channel,policy.category,contact_window_id_v2(policy),policy.version)
            or (claim.approval_ref,claim.approval_digest)!=(work.contact_policy.original_ref,work.contact_policy.digest)
            or (parent.segment_manifest_digest,canonical_digest(parent))!=(original.whole_manifest_digest,original.parent_grant_digest)
            or request.segment_authorization_ref!=parent.segment_authorization_ref(evidence.segment_id)
            or evidence.digest!=admission.admission.candidate_digest or parent.qualification_receipt_digest!=canonical_digest(admission.admission.check_receipts)
            or batch.content.digest!=original.reviewed_content_digest or plan_digest!=original.plan_digest
            or members['goal']['ref']!=original.same_goal_ref or canonical_digest(members['goal']['value'])!=original.goal_digest
            or members['claim']['ref']!=original.same_claim_ref or canonical_digest(claim)!=original.original_claim_digest
            or members['cancellation']['value']['state']!='active' or members['job']['value']['phase']!='waiting'
            or members['outbox']['value']['phase']!='pending'):
        raise AuthorityUnavailable('First Contact P2 current whole grant/claim/window/Goal/checks or original new members differ')
    from ..runtime_journal import QuotaOccupancy
    bucket=canonical_digest((work.namespace,claim.subject_ref,claim.channel,claim.category))
    if (request.footprint.object_gate_keys!=('contact-object:'+bucket,)
            or request.footprint.quota_occupancies!=(QuotaOccupancy('contact-quota:'+bucket,claim.window_id,1),)
            or request.footprint.communication_action!=parent.communication_action_id):
        raise AuthorityUnavailable('First Contact P2 object gate and one whole-claim quota differ')
    from .dispatch_graph_claim import dispatch_claim_key
    dc=dispatch_claim_key(work.namespace,original.effect_id)
    row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),key=(dc.token,*work.namespace.as_tuple))
    claim_member={'ref':dc.token,'revision':0,'value':None,'valid':False}if row is None else {'ref':dc.token,'revision':row[0],'value':background_json_loads_v3(row[1]),'valid':bool(row[2])}
    if expected_capsule is None:
        if claim_receipt is not None or row is not None:raise AuthorityUnavailable('First Contact P2 pre-CAS already has a Graph dispatch claim')
    else:
        expected={'handoff_id':context.handoff_id,'operation_id':original.operation_id,'effect_id':original.effect_id,
            'binding_digest':authority_digest(binding),'claimed_receipt_digest':authority_digest(claimed),
            'context_digest':authority_digest(context),'p2_permit_digest':authority_digest(context.permit),
            'p2_fence_epoch':context.permit.fence_epoch,'p2_revision':context.permit.revision,
            'p2_execution_seq':context.permit.pinned_anchor.execution_seq,'p2_execution_digest':context.permit.pinned_anchor.execution_digest,
            'owner_witness_digest':expected_capsule.owner_witness_digest}
        if (type(claim_receipt)is not DispatchGraphClaimReceiptV1 or row is None or row[0]!=1 or row[2]!=1
                or claim_receipt.context_digest!=authority_digest(context)or claim_receipt.graph_claim_ref!='dispatch-claim:'+original.effect_id
                or claim_receipt.graph_claim_digest!='sha256:'+canonical_digest(claim_member['value'])
                or claim_receipt.graph_namespace!=binding.graph_namespace or claim_receipt.graph_incarnation!=binding.graph_incarnation
                or any(claim_member['value'][k]!=v for k,v in expected.items())):
            raise AuthorityUnavailable('First Contact P2 post-CAS differs from its actual Core claim/context')
    members['dispatch_claim']=claim_member
    from .contact_continuation_v1 import _financial
    origin=_financial(db,namespace=work.namespace,kind='origin',ref=original.operation_id,issuer=issuer)
    quote=issuer._d02.original_signed_quote(db,original.quote_id,original.quote_version)
    reservation=_point(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(original.root_lease_ref,original.operation_id))
    if (canonical_digest(quote)!=original.quote_digest or reservation is None or reservation[2]!='reserved'
            or reservation[0]!=original.reservation_digest or background_json_loads_v3(reservation[1])!=dict(original.reservation_ceiling)):
        raise AuthorityUnavailable('First Contact P2 actual original quote/reserve changed')
    return {'segment_original':asdict(original),'observation_wire':p['observation'],'request':request,'admission_receipt':admission,
        'inputs':json.loads(canonical_serialize(original.core_observation['inputs'])),'p2_members':members,
        'birth_ref':p['birth_ref'],'birth_digest':p['birth_digest'],'successor_ref':p['successor_ref'],'successor_digest':p['successor_digest'],
        'final_receipt_digest':p['final_receipt_digest'],'policy_original_ref':work.contact_policy.original_ref,
        'policy_original_digest':work.contact_policy.digest,'plan_ref':original.plan_ref,'batch_ref':original.batch_ref,
        'deadline_utc':min(original.deadline_utc,*(check.valid_until for check in proof.qualification.checks)),
        'proof_valid_until_utc':min(check.valid_until for check in proof.qualification.checks),
        'first_prospective':p,
        'quote':asdict(quote),'reservation':{'digest':reservation[0],'ceiling':dict(original.reservation_ceiling),'state':'reserved'},
        'root_grant_id':original.root_grant_id,'root_grant_version':original.root_grant_version,
        'root_grant_digest':original.root_grant_digest,'root_lease_ref':original.root_lease_ref,
        'same_object_gate':request.footprint.object_gate_keys[0],'communication_action':request.footprint.communication_action,
        'quota_occupancies':request.footprint.quota_occupancies}


def validate_contact_first_whole_birth_v1(db,*,namespace,operation_id,receipt,admission,request,qualification):
    from ..runtime_storage_v3 import read_graph_row_v3
    from .contact_dispatch_candidate_v3 import validate_contact_dispatch_candidate_writes_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import OperationIdentity
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2,contact_window_id_v2
    from ..domains.d09.contact_batch_v3 import validate_contact_verified_batch_v3
    if request.segment_index!=0 or not 1<=request.segment_count<=3 or len(receipt.write_versions)!=11:
        raise AuthorityUnavailable('First Contact historical whole proof requires exact first eleven-member identity')
    writes=[];values={}
    for version in receipt.write_versions:
        history=read_graph_row_v3(db,columns=('event_id','value','valid'),where='token=? AND revision=?',parameters=(version.key.token,version.revision),history=True)
        if history is None or history[0]!=operation_id or history[2]!=1 or version.revision!=1 or version.key.type_name in values:
            raise AuthorityUnavailable('First Contact historical whole proof has another producing member')
        value=json.loads(history[1]);values[version.key.type_name]=value
        dependencies=tuple(AtomKey.from_token(ref)for(ref,)in db.execute('SELECT dependency_token FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',(version.key.token,)))
        writes.append(('d11'if version.key.type_name.startswith('runtime.')else version.key.type_name[:3],GraphWrite(version.key,value,dependencies)))
    identity=decode_typed_production_value_v1(values['d08.action_intent.v1']['identity'],OperationIdentity)
    evidence=validate_contact_dispatch_candidate_writes_v3(tuple(writes),namespace=namespace,identity=identity,
        read_versions=receipt.read_versions,source_refs=tuple(values['d08.action_intent.v1']['source_refs']),
        access_epoch=admission.admission.access_epoch,delete_epoch=admission.admission.delete_epoch,query_epoch=qualification.graph_epoch-1)
    parent=next(s.validator for s in GoalExecutionProvider().register_types()if s.name=='d08.communication_intent_grant.v1')(values['d08.communication_intent_grant.v1'])
    claim=decode_contact_claim_v2(values['d10.contact_claim.v2']);batch=validate_contact_verified_batch_v3(values['d09.contact_verified_batch.v3'])
    policy=qualification.owner_policy.policy
    from ..runtime_journal import QuotaOccupancy
    bucket=canonical_digest((namespace,claim.subject_ref,claim.channel,claim.category))
    if (evidence.digest!=admission.admission.candidate_digest or batch.content.contact_id!=request.footprint.contact_id
            or len(batch.content.segments)!=request.segment_count or len(parent.segment_grants)!=request.segment_count
            or claim.segment_effects!=tuple(part.segment.effect_id for part in batch.content.segments)
            or claim.status!='claimed' or claim.observations or claim.communication_action_id!=parent.communication_action_id
            or claim.subject_ref!=parent.target_ref or claim.channel!=policy.channel or claim.category!=policy.category
            or claim.window_id!=contact_window_id_v2(policy)or claim.policy_version!=policy.version
            or (claim.approval_ref,claim.approval_digest)!=(qualification.owner_policy.original_ref,qualification.owner_policy.digest)
            or request.segment_manifest_digest!=parent.segment_manifest_digest
            or request.segment_authorization_ref!=parent.segment_authorization_ref(batch.content.segments[0].segment.segment_id)
            or request.payload_digest!=batch.content.segments[0].payload_digest
            or request.footprint.communication_action!=parent.communication_action_id
            or request.footprint.object_gate_keys!=('contact-object:'+bucket,)
            or request.footprint.quota_occupancies!=(QuotaOccupancy('contact-quota:'+bucket,claim.window_id,1),)):
        raise AuthorityUnavailable('First Contact historical count cannot replace actual whole grant/claim/policy and first footprint proof')
    return evidence
