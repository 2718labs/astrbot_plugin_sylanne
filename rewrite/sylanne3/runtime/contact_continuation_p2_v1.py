"""Independent current Contact continuation P2 reader and five-member historical birth."""
from dataclasses import dataclass,replace
from contextlib import contextmanager
import json
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import canonical_digest as authority_digest
from ..authority_service.contact_continuation_p2_contract_v1 import (ContactContinuationP2PolicyCapsuleV1,
    require_exact_contact_continuation_p2_capsule_v1,contact_continuation_p2_capsule_from_wire_v1,contact_continuation_p2_capsule_to_wire_v1)
from .contact_p2_current_read_v1 import ContactP2CurrentReadV1
from .contact_continuation_v1 import read_contact_segment_original_v1,_prefix
from .contact_batch_current_v3 import require_current_contact_batch_v3
_ACTIVE={}

@dataclass(frozen=True,slots=True)
class ContactContinuationP2BirthV1:
    original:dict
    admission:object
    request:object
    qualification:object
    batch_ref:str
    job_ref:str
    outbox_ref:str
    segment_original:object

def read_contact_continuation_p2_birth_v1(db,*,namespace,operation_id,issuer,prepared_original=None):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .contact_final_stage_v3 import validate_contact_final_provenance_v3
    from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3
    from .dispatch_admission import load_request
    from .dispatch_action_job_binding import load_action_job_binding
    from ..runtime_storage_v3 import read_graph_row_v3
    evidence=None
    if prepared_original is None:original=read_adopted_domain_operation_v1(db,namespace,operation_id)
    else:
        from .dispatch_initial_source_read_v3 import PreparedContactBirthOriginalsV3
        if type(prepared_original)is not PreparedContactBirthOriginalsV3:
            raise AuthorityUnavailable('Continuation P2 needs actual prepared five-member original metadata')
        original,evidence,heads=prepared_original.require_for_v3(db,namespace,operation_id)
    if original is None or original['operation_kind']!='prepare_contact_dispatch_v3':
        raise AuthorityUnavailable('Continuation P2 actual adopted five-member birth is absent')
    proof=original['payload']['provenance'];validate_contact_final_provenance_v3(proof,prepared_evidence=evidence)
    if evidence is None:evidence=decode_contact_qualification_evidence_v3(proof['qualification_evidence'],expected_digest=proof['qualification_digest'])
    issued=load_request(db,namespace,proof['admission_ref'])
    if issued is None:raise AuthorityUnavailable('Continuation P2 actual immutable admission is absent')
    admission,request=issued;receipt=original['receipt']
    segment=read_contact_segment_original_v1(db,namespace=namespace,contact_id=request.footprint.contact_id,segment_index=request.segment_index,issuer=issuer)
    if (segment is None or not 0<request.segment_index<request.segment_count<=3 or request.proactive_contact is not True
            or request.footprint.quota_occupancies or len(request.footprint.object_gate_keys)!=1
            or segment.operation_id!=operation_id or segment.effect_id!=request.effect_id
            or segment.admission_ref!=admission.admission.admission_ref or segment.admission_receipt_digest!=admission.receipt_digest
            or segment.dispatch_request_digest!=canonical_digest(request)or segment.producing_receipt_digest!=canonical_digest(receipt)
            or evidence.namespace!=namespace or evidence.operation_id!=operation_id
            or request.activation_generation!=evidence.activation_generation or admission.graph_epoch!=evidence.graph_epoch
            or request.dispatch_generation!=request.activation_generation
            or proof['admission_receipt_digest']!=admission.receipt_digest or proof['request_digest']!=canonical_digest(request)
            or proof['footprint_digest']!=canonical_digest(request.footprint)
            or len(receipt.write_versions)!=5 or len(proof['write_commitments'])!=5
            or evidence.qualification.checks!=admission.admission.check_receipts
            or {(v.key.token,v.revision)for v in receipt.write_versions}!={(v['ref'],v['revision'])for v in proof['write_commitments']}
            or load_action_job_binding(db,namespace,proof['admission_ref'])is None):
        raise AuthorityUnavailable('Continuation P2 original five-member admission/W01 identity differs')
    if {v.key.type_name for v in receipt.write_versions}!={'d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1','runtime.job','runtime.outbox'}:
        raise AuthorityUnavailable('Continuation P2 birth cannot update whole Goal/grant/batch/claim')
    for row in proof['write_commitments']:
        history=read_graph_row_v3(db,columns=('event_id','value','valid'),where='token=? AND revision=?',parameters=(row['ref'],row['revision']),history=True)
        if history is None or history[0]!=operation_id or history[2]!=1 or canonical_digest(json.loads(history[1]))!=row['digest']:
            raise AuthorityUnavailable('Continuation P2 five producing commitments differ from actual history')
    fence=db.execute('SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    attempt=db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    from ..authority_service.v2_contract import from_wire
    permit=None if fence is None else from_wire(json.loads(fence[1]))
    if (fence is None or attempt is None or fence[0]!=receipt.operation_digest or fence[1]!=attempt[2]
            or permit.operation!='write' or permit.operation_id!=attempt[1]or permit.token!=request.content_fence
            or fence[4:6]!=(fence[2]+1,fence[3]+1)or(admission.graph_revision,admission.graph_epoch)!=fence[4:6]
            or fence[6:]!=('finish:'+attempt[1],'sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3',
                'operation_id':operation_id,'request_digest':attempt[0],'permit_token':permit.token}))):
        raise AuthorityUnavailable('Continuation P2 historical original WRITE/final COMMIT linkage differs')
    return ContactContinuationP2BirthV1(original,admission,request,evidence,segment.batch_ref,segment.job_ref,segment.outbox_ref,segment)

class ContactContinuationP2CurrentReadV1(ContactP2CurrentReadV1):
    def __init__(self,*,graph,db,scope,context,binding,claimed,owner_witness,authority_snapshot,capsule,now_utc,prepared_inventory=None):
        if type(capsule)is not ContactContinuationP2PolicyCapsuleV1:
            raise AuthorityUnavailable('Continuation current P2 requires its independent typed closed Core capsule')
        self.graph,self.db,self.scope=graph,db,scope
        self.context,self.binding,self.claimed=context,binding,claimed
        self.owner_witness,self.authority_snapshot,self.capsule=owner_witness,authority_snapshot,capsule
        self.now_utc=now_utc;self.prepared_inventory=prepared_inventory;self._source_versions_v3={}
        if prepared_inventory is not None:
            from .domain_production_contracts_v1 import ProductionOperationLimitsV1
            prepared_inventory.operation.retain(ProductionOperationLimitsV1().max_graph_heads*96+1024)
        self.birth=read_contact_continuation_p2_birth_v1(db,namespace=scope.namespace,operation_id=binding.operation_id,
            issuer=graph._GraphCoordinator__d11_issuer,prepared_original=None if prepared_inventory is None else prepared_inventory.contact_birth)
        self.batch,self.batch_proof,_=require_current_contact_batch_v3(db,namespace=scope.namespace,batch_ref=self.birth.batch_ref,
            operation_id=self.birth.segment_original.first_operation_id,generation=scope.generation,graph_incarnation=binding.graph_incarnation)
        self._materialize()
    def _require(self,db):
        from ..graph_coordinator import GraphCoordinator
        from ..graph_store import ProductionGraphStore
        from ..runtime_contracts import FenceScope
        if (type(self.graph)is not GraphCoordinator or type(self.graph._GraphCoordinator__store)is not ProductionGraphStore
                or _ACTIVE.get(id(self))is not self or db is not self.db or db is not self.graph._GraphCoordinator__store._db
                or not db.in_transaction or not self.graph._GraphCoordinator__store._lock._is_owned()
                or type(self.scope)is not FenceScope or self.scope.operation!='dispatch' or self.scope.permit!=self.context.permit):
            raise AuthorityUnavailable('Continuation current P2 lost its actual registered reverse SQL scope')
        from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity,require_exact_authority_snapshot
        require_exact_reverse_handoff_identity(self.scope.authority_namespace,self.context,self.binding,self.claimed)
        require_exact_authority_snapshot(self.context,self.owner_witness,self.authority_snapshot)
        require_exact_contact_continuation_p2_capsule_v1(self.context,self.binding,self.claimed,self.owner_witness,self.authority_snapshot,self.capsule)
        c=self.capsule;s=self.birth.segment_original
        if (c.batch_ref!=s.batch_ref or c.plan_ref!=s.plan_ref or c.same_claim_ref!=s.same_claim_ref or c.same_goal_ref!=s.same_goal_ref
                or c.quote_id!=s.quote_id or c.quote_version!=s.quote_version or c.quote_digest!=s.quote_digest
                or c.reservation_digest!=s.reservation_digest or c.root_grant_digest!=s.root_grant_digest
                or c.same_object_gate!=self.birth.request.footprint.object_gate_keys[0]
                or c.communication_action!=self.birth.request.footprint.communication_action
                or c.policy_original.original_ref!=self.batch_proof.qualification.check_versions.owner_policy_ref
                or c.policy_original.digest!=self.batch_proof.qualification.check_versions.owner_policy_digest):
            raise AuthorityUnavailable('Continuation P2 current Core capsule changed original whole parent or new message price')
        stamp,epoch=self.graph._v2_graph_stamp(self.scope.namespace)
        if (epoch!=self.scope.graph_epoch or stamp.graph_revision!=self.scope.graph_revision
                or stamp.requirements.graph_incarnation!=c.graph_incarnation or stamp.requirements.activation_generation!=self.scope.generation
                or not self.graph._accounting_anchor_covers(stamp.requirements,self.scope.pinned_anchor)):
            raise AuthorityUnavailable('Continuation P2 current Graph/Authority root changed')

@contextmanager
def current_contact_continuation_p2_read_v1(**actual):
    value=ContactContinuationP2CurrentReadV1(**actual);_ACTIVE[id(value)]=value
    try:
        value.check(value.db)
        value.source_family(value.db,value.birth.qualification.expression_roots,purpose='expression',audience=value.batch.content.audience_id)
        require_current_continuation_p2_prefix_v1(value,value.db)
        yield value
    finally:_ACTIVE.pop(id(value),None)

def require_current_contact_continuation_p2_read_v1(value,db):
    if type(value)is not ContactContinuationP2CurrentReadV1:raise AuthorityUnavailable('Exact independent continuation current P2 reader required')
    value.check(db)
    return value

def require_current_continuation_p2_prefix_v1(read,db):
    require_current_contact_continuation_p2_read_v1(read,db)
    first=read_contact_segment_original_v1(db,namespace=read.scope.namespace,contact_id=read.birth.segment_original.contact_id,segment_index=0,
        issuer=read.graph._GraphCoordinator__d11_issuer)
    raw=_prefix(db,first=first,index=read.birth.request.segment_index,issuer=read.graph._GraphCoordinator__d11_issuer)
    saved=json.loads(read.capsule.continuation.inputs_json)
    if canonical_serialize(raw)!=canonical_serialize(saved['prefix']) or len(read.capsule.prefix)!=read.birth.request.segment_index:
        raise AuthorityUnavailable('Continuation P2 actual financial predecessor prefix changed')
    return read.capsule.prefix

from ..runtime_contracts import NamespaceId,schema_hash
from ..graph_types import Owner,TypeSpec,GraphWrite
from ..domains.d01.production_operations_v1 import plain_v1
from .contact_p2_qualification_v1 import ContactP2QualificationV1
CONTACT_CONTINUATION_P2_PROOF_TYPE_V1='d11.contact_continuation_p2_qualification.v1'

@dataclass(frozen=True, slots=True)
class ContactContinuationP2GraphProofV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    effect_id: str
    activity_id: str
    admission_ref: str
    graph_incarnation: str
    context_digest: str
    policy_capsule: ContactContinuationP2PolicyCapsuleV1
    qualification: ContactP2QualificationV1
    schema: str = CONTACT_CONTINUATION_P2_PROOF_TYPE_V1

    def __post_init__(self):
        c,q=self.policy_capsule,self.qualification
        if (self.schema!=CONTACT_CONTINUATION_P2_PROOF_TYPE_V1 or type(self.namespace) is not NamespaceId
                or type(c) is not ContactContinuationP2PolicyCapsuleV1 or type(q) is not ContactP2QualificationV1
                or (c.namespace,c.installation_id,c.admission_ref,c.graph_incarnation,c.context_digest)!=
                   (self.namespace,self.installation_id,self.admission_ref,self.graph_incarnation,self.context_digest)
                or c.digest!=q.policy_capsule_digest
                or c.claimed_receipt_digest!=q.claimed_receipt_digest
                or c.authority_snapshot_digest!=q.authority_snapshot_digest
                or q.check_versions.namespace!=self.namespace
                or any(type(v) is not str or not v for v in (self.operation_id,self.effect_id,self.activity_id))):
            raise ValueError('Contact P2 immutable Graph proof scope/capsule differs')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def contact_continuation_p2_graph_proof_from_wire_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!=set(ContactContinuationP2GraphProofV1.__dataclass_fields__):
        raise AuthorityUnavailable('Continuation P2 proof exact closed fields differ')
    payload=dict(raw);payload['namespace']=NamespaceId(**payload['namespace'])
    payload['policy_capsule']=contact_continuation_p2_capsule_from_wire_v1(payload['policy_capsule'])
    payload['qualification']=decode_typed_production_value_v1(payload['qualification'],ContactP2QualificationV1)
    value=ContactContinuationP2GraphProofV1(**payload)
    if canonical_serialize(plain_v1(value))!=canonical_serialize(raw):
        raise ValueError('Contact P2 graph proof canonical wire differs')
    return value


def contact_continuation_p2_graph_proof_key_v1(namespace,effect_id,activity_id):
    return AtomKey(Owner('activity',*namespace.as_tuple,activity_id),CONTACT_CONTINUATION_P2_PROOF_TYPE_V1,effect_id)


def contact_continuation_p2_graph_proof_write_v1(value):
    if type(value) is not ContactContinuationP2GraphProofV1:
        raise ValueError('Contact P2 exact immutable companion required')
    return GraphWrite(contact_continuation_p2_graph_proof_key_v1(value.namespace,value.effect_id,value.activity_id),plain_v1(value),
        tuple(v.key for v in value.qualification.positive_reads))


def contact_continuation_p2_graph_proof_type_spec_v1():
    return TypeSpec(CONTACT_CONTINUATION_P2_PROOF_TYPE_V1,('activity',),'state',contact_continuation_p2_graph_proof_from_wire_v1,
        immutable=True,writer_domain='d11',schema_hash=schema_hash({'type':CONTACT_CONTINUATION_P2_PROOF_TYPE_V1,
            'version':1,'fields':sorted(ContactContinuationP2GraphProofV1.__dataclass_fields__),
            'qualification_fields':sorted(ContactP2QualificationV1.__dataclass_fields__),
            'capsule_fields':sorted(ContactContinuationP2PolicyCapsuleV1.__dataclass_fields__),
            'purpose':'actual Contact claimed P2 current provider metadata; no body or send grant'}))


def commit_contact_continuation_dispatch_final_claim_v1(graph, context, binding, claimed, witness,
        authority_snapshot, contact_policy_witness, *, prepared, expected_receipt=None):
    from dataclasses import asdict
    from ..authority_service.contact_continuation_p2_contract_v1 import require_exact_contact_continuation_p2_capsule_v1 as require_exact_contact_p2_policy_capsule_v1
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity, require_exact_authority_snapshot
    from ..authority_service.v2_contract import DispatchGraphClaimReceiptV1, canonical_digest as authority_digest
    from ..host.installed_dispatch_route import InstalledDispatchRouteReadV1
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from ..runtime_contracts import FenceScope, NamespaceId, canonical_digest
    from .contact_continuation_p2_v1 import read_contact_continuation_p2_birth_v1 as read_contact_p2_birth_v1
    from .contact_continuation_p2_v1 import current_contact_continuation_p2_read_v1 as current_contact_p2_read_v1
    from .contact_p2_qualification_v1 import (
        issue_current_contact_p2_qualification_v1,verify_current_contact_p2_sql_v1,
        retire_current_contact_p2_qualification_v1,
    )
    from .contact_continuation_p2_v1 import (ContactContinuationP2GraphProofV1 as ContactP2GraphProofV1,
        contact_continuation_p2_graph_proof_key_v1 as contact_p2_graph_proof_key_v1,
        contact_continuation_p2_graph_proof_from_wire_v1 as contact_p2_graph_proof_from_wire_v1)
    from .contact_dispatch_host_v3 import require_prepared_contact_p2_writer_v1
    from .dispatch_graph_claim import DispatchGraphClaimValueV1,dispatch_claim_key
    from .first_ingress_v2 import trusted_upper
    handle=require_prepared_contact_p2_writer_v1(prepared)
    if (claimed!=handle.claimed or context.handoff_id!=handle.handoff_id
            or binding.operation_id!=handle.original.operation_id
            or binding.origin.admission_ref!=handle.original.admission.admission.admission_ref):
        raise ValueError('Contact current recheck lost its exact prepared claimed handoff identity')
    installed=handle.installed
    namespace=NamespaceId(*binding.graph_namespace.split('/'))
    require_exact_reverse_handoff_identity(context.permit.namespace,context,binding,claimed)
    require_exact_authority_snapshot(context,witness,authority_snapshot)
    require_exact_contact_p2_policy_capsule_v1(context,binding,claimed,witness,authority_snapshot,contact_policy_witness)
    if (graph is not installed.graph or type(handle.frozen_clock) is not VerifiedIngressClockV2
            or handle.installation_id!=witness.guard.installation_id
            or handle.frozen_clock.sample.installation_id!=handle.installation_id
            or handle.frozen_clock.sample.authority_id!=context.permit.authority_id
            or handle.frozen_clock.sample.source_id!=installed.clock_policy.source_id):
        raise ValueError('Contact P2 requires its actual installed clock and prepared coordinator')
    now=max(trusted_upper(handle.frozen_clock),contact_policy_witness.observed_at_utc)
    store=graph._GraphCoordinator__store;db=store._db
    with store._lock:
        db.execute('BEGIN')
        try:
            birth=read_contact_p2_birth_v1(db,namespace=namespace,operation_id=binding.operation_id,issuer=graph._GraphCoordinator__d11_issuer)
            selectors=(birth.admission.admission.account_ref,birth.admission.admission.destination_ref,
                birth.admission.admission.scene_ref)
        finally:db.rollback()
    route_digest=canonical_digest(dict(zip(('account_ref','destination_ref','scene_ref'),selectors)))
    route=installed.route_port.read_live_host_scene_only(namespace=namespace,account_ref=selectors[0],
        destination_ref=selectors[1],scene_ref=selectors[2],route_digest=route_digest)
    if (type(route) is not InstalledDispatchRouteReadV1 or route.status!='verified_route'
            or route.current_scene is None or route.route_digest!=route_digest
            or route.current_scene.namespace!=namespace or route.current_scene.scene_ref!=selectors[2]):
        raise ValueError('Contact P2 actual live Host private route is unavailable')
    with store._lock:
        db.execute('BEGIN IMMEDIATE')
        try:
            metadata,epoch=graph._v2_graph_stamp(namespace)
            from ..runtime_storage_v3 import runtime_storage_v3
            if runtime_storage_v3(db) is not None:
                from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3, PreparedCurrentDispatchSuccessorInventoryV3
                if type(handle.prepared_inventory) not in (PreparedCurrentDispatchInventoryV3,PreparedCurrentDispatchSuccessorInventoryV3):
                    raise ValueError('actual pre-P1 Contact full dispatch inventory required')
                handle.prepared_inventory.require_for(context,binding,claimed,db,authority_snapshot=authority_snapshot)
            scope=FenceScope(namespace,context.permit.namespace,context.permit.generation,'dispatch',
                context.permit.operation_id,context.permit,context.permit.pinned_anchor,epoch,metadata.graph_revision)
            with current_contact_p2_read_v1(graph=graph,db=db,scope=scope,context=context,binding=binding,
                    claimed=claimed,owner_witness=witness,authority_snapshot=authority_snapshot,
                    capsule=contact_policy_witness,now_utc=now,prepared_inventory=handle.prepared_inventory) as read:
                if (read.birth.admission.admission.account_ref,read.birth.admission.admission.destination_ref,
                        read.birth.admission.admission.scene_ref)!=selectors:
                    raise ValueError('Contact P2 private route changed before final claim transaction')
                read.birth.admission.admission.require_current(now)
                issued=issue_current_contact_p2_qualification_v1(db,read)
                try:
                    qualification=verify_current_contact_p2_sql_v1(db,read,issued)
                    owner_epochs=graph._verify_dispatch_owner_graph_locked(namespace,witness,
                        read.birth.admission.admission,epoch.revision,handle.installation_id)
                    key=dispatch_claim_key(namespace,binding.origin.effect_id)
                    existing=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
                    if existing is None:
                        if expected_receipt is not None:
                            raise ValueError('Contact cached callback lost its original claim; no new claim allowed')
                        proof=ContactP2GraphProofV1(namespace,handle.installation_id,binding.operation_id,
                            binding.origin.effect_id,binding.origin.activity_id,binding.origin.admission_ref,
                            binding.graph_incarnation,authority_digest(context),contact_policy_witness,qualification)
                        value=DispatchGraphClaimValueV1(*namespace.as_tuple,binding.graph_incarnation,
                            binding.origin.activity_id,binding.origin.effect_id,binding.operation_id,context.handoff_id,
                            binding.origin.admission_ref,scope.authority_namespace,authority_digest(context.permit),
                            context.permit.fence_epoch,context.permit.revision,scope.pinned_anchor.execution_seq,
                            scope.pinned_anchor.execution_digest,authority_digest(context),authority_digest(witness),
                            authority_digest(binding),authority_digest(claimed),'sha256:'+proof.digest)
                    else:
                        if existing[0]!=1 or existing[2]!=1:
                            raise ValueError('Contact P2 original claim was invalidated')
                        value=DispatchGraphClaimValueV1(**json.loads(existing[1]))
                        proof_key=contact_p2_graph_proof_key_v1(namespace,binding.origin.effect_id,binding.origin.activity_id)
                        old=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(proof_key.token,)).fetchone()
                        if old is None or old[0]!=1 or old[2]!=1:
                            raise ValueError('Contact P2 original claim qualification companion is absent')
                        proof=contact_p2_graph_proof_from_wire_v1(json.loads(old[1]))
                        old_capsule=proof.policy_capsule
                        if (value.context_digest!=authority_digest(context)
                                or contact_policy_witness.observed_at_utc<old_capsule.observed_at_utc
                                or replace(contact_policy_witness,observed_at_utc=old_capsule.observed_at_utc)!=old_capsule
                                or now>=min(v.valid_until for v in proof.qualification.checks)):
                            raise ValueError('Contact P2 ACKloss replay changed identity or expired original qualification')
                    delta_capture=None
                    if handle.prepared_inventory is not None and expected_receipt is None and existing is None:
                        from .dispatch_current_inventory_v3 import begin_contact_dispatch_delta_capture_v3
                        delta_capture=begin_contact_dispatch_delta_capture_v3(handle.prepared_inventory,handle,context,binding,claimed)
                    version,claim_epoch,_=graph._commit_dispatch_claim_atom_in_transaction(namespace,value,claimed,
                        contact_p2_proof=proof,_inventory_delta_capture=delta_capture)
                    receipt=DispatchGraphClaimReceiptV1(authority_digest(context),binding.graph_namespace,
                        binding.graph_incarnation,'graph:'+str(version.revision),claim_epoch,*owner_epochs,
                        'dispatch-claim:'+binding.origin.effect_id,'sha256:'+canonical_digest(asdict(value)),installed.issuer_id)
                    if expected_receipt is not None and receipt!=expected_receipt:
                        raise ValueError('Contact cached callback current read differs from original receipt')
                    db.commit()
                    if delta_capture is not None:
                        successor=delta_capture.committed(receipt)
                        object.__setattr__(handle,'prepared_inventory',successor)
                    return receipt
                finally:retire_current_contact_p2_qualification_v1(issued)
        except BaseException:
            db.rollback()
            raise


def read_contact_continuation_host_identity_v1(graph,namespace,operation_id,original,result,issued):
    from ..host.contact_dispatch_driver_v3 import OriginalContactDispatchV3
    db=graph._GraphCoordinator__store._db
    admission,request=issued
    segment=read_contact_segment_original_v1(db,namespace=namespace,contact_id=request.footprint.contact_id,segment_index=request.segment_index,issuer=graph._GraphCoordinator__d11_issuer)
    proof=original['payload']['provenance'];receipt=original['receipt']
    if (segment is None or not 0<request.segment_index<request.segment_count<=3 or request.footprint.quota_occupancies
            or segment.operation_id!=operation_id or segment.effect_id!=request.effect_id
            or segment.dispatch_request_digest!=canonical_digest(request)or segment.admission_receipt_digest!=admission.receipt_digest
            or segment.producing_receipt_digest!=canonical_digest(receipt)or segment.admission_ref!=proof['admission_ref']
            or len(receipt.write_versions)!=5 or len(proof['write_commitments'])!=5
            or {(v.key.token,v.revision)for v in receipt.write_versions}!={(row['ref'],row['revision'])for row in proof['write_commitments']}):
        raise AuthorityUnavailable('Continuation Host original is outside its exact immutable five-write COMMIT')
    from ..runtime_storage_v3 import read_graph_row_v3
    for row in proof['write_commitments']:
        history=read_graph_row_v3(db,columns=('event_id','value','valid'),where='token=? AND revision=?',parameters=(row['ref'],row['revision']),history=True)
        if history is None or history[0]!=operation_id or history[2]!=1 or canonical_digest(json.loads(history[1]))!=row['digest']:
            raise AuthorityUnavailable('Continuation Host producing member history differs')
    return OriginalContactDispatchV3(namespace,operation_id,segment.outbox_ref,segment.batch_ref,request,admission,receipt),result
