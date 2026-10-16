"""Named first Contact P2 Source bridge: index zero, actual whole eleven-member proof."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
import hmac,secrets
from .contract import AuthorityUnavailable
from .v2_contract import DispatchHandoffContextV1,ExecutionBindingV2,MutationReceiptV2,canonical_digest as authority_digest
from .contact_prospective_contract_v1 import ContactProspectiveObservationV1,contact_prospective_from_wire_v1,contact_prospective_to_wire_v1
from .contact_p2_source_binding_v1 import capture_contact_p2_source_binding_v1,require_contact_p2_source_binding_in_tx_v1
from ..runtime_contracts import canonical_digest
_ISSUED=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class ContactFirstP2SourceSelectorV1:
    service:object
    binding_digest:str
    context_digest:str
    claimed_digest:str
    storage_commitment:str
    admission_ref:str
    batch_ref:str
    plan_ref:str
    policy_id:str
    policy_original_ref:str
    policy_original_digest:str
    proof_valid_until_utc:float
    source_binding:object

def require_first_contact_p2_source_selector_in_tx_v1(service,db,selector,*,context,binding,claimed_receipt):
    if (type(selector)is not ContactFirstP2SourceSelectorV1 or selector.service is not service
            or _ISSUED.get(selector)!=(service,authority_digest(binding),authority_digest(context),authority_digest(claimed_receipt))
            or binding.origin.segment_index!=0 or type(binding.origin.segment_count)is not int or not 1<=binding.origin.segment_count<=3):
        raise AuthorityUnavailable('First Contact P2 lost its actual Source-qualified whole eleven-member selector')
    require_contact_p2_source_binding_in_tx_v1(db,selector.source_binding,expected_anchor=context.permit.pinned_anchor,holder=context.permit.holder)
    return selector

class InstalledContactFirstP2SourceServiceV1:
    def __init__(self,*,first,prospective):
        from .contact_p2_service_v1 import InstalledContactP2ServiceV1
        from .contact_prospective_service_v1 import InstalledContactProspectiveObserverV1
        if (type(first)is not InstalledContactP2ServiceV1 or type(prospective)is not InstalledContactProspectiveObserverV1
                or first.policy is not prospective.policy or first.execution is not prospective.execution
                or first.issuer is not prospective.reader._issuer):
            raise AuthorityUnavailable('First Contact P2 Source requires its actual installed first/policy/reader pair')
        self.first,self.prospective=first,prospective
    def read_current_first_contact_p2_selector_v1(self,*,credential,subject,context,binding,claimed_receipt,claim_receipt=None,expected_capsule=None):
        from ..runtime.contact_first_p2_source_v1 import (begin_contact_first_p2_locator_source_read_v1,read_contact_first_p2_locator_v1,
            promote_contact_first_p2_metadata_source_v1,read_contact_first_p2_selector_v1)
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
        from .contact_p2_contract_v1 import ContactP2PolicyCapsuleV1
        first,observer=self.first,self.prospective
        if (type(context)is not DispatchHandoffContextV1 or type(binding)is not ExecutionBindingV2 or type(claimed_receipt)is not MutationReceiptV2
                or binding.origin.proactive_contact is not True or binding.origin.segment_index!=0
                or type(binding.origin.segment_count)is not int or not 1<=binding.origin.segment_count<=3
                or context.binding_digest!=authority_digest(binding)or context.claimed_receipt_digest!=authority_digest(claimed_receipt)
                or subject!=observer.subject or context.permit.subject!=subject or context.permit.holder!=observer.holder
                or (claim_receipt is None)!=(expected_capsule is None)
                or expected_capsule is not None and type(expected_capsule)is not ContactP2PolicyCapsuleV1):
            raise AuthorityUnavailable('First Contact P2 needs its actual separate first-index handoff caller')
        first.policy.core._require(credential,'execution',first.policy.fences.namespace,observer.holder)
        with first.policy.fences._frozen()as(db,deletion,execution,_):
            first.execution._check_handoff_current_locked(db,permit=context.permit,subject=subject,
                claimed_receipt=claimed_receipt,deletion_head=deletion,execution_head=execution)
            anchor=first.policy.fences._current_locked(db,deletion,execution)
        permit=first.policy.fences.begin_fence(credential=credential,subject=subject,holder=observer.holder,operation='read',
            operation_id='contact-first-p2-source-read:'+secrets.token_hex(24),expected_anchor=anchor)
        work=None
        try:
            location=observer.reader._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
            work=begin_contact_first_p2_locator_source_read_v1(observer.reader,credential=credential,subject=subject,permit=permit,
                context=context,binding=binding,claimed_receipt=claimed_receipt,location=location)
            original=read_authority_graph_current_v3(work,lambda db:read_contact_first_p2_locator_v1(db,work=work,binding=binding,issuer=first.issuer))
            birth=original.first_prospective
            if type(birth)is not dict:raise AuthorityUnavailable('First Contact P2 has no actual born prospective/successor metadata')
            observation=contact_prospective_from_wire_v1(birth['observation'],ContactProspectiveObservationV1)
            wire=contact_prospective_to_wire_v1(observation)
            if not hmac.compare_digest(observation.signature,first.policy._sign({k:v for k,v in wire.items()if k!='signature'})):
                raise AuthorityUnavailable('First Contact P2 original typed birth Core signature differs')
            selected=observation.selector
            if (selected.namespace,selected.contact_id,selected.final_operation_id,selected.effect_id)!=(
                    first.policy.namespace,binding.footprint.contact_id,binding.operation_id,binding.origin.effect_id):
                raise AuthorityUnavailable('First Contact P2 typed birth differs from actual first final and effect')
            with first.policy.fences._frozen()as(db,deletion,execution,_):
                policy=first.policy._head(db,selected.policy_id)
                if policy is None or policy.action!='issue' or not policy.policy.window_start<=observer.reader._clock()<policy.policy.window_end:
                    raise AuthorityUnavailable('First Contact P2 current original standing policy is unavailable')
            promote_contact_first_p2_metadata_source_v1(work,binding=binding,selector=selected,policy=policy,location=location)
            owner=observer._owner_policy(work)
            def current(db):return read_contact_first_p2_selector_v1(db,work=work,binding=binding,
                claim_receipt=claim_receipt,expected_capsule=expected_capsule,issuer=first.issuer)
            value=read_authority_graph_current_v3(work,current)
            request,admission=value['request'],value['admission_receipt']
            if (value['first_prospective']!=birth or 'sha256:'+admission.receipt_digest!=binding.admission_receipt_digest
                    or (request.operation_id,request.effect_id,request.payload_digest,request.segment_index,request.segment_count,request.footprint)!=(
                        binding.operation_id,binding.origin.effect_id,binding.origin.payload_digest.removeprefix('sha256:'),0,binding.origin.segment_count,binding.footprint)
                    or (value['policy_original_ref'],value['policy_original_digest'])!=(policy.original_ref,policy.digest)):
                raise AuthorityUnavailable('First Contact P2 actual whole proof, first admission, policy or birth/successor changed')
            if read_authority_graph_current_v3(work,current)!=value or observer._owner_policy(work)!=owner:
                raise AuthorityUnavailable('First Contact P2 actual whole Source facts or current Owner changed')
            source_binding=capture_contact_p2_source_binding_v1(work,expected_anchor=context.permit.pinned_anchor)
            first.policy.fences.validate_fence(credential=credential,subject=subject,permit=permit)
            storage_context,storage,member=first._storage_v1()
            first.source_location._control.verify_member_v1(member,prepared=False);storage_context.require_current('business')
            if storage['graph_incarnation']!=binding.graph_incarnation:raise AuthorityUnavailable('First Contact P2 actual selected Graph differs')
            deadline=min(value['deadline_utc'],value['proof_valid_until_utc'],work.deadline_utc,policy.policy.window_end)
            result=ContactFirstP2SourceSelectorV1(first,authority_digest(binding),authority_digest(context),authority_digest(claimed_receipt),
                canonical_digest(storage),binding.origin.admission_ref,value['batch_ref'],value['plan_ref'],selected.policy_id,
                policy.original_ref,policy.digest,float(deadline),source_binding)
            _ISSUED[result]=(first,result.binding_digest,result.context_digest,result.claimed_digest)
            return result
        finally:
            finish_authority_graph_read_work_v3(work)
            first.policy.fences.finish_fence(credential=credential,subject=subject,permit=permit,
                request_id='contact-first-p2-source-finish:'+canonical_digest((permit.operation_id,permit.token)),
                request_digest='sha256:'+canonical_digest(('contact-first-p2-source-finish.v1',authority_digest(binding),permit.token)))
