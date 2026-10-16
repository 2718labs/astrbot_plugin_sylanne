"""Actual separate Core P2 branch for later Contact five-write births."""
from dataclasses import dataclass,replace
from datetime import datetime
from weakref import WeakKeyDictionary
import json,hmac,secrets
from .contract import AuthorityUnavailable
from .contact_continuation_contract_v1 import ContactContinuationSelectorV1,ContactContinuationObservationV1,contact_continuation_to_wire_v1,contact_continuation_from_wire_v1
from .contact_continuation_p2_contract_v1 import ContactContinuationP2PolicyCapsuleV1
from .v2_contract import ExecutionBindingV2,DispatchHandoffContextV1,MutationReceiptV2,OwnerDispatchWitnessV1,AuthorityDispatchSnapshotV1,canonical_digest as authority_digest
from ..runtime_contracts import canonical_digest
_ISSUED=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class _ContactContinuationP2SelectorV1:
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
    observation:ContactContinuationObservationV1
    same_object_gate:str
    communication_action:str
    quote_id:str
    quote_version:int
    quote_digest:str
    reservation_digest:str
    root_grant_id:str
    root_grant_version:int
    root_grant_digest:str
    root_lease_ref:str
    deadline_utc:float
    source_binding:object

class InstalledContactContinuationP2ServiceV1:
    def __init__(self,*,first,observer):
        from .contact_p2_service_v1 import InstalledContactP2ServiceV1
        from .contact_continuation_service_v1 import InstalledContactContinuationObserverV1
        if (type(first)is not InstalledContactP2ServiceV1 or type(observer)is not InstalledContactContinuationObserverV1
                or first is not observer.accounting.p2 or first.policy is not observer.policy
                or first.execution is not observer.execution or first.issuer is not observer.reader._issuer):
            raise AuthorityUnavailable('Contact continuation P2 requires its actual installed original service pair')
        self.first,self.observer=first,observer
        self.policy,self.execution,self.issuer=first.policy,first.execution,first.issuer
    def _scope(self,credential,subject,context,binding,claimed_receipt):
        if (type(context)is not DispatchHandoffContextV1 or type(binding)is not ExecutionBindingV2 or type(claimed_receipt)is not MutationReceiptV2
                or binding.origin.proactive_contact is not True or not 1<=binding.origin.segment_index<binding.origin.segment_count<=3
                or context.binding_digest!=authority_digest(binding)or context.claimed_receipt_digest!=authority_digest(claimed_receipt)
                or subject!=self.observer.subject or context.permit.subject!=subject or context.permit.holder!=self.observer.holder
                or binding.graph_namespace!='/'.join(self.policy.namespace.as_tuple)):
            raise AuthorityUnavailable('Contact continuation P2 needs its exact actual claimed later-segment call')
        self.policy.core._require(credential,'execution',self.policy.fences.namespace,self.observer.holder)
        with self.policy.fences._frozen()as(db,deletion,execution,_):
            self.execution._check_handoff_current_locked(db,permit=context.permit,subject=subject,
                claimed_receipt=claimed_receipt,deletion_head=deletion,execution_head=execution)
            return self.policy.fences._current_locked(db,deletion,execution)
    def read_graph_selector_v1(self,*,credential,subject,context,binding,claimed_receipt,claim_receipt=None,expected_capsule=None):
        from ..runtime.contact_continuation_v1 import (begin_contact_continuation_locator_source_read_v1,
            read_contact_continuation_locator_v1,promote_contact_continuation_metadata_source_v1,
            read_contact_continuation_p2_selector_v1)
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
        anchor=self._scope(credential,subject,context,binding,claimed_receipt)
        if (claim_receipt is None)!=(expected_capsule is None) or expected_capsule is not None and type(expected_capsule)is not ContactContinuationP2PolicyCapsuleV1:
            raise AuthorityUnavailable('Contact continuation P2 post-CAS requires its separate actual claim/capsule pair')
        read_permit=self.policy.fences.begin_fence(credential=credential,subject=subject,holder=self.observer.holder,operation='read',
            operation_id='contact-continuation-p2-read:'+secrets.token_hex(24),expected_anchor=anchor)
        work=None
        try:
            location=self.observer.reader._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=read_permit)
            work=begin_contact_continuation_locator_source_read_v1(self.observer.reader,credential=credential,subject=subject,
                permit=read_permit,binding=binding,context=context,claimed_receipt=claimed_receipt,location=location)
            locator=read_authority_graph_current_v3(work,lambda db:read_contact_continuation_locator_v1(db,work=work,binding=binding,issuer=self.issuer))
            observation=contact_continuation_from_wire_v1(locator.core_observation,ContactContinuationObservationV1)
            if type(observation)is not ContactContinuationObservationV1:raise AuthorityUnavailable('Contact continuation P2 locator lacks its exact stored Core observation')
            selector=observation.selector
            if (selector.namespace,selector.contact_id,selector.operation_id,selector.segment_index)!=(
                    self.policy.namespace,binding.footprint.contact_id,binding.operation_id,binding.origin.segment_index):
                raise AuthorityUnavailable('Contact continuation P2 actual locator identifies another original segment')
            wire=contact_continuation_to_wire_v1(observation)
            if not hmac.compare_digest(observation.signature,self.policy._sign({k:v for k,v in wire.items()if k!='signature'})):
                raise AuthorityUnavailable('Contact continuation P2 original Core observation signature differs')
            policy=self.observer._policy(credential,subject,selector)
            promote_contact_continuation_metadata_source_v1(work,binding=binding,selector=selector,policy=policy,location=location)
            owner=self.observer.prospective._owner_policy(work)
            def current(db):return read_contact_continuation_p2_selector_v1(db,work=work,binding=binding,
                claim_receipt=claim_receipt,expected_capsule=expected_capsule,issuer=self.issuer)
            value=read_authority_graph_current_v3(work,current)
            fresh=value['inputs'];captured=json.loads(observation.inputs_json)
            if (value['observation_wire']!=wire or set(fresh)!=set(captured)
                    or any(fresh[k]!=captured[k]for k in set(fresh)-{'graph_revision','graph_epoch'})
                    or value['quota_occupancies']!=()or value['reservation']['state']!='reserved'
                    or self.observer._prefix(credential,subject,fresh)!=observation.prefix):
                raise AuthorityUnavailable('Contact continuation P2 changed its original business or current complete paid prefix')
            request,admission=value['request'],value['admission_receipt']
            if ('sha256:'+admission.receipt_digest!=binding.admission_receipt_digest
                    or (request.operation_id,request.effect_id,request.payload_digest,request.footprint,request.segment_index,request.segment_count)!=(
                        binding.operation_id,binding.origin.effect_id,binding.origin.payload_digest.removeprefix('sha256:'),binding.footprint,
                        binding.origin.segment_index,binding.origin.segment_count)):
                raise AuthorityUnavailable('Contact continuation P2 is outside its exact five-write admission')
            members=value['p2_members']
            if set(members)!={'action','action_schema','cancellation','job','outbox','claim','goal','communication_grant','dispatch_claim'}:
                raise AuthorityUnavailable('Contact continuation P2 five-member/current-cause coverage differs')
            for name in ('action','action_schema','cancellation','job','outbox','claim','goal','communication_grant'):
                if not members[name]['valid'] or members[name]['revision']<1:
                    raise AuthorityUnavailable('Contact continuation P2 current required member is unavailable')
            claim=members['dispatch_claim']
            if (expected_capsule is None and (claim['revision']!=0 or claim['valid']))or(expected_capsule is not None and (claim['revision']!=1 or not claim['valid'])):
                raise AuthorityUnavailable('Contact continuation P2 actual pre/post claim state differs')
            root=self.observer.bundle.installation_policy.root_grant;quote=value['quote'];reservation=value['reservation']
            if (value['root_grant_id'],value['root_grant_version'],value['root_grant_digest'],value['root_lease_ref'])!=(
                    root.grant_id,root.version,canonical_digest(root),root.lease_id):
                raise AuthorityUnavailable('Contact continuation P2 changed its originally installed root')
            if (quote['operation_id'],quote['effect_id'],quote['parent_budget_lease_ref'])!=(binding.operation_id,binding.origin.effect_id,root.lease_id):
                raise AuthorityUnavailable('Contact continuation P2 quote is not this new segment original')
            deadline=min(observation.deadline_utc,work.deadline_utc,quote['deadline_utc'],quote['valid_until_utc'],
                datetime.fromisoformat(binding.utc_deadline.replace('Z','+00:00')).timestamp())
            if not self.policy._clock()<deadline:raise AuthorityUnavailable('Contact continuation P2 original absolute deadline expired')
            if read_authority_graph_current_v3(work,current)!=value or self.observer.prospective._owner_policy(work)!=owner:
                raise AuthorityUnavailable('Contact continuation P2 actual current Source members or Owner changed')
            self.policy.fences.validate_fence(credential=credential,subject=subject,permit=read_permit)
            from .contact_p2_source_binding_v1 import capture_contact_p2_source_binding_v1
            source_binding=capture_contact_p2_source_binding_v1(work,expected_anchor=context.permit.pinned_anchor)
            _,storage,_=self.first._storage_v1()
            if storage['graph_incarnation']!=binding.graph_incarnation:raise AuthorityUnavailable('Contact continuation P2 current selected Graph identity differs')
            selected=_ContactContinuationP2SelectorV1(self,authority_digest(binding),authority_digest(context),authority_digest(claimed_receipt),
                canonical_digest(storage),binding.origin.admission_ref,fresh['batch_ref'],fresh['plan_ref'],selector.policy_id,
                policy.original_ref,policy.digest,observation,value['same_object_gate'],value['communication_action'],
                quote['quote_id'],quote['version'],canonical_digest(quote),reservation['digest'],root.grant_id,root.version,
                canonical_digest(root),root.lease_id,float(deadline),source_binding)
            _ISSUED[selected]=(self,selected.binding_digest,selected.context_digest,selected.claimed_digest,selected.observation.digest)
            return selected
        finally:
            finish_authority_graph_read_work_v3(work)
            self.policy.fences.finish_fence(credential=credential,subject=subject,permit=read_permit,
                request_id='contact-continuation-p2-read-finish:'+canonical_digest((read_permit.operation_id,read_permit.token)),
                request_digest='sha256:'+canonical_digest(('contact-continuation-p2-read-finish.v1',authority_digest(binding),read_permit.token)))
    def _prefix_in_tx_v1(self,db,observation):
        from .contact_effect_accounting_contract_v1 import ContactEffectAccountingRequestV1,from_wire
        terms=json.loads(observation.inputs_json)
        for item,prefix in zip(terms['prefix'],observation.prefix,strict=True):
            request=from_wire(item['accounting_request'],ContactEffectAccountingRequestV1)
            fact=self.observer.accounting._fact_locked(db,request.origin,request.observed_mutation_id,request.measurement_receipt_digest)
            row=self.policy.fences.fences._row(db,request.operation_id)
            permit=None if row is None else self.policy.fences.fences._permit(row)
            if (fact.digest!=prefix.fact_digest or fact.observation_outcome!='accepted' or row is None or row[6]!='finished'
                    or row[10]is not None or permit.operation!='accounting' or permit.subject!=self.observer.subject
                    or permit.holder!=self.observer.holder or permit.namespace!=self.policy.fences.namespace
                    or permit.pinned_anchor!=request.expected_anchor or permit.command_digest!=self.observer.accounting._binding(request,fact)
                    or row[8:10]!=(prefix.finish_request_id,prefix.finish_request_digest)
                    or row[8:10]!=self.observer.accounting._finish_identity(request,permit)):
                raise AuthorityUnavailable('Contact continuation P2 current prefix lacks actual finished accounting ACK')
    def read_current_contact_continuation_policy_for_dispatch_in_tx_v1(self,db,*,context,binding,claimed_receipt,
            owner_witness,authority_snapshot,selector):
        if (db is not self.policy.core._db or not db.in_transaction or type(context)is not DispatchHandoffContextV1
                or type(binding)is not ExecutionBindingV2 or type(owner_witness)is not OwnerDispatchWitnessV1
                or type(authority_snapshot)is not AuthorityDispatchSnapshotV1 or type(selector)is not _ContactContinuationP2SelectorV1
                or _ISSUED.get(selector)!=(self,authority_digest(binding),authority_digest(context),authority_digest(claimed_receipt),selector.observation.digest)
                or selector.service is not self or context.binding_digest!=authority_digest(binding)
                or context.claimed_receipt_digest!=authority_digest(claimed_receipt)
                or authority_snapshot.context_digest!=authority_digest(context)
                or authority_snapshot.owner_witness_digest!=authority_digest(owner_witness)
                or authority_snapshot.anchor!=context.permit.pinned_anchor or binding.origin.proactive_contact is not True
                or not 1<=binding.origin.segment_index<binding.origin.segment_count<=3 or binding.footprint.quota_occupancies):
            raise AuthorityUnavailable('Contact continuation P2 capsule lost its actual current Core reverse identity')
        from .contact_p2_source_binding_v1 import require_contact_p2_source_binding_in_tx_v1
        require_contact_p2_source_binding_in_tx_v1(db,selector.source_binding,expected_anchor=context.permit.pinned_anchor,holder=context.permit.holder)
        current=self.policy.tickets.current_dispatch_witness_in_tx(db,context=context,binding=binding,installation_id=self.policy.installation_id)
        head=self.policy.tickets.current_migration_head_in_tx(db,authority_namespace=self.policy.fences.namespace)
        if current!=owner_witness or head is None or head.state!='active' or head.guard!=current.guard or head.issue_operation.operation_id!=current.issue_operation_id:
            raise AuthorityUnavailable('Contact continuation P2 current original Owner changed')
        original=self.policy._head(db,selector.policy_id);now=self.policy._clock()
        if (original is None or original.action!='issue' or original.original_ref!=selector.policy_original_ref
                or original.digest!=selector.policy_original_digest or original.authority_id!=context.permit.authority_id
                or original.owner_head_digest!=head.guard.authorization_head
                or original.owner_authorization_revision!=head.guard.authorization_revision
                or original.owner_principal_epoch!=self.policy._principal_epoch(db,head)
                or not original.policy.window_start<=now<min(original.policy.window_end,selector.deadline_utc)
                or selector.observation.policy_original_ref!=original.original_ref or selector.observation.policy_original_digest!=original.digest):
            raise AuthorityUnavailable('Contact continuation P2 current policy, Owner principal or original absolute deadline differs')
        self._prefix_in_tx_v1(db,selector.observation)
        return ContactContinuationP2PolicyCapsuleV1(self.policy.installation_id,self.policy.namespace,binding.graph_incarnation,
            selector.storage_commitment,selector.admission_ref,selector.batch_ref,selector.plan_ref,
            authority_digest(context),authority_digest(binding),authority_digest(claimed_receipt),authority_digest(owner_witness),
            authority_digest(authority_snapshot),original,selector.observation,selector.observation.prefix,
            selector.same_object_gate,selector.communication_action,selector.quote_id,selector.quote_version,selector.quote_digest,
            selector.reservation_digest,selector.root_grant_id,selector.root_grant_version,selector.root_grant_digest,selector.root_lease_ref,
            (),float(now),selector.deadline_utc)
    def require_same_contact_continuation_policy_after_claim_in_tx_v1(self,db,*,capsule,**current):
        if type(capsule)is not ContactContinuationP2PolicyCapsuleV1:raise AuthorityUnavailable('Contact continuation post-claim cannot use the first capsule')
        observed=self.read_current_contact_continuation_policy_for_dispatch_in_tx_v1(db,**current)
        if replace(observed,observed_at_utc=capsule.observed_at_utc)!=capsule:
            raise AuthorityUnavailable('Contact continuation P2 permission/original quota/prefix changed during actual Graph claim')
        return capsule
