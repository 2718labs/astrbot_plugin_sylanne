"""Independent later Contact observation with actual Core accounting finish readback."""
from dataclasses import asdict,replace
from datetime import datetime
import json,hmac,secrets
from .contract import AuthorityUnavailable
from .contact_continuation_contract_v1 import (ContactContinuationSelectorV1,ContactContinuationPrefixFactV1,
    ContactContinuationObservationV1,ContactContinuationObservationProjectionReadV1,
    MAX_INPUT_BYTES,MAX_OBSERVATION_BYTES,contact_continuation_to_wire_v1,contact_continuation_from_wire_v1)
from .v2_contract import FencePermitV2,to_wire,canonical_digest as authority_digest
from ..runtime_contracts import canonical_digest,canonical_serialize

class InstalledContactContinuationObserverV1:
    def __init__(self,*,prospective,accounting):
        from .contact_prospective_service_v1 import InstalledContactProspectiveObserverV1
        from .contact_effect_accounting_v1 import InstalledContactEffectAccountingServiceV1
        if (type(prospective)is not InstalledContactProspectiveObserverV1 or type(accounting)is not InstalledContactEffectAccountingServiceV1
                or accounting.core is not prospective.core or accounting.fences is not prospective.fences
                or accounting.execution is not prospective.execution or accounting.issuer is not prospective.reader._issuer
                or accounting.bundle.installation_policy!=prospective.bundle.installation_policy
                or accounting.subject!=prospective.subject or accounting.holder!=prospective.holder):
            raise AuthorityUnavailable('Contact continuation requires its actual installed Core/financial/Source composition')
        self.prospective,self.accounting=prospective,accounting
        self.reader,self.execution,self.bundle=prospective.reader,prospective.execution,prospective.bundle
        self.policy,self.fences,self.core=prospective.policy,prospective.fences,prospective.core
        self.namespace,self.installation_id=prospective.namespace,prospective.installation_id
        self.subject,self.holder=prospective.subject,prospective.holder
    def _policy(self,credential,subject,selector):
        if type(selector)is not ContactContinuationSelectorV1 or subject!=self.subject or selector.namespace!=self.bundle.installation_policy.namespace:
            raise AuthorityUnavailable('Contact continuation exact installed selector/Host differs')
        self.core._require(credential,'current',self.namespace,self.holder)
        with self.fences._frozen()as(db,deletion,execution,_):
            policy=self.policy._head(db,selector.policy_id)
            if policy is None or policy.action!='issue' or policy.namespace!=selector.namespace or not policy.policy.window_start<=self.reader._clock()<policy.policy.window_end:
                raise AuthorityUnavailable('Contact continuation current signed standing policy is unavailable')
        return policy
    def _inputs(self,db,work,selector):
        from ..runtime.contact_continuation_v1 import read_contact_continuation_inputs_v1
        terms=read_contact_continuation_inputs_v1(db,work=work,selector=selector,issuer=self.reader._issuer,now_utc=self.reader._clock())
        root=self.bundle.installation_policy.root_grant
        if ((terms['namespace'],terms['contact_id'],terms['segment_index'],terms['operation_id'],terms['request_digest'],
                terms['old_causal_dedupe_key'],terms['attempt_id'],terms['permit_digest'])!=(
                asdict(selector.namespace),selector.contact_id,selector.segment_index,selector.operation_id,selector.request_digest,
                selector.causal_dedupe_key,work.permit.operation_id,authority_digest(work.permit).removeprefix('sha256:'))
                or not selector.segment_index<terms['segment_count']<=3
                or (terms['root_grant_id'],terms['root_grant_version'],terms['root_grant_digest'],terms['root_lease_ref'])!=(
                    root.grant_id,root.version,canonical_digest(root),root.lease_id)):
            raise AuthorityUnavailable('Contact continuation changed actual attempt, whole manifest or original installed root')
        return terms
    def _prefix(self,credential,subject,terms):
        from .contact_effect_accounting_contract_v1 import (SignedContactEffectBudgetOriginV1,ContactEffectAccountingRequestV1,
            from_wire as accounting_read,SETTLEMENT_SIGN,to_wire as accounting_wire)
        from ..runtime.contact_effect_accounting_v1 import restore_stored_fact_v1
        prefix=terms['prefix']
        if len(prefix)!=terms['segment_index']:raise AuthorityUnavailable('Contact continuation omitted a prior segment')
        facts=[]
        for index,item in enumerate(prefix):
            signed=accounting_read(item['budget_origin'],SignedContactEffectBudgetOriginV1)
            request=accounting_read(item['accounting_request'],ContactEffectAccountingRequestV1)
            settlement=item['settlement'];raw=settlement['payload'];stored=raw['result'];origin=signed.origin
            if set(settlement)!={'payload','payload_digest','signature'} or canonical_digest(raw)!=settlement['payload_digest']:
                raise AuthorityUnavailable('Contact continuation settlement original wrapper differs')
            self.reader._issuer._signer.verify(SETTLEMENT_SIGN,canonical_serialize(raw),settlement['signature'])
            self.accounting._request(credential,subject,request)
            saved_fact=restore_stored_fact_v1(raw,signed)
            if (item['segment_index']!=index or item['budget_status']!='settled' or item['observation_outcome']!='accepted'
                    or stored['accounting_finished']is not False or stored['budget_status']!='settled'
                    or stored['observation_outcome']!='accepted' or request.origin!=signed
                    or request.operation_id!=raw['request_ref'] or request.observed_mutation_id!=item['observed_mutation_id']
                    or (origin.namespace,origin.installation_id,origin.authority_namespace,origin.operation_id,origin.effect_id,
                        origin.admission_ref,origin.admission_receipt_digest,origin.request_digest)!=(
                        self.bundle.installation_policy.namespace,self.installation_id,self.namespace,item['operation_id'],item['effect_id'],
                        item['admission_ref'],item['admission_receipt_digest'],item['request_digest'])
                    or origin.parent_budget_lease_ref!=terms['root_lease_ref']
                    or (saved_fact.observed_receipt_digest,saved_fact.binding_digest,saved_fact.observation_outcome)!=(
                        item['observed_receipt_digest'],item['binding_digest'],'accepted')):
                raise AuthorityUnavailable('Contact continuation requires every accepted settled original; cleanup is not success')
            with self.fences._frozen()as(db,deletion,execution,_):
                self.accounting.accounting._require_closed_deletion_history()
                actual=self.accounting._fact_locked(db,signed,request.observed_mutation_id,request.measurement_receipt_digest)
                row=self.fences.fences._row(db,request.operation_id)
                permit=None if row is None else self.fences.fences._permit(row)
                if (actual!=saved_fact or actual.observation_outcome!='accepted' or row is None or row[6]!='finished' or row[10]is not None
                        or permit.operation!='accounting' or (permit.subject,permit.holder,permit.namespace)!=(subject,self.holder,self.namespace)
                        or permit.pinned_anchor!=request.expected_anchor or permit.command_digest!=self.accounting._binding(request,actual)
                        or row[8:10]!=self.accounting._finish_identity(request,permit)):
                    raise AuthorityUnavailable('Contact continuation lacks actual Core finished accounting and exact finish ACK')
                mutation=self.execution.fences.mutation_locked(db,request.observed_mutation_id)
                completed=None if mutation is None else self.execution._completed_result(mutation)
                if completed is None or authority_digest(completed[0]).removeprefix('sha256:')!=item['observed_receipt_digest']:
                    raise AuthorityUnavailable('Contact continuation prefix actual observed mutation differs')
                binding=completed[0].pending.binding
                if (binding.origin.segment_index,binding.origin.payload_digest,binding.origin.segment_count,binding.origin.segment_manifest_digest)!=(
                        index,'sha256:'+item['payload_digest'],terms['segment_count'],'sha256:'+terms['whole_manifest_digest']):
                    raise AuthorityUnavailable('Contact continuation prefix changed whole manifest or payload index')
                finish_id,finish_digest=row[8:10]
            current=self.execution.read_current_effect(credential=credential,subject=subject,effect_id=item['effect_id'])
            if current.state!='observed' or current.observation_outcome!='accepted' or current.mutation_id!=item['observed_mutation_id']:
                raise AuthorityUnavailable('Contact continuation prefix no longer has its current accepted observation')
            facts.append(ContactContinuationPrefixFactV1(index,item['operation_id'],item['effect_id'],item['admission_ref'],
                item['admission_receipt_digest'],item['request_digest'],item['payload_digest'],item['observed_receipt_digest'],
                item['observed_mutation_id'],item['binding_digest'],origin.digest,settlement['payload_digest'],actual.digest,
                request.operation_id,canonical_digest(accounting_wire(request)),finish_id,finish_digest))
        if not facts or facts[0].admission_ref!=terms['first_admission_ref']:
            raise AuthorityUnavailable('Contact continuation lacks its original first admission')
        return tuple(facts)
    def capture(self,*,credential,subject,permit,selector):
        from .contact_background_graph_v3 import ContactBackgroundSelectorV3,begin_contact_authority_graph_read_v3
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        from .owner_location_read_v3 import require_owner_location_observation_current_for_contact_v3
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        policy=self._policy(credential,subject,selector)
        if (type(permit)is not FencePermitV2 or permit.operation!='write' or permit.subject!=subject
                or permit.holder!=self.holder or permit.namespace!=self.namespace):
            raise AuthorityUnavailable('Contact continuation needs its actual independent new-segment WRITE attempt')
        self.core._require(credential,'write',self.namespace,self.holder)
        self.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        location=self.reader._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
        selected=ContactBackgroundSelectorV3(selector.namespace,selector.contact_id,selector.operation_id,
            selector.request_digest,selector.policy_id,selector.causal_dedupe_key)
        work=begin_contact_authority_graph_read_v3(self.reader,credential=credential,subject=subject,
            permit=permit,selector=selected,policy=policy,location=location)
        try:
            owner=self.prospective._owner_policy(work)
            terms=read_authority_graph_current_v3(work,lambda db:self._inputs(db,work,selector))
            prefix=self._prefix(credential,subject,terms)
            effect=self.execution.read_current_effect(credential=credential,subject=subject,effect_id=terms['effect_id'])
            snapshot=self.execution.read_current_effect_snapshot_for_write_fence(credential=credential,subject=subject,permit=permit)
            if effect.state!='absent' or snapshot.coverage!='complete' or snapshot.anchor!=permit.pinned_anchor:
                raise AuthorityUnavailable('Contact continuation selected new effect is not independently absent')
            if read_authority_graph_current_v3(work,lambda db:self._inputs(db,work,selector))!=terms or self._prefix(credential,subject,terms)!=prefix:
                raise AuthorityUnavailable('Contact continuation Source originals or full prefix changed')
            if self.prospective._owner_policy(work)!=owner:raise AuthorityUnavailable('Contact continuation current Owner changed')
            authority={**current_owner_authority_to_wire_v1(owner),'permit':to_wire(permit)}
            from .contact_p2_source_binding_v1 import capture_contact_p2_source_binding_v1,require_contact_p2_source_binding_in_tx_v1
            source_binding=capture_contact_p2_source_binding_v1(work,expected_anchor=permit.pinned_anchor)
            with self.fences._frozen()as(db,deletion,execution,_):
                anchor=self.fences._current_locked(db,deletion,execution)
                self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
                require_owner_location_observation_current_for_contact_v3(self.policy.owner_service,work,owner,db)
                require_contact_p2_source_binding_in_tx_v1(db,source_binding,expected_anchor=permit.pinned_anchor,holder=permit.holder)
                head=self.policy._current_owner(db,owner,permit);now=self.reader._clock()
                deadline=min(terms['deadline_utc'],policy.policy.window_end,work.deadline_utc)
                if self.policy._head(db,selector.policy_id)!=policy or policy.owner_principal_epoch!=self.policy._principal_epoch(db,head)or not now<deadline:
                    raise AuthorityUnavailable('Contact continuation original Owner/policy/absolute deadline changed')
                input_size=c09_canonical_json_size_v3(terms,ascii=True,exact=True)
                if input_size>MAX_INPUT_BYTES:raise AuthorityUnavailable('Contact continuation actual metadata exceeds its original bound')
                work.operation.retain(input_size*2+8192)
                material=dict(selector=contact_continuation_to_wire_v1(selector),authority_id=permit.authority_id,
                    authority_namespace=self.namespace,installation_id=self.installation_id,subject=subject,
                    attempt_id=permit.operation_id,permit_digest=authority_digest(permit).removeprefix('sha256:'),
                    anchor_digest=canonical_digest(asdict(anchor)),selection_digest=work.selection_digest,
                    owner_authority_digest=canonical_digest(authority),owner_actor=policy.owner_actor_id,
                    owner_head_digest=policy.owner_head_digest,owner_revision=policy.owner_authorization_revision,
                    principal_epoch=policy.owner_principal_epoch,policy_original_ref=policy.original_ref,
                    policy_original_digest=policy.digest,policy_window_id=policy.window_id,policy_version=policy.policy.version,
                    first_admission_ref=terms['first_admission_ref'],whole_manifest_digest=terms['whole_manifest_digest'],
                    old_cause_ref=terms['old_cause_ref'],old_cause_digest=terms['old_cause_digest'],same_claim_ref=terms['same_claim_ref'],
                    same_goal_ref=terms['same_goal_ref'],segment_count=terms['segment_count'],inputs_json=canonical_serialize(terms),
                    prefix=[contact_continuation_to_wire_v1(f)for f in prefix],current_effect=to_wire(effect),effect_snapshot=to_wire(snapshot),
                    observed_at_utc=float(now),deadline_utc=float(deadline),schema='authority.contact-continuation-observation.v1')
                size=c09_canonical_json_size_v3(material,ascii=True,exact=True)
                if size+256>MAX_OBSERVATION_BYTES:raise AuthorityUnavailable('Contact continuation wire exceeds its original bound')
                work.operation.retain(size*3+8192)
                material['observation_ref']='contact-continuation-observation:'+canonical_digest(material)
                material['signature']=self.policy._sign(material)
                observation=contact_continuation_from_wire_v1(material,ContactContinuationObservationV1)
            self.fences.validate_fence(credential=credential,subject=subject,permit=permit)
            return observation,authority
        finally:finish_authority_graph_read_work_v3(work)
    def _original_write_v1(self,credential,subject,write_permit,selector):
        if (type(write_permit)is not FencePermitV2 or write_permit.operation!='write'
                or (write_permit.subject,write_permit.holder,write_permit.namespace)!=(subject,self.holder,self.namespace)):
            raise AuthorityUnavailable('Existing continuation requires its actual original WRITE permit')
        self.core._require(credential,'current',self.namespace,self.holder)
        expected_id='finish:'+write_permit.operation_id
        expected_digest='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3','operation_id':selector.operation_id,
            'request_digest':selector.request_digest,'permit_token':write_permit.token})
        with self.fences._frozen()as(db,deletion,execution,_):
            anchor=self.fences._current_locked(db,deletion,execution);row=self.fences.fences._row(db,write_permit.operation_id)
            if (row is None or self.fences.fences._permit(row)!=write_permit or row[6]not in{'active','finished'}
                    or row[10]is not None or (anchor.authority_id,anchor.activation_generation)!=(write_permit.authority_id,write_permit.generation)):
                raise AuthorityUnavailable('Existing continuation original WRITE is unavailable or changed')
            if row[6]=='active':self.fences.fences.validate_fence_locked(db,write_permit,subject=subject,current_anchor=anchor)
            elif row[8:10]!=(expected_id,expected_digest):
                raise AuthorityUnavailable('Existing continuation original WRITE has another actual finish ACK')
            return row[6],anchor
    def read_existing_contact_continuation_v1(self,*,credential,subject,original_write_permit,selector):
        from ..runtime.contact_continuation_v1 import begin_contact_continuation_capture_read_v1,read_contact_continuation_capture_original_v1
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        from .owner_location_read_v3 import require_owner_location_observation_current_for_contact_v3
        from .contact_p2_source_binding_v1 import capture_contact_p2_source_binding_v1,require_contact_p2_source_binding_in_tx_v1
        policy=self._policy(credential,subject,selector)
        original=self._original_write_v1(credential,subject,original_write_permit,selector)
        owns_read=original[0]=='finished'
        read_permit=(self.fences.begin_fence(credential=credential,subject=subject,holder=self.holder,operation='read',
            operation_id='contact-continuation-existing-read:'+secrets.token_hex(24),expected_anchor=original[1])
            if owns_read else original_write_permit)
        work=None
        try:
            location=self.reader._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=read_permit)
            work=begin_contact_continuation_capture_read_v1(self.reader,credential=credential,subject=subject,permit=read_permit,
                write_permit=original_write_permit,selector=selector,policy=policy,location=location)
            owner=self.prospective._owner_policy(work)
            def current(db):return read_contact_continuation_capture_original_v1(db,work=work,write_permit=original_write_permit,
                selector=selector,issuer=self.reader._issuer)
            value=read_authority_graph_current_v3(work,current)
            observation=contact_continuation_from_wire_v1(value['observation_wire'],ContactContinuationObservationV1)
            wire=contact_continuation_to_wire_v1(observation);captured=json.loads(observation.inputs_json);fresh=value['inputs']
            root=self.bundle.installation_policy.root_grant
            request,admission=value['request'],value['admission_receipt']
            if (not hmac.compare_digest(observation.signature,self.policy._sign({k:v for k,v in wire.items()if k!='signature'}))
                    or observation.selector!=selector or observation.installation_id!=self.installation_id or observation.subject!=subject
                    or observation.authority_namespace!=self.namespace or observation.attempt_id!=original_write_permit.operation_id
                    or observation.permit_digest!=authority_digest(original_write_permit).removeprefix('sha256:')
                    or (request.operation_id,request.effect_id,request.segment_index,request.segment_count)!=(
                        selector.operation_id,observation.current_effect.effect_id,selector.segment_index,observation.segment_count)
                    or admission.admission.admission_ref!=value['segment_original']['admission_ref']
                    or set(fresh)!=set(captured)or any(fresh[k]!=captured[k]for k in set(fresh)-{'graph_revision','graph_epoch'})
                    or (fresh['root_grant_id'],fresh['root_grant_version'],fresh['root_grant_digest'],fresh['root_lease_ref'])!=(
                        root.grant_id,root.version,canonical_digest(root),root.lease_id)
                    or observation.prefix!=self._prefix(credential,subject,fresh)
                    or (observation.policy_original_ref,observation.policy_original_digest)!=(policy.original_ref,policy.digest)
                    or (observation.owner_head_digest,observation.owner_revision)!=(owner.guard.authorization_head,owner.guard.authorization_revision)
                    or not self.reader._clock()<min(observation.deadline_utc,work.deadline_utc,policy.policy.window_end)):
                raise AuthorityUnavailable('Existing continuation stored WRITE observation or current complete prefix/Owner/Root changed')
            if read_authority_graph_current_v3(work,current)!=value or self.prospective._owner_policy(work)!=owner:
                raise AuthorityUnavailable('Existing continuation actual Source originals or current Owner changed')
            source_binding=capture_contact_p2_source_binding_v1(work,expected_anchor=read_permit.pinned_anchor)
            with self.fences._frozen()as(db,deletion,execution,_):
                anchor=self.fences._current_locked(db,deletion,execution)
                self.fences.fences.validate_fence_locked(db,read_permit,subject=subject,current_anchor=anchor)
                require_owner_location_observation_current_for_contact_v3(self.policy.owner_service,work,owner,db)
                require_contact_p2_source_binding_in_tx_v1(db,source_binding,expected_anchor=read_permit.pinned_anchor,holder=self.holder)
                head=self.policy._current_owner(db,owner,read_permit)
                if self.policy._head(db,selector.policy_id)!=policy or observation.principal_epoch!=self.policy._principal_epoch(db,head):
                    raise AuthorityUnavailable('Existing continuation current policy or original Owner principal changed')
            if self._original_write_v1(credential,subject,original_write_permit,selector)!=original:
                raise AuthorityUnavailable('Existing continuation original WRITE changed during its separate current READ')
            return observation,{**current_owner_authority_to_wire_v1(owner),'permit':to_wire(original_write_permit)}
        finally:
            finish_authority_graph_read_work_v3(work)
            if owns_read:
                self.fences.finish_fence(credential=credential,subject=subject,permit=read_permit,
                    request_id='contact-continuation-existing-finish:'+canonical_digest((read_permit.operation_id,read_permit.token)),
                    request_digest='sha256:'+canonical_digest(('contact-continuation-existing-finish.v1',
                        contact_continuation_to_wire_v1(selector),read_permit.token)))
    def _observed(self,credential,subject,selector,effect_id):
        receipt=self.execution.read_current_observation_receipt_v1(credential=credential,subject=subject,effect_id=effect_id)
        binding=receipt.pending.binding
        updated=replace(receipt.pending.permit,revision=receipt.updated_revision,pinned_anchor=receipt.after_anchor)
        if (binding.origin.proactive_contact is not True or (binding.footprint.contact_id,binding.operation_id,binding.origin.segment_index)!=(
                selector.contact_id,selector.operation_id,selector.segment_index)or binding.origin.effect_id!=effect_id
                or (updated.holder,updated.subject,updated.namespace)!=(self.holder,subject,self.namespace)):
            raise AuthorityUnavailable('Contact continuation projection selected another actual dispatch')
        with self.fences._frozen()as(db,deletion,execution,_):
            anchor=self.fences._current_locked(db,deletion,execution)
            row=self.fences.fences._row(db,updated.operation_id)
            if (row is None or self.fences.fences._permit(row)!=updated or row[6]not in {'active','finished'}
                    or row[10]is not None or (anchor.authority_id,anchor.activation_generation)!=(updated.authority_id,updated.generation)):
                raise AuthorityUnavailable('Contact continuation actual observed fence is unavailable')
            if row[6]=='active':self.fences.fences.validate_fence_locked(db,updated,subject=subject,current_anchor=anchor)
            state=row[6]
        return receipt,updated,state,anchor
    def read_projection(self,*,credential,subject,holder,effect_id,selector):
        from ..runtime.contact_continuation_v1 import begin_contact_continuation_projection_source_read_v1,read_contact_continuation_projection_v1
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
        policy=self._policy(credential,subject,selector)
        if holder!=self.holder:raise AuthorityUnavailable('Contact continuation projection requires its actual installed holder')
        original=self._observed(credential,subject,selector,effect_id);receipt,updated,state,anchor=original
        deadline=datetime.fromisoformat(receipt.pending.binding.utc_deadline.replace('Z','+00:00')).timestamp()
        if not self.reader._clock()<min(deadline,policy.policy.window_end):raise AuthorityUnavailable('Contact continuation original dispatch deadline expired')
        read_permit=self.fences.begin_fence(credential=credential,subject=subject,holder=holder,operation='read',
            operation_id='contact-continuation-projection-read:'+secrets.token_hex(24),expected_anchor=anchor)
        work=None
        try:
            location=self.reader._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=read_permit)
            work=begin_contact_continuation_projection_source_read_v1(self.reader,credential=credential,subject=subject,
                permit=read_permit,observed_receipt=receipt,selector=selector,policy=policy,location=location)
            if work.deadline_utc>deadline:raise AuthorityUnavailable('Contact continuation Source factory extended the original dispatch expiry')
            owner=self.prospective._owner_policy(work)
            value=read_authority_graph_current_v3(work,lambda db:read_contact_continuation_projection_v1(db,
                work=work,selector=selector,effect_id=effect_id,issuer=self.reader._issuer))
            observation=contact_continuation_from_wire_v1(value['observation_wire'],ContactContinuationObservationV1)
            wire=contact_continuation_to_wire_v1(observation)
            if not hmac.compare_digest(observation.signature,self.policy._sign({k:v for k,v in wire.items()if k!='signature'})):
                raise AuthorityUnavailable('Contact continuation stored Core signature differs')
            request,admission=value['request'],value['admission_receipt'];binding=receipt.pending.binding
            captured=json.loads(observation.inputs_json);fresh=value['inputs']
            if (observation.selector!=selector or observation.current_effect.effect_id!=effect_id
                    or observation.installation_id!=self.installation_id or observation.subject!=subject
                    or 'sha256:'+admission.receipt_digest!=binding.admission_receipt_digest
                    or (request.operation_id,request.effect_id,request.payload_digest,request.footprint)!=(
                        binding.operation_id,binding.origin.effect_id,binding.origin.payload_digest.removeprefix('sha256:'),binding.footprint)
                    or set(fresh)!=set(captured)or any(fresh[k]!=captured[k]for k in set(fresh)-{'graph_revision','graph_epoch'})):
                raise AuthorityUnavailable('Contact continuation projection actual saved admission or Source originals differ')
            prefix=self._prefix(credential,subject,fresh)
            if prefix!=observation.prefix:raise AuthorityUnavailable('Contact continuation current entire prefix differs from its original before-WRITE observation')
            context,storage,member=self.accounting.p2._storage_v1()
            self.accounting.p2.source_location._control.verify_member_v1(member,prepared=False);context.require_current('business')
            if receipt.pending.binding.graph_incarnation!=storage['graph_incarnation']:raise AuthorityUnavailable('Contact continuation actual Graph incarnation changed')
            if read_authority_graph_current_v3(work,lambda db:read_contact_continuation_projection_v1(db,
                    work=work,selector=selector,effect_id=effect_id,issuer=self.reader._issuer))!=value:
                raise AuthorityUnavailable('Contact continuation projection actual original metadata changed')
            if self.prospective._owner_policy(work)!=owner or self._observed(credential,subject,selector,effect_id)[:3]!=original[:3]:
                raise AuthorityUnavailable('Contact continuation projection current Owner or observed original changed')
            self.fences.validate_fence(credential=credential,subject=subject,permit=read_permit)
            context.require_current('business')
            return ContactContinuationObservationProjectionReadV1(selector.namespace,self.installation_id,
                storage['graph_path'],storage['graph_device'],storage['graph_file_id'],storage['graph_incarnation'],
                canonical_digest(storage),receipt,updated,state,observation,prefix)
        finally:
            finish_authority_graph_read_work_v3(work)
            self.fences.finish_fence(credential=credential,subject=subject,permit=read_permit,
                request_id='contact-continuation-projection-finish:'+canonical_digest((read_permit.operation_id,read_permit.token)),
                request_digest='sha256:'+canonical_digest(('contact-continuation-projection-read-finish.v1',
                    contact_continuation_to_wire_v1(selector),effect_id,read_permit.token)))
