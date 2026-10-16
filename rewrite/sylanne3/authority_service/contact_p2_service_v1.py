"""Installed Core current Contact policy for the named P2 reverse branch.

Graph selection happens outside the Core freeze. The sealed selector is consumed
only by this service in the actual frozen Core transaction; it carries no body,
send permission, caller policy or mutable cache of policy state.
"""
from pathlib import Path

from .contract import AuthorityUnavailable
from .contact_p2_contract_v1 import ContactP2PolicyCapsuleV1
from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
from .v2_contract import (
    AuthorityDispatchSnapshotV1, DispatchHandoffContextV1, ExecutionBindingV2,
    OwnerDispatchWitnessV1, canonical_digest as authority_digest,
)
from ..runtime_contracts import canonical_digest


class InstalledContactP2ServiceV1:
    def __init__(self, *, policy_service, source_location, issuer, execution):
        if (type(policy_service) is not InstalledD10ContactPolicyServiceV1
                or type(source_location) is not InstalledCurrentSourceLocationQualifierV1
                or policy_service.core is not source_location.core
                or policy_service.fences is not source_location._fences
                or policy_service.namespace != source_location.namespace_id
                or policy_service.installation_id != source_location.installation_id
                or getattr(policy_service.core,'_c09_storage_reader_v1',None) is not source_location._control):
            raise AuthorityUnavailable('Contact P2 requires its actual paired Core, D10 and C09 Source location')
        from ..runtime.issuers import D11BudgetJobIssuer
        if type(issuer) is not D11BudgetJobIssuer:
            raise AuthorityUnavailable('Contact P2 actual signed D11 original reader is absent')
        from .v2_execution_bridge import AuthorityV2ExecutionBridge
        if (type(execution) is not AuthorityV2ExecutionBridge or execution.core is not policy_service.core
                or execution.fences is not policy_service.fences.fences
                or execution.namespace!=policy_service.fences.namespace):
            raise AuthorityUnavailable('Contact observation needs its actual same-Core execution originals')
        self.policy, self.source_location, self.issuer, self.execution = policy_service, source_location, issuer, execution
        self.continuation = None
        self.first_source = None

    def install_contact_continuation_p2_service_v1(self, service):
        from .contact_continuation_p2_service_v1 import InstalledContactContinuationP2ServiceV1
        if type(service)is not InstalledContactContinuationP2ServiceV1 or service.first is not self or self.continuation is not None:
            raise AuthorityUnavailable('Contact continuation P2 requires its one actual installed sibling')
        self.continuation=service

    def install_contact_first_p2_source_service_v1(self, service):
        from .contact_first_p2_source_v1 import InstalledContactFirstP2SourceServiceV1
        if type(service)is not InstalledContactFirstP2SourceServiceV1 or service.first is not self or self.first_source is not None:
            raise AuthorityUnavailable('First Contact P2 Source requires its exact one installed producer')
        self.first_source=service

    def _storage_v1(self):
        source=self.source_location;control=source._control
        context=control.read_verified_current_storage_v1();context.require_current('business')
        members={v['role']:v for v in context.manifest['members']}
        graph=members['graph']
        if (Path(graph['resolved_path'])!=source._graph_db_path
                or Path(members['core']['resolved_path'])!=self.policy.core.path.resolve(strict=True)):
            raise AuthorityUnavailable('Contact P2 actual selected Core/Source Graph differs')
        storage={'pointer_version':context.pointer_version,'manifest_digest':context.manifest_digest,
            'storage_generation':context.storage_generation,'graph_path':graph['resolved_path'],
            'core_path':members['core']['resolved_path'],'graph_device':graph['device'],
            'graph_file_id':graph['file_id'],'graph_incarnation':graph['incarnation_or_journal_id']}
        return context,storage,graph

    def _require_storage_pointer_in_tx_v1(self, db, context):
        control=self.source_location._control
        if (db is not self.policy.core._db or not db.in_transaction or context._reader is not control
                or context._capability is not control._capability
                or self.policy.core._c09_storage_reader_v1 is not control):
            raise AuthorityUnavailable('Contact P2 current pointer requires its actual same-Core C09 context')
        with control._db() as observed:
            pointer=control._current(observed)
            if (pointer['pointer_version'],pointer['current_manifest_digest'],pointer['stage'])!=(
                    context.pointer_version,context.manifest_digest,context.stage):
                raise AuthorityUnavailable('Contact P2 current selected storage pointer changed')

    def read_current_first_contact_p2_selector_v1(self, *, credential, subject, context, binding, claimed_receipt,
            claim_receipt=None, expected_capsule=None):
        if self.first_source is None:
            raise AuthorityUnavailable('installed named first Contact P2 Source service is absent')
        return self.first_source.read_current_first_contact_p2_selector_v1(credential=credential,subject=subject,
            context=context,binding=binding,claimed_receipt=claimed_receipt,
            claim_receipt=claim_receipt,expected_capsule=expected_capsule)

    def read_current_contact_policy_for_dispatch_in_tx_v1(self, db, *, context, binding,
            claimed_receipt, owner_witness, authority_snapshot, selector):
        if (db is not self.policy.core._db or not db.in_transaction
                or type(context) is not DispatchHandoffContextV1 or type(binding) is not ExecutionBindingV2
                or type(owner_witness) is not OwnerDispatchWitnessV1
                or type(authority_snapshot) is not AuthorityDispatchSnapshotV1
                or selector.binding_digest != authority_digest(binding)
                or context.binding_digest != authority_digest(binding)
                or context.claimed_receipt_digest != authority_digest(claimed_receipt)
                or authority_snapshot.context_digest != authority_digest(context)
                or authority_snapshot.owner_witness_digest != authority_digest(owner_witness)
                or authority_snapshot.anchor != context.permit.pinned_anchor
                or binding.origin.proactive_contact is not True):
            raise AuthorityUnavailable('Contact P2 capsule lost its actual frozen reverse identity')
        from .contact_first_p2_source_v1 import require_first_contact_p2_source_selector_in_tx_v1
        require_first_contact_p2_source_selector_in_tx_v1(self,db,selector,context=context,binding=binding,claimed_receipt=claimed_receipt)
        current = self.policy.tickets.current_dispatch_witness_in_tx(db, context=context,
            binding=binding, installation_id=self.policy.installation_id)
        if current != owner_witness:
            raise AuthorityUnavailable('Contact P2 current Owner witness changed')
        head = self.policy.tickets.current_migration_head_in_tx(db,
            authority_namespace=self.policy.fences.namespace)
        if (head is None or head.state != 'active' or head.guard != current.guard
                or head.issue_operation.operation_id != current.issue_operation_id):
            raise AuthorityUnavailable('Contact P2 current Owner policy origin changed')
        original = self.policy._head(db,selector.policy_id)
        now = self.policy._clock()
        if selector.proof_valid_until_utc is not None and now>=selector.proof_valid_until_utc:
            raise AuthorityUnavailable('Contact P2 original claim provider deadline expired during recovery')
        if (original is None or original.action != 'issue'
                or original.original_ref != selector.policy_original_ref
                or original.digest != selector.policy_original_digest
                or original.authority_id != context.permit.authority_id
                or original.owner_head_digest != head.guard.authorization_head
                or original.owner_authorization_revision != head.guard.authorization_revision
                or original.owner_principal_epoch != self.policy._principal_epoch(db,head)
                or not original.policy.window_start <= now < original.policy.window_end):
            raise AuthorityUnavailable('Contact P2 current signed policy, principal or window changed')
        return ContactP2PolicyCapsuleV1(self.policy.installation_id,self.policy.namespace,
            binding.graph_incarnation,selector.storage_commitment,selector.admission_ref,
            selector.batch_ref,selector.plan_ref,authority_digest(context),authority_digest(binding),
            authority_digest(claimed_receipt),authority_digest(owner_witness),
            authority_digest(authority_snapshot),original,now)

    def require_same_contact_policy_after_claim_in_tx_v1(self, db, *, capsule, **current):
        observed = self.read_current_contact_policy_for_dispatch_in_tx_v1(db,**current)
        # A new observation time is expected. Every permission and identity
        # field must retain the exact pre-reverse capsule commitment.
        from dataclasses import replace
        if replace(observed,observed_at_utc=capsule.observed_at_utc) != capsule:
            raise AuthorityUnavailable('Contact P2 permission changed during the Graph claim')
        return capsule


    def read_current_contact_observation_for_projection_v1(self, *, credential, subject, holder, effect_id):
        from dataclasses import replace
        from .mtls_server import MtlsPeerCredential
        from .contact_p2_contract_v1 import ContactObservationProjectionReadV1
        if type(credential) is not MtlsPeerCredential or subject!='mtls:sha256:'+credential.certificate_sha256:
            raise AuthorityUnavailable('Contact observation requires its actual paired Host subject')
        self.policy.core._require(credential,'current',self.policy.fences.namespace,holder)
        context,storage,member=self._storage_v1()
        receipt=self.execution.read_current_observation_receipt_v1(credential=credential,subject=subject,effect_id=effect_id)
        updated=replace(receipt.pending.permit,revision=receipt.updated_revision,pinned_anchor=receipt.after_anchor)
        if (updated.holder!=holder or updated.subject!=subject or updated.effect_id!=effect_id
                or updated.namespace!=self.policy.fences.namespace
                or receipt.pending.binding.graph_incarnation!=storage['graph_incarnation']):
            raise AuthorityUnavailable('Contact observation actual original crossed its installed effect/storage')
        self.source_location._control.verify_member_v1(member,prepared=False);context.require_current('business')
        with self.policy.fences._frozen() as (db,deletion,execution,_):
            self._require_storage_pointer_in_tx_v1(db,context)
            anchor=self.policy.fences._current_locked(db,deletion,execution)
            row=self.policy.fences.fences._row(db,updated.operation_id)
            if (row is None or self.policy.fences.fences._permit(row)!=updated or row[6] not in {'active','finished'}
                    or row[10] is not None or anchor.authority_id!=updated.authority_id
                    or anchor.activation_generation!=updated.generation):
                raise AuthorityUnavailable('Contact observation current exact observed permit differs')
            if row[6]=='active':
                if anchor!=updated.pinned_anchor:
                    raise AuthorityUnavailable('Contact active observation original anchor changed')
                self.policy.fences.fences.validate_fence_locked(db,updated,subject=subject,current_anchor=anchor)
            state=row[6]
        return ContactObservationProjectionReadV1(self.policy.namespace,self.policy.installation_id,
            storage['graph_path'],storage['graph_device'],storage['graph_file_id'],storage['graph_incarnation'],
            canonical_digest(storage),receipt,updated,state)
