"""Installed Contact sender reads and the closed current-P2 entry.

The original final write reader stays strict. Its qualifications cannot be
relabelled as a dispatch-fence qualification; the independent private P2 reader and issuer below requalify actual current
SQL rows and the Core policy capsule before the atomic final claim.
"""
from dataclasses import dataclass, replace
import json
import weakref

from ..graph_store import ProductionGraphStore
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_serialize

_INSTALLED = weakref.WeakValueDictionary()
_PREPARED = {}
from .dispatch_admission import load_request
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


@dataclass(frozen=True, slots=True, weakref_slot=True)
class InstalledContactFinalClaimWriterV3:
    graph: object
    port: object
    clock_policy: object
    route_port: object
    issuer_id: str

    def __call__(self, *args, **kwargs):
        raise ValueError('Contact final claim requires the prepared writer issued after its actual claimed receipt')

    def require_current_entry(self, graph, authority, lease, original):
        from ..host.contact_dispatch_driver_v3 import OriginalContactDispatchV3
        from .contact_dispatch_host_read_v1 import prepare_contact_dispatch_text_work_v1
        if (_INSTALLED.get(id(self))is not self or self.graph is not graph
                or type(original)is not OriginalContactDispatchV3 or original.namespace!=authority.namespace):
            raise ValueError('Contact preflight requires its actual installed original and current Source/Owner Work')
        return prepare_contact_dispatch_text_work_v1(self,graph,authority,lease,original.request,original=original)

    def recover_observation_metadata(self, graph, operation_id):
        from ..graph_coordinator import namespace_ref
        if _INSTALLED.get(id(self)) is not self or graph is not self.graph:
            raise ValueError('Contact observation recovery crossed its installed private writer')
        ns=self.route_port._namespace;store=graph._GraphCoordinator__store
        with store._lock:
            rows=store._db.execute("SELECT a.effect_id FROM graph_dispatch_admissions a "
                "JOIN graph_domain_production_originals_v1 d ON (a.bot,a.persona,a.operation_id)=(d.bot,d.persona,d.operation_id) "
                "WHERE a.bot=? AND a.persona=? AND a.operation_id=? AND d.operation_kind='prepare_contact_dispatch_v3' LIMIT 2",
                (*ns.as_tuple,operation_id)).fetchall()
        if not rows:return None
        if len(rows)!=1:
            raise ValueError('Contact observation actual original locator is not unique')
        effect=self.port.read_current_effect(namespace=ns,authority_namespace=namespace_ref(ns),effect_id=rows[0][0])
        if effect.state=='observed':
            return graph._consume_current_contact_observation_v1(self,operation_id=operation_id,effect_id=rows[0][0])
        return None

    def consume_observation(self, graph, original):
        return graph._consume_current_contact_observation_v1(self,operation_id=original.operation_id,
            effect_id=original.request.effect_id)

    def prepare_contact_for_handoff(self, graph, claimed, handoff_id, original, *, prepared_inventory=None):
        from ..authority_service.v2_contract import MutationReceiptV2
        from ..host.v2_fence_port import VerifiedIngressClockV2
        from .first_ingress_v2 import trusted_upper
        if (_INSTALLED.get(id(self)) is not self or graph is not self.graph
                or type(claimed) is not MutationReceiptV2 or claimed.durable_state!='committed'
                or claimed.pending.phase!='claimed' or claimed.pending.binding.origin.proactive_contact is not True
                or claimed.pending.binding.operation_id!=original.operation_id
                or claimed.pending.binding.origin.admission_ref!=original.admission.admission.admission_ref
                or claimed.pending.binding.origin.footprint!=original.request.footprint):
            raise ValueError('Contact prepared writer needs its actual installed claimed original')
        clock=self.port.read_ingress_clock(self.clock_policy)
        if type(clock) is not VerifiedIngressClockV2:
            raise ValueError('Contact prepared writer actual installed clock is unavailable')
        original.admission.admission.require_current(trusted_upper(clock))
        grant=self.port.installation_grant
        if (grant.installation_id!=clock.sample.installation_id or grant.authority_id!=claimed.pending.permit.authority_id
                or clock.sample.source_id!=self.clock_policy.source_id):
            raise ValueError('Contact prepared writer installation/current clock differs')
        value=_PreparedContactP2WriterV1(self,claimed,handoff_id,original,clock,grant.installation_id,prepared_inventory)
        _PREPARED[id(value)]=value
        return value


def register_contact_dispatch_final_claim_writer_v3(graph, bootstrap, *, route_port=None, issuer_id=None):
    from ..host.authority_profile import AdminIngressClockPolicy
    from ..host.installed_dispatch_route import InstalledDispatchRoutePort
    graph._admin(bootstrap)
    port = graph._GraphCoordinator__content_fence_v2
    clock_policy = graph._GraphCoordinator__dispatch_clock_policy
    if (not isinstance(graph._GraphCoordinator__store, ProductionGraphStore)
            or port is None or type(clock_policy) is not AdminIngressClockPolicy
            or type(route_port) is not InstalledDispatchRoutePort
            or route_port._coordinator is not graph
            or type(issuer_id) is not str or not issuer_id
            or not callable(getattr(port, "read_ingress_clock", None))):
        raise RuntimeError("installed Contact final claim dependencies unavailable; HOLD")
    value = InstalledContactFinalClaimWriterV3(graph, port, clock_policy, route_port, issuer_id)
    _INSTALLED[id(value)] = value
    return value


def _identity_locked(graph, namespace, operation_id):
    from ..host.contact_dispatch_driver_v3 import OriginalContactDispatchV3
    db = graph._GraphCoordinator__store._db
    original = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if original is None or original['operation_kind'] != 'prepare_contact_dispatch_v3':
        raise ValueError("actual Contact3 adopted original is absent")
    row = db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*namespace.as_tuple, operation_id)).fetchone()
    if row is None or not row[0]:
        raise ValueError("actual Contact3 Owner receipt is absent")
    result = json.loads(row[0])
    if (canonical_serialize(result) != row[0]
            or result.get('operation_id') != operation_id
            or result.get('original_digest') != original['original_digest']
            or result.get('coverage') != 'complete'):
        raise ValueError("actual Contact3 saved result differs")
    proof = original['payload']['provenance']
    issued = load_request(db, namespace, proof['admission_ref'])
    if issued is None:
        raise ValueError("actual Contact3 dispatch command is absent")
    receipt, request = issued
    if request.segment_index>0:
        from .contact_continuation_p2_v1 import read_contact_continuation_host_identity_v1
        return read_contact_continuation_host_identity_v1(graph,namespace,operation_id,original,result,issued)
    operation = original['receipt']
    if (operation.outbox_refs != (proof['outbox_ref'],)
            or receipt.receipt_digest != proof['admission_receipt_digest']
            or len(operation.write_versions) != 11
            or {(row['ref'], row['revision']) for row in proof['write_commitments']}
               != {(v.key.token, v.revision) for v in operation.write_versions}):
        raise ValueError("actual Contact3 original eleven-member receipt differs")
    # Identity-only recovery can survive an added dispatch claim. It never
    # releases text or authorizes a send. Every original member still has its
    # exact producing history; current content permission is checked separately.
    for member in proof['write_commitments']:
        history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
            (member['ref'], member['revision'])).fetchone()
        if history is None or history[0] != operation_id or history[2] != 1:
            raise ValueError("actual Contact3 producing member history is absent")
    batch = tuple(v.key.token for v in operation.write_versions if v.key.type_name == 'd09.contact_verified_batch.v3')
    if len(batch) != 1:
        raise ValueError("actual Contact3 whole batch identity is absent")
    return OriginalContactDispatchV3(namespace, operation_id, proof['outbox_ref'],
        batch[0], request, receipt, operation), result


def read_committed_contact_dispatch_v3(graph, authority, lease, operation_id):
    from .contact_dispatch_host_read_v1 import prepare_contact_dispatch_identity_work_v3
    return prepare_contact_dispatch_identity_work_v3(graph,authority,lease,operation_id)


def get_contact_dispatch_text_segment_v3(graph, authority, lease, request):
    from .contact_dispatch_host_read_v1 import prepare_contact_dispatch_text_work_v1
    installed=tuple(value for value in _INSTALLED.values()if value.graph is graph and value.route_port._namespace==authority.namespace)
    if len(installed)!=1:raise ValueError('Contact text requires its single actual installed private dispatch producer')
    return prepare_contact_dispatch_text_work_v1(installed[0],graph,authority,lease,request)


@dataclass(frozen=True, slots=True)
class _PreparedContactP2WriterV1:
    installed: InstalledContactFinalClaimWriterV3
    claimed: object
    handoff_id: str
    original: object
    frozen_clock: object
    installation_id: str
    prepared_inventory: object = None

    def __call__(self, graph, context, binding, claimed, witness, authority_snapshot, contact_policy_witness):
        require_prepared_contact_p2_writer_v1(self)
        if (graph is not self.installed.graph or claimed != self.claimed
                or context.handoff_id != self.handoff_id or binding.operation_id != self.original.operation_id
                or binding.origin.admission_ref != self.original.admission.admission.admission_ref):
            raise ValueError('Contact prepared writer lost its actual claimed handoff identity')
        from .dispatch_current_inventory_v3 import bind_prepared_dispatch_inventory_v3
        with bind_prepared_dispatch_inventory_v3(self.prepared_inventory,graph._GraphCoordinator__store._db):
            return commit_contact_dispatch_final_claim_v3(graph,context,binding,claimed,witness,
                authority_snapshot,contact_policy_witness,prepared=self)

    def recheck(self, graph, context, binding, claimed, witness, authority_snapshot, contact_policy_witness, receipt):
        require_prepared_contact_p2_writer_v1(self)
        from .dispatch_current_inventory_v3 import bind_prepared_dispatch_inventory_v3
        with bind_prepared_dispatch_inventory_v3(self.prepared_inventory,graph._GraphCoordinator__store._db):
            return commit_contact_dispatch_final_claim_v3(graph,context,binding,claimed,witness,
                authority_snapshot,contact_policy_witness,prepared=self,expected_receipt=receipt)

    def close(self):
        _PREPARED.pop(id(self),None)


def require_prepared_contact_p2_writer_v1(value):
    if (type(value) is not _PreparedContactP2WriterV1 or _PREPARED.get(id(value)) is not value
            or _INSTALLED.get(id(value.installed)) is not value.installed):
        raise ValueError('Contact P2 requires its registry-sealed installed prepared writer')
    return value


def commit_contact_dispatch_final_claim_v3(graph, context, binding, claimed, witness,
        authority_snapshot, contact_policy_witness, *, prepared, expected_receipt=None):
    from ..authority_service.contact_continuation_p2_contract_v1 import ContactContinuationP2PolicyCapsuleV1
    if type(contact_policy_witness)is ContactContinuationP2PolicyCapsuleV1:
        from .contact_continuation_p2_v1 import commit_contact_continuation_dispatch_final_claim_v1
        return commit_contact_continuation_dispatch_final_claim_v1(graph,context,binding,claimed,witness,authority_snapshot,
            contact_policy_witness,prepared=prepared,expected_receipt=expected_receipt)
    from dataclasses import asdict
    from ..authority_service.contact_p2_contract_v1 import require_exact_contact_p2_policy_capsule_v1
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity, require_exact_authority_snapshot
    from ..authority_service.v2_contract import DispatchGraphClaimReceiptV1, canonical_digest as authority_digest
    from ..host.installed_dispatch_route import InstalledDispatchRouteReadV1
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from ..runtime_contracts import FenceScope, NamespaceId, canonical_digest
    from .contact_p2_birth_v1 import read_contact_p2_birth_v1
    from .contact_p2_current_read_v1 import current_contact_p2_read_v1
    from .contact_p2_qualification_v1 import (
        ContactP2GraphProofV1,contact_p2_graph_proof_key_v1,contact_p2_graph_proof_from_wire_v1,
        issue_current_contact_p2_qualification_v1,verify_current_contact_p2_sql_v1,
        retire_current_contact_p2_qualification_v1,
    )
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
            birth=read_contact_p2_birth_v1(db,namespace=namespace,operation_id=binding.operation_id)
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
