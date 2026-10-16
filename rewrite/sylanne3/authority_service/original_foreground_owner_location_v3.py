"""Independent current Owner metadata for one actual Original foreground/Owner task WRITE Work."""
from contextlib import contextmanager
from threading import get_ident
from weakref import WeakKeyDictionary, ref
import json
from .contract import AuthorityUnavailable
from .original_foreground_source_read_v3 import original_source_clock_upper_v3,original_owner_header_kind_v3
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from .owner_location_read_v3 import (
    OwnerLocationCallerProofV3, _OWNER_CALLER_ISSUER_V3,
    register_owner_location_retained_state_v3, prepare_owner_location_read_work_v3,
    owner_location_read_quantum_v3, prepare_source_owner_location_lineage_v3,
    prepare_target_owner_location_lineage_v3,
    resolve_source_owner_storage_admission_from_completed_location_v3,
    resolve_target_owner_storage_continuation_from_completed_location_v3,
    _OwnerLocationJSONAllocationScanV3, reserve_owner_location_retained_growth_v3,
    finish_owner_location_retained_growth_v3, _owner_alloc_size_v3,
    _owner_heap_size_v3, _owner_location_payload_heap_v3,
    _require_owner_operation_v3)

_OWNERS = WeakKeyDictionary()

def _require_original_owner_components_v3(owner, work):
    from .original_foreground_source_read_v3 import require_original_foreground_work_v3
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
    saved = require_original_foreground_work_v3(work)
    service = work.service
    identity = service.self_identity
    if (type(owner) not in (InstalledD12OwnerStorageAdmissionServiceV1, InstalledD12TargetOwnerAdmissionServiceV1)
            or identity._owner_storage is not owner or identity._fences is not owner.fences
            or identity._core is not owner.core or identity._source_location is not work.controller.location
            or identity._installation_id != owner.installation_id or identity._holder != owner.holder
            or work.namespace != owner.namespace_id or work.permit.holder != owner.holder
            or work.permit.namespace != owner.namespace or work.subject != work.permit.subject):
        raise AuthorityUnavailable("Original foreground/Owner task Owner crossed the actual original installation")
    control = owner.control if type(owner) is InstalledD12OwnerStorageAdmissionServiceV1 else owner.storage_continuation_reader.control
    path = owner.graph_path if type(owner) is InstalledD12OwnerStorageAdmissionServiceV1 else owner.target_graph
    if (work.controller.control is not control or owner.core._c09_storage_reader_v1 is not control
            or identity._graph._path != path or work.controller.location._graph_db_path != path):
        raise AuthorityUnavailable("Original foreground/Owner task Owner crossed current selected storage")
    _require_owner_operation_v3(work.operation, db=work.db, namespace=work.namespace, control=control)
    return saved, service, identity, work.controller.location, control

class _OriginalOwnerCallV3:
    def __init__(self, issuer, owner_service, work, *, anchor, head, history, actor, login):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable("Original foreground/Owner task Owner requires its private registered caller")
        self.binding, self.service, self.identity, self.location, self.control = _require_original_owner_components_v3(owner_service, work)
        self.work, self.owner_service, self.controller = ref(work), owner_service, work.controller
        self.db, self.operation, self.scope = work.db, work.operation, work.scope
        self.permit, self.credential, self.subject = work.permit, work.credential, work.subject
        self.namespace, self.selection_digest = work.namespace, work.selection_digest
        self.anchor, self.head, self.history, self.actor, self.login = anchor, head, history, actor, login
        self.deadline_utc, self.thread = work.deadline_utc, get_ident()
        self.proof = self.facts = self.lineage = self.grant = self.observed = None
        self.closed = False

    def _actual(self):
        work = self.work()
        if (work is None or self.closed or self.thread != get_ident() or _OWNERS.get(work) is not self
                or self.binding != _require_original_owner_components_v3(self.owner_service, work)[0]
                or self.db is not work.db or self.operation is not work.operation or self.scope is not work.scope
                or self.permit != work.permit or self.credential is not work.credential
                or self.selection_digest != work.selection_digest or work.deadline_utc > self.deadline_utc):
            raise AuthorityUnavailable("Original foreground/Owner task Owner lost the exact original WRITE Work")
        return work

    def _check_permission_v3(self):
        work = self._actual()
        owner = self.owner_service
        if self.db.in_transaction or owner.core._db.in_transaction:
            raise AuthorityUnavailable("Original foreground/Owner task Owner observation must precede Graph and Core SQL")
        work._check_permission_v3()
        owner.core._require(self.credential, "owner_guard_read", owner.namespace, owner.holder)
        with owner.fences._frozen() as (db, deletion, execution, _):
            anchor = owner.fences._current_locked(db, deletion, execution, holder=owner.holder, generation=self.permit.generation)
            self._require_current_core_v3(db, anchor)

    def _require_current_core_v3(self, db, anchor):
        self._actual()
        owner = self.owner_service
        if db is not owner.core._db or not db.in_transaction:
            raise AuthorityUnavailable("Original foreground/Owner task Owner requires its actual current Core transaction")
        owner.fences.fences.validate_fence_locked(db, self.permit, subject=self.subject, current_anchor=anchor)
        head = owner.tickets.current_migration_head_in_tx(db, authority_namespace=owner.namespace)
        if anchor != self.anchor or head != self.head or head is None or head.state != "active":
            raise AuthorityUnavailable("Original foreground/Owner task current Owner or original permission changed")
        if self.history is None:
            if owner._head_in_tx(db) != head or owner._background_identity_in_tx(db, head) != (self.actor, self.login):
                raise AuthorityUnavailable("Original foreground/Owner task current Source Owner pairing changed")
        elif owner._current_transfer(db, generation=anchor.activation_generation) != self.history:
            raise AuthorityUnavailable("Original foreground/Owner task current Target Owner history changed")
        if original_source_clock_upper_v3(self.work()) >= self.work().deadline_utc:
            raise AuthorityUnavailable("Original foreground/Owner task exceeded its original deadline")

    def _c09_retained_heap_bytes_v3(self):
        return (_owner_heap_size_v3(self) + _owner_heap_size_v3(self.__dict__)
            + _owner_location_payload_heap_v3((self.binding, self.anchor, self.head, self.history,
                self.actor, self.login, self.grant, self.observed, self.namespace, self.subject), set()))

    def release_v3(self):
        if self.closed:
            return
        self.closed = True
        work = self.work()
        if work is not None:
            _OWNERS.pop(work, None)
        if self.lineage is not None:
            self.lineage.close_v3()
        elif self.facts is not None:
            self.facts.work.close_v3()
        if self.proof is not None:
            self.proof.release_v3()
        self.binding = self.facts = self.lineage = self.grant = self.observed = None

def require_original_foreground_owner_header_v3(proof, graph_stamp=None):
    call = proof.request
    if (type(call) is not _OriginalOwnerCallV3 or proof.kind != original_owner_header_kind_v3(call._actual())
            or call.proof is not proof or proof.owner_service is not call.owner_service
            or proof.controller is not call.controller or proof.service is not call.service
            or proof.bundle is not call.service.installed_bundle
            or proof.retained_operation is not call.operation or proof.scope is not call.scope
            or proof.original_permit != call.permit or proof.current_owner_head != call.head
            or proof.permission_anchor != call.anchor or proof.graph_comparison_anchor != call.anchor
            or proof.target_history != call.history or proof.control is not call.control
            or proof.selection_digest != call.selection_digest):
        raise AuthorityUnavailable("Original foreground/Owner task Owner proof changed its exact private current caller")
    call._actual()
    if graph_stamp is not None:
        metadata, epoch = graph_stamp
        req, anchor = metadata.requirements, call.anchor
        if (req.namespace != call.namespace or req.authority_namespace != anchor.namespace
                or any(getattr(req, name) != getattr(anchor, name) for name in (
                    "authority_id", "activation_generation", "revocation_epoch", "deletion_journal_id",
                    "deletion_seq", "deletion_digest", "execution_journal_id", "execution_seq", "execution_digest"))):
            raise AuthorityUnavailable("Original foreground/Owner task Owner comparison anchor changed")
    return call

def prepare_original_foreground_owner_v3(owner_service,work):
    """Complete bodyless Owner/Source or Target location EOF in this actual Work."""
    _require_original_owner_components_v3(owner_service,work)
    if work.db.in_transaction or owner_service.core._db.in_transaction:
        raise AuthorityUnavailable('Original foreground/Owner task Owner metadata must be observed outside Graph/Core SQL')
    prior=_OWNERS.get(work)
    if prior is not None:
        prior._check_permission_v3()
        if prior.observed is None:raise AuthorityUnavailable('Original foreground/Owner task Owner original observation did not complete')
        return prior.observed
    work._check_permission_v3()
    owner_service.core._require(work.credential,'owner_guard_read',owner_service.namespace,owner_service.holder)
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    with owner_service.fences._frozen()as(db,deletion,execution,_):
        anchor=owner_service.fences._current_locked(db,deletion,execution,
            holder=owner_service.holder,generation=work.permit.generation)
        owner_service.fences.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
        if anchor!=work.permit.pinned_anchor:
            raise AuthorityUnavailable('Original foreground/Owner task original Owner permission anchor changed')
        head=owner_service.tickets.current_migration_head_in_tx(db,authority_namespace=owner_service.namespace)
        if head is None or head.state!='active':raise AuthorityUnavailable('Original foreground/Owner task actual current Owner head is absent')
        if type(owner_service)is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner_service._head_in_tx(db)!=head:raise AuthorityUnavailable('Original foreground/Owner task Source current Owner changed')
            actor,login=owner_service._background_identity_in_tx(db,head);history=None
        else:
            history=owner_service._current_transfer(db,generation=anchor.activation_generation);actor=login=None
    call=_OriginalOwnerCallV3(_OWNER_CALLER_ISSUER_V3,owner_service,work,
        anchor=anchor,head=head,history=history,actor=actor,login=login)
    _OWNERS[work]=call
    graph_work=None
    try:
        proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,original_owner_header_kind_v3(work),None,work.service,
            owner_service,work.controller,None,work.service.installed_bundle,work.scope,None,head.issue_operation.principal,
            D12CurrentOwnerAuthorityV1(head.guard,None),head,work.operation,call.control,work.selection_digest,
            work.namespace,owner_service.installation_id,owner_service.holder,anchor,anchor,work.credential,
            work.subject,work.permit,call,work.deadline_utc,get_ident(),target_history=history,
            target_role=None if history is None else 'background_existing_header')
        call.proof=proof;register_owner_location_retained_state_v3(proof,call)
        graph_work=prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=graph_work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts=graph_work.result.require_for_v3(proof);call.facts=facts
        lineage=(prepare_source_owner_location_lineage_v3(proof,facts)if history is None
            else prepare_target_owner_location_lineage_v3(proof,facts))
        call.lineage=lineage
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=lineage.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        if history is None:admission=resolve_source_owner_storage_admission_from_completed_location_v3(proof,facts)
        else:admission=resolve_target_owner_storage_continuation_from_completed_location_v3(proof,facts)
        raw=facts.atom[1];scan=_OwnerLocationJSONAllocationScanV3(lineage,(),('original-activity-owner-grant',))
        reserve_owner_location_retained_growth_v3(proof,4*len(raw)+_owner_alloc_size_v3(b''))
        try:scan._feed(raw.encode('utf-8'));scan.complete=True
        finally:finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof,scan.decode_growth_bound_v3())
        try:
            from ..graph_types import validate_owner_grant_v1
            call.grant=json.loads(raw);validate_owner_grant_v1(call.grant)
        finally:finish_owner_location_retained_growth_v3(proof)
        stamp=(facts.graph_epoch.revision,*facts.epochs)
        if work.graph_stamp is None:work.graph_stamp=stamp
        elif work.graph_stamp!=stamp:raise AuthorityUnavailable('Original foreground/Owner task Owner location changed the actual selected Graph epoch')
        call._check_permission_v3()
        with owner_service.fences._frozen()as(db,deletion,execution,_):
            anchor=owner_service.fences._current_locked(db,deletion,execution,
                holder=owner_service.holder,generation=work.permit.generation)
            call._require_current_core_v3(db,anchor)
            reserve_owner_location_retained_growth_v3(proof,65536)
            try:
                if history is None:call.observed=D12CurrentOwnerAuthorityV1(head.guard,None,admission)
                else:
                    target=owner_service._current_background_identity_for_verified_location_in_tx_v1(db,
                        head=head,history=history,metadata=facts.metadata,revision=facts.atom[0],
                        grant_digest=head.grant_digest,imported=lineage.imported,continuation=admission,anchor=anchor)
                    call.observed=D12CurrentOwnerAuthorityV1(target.guard,target.target_admission,admission)
            finally:finish_owner_location_retained_growth_v3(proof)
        call._check_permission_v3()
        return call.observed
    except BaseException as error:
        if call.lineage is not None:call.lineage.cancel_v3(error)
        elif graph_work is not None:graph_work.cancel_v3(error)
        call.release_v3()
        raise


@contextmanager
def bind_original_foreground_owner_v3(work):
    call = _OWNERS.get(work)
    if call is None or call.observed is None:
        raise AuthorityUnavailable("Original foreground/Owner task current Owner EOF has not completed")
    require_original_foreground_owner_header_v3(call.proof)
    call.facts.require_for_v3(call.proof)
    yield call
    require_original_foreground_owner_header_v3(call.proof)
    call.facts.require_for_v3(call.proof)

def release_original_foreground_owner_v3(work):
    call = _OWNERS.get(work)
    if call is not None:
        call.release_v3()
