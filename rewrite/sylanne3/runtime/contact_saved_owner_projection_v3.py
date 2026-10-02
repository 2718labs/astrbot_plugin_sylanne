"""Installed V3 saved-COMMIT Owner observation under the original permit.

The original FenceScope is never rewritten. Its pre-COMMIT Graph stamp and
the independently authenticated post-COMMIT SQL stamp have distinct roles.
This reader creates no lease, permission, business result, charge or write.
"""
from dataclasses import asdict, fields
import json

from ..contracts import canonical_json
from ..runtime_contracts import canonical_serialize


class _ContactSavedFinishedV3(Exception):
    """Actual same permit raced to finished; only the authenticated reader may return."""


def _owner_binding_wire_v3(binding):
    """Compare every concrete lease field without extending generic JSON."""
    from ..graph_coordinator import OwnerLeaseBindingV1
    if type(binding) is not OwnerLeaseBindingV1:
        raise TypeError('Contact saved Owner binding must be its exact installed type')
    result={field.name:getattr(binding,field.name) for field in fields(binding)}
    for name in ('capabilities','purposes','audiences'):
        values=result[name]
        if type(values) is not frozenset or any(type(value) is not str for value in values):
            raise TypeError('Contact saved Owner binding has invalid finite grant sets')
        result[name]=tuple(sorted(values))
    return canonical_serialize(result)


def _require_call(call, scope, result, owner, session):
    from .contact_final_ack_v1 import require_contact_owner_call_v1, _SAVED
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from ..graph_coordinator import OwnerLeaseBindingV1
    require_contact_owner_call_v1(call)
    graph=call.runtime.graph
    if (type(call.request) is not PrepareCurrentContactDispatchRequestV3
            or type(owner) is not OwnerLeaseBindingV1
            or result.get('operation_kind') != 'prepare_contact_dispatch_v3'
            or result.get('operation_id') != call.operation_id
            or scope.namespace != call.authority.namespace
            or scope.generation != call.authority.activation_generation
            or scope.operation != 'write' or scope.permit.operation != 'write'
            or scope.operation_id != scope.permit.operation_id
            or scope.pinned_anchor != scope.permit.pinned_anchor
            or graph._GraphCoordinator__owner_leases.get(call.lease) is not owner
            or graph._GraphCoordinator__owner_session_proofs.get(call.lease) != session
            or session is None or session[1].principal != owner.principal):
        raise ValueError('Contact V3 saved Owner invocation/lease/session identity differs')
    saved=_SAVED.get(id(call))
    if (saved is None or saved[0] is not call or saved[1] is not scope
            or saved[2] != canonical_serialize(result)):
        raise ValueError('Contact V3 saved Owner observation has no actual durable issuance')
    from .contact_owner_invocation_v3 import require_saved_contact_owner_session_binding_v3
    require_saved_contact_owner_session_binding_v3(call,scope,result,owner,session)
    return graph


def _require_active(graph, scope):
    actual,state=graph._GraphCoordinator__content_fence_v2.get_fence_operation(
        namespace=scope.namespace,authority_namespace=scope.authority_namespace,
        operation_id=scope.operation_id)
    if actual==scope.permit and state=='finished':
        raise _ContactSavedFinishedV3()
    if actual != scope.permit or state != 'active':
        raise ValueError('Contact V3 saved Owner original permit is not authenticated active; HOLD')


def _require_live(evidence, now, content, parent, quote):
    # Values come exclusively from authenticated durable SQL originals and
    # the actual paired Authority clock, never a caller deadline or flag.
    limits=(evidence.deadline_utc,content.valid_until,parent.valid_until_utc,
        quote.valid_until_utc,quote.deadline_utc,
        *(check.valid_until for check in evidence.qualification.checks))
    if not now < min(limits):
        raise ValueError('Contact V3 saved Owner original qualification/deadline expired; HOLD')


def _live_terms(db, call):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .jobs import get_job
    from ..graph_types import AtomKey
    issuer=call.runtime.graph._GraphCoordinator__d11_issuer
    original=read_adopted_domain_operation_v1(db,call.authority.namespace,call.operation_id)
    job=get_job(db,AtomKey.from_token(original['payload']['provenance']['job_ref']).name)
    quote_id,version=job.operator_versions['resource_quote'].rsplit(':',1)
    quote=issuer._d02._load_quote(db,quote_id,int(version))
    parent=issuer.current_budget_grant(db,original['payload']['parent_budget'])
    content=read_contact_reviewed_content_original_v2(db,namespace=call.authority.namespace,
        contact_id=call.request.contact_id,issuer=issuer,resource_issuer=issuer._d02)
    return content,parent,quote


def require_current_contact_finish_deadline_v3(call, scope, result):
    """The exact installed pre-finish verifier checks real current UTC again."""
    from .contact_final_ack_v1 import require_contact_owner_call_v1, _readonly
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .first_ingress_v2 import trusted_upper
    require_contact_owner_call_v1(call)
    runtime=call.runtime;graph=runtime.graph
    if (type(call.request) is not PrepareCurrentContactDispatchRequestV3
            or runtime._active_contact_final_scope_v1 is not scope
            or runtime._active_contact_final_command_v1 != (call.request,call.operation_id)):
        raise ValueError('Contact V3 finish clock requires its actual active installed scope')
    require_saved_finished_contact_deadline_v3(call,scope,result)


def require_saved_finished_contact_deadline_v3(call,scope,result):
    """Finite actual-clock SQL checks; this does not authenticate a finish ACK."""
    from .contact_final_ack_v1 import require_contact_owner_call_v1, _readonly
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .first_ingress_v2 import trusted_upper
    require_contact_owner_call_v1(call)
    if type(call.request) is not PrepareCurrentContactDispatchRequestV3 or scope.namespace!=call.authority.namespace:
        raise ValueError('Contact V3 original deadline scope differs')
    graph=call.runtime.graph
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    store=graph._GraphCoordinator__store
    with store._lock:
        evidence=_readonly(call,result)
        store._db.execute('BEGIN')
        try:
            _require_live(evidence,trusted_upper(clock),*_live_terms(store._db,call))
        finally:store._db.rollback()


def _sql_snapshot(call, scope, result, owner, session, *, now, guard=None,
        target_admission=None, storage_admission=None):
    graph=_require_call(call,scope,result,owner,session)
    store=graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:
            raise ValueError('Contact V3 saved Owner observation requires completed COMMIT')
        db=store._db;db.execute('BEGIN')
        try:
            # The full current qualification and Owner/pre-post proof belong
            # to this one pinned SQL transaction, not consecutive snapshots.
            from .contact_final_stage_v3 import verify_contact_final_committed_v3
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3
            verify_contact_final_committed_v3(db,namespace=scope.namespace,result=result,
                issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
            proof=read_adopted_domain_operation_v1(db,scope.namespace,call.operation_id)['payload']['provenance']
            evidence=decode_contact_qualification_evidence_v3(proof['qualification_evidence'],
                expected_digest=proof['qualification_digest'])
            from ..authority_service.v2_contract import to_wire
            from ..runtime_contracts import canonical_digest
            attempt=db.execute('SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json,receipt_json '
                'FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
                (*scope.namespace.as_tuple,call.operation_id)).fetchone()
            if attempt != (call.request_digest,scope.operation_id,canonical_json(asdict(scope.pinned_anchor)),
                    scope.graph_revision,scope.graph_epoch.revision,canonical_json(to_wire(scope.permit)),canonical_serialize(result)):
                raise ValueError('Contact V3 saved Owner original pre-COMMIT attempt differs')
            fence=db.execute('SELECT permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest '
                'FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?',
                (*scope.namespace.as_tuple,call.operation_id)).fetchone()
            finish='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3',
                'operation_id':call.operation_id,'request_digest':call.request_digest,'permit_token':scope.permit.token})
            metadata,epoch=graph._v2_graph_stamp(scope.namespace)
            if (fence is None or fence[:3] != (attempt[5],scope.graph_revision,scope.graph_epoch.revision)
                    or fence[3:5] != (scope.graph_revision+1,scope.graph_epoch.revision+1)
                    or fence[5:] != ('finish:'+scope.operation_id,finish)
                    or (metadata.graph_revision,epoch.revision) != fence[3:5]
                    or evidence.graph_epoch != epoch.revision
                    or evidence.namespace != scope.namespace or evidence.activation_generation != scope.generation
                    or metadata.requirements.activation_generation != scope.generation
                    or metadata.requirements.graph_incarnation != owner.graph_incarnation
                    or not graph._anchor_matches(metadata.requirements,scope.pinned_anchor)):
                raise ValueError('Contact V3 saved Owner authenticated pre/post stamp/root differs')
            _require_live(evidence,now,*_live_terms(db,call))
            if guard is None:
                # These are the original authenticated lease's concrete
                # admissions. They supply pre-RPC SQL consistency only.
                target_admission=owner.target_admission;storage_admission=owner.storage_admission
                admission=target_admission if target_admission is not None else storage_admission
                pre_guard=None if admission is None else admission.source_owner_guard
            else:pre_guard=guard
            current=graph._owner_graph_binding_locked(call.authority,owner.principal,
                target_admission=target_admission,storage_admission=storage_admission,current_guard=pre_guard)
            if _owner_binding_wire_v3(current) != _owner_binding_wire_v3(owner):
                raise ValueError('Contact V3 saved Owner lease/grant/revoke/admission changed')
            return evidence,metadata,epoch,current
        finally:
            db.rollback()


def _read_saved_contact_owner_projection_v3(call, scope, result, owner, session):
    """Two complete SQL observations bracket the actual same-permit Owner RPC."""
    from .contact_final_ack_v1 import _issue_saved_contact_recovery_v1, require_contact_owner_call_v1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    from .first_ingress_v2 import trusted_upper
    require_contact_owner_call_v1(call)
    if type(call.request) is not PrepareCurrentContactDispatchRequestV3:
        raise ValueError('Contact saved post-COMMIT Owner projection is V3-only')
    _issue_saved_contact_recovery_v1(call,scope,result)
    graph=_require_call(call,scope,result,owner,session)
    port=graph._GraphCoordinator__content_fence_v2
    _require_active(graph,scope)
    paired=graph._current_owner_principal(call.authority.actor,scope.namespace)
    if paired != owner.principal:
        raise ValueError('Contact V3 saved Owner pairing changed')
    before_clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    before=_sql_snapshot(call,scope,result,owner,session,now=trusted_upper(before_clock))
    # No Graph SQL lock or transaction is held across the Authority transport.
    guarded=port.get_current_owner_authority_for_fence_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=call.authority.actor,owner_session_token=session[0],owner_session_request=session[1])
    target=storage=None
    if type(guarded) is tuple and len(guarded)==2 and type(guarded[0]) is D12CurrentOwnerAuthorityV1:
        target=guarded[0].target_admission;storage=guarded[0].storage_admission
        guarded=(guarded[0].guard,guarded[1])
    if (type(guarded) is not tuple or len(guarded)!=2
            or type(guarded[0]) is not OwnerAuthorizationGuardV1 or guarded[1] != scope.permit):
        raise ValueError('Contact V3 saved Owner authenticated guard/permit unavailable')
    guard=guarded[0]
    _require_active(graph,scope)
    after_clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    if graph._current_owner_principal(call.authority.actor,scope.namespace) != paired:
        raise ValueError('Contact V3 saved Owner pairing drifted across RPC')
    after=_sql_snapshot(call,scope,result,owner,session,now=trusted_upper(after_clock),
        guard=guard,target_admission=target,storage_admission=storage)
    if canonical_serialize(after[:3]) != canonical_serialize(before[:3]):
        raise ValueError('Contact V3 saved Owner SQL/qualification drifted across RPC')
    current=after[3]
    if (guard.authority_id != scope.pinned_anchor.authority_id
            or (target is None and guard.installation_id != port.installation_grant.installation_id)
            or guard.namespace != scope.namespace
            or guard.authorization_revision != current.authorization_revision
            or guard.authorization_head != current.authorization_head
            or guard.minimum_revocation_revision != 0
            or guard.minimum_revocation_epoch != current.revocation_epoch
            or guard.pending_revoke_operation_id is not None):
        raise ValueError('Contact V3 saved Owner current authorization/revocation differs')
    return guard,current
