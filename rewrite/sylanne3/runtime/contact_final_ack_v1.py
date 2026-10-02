"""Installed-only Contact COMMIT readback and exact Authority finish recovery.

There is no caller callback or phase flag. A concrete runtime invocation is
registered for its exact request, Authority object, Owner lease and digest.
Business results are returned only after the actual original fence is finished.
"""
from dataclasses import dataclass
import json

from ..runtime_contracts import canonical_serialize

_CALLS = {}
_SAVED = {}


@dataclass(frozen=True, slots=True)
class _ContactOwnerCallV1:
    runtime: object
    authority: object
    lease: str
    request: object
    operation_id: str
    request_digest: str


def issue_contact_owner_call_v1(runtime, *, authority, lease, request, operation_id, request_digest):
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from .contact_final_stage_v1 import PrepareCurrentContactDispatchRequestV1
    from .contact_final_stage_v2 import PrepareCurrentContactDispatchRequestV2
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(runtime) is not InstalledDomainOperationRuntimeV1 or type(request) not in (PrepareCurrentContactDispatchRequestV1,PrepareCurrentContactDispatchRequestV2,PrepareCurrentContactDispatchRequestV3):
        raise TypeError('Contact ACK invocation requires the actual installed runtime/request')
    runtime._current()
    if getattr(runtime,'_active_contact_owner_call_v1',None) is not None:
        raise ValueError('another Contact Owner invocation is already active')
    call = _ContactOwnerCallV1(runtime,authority,lease,request,operation_id,request_digest)
    _CALLS[id(call)] = call
    runtime._active_contact_owner_call_v1 = call
    return call


def revoke_contact_owner_call_v1(runtime):
    call=getattr(runtime,'_active_contact_owner_call_v1',None)
    if call is not None:
        from .contact_owner_invocation_v3 import release_contact_owner_invocation_v3
        release_contact_owner_invocation_v3(call)
        _CALLS.pop(id(call),None)
        _SAVED.pop(id(call),None)
    runtime._active_contact_owner_call_v1=None


def require_contact_owner_call_v1(call):
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    if (type(call) is not _ContactOwnerCallV1 or _CALLS.get(id(call)) is not call
            or type(call.runtime) is not InstalledDomainOperationRuntimeV1
            or call.runtime._active_contact_owner_call_v1 is not call
            or call.runtime.graph._GraphCoordinator__domain_production_runtime_v1 is not call.runtime):
        raise ValueError('Contact ACK lacks its exact active installed Owner invocation')
    call.runtime._current()
    return call


def contact_owner_call_v1(graph, authority, lease, operation_id, request_digest):
    runtime=getattr(graph,'_GraphCoordinator__domain_production_runtime_v1',None)
    if runtime is None:return None
    call=getattr(runtime,'_active_contact_owner_call_v1',None)
    if call is None:return None
    require_contact_owner_call_v1(call)
    if (call.runtime.graph is not graph or call.authority is not authority or call.lease != lease
            or (call.operation_id,call.request_digest) != (operation_id,request_digest)):
        raise ValueError('Contact ACK invocation crossed its actual request/Owner identity')
    return call


def _readonly(call, result):
    from .contact_final_stage_v1 import verify_contact_final_committed_v1
    graph=call.runtime.graph; store=graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:
            raise ValueError('Contact ACK verifier requires actual completed COMMIT')
        store._db.execute('BEGIN')
        try:
            attempt=store._db.execute('SELECT request_digest,receipt_json FROM graph_owner_domain_attempts_v3 '
                'WHERE bot=? AND persona=? AND operation_id=?',(*call.authority.namespace.as_tuple,call.operation_id)).fetchone()
            if attempt != (call.request_digest,canonical_serialize(result)):
                raise ValueError('Contact ACK actual saved request/result differs')
            from .contact_final_stage_v2 import PrepareCurrentContactDispatchRequestV2, verify_contact_final_committed_v2
            from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3, verify_contact_final_committed_v3
            verify = verify_contact_final_committed_v3 if type(call.request) is PrepareCurrentContactDispatchRequestV3 else verify_contact_final_committed_v2 if type(call.request) is PrepareCurrentContactDispatchRequestV2 else verify_contact_final_committed_v1
            verify(store._db,namespace=call.authority.namespace,result=result,
                issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            from .contact_qualification_evidence_v1 import decode_contact_qualification_evidence_v1
            original=read_adopted_domain_operation_v1(store._db,call.authority.namespace,call.operation_id)
            proof=original['payload']['provenance']
            if type(call.request) is PrepareCurrentContactDispatchRequestV3:
                from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3 as decode_contact_qualification_evidence_v1
            return decode_contact_qualification_evidence_v1(proof['qualification_evidence'],expected_digest=proof['qualification_digest'])
        finally:
            store._db.rollback()


def _issue_saved_contact_recovery_v1(call, scope, result):
    """Bind only the actual durable Owner attempt to its original live permit."""
    require_contact_owner_call_v1(call)
    from ..authority_service.v2_contract import from_wire
    store=call.runtime.graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:
            raise ValueError('Contact saved recovery cannot issue inside a business transaction')
        row=store._db.execute('SELECT request_digest,attempt_id,permit_json,receipt_json FROM '
            'graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
            (*scope.namespace.as_tuple,call.operation_id)).fetchone()
        if (row is None or row[:2] != (call.request_digest,scope.operation_id)
                or row[2] is None or from_wire(json.loads(row[2])) != scope.permit
                or row[3] != canonical_serialize(result) or scope.namespace != call.authority.namespace):
            raise ValueError('Contact saved recovery differs from its actual durable request/permit/result')
    actual,state=call.runtime.graph._GraphCoordinator__content_fence_v2.get_fence_operation(
        namespace=scope.namespace,authority_namespace=scope.authority_namespace,operation_id=scope.operation_id)
    if actual != scope.permit or state != 'active':
        raise ValueError('Contact saved recovery lacks its authenticated original active permit')
    _SAVED[id(call)]=(call,scope,canonical_serialize(result))


def verify_contact_before_finish_v1(call, scope, result):
    require_contact_owner_call_v1(call)
    if result.get('schema') != 'sylanne.domain-production-receipt.v1':
        return  # A known transactional refusal has no Contact admission.
    runtime=call.runtime
    if (runtime._active_contact_final_command_v1 != (call.request,call.operation_id)
            or runtime._active_contact_final_scope_v1 is not scope
            or getattr(runtime,'_active_contact_final_stage_call_v1',None) is None):
        raise ValueError('Contact COMMIT verifier lacks its real active original stage/scope')
    graph=runtime.graph;port=graph._GraphCoordinator__content_fence_v2
    # RPCs stay outside the SQL lock. The held original write fence pins the
    # Authority head; the subsequent independent SQL snapshot rechecks all rows.
    effect=port.read_current_effect(namespace=scope.namespace,authority_namespace=scope.authority_namespace,
        effect_id=runtime._active_contact_final_effect_v1.effect_id)
    snapshot=port.read_current_effect_snapshot_for_write_fence(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit)
    evidence=_readonly(call,result)
    current_policy=runtime._active_current_contact_policy_v1
    if (current_policy is None or current_policy.scope is not scope
            or canonical_serialize(current_policy.original) != canonical_serialize(evidence.owner_policy)
            or canonical_serialize(effect) != canonical_serialize(evidence.current_effect)
            or canonical_serialize(snapshot) != canonical_serialize(evidence.effect_snapshot)
            or scope.generation != evidence.activation_generation
            or scope.pinned_anchor != evidence.effect_snapshot.anchor):
        raise ValueError('Contact COMMIT independent current Owner/Authority qualification differs')
    stage=getattr(runtime,'_active_contact_final_stage_v1',None)
    if stage is None:
        saved=_SAVED.get(id(call))
        if (saved is None or saved[0] is not call or saved[1] is not scope
                or saved[2] != canonical_serialize(result)):
            raise ValueError('Contact COMMIT requires an issued sealed stage or exact saved recovery')
    else:
        from .contact_final_stage_v1 import ContactFinalStageV1, require_installed_contact_material_v1, _QUALIFIED
        from .contact_final_stage_v2 import ContactFinalStageV2, PrepareCurrentContactDispatchRequestV2
        from .contact_final_stage_v3 import ContactFinalStageV3, PrepareCurrentContactDispatchRequestV3
        if type(call.request) is PrepareCurrentContactDispatchRequestV3:
            from .contact_final_stage_v3 import require_installed_contact_material_v3 as require_installed_contact_material_v1, _QUALIFIED
        expected_stage = ContactFinalStageV3 if type(call.request) is PrepareCurrentContactDispatchRequestV3 else ContactFinalStageV2 if type(call.request) is PrepareCurrentContactDispatchRequestV2 else ContactFinalStageV1
        if type(stage) is not expected_stage:
            raise ValueError('Contact COMMIT stage is not the concrete installed final stage')
        material=require_installed_contact_material_v1(stage.material)
        if (material.scope is not scope or material.request is not call.request
                or material.final_bundle is not stage.bundle
                or canonical_serialize(_QUALIFIED.get(id(material))) != canonical_serialize(evidence)):
            raise ValueError('Contact COMMIT persisted qualification differs from the actually sealed stage')
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(call.request) is PrepareCurrentContactDispatchRequestV3:
        from .contact_saved_owner_projection_v3 import require_current_contact_finish_deadline_v3
        require_current_contact_finish_deadline_v3(call,scope,result)


def require_contact_finish_ack_v1(call, scope):
    require_contact_owner_call_v1(call)
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(call.request) is PrepareCurrentContactDispatchRequestV3:
        from ..runtime_contracts import canonical_digest
        graph=call.runtime.graph;store=graph._GraphCoordinator__store
        with store._lock:
            row=store._db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
                'WHERE bot=? AND persona=? AND operation_id=?',(*scope.namespace.as_tuple,call.operation_id)).fetchone()
            from ..authority_service.v2_contract import from_wire
            if (row is None or row[:2]!=(call.request_digest,scope.operation_id)
                    or from_wire(json.loads(row[2]))!=scope.permit):
                raise ValueError('Contact V3 finished ACK lost its actual original request/permit')
        digest='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3','operation_id':call.operation_id,
            'request_digest':call.request_digest,'permit_token':scope.permit.token})
        graph._GraphCoordinator__content_fence_v2.read_contact_finished_original_v3(scope,
            request_id='finish:'+scope.operation_id,request_digest=digest)
        return
    actual,state=call.runtime.graph._GraphCoordinator__content_fence_v2.get_fence_operation(
        namespace=scope.namespace,authority_namespace=scope.authority_namespace,operation_id=scope.operation_id)
    if actual != scope.permit or state != 'finished':
        raise ValueError('Contact original COMMIT has no authenticated Authority finish ACK; HOLD')


def read_finished_contact_recovery_v1(call, scope, result, *, owner, owner_session_proof):
    """Already ACKed receipt: readonly current Owner read, no new write or fee."""
    require_contact_finish_ack_v1(call,scope)
    graph=call.runtime.graph
    if result.get('schema') != 'sylanne.domain-production-receipt.v1':
        return graph._read_v2(call.authority,lambda:result,owner_binding=owner,owner_session_proof=owner_session_proof)
    evidence=_readonly(call,result)
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(call.request) is PrepareCurrentContactDispatchRequestV3:
        from .contact_owner_invocation_v3 import require_saved_contact_owner_session_binding_v3
        require_saved_contact_owner_session_binding_v3(call,scope,result,owner,owner_session_proof)
        from .contact_saved_owner_projection_v3 import require_saved_finished_contact_deadline_v3
        require_saved_finished_contact_deadline_v3(call,scope,result)
    observed={}
    def observe(read_scope):
        port=graph._GraphCoordinator__content_fence_v2
        policy=graph._GraphCoordinator__c04_authority_port_v3.contact_policy(read_scope.permit,'read_current',
            policy_id=evidence.owner_policy.policy.policy_id)
        effect=port.read_current_effect(namespace=read_scope.namespace,authority_namespace=read_scope.authority_namespace,
            effect_id=evidence.current_effect.effect_id)
        if (canonical_serialize(policy) != canonical_serialize(evidence.owner_policy)
                or canonical_serialize(effect) != canonical_serialize(evidence.current_effect)
                or read_scope.pinned_anchor != evidence.effect_snapshot.anchor
                or read_scope.generation != evidence.activation_generation):
            raise ValueError('Contact cold ACK recovery current Authority/Owner state drifted')
        observed['value']=(policy,effect)
        return observed['value']
    def read():
        actual=_readonly(call,result)
        if canonical_serialize(actual) != canonical_serialize(evidence) or 'value' not in observed:
            raise ValueError('Contact cold recovery durable evidence changed')
        return result
    return graph._read_v2(call.authority,read,owner_binding=owner,owner_session_proof=owner_session_proof,fence_observer=observe)
