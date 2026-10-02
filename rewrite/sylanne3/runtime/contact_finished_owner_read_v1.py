"""Finite installed read of a same-Authority-boot finished Contact original.

No process write lease, active Contact call, job, admission or send authority is
issued. The private marker lives only inside its actual current read fence.
"""
from dataclasses import asdict, dataclass
import json

from ..runtime_contracts import NamespaceId, FenceScope, canonical_serialize, canonical_digest
from ..graph_types import NamespaceEpoch
from ..authority_service.contact_finished_owner_read_v1 import OwnerContactFinishedReadUseV1
from ..authority_service.contact_owner_session_v3 import from_wire as session_from_wire
from ..authority_service.v2_owner_session import _verifier, OwnerSessionLoginRequestV1
from ..authority_service.v2_contract import from_wire as permit_from_wire, to_wire as permit_to_wire
from .restore_anchor import RestoreAnchor
from .contact_owner_invocation_v3 import (
    read_contact_owner_invocation_v3, owner_binding_from_wire_v3, authority_from_wire_v3,
    _command_from_adopted)
from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3, verify_contact_final_committed_v3
from .contact_saved_owner_projection_v3 import _require_live, _live_terms
from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3
from .first_ingress_v2 import trusted_upper


@dataclass(frozen=True, slots=True)
class _ContactFinishedReadV1:
    graph: object
    runtime: object
    authority: object
    owner: object
    scope: FenceScope
    request: PrepareCurrentContactDispatchRequestV3
    operation_id: str
    request_digest: str
    original: object
    read_scope: FenceScope
    use: OwnerContactFinishedReadUseV1
    finished: object


_READS = {}


@dataclass(frozen=True, slots=True)
class _ContactFinishedSqlIdentityV1:
    runtime: object
    authority: object
    request: PrepareCurrentContactDispatchRequestV3
    operation_id: str


def require_contact_finished_read_v1(marker, graph, read_scope):
    if (type(marker) is not _ContactFinishedReadV1 or _READS.get(id(marker)) is not marker
            or marker.graph is not graph or marker.read_scope is not read_scope
            or read_scope.operation != 'read' or read_scope.permit.operation != 'read'):
        raise ValueError('Contact finished read marker lacks its exact authenticated read fence')
    return marker


def _snapshot(graph, original, scope, authority, owner, request, *, now, current=None):
    """Pinned SQL; authenticate full invocation and durable eleven-member chain."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    raw = json.loads(original.payload_json)
    store = graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:
            raise ValueError('finished Contact read needs independent completed SQL COMMIT')
        db = store._db
        db.execute('BEGIN')
        try:
            actual = read_contact_owner_invocation_v3(db, graph._GraphCoordinator__d11_issuer,
                authority.namespace, raw['operation_id'], raw['request_digest'])
            if actual != original:
                raise ValueError('finished Contact signed invocation changed')
            verify_contact_final_committed_v3(db, namespace=authority.namespace, result=raw['result'],
                issuer=graph._GraphCoordinator__d11_issuer, graph=graph)
            adopted = read_adopted_domain_operation_v1(db, authority.namespace, raw['operation_id'])
            if _command_from_adopted(adopted) != raw['command'] or adopted['payload']['provenance'] != raw['provenance']:
                raise ValueError('finished Contact durable command/provenance differs')
            attempt = db.execute('SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json,receipt_json '
                'FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
                (*authority.namespace.as_tuple, raw['operation_id'])).fetchone()
            from ..contracts import canonical_json
            if attempt != (raw['request_digest'], scope.operation_id, canonical_json(asdict(scope.pinned_anchor)),
                    scope.graph_revision, scope.graph_epoch.revision, canonical_json(permit_to_wire(scope.permit)),
                    canonical_serialize(raw['result'])):
                raise ValueError('finished Contact exact original attempt/result differs')
            metadata, epoch = graph._v2_graph_stamp(authority.namespace)
            if ((metadata.graph_revision, epoch.revision) != (raw['post_graph_revision'], raw['post_graph_epoch'])
                    or metadata.requirements.graph_incarnation != owner.graph_incarnation
                    or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
                raise ValueError('finished Contact current head/incarnation/root differs; HOLD')
            evidence = decode_contact_qualification_evidence_v3(raw['provenance']['qualification_evidence'],
                expected_digest=raw['provenance']['qualification_digest'])
            # A read-only identity view is used only by existing SQL loaders;
            # it is never passed to any marker/lease or production issuer.
            view = _ContactFinishedSqlIdentityV1(graph._GraphCoordinator__domain_production_runtime_v1,
                authority, request, raw['operation_id'])
            _require_live(evidence, now, *_live_terms(db, view))
            if current is None:
                target, storage = owner.target_admission, owner.storage_admission
                admission = target if target is not None else storage
                guard = None if admission is None else admission.source_owner_guard
            else:
                target, storage, guard = current.target_admission, current.storage_admission, current.guard
            binding = graph._owner_graph_binding_locked(authority, owner.principal,
                current_guard=guard, target_admission=target, storage_admission=storage)
            # Current location proofs are actual D12 originals. Exact equality
            # retains every old right/location; unlinked reissuance stays HOLD.
            if _owner_binding_wire_v3(binding) != _owner_binding_wire_v3(owner):
                raise ValueError('finished Contact current full Owner grant/location differs; HOLD')
            if (current is not None and (
                    guard.authority_id != scope.pinned_anchor.authority_id
                    or guard.namespace != authority.namespace
                    or guard.authorization_head != binding.authorization_head
                    or guard.authorization_revision != binding.authorization_revision
                    or guard.minimum_revocation_revision != 0
                    or guard.minimum_revocation_epoch != binding.revocation_epoch
                    or guard.pending_revoke_operation_id is not None)):
                raise ValueError('finished Contact current Owner authorization/revocation differs')
            return evidence
        finally:
            db.rollback()


def read_finished_contact_for_owner_v1(graph, bootstrap, *, namespace, operation_id, request_digest,
        owner_session_token, owner_session_request, use, signature):
    from ..graph_coordinator import GraphCoordinator
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    if type(graph) is not GraphCoordinator or type(namespace) is not NamespaceId:
        raise TypeError('actual installed Graph and namespace required')
    graph._admin(bootstrap)
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    if type(runtime) is not InstalledDomainOperationRuntimeV1:
        raise ValueError('finished Contact installed runtime unavailable')
    runtime._current()
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    with store._lock:
        if store._db.in_transaction:
            raise ValueError('finished Contact entry requires independent durable SQL')
        store._db.execute('BEGIN')
        try:
            original = read_contact_owner_invocation_v3(store._db, graph._GraphCoordinator__d11_issuer,
                namespace, operation_id, request_digest)
        finally:
            store._db.rollback()
    raw = json.loads(original.payload_json)
    owner = owner_binding_from_wire_v3(raw['owner'])
    authority = authority_from_wire_v3(raw['authority'])
    parts = dict(raw['scope'])
    parts.update(namespace=NamespaceId(**parts['namespace']), graph_epoch=NamespaceEpoch(**parts['graph_epoch']),
        pinned_anchor=RestoreAnchor(**parts['pinned_anchor']), permit=permit_from_wire(parts['permit']))
    scope = FenceScope(**parts)
    request = PrepareCurrentContactDispatchRequestV3(**raw['request'])
    old = session_from_wire(raw['session_observation'])
    finish_digest = 'sha256:' + canonical_digest(dict(schema='w01.owner-domain-write.v3',
        operation_id=operation_id, request_digest=request_digest, permit_token=scope.permit.token))
    if (type(owner_session_request) is not OwnerSessionLoginRequestV1
            or type(use) is not OwnerContactFinishedReadUseV1 or use.invocation_digest != original.digest
            or use.original_session_commitment != old.commitment
            or use.new_verifier_commitment != 'sha256:' + _verifier(owner_session_token)
            or use.principal != owner.principal or use.actor != owner.actor
            or (use.operation_id, use.request_digest, use.old_permit_digest, use.deadline_utc,
                use.finish_request_id, use.finish_request_digest, use.authority_id, use.authority_namespace,
                use.installation_id, use.generation, use.graph_incarnation)
                != (operation_id, request_digest, old.permit_digest, raw['deadline_utc'], 'finish:' + scope.operation_id,
                    finish_digest, old.authority_id, old.authority_namespace, old.installation_id, scope.generation,
                    owner.graph_incarnation)
            or owner_session_request.principal != owner.principal
            or type(signature) is not bytes or len(signature) != 64
            or 'workbench.read' not in owner.capabilities
            or authority.purpose not in owner.purposes or not set(authority.audience).issubset(owner.audiences)):
        raise ValueError('finished Contact explicit readonly use/original permission differs; HOLD')
    if graph._current_owner_principal(owner.actor, namespace) != owner.principal:
        raise ValueError('finished Contact actual Owner pairing changed')
    finished = port.read_contact_finished_original_v3(scope,
        request_id=use.finish_request_id, request_digest=use.finish_request_digest)
    evidence = _snapshot(graph, original, scope, authority, owner, request,
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)))
    active = {}
    markers = []
    def observe(read_scope):
        runtime._current()
        if (read_scope.namespace != namespace or read_scope.operation != 'read'
                or read_scope.generation != scope.generation or read_scope.pinned_anchor != scope.pinned_anchor):
            raise ValueError('finished Contact actual current read scope differs')
        association, current, actual_finished = port.associate_contact_finished_owner_read_v1(
            namespace=namespace, authority_namespace=scope.authority_namespace, permit=read_scope.permit,
            old_permit=scope.permit, owner_actor_id=owner.actor, owner_session_token=owner_session_token,
            owner_session_request=owner_session_request, original=old, use=use, signature=signature)
        if actual_finished != finished:
            raise ValueError('finished Contact actual ACK changed')
        # Current D12 read proof, full signed old binding and true pairing all
        # agree. This is independent of any old active-write recovery marker.
        if graph._current_owner_principal(owner.actor, namespace) != owner.principal:
            raise ValueError('finished Contact current Owner pairing drifted')
        policy = graph._GraphCoordinator__c04_authority_port_v3.contact_policy(read_scope.permit,
            'read_current', policy_id=evidence.owner_policy.policy.policy_id)
        effect = port.read_current_effect(namespace=namespace, authority_namespace=scope.authority_namespace,
            effect_id=evidence.current_effect.effect_id)
        if (canonical_serialize(policy) != canonical_serialize(evidence.owner_policy)
                or canonical_serialize(effect) != canonical_serialize(evidence.current_effect)):
            raise ValueError('finished Contact current policy/effect drifted')
        now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        actual = _snapshot(graph, original, scope, authority, owner, request, now=now, current=current)
        if canonical_serialize(actual) != canonical_serialize(evidence):
            raise ValueError('finished Contact durable qualification changed')
        # Session logout does not mutate the content anchor. Recheck both
        # actual rows after policy/effect/clock/SQL observation as well; a
        # revoked old session must not survive those independent reads.
        after_association, after_current, after_finished = port.associate_contact_finished_owner_read_v1(
            namespace=namespace, authority_namespace=scope.authority_namespace, permit=read_scope.permit,
            old_permit=scope.permit, owner_actor_id=owner.actor, owner_session_token=owner_session_token,
            owner_session_request=owner_session_request, original=old, use=use, signature=signature)
        if (after_association != association or after_current != current or after_finished != finished):
            raise ValueError('finished Contact final read association drifted')
        if not markers:
            marker = _ContactFinishedReadV1(graph, runtime, authority, owner, scope, request,
                operation_id, request_digest, original, read_scope, use, finished)
            _READS[id(marker)] = marker
            markers.append(marker)
        require_contact_finished_read_v1(markers[0], graph, read_scope)
        active.update(scope=read_scope, current=current, now=now)
        return association, policy, effect
    def read():
        if not markers:
            raise ValueError('finished Contact lacks authenticated read issuance')
        marker = require_contact_finished_read_v1(markers[0], graph, active['scope'])
        actual = _snapshot(graph, marker.original, marker.scope, authority, owner, request,
            now=active['now'], current=active['current'])
        if canonical_serialize(actual) != canonical_serialize(evidence):
            raise ValueError('finished Contact final SQL evidence changed')
        return json.loads(original.payload_json)['result']
    def final_check(result):
        if result != read():
            raise ValueError('finished Contact final readonly result differs')
    try:
        return graph._read_v2(authority, read, owner_principal=owner.principal,
            owner_session_proof=(owner_session_token, owner_session_request),
            fence_observer=observe, final_check=final_check)
    finally:
        for marker in markers:
            _READS.pop(id(marker), None)


__all__ = ('read_finished_contact_for_owner_v1',)
