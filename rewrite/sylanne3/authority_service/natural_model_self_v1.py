"""Authority-internal Self guard for one original natural model admission.

This is not the public Self wire protocol and cannot be used to issue a grant.
It observes the actual installed Core/Owner/Graph under the existing model
permit; it never borrows a Host subject or begins another content fence.
"""
from dataclasses import dataclass

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1
from ..runtime_contracts import canonical_digest
from ..domains.d03.self_perspective import SelfIdentityMapping

_KEY = object()


@dataclass(frozen=True, slots=True)
class _NaturalModelSelfRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: object
    installation_id: str
    manifest_digest: str
    request_operation_id: str
    permit: FencePermitV2


@dataclass(frozen=True, slots=True, init=False)
class _NaturalModelSelfV1:
    namespace: object
    permit: FencePermitV2
    request_operation_id: str
    activation_generation: int
    self_entity_ref: str
    graph_revision: int
    graph_epoch: int
    mapping: SelfIdentityMapping

    def __init__(self, key, *, namespace, permit, activation_generation,
                 self_entity_ref, graph_revision, graph_epoch, mapping):
        if key is not _KEY:
            raise TypeError("model Self guard is issued only by its actual installed reader")
        for name, value in (("namespace", namespace), ("permit", permit),
                ("request_operation_id", permit.operation_id),
                ("activation_generation", activation_generation),
                ("self_entity_ref", self_entity_ref), ("graph_revision", graph_revision),
                ("graph_epoch", graph_epoch), ("mapping", mapping)):
            object.__setattr__(self, name, value)


def read_natural_model_self_v1(*, self_service, model_service, credential, subject, permit, intent):
    from .v2_self_identity_service import AuthorityV2SelfIdentityService
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    if (type(self_service) is not AuthorityV2SelfIdentityService
            or type(model_service) is not AuthorityV2ModelEgressService
            or model_service._fences is not self_service._fences
            or model_service._graph_verifier is None
            or model_service._graph_verifier._path != self_service._graph._path
            or type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2
            or permit.operation != "model_egress"
            or (permit.subject, permit.operation_id, permit.token, permit.namespace) !=
               (subject, intent.operation_id, intent.fence_token, intent.namespace)
            or subject != intent.subject or permit.holder != self_service._holder
            or permit.generation != intent.authority_activation_generation):
        raise AuthorityUnavailable("natural producer Self guard crossed its actual model admission")
    fences = self_service._fences
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    request = _NaturalModelSelfRequestV1(
        permit.authority_id, fences.namespace, self_service._namespace_id,
        self_service._installation_id, self_service._manifest_digest, permit.operation_id, permit)
    location_reader, owner_reader = self_service._source_location, self_service._owner_storage
    if location_reader is None or owner_reader is None:
        raise AuthorityUnavailable("natural model Self guard requires actual installed storage readers")
    location = location_reader.observe_business_for_fence_v1(
        credential=credential, subject=subject, permit=permit)
    with fences._frozen() as (db, deletion, execution, history):
        record = model_service._store.read_locked(db, intent)
        if record.state != "prepared" or not model_service._store.is_fence_bound_locked(db, intent):
            raise AuthorityUnavailable("natural producer Self guard has no original prepared model fence")
        before = self_service._read_locked(
            db, deletion, execution, history, credential, subject, request, location)
        owner_head = owner_reader._head_in_tx(db)
        owner_reader._background_identity_in_tx(db, owner_head)
    if before is None:
        raise AuthorityUnavailable("current Core Self is revoked or unregistered")
    head, guard, anchor, _epoch = before
    if owner_head.guard != guard:
        raise AuthorityUnavailable("model Self guard current Owner differs")
    _, _, admission = owner_reader._read_graph(owner_head=owner_head, anchor=anchor)
    graph = self_service._graph.current(request.namespace, anchor, request.installation_id, guard,
        source_location=location_reader, location_observation=location,
        storage_admission=admission, holder=self_service._holder)
    if graph is None:
        raise AuthorityUnavailable("natural model Self guard has no current D01/Graph identity")
    with fences._frozen() as (db, deletion, execution, history):
        after = self_service._read_locked(
            db, deletion, execution, history, credential, subject, request, location)
        if (after != before or owner_reader._head_in_tx(db) != owner_head
                or model_service._store.read_locked(db, intent) != record):
            raise AuthorityUnavailable("actual model/Self/Owner original changed during graph read")
        owner_reader._background_identity_in_tx(db, owner_head)
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    incarnation, role_head, revision, graph_epoch = graph
    persona = "persona:" + request.namespace.persona_id
    certification = canonical_digest({
        "authority_id": anchor.authority_id, "authority_namespace": request.authority_namespace,
        "namespace": request.namespace.as_tuple, "installation_id": request.installation_id,
        "manifest_digest": request.manifest_digest, "mapping_id": head[3],
        "mapping_revision": head[5], "mapping_revocation_epoch": head[6],
        "registration_operation_id": head[8], "registration_digest": head[9],
        "persona_ref": persona, "self_entity_ref": head[4],
    })
    mapping = SelfIdentityMapping(head[3], persona, head[4],
        "authority:self-identity:" + certification, role_head,
        admission.source_graph_incarnation if admission is not None else incarnation, "active")
    return _NaturalModelSelfV1(_KEY, namespace=request.namespace, permit=permit,
        activation_generation=anchor.activation_generation, self_entity_ref=head[4],
        graph_revision=revision, graph_epoch=graph_epoch, mapping=mapping)
