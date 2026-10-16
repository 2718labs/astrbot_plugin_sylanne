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


def read_natural_model_self_v1(*,self_service,model_service,credential,subject,permit,intent):
    from .owner_location_read_v3 import (prepare_owner_location_for_natural_self_v3,
        _owner_location_service_invocation_v3)
    with _owner_location_service_invocation_v3(self_service):
        return prepare_owner_location_for_natural_self_v3(self_service=self_service,model_service=model_service,
            credential=credential,subject=subject,permit=permit,intent=intent)
