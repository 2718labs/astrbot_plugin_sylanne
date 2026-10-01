"""Actual SQL-free D03 self-identity observation for structured experience."""
import json
from types import SimpleNamespace

from ..graph_types import AtomKey, GraphAtom, Owner
from ..runtime_contracts import canonical_digest
from ..domains.d03.self_identity_qualification import qualify_authority_current_self_identity
from .domain_production_contracts_v1 import ProductionOriginalRefV1


def observe_structured_self_identity_v1(graph, *, namespace, operation_id, scope, owner_guard):
    from ..graph_coordinator import GraphCoordinator
    if type(graph) is not GraphCoordinator:
        raise TypeError("structured self observation requires installed Graph")
    store = graph._GraphCoordinator__store
    port = graph._GraphCoordinator__content_fence_v2
    reader = graph._GraphCoordinator__self_identity_port
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or reader is None or store._db.in_transaction:
        raise ValueError("actual installed SQL-free self identity observer required")
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        if metadata.graph_revision != scope.graph_revision or epoch != scope.graph_epoch:
            raise ValueError("structured self observation Graph stamp changed")
        role, _, role_epoch, _ = graph._scene_binding_state_locked(namespace, owner_guard)
        key = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")
        row = store._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if row is None or role_epoch != epoch:
            raise ValueError("structured experience current role disappeared")
        activation = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
    current = reader.current_self_identity(namespace=namespace,
        authority_namespace=metadata.requirements.authority_namespace,
        request_operation_id=operation_id, permit=scope.permit)
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    current_owner, observed = port.get_current_background_owner_authority_for_fence_v1(
        namespace=namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
    if (type(current_owner) is not D12CurrentOwnerAuthorityV1 or current_owner.guard != owner_guard
            or current_owner.target_admission is not None or observed != scope.permit):
        raise ValueError("structured current source Owner observation differs")
    mapping = qualify_authority_current_self_identity(role=role, activation_atom=activation,
        policy=assembly.installation_policy, installation_grant=port.installation_grant,
        owner_guard=owner_guard, request_operation_id=operation_id, permit=scope.permit,
        port=SimpleNamespace(current_self_identity=lambda **_: current),
        storage_admission=current_owner.storage_admission, graph_metadata=metadata, graph_epoch=epoch)
    if (current.graph_revision != metadata.graph_revision or current.graph_epoch != epoch.revision
            or port.validate_fence(scope) != scope.permit):
        raise ValueError("structured self observation changed under its actual permit")
    with store._lock:
        if graph._v2_graph_stamp(namespace) != (metadata, epoch):
            raise ValueError("structured self observation lost its current Graph snapshot")
    from ..authority_service.v2_self_identity_contract import current_self_identity_commitment_v1
    return ProductionOriginalRefV1("d03.current_self_identity", mapping.certification_ref,
        current_self_identity_commitment_v1(current))
