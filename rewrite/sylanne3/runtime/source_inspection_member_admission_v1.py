"""Private member provenance from the actual paired Authority verifier."""
from __future__ import annotations

from dataclasses import dataclass
from weakref import WeakKeyDictionary, ref

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest

_ISSUER = object()
_PROOFS = WeakKeyDictionary()
_SERVICES = WeakKeyDictionary()
_HISTORY = WeakKeyDictionary()
_VERIFICATION_FIELDS = frozenset({'schema', 'authority_id', 'authority_namespace', 'installation_id',
    'control_store_id', 'namespace', 'admission_digest', 'migration_operation_id', 'producer_operation_id',
    'target_ref', 'target_revision', 'metadata_ref', 'metadata_schema_digest'})


def install_source_inspection_member_verifier_v1(server, migration):
    from ..authority_service.mtls_server import AuthorityRpcServer
    from ..authority_service.source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
    if type(server) is not AuthorityRpcServer or type(migration) is not InstalledSourceInspectionMigrationV1:
        raise AuthorityUnavailable('actual installed member verifier composition required')
    lifecycle = migration.lifecycle
    key = (lifecycle.namespace, lifecycle.installation_id)
    if (server._core is not lifecycle.core or server._v2_fences.get(lifecycle.namespace) is not lifecycle.fences
            or server._d12_source_inspection_migration_services_v1.get(key) is not migration):
        raise AuthorityUnavailable('member verifier crosses its real Core/lifecycle registry')
    previous = _SERVICES.get(lifecycle.fences)
    if previous is not None and previous() is not migration:
        raise AuthorityUnavailable('installed member verifier cannot be replaced')
    _SERVICES[lifecycle.fences] = ref(migration)


def require_registered_source_inspection_member_service_v1(fences):
    reference = _SERVICES.get(fences)
    service = None if reference is None else reference()
    if service is None or service.lifecycle.fences is not fences:
        raise AuthorityUnavailable('actual installed member verifier is unavailable')
    return service


def install_source_inspection_migration_history_v1(server, migration, *, credential):
    from ..authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
    lifecycle = migration.lifecycle
    if require_registered_source_inspection_member_service_v1(lifecycle.fences) is not migration:
        raise AuthorityUnavailable('migration history requires its registered actual service')
    certificate, profile = lifecycle.peer
    installed = server._installations_v2[(certificate, profile)]
    if (installed.installation_id != lifecycle.installation_id
            or server._namespace_bindings_v2.get((certificate, profile, lifecycle.namespace_id)) != lifecycle.namespace):
        raise AuthorityUnavailable('migration history peer/namespace differs from actual installation')
    execution = server._v2_execution[lifecycle.namespace]
    if (type(execution) is not AuthorityV2ExecutionBridge or execution.core is not lifecycle.core
            or execution.fences is not lifecycle.fences.fences):
        raise AuthorityUnavailable('migration history requires the actual same Core execution bridge')
    lifecycle.core._require(credential, 'current', lifecycle.namespace)
    _HISTORY[migration] = (ref(execution), credential, 'mtls:sha256:' + certificate)


def read_source_inspection_migration_historical_observation_v1(owner, *, effect_id,
        mutation_id, expected_receipt_digest):
    from .source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
    if type(owner) is not SourceInspectionMigrationWorkV1:
        raise AuthorityUnavailable('actual maintenance Work is required for historical provenance')
    owner.require_external_inspection_metadata_owner_v1()
    service = owner.service
    if require_registered_source_inspection_member_service_v1(service.lifecycle.fences) is not service:
        raise AuthorityUnavailable('migration history lost its actual registered service')
    binding = _HISTORY.get(service)
    if binding is None or binding[0]() is None:
        raise AuthorityUnavailable('migration historical observation verifier is unavailable')
    execution = binding[0]()
    if execution.core._db.in_transaction or owner.db.in_transaction:
        raise AuthorityUnavailable('migration historical verification must precede Core/Graph SQL')
    return execution.read_historical_observation_receipt_v3(credential=binding[1], subject=binding[2],
        effect_id=effect_id, mutation_id=mutation_id, expected_receipt_digest=expected_receipt_digest)


def _task_binding_v1(owner, task, admission):
    from .source_inspection_migration_v1 import SourceInspectionMigrationProvenanceReadV1
    if type(task) is not SourceInspectionMigrationProvenanceReadV1:
        raise AuthorityUnavailable('member verification requires its exact private provenance task')
    task.require_member_admission_binding_v1(owner, admission)
    operation = owner.operation
    return (id(owner), id(task), id(operation), operation.operation_id,
        operation.selection_digest, id(owner.db), id(operation.handle), owner.namespace,
        canonical_digest(admission))


@dataclass(frozen=True, eq=False)
class VerifiedSourceInspectionMemberAdmissionV1:
    _issuer: object
    _binding: tuple

    def __post_init__(self):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable('member verification private issuer required')
        _PROOFS[self] = self._binding


def verify_source_inspection_member_admission_v1(owner, task, admission):
    from .source_inspection_metadata_read_v3 import source_inspection_member_authority_route_v1
    route = source_inspection_member_authority_route_v1(owner)
    binding = _task_binding_v1(owner, task, admission)
    if task.pending_member_admission_v1(owner) != admission:
        raise AuthorityUnavailable('member proof issuance requires the actual pending verification phase')
    if type(route) is tuple:
        port, namespace, authority_namespace = route
        verification = port.verify_source_inspection_member_admission_v1(
            namespace=namespace, authority_namespace=authority_namespace, admission=admission)
    else:
        verification = route.verify_member_admission_v1(admission)
    expected = {name: admission[name] for name in _VERIFICATION_FIELDS - {'schema'}}
    expected['schema'] = 'sylanne.source-inspection-member-admission-verification.v1'
    if (type(verification) is not dict or set(verification) != _VERIFICATION_FIELDS
            or verification != expected or _task_binding_v1(owner, task, admission) != binding):
        raise AuthorityUnavailable('actual Authority member verification returned another signed admission')
    return VerifiedSourceInspectionMemberAdmissionV1(_ISSUER, binding)


def require_verified_member_admission_v1(proof, *, owner, task, admission):
    if (type(proof) is not VerifiedSourceInspectionMemberAdmissionV1
            or _PROOFS.get(proof) != _task_binding_v1(owner, task, admission)):
        raise AuthorityUnavailable('member proof crossed its actual task/operation/selection/original')
    return proof
