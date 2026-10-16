"""Installed caller proofs for bounded, read-only Owner location material.

Physical selected storage and an Owner DTO never grant a read. These private
proofs retain the exact operation that already owns the real caller admission.
"""
from dataclasses import dataclass, InitVar, asdict
import sqlite3
from threading import get_ident
from weakref import WeakSet, WeakKeyDictionary, ref
from .contract import AuthorityUnavailable
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from .v2_owner_contract import OwnerPrincipalV1
from ..runtime_contracts import AuthorityContext, FenceScope, NamespaceId, namespace_ref, canonical_digest
from ..runtime_storage_v3 import RuntimeStorageOperationV3, runtime_storage_v3

_OWNER_CALLER_ISSUER_V3 = object()
_OWNER_CALLERS_V3 = WeakSet()
_OWNER_CALLER_RETAINED_V3 = WeakKeyDictionary()
_D07_MODEL_SOURCE_OWNER_SERVICES_V3 = WeakKeyDictionary()
_D07_MODEL_SOURCE_OBSERVER_PHASE_V3 = object()
_D07_MODEL_SOURCE_POLICY_PHASE_V3 = object()
_OWNER_CALLER_KINDS_V3 = frozenset(("host_artifact_borrowed_header", "host_artifact_model_dispatch_read", "host_named_joint_source_read", "host_named_joint_write_source", "host_conditioned_write_source", "host_habit_write_source", "host_habit_maintenance_write_source", "host_conditioned_source_read", "host_habit_source_read", "host_semantic_recovery_read", "host_d07_write", "host_d07_model_seal", "host_foreground_read",
    "host_d07_stage_read", "host_method_owner_read", "host_owner_lease_read",
    "host_contact_dispatch_identity_read", "host_contact_dispatch_text_read", "host_beta1_fixture_evidence_read", "host_contact_owner_read", "host_contact_owner_write", "authority_model_header", "authority_model_seal",
    "authority_internal_life_model_header", "authority_artifact_model_header", "authority_foreground_mesh_header",
    "authority_original_foreground_header", "authority_original_owner_task_header",
    "authority_numeric_model_header", "authority_habit_header", "authority_named_joint_header",
    "authority_numeric_location", "authority_root_location", "authority_series_location",
    "authority_life_location", "authority_offline_location", "authority_source_fence_location",
    "authority_target_public_location", "authority_target_background_location",
    "authority_life_numeric_result", "authority_life_content_result", "authority_artifact_model_result",
    "authority_natural_self_location", "authority_c04_self_location", "authority_conditioned_child_location", "goal_management_metadata", "authority_contact_location", "artifact_no_dispatch_metadata", "goal_projection_metadata"))


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class OwnerLocationCallerProofV3:
    issuer: InitVar[object]
    kind: str
    graph: object
    service: object
    owner_service: object
    controller: object
    port: object
    bundle: object
    scope: object
    authority: object
    principal: OwnerPrincipalV1
    current_owner_authority: D12CurrentOwnerAuthorityV1
    current_owner_head: object
    retained_operation: RuntimeStorageOperationV3
    control: object
    selection_digest: str
    namespace: NamespaceId
    installation_id: str
    holder: str
    permission_anchor: object
    graph_comparison_anchor: object
    credential: object
    subject: str
    original_permit: object
    request: object
    deadline_utc: float | None
    thread: int
    header_proof: object = None
    model_authority: object = None
    content_source_scope: object = None
    model_source_phase: str | None = None
    target_history: object = None
    target_role: str | None = None

    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3 or self.kind not in _OWNER_CALLER_KINDS_V3:
            raise AuthorityUnavailable("Owner location requires its actual installed caller")
        if self.kind in ("authority_model_header", "authority_model_seal"):
            if self.model_source_phase not in ("model_seal_observer", "model_policy"):
                raise AuthorityUnavailable("model Source requires its fixed actual caller phase")
        elif self.kind == "authority_internal_life_model_header":
            from .internal_life_model_source_read_v3 import require_internal_life_owner_header_v3
            require_internal_life_owner_header_v3(self)
        elif self.kind == "authority_artifact_model_header":
            from .artifact_model_source_read_v3 import require_artifact_model_owner_header_v3
            require_artifact_model_owner_header_v3(self)
        elif self.kind == "authority_numeric_model_header":
            if self.model_source_phase not in ("numeric_model_seal_observer", "numeric_model_policy"):
                raise AuthorityUnavailable("Numeric model Source requires its private actual caller phase")
        elif self.model_source_phase is not None:
            raise AuthorityUnavailable("non-model Owner caller cannot claim a model Source phase")
        _OWNER_CALLERS_V3.add(self)
        provider = _OwnerCallerRetainedStateV3(self)
        try:
            if self.header_proof is None:
                self.retained_operation.register_retained_state_v3(provider)
            else:
                header = self.header_proof
                if (header not in _OWNER_CALLERS_V3 or header.retained_operation is not self.retained_operation
                        or header.control is not self.control or header.selection_digest != self.selection_digest
                        or header.original_permit != self.original_permit):
                    raise AuthorityUnavailable("Owner final proof crossed its actual retained header")
                prior = _OWNER_CALLER_RETAINED_V3[header]
                provider.states = prior.states
                self.retained_operation.transfer_retained_state_v3(prior, provider)
                _OWNER_CALLER_RETAINED_V3[header] = provider
        except BaseException:
            _OWNER_CALLERS_V3.discard(self)
            raise
        _OWNER_CALLER_RETAINED_V3[self] = provider

    @property
    def clock_policy_digest(self):
        if self.kind in ('host_artifact_borrowed_header','host_artifact_model_dispatch_read','host_named_joint_source_read','host_named_joint_write_source','host_conditioned_write_source','host_habit_write_source','host_habit_maintenance_write_source','host_conditioned_source_read','host_habit_source_read','host_semantic_recovery_read','host_method_owner_read','host_owner_lease_read','host_contact_dispatch_identity_read','host_contact_dispatch_text_read'):
            return canonical_digest(asdict(self.graph._GraphCoordinator__scene_clock_policy))
        return canonical_digest(asdict(self.bundle.ingress_clock))

    @property
    def original_deadline_utc(self):
        return self.deadline_utc

    @property
    def operation(self):
        return self.retained_operation

    def release_v3(self):
        _OWNER_CALLERS_V3.discard(self)
        provider = _OWNER_CALLER_RETAINED_V3.pop(self, None)
        if provider is not None:
            provider.states.clear()
            self.retained_operation.unregister_retained_state_v3(provider)
        if self.content_source_scope is not None:
            self.content_source_scope.release_v3()
        if self.header_proof is not None:
            self.header_proof.release_v3()
        if self.kind == "authority_model_seal":
            self.request.release_v3()


def _require_owner_operation_v3(operation, *, db, namespace, control=None):
    handle = runtime_storage_v3(db)
    if (type(operation) is not RuntimeStorageOperationV3 or operation.closed
            or handle is None or operation.handle is not handle
            or operation.selection_digest != handle.selection_digest
            or handle.role != "graph" or handle.context._reader.namespace != namespace_ref(namespace)):
        raise AuthorityUnavailable("Owner location crossed its actual selected Graph operation")
    actual_control = handle.context._reader
    if control is not None and actual_control is not control:
        raise AuthorityUnavailable("Owner location crossed its actual selected Control")
    return actual_control


def _require_host_d07_components_v3(graph, *, port, service, bootstrap, bundle, scope,
        authority, principal, operation):
    from ..graph_coordinator import GraphCoordinator
    from ..runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    from ..host.authority_profile import AdminInstallationBundle
    if (type(graph) is not GraphCoordinator or type(service) is not InstalledD07ExecutionServiceV1
            or type(bundle) is not AdminInstallationBundle
            or graph._GraphCoordinator__d07_execution_service_v1 is not service
            or service.graph is not graph or service.bundle is not bundle
            or service.bootstrap is not bootstrap
            or port is not graph._GraphCoordinator__content_fence_v2
            or service._store is not graph._GraphCoordinator__store
            or service._db is not service._store._db
            or type(scope) is not FenceScope or type(authority) is not AuthorityContext
            or type(principal) is not OwnerPrincipalV1):
        raise AuthorityUnavailable("D07 Owner caller is not its actual installed service")
    graph._admin(bootstrap)
    policy = bundle.installation_policy
    if (scope.namespace != policy.namespace or authority.namespace != policy.namespace
            or scope.authority_namespace != policy.authority_namespace
            or scope.operation not in ("write", "model_egress")
            or scope.permit.holder != policy.administrator_holder
            or scope.generation != authority.activation_generation
            or port.installation_grant.installation_id != policy.installation_id
            or service._db.in_transaction
            or graph._current_owner_principal(authority.actor, authority.namespace) != principal):
        raise AuthorityUnavailable("D07 Owner caller crossed its actual scope or current pairing")
    return _require_owner_operation_v3(operation, db=service._db, namespace=policy.namespace)


def create_host_d07_write_owner_caller_proof_v3(graph, *, port, installed_d07_service,
        bootstrap, bundle, scope, current_authority, principal, authority, operation):
    """Validate the fresh WRITE before SQL; never reuse a sealed READ's Owner getter."""
    control = _require_host_d07_components_v3(graph, port=port, service=installed_d07_service,
        bootstrap=bootstrap, bundle=bundle, scope=scope, authority=authority,
        principal=principal, operation=operation)
    if scope.operation != "write" or type(current_authority) is not D12CurrentOwnerAuthorityV1:
        raise AuthorityUnavailable("D07 Owner entry needs its actual fresh WRITE")
    if port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable("D07 Owner fresh WRITE permit changed")
    observed, actual_permit = port.get_current_background_owner_authority_for_fence_v1(
        namespace=scope.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
    if (actual_permit != scope.permit or observed != current_authority
            or observed.guard.namespace != scope.namespace
            or observed.guard.authority_id != scope.pinned_anchor.authority_id
            or observed.guard.pending_revoke_operation_id is not None
            or observed.guard.minimum_revocation_revision
            or observed.guard.minimum_revocation_epoch):
        raise AuthorityUnavailable("D07 Owner fresh WRITE identity changed")
    from ..runtime.first_ingress_v2 import trusted_upper
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    if operation.deadline_utc is not None and now >= operation.deadline_utc:
        raise AuthorityUnavailable("D07 Owner read exceeded its original operation deadline")
    return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        "host_d07_write", graph, installed_d07_service, None, None, port, bundle,
        scope, authority, principal, observed, None, operation, control,
        operation.selection_digest, scope.namespace, bundle.installation_policy.installation_id,
        bundle.installation_policy.administrator_holder, scope.pinned_anchor, scope.pinned_anchor,
        None, scope.permit.subject, scope.permit, None, operation.deadline_utc, get_ident())


def _require_owner_graph_stamp_v3(proof, graph_stamp):
    metadata, epoch = graph_stamp
    if (metadata.requirements.namespace != proof.namespace
            or metadata.graph_revision != proof.scope.graph_revision
            or epoch != proof.scope.graph_epoch
            or not proof.graph._anchor_matches(metadata.requirements, proof.graph_comparison_anchor)):
        raise AuthorityUnavailable("Owner location current Graph scope changed")
    from ..runtime.c09_paged_sql_v2 import peek_current_c09_sql_meter_v3
    from contextlib import nullcontext
    store = proof.graph._GraphCoordinator__store
    active = peek_current_c09_sql_meter_v3()
    with store._lock:
        context = nullcontext(active) if active is not None else proof.retained_operation.handle.quantum()
        with context as meter:
            row = meter.read_fixed_row(store._db, "graph_recovery_metadata_v2", ("graph_revision",),
                "bot=? AND persona=?", proof.namespace.as_tuple)
            current_epoch = meter.read_fixed_row(store._db, "graph_epochs", ("revision",),
                "bot=? AND persona=?", proof.namespace.as_tuple)
            if (row != (metadata.graph_revision,) or current_epoch != (epoch.revision,)):
                raise AuthorityUnavailable("Owner location live Graph revision or epoch changed")


def _require_foreground_owner_caller_v3(proof):
    from ..runtime.foreground_activity_issuance_v1 import _IssuedForegroundReceiptReadV1, _ACTIVE
    issued = proof.request
    graph = proof.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(issued) is not _IssuedForegroundReceiptReadV1 or _ACTIVE.get(id(issued)) is not issued
            or issued.graph is not graph or issued.scope is not proof.scope
            or issued.current_owner != proof.current_owner_authority
            or assembly is None or assembly.admin_bundle is not proof.bundle
            or proof.service is not graph._GraphCoordinator__domain_production_runtime_v1
            or graph._GraphCoordinator__content_fence_v2 is not proof.port
            or proof.scope.operation != "read" or proof.original_permit != proof.scope.permit):
        raise AuthorityUnavailable("foreground Owner metadata caller crossed its actual private READ issuance")
    _require_owner_operation_v3(proof.retained_operation,
        db=graph._GraphCoordinator__store._db, namespace=proof.namespace, control=proof.control)


def require_owner_location_caller_proof_v3(proof, *, phase, graph_stamp=None):
    """Require the original registered producer; this local check performs no RPC."""
    if (type(proof) is not OwnerLocationCallerProofV3 or proof not in _OWNER_CALLERS_V3
            or proof.thread != get_ident() or phase not in ("before", "after")
            or proof.retained_operation.closed
            or proof.retained_operation.selection_digest != proof.selection_digest
            or (proof.retained_operation.deadline_utc != proof.deadline_utc
                and (proof.kind not in ('authority_contact_location','host_contact_owner_read','host_contact_owner_write','host_beta1_fixture_evidence_read') or proof.deadline_utc is None
                    or proof.retained_operation.deadline_utc is None
                    or proof.retained_operation.deadline_utc>proof.deadline_utc))):
        raise AuthorityUnavailable("Owner location caller or original retained operation ended")
    if proof.kind in ('authority_original_foreground_header','authority_original_owner_task_header'):
        from .original_foreground_owner_location_v3 import require_original_foreground_owner_header_v3
        require_original_foreground_owner_header_v3(proof,graph_stamp)
        return proof
    if proof.kind == 'authority_foreground_mesh_header':
        from .foreground_mesh_owner_location_v3 import require_foreground_mesh_owner_header_v3
        require_foreground_mesh_owner_header_v3(proof,graph_stamp)
        return proof
    if proof.kind.startswith("host_"):
        if proof.kind=='host_artifact_borrowed_header':
            from .artifact_borrowed_owner_location_v3 import require_artifact_borrowed_owner_caller_v3
            require_artifact_borrowed_owner_caller_v3(proof,graph_stamp)
        elif proof.kind in _CONTACT_OWNER_SOURCE_KINDS_V3:
            _require_contact_owner_source_caller_v3(proof)
        elif proof.kind == "host_beta1_fixture_evidence_read":
            _require_host_beta1_fixture_owner_caller_v3(proof)
        elif proof.kind == "host_owner_lease_read":
            _require_host_owner_lease_caller_v3(proof)
        elif proof.kind in _CONTACT_DISPATCH_OWNER_KINDS_V1:
            _require_contact_dispatch_owner_caller_v1(proof)
        elif proof.kind in ('host_named_joint_write_source', 'host_habit_write_source', 'host_habit_maintenance_write_source', 'host_conditioned_write_source'):
            _require_semantic_write_owner_caller_v3(proof)
        elif proof.kind in _SEMANTIC_BACKGROUND_OWNER_KINDS_V3:
            _require_semantic_background_owner_caller_v3(proof)
        elif proof.kind == "host_method_owner_read":
            _require_host_method_owner_caller_v3(proof)
        elif proof.kind == "host_foreground_read":
            _require_foreground_owner_caller_v3(proof)
        elif proof.kind == "host_d07_stage_read":
            _require_d07_stage_owner_caller_v3(proof)
        else:
            graph, service = proof.graph, proof.service
            if (graph._GraphCoordinator__d07_execution_service_v1 is not service
                    or service.graph is not graph or service.bundle is not proof.bundle
                    or graph._GraphCoordinator__content_fence_v2 is not proof.port
                    or proof.scope.permit != proof.original_permit):
                raise AuthorityUnavailable("Owner location Host installation changed")
            _require_owner_operation_v3(proof.retained_operation, db=service._db,
                namespace=proof.namespace, control=proof.control)
        if graph_stamp is not None:
            _require_owner_graph_stamp_v3(proof, graph_stamp)
    elif proof.kind=='artifact_no_dispatch_metadata':
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import (
            ActualArtifactNoDispatchMetadataInvocationV1, require_artifact_no_dispatch_metadata_invocation_v1)
        invocation=proof.request
        if (type(invocation) is not ActualArtifactNoDispatchMetadataInvocationV1
                or proof.scope is not None or proof.authority is not None or proof.current_owner_authority is not None
                or proof.original_permit is not invocation.grant or proof.graph is not invocation.graph
                or proof.service is not invocation.runtime or proof.port is not invocation.port
                or proof.bundle is not invocation.bundle or proof.owner_service is not None or proof.controller is not None
                or proof.control is not invocation.control or proof.retained_operation is not invocation.retained_operation
                or proof.selection_digest!=invocation.selection_digest or proof.current_owner_head!=invocation.current_owner_head
                or proof.permission_anchor!=invocation.current_anchor or proof.graph_comparison_anchor!=invocation.current_anchor
                or proof.principal!=invocation.principal or proof.subject!=invocation.grant.subject
                or proof.credential is not None or proof.namespace!=invocation.namespace
                or proof.installation_id!=invocation.installation_id or proof.holder!=invocation.holder):
            raise AuthorityUnavailable('Artifact financial Owner metadata crossed its actual private caller')
        require_artifact_no_dispatch_metadata_invocation_v1(invocation,phase=phase,graph_stamp=graph_stamp)
    elif proof.kind=='goal_projection_metadata':
        from .goal_projection_metadata_invocation_v1 import (
            GoalProjectionMetadataInvocationV1,require_goal_projection_metadata_invocation_v1,
            require_goal_projection_committed_bridge_v1)
        invocation=proof.request
        if (type(invocation) is not GoalProjectionMetadataInvocationV1
                or proof.scope is not invocation.original_permit or proof.original_permit is not invocation.original_permit
                or proof.graph is not None or proof.authority is not None or proof.current_owner_authority is not None
                or proof.service is not invocation.service or proof.owner_service is not invocation.owner_service
                or proof.controller is not None or proof.port is not None or proof.bundle is not invocation.bundle
                or proof.control is not invocation.control or proof.retained_operation is not invocation.retained_operation
                or proof.selection_digest!=invocation.selection_digest or proof.current_owner_head!=invocation.current_owner_head
                or proof.permission_anchor!=invocation.current_anchor or proof.graph_comparison_anchor!=invocation.current_anchor
                or proof.principal!=invocation.principal or proof.subject!=invocation.subject
                or proof.credential is not invocation.credential or proof.namespace!=invocation.namespace
                or proof.installation_id!=invocation.installation_id or proof.holder!=invocation.holder):
            raise AuthorityUnavailable('Goal projection Owner metadata crossed its actual independent WRITE caller')
        require_goal_projection_metadata_invocation_v1(invocation,phase=phase,graph_stamp=graph_stamp)
        require_goal_projection_committed_bridge_v1(invocation,graph_stamp=graph_stamp)
    elif proof.kind=='goal_management_metadata':
        from .owner_goal_cancellation_v1 import GoalManagementInvocationV1,require_goal_management_invocation_v1
        invocation=proof.request
        if (type(invocation) is not GoalManagementInvocationV1 or proof.scope is not None
                or proof.original_permit is not None or proof.current_owner_authority is not None
                or proof.service is not invocation.service or proof.owner_service is not invocation.owner_service
                or proof.control is not invocation.control or proof.retained_operation is not invocation.retained_operation
                or proof.selection_digest!=invocation.selection_digest or proof.current_owner_head!=invocation.current_owner_head
                or proof.permission_anchor!=invocation.current_anchor or proof.graph_comparison_anchor!=invocation.current_anchor
                or proof.principal!=invocation.principal or proof.subject!=invocation.subject
                or proof.credential is not invocation.credential or proof.namespace!=invocation.namespace
                or proof.installation_id!=invocation.installation_id or proof.holder!=invocation.holder):
            raise AuthorityUnavailable('Goal management Owner metadata crossed its actual private caller')
        require_goal_management_invocation_v1(invocation,phase=phase,graph_stamp=graph_stamp)
    elif proof.kind == "authority_internal_life_model_header":
        from .internal_life_model_source_read_v3 import require_internal_life_owner_header_v3
        require_internal_life_owner_header_v3(proof)
        if graph_stamp is not None:
            metadata, epoch = graph_stamp
            intent = proof.request.request
            if (metadata.requirements.namespace != proof.namespace
                    or metadata.graph_revision != intent.graph_revision
                    or epoch.revision != intent.graph_epoch):
                raise AuthorityUnavailable("InternalLife Owner location changed its original Graph comparison")
    elif proof.kind=='authority_artifact_model_header':
        from .artifact_model_source_read_v3 import require_artifact_model_owner_header_v3
        require_artifact_model_owner_header_v3(proof)
        if graph_stamp is not None:
            metadata,epoch=graph_stamp;intent=proof.request.request
            if(metadata.requirements.namespace!=proof.namespace or metadata.graph_revision!=intent.graph_revision
                    or epoch.revision!=intent.graph_epoch):
                raise AuthorityUnavailable('Artifact Owner changed actual model Graph comparison')
    elif proof.kind=='authority_habit_header':
        _require_habit_owner_caller_v3(proof,graph_stamp)
    elif proof.kind=='authority_named_joint_header':
        _require_named_joint_owner_caller_v3(proof,graph_stamp)
    elif proof.kind=='authority_contact_location':
        _require_contact_owner_caller_proof_v3(proof,graph_stamp)
    elif proof.kind in _OWNER_LOCATION_AUTHORITY_KINDS_V3:
        call=proof.request
        if (type(call) is not _AuthorityOwnerLocationCallV3 or call.owner_service is not proof.owner_service
                or call.controller is not proof.controller or call.service is not proof.service
                or call.operation is not proof.retained_operation or call.permit!=proof.original_permit
                or call.head!=proof.current_owner_head or call.permission_anchor!=proof.permission_anchor
                or call.comparison_anchor!=proof.graph_comparison_anchor or call.history!=proof.target_history):
            raise AuthorityUnavailable('Owner metadata proof crossed its actual registered service call')
        call._actual()
        if graph_stamp is not None:
            metadata,epoch=graph_stamp
            req=metadata.requirements;anchor=proof.graph_comparison_anchor
            if (req.namespace!=proof.namespace or req.authority_namespace!=anchor.namespace
                    or any(getattr(req,name)!=getattr(anchor,name) for name in (
                        'authority_id','activation_generation','revocation_epoch','deletion_journal_id',
                        'deletion_seq','deletion_digest','execution_journal_id','execution_seq','execution_digest'))):
                raise AuthorityUnavailable('Owner metadata lost its authenticated exact comparison anchor')
    else:
        proof.controller.require_installed_v3()
        if proof.kind == "authority_numeric_model_header":
            from .life_numeric_source_read_v3 import require_authority_numeric_model_phase_v3
            if proof.model_source_phase != require_authority_numeric_model_phase_v3(proof.request,proof.controller.verifier._life_numeric_reader_v1):
                raise AuthorityUnavailable("Numeric Owner header crossed its private actual model phase")
        if proof.controller.service is not proof.service:
            raise AuthorityUnavailable("Owner location actual Authority service changed")
        proof.request._actual()
        if (proof.request.operation is not proof.retained_operation
                or proof.request.permit != proof.original_permit):
            raise AuthorityUnavailable("Owner location Authority Work crossed its original permit")
        if graph_stamp is not None:
            metadata, epoch = graph_stamp
            intent = proof.request.request
            if (metadata.requirements.namespace != proof.namespace
                    or metadata.graph_revision != intent.graph_revision
                    or epoch.revision != intent.graph_epoch):
                raise AuthorityUnavailable("Owner location original Authority Graph scope changed")
    provider = _OWNER_CALLER_RETAINED_V3.get(proof)
    if provider is not None:
        proof.retained_operation.refresh_retained_state_v3(provider)
    return proof


def create_model_seal_owner_caller_proof_v3(owner_service, *, model_service, credential,
        subject, original_permit, intent, now, location_observation=None):
    return _create_d07_model_source_owner_caller_proof_v3(owner_service,
        model_service=model_service, credential=credential, subject=subject,
        original_permit=original_permit, intent=intent, now=now,
        location_observation=location_observation, phase_issuer=_D07_MODEL_SOURCE_OBSERVER_PHASE_V3)


def _create_d07_model_source_owner_caller_proof_v3(owner_service, *, model_service, credential,
        subject, original_permit, intent, now, location_observation, phase_issuer):
    """Qualify the original model and independent Owner/Source identities without another fence."""
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_model_egress_contract import ModelEgressIntentV1
    from .current_authority_graph_read_v3 import (
        require_authority_graph_read_controller_v3, begin_authority_model_graph_read_work_v3)
    from ..runtime.lifecycle_operations_v1 import digest as original_digest
    from ..contracts import canonical_json
    from ..graph_types import owner_grant_key, validate_owner_grant_v1
    if (type(owner_service) is not InstalledD12OwnerStorageAdmissionServiceV1
            or type(model_service) is not AuthorityV2ModelEgressService
            or type(intent) is not ModelEgressIntentV1
            or model_service._fences is not owner_service.fences
            or model_service._store._db is not owner_service.core._db
            or subject != intent.subject or original_permit.subject != subject
            or original_permit.operation != "model_egress"
            or original_permit.operation_id != intent.operation_id
            or original_permit.namespace != owner_service.namespace):
        raise AuthorityUnavailable("model Owner observer crossed its actual installed admission")
    if phase_issuer is _D07_MODEL_SOURCE_OBSERVER_PHASE_V3:
        model_source_phase = "model_seal_observer"
    elif (phase_issuer is _D07_MODEL_SOURCE_POLICY_PHASE_V3
            and _D07_MODEL_SOURCE_OWNER_SERVICES_V3.get(model_service) is owner_service):
        model_source_phase = "model_policy"
    else:
        raise AuthorityUnavailable("D07 Source phase requires its actual installed private producer")
    verifier = model_service._graph_verifier
    controller = require_authority_graph_read_controller_v3(verifier)
    bundle = verifier._artifact_draft_bundle
    if (controller.service is not model_service
            or controller.control is not owner_service.control
            or controller.location._graph_db_path != owner_service.graph_path
            or bundle.installation_policy.installation_id != owner_service.installation_id):
        raise AuthorityUnavailable("model Owner observer crossed its actual Graph installation")
    fences = owner_service.fences
    fences.core._require(credential, "owner_guard_read", owner_service.namespace, owner_service.holder)
    fences.validate_fence(credential=credential, subject=subject, permit=original_permit)
    with fences._frozen() as (db, deletion, execution, _):
        anchor = fences._current_locked(db, deletion, execution,
            holder=original_permit.holder, generation=original_permit.generation)
        fences.fences.validate_fence_locked(db, original_permit, subject=subject, current_anchor=anchor)
        record = model_service._store.read_locked(db, intent)
        if (anchor != original_permit.pinned_anchor
                or canonical_digest(asdict(anchor)) != intent.anchor_digest
                or record.state != "prepared"):
            raise AuthorityUnavailable("model Owner observer requires the original prepared live model")
        head = owner_service._head_in_tx(db)
        actor, _ = owner_service._background_identity_in_tx(db, head)
    work = begin_authority_model_graph_read_work_v3(verifier, model_service=model_service,
        credential=credential, subject=subject, permit=original_permit, intent=intent, now_utc=now)
    header = owner_work = lineage = None
    try:
        _require_owner_operation_v3(work.operation, db=work.db,
            namespace=owner_service.namespace_id, control=owner_service.control)
        # This admission permits only the fixed Owner recovery/grant/issue columns.
        # Body qualification is a separate step using the actual signed content delegate.
        header = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
            "authority_model_header", None, model_service, owner_service, controller, None,
            bundle, work.scope, None, head.issue_operation.principal,
            D12CurrentOwnerAuthorityV1(head.guard, None), head, work.operation, owner_service.control,
            work.selection_digest, owner_service.namespace_id, owner_service.installation_id,
            owner_service.holder, anchor, anchor, credential, subject, original_permit, work,
            work.deadline_utc, get_ident(), model_source_phase=model_source_phase)
        owner_work = prepare_owner_location_read_work_v3(header)
        while not owner_work.complete:
            with owner_location_read_quantum_v3(header) as meter:
                progress = owner_work.advance(meter=meter)
            if type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
                owner_work.complete_reserved_quantum_v3(header)
        facts = owner_work.result.require_for_v3(header)
        grant = json.loads(facts.atom[1])
        validate_owner_grant_v1(grant)
        if (facts.atom[0] != 1 or facts.atom[2] != 1
                or original_digest(grant) != head.grant_digest
                or grant["principal"] != asdict(head.issue_operation.principal)
                or facts.proof_row[-1] != canonical_json(asdict(head.issue_proof))
                or grant["scope"] != "/".join(owner_service.namespace_id.as_tuple)
                or "workbench.read" not in grant["capabilities"]):
            raise AuthorityUnavailable("model Owner observer lost the immutable actual Owner issue")
        lineage = prepare_source_owner_location_lineage_v3(header, facts)
        while not lineage.complete:
            with owner_location_read_quantum_v3(header) as meter:
                progress = lineage.advance(meter=meter)
            if type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
                lineage.complete_reserved_quantum_v3(header)
        admission = resolve_source_owner_storage_admission_from_completed_location_v3(header, facts)
        owner_acl = AuthorityContext(actor.actor_id, "d12",
            owner_grant_key(*owner_service.namespace_id.as_tuple).token, owner_service.namespace_id,
            ("d11",), grant["purposes"][0], (grant["audiences"][0],), grant["issuer_ref"],
            anchor.activation_generation)
        from .d07_authority_model_source_read_v3 import prepare_current_d07_authority_model_source_read_v3
        if location_observation is None:
            location_observation = controller.location.observe_business_for_fence_v1(
                credential=credential, subject=subject, permit=original_permit)
        source_reader = prepare_current_d07_authority_model_source_read_v3(
            work, owner_header_proof=header, owner_acl_authority=owner_acl, bundle=bundle,
            location_observation=location_observation)
        while not source_reader.complete:
            source_reader.advance()
        prepared, job, frozen, request, basis = source_reader.result.require_for_observer_v3(work)
        content_scope = _issue_d07_content_source_scope_v3(work, prepared=prepared, request=request,
            job=job, frozen=frozen, basis=basis, source_material=source_reader.result)
        _require_owner_permission_outside_graph_v3(header)
        return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
            "authority_model_seal", None, model_service, owner_service, controller, None,
            bundle, work.scope, owner_acl, head.issue_operation.principal,
            D12CurrentOwnerAuthorityV1(head.guard, None, admission), head, work.operation, owner_service.control,
            work.selection_digest, owner_service.namespace_id, owner_service.installation_id,
            owner_service.holder, anchor, anchor, credential, subject, original_permit, work,
            work.deadline_utc, get_ident(), header, request.envelope.authority, content_scope,
            model_source_phase=model_source_phase)
    except BaseException:
        if header is not None: header.release_v3()
        work.release_v3()
        raise
    finally:
        if owner_work is not None: owner_work.close_v3()
        if lineage is not None: lineage.close_v3()


def _require_owner_permission_outside_graph_v3(proof):
    """Observe real admission outside Graph SQL; local fact consumers never call this."""
    require_owner_location_caller_proof_v3(proof, phase="before")
    if proof.kind.startswith("host_"):
        if _owner_graph_db_v3(proof).in_transaction:
            raise AuthorityUnavailable("Owner permission observation cannot run in Graph SQL")
        if proof.kind=='host_artifact_borrowed_header':
            from .artifact_borrowed_owner_location_v3 import require_artifact_borrowed_owner_permission_v3
            return require_artifact_borrowed_owner_permission_v3(proof)
        if proof.kind in _CONTACT_OWNER_SOURCE_KINDS_V3:
            state,write=proof.request
            current=_observe_contact_owner_source_authority_v3(state,write)
            if current!=proof.current_owner_authority:
                raise AuthorityUnavailable("Contact Owner original current Authority changed")
            return proof
        elif proof.kind == "host_beta1_fixture_evidence_read":
            current=_observe_host_beta1_fixture_owner_authority_v3(proof.request)
            if current!=proof.current_owner_authority:
                raise AuthorityUnavailable("Beta1 evidence original current Authority changed")
            return proof
        elif proof.kind == "host_owner_lease_read":
            current=_observe_host_owner_lease_authority_v3(proof.request)
            if current!=proof.current_owner_authority:
                raise AuthorityUnavailable("Owner lease/view original current Authority changed")
            return proof
        elif proof.kind in _CONTACT_DISPATCH_OWNER_KINDS_V1:
            current=_observe_contact_dispatch_owner_authority_v1(proof.request,proof.kind)
            if current!=proof.current_owner_authority:
                raise AuthorityUnavailable("Contact dispatch original current Owner Authority changed")
            return proof
        elif proof.kind in ('host_named_joint_write_source', 'host_habit_write_source', 'host_habit_maintenance_write_source', 'host_conditioned_write_source'):
            reader, scope, issued, state = _SEMANTIC_WRITE_OWNER_CALLERS_V3[proof]
            current = _observe_semantic_write_owner_authority_v3(reader, scope, issued)
            if current != proof.current_owner_authority:
                raise AuthorityUnavailable('Habit fresh WRITE current Owner authority changed')
            acl = _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.get(proof)
            if acl is not None:
                authority, principal = acl
                pairing = proof.port.current_owner_principal_binding(namespace=proof.namespace,
                    authority_namespace=scope.authority_namespace, principal=principal)
                if (pairing is None or pairing.principal != principal or pairing.actor_id != authority.actor
                        or pairing.installation_id != proof.installation_id):
                    raise AuthorityUnavailable('Habit WRITE actual Owner principal pairing changed')
            return proof
        elif proof.kind in _SEMANTIC_BACKGROUND_OWNER_KINDS_V3:
            current = _observe_semantic_background_owner_authority_v3(proof.request)
            if current != proof.current_owner_authority:
                raise AuthorityUnavailable("semantic background original Owner Authority changed")
            acl = _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.get(proof)
            if acl is not None:
                authority, principal = acl
                pairing = proof.port.current_owner_principal_binding(namespace=proof.namespace,
                    authority_namespace=proof.scope.authority_namespace, principal=principal)
                if (pairing is None or pairing.principal != principal or pairing.actor_id != authority.actor
                        or pairing.installation_id != proof.installation_id):
                    raise AuthorityUnavailable("semantic background actual Owner principal pairing changed")
            return proof
        elif proof.kind == "host_method_owner_read":
            current=_observe_host_method_owner_authority_v3(proof.request)
            if current!=proof.current_owner_authority:
                raise AuthorityUnavailable("Method Owner original current Authority changed")
            return proof
        elif proof.kind == "host_foreground_read":
            issued = proof.request
            current = proof.graph._GraphCoordinator__self_identity_port.current_self_identity(
                namespace=proof.namespace, authority_namespace=proof.scope.authority_namespace,
                request_operation_id=proof.scope.operation_id, permit=proof.original_permit)
            owner, permit = proof.port.get_current_background_owner_authority_for_fence_v1(
                namespace=proof.namespace, authority_namespace=proof.scope.authority_namespace,
                permit=proof.original_permit)
            if current != issued.current_self or owner != issued.current_owner or permit != proof.original_permit:
                raise AuthorityUnavailable("foreground Owner READ current Self or Owner changed")
        elif proof.kind == "host_d07_stage_read":
            if proof.port.validate_fence(proof.scope) != proof.original_permit:
                raise AuthorityUnavailable("D07 stage metadata original READ permit changed")
            owner, permit = proof.port.get_current_background_owner_authority_for_fence_v1(
                namespace=proof.namespace, authority_namespace=proof.scope.authority_namespace,
                permit=proof.original_permit)
            if owner != proof.current_owner_authority or permit != proof.original_permit:
                raise AuthorityUnavailable("D07 stage metadata current Owner observation changed")
        elif proof.kind == "host_d07_write":
            if proof.port.validate_fence(proof.scope) != proof.original_permit:
                raise AuthorityUnavailable("Owner read original WRITE permit changed")
            observed, permit = proof.port.get_current_background_owner_authority_for_fence_v1(
                namespace=proof.namespace, authority_namespace=proof.scope.authority_namespace,
                permit=proof.original_permit)
            if observed != proof.current_owner_authority or permit != proof.original_permit:
                raise AuthorityUnavailable("Owner read original WRITE identity changed")
        else:
            require_verified_model_seal_owner_observation_v3(proof.request,
                port=proof.port, installed_d07_service=proof.service, bundle=proof.bundle,
                intent=proof.request.intent, permit=proof.original_permit)
        from ..runtime.first_ingress_v2 import trusted_upper
        now = trusted_upper(proof.port.read_ingress_clock(proof.bundle.ingress_clock))
    elif proof.kind=='artifact_no_dispatch_metadata':
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import require_artifact_no_dispatch_metadata_invocation_v1
        if proof.request.actual_db.in_transaction:
            raise AuthorityUnavailable('Artifact financial permission observation must precede Graph SQL')
        require_artifact_no_dispatch_metadata_invocation_v1(proof.request,phase='before')
        return proof
    elif proof.kind=='goal_projection_metadata':
        from .goal_projection_metadata_invocation_v1 import (require_goal_projection_metadata_invocation_v1,
            require_goal_projection_committed_bridge_v1)
        if proof.request.actual_db.in_transaction:
            raise AuthorityUnavailable('Goal projection permission observation must precede Graph SQL')
        require_goal_projection_metadata_invocation_v1(proof.request,phase='before')
        require_goal_projection_committed_bridge_v1(proof.request)
        return proof
    elif proof.kind=='goal_management_metadata':
        from .owner_goal_cancellation_v1 import require_goal_management_invocation_v1
        if proof.request.actual_db.in_transaction:
            raise AuthorityUnavailable('Goal management permission observation must precede Graph SQL')
        require_goal_management_invocation_v1(proof.request,phase='before')
        return proof
    elif proof.kind in ('authority_original_foreground_header','authority_original_owner_task_header'):
        from .original_foreground_owner_location_v3 import require_original_foreground_owner_header_v3
        call=require_original_foreground_owner_header_v3(proof)
        call._check_permission_v3()
        return proof
    elif proof.kind == 'authority_foreground_mesh_header':
        from .foreground_mesh_owner_location_v3 import require_foreground_mesh_owner_header_v3
        call = require_foreground_mesh_owner_header_v3(proof)
        call._check_permission_v3()
        return proof
    elif proof.kind=='authority_contact_location':
        proof.request._check_permission_v3()
        return proof
    elif proof.kind in _OWNER_LOCATION_AUTHORITY_KINDS_V3:
        proof.request._check_permission_v3()
        return proof
    else:
        work = proof.request
        work._check_permission_v3()
        if work.db.in_transaction:
            raise AuthorityUnavailable("Owner admission observation must precede Graph SQL")
        owner = proof.owner_service
        with owner.fences._frozen() as (db, deletion, execution, _):
            anchor = owner.fences._current_locked(db, deletion, execution,
                holder=proof.holder, generation=proof.original_permit.generation)
            owner.fences.fences.validate_fence_locked(db, proof.original_permit,
                subject=proof.subject, current_anchor=anchor)
            if anchor != proof.permission_anchor or owner._head_in_tx(db) != proof.current_owner_head:
                raise AuthorityUnavailable("Owner read original permission or authorization head changed")
            owner._background_identity_in_tx(db, proof.current_owner_head)
        reading = proof.controller.clock()
        now = reading.utc_seconds+reading.utc_error_seconds if proof.kind in {'authority_habit_header','authority_named_joint_header'} else reading
    if proof.deadline_utc is not None and now >= proof.deadline_utc:
        raise AuthorityUnavailable("Owner read exceeded its original caller deadline")
    return proof


from contextlib import contextmanager


@contextmanager
def owner_location_read_quantum_v3(proof):
    """Use the caller's existing selected retention lease and ordinary read quantum."""
    from ..runtime.c09_paged_sql_v2 import peek_current_c09_sql_meter_v3, require_c09_reserved_meter_v3
    _require_owner_permission_outside_graph_v3(proof)
    db = _owner_graph_db_v3(proof)
    if db.in_transaction:
        raise AuthorityUnavailable("Owner metadata read cannot inherit business Graph SQL")
    if peek_current_c09_sql_meter_v3() is not None:
        raise AuthorityUnavailable("Owner read cannot create a nested reserved root")
    with proof.control.reserve_control_read_v3() as budget:
        meter = require_c09_reserved_meter_v3(budget)
        yield meter
    _require_owner_permission_outside_graph_v3(proof)


class _OwnerCallerRetainedStateV3:
    def __init__(self, proof):
        self.proof = ref(proof)
        self.states = []

    def _runtime_retained_heap_bytes_v3(self):
        proof = self.proof()
        if proof is None:
            return 0
        seen = set()
        amount = _owner_heap_size_v3(self) + _owner_location_payload_heap_v3((
            proof.authority, proof.principal, proof.current_owner_authority,
            proof.current_owner_head, proof.permission_anchor, proof.graph_comparison_anchor,
            proof.original_permit, proof.deadline_utc), seen)
        if proof.kind == "host_d07_model_seal":
            amount += _owner_location_payload_heap_v3(proof.request.wire, seen)
        if proof.content_source_scope is not None:
            scope = proof.content_source_scope
            amount += _owner_location_payload_heap_v3((scope.wire_json,
                scope.effective_source_authority, scope.model_authority, scope.owner_acl_authority,
                scope.commitment), seen)
        for state in self.states:
            # A transferred lineage provider includes its actual Graph facts.
            amount += state._c09_retained_heap_bytes_v3()
        return amount


def register_owner_location_retained_state_v3(proof, state):
    require_owner_location_caller_proof_v3(proof, phase="before")
    provider = _OWNER_CALLER_RETAINED_V3[proof]
    if (state.proof is not proof or state.control is not proof.control
            or state in provider.states):
        raise AuthorityUnavailable("Owner payload requires its same actual caller and selected Control")
    provider.states.append(state)
    try:
        proof.retained_operation.refresh_retained_state_v3(provider)
    except BaseException:
        provider.states.remove(state)
        raise


def transfer_owner_location_retained_state_v3(proof, prior, successor):
    require_owner_location_caller_proof_v3(proof, phase="before")
    provider = _OWNER_CALLER_RETAINED_V3[proof]
    if (prior not in provider.states or prior.proof is not proof
            or successor.proof is not proof or successor.control is not proof.control
            or successor.facts.work is not prior):
        raise AuthorityUnavailable("Owner payload transfer crossed its actual original facts")
    index = provider.states.index(prior)
    provider.states[index] = successor
    try:
        proof.retained_operation.refresh_retained_state_v3(provider)
    except BaseException:
        provider.states[index] = prior
        raise


def reserve_owner_location_retained_growth_v3(proof, growth_bound):
    """Called by the fixed IO producer before a known bounded allocation."""
    require_owner_location_caller_proof_v3(proof, phase="before")
    proof.retained_operation.reserve_retained_state_growth_v3(
        _OWNER_CALLER_RETAINED_V3[proof], growth_bound)


def finish_owner_location_retained_growth_v3(proof):
    provider = _OWNER_CALLER_RETAINED_V3.get(proof)
    if provider is not None:
        proof.retained_operation.finish_retained_state_growth_v3(provider)


def _owner_graph_db_v3(proof):
    if proof.kind in ('goal_management_metadata','artifact_no_dispatch_metadata','goal_projection_metadata'):return proof.request.actual_db
    return proof.graph._GraphCoordinator__store._db if proof.kind.startswith("host_") else proof.request.db


_FOREGROUND_OWNER_ENTRIES_V3 = WeakKeyDictionary()


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class _HostForegroundReadOwnerEntryV3:
    issuer: InitVar[object]

    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable("foreground Owner entry requires its actual READ producer")

    def require_for_v3(self, graph, issued, operation):
        state = _FOREGROUND_OWNER_ENTRIES_V3.get(self)
        if (state is None or state[0].graph is not graph or state[0].request is not issued
                or state[0].retained_operation is not operation):
            raise AuthorityUnavailable("foreground Owner entry crossed its original READ operation")
        proof, work, facts, authority, principal, owner = state
        facts.require_for_v3(proof)
        current = proof.current_owner_authority
        actual = graph._owner_graph_binding_from_current_metadata_v3(
            authority, principal, metadata=facts.metadata, graph_epoch=facts.graph_epoch,
            atom=facts.atom, proof_row=facts.proof_row, epochs=facts.epochs,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=current.guard)
        if actual != owner:
            raise AuthorityUnavailable("foreground actual Owner binding changed before consumption")
        return actual

    def release_v3(self):
        state = _FOREGROUND_OWNER_ENTRIES_V3.pop(self, None)
        if state is not None:
            proof, work = state[:2]
            try:
                work.close_v3()
            finally:
                proof.release_v3()


def prepare_current_host_foreground_read_owner_entry_v3(graph, *, issued, bundle, operation):
    """Complete only the fixed Owner metadata EOF under the actual current Self READ."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.authority_profile import AdminInstallationBundle
    from ..runtime.foreground_activity_issuance_v1 import _IssuedForegroundReceiptReadV1, _ACTIVE
    from ..runtime.first_ingress_v2 import trusted_upper
    from ..graph_types import owner_grant_key, validate_owner_grant_v1
    if (type(graph) is not GraphCoordinator or type(bundle) is not AdminInstallationBundle
            or type(issued) is not _IssuedForegroundReceiptReadV1 or _ACTIVE.get(id(issued)) is not issued
            or issued.graph is not graph or issued.scope.operation != "read"
            or graph._GraphCoordinator__store._db.in_transaction
            or graph._GraphCoordinator__d04_installed_joint_assembly is None
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise AuthorityUnavailable("foreground Owner metadata requires its actual installed READ issuance")
    scope, current = issued.scope, issued.current_owner
    policy = bundle.installation_policy
    port = graph._GraphCoordinator__content_fence_v2
    if (scope.namespace != policy.namespace or scope.authority_namespace != policy.authority_namespace
            or scope.permit.holder != policy.administrator_holder
            or port.installation_grant.installation_id != policy.installation_id
            or current.guard.namespace != policy.namespace):
        raise AuthorityUnavailable("foreground Owner metadata crossed its actual installed scope")
    control = _require_owner_operation_v3(operation, db=graph._GraphCoordinator__store._db,
        namespace=scope.namespace)
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    if operation.deadline_utc is not None and now >= operation.deadline_utc:
        raise AuthorityUnavailable("foreground Owner metadata exceeded its original deadline")
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        "host_foreground_read", graph, graph._GraphCoordinator__domain_production_runtime_v1,
        None, None, port, bundle, scope, None, None, current, None, operation, control,
        operation.selection_digest, scope.namespace, policy.installation_id,
        policy.administrator_holder, scope.pinned_anchor, scope.pinned_anchor, None,
        scope.permit.subject, scope.permit, issued, operation.deadline_utc, get_ident())
    work = None
    try:
        _require_owner_permission_outside_graph_v3(proof)
        work = prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = work.advance(meter=meter)
            if type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
                work.complete_reserved_quantum_v3(proof)
        facts = work.result.require_for_v3(proof)
        grant = json.loads(facts.atom[1])
        validate_owner_grant_v1(grant)
        principal = OwnerPrincipalV1(**grant["principal"])
        pairing = port.current_owner_principal_binding(namespace=scope.namespace,
            authority_namespace=scope.authority_namespace, principal=principal)
        if pairing is None or pairing.principal != principal or pairing.installation_id != policy.installation_id:
            raise AuthorityUnavailable("foreground Owner metadata lost its actual current paired principal")
        authority = AuthorityContext(pairing.actor_id, "d12", owner_grant_key(*scope.namespace.as_tuple).token,
            scope.namespace, ("d11",), issued.purpose, issued.audiences,
            grant["issuer_ref"], scope.generation)
        owner = graph._owner_graph_binding_from_current_metadata_v3(authority, principal,
            metadata=facts.metadata, graph_epoch=facts.graph_epoch, atom=facts.atom,
            proof_row=facts.proof_row, epochs=facts.epochs,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=current.guard)
        if (owner.authorization_head != current.guard.authorization_head
                or owner.authorization_revision != current.guard.authorization_revision
                or current.guard.pending_revoke_operation_id is not None):
            raise AuthorityUnavailable("foreground Owner metadata current authorization head changed")
        _require_owner_permission_outside_graph_v3(proof)
        entry = _HostForegroundReadOwnerEntryV3(_OWNER_CALLER_ISSUER_V3)
        _FOREGROUND_OWNER_ENTRIES_V3[entry] = (proof, work, facts, authority, principal, owner)
        return entry
    except BaseException as exc:
        if work is not None:
            work.cancel_v3(exc)
        proof.release_v3()
        raise


def accept_host_d07_model_seal_owner_caller_proof_v3(graph, *, port,
        installed_d07_service, bundle, verified_observation, scope, intent, permit,
        operation, clock_policy):
    observed = require_verified_model_seal_owner_observation_v3(verified_observation,
        port=port, installed_d07_service=installed_d07_service, bundle=bundle,
        intent=intent, permit=permit)
    if (clock_policy is not bundle.ingress_clock or scope.operation != "model_egress"
            or scope.permit != permit or scope.operation_id != intent.operation_id
            or scope.pinned_anchor != permit.pinned_anchor
            or observed.wire["selection_digest"] != operation.selection_digest):
        raise AuthorityUnavailable("D07 model Owner caller crossed its original signed model scope")
    control = _require_host_d07_components_v3(graph, port=port,
        service=installed_d07_service, bootstrap=installed_d07_service.bootstrap,
        bundle=bundle, scope=scope, authority=observed.owner_acl_authority,
        principal=observed.principal, operation=operation)
    matches = [content for content, state in _D07_CONTENT_SCOPES_V3.items()
        if state[0] == "host" and state[1]() is graph and state[2]() is installed_d07_service
        and state[3] is bundle and state[4]() is operation and state[5]() is observed
        and state[6] == permit and state[7] == intent]
    if len(matches) != 1:
        raise AuthorityUnavailable("D07 model Owner caller lacks its exact already qualified Source scope")
    content = matches[0]
    content.require_for_v3(graph, installed_d07_service, bundle, operation,
        observed.model_authority, permit)
    from ..runtime.first_ingress_v2 import trusted_upper
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    signed_deadline = observed.wire["original_deadline_utc"]
    if (operation.deadline_utc is None or signed_deadline is None
            or operation.deadline_utc > signed_deadline or now >= operation.deadline_utc):
        raise AuthorityUnavailable("D07 model Owner caller exceeded its original signed deadline")
    return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        "host_d07_model_seal", graph, installed_d07_service, None, None, port, bundle,
        scope, observed.owner_acl_authority, observed.principal, observed.current_authority,
        None, operation, control, operation.selection_digest, scope.namespace,
        bundle.installation_policy.installation_id, bundle.installation_policy.administrator_holder,
        permit.pinned_anchor, permit.pinned_anchor, None, intent.subject, permit,
        observed, operation.deadline_utc, get_ident(), None, observed.model_authority, content)


_D07_STAGE_OWNER_ENTRIES_V3 = WeakKeyDictionary()


def _require_d07_stage_owner_caller_v3(proof):
    from ..runtime.domain_background_read_v3 import BackgroundReadWorkV3, _READERS
    reader = proof.request
    service, graph = proof.service, proof.graph
    if (type(reader) is not BackgroundReadWorkV3 or reader not in _READERS
            or reader.kind != "d07_stage" or reader.graph is not graph
            or reader.d07_service is not service or reader.bundle is not proof.bundle
            or reader.operation is not proof.retained_operation or reader.read_scope is not proof.scope
            or reader.fence is None or reader.fence.scope is not proof.scope
            or reader.graph_stamp != (reader.fence.metadata, reader.fence.epoch)
            or reader.work is None or reader.work.state is not reader
            or reader.work.operation is not reader.operation
            or graph._GraphCoordinator__d07_execution_service_v1 is not service
            or service.graph is not graph or service.bundle is not proof.bundle
            or graph._GraphCoordinator__content_fence_v2 is not proof.port
            or proof.scope.operation != "read" or proof.scope.permit != proof.original_permit):
        raise AuthorityUnavailable("D07 stage Owner metadata lost its actual private READ Work")
    reader.work._require_invocation(graph)
    _require_owner_operation_v3(proof.retained_operation, db=reader.db,
        namespace=reader.namespace, control=proof.control)


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class _HostD07StageReadOwnerEntryV3:
    issuer: InitVar[object]

    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable("D07 stage Owner entry requires its actual READ producer")

    @property
    def current_owner_authority(self):
        state = _D07_STAGE_OWNER_ENTRIES_V3.get(self)
        if state is None:
            raise AuthorityUnavailable("D07 stage Owner metadata entry ended")
        return state[0].current_owner_authority

    @property
    def current_owner_guard(self):
        return self.current_owner_authority.guard

    @property
    def owner_acl_authority(self):
        state = _D07_STAGE_OWNER_ENTRIES_V3.get(self)
        if state is None:
            raise AuthorityUnavailable("D07 stage Owner metadata entry ended")
        return state[3]

    def require_for_v3(self, reader):
        state = _D07_STAGE_OWNER_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable("D07 stage Owner entry crossed its actual READ Work")
        proof, work, facts, authority, principal, owner = state
        facts.require_for_v3(proof)
        current = proof.current_owner_authority
        actual = reader.graph._owner_graph_binding_from_current_metadata_v3(authority, principal,
            metadata=facts.metadata, graph_epoch=facts.graph_epoch, atom=facts.atom,
            proof_row=facts.proof_row, epochs=facts.epochs,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=current.guard)
        if actual != owner:
            raise AuthorityUnavailable("D07 stage actual metadata Owner binding changed")
        return actual

    def release_v3(self):
        state = _D07_STAGE_OWNER_ENTRIES_V3.pop(self, None)
        if state is not None:
            try:
                state[1].close_v3()
            finally:
                state[0].release_v3()


def prepare_current_host_d07_stage_owner_entry_v3(reader):
    """Use the actual phase READ; publish no business Frame or Self authority."""
    from ..runtime.domain_background_read_v3 import BackgroundReadWorkV3, _READERS
    from ..runtime.first_ingress_v2 import trusted_upper
    from ..graph_types import owner_grant_key, validate_owner_grant_v1
    if (type(reader) is not BackgroundReadWorkV3 or reader not in _READERS
            or reader.kind != "d07_stage" or reader.read_scope is None
            or reader.read_scope.operation != "read" or reader.db.in_transaction
            or reader.work is None or reader.work.state is not reader):
        raise AuthorityUnavailable("D07 stage metadata requires its actual already issued READ Scope")
    graph, service, scope, bundle = reader.graph, reader.d07_service, reader.read_scope, reader.bundle
    port = graph._GraphCoordinator__content_fence_v2
    _require_d07_installation_v3(graph, service, reader.bootstrap, bundle, port)
    policy = bundle.installation_policy
    if (scope.namespace != policy.namespace or scope.authority_namespace != policy.authority_namespace
            or scope.permit.holder != policy.administrator_holder
            or scope.permit.operation_id != scope.operation_id
            or port.validate_fence(scope) != scope.permit):
        raise AuthorityUnavailable("D07 stage metadata READ permit differs from actual installed admission")
    current, permit = port.get_current_background_owner_authority_for_fence_v1(
        namespace=scope.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
    if type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit:
        raise AuthorityUnavailable("D07 stage metadata lost its actual current Owner read observation")
    control = _require_owner_operation_v3(reader.operation, db=reader.db, namespace=reader.namespace)
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    if reader.operation.deadline_utc is not None and now >= reader.operation.deadline_utc:
        raise AuthorityUnavailable("D07 stage metadata exceeded its original Work deadline")
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        "host_d07_stage_read", graph, service, None, None, port, bundle, scope,
        None, None, current, None, reader.operation, control, reader.selection_digest,
        reader.namespace, policy.installation_id, policy.administrator_holder,
        scope.pinned_anchor, scope.pinned_anchor, None, scope.permit.subject,
        scope.permit, reader, reader.operation.deadline_utc, get_ident())
    work = None
    try:
        _require_owner_permission_outside_graph_v3(proof)
        work = prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = work.advance(meter=meter)
            if type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
                work.complete_reserved_quantum_v3(proof)
        facts = work.result.require_for_v3(proof)
        grant = json.loads(facts.atom[1])
        validate_owner_grant_v1(grant)
        principal = OwnerPrincipalV1(**grant["principal"])
        pairing = port.current_owner_principal_binding(namespace=scope.namespace,
            authority_namespace=scope.authority_namespace, principal=principal)
        if pairing is None or pairing.principal != principal or pairing.installation_id != policy.installation_id:
            raise AuthorityUnavailable("D07 stage metadata lost its actual current Owner pairing")
        authority = AuthorityContext(pairing.actor_id, "d12", owner_grant_key(*scope.namespace.as_tuple).token,
            scope.namespace, ("d11",), grant["purposes"][0], (grant["audiences"][0],),
            grant["issuer_ref"], scope.generation)
        owner = graph._owner_graph_binding_from_current_metadata_v3(authority, principal,
            metadata=facts.metadata, graph_epoch=facts.graph_epoch, atom=facts.atom,
            proof_row=facts.proof_row, epochs=facts.epochs,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=current.guard)
        if (owner.authorization_head != current.guard.authorization_head
                or owner.authorization_revision != current.guard.authorization_revision
                or current.guard.pending_revoke_operation_id is not None):
            raise AuthorityUnavailable("D07 stage metadata current Owner head changed")
        _require_owner_permission_outside_graph_v3(proof)
        entry = _HostD07StageReadOwnerEntryV3(_OWNER_CALLER_ISSUER_V3)
        _D07_STAGE_OWNER_ENTRIES_V3[entry] = (proof, work, facts, authority, principal, owner)
        return entry
    except BaseException as exc:
        if work is not None:
            work.cancel_v3(exc)
        proof.release_v3()
        raise


@contextmanager
def current_d07_model_policy_source_v3(model_service, *, credential, subject, intent, permit,
        location_observation=None):
    """Keep the actual qualified Source Work through Graph and installed policy checks."""
    owner_service = _D07_MODEL_SOURCE_OWNER_SERVICES_V3.get(model_service)
    if owner_service is None:
        raise AuthorityUnavailable("D07 policy Source reader was not installed on this model service")
    if model_service._store._db.in_transaction:
        raise AuthorityUnavailable("D07 policy Source qualification must precede Core SQL")
    proof = _create_d07_model_source_owner_caller_proof_v3(owner_service,
        model_service=model_service, credential=credential, subject=subject,
        original_permit=permit, intent=intent, now=model_service._graph_verifier._clock(),
        location_observation=location_observation, phase_issuer=_D07_MODEL_SOURCE_POLICY_PHASE_V3)
    try:
        from .d07_authority_model_source_read_v3 import (
            require_current_d07_authority_namespace_recipe_v3, PreparedD07AuthoritySourceMaterialV3)
        work = proof.request
        reader = require_current_d07_authority_namespace_recipe_v3(work)
        material = None if reader is None else reader.result
        if type(material) is not PreparedD07AuthoritySourceMaterialV3:
            raise AuthorityUnavailable("D07 policy has no exact actual completed Source material")
        material.require_for_observer_v3(work)
        yield material
    finally:
        proof.release_v3()



from weakref import WeakKeyDictionary, ref
import json

_D07_CONTENT_SCOPE_ISSUER_V3 = object()
_D07_CONTENT_SCOPES_V3 = WeakKeyDictionary()
_D07_SOURCE_SCOPE_FIELDS_V3 = frozenset((
    "schema", "kind", "namespace", "installation_id", "effective_source_authority",
    "model_authority", "owner_acl_authority", "prepared_digest", "request_digest",
    "job_id", "call_id", "acquire_operation_id", "permit_digest", "parent_budget_lease_ref",
    "reservation_digest", "delegation_originals", "source_versions",
    "source_authorization_digest", "query_inventory_digest", "access_epoch", "delete_epoch",
    "activation_generation", "selection_digest", "original_deadline_utc"))
_D07_SOURCE_SCOPE_KINDS_V3 = frozenset((
    "ordinary_owner", "ingress_recall_self", "relationship_self", "method_growth_self",
    "reflection", "general_growth_owner"))


def _d07_authority_from_plain_v3(raw):
    if type(raw) is not dict or set(raw) != set(AuthorityContext.__dataclass_fields__):
        raise AuthorityUnavailable("D07 source authority exact fields differ")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["owner_scope"] = tuple(value["owner_scope"])
    value["audience"] = tuple(value["audience"])
    return AuthorityContext(**value)


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class D07ContentSourceScopeV3:
    issuer: InitVar[object]
    wire_json: str
    effective_source_authority: AuthorityContext
    model_authority: AuthorityContext
    owner_acl_authority: AuthorityContext
    commitment: str

    def __post_init__(self, issuer):
        if issuer is not _D07_CONTENT_SCOPE_ISSUER_V3:
            raise AuthorityUnavailable("D07 content scope requires its actual qualified producer")
        raw = json.loads(self.wire_json)
        if (set(raw) != _D07_SOURCE_SCOPE_FIELDS_V3
                or raw["schema"] != "d07.content-source-scope.v3"
                or raw["kind"] not in _D07_SOURCE_SCOPE_KINDS_V3
                or canonical_digest(raw) != self.commitment):
            raise AuthorityUnavailable("D07 content scope does not preserve its exact signed domain")

    @property
    def original_deadline_utc(self):
        return json.loads(self.wire_json)["original_deadline_utc"]

    def release_v3(self):
        _D07_CONTENT_SCOPES_V3.pop(self, None)

    def require_for_v3(self, graph, service, bundle, operation, model_authority, permit):
        state = _D07_CONTENT_SCOPES_V3.get(self)
        if (state is None or state[0] != "host"
                or state[1]() is not graph or state[2]() is not service
                or state[3] is not bundle or state[4]() is not operation
                or operation.closed or model_authority != self.model_authority
                or state[6] != permit
                or operation.selection_digest != json.loads(self.wire_json)["selection_digest"]):
            raise AuthorityUnavailable("D07 Source scope crossed its actual model and retained consumer")
        observation = state[5]()
        require_verified_model_seal_owner_observation_v3(observation,
            port=graph._GraphCoordinator__content_fence_v2, installed_d07_service=service,
            bundle=bundle, intent=state[7], permit=permit)
        if (canonical_digest(observation.wire["content_source_scope"]) != self.commitment
                or observation.model_authority != self.model_authority
                or observation.owner_acl_authority != self.owner_acl_authority):
            raise AuthorityUnavailable("D07 Source and Owner scopes changed delegation")
        return self


def d07_content_source_scope_to_wire_v3(scope):
    if type(scope) is not D07ContentSourceScopeV3:
        raise AuthorityUnavailable("D07 source scope was not actually issued")
    state = _D07_CONTENT_SCOPES_V3.get(scope)
    if state is None:
        raise AuthorityUnavailable("D07 source scope producer lifetime ended")
    if state[0] == "server":
        work = state[1]()
        if work is None:
            raise AuthorityUnavailable("D07 source scope qualified Authority Work ended")
        work._actual()
    raw = json.loads(scope.wire_json)
    if canonical_digest(raw) != scope.commitment:
        raise AuthorityUnavailable("D07 source scope commitment changed")
    return raw


def _issue_d07_content_source_scope_v3(work, *, prepared, request, job, frozen,
        basis, source_material):
    from .d07_authority_model_source_read_v3 import PreparedD07AuthoritySourceMaterialV3
    if type(source_material) is not PreparedD07AuthoritySourceMaterialV3:
        raise AuthorityUnavailable("D07 Source scope requires the actual completed private material")
    actual = source_material.require_for_observer_v3(work)
    if actual != (prepared, job, frozen, request, basis) or actual[-1] is not basis:
        raise AuthorityUnavailable("D07 Source scope changed its actual fully qualified material")
    owner_acl_authority = basis.owner_acl_authority
    effective_source_authority = basis.effective_source_authority
    kind, delegation_originals = basis.kind, basis.delegation_originals
    from ..domains.d01.production_operations_v1 import plain_v1
    from .v2_contract import to_wire as fence_to_wire
    if (request.envelope.authority.actor != work.subject
            or request.envelope.authority.worker_fence != job.fence
            or request.envelope.authority.namespace != work.namespace
            or effective_source_authority.namespace != work.namespace
            or owner_acl_authority.namespace != work.namespace
            or effective_source_authority.purpose != prepared.purpose
            or effective_source_authority.audience != prepared.audience):
        raise AuthorityUnavailable("D07 source scope crossed the original authorized content")
    original = dict(schema="d07.content-source-scope.v3", kind=kind,
        namespace=plain_v1(work.namespace), installation_id=work.controller.control.installation_id,
        effective_source_authority=plain_v1(effective_source_authority),
        model_authority=plain_v1(request.envelope.authority),
        owner_acl_authority=plain_v1(owner_acl_authority),
        prepared_digest=prepared.digest, request_digest=request.digest, job_id=job.job_id,
        call_id=request.call_id, acquire_operation_id=request.identity.operation_id,
        permit_digest=canonical_digest(fence_to_wire(work.permit)),
        parent_budget_lease_ref=request.envelope.parent_budget_lease_ref,
        reservation_digest=prepared.reservation_digest,
        delegation_originals=plain_v1(tuple(delegation_originals)),
        source_versions=plain_v1(basis.source_versions),
        source_authorization_digest=basis.source_authorization_digest,
        query_inventory_digest=basis.query_inventory_digest,
        access_epoch=prepared.access_epoch, delete_epoch=prepared.delete_epoch,
        activation_generation=prepared.activation_generation,
        selection_digest=work.selection_digest, original_deadline_utc=basis.original_deadline_utc)
    if (basis.original_deadline_utc is None or work.deadline_utc is None
            or basis.original_deadline_utc > work.deadline_utc
            or work.controller.clock() >= basis.original_deadline_utc):
        raise AuthorityUnavailable("D07 Source scope exceeded its actual original deadline intersection")
    encoded = canonical_serialize(original)
    scope = D07ContentSourceScopeV3(_D07_CONTENT_SCOPE_ISSUER_V3, encoded,
        effective_source_authority, request.envelope.authority, owner_acl_authority,
        canonical_digest(original))
    _D07_CONTENT_SCOPES_V3[scope] = ("server", ref(work))
    return scope


def accept_verified_d07_content_source_scope_v3(observation, *, graph,
        installed_d07_service, bundle, intent, permit, operation):
    require_verified_model_seal_owner_observation_v3(observation,
        port=graph._GraphCoordinator__content_fence_v2, installed_d07_service=installed_d07_service,
        bundle=bundle, intent=intent, permit=permit)
    raw = observation.wire["content_source_scope"]
    if (type(raw) is not dict or set(raw) != _D07_SOURCE_SCOPE_FIELDS_V3
            or raw["namespace"] != asdict(bundle.installation_policy.namespace)
            or raw["installation_id"] != bundle.installation_policy.installation_id
            or raw["job_id"] != intent.job_id or raw["call_id"] != intent.call_id
            or raw["prepared_digest"] != intent.binding_digest
            or raw["request_digest"] != intent.request_digest
            or raw["acquire_operation_id"] != intent.acquire_operation_id
            or raw["parent_budget_lease_ref"] != intent.budget_lease_id
            or raw["reservation_digest"] != intent.budget_reservation_digest
            or raw["selection_digest"] != operation.selection_digest
            or operation.deadline_utc is None or raw["original_deadline_utc"] is None
            or operation.deadline_utc > raw["original_deadline_utc"]
            or raw["permit_digest"] != canonical_digest(fence_to_wire(permit))
            or (raw["access_epoch"], raw["delete_epoch"], raw["activation_generation"]) !=
                (intent.access_epoch, intent.delete_epoch, intent.authority_activation_generation)):
        raise AuthorityUnavailable("D07 signed Source scope changed original current execution")
    effective = _d07_authority_from_plain_v3(raw["effective_source_authority"])
    model = _d07_authority_from_plain_v3(raw["model_authority"])
    owner = _d07_authority_from_plain_v3(raw["owner_acl_authority"])
    if model != observation.model_authority or owner != observation.owner_acl_authority:
        raise AuthorityUnavailable("D07 Source scope changed its exact independent authorities")
    scope = D07ContentSourceScopeV3(_D07_CONTENT_SCOPE_ISSUER_V3, canonical_serialize(raw),
        effective, model, owner, canonical_digest(raw))
    _D07_CONTENT_SCOPES_V3[scope] = ("host", ref(graph), ref(installed_d07_service),
        bundle, ref(operation), ref(observation), permit, intent)
    return scope


# Host D07 adapter section for authority_service/owner_location_read_v3.py.
# The named CallerProof factories and metered IO Work below are Root's unique
# implementation in this same module. No adapter creates an Owner grant.
from dataclasses import dataclass
from weakref import WeakKeyDictionary, ref
from hashlib import sha256
from ..runtime_contracts import FenceScope, AuthorityContext, NamespaceId, canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, to_wire as fence_to_wire, from_wire as fence_from_wire
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_model_egress_wire import to_wire as model_to_wire, from_wire as model_from_wire
from .v2_owner_contract import OwnerPrincipalV1
from .d12_target_owner_admission_v1 import (
    D12CurrentOwnerAuthorityV1, current_owner_authority_to_wire_v1,
    current_owner_authority_from_wire_v1)

_D07_OWNER_ISSUER_V3 = object()
_D07_VERIFIED_OBSERVATIONS_V3 = WeakKeyDictionary()
_D07_WRITE_ENTRIES_V3 = WeakKeyDictionary()
_D07_MODEL_BINDINGS_V3 = WeakKeyDictionary()
D07_MODEL_OWNER_OBSERVER_METHOD_V3 = "d07_current_model_seal_owner_observe_v3"
D07_MODEL_OWNER_OBSERVER_SIGN_V3 = "d11.d07-model-seal-owner-observation.v3"
D07_MODEL_OWNER_OBSERVER_SCHEMA_V3 = "d07.actual-model-seal-owner-observation.v3"


def _require_d07_installation_v3(graph, service, bootstrap, bundle, port):
    from ..host.v2_fence_port import V2FencePort
    from ..runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    graph._admin(bootstrap)
    if (type(service) is not InstalledD07ExecutionServiceV1
            or service.graph is not graph or service.bundle is not bundle
            or service.bootstrap is not bootstrap
            or graph._GraphCoordinator__d07_execution_service_v1 is not service
            or graph._GraphCoordinator__content_fence_v2 is not port
            or type(port) is not V2FencePort):
        raise AuthorityUnavailable("actual installed Host D07/port/Graph identity differs")


def _d07_owner_graph_binding_v3(graph, proof, facts):
    current = proof.current_owner_authority
    return graph._owner_graph_binding_from_current_metadata_v3(
        proof.authority, proof.principal,
        metadata=facts.metadata, graph_epoch=facts.graph_epoch,
        atom=facts.atom, proof_row=facts.proof_row, epochs=facts.epochs,
        target_admission=current.target_admission,
        storage_admission=current.storage_admission, current_guard=current.guard)


def _complete_d07_owner_work_before_transaction_v3(graph, proof, work):
    """Only current metadata IO, over the original operation's bounded quanta."""
    store = graph._GraphCoordinator__store
    if store._db.in_transaction:
        raise AuthorityUnavailable("D07 Owner EOF preparation must precede SQL BEGIN")
    while True:
        with store._lock, owner_location_read_quantum_v3(proof) as meter:
            # Work owns the installed location selection and checks its fixed
            # CallerProof before/after every bounded actual IO advance.
            progress = work.advance(meter=meter)
        if type(progress) is OwnerLocationGraphFactsV3:
            facts = progress
        elif type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
            facts = work.complete_reserved_quantum_v3(proof)
        else:
            continue
        return facts.require_for_v3(proof)


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class _HostD07WriteOwnerEntryV3:
    issuer: object

    def require_for_v3(self, graph, scope, current_authority, authority):
        state = _D07_WRITE_ENTRIES_V3.get(self)
        if (self.issuer is not _D07_OWNER_ISSUER_V3 or state is None
                or state.graph() is not graph or state.scope is not scope
                or state.current_authority != current_authority
                or state.authority is not authority or state.owner is None):
            raise AuthorityUnavailable("D07 WRITE private entry differs from its actual caller")
        require_owner_location_caller_proof_v3(
            state.proof, phase="after", graph_stamp=state.graph_stamp)
        return state.owner

    def release_v3(self):
        state = _D07_WRITE_ENTRIES_V3.pop(self, None)
        if state is not None:
            try:
                state.work.close_v3()
            finally:
                state.proof.release_v3()


@dataclass(slots=True)
class _D07WriteOwnerStateV3:
    graph: object
    service: object
    bundle: object
    scope: FenceScope
    current_authority: D12CurrentOwnerAuthorityV1
    principal: OwnerPrincipalV1
    authority: AuthorityContext
    operation: object
    proof: object
    work: object
    graph_stamp: tuple
    facts: object
    owner: object = None


def prepare_current_host_d07_write_owner_entry_v3(graph, *, port,
        installed_d07_service, bootstrap, bundle, scope, current_authority,
        principal, authority, operation):
    """Actual RPC/controller issuance and whole Owner EOF before BEGIN."""
    _require_d07_installation_v3(graph, installed_d07_service, bootstrap, bundle, port)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable("D07 WRITE Owner RPC cannot run in a business transaction")
    if (type(scope) is not FenceScope or scope.operation != "write"
            or type(current_authority) is not D12CurrentOwnerAuthorityV1
            or type(principal) is not OwnerPrincipalV1 or type(authority) is not AuthorityContext
            or (scope.namespace, scope.generation) !=
               (authority.namespace, authority.activation_generation)):
        raise AuthorityUnavailable("D07 WRITE actual scope/Owner selectors differ")
    # This Root factory performs real port.validate_fence/current-D12/pairing,
    # retains this exact operation, and registers its private CallerProof.
    proof = create_host_d07_write_owner_caller_proof_v3(
        graph, port=port, installed_d07_service=installed_d07_service,
        bootstrap=bootstrap, bundle=bundle, scope=scope,
        current_authority=current_authority, principal=principal,
        authority=authority, operation=operation)
    work = None
    try:
        work = prepare_owner_location_read_work_v3(proof)
        facts = _complete_d07_owner_work_before_transaction_v3(graph, proof, work)
        if (facts.metadata.graph_revision, facts.graph_epoch) != (
                scope.graph_revision, scope.graph_epoch):
            raise AuthorityUnavailable("D07 WRITE Owner metadata stamp changed")
        entry = _HostD07WriteOwnerEntryV3(_D07_OWNER_ISSUER_V3)
        _D07_WRITE_ENTRIES_V3[entry] = _D07WriteOwnerStateV3(
            ref(graph), ref(installed_d07_service), bundle, scope, current_authority,
            principal, authority, operation, proof, work,
            (facts.metadata, facts.graph_epoch), facts, _d07_owner_graph_binding_v3(graph, proof, facts))
        return entry
    except BaseException as exc:
        try:
            if work is not None: work.cancel_v3(exc)
        finally:
            proof.release_v3()
        raise


def resolve_current_host_d07_write_owner_binding_v3(graph, *,
        installed_d07_service, bootstrap, bundle, scope, current_authority,
        principal, authority, operation, meter, owner_entry):
    """No RPC and no body read: consume the private, completed WRITE entry."""
    port = graph._GraphCoordinator__content_fence_v2
    _require_d07_installation_v3(graph, installed_d07_service, bootstrap, bundle, port)
    state = _D07_WRITE_ENTRIES_V3.get(owner_entry)
    if (type(owner_entry) is not _HostD07WriteOwnerEntryV3 or state is None
            or state.graph() is not graph or state.service() is not installed_d07_service
            or state.bundle is not bundle or state.scope is not scope
            or state.current_authority != current_authority or state.principal != principal
            or state.authority is not authority or state.operation is not operation
            or not graph._GraphCoordinator__store._db.in_transaction):
        raise AuthorityUnavailable("D07 WRITE consumed another private entry or original operation")
    # Full canonical Owner EOF was established before BEGIN. Root's current
    # same-stamp proof check does no RPC, no cell advance and no body allocation.
    facts = state.facts.require_for_v3(state.proof)
    if (facts.metadata, facts.graph_epoch) != state.graph_stamp:
        raise AuthorityUnavailable("D07 WRITE completed Owner EOF proof drifted")
    if _d07_owner_graph_binding_v3(graph, state.proof, facts) != state.owner:
        raise AuthorityUnavailable("D07 WRITE actual Owner binding changed")
    return owner_entry


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class _VerifiedD07ModelOwnerObservationV3:
    issuer: object
    wire: dict
    current_authority: D12CurrentOwnerAuthorityV1
    principal: OwnerPrincipalV1
    owner_acl_authority: AuthorityContext
    model_authority: AuthorityContext


def require_verified_model_seal_owner_observation_v3(observation, *, port,
        installed_d07_service, bundle, intent, permit):
    registered = _D07_VERIFIED_OBSERVATIONS_V3.get(observation)
    if (type(observation) is not _VerifiedD07ModelOwnerObservationV3
            or observation.issuer is not _D07_OWNER_ISSUER_V3 or registered is None
            or registered[0]() is not port or registered[1]() is not installed_d07_service
            or registered[2] is not bundle
            or registered[3] != canonical_digest(model_to_wire(intent))
            or registered[4] != canonical_digest(fence_to_wire(permit))
            or registered[5] != canonical_digest(observation.wire)):
        raise AuthorityUnavailable("model Owner observation was not issued by its actual RPC consumer")
    raw = observation.wire
    if (raw["intent_digest"] != registered[3] or raw["permit"] != fence_to_wire(permit)
            or raw["job_id"] != intent.job_id
            or raw["namespace"] != list(bundle.installation_policy.namespace.as_tuple)
            or raw["installation_id"] != bundle.installation_policy.installation_id):
        raise AuthorityUnavailable("model Owner observation crossed original intent/installation")
    return observation


def _model_owner_observer_request_v3(bundle, intent, permit, job_id, graph_stamp, clock_policy):
    metadata, epoch = graph_stamp
    if (type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2
            or permit.operation != "model_egress" or job_id != intent.job_id
            or (intent.namespace, intent.subject, intent.operation_id) !=
               (permit.namespace, permit.subject, permit.operation_id)
            or (intent.fence_token, intent.fence_epoch, intent.fence_revision) !=
               (permit.token, permit.fence_epoch, permit.revision)
            or intent.anchor_digest != canonical_digest(fence_to_wire(permit)["pinned_anchor"])
            or clock_policy is not bundle.ingress_clock):
        raise AuthorityUnavailable("D07 model observation requires the original live model permit")
    return {"namespace": intent.namespace, "intent": model_to_wire(intent),
        "permit": fence_to_wire(permit), "job_id": job_id,
        "graph_stamp_digest": canonical_digest(graph_stamp),
        "clock_policy_digest": canonical_digest(clock_policy),
        "installation_id": bundle.installation_policy.installation_id}


def _observe_host_d07_model_owner_v3(port, service, bundle, intent, permit,
        job_id, graph_stamp, clock_policy):
    command = _model_owner_observer_request_v3(bundle, intent, permit, job_id, graph_stamp, clock_policy)
    async def call():
        from .v2_contract import SCHEMA
        await port._mapped(bundle.installation_policy.namespace, intent.namespace)
        handshake, grant = port._identity()
        if ((grant.authority_id, grant.subject, grant.administrator_holder, grant.installation_id) !=
                (permit.authority_id, permit.subject, permit.holder, command["installation_id"])):
            raise AuthorityUnavailable("D07 observer crossed actual installed Host pairing")
        result = await port._transport._content_rpc(
            port._request, handshake, D07_MODEL_OWNER_OBSERVER_METHOD_V3,
            command, protocol=SCHEMA)
        if set(result) != {"observation", "signature", "channel_binding_sha256"}:
            raise AuthorityUnavailable("D07 observer exact authenticated response differs")
        raw = result["observation"]
        encoded = canonical_serialize(raw)
        service.d11_issuer._signer.verify(D07_MODEL_OWNER_OBSERVER_SIGN_V3, encoded, result["signature"])
        if (set(raw) != D07_MODEL_OWNER_OBSERVER_FIELDS_V3
                or raw["schema"] != D07_MODEL_OWNER_OBSERVER_SCHEMA_V3
                or raw["intent_digest"] != canonical_digest(model_to_wire(intent))
                or raw["permit"] != fence_to_wire(permit) or raw["job_id"] != job_id
                or raw["graph_stamp_digest"] != command["graph_stamp_digest"]
                or raw["clock_policy_digest"] != command["clock_policy_digest"]
                or raw["installation_id"] != command["installation_id"]
                or raw["authority_id"] != permit.authority_id
                or raw["authority_namespace"] != intent.namespace or raw["subject"] != intent.subject
                or raw["holder"] != permit.holder or raw["namespace"] != list(bundle.installation_policy.namespace.as_tuple)
                or (raw["call_id"], raw["acquire_operation_id"], raw["prepared_digest"], raw["request_digest"],
                    raw["worker_fence"], raw["access_epoch"], raw["delete_epoch"], raw["activation_generation"]) !=
                   (intent.call_id, intent.acquire_operation_id, intent.binding_digest, intent.request_digest,
                    intent.worker_fence, intent.access_epoch, intent.delete_epoch, intent.authority_activation_generation)
                or raw["permission_anchor"] != fence_to_wire(permit)["pinned_anchor"]):
            raise AuthorityUnavailable("D07 signed observer changed original permit/intent/stamp/clock")
        current = current_owner_authority_from_wire_v1(raw["current_owner_authority"])
        principal = OwnerPrincipalV1(**raw["principal"])
        def decode_authority(data):
            value = dict(data)
            value["namespace"] = NamespaceId(**value["namespace"])
            value["owner_scope"] = tuple(value["owner_scope"])
            value["audience"] = tuple(value["audience"])
            return AuthorityContext(**value)
        owner_acl_authority = decode_authority(raw["owner_acl_authority"])
        model_authority = decode_authority(raw["model_authority"])
        if (canonical_digest(owner_acl_authority) != raw["owner_acl_authority_commitment"]
                or canonical_digest(model_authority) != raw["model_authority_commitment"]
                or canonical_digest(raw["content_source_scope"]) != raw["content_source_scope_commitment"]
                or model_authority.actor != intent.subject or model_authority.worker_fence != intent.worker_fence
                or model_authority.namespace != bundle.installation_policy.namespace):
            raise AuthorityUnavailable("D07 signed Owner ACL/model/effective Source commitments differ")
        value = _VerifiedD07ModelOwnerObservationV3(
            _D07_OWNER_ISSUER_V3, raw, current, principal, owner_acl_authority, model_authority)
        _D07_VERIFIED_OBSERVATIONS_V3[value] = (
            ref(port), ref(service), bundle,
            raw["intent_digest"], canonical_digest(fence_to_wire(permit)), canonical_digest(raw))
        return value
    return port._submit(port._with_session_repair(call))


D07_MODEL_OWNER_OBSERVER_FIELDS_V3 = frozenset((
    "schema", "authority_id", "authority_namespace", "namespace", "installation_id",
    "subject", "holder", "intent_digest", "permit", "job_id", "graph_stamp_digest",
    "clock_policy_digest", "current_owner_authority", "principal",
    "owner_acl_authority", "owner_acl_authority_commitment", "model_authority", "model_authority_commitment",
    "content_source_scope", "content_source_scope_commitment", "call_id", "acquire_operation_id",
    "prepared_digest", "request_digest", "worker_fence", "access_epoch", "delete_epoch", "activation_generation",
    "owner_head_commitment", "selection_digest", "permission_anchor",
    "graph_comparison_anchor", "original_deadline_utc"))


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class D07ActualModelSealReadBindingV3:
    issuer: object

    def _state_v3(self):
        state = _D07_MODEL_BINDINGS_V3.get(self)
        if self.issuer is not _D07_OWNER_ISSUER_V3 or state is None:
            raise AuthorityUnavailable("D07 model seal private binding was not actually issued")
        return state

    @property
    def owner_acl_authority(self): return self._state_v3().observation.owner_acl_authority
    @property
    def model_authority(self): return self._state_v3().observation.model_authority
    @property
    def content_source_scope(self):
        value = self._state_v3().content_source_scope
        if type(value) is not D07ContentSourceScopeV3:
            raise AuthorityUnavailable("D07 original effective Source delegation is not qualified")
        return value
    @property
    def effective_source_authority(self): return self.content_source_scope.effective_source_authority
    @property
    def owner_guard(self): return self._state_v3().observation.current_authority.guard
    @property
    def owner(self):
        state = self._state_v3()
        if state.owner is None: raise AuthorityUnavailable("D07 model Owner EOF is not complete")
        return state.owner
    @property
    def scope(self): return self._state_v3().scope
    @property
    def intent(self): return self._state_v3().intent
    @property
    def permit(self): return self._state_v3().permit
    @property
    def graph_stamp(self): return self._state_v3().graph_stamp
    @property
    def original_deadline_utc(self):
        return self._state_v3().observation.wire["content_source_scope"]["original_deadline_utc"]

    def require_for_work_v3(self, graph, service, bundle, operation):
        state = self._state_v3()
        if (state.graph() is not graph or state.service() is not service or state.bundle is not bundle
                or state.operation is not None and state.operation() is not operation):
            raise AuthorityUnavailable("D07 model seal binding crossed its actual original Work")
        if state.operation is None:
            content_scope = proof = work = None
            try:
                content_scope = accept_verified_d07_content_source_scope_v3(
                    state.observation, graph=graph, installed_d07_service=service, bundle=bundle,
                    intent=state.intent, permit=state.permit, operation=operation)
                if type(content_scope) is not D07ContentSourceScopeV3:
                    raise AuthorityUnavailable("D07 Source scope was not issued by its exact original factory")
                content_scope.require_for_v3(graph, service, bundle, operation,
                    state.observation.model_authority, state.permit)
                if (content_scope.owner_acl_authority != state.observation.owner_acl_authority
                        or content_scope.model_authority != state.observation.model_authority
                        or canonical_digest(d07_content_source_scope_to_wire_v3(content_scope)) !=
                           state.observation.wire["content_source_scope_commitment"]):
                    raise AuthorityUnavailable("D07 actual Source delegation differs from the signed observer")
                state.content_source_scope = content_scope
                proof = accept_host_d07_model_seal_owner_caller_proof_v3(
                    graph, port=state.port(), installed_d07_service=service, bundle=bundle,
                    verified_observation=state.observation, scope=state.scope,
                    intent=state.intent, permit=state.permit, operation=operation,
                    clock_policy=state.clock_policy)
                work = prepare_owner_location_read_work_v3(proof)
                state.proof, state.work, state.operation = proof, work, ref(operation)
                facts = _complete_d07_owner_work_before_transaction_v3(graph, proof, work)
                if (facts.metadata, facts.graph_epoch) != state.graph_stamp:
                    raise AuthorityUnavailable("D07 model original Graph stamp changed")
                state.facts = facts
                state.owner = _d07_owner_graph_binding_v3(graph, proof, facts)
            except BaseException as exc:
                try:
                    if work is not None: work.cancel_v3(exc)
                finally:
                    try:
                        if proof is not None: proof.release_v3()
                    finally:
                        if content_scope is not None: content_scope.release_v3()
                        state.proof = state.work = state.operation = state.facts = state.owner = state.content_source_scope = None
                raise
        require_owner_location_caller_proof_v3(
            state.proof, phase="before", graph_stamp=state.graph_stamp)
        return self

    def observe_current_for_work_v3(self, reader):
        state = self._state_v3()
        if state.operation is None or state.operation() is not reader.operation:
            raise AuthorityUnavailable("D07 model observer crossed its retained Work")
        graph = state.graph()
        if graph._GraphCoordinator__store._db.in_transaction:
            raise AuthorityUnavailable("D07 model observer RPC must precede SQL BEGIN")
        observed = _observe_host_d07_model_owner_v3(
            state.port(), state.service(), state.bundle, state.intent, state.permit,
            state.intent.job_id, state.graph_stamp, state.clock_policy)
        require_verified_model_seal_owner_observation_v3(
            observed, port=state.port(), installed_d07_service=state.service(),
            bundle=state.bundle, intent=state.intent, permit=state.permit)
        if (observed.current_authority != state.observation.current_authority
                or observed.principal != state.observation.principal
                or observed.owner_acl_authority != state.observation.owner_acl_authority
                or observed.model_authority != state.observation.model_authority
                or observed.wire["content_source_scope_commitment"] != state.observation.wire["content_source_scope_commitment"]
                or observed.wire["owner_head_commitment"] != state.observation.wire["owner_head_commitment"]
                or observed.wire["selection_digest"] != state.observation.wire["selection_digest"]):
            raise AuthorityUnavailable("D07 model Source/Owner/controller observation changed")
        state.content_source_scope.require_for_v3(
            graph, state.service(), state.bundle, reader.operation,
            state.observation.model_authority, state.permit)
        require_owner_location_caller_proof_v3(
            state.proof, phase="before", graph_stamp=state.graph_stamp)
        return observed.current_authority.guard

    def require_current_data_v3(self, reader, meter):
        state = self._state_v3()
        if (state.operation is None or state.operation() is not reader.operation
                or reader.read_scope is not state.scope or reader.owner != state.owner):
            raise AuthorityUnavailable("D07 model data crossed current exact Work/Scope/Owner")
        state.content_source_scope.require_for_v3(
            state.graph(), state.service(), state.bundle, reader.operation,
            state.observation.model_authority, state.permit)
        facts = state.facts.require_for_v3(state.proof)
        if (facts.metadata, facts.graph_epoch) != state.graph_stamp:
            raise AuthorityUnavailable("D07 model completed Owner metadata EOF changed")

    def release_v3(self):
        state = _D07_MODEL_BINDINGS_V3.pop(self, None)
        if state is not None:
            _D07_VERIFIED_OBSERVATIONS_V3.pop(state.observation, None)
            try:
                if state.work is not None: state.work.close_v3()
            finally:
                try:
                    if state.proof is not None: state.proof.release_v3()
                finally:
                    if state.content_source_scope is not None: state.content_source_scope.release_v3()


@dataclass(slots=True)
class _D07ModelOwnerStateV3:
    graph: object
    service: object
    port: object
    bundle: object
    intent: ModelEgressIntentV1
    permit: FencePermitV2
    clock_policy: object
    observation: _VerifiedD07ModelOwnerObservationV3
    scope: FenceScope
    graph_stamp: tuple
    operation: object = None
    proof: object = None
    work: object = None
    facts: object = None
    owner: object = None
    content_source_scope: object = None


def prepare_current_d07_model_seal_binding_v3(port, *, installed_d07_service,
        installed_bundle, intent, permit, job_id, graph_stamp, clock_policy):
    service, bundle = installed_d07_service, installed_bundle
    graph = service.graph
    _require_d07_installation_v3(graph, service, service.bootstrap, bundle, port)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable("D07 model seal preparation cannot perform RPC in SQL")
    observed = _observe_host_d07_model_owner_v3(
        port, service, bundle, intent, permit, job_id, graph_stamp, clock_policy)
    metadata, epoch = graph_stamp
    scope = FenceScope(bundle.installation_policy.namespace, intent.namespace,
        permit.generation, "model_egress", permit.operation_id, permit,
        permit.pinned_anchor, epoch, metadata.graph_revision)
    binding = D07ActualModelSealReadBindingV3(_D07_OWNER_ISSUER_V3)
    _D07_MODEL_BINDINGS_V3[binding] = _D07ModelOwnerStateV3(
        ref(graph), ref(service), ref(port), bundle, intent, permit, clock_policy,
        observed, scope, graph_stamp)
    return binding

def _d07_model_head_commitment_v3(value):
    from dataclasses import is_dataclass, asdict
    def metadata(item):
        if type(item) is bytes:
            return {"sha256": sha256(item).hexdigest(), "bytes": len(item)}
        if is_dataclass(item): return metadata(asdict(item))
        if type(item) in (tuple, list): return [metadata(v) for v in item]
        if type(item) is dict: return {k:metadata(v) for k,v in item.items()}
        return item
    return canonical_digest(metadata(value))


def install_d07_model_seal_owner_observer_v3(server, owner_service):
    """Configured routing to the actual installed Root Owner-location service."""
    key = (owner_service.namespace, owner_service.installation_id)
    model = server._v2_model_egress.get(key[0])
    if (model is None or model._fences is not server._v2_fences.get(key[0])
            or model._fences.core is not server._core
            or owner_service.core is not server._core
            or owner_service.fences is not model._fences):
        raise AuthorityUnavailable("D07 observer must use the actual same Core/fences/Owner service")
    routes = getattr(server, "_d07_model_seal_owner_observers_v3", None)
    if routes is None:
        routes = {}
        server._d07_model_seal_owner_observers_v3 = routes
    if key in routes and routes[key] is not owner_service:
        raise AuthorityUnavailable("D07 model Owner observer installation is already bound")
    prior = _D07_MODEL_SOURCE_OWNER_SERVICES_V3.get(model)
    if prior is not None and prior is not owner_service:
        raise AuthorityUnavailable("D07 policy Source reader cannot change its actual installed Owner service")
    routes[key] = owner_service
    _D07_MODEL_SOURCE_OWNER_SERVICES_V3[model] = owner_service


def _lookup_d07_model_observer_original_v3(model, credential, subject, holder, intent, installation_id):
    result = model.lookup_original_intent_v1(
        credential=credential, subject=subject, holder=holder,
        authority_id=intent.authority_id, installation_id=installation_id,
        namespace=intent.namespace, job_id=intent.job_id,
        acquire_operation_id=intent.acquire_operation_id,
        original_model_operation_id=intent.operation_id, call_id=intent.call_id,
        request_digest=intent.request_digest, binding_digest=intent.binding_digest)
    if result is None or result[0].intent != intent or result[0].state != "prepared":
        raise AuthorityUnavailable("D07 seal observer requires the actual unconsumed prepared model original")
    return result


def dispatch_current_d07_model_seal_owner_observe_v3(server, method, command, *,
        credential, profile_id, manifest_digest):
    """Closed authenticated observer; no admission, dispatch, begin or finish."""
    if method != D07_MODEL_OWNER_OBSERVER_METHOD_V3: return None
    expected = {"namespace", "intent", "permit", "job_id", "graph_stamp_digest",
        "clock_policy_digest", "installation_id"}
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("D07 model Owner observer exact command fields differ")
    namespace = command["namespace"]
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    subject = "mtls:sha256:" + credential.certificate_sha256
    model = server._v2_model_egress.get(namespace)
    owner_service = getattr(server, "_d07_model_seal_owner_observers_v3", {}).get(
        (namespace, installed.installation_id))
    intent = model_from_wire(command["intent"], ModelEgressIntentV1)
    permit = fence_from_wire(command["permit"])
    if (model is None or owner_service is None or model._fences is not fences
            or server._model_observers_v2.get(namespace) != (credential.certificate_sha256, profile_id)
            or type(permit) is not FencePermitV2 or permit.operation != "model_egress"
            or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
               (intent.authority_id, namespace, subject, installed.administrator_holder)
            or (intent.subject, intent.namespace, intent.job_id, intent.operation_id) !=
               (subject, namespace, command["job_id"], permit.operation_id)
            or command["installation_id"] != installed.installation_id):
        raise AuthorityUnavailable("D07 model observer crossed actual installed controller/permit/original")
    fences.core._require(credential, "model_egress", namespace, installed.administrator_holder)
    if fences.validate_fence(credential=credential, subject=subject, permit=permit) != permit:
        raise AuthorityUnavailable("D07 observer original model permit changed")
    before = _lookup_d07_model_observer_original_v3(
        model, credential, subject, installed.administrator_holder, intent, installed.installation_id)
    if before[1] != permit:
        raise AuthorityUnavailable("D07 observer did not receive its original durable model fence")
    now = model._graph_verifier._clock()
    # The Root factory qualifies the real D07 acquired worker, prepared/request,
    # quote/reservation, all current Source rights, Owner head and actual
    # model-controller location. It registers its private CallerProof; neither
    # this command nor an Owner DTO can issue that proof.
    proof = create_model_seal_owner_caller_proof_v3(
        owner_service, model_service=model, credential=credential, subject=subject,
        original_permit=permit, intent=intent, now=now)
    work = None
    try:
        work = prepare_owner_location_read_work_v3(proof)
        while True:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = work.advance(meter=meter)
            if type(progress) is OwnerLocationGraphFactsV3:
                facts = progress
                break
            if type(progress) is dict and progress.get("phase") == "owner_location_quantum_commit":
                facts = work.complete_reserved_quantum_v3(proof)
                break
        facts.require_for_v3(proof)
        stamp = (facts.metadata, facts.graph_epoch)
        require_owner_location_caller_proof_v3(proof, phase="after", graph_stamp=stamp)
        if (canonical_digest(stamp) != command["graph_stamp_digest"]
                or proof.clock_policy_digest != command["clock_policy_digest"]
                or proof.namespace != proof.current_owner_authority.guard.namespace
                or proof.installation_id != installed.installation_id
                or proof.holder != installed.administrator_holder):
            raise AuthorityUnavailable("D07 observer current Graph/Owner/clock/install differs")
        after = _lookup_d07_model_observer_original_v3(
            model, credential, subject, installed.administrator_holder, intent, installed.installation_id)
        if after != before or fences.validate_fence(
                credential=credential, subject=subject, permit=permit) != permit:
            raise AuthorityUnavailable("D07 original model state changed across current Owner observation")
        from ..domains.d01.production_operations_v1 import plain_v1
        scope = proof.content_source_scope
        if type(scope) is not D07ContentSourceScopeV3:
            raise AuthorityUnavailable("server model proof lacks its actual tagged Source delegation")
        if scope.owner_acl_authority != proof.authority or scope.model_authority != proof.model_authority:
            raise AuthorityUnavailable("server Owner ACL and actual model request scope differ")
        scope_wire = d07_content_source_scope_to_wire_v3(scope)
        wire = {"schema": D07_MODEL_OWNER_OBSERVER_SCHEMA_V3,
            "authority_id": intent.authority_id, "authority_namespace": namespace,
            "namespace": list(proof.namespace.as_tuple),
            "installation_id": installed.installation_id, "subject": subject,
            "holder": installed.administrator_holder,
            "intent_digest": canonical_digest(model_to_wire(intent)),
            "permit": fence_to_wire(permit), "job_id": intent.job_id,
            "graph_stamp_digest": canonical_digest(stamp),
            "clock_policy_digest": proof.clock_policy_digest,
            "current_owner_authority": current_owner_authority_to_wire_v1(proof.current_owner_authority),
            "principal": plain_v1(proof.principal),
            "owner_acl_authority": plain_v1(proof.authority),
            "owner_acl_authority_commitment": canonical_digest(proof.authority),
            "model_authority": plain_v1(proof.model_authority),
            "model_authority_commitment": canonical_digest(proof.model_authority),
            "content_source_scope": scope_wire, "content_source_scope_commitment": canonical_digest(scope_wire),
            "call_id": intent.call_id, "acquire_operation_id": intent.acquire_operation_id,
            "prepared_digest": intent.binding_digest, "request_digest": intent.request_digest,
            "worker_fence": intent.worker_fence, "access_epoch": intent.access_epoch, "delete_epoch": intent.delete_epoch,
            "activation_generation": intent.authority_activation_generation,
            "owner_head_commitment": _d07_model_head_commitment_v3(proof.current_owner_head),
            "selection_digest": proof.selection_digest,
            "permission_anchor": plain_v1(permit.pinned_anchor),
            "graph_comparison_anchor": plain_v1(proof.graph_comparison_anchor),
            "original_deadline_utc": proof.original_deadline_utc}
        encoded = canonical_serialize(wire)
        response_size = len(canonical_serialize({"request_id":"0"*32, "ok":True,
            "result":{"observation":wire, "signature":"0"*64, "channel_binding_sha256":"0"*64}}).encode("utf8")) + 1
        if response_size > 65536:
            raise AuthorityUnavailable("D07 full signed metadata observer exceeds the existing frame bound")
        signature = model._graph_verifier._issuer._signer.sign(
            D07_MODEL_OWNER_OBSERVER_SIGN_V3, encoded)
        return {"observation":wire, "signature":signature}
    finally:
        try:
            if work is not None: work.close_v3()
        finally:
            proof.release_v3()


from dataclasses import InitVar, asdict, dataclass
from weakref import WeakSet
import json

from .contract import AuthorityUnavailable
from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
from .c09_close_apply_v1 import SelectedAppliedReadV3, _SELECTED_APPLIED_V3
from .c09_paged_recovery_facts_v2 import (
    C09VerifiedLegacyPreparedSummaryV2, C09VerifiedPagedPreparedSummaryV2, _TOKEN as _PREPARED_TOKEN_V3)
from .c09_prepared_storage_v3 import C09VerifiedPagedPreparedSummaryV3
from .c09_graph_rebase_issue_v1 import AuthorityGraphRebaseIssuedV1
from .c09_graph_rebase_issue_v2 import AuthorityGraphRebaseIssuedV2
from .c09_storage_control_v1 import digest as _control_digest_v3
from .d12_owner_storage_admission_v1 import D12OwnerStorageAdmissionV1
from .d12_c09_target_continuation_v1 import D12C09TargetContinuationV1
from .v2_owner_contract import OwnerMigrationHeadV1
from .v2_migration_contract import MigrationStatusV2
from .v2_contract import DeletionMutationReceiptV1
from ..graph_store import GraphRecoveryMetadataV2
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime.c09_storage_rebase_contract_v1 import GraphErasureRebaseCertificateV1
from ..runtime.c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2
from ..runtime.lifecycle_operations_v1 import digest as _owner_wire_digest_v3
from ..runtime_contracts import canonical_digest, canonical_serialize

_OWNER_LOCATION_EDGE_ISSUER_V3=object()
_OWNER_LOCATION_EDGE_ORIGINALS_V3=WeakSet()
_OWNER_LOCATION_LINEAGE_FACTS_V3=WeakSet()
_OWNER_LOCATION_PREPARED_TYPES_V3=(C09VerifiedLegacyPreparedSummaryV2,
    C09VerifiedPagedPreparedSummaryV2,C09VerifiedPagedPreparedSummaryV3)
_OWNER_LOCATION_PREPARED_SCHEMAS_V3={
    C09VerifiedLegacyPreparedSummaryV2:'sylanne3.c09.storage_prepared_original.v1',
    C09VerifiedPagedPreparedSummaryV2:'sylanne3.c09.storage_prepared_original.v2',
    C09VerifiedPagedPreparedSummaryV3:'sylanne3.c09.storage_prepared_original.v3'}


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _OwnerLocationEdgeOriginalsV3:
    # Issued only by this module's fixed actual Original/EOF/ACK readers.
    issuer: InitVar[object]
    view: VerifiedSelectedHistoryReadV3
    prepared: object
    certificate: object
    issue: object
    manifest_json: str
    release_json: str
    ack_json: str
    pending: DeletionMutationReceiptV1
    accepted: DeletionMutationReceiptV1
    closed: DeletionMutationReceiptV1
    graph_issue_original_digest: str|None
    graph_mirror_original_digest: str|None
    legacy_prepared_certificate_digest: str|None
    legacy_prepared_issue_digest: str|None
    actual_prior_certificate_schema: str|None
    actual_prior_certificate_digest: str|None
    legacy_prepared_certificate_bytes_digest: str|None
    graph_certificate_bytes_digest: str
    legacy_prepared_issue_bytes_digest: str|None
    core_issue_bytes_digest: str
    imported_root: object|None=None

    def __post_init__(self,issuer):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual Owner location Original issuer required')
        if (not (type(self.view)is VerifiedSelectedHistoryReadV3
                    or type(self.view)is _OwnerLocationLegacySelectionV3 and self.view.work in _OWNER_LOCATION_EDGE_READ_WORKS_V3
                        and self.view.work.failed is None)
                or type(self.prepared)not in _OWNER_LOCATION_PREPARED_TYPES_V3
                or self.prepared._issuer is not _PREPARED_TOKEN_V3
                or self.prepared._control is not self.view.basis.control
                or self.prepared['schema']!=_OWNER_LOCATION_PREPARED_SCHEMAS_V3[type(self.prepared)]
                or self.prepared._selection!=(self.view.basis.current['pointer_version'],
                    self.view.basis.manifest['manifest_digest'],self.view.basis.manifest['generation'])):
            raise AuthorityUnavailable('Owner location requires exact authenticated selected PREPARED')
        if (any(type(x)is not str for x in (self.manifest_json,self.release_json,self.ack_json))
                or any(type(x)is not DeletionMutationReceiptV1 for x in (self.pending,self.accepted,self.closed))):
            raise AuthorityUnavailable('Owner location actual compact Originals/closed receipts differ')
        _OWNER_LOCATION_EDGE_ORIGINALS_V3.add(self)


def _issue_owner_location_edge_originals_v3(issuer,**values):
    # Fixed IO must first authenticate signed PREPARED EOF, Core issue,
    # Graph mirror, signed RELEASED, closed + independent journal, and full ACK.
    return _OwnerLocationEdgeOriginalsV3(issuer=issuer,**values)


@dataclass(frozen=True,slots=True)
class _OwnerLocationLineageEdgeV3:
    schema: str
    certificate_digest: str
    prior_schema: str|None
    prior_digest: str|None
    old_incarnation: str
    new_incarnation: str
    authority_id: str
    installation_id: str
    authority_namespace: str
    operation_id: str
    maintenance_generation: int
    old_manifest_digest: str
    new_manifest_digest: str
    prior_prepared_digest: str|None
    prepared_digest: str
    release_digest: str
    before: RestoreAnchor
    after: RestoreAnchor
    ingress_before: RestoreAnchor
    applied_revocation_epoch: int


def _owner_location_lineage_edge_v3(originals):
    if (type(originals)is not _OwnerLocationEdgeOriginalsV3
            or originals not in _OWNER_LOCATION_EDGE_ORIGINALS_V3):
        raise AuthorityUnavailable('qualified actual Owner location Original required')
    p=originals.prepared;c=originals.certificate;issue=originals.issue
    manifest=json.loads(originals.manifest_json)
    released=json.loads(originals.release_json);ack=json.loads(originals.ack_json)
    identity=(p['authority_id'],p['installation_id'],p['namespace'],p['operation_id'],p['maintenance_generation'])
    if type(p)is C09VerifiedLegacyPreparedSummaryV2:
        if type(c)is OwnerLegacyCertificateEdgeV3:
            c.require_actual_location_edge_v3(c.work)
            certificate_schema=c.certificate_schema
        elif type(c)is GraphErasureRebaseCertificateV1:certificate_schema=c.schema
        else:raise AuthorityUnavailable('actual V1 certificate or private authenticated location edge required')
        if type(issue)is not AuthorityGraphRebaseIssuedV1:
            raise AuthorityUnavailable('legacy Owner location requires its actual V1 certificate and Core issue')
        actual=(c.authority_id,c.installation_id,c.namespace,c.operation_id,c.maintenance_generation)
        old,new=c.old_incarnation,c.new_incarnation
        prior_schema=None if c.prior_certificate_digest is None else certificate_schema
        prior_digest=c.prior_certificate_digest
        if (actual!=identity or (issue.authority_id,issue.installation_id,issue.namespace,
                issue.operation_id,issue.maintenance_generation)!=identity
                or issue.certificate_digest!=c.certificate_digest
                or originals.legacy_prepared_certificate_digest!=c.certificate_digest
                or originals.legacy_prepared_issue_digest!=issue.issue_digest
                or c.accepted_receipt_digest!=p['accepted_receipt_digest']
                or c.barrier_receipt_digest!=p['barrier_receipt_digest']
                or originals.legacy_prepared_certificate_bytes_digest!=originals.graph_certificate_bytes_digest
):
            raise AuthorityUnavailable('legacy PREPARED EOF/Core issue/Graph certificate original differs')
    else:
        if type(c)is not GraphErasureRebaseCertificateV2 or type(issue)is not AuthorityGraphRebaseIssuedV2:
            raise AuthorityUnavailable('paged Owner location requires its actual V2 certificate and Core issue')
        candidate=c.candidate;scope=candidate.scope
        actual=(scope.authority_id,scope.installation_id,scope.authority_namespace,
            scope.operation_id,scope.maintenance_generation)
        old,new=candidate.old_incarnation,candidate.new_incarnation
        prior_schema,prior_digest=c.prior_certificate_schema_or_none,c.prior_certificate_digest_or_none
        if (actual!=identity or issue.certificate!=c
                or scope.scope_digest!=p['capture_scope_digest']
                or tuple(json.loads(scope.graph_namespace))!=tuple(json.loads(originals.view.scope.graph_namespace))
                or originals.graph_issue_original_digest!=p['graph_issue_original_digest']
                or originals.graph_mirror_original_digest!=p['graph_mirror_original_digest']):
            raise AuthorityUnavailable('paged PREPARED issue/mirror references or exact capture scope differ')
    if (prior_schema,prior_digest)!=(originals.actual_prior_certificate_schema,originals.actual_prior_certificate_digest):
        raise AuthorityUnavailable('Owner location prior schema/digest differs from its actual authenticated predecessor original')
    transition=p['anchor_transition_original']
    before=RestoreAnchor(**transition['before_anchor']);after=RestoreAnchor(**transition['after_anchor'])
    if (transition['transition_digest']!=_control_digest_v3({k:v for k,v in transition.items()if k!='transition_digest'})
            or tuple(transition[k]for k in ('authority_id','installation_id','namespace','operation_id','maintenance_generation'))!=identity
            or transition['old_manifest_digest']!=p['old_manifest_digest']
            or transition['accepted_receipt_digest']!=p['accepted_receipt_digest']
            or transition['continuation_permit']['pinned_anchor']!=asdict(after)
            or before.namespace!=identity[2] or after.namespace!=identity[2]
            or before.authority_id!=identity[0] or after.authority_id!=identity[0]
            or before.activation_generation!=after.activation_generation
            or after.revocation_epoch!=before.revocation_epoch+1):
        raise AuthorityUnavailable('Owner location actual Core rebase anchor transition differs')
    if type(p)is C09VerifiedLegacyPreparedSummaryV2:
        if (asdict(before)!=p['old_core_anchor_original'] or asdict(after)!=p['new_core_anchor_original']):
            raise AuthorityUnavailable('legacy Owner anchor originals differ from retained transition')
    pending,accepted,closed=originals.pending,originals.accepted,originals.closed
    for receipt,source,target in ((pending,'absent','pending'),(accepted,'pending','accepted'),(closed,'accepted','closed')):
        if (receipt.pending.deletion_operation_id!=identity[3]
                or receipt.pending.source_phase!=source or receipt.pending.target_phase!=target
                or receipt.pending.before_anchor.namespace!=identity[2]
                or receipt.after_anchor.authority_id!=identity[0]
                or receipt.after_anchor.activation_generation!=before.activation_generation):
            raise AuthorityUnavailable('Owner location exact pending/accepted/closed mutation lineage differs')
    if (pending.after_anchor!=accepted.pending.before_anchor or accepted.after_anchor!=before
            or canonical_digest(accepted)!=p['accepted_receipt_digest']
            or closed.pending.before_anchor!=after or canonical_digest(closed)!=released['closed_digest']
            or (closed.after_anchor.deletion_seq,closed.after_anchor.deletion_digest)!=
                (released['applied_seq'],released['applied_digest'])):
        raise AuthorityUnavailable('Owner location independent closed journal lineage differs')
    graph_member=next(member for member in manifest['members']if member['role']=='graph')
    if ((manifest['authority_id'],manifest['installation_id'])!=identity[:2]
            or tuple(manifest['cohort_namespaces'])!=(identity[2],)
            or manifest['generation']!=identity[4]
            or manifest['manifest_digest']!=p['new_manifest_digest']
            or manifest['prior_manifest_digest']!=p['old_manifest_digest']
            or manifest['certificate_digest']!=c.certificate_digest or manifest['graph_issue_digest']!=issue.issue_digest
            or graph_member['incarnation_or_journal_id']!=new
            or released['installation_id']!=identity[1] or released['operation_id']!=identity[3]
            or released['storage_generation']!=identity[4] or released['manifest_digest']!=p['new_manifest_digest']
            or released['state']!='applied' or ack['ack_digest']!=released['graph_ack_digest']
            or ack['operation_id']!=identity[3] or ack['namespace']!=list(json.loads(originals.view.scope.graph_namespace))
            or ack['certificate_digest']!=c.certificate_digest or ack['new_incarnation']!=new
            or ack['storage_generation']!=identity[4] or ack['manifest_digest']!=p['new_manifest_digest']
            or ack['closed_digest']!=released['closed_digest']
            or ack['cumulative_tombstone_root']!=manifest['cumulative_tombstone_root']
            or (ack['deletion_seq'],ack['deletion_digest'],ack['deletion_epoch'])!=
                (released['applied_seq'],released['applied_digest'],released['applied_epoch'])):
        raise AuthorityUnavailable('Owner location signed manifest/RELEASED/qualified historical Graph ACK differs')
    return _OwnerLocationLineageEdgeV3(certificate_schema if type(p)is C09VerifiedLegacyPreparedSummaryV2 else c.schema,
        c.certificate_digest,prior_schema,prior_digest,old,new,
        *identity,p['old_manifest_digest'],p['new_manifest_digest'],p['prior_prepared_digest'],
        p['prepared_digest'],released['release_digest'],before,after,pending.pending.before_anchor,
        closed.after_anchor.revocation_epoch+1)


def _owner_location_origin_key_v3(head,history):
    if type(head)is not OwnerMigrationHeadV1 or head.state!='active':
        raise AuthorityUnavailable('actual current immutable Owner head required')
    if history is None:return ('source',head.authority_namespace,head.grant_digest,head.guard,head.issue_proof)
    if (type(history)is not MigrationStatusV2 or history.phase!='activated'
            or history.target_recovery is None or history.target_permit is None):
        raise AuthorityUnavailable('actual activated target import history required')
    return ('target',head.authority_namespace,head.grant_digest,head.guard,head.issue_proof,
        history.plan,history.target_recovery,history.target_permit)


class _OwnerLocationLineageAccumulatorV3:
    def __init__(self,issuer,*,view,applied,metadata,head,source_grant_json,holder,history=None):
        legacy=(type(view)is _OwnerLocationLegacySelectionV3 and view.work in _OWNER_LOCATION_EDGE_READ_WORKS_V3
            and view.work.failed is None and applied is None)
        selected=(type(view)is VerifiedSelectedHistoryReadV3 and type(applied)is SelectedAppliedReadV3
            and applied._issuer is _SELECTED_APPLIED_V3 and applied.view is view)
        if (issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or not (legacy or selected)
                or type(metadata)is not GraphRecoveryMetadataV2):
            raise AuthorityUnavailable('actual selected complete history/applied proofs required for Owner lineage')
        self.view,self.applied,self.metadata,self.head,self.holder=view,applied,metadata,head,holder
        self.history=history;self.origin_key=_owner_location_origin_key_v3(head,history)
        grant=json.loads(source_grant_json);validate_owner_grant_v1(grant)
        req=metadata.requirements;control=view.basis.control
        if (grant['principal']!=asdict(head.issue_operation.principal) or _owner_wire_digest_v3(grant)!=head.grant_digest
                or grant['graph_incarnation']!=head.issue_proof.graph_incarnation
                or grant['scope']!='/'.join(req.namespace.as_tuple)
                or head.guard.namespace!=req.namespace or head.authority_namespace!=req.authority_namespace
                or (control.authority_id,control.installation_id,view.basis.prepared['namespace'])!=
                    (req.authority_id,view.basis.prepared['installation_id'],req.authority_namespace)):
            raise AuthorityUnavailable('Owner lineage initial Graph grant/original namespace differs')
        self.namespace=req.namespace;self.authority_id=req.authority_id
        self.installation_id=control.installation_id;self.authority_namespace=req.authority_namespace
        if history is None:
            if (grant['installation_id']!=self.installation_id or head.guard.installation_id!=self.installation_id
                    or head.grant_revision!=1):
                raise AuthorityUnavailable('source Owner location crossed installation')
            self.origin=grant['graph_incarnation'];self.activation_generation=grant['activation_generation'];self.previous_epoch=None
        else:
            if (history.plan.namespace_id!=req.namespace or history.plan.namespace!=req.authority_namespace
                    or history.plan.target_installation_id!=self.installation_id
                    or history.plan.source_installation_id!=head.guard.installation_id):
                raise AuthorityUnavailable('target Owner location is not the actual activated import installation')
            self.origin=history.target_recovery.new_graph_incarnation
            self.activation_generation=history.target_permit.generation
            self.previous_epoch=history.target_recovery.current_requirements.revocation_epoch
        if (req.activation_generation!=self.activation_generation or req.graph_incarnation==self.origin):
            raise AuthorityUnavailable('Owner lineage must continue its unchanged generation to a distinct Graph')
        self.generation=0;self.prior_prepared=None;self.prior_manifest=None;self.prior_certificate=None
        self.history_root=canonical_digest(('sylanne3.c09.selected-history-chain.v3',control.authority_id,control.installation_id))
        self.path_started=False;self.incarnation=self.origin;self.commitments=[];self.complete=False
        self.last_edge=None

    def advance(self,originals):
        if (self.complete or type(originals)is not _OwnerLocationEdgeOriginalsV3
                or originals not in _OWNER_LOCATION_EDGE_ORIGINALS_V3 or originals.view is not self.view):
            raise AuthorityUnavailable('Owner lineage changed its selected Original stream')
        edge=_owner_location_lineage_edge_v3(originals)
        if self.generation==0 and (edge.prior_schema,edge.prior_digest)!=(None,None):
            if self.history is None or type(originals.imported_root)is not _OwnerLocationTargetImportRootV3:
                raise AuthorityUnavailable('actual imported Target first prior membership proof required')
            originals.imported_root.require_for_v3(self.view.work if type(self.view)is _OwnerLocationLegacySelectionV3 else originals.imported_root.work,
                (edge.prior_schema,edge.prior_digest),edge.old_manifest_digest)
            if (originals.imported_root.work.view is not self.view or originals.imported_root.work.history is not self.history):
                raise AuthorityUnavailable('actual Target imported root changed selected history/controller')
        if ((edge.authority_id,edge.installation_id,edge.authority_namespace)!=
                (self.authority_id,self.installation_id,self.authority_namespace)
                or edge.maintenance_generation!=self.generation+1 or edge.prior_prepared_digest!=self.prior_prepared
                or self.prior_manifest is not None and edge.old_manifest_digest!=self.prior_manifest
                or self.generation and (edge.prior_schema,edge.prior_digest)!=self.prior_certificate
                or self.last_edge is not None and edge.old_incarnation!=self.last_edge.new_incarnation):
            raise AuthorityUnavailable('Owner lineage prior schema/digest, manifest or consecutive generation differs')
        if edge.old_incarnation==self.origin:self.path_started=True
        if self.path_started:
            if (edge.old_incarnation!=self.incarnation or edge.before.activation_generation!=self.activation_generation
                    or self.previous_epoch is not None and edge.ingress_before.revocation_epoch!=self.previous_epoch):
                raise AuthorityUnavailable('Owner lineage does not descend from its actual grant/import origin')
            if len(self.commitments)>=1024:
                raise AuthorityUnavailable('Owner storage ancestry exceeds its original installed 1024-edge bound')
            self.commitments.append((edge.certificate_digest,edge.prepared_digest,edge.release_digest))
            self.incarnation=edge.new_incarnation;self.previous_epoch=edge.applied_revocation_epoch
        self.generation=edge.maintenance_generation;self.prior_prepared=edge.prepared_digest
        self.prior_manifest=edge.new_manifest_digest;self.prior_certificate=(edge.schema,edge.certificate_digest)
        self.history_root=canonical_digest(('sylanne3.c09.selected-history-member.v3',self.history_root,
            self.generation,self.prior_prepared,self.prior_manifest))
        self.last_edge=edge

    def finish(self,*,authenticated_stream_eof):
        # Only the fixed selected-generation keyset reader calls this after actual EOF.
        if not authenticated_stream_eof or self.complete:
            raise AuthorityUnavailable('Owner lineage actual Original stream EOF required')
        view=self.view;basis=view.basis;last=self.last_edge;req=self.metadata.requirements
        if type(view)is _OwnerLocationLegacySelectionV3 and (not view.complete
                or type(self.applied)is not _OwnerLocationLegacyAppliedV3 or self.applied.view is not view
                or self.applied.work is not view.work or not view.work.history_eof):
            raise AuthorityUnavailable('actual complete legacy location history/ACK EOF required')
        if (not self.path_started or not self.commitments or last is None
                or self.generation!=view.history_count or self.history_root!=view.history_root
                or self.generation!=basis.manifest['generation']
                or self.prior_prepared!=basis.prepared['prepared_digest']
                or self.prior_manifest!=basis.manifest['manifest_digest']
                or last.certificate_digest!=basis.manifest['certificate_digest']
                or last.release_digest!=self.applied.release['release_digest']
                or self.incarnation!=req.graph_incarnation or self.previous_epoch!=req.revocation_epoch):
            raise AuthorityUnavailable('Owner location EOF fails selected history/current RELEASED metadata')
        if self.history is None:
            body=dict(schema='d12.owner-storage-admission.v1',namespace=self.namespace,
                authority_namespace=self.authority_namespace,installation_id=self.installation_id,holder=self.holder,
                source_grant_ref=owner_grant_key(*self.namespace.as_tuple).token,source_grant_revision=1,
                source_grant_digest=self.head.grant_digest,source_owner_guard=self.head.guard,
                principal=self.head.issue_operation.principal,source_graph_incarnation=self.origin,
                current_graph_incarnation=self.incarnation,activation_generation=self.activation_generation,
                revocation_epoch=self.previous_epoch,storage_generation=basis.manifest['generation'],
                pointer_version=basis.current['pointer_version'],manifest_digest=basis.manifest['manifest_digest'],
                release_digest=self.applied.release['release_digest'],certificate_chain=tuple(self.commitments))
            material={**body,'namespace':asdict(body['namespace']),
                'source_owner_guard':asdict(body['source_owner_guard']),'principal':asdict(body['principal'])}
            body['original_ref']='d12-owner-storage:'+_owner_wire_digest_v3(material)[7:]
            material['original_ref']=body['original_ref']
            result=D12OwnerStorageAdmissionV1(**body,original_digest=_owner_wire_digest_v3(material))
        else:
            material=dict(authority_namespace=self.authority_namespace,installation_id=self.installation_id,
                transfer_id=self.history.plan.transfer_id,source_graph_incarnation=self.origin,
                current_graph_incarnation=self.incarnation,activation_generation=self.activation_generation,
                revocation_epoch=self.previous_epoch,storage_generation=basis.manifest['generation'],
                manifest_digest=basis.manifest['manifest_digest'],release_digest=self.applied.release['release_digest'],
                certificate_chain=tuple(self.commitments))
            material['original_ref']='d12c09location:'+_owner_wire_digest_v3(material)[7:]
            material['original_digest']=_owner_wire_digest_v3(material)
            result=D12C09TargetContinuationV1(**material)
        self.complete=True
        return _OwnerLocationLineageFactsV3(_OWNER_LOCATION_EDGE_ISSUER_V3,basis.control,
            basis.selection_digest,basis.current['pointer_version'],basis.manifest['manifest_digest'],
            view.history_root,view.history_count,self.origin_key,self.namespace,
            (req.graph_incarnation,req.activation_generation,req.revocation_epoch),
            self.applied.release['release_digest'],result)


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _OwnerLocationLineageFactsV3:
    # Immutable location evidence, never a permit or fresh Owner observation.
    issuer: InitVar[object]
    control: object
    selection_digest: str
    pointer_version: int
    manifest_digest: str
    history_root: str
    history_count: int
    origin_key: tuple
    namespace: object
    location: tuple
    release_digest: str
    result: object

    def __post_init__(self,issuer):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual completed Owner location lineage issuer required')
        _OWNER_LOCATION_LINEAGE_FACTS_V3.add(self)


def _reuse_owner_location_lineage_facts_v3(facts,*,view,applied,metadata,head,history=None):
    # Caller must freshly validate actual selected/current Source, Owner and permit.
    if (type(facts)is not _OwnerLocationLineageFactsV3 or facts not in _OWNER_LOCATION_LINEAGE_FACTS_V3
            or type(view)is not VerifiedSelectedHistoryReadV3 or type(applied)is not SelectedAppliedReadV3
            or applied._issuer is not _SELECTED_APPLIED_V3 or applied.view is not view
            or type(metadata)is not GraphRecoveryMetadataV2):
        raise AuthorityUnavailable('actual completed Owner lineage facts/current selected proofs required')
    basis=view.basis;req=metadata.requirements
    if (basis.control is not facts.control or basis.selection_digest!=facts.selection_digest
            or basis.current['pointer_version']!=facts.pointer_version or basis.manifest['manifest_digest']!=facts.manifest_digest
            or (view.history_root,view.history_count)!=(facts.history_root,facts.history_count)
            or applied.release['release_digest']!=facts.release_digest or req.namespace!=facts.namespace
            or (req.graph_incarnation,req.activation_generation,req.revocation_epoch)!=facts.location
            or _owner_location_origin_key_v3(head,history)!=facts.origin_key):
        raise AuthorityUnavailable('Owner lineage fact cache changed its exact selected location or grant/import origin')
    return facts.result



from dataclasses import fields as _owner_heap_fields_v3
from types import MappingProxyType
from sys import getsizeof as _owner_heap_size_v3
from ..runtime_contracts import NamespaceId,SnapshotRequirementsV2
from ..graph_types import NamespaceEpoch
from .v2_owner_contract import (OwnerPrincipalV1,OwnerActorBindingV1,OwnerClaimTicketV1,
    OwnerAuthorizationGuardV1,OwnerAuthorizationOperationV1,OwnerAuthorizationReceiptV1,OwnerGraphCommitProofV1)
from .v2_contract import FencePermitV2,DeletionPendingV1,DeletionEvidenceV1
from ..runtime.c09_paged_capture_contract_v2 import _WIRE_TYPES_V2 as _OWNER_C09_HEAP_DTOS_V3
from .c09_paged_recovery_facts_v2 import C09PagedFactsCompletionV2
from .d12_target_owner_admission_v1 import D12TargetOwnerAdmissionV1
from .v2_migration_contract import (MigrationPlanV2,MigrationPermitV2,SourceSnapshotReceiptV2,
    TargetRecoveryReceiptV2,MigrationStageReceiptV2)
from ..runtime.graph_migration_snapshot_v1 import TargetGraphImportReceiptV1
from .migration_snapshot_certificate_members_v1 import (
    MigrationSnapshotCertificateSourceV1,MigrationSnapshotCertificateCellV1,
    SignedMigrationSnapshotCertificateMemberV1,SignedMigrationSnapshotCertificateMemberSetV1,
    SignedMigrationActivationCertificateMemberSetV1)
from ..runtime.c09_canonical_json_stream_v2 import _ContainerV2 as _OWNER_JSON_CONTAINER_V3

_OWNER_LOCATION_PAYLOAD_DTOS_V3=frozenset((NamespaceId,SnapshotRequirementsV2,NamespaceEpoch,
    GraphRecoveryMetadataV2,RestoreAnchor,OwnerPrincipalV1,OwnerActorBindingV1,OwnerClaimTicketV1,
    OwnerAuthorizationGuardV1,OwnerAuthorizationOperationV1,OwnerAuthorizationReceiptV1,OwnerGraphCommitProofV1,
    OwnerMigrationHeadV1,FencePermitV2,DeletionPendingV1,DeletionEvidenceV1,DeletionMutationReceiptV1,
    AuthorityGraphRebaseIssuedV1,AuthorityGraphRebaseIssuedV2,C09PagedFactsCompletionV2,
    D12OwnerStorageAdmissionV1,D12TargetOwnerAdmissionV1,D12C09TargetContinuationV1,
    _OwnerLocationLineageEdgeV3,_OWNER_JSON_CONTAINER_V3,MigrationStatusV2,MigrationPlanV2,
    MigrationPermitV2,SourceSnapshotReceiptV2,TargetRecoveryReceiptV2,MigrationStageReceiptV2,
    TargetGraphImportReceiptV1,MigrationSnapshotCertificateSourceV1,MigrationSnapshotCertificateCellV1,
    SignedMigrationSnapshotCertificateMemberV1,SignedMigrationSnapshotCertificateMemberSetV1,
    SignedMigrationActivationCertificateMemberSetV1))|_OWNER_C09_HEAP_DTOS_V3


def _owner_location_payload_heap_v3(value,seen):
    # Only these closed pure DTOs and payload containers are traversed.
    # Actual Control/SQLite/service/reader/CallerProof capabilities are excluded.
    identity=id(value)
    if identity in seen:return 0
    seen.add(identity);amount=_owner_heap_size_v3(value);kind=type(value)
    if kind in(dict,MappingProxyType):
        return amount+sum(_owner_location_payload_heap_v3(key,seen)+_owner_location_payload_heap_v3(item,seen)
            for key,item in value.items())
    if kind in(tuple,list,set,frozenset):
        return amount+sum(_owner_location_payload_heap_v3(item,seen)for item in value)
    if kind in _OWNER_LOCATION_PAYLOAD_DTOS_V3:
        return amount+sum(_owner_location_payload_heap_v3(getattr(value,field.name),seen)
            for field in _owner_heap_fields_v3(value))
    if kind in _OWNER_LOCATION_PREPARED_TYPES_V3:
        return amount+_owner_location_payload_heap_v3((value._header,value._row,value._selection),seen)
    return amount


def _owner_location_selected_payload_heap_v3(view,seen):
    if type(view)is not VerifiedSelectedHistoryReadV3:return 0
    amount=_owner_location_payload_heap_v3((view.basis.current,view.basis.manifest,view.basis.prepared,
        view.scope,view.completion,view.history_count,view.history_root,view.family_eof),seen)
    for role in view.verified_roles:
        # Exact VerifiedSegmentedRoleOriginalV3 metadata, never its Control capability.
        amount+=_owner_location_payload_heap_v3((role.details,role.base_header,role.selection,
            role.child_original_digests,role.child_locators,role.target_stamp),seen)
    p=view.natural_core_proof
    amount+=_owner_location_payload_heap_v3((p.summary,p.preparedref,p.selection_digest,p.target_path,p.target_inode,p.core_original_digest),seen)
    p=view.core_source_proof
    amount+=_owner_location_payload_heap_v3((p.root,p.counts,p.directory),seen)
    p=view.runtime_physical_proof
    amount+=_owner_location_payload_heap_v3((p.root,p.counts,p.eof_digest),seen)
    p=view.provider_scope_proof
    amount+=_owner_location_payload_heap_v3((p.original,p.details),seen)
    return amount


def _owner_location_parser_heap_v3(parser,seen):
    amount=_owner_heap_size_v3(parser)+_owner_location_payload_heap_v3((parser._stack,
        parser._string,parser._number,parser._literal,parser._active_scalar),seen)
    amount+=_owner_heap_size_v3(parser._sha256)
    if parser._string is not None and parser._string['decoder']is not None:
        amount+=_owner_location_payload_heap_v3(parser._string['decoder'].getstate(),seen)
    return amount


from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from time import monotonic_ns
from ..runtime.c09_paged_sql_v2 import (
    peek_current_c09_sql_meter_v3,require_c09_reserved_meter_v3,
    read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2)
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3


class _OwnerLocationCanonicalColumnV3:
    """Complete canonical Owner metadata only, bound to one actual fixed SQL locator."""
    def __init__(self,issuer,*,role,kind,namespace,operation_id=None,transfer_id=None):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual Owner location fixed column issuer required')
        locations={
            'recovery':('graph','graph_recovery_metadata_v2','requirements_json','bot=? AND persona=?',namespace.as_tuple),
            'owner_grant':('graph','graph_atoms','value','token=? AND bot=? AND persona=?',
                (owner_grant_key(*namespace.as_tuple).token,*namespace.as_tuple)),
            'owner_issue_proof':('graph','graph_owner_issue_operations_v1','proof_json','bot=? AND persona=?',namespace.as_tuple),
            'graph_certificate_v1':('graph','graph_c09_rebase_certificates_v1','certificate_json',
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)),
            'graph_certificate_v2':('graph','graph_c09_rebase_certificates_v2','certificate_json',
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)),
            'target_import':('graph','graph_migration_import_receipts_v1','receipt_json',
                'bot=? AND persona=? AND transfer_id=?',(*namespace.as_tuple,transfer_id)),
            'graph_ack':('graph','graph_c09_cumulative_applications_v1','original_json',
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)),
        }
        if kind not in locations or locations[kind][0]!=role:
            raise AuthorityUnavailable('unregistered Owner location canonical column')
        _,self.table,self.column,self.where,self.parameters=locations[kind]
        self.kind,self.namespace=kind,namespace;self.operation_id=operation_id
        self.position=0;self.length=None;self.parser=None;self.complete=False
        self.bytes=bytearray();self.sha256=None;self.cell_id=None;self.header=None
        self.ordinal=0;self.segment_root=None;self.metadata=None
        self.retain=(kind!='graph_certificate_v1')
        self.scalar=bytearray();self.header_values={};self.starts={};self.spans={};self.field_names=set()
        self.allocation=_OwnerLocationJSONAllocationScanV3(None,(),None)

    def _event(self,event):
        # These are fixed content-free certificate identity fields. No row body is retained.
        names={'schema','authority_id','installation_id','namespace','operation_id','maintenance_generation',
            'old_incarnation','new_incarnation','certificate_digest','prior_certificate_digest',
            'accepted_receipt_digest','barrier_receipt_digest','frozen_inventory_digest','tombstone_root','cold_read_digest'}
        if event.kind=='key' and len(event.path)==1:self.field_names.add(event.key)
        if len(event.path)==1 and event.path[0]in names:
            if event.kind=='scalar_start':self.scalar.clear()
            elif event.kind=='scalar_chunk':
                if len(self.scalar)+len(event.raw)>1024:
                    raise AuthorityUnavailable('actual fixed certificate identity scalar exceeds its original metadata codec')
                self.scalar.extend(event.raw)
            elif event.kind=='scalar_end':
                self.header_values[event.path[0]]=json.loads(bytes(self.scalar));self.scalar.clear()

    def advance(self,db,view,meter):
        from .c09_selected_history_v3 import _read_one
        if type(view)is VerifiedSelectedHistoryReadV3:view.basis.require_current(meter=meter)
        if self.complete:return True
        if self.length is None:
            if self.kind=='owner_grant':
                segmented=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'",(),meter)is not None
                self.metadata=_read_one(db,('SELECT revision,valid,value_cell_id FROM graph_atoms 'if segmented
                    else'SELECT revision,valid FROM graph_atoms ')+'WHERE token=? AND bot=? AND persona=?',self.parameters,meter)
                if self.metadata is None or self.metadata[:2]!=(1,1):
                    raise AuthorityUnavailable('actual current immutable Owner grant metadata absent/changed')
                self.cell_id=self.metadata[2]if segmented else None
            if self.cell_id is not None:
                self.header=meter.read_fixed_row(db,'segmented_cells_v1',
                    ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                     'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(self.cell_id,))
                if (self.header is None or self.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1')
                        or self.header[1]!=self.parameters[0]):
                    raise AuthorityUnavailable('actual Owner grant canonical cell/origin locator differs')
                read_selected_runtime_cell_origin_v3(db,selected_basis=view,role='graph',
                    cell_id=self.cell_id,header=self.header,meter=meter)
                self.length=self.header[3]
                self.segment_root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
                self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.header[0]=='canonical-json.ascii.v1')
            else:
                with legacy_cell_read_transaction_v2(db):
                    _,self.length,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=0,length=0,meter=meter)
                if kind!='text':raise AuthorityUnavailable('actual Owner metadata JSON column changed storage kind')
                self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.kind in('graph_certificate_v1','graph_certificate_v2','graph_ack'))
        if self.position<self.length:
            if self.cell_id is not None:
                row=meter.read_fixed_row(db,'segmented_cell_segments_v1',
                    ('byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(self.cell_id,self.ordinal))
                if (row is None or row[0]!=self.position or type(row[1])is not bytes
                        or not 0<len(row[1])<=16384 or sha256(row[1]).hexdigest()!=row[2]):
                    raise AuthorityUnavailable('actual Owner canonical cell segment order/byte SHA differs')
                chunk=row[1]
                self.segment_root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.segment_root,
                    self.cell_id,self.ordinal,self.position,len(chunk),row[2]));self.ordinal+=1
            else:
                with legacy_cell_read_transaction_v2(db):
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=self.position,
                        length=min(16384,self.length-self.position),meter=meter)
                if total!=self.length or kind!='text':
                    raise AuthorityUnavailable('actual Owner metadata byte length/type changed during EOF')
            if self.retain:
                # Original compact metadata codec; the large V1 certificate is projected instead.
                if len(self.bytes)+len(chunk)>65536:
                    raise AuthorityUnavailable('Owner fixed compact metadata exceeds its original descriptor codec')
                self.bytes.extend(chunk)
            self.allocation._feed(chunk);self.parser.feed(chunk,self._event);self.position+=len(chunk)
            if self.position>self.length:raise AuthorityUnavailable('Owner canonical cell crossed actual byte EOF')
            return False
        if self.cell_id is not None:
            if (self.ordinal!=self.header[4] or self.segment_root!=self.header[6]
                    or _read_one(db,'SELECT 1 FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                        (self.cell_id,self.ordinal),meter)is not None):
                raise AuthorityUnavailable('Owner canonical cell count/ordered-root/extra-segment EOF differs')
        result=self.parser.finish()
        if result.byte_count!=self.length or self.cell_id is not None and result.sha256!=self.header[5]:
            raise AuthorityUnavailable('actual Owner metadata canonical byte EOF differs')
        self.sha256=result.sha256;self.complete=True
        return True

    def text(self):
        if not self.complete or not self.retain:
            raise AuthorityUnavailable('actual complete retained Owner metadata descriptor required')
        return bytes(self.bytes).decode('utf-8')


_OWNER_LOCATION_GRAPH_WORKS_V3=WeakSet()
_OWNER_LOCATION_GRAPH_FACTS_V3=WeakSet()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class OwnerLocationGraphFactsV3:
    issuer: InitVar[object]
    work: object
    metadata: GraphRecoveryMetadataV2
    graph_epoch: object
    atom: tuple
    proof_row: tuple
    epochs: tuple
    selection_digest: str
    pointer_version: int
    manifest_digest: str

    def __post_init__(self,issuer):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or self.work not in _OWNER_LOCATION_GRAPH_WORKS_V3:
            raise AuthorityUnavailable('actual completed Owner Graph metadata Work required')
        _OWNER_LOCATION_GRAPH_FACTS_V3.add(self)

    def require_for_v3(self,proof):
        if (self not in _OWNER_LOCATION_GRAPH_FACTS_V3 or proof is not self.work.proof
                or self.work.failed is not None or not self.work.complete or self.work.result is not self):
            raise AuthorityUnavailable('Owner metadata facts belong to another actual caller proof')
        require_owner_location_caller_proof_v3(proof,phase='after',graph_stamp=(self.metadata,self.graph_epoch))
        return self


class OwnerLocationReadWorkV3:
    # This slice returns Graph facts only. Authority lineage qualification is separate.
    def __init__(self,issuer,proof):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual fixed Owner location Work issuer required')
        require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=None)
        self.proof,self.control=proof,proof.control;self.phase='selection'
        self.view=self.context=None;self.manifest=None;self.current=None
        self.column=None;self.recovery_json=None;self.metadata=None;self.graph_epoch=None
        self.schema=self.graph_revision=None;self.grant_metadata=self.issue_metadata=None
        self.grant_json=self.issue_json=None;self.atom=self.proof_row=self.epochs=None
        self.result=None;self.complete=False;self.failed=None;self.pending_facts=None;self.retained_owner=None
        self.legacy_reader=None;self.pending_legacy_selected=None;self.legacy_selected_summary=None;self.allocation_scan=None
        _OWNER_LOCATION_GRAPH_WORKS_V3.add(self)
        self.control.register_c09_retained_state_v3(self)
        register_owner_location_retained_state_v3(proof,self)

    def _c09_retained_heap_bytes_v3(self,_seen=None):
        seen=set()if _seen is None else _seen
        size=_owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)+_owner_location_payload_heap_v3((self.current,self.manifest,
            self.recovery_json,self.metadata,self.graph_epoch,self.grant_json,self.issue_json,
            self.grant_metadata,self.issue_metadata,self.atom,self.proof_row,self.epochs,
            None if self.context is None else self.context.prepared_original,
            self.pending_legacy_selected,self.legacy_selected_summary),seen)
        size+=_owner_location_selected_payload_heap_v3(self.view,seen)
        if self.allocation_scan is not None:size+=self.allocation_scan.heap_v3(seen)
        if self.column is not None:
            c=self.column;size+=_owner_heap_size_v3(c)
            size+=_owner_location_payload_heap_v3((c.bytes,c.scalar,c.header_values,c.field_names,c.metadata,c.header),seen)
            size+=c.allocation.heap_v3(seen)
            if c.parser is not None:
                size+=_owner_location_parser_heap_v3(c.parser,seen)
        if self.legacy_reader is not None:
            r=self.legacy_reader;size+=_owner_heap_size_v3(r)
            size+=_owner_location_payload_heap_v3((r.header,r.row,r.result),seen)
            if r.cell is not None:
                size+=_owner_heap_size_v3(r.cell)+_owner_location_payload_heap_v3((r.cell.spans,r.cell.starts),seen)
                size+=_owner_location_parser_heap_v3(r.cell.parser,seen)
        return size

    def _transfer_retained_owner_v3(self,owner):
        if (owner not in _OWNER_LOCATION_EDGE_READ_WORKS_V3 or owner.facts.work is not self
                or owner.proof is not self.proof or owner.control is not self.control
                or owner not in self.control._c09_retained_states_v3):
            raise AuthorityUnavailable('actual registered same-Work Owner payload retention transfer required')
        transfer_owner_location_retained_state_v3(self.proof,self,owner)
        self.retained_owner=owner
        self.control._c09_retained_states_v3.discard(self)

    def _require_selected(self,meter):
        from .c09_selected_history_v3 import _read_one
        if self.view is not None:
            current=self.view.basis.require_current(meter=meter)
            if current['stage']!='RELEASED':raise AuthorityUnavailable('actual Owner Graph selected storage is not RELEASED')
        else:
            with self.control._db()as db:current=self.control._current(db)
            if (current['pointer_version'],current['current_manifest_digest'],current['stage'])!=                    (self.current['pointer_version'],self.current['current_manifest_digest'],self.context.stage):
                raise AuthorityUnavailable('actual legacy Owner Graph selected pointer/stage changed')
        for member in self.manifest['members']:
            stat=Path(member['resolved_path']).stat()
            if (stat.st_dev,stat.st_ino)!=(member['device'],member['file_id']):
                raise AuthorityUnavailable('actual Owner Graph selected member identity changed')
        return current

    @contextmanager
    def _graph_snapshot(self,meter):
        import sqlite3
        from contextlib import closing
        self._require_selected(meter)
        member=next(item for item in self.manifest['members']if item['role']=='graph')
        started=monotonic_ns()
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            try:yield db
            finally:db.rollback()
        if monotonic_ns()-started>meter.budget.max_read_ns:
            raise AuthorityUnavailable('actual Owner metadata snapshot exceeded original read duration')
        self._require_selected(meter)

    def _advance_graph(self,meter):
        from .c09_selected_history_v3 import _read_one
        from ..graph_store import GraphStore
        from ..graph_types import NamespaceEpoch
        p=self.proof;namespace=p.namespace
        if self.phase=='legacy_selected_header':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2,C09VerifiedLegacyPreparedSummaryV2
            if self.legacy_reader is None:
                self.legacy_reader=begin_next_authenticated_prepared_reader_v2(self.control,
                    after_generation=self.manifest['generation']-1,through_generation=self.manifest['generation'],meter=meter)
                if self.legacy_reader is None:raise AuthorityUnavailable('actual selected legacy PREPARED absent')
            summary=self.legacy_reader.advance(meter=meter)
            if summary is not None:
                if (type(summary)is not C09VerifiedLegacyPreparedSummaryV2
                        or summary['maintenance_generation']!=self.manifest['generation']
                        or summary['new_manifest_digest']!=self.manifest['manifest_digest']):
                    raise AuthorityUnavailable('actual selected legacy streamed Original differs from current manifest')
                self.pending_legacy_selected=summary
            return None
        if self.phase=='selection':
            self.view=getattr(self.control,'_selected_history_read_v3',None)
            if self.view is not None:
                if type(self.view)is not VerifiedSelectedHistoryReadV3:
                    raise AuthorityUnavailable('actual selected history proof type differs')
                self.current=self.view.basis.require_current(meter=meter)
                self.manifest=self.view.basis.manifest
                selected=self.view.basis.selection_digest
                if selected!=p.selection_digest:
                    raise AuthorityUnavailable('Owner metadata caller retained selection differs from actual Graph')
            else:
                # Preserve the real installed legacy reader, never manufacture a V3 view.
                with self.control._db()as db:
                    self.current=self.control._current(db)
                    self.manifest=self.control._read_manifest(db,self.current['current_manifest_digest'])
                if (self.manifest['schema']=='sylanne3.c09.storage_manifest.v1'and self.manifest['generation']>0
                        and self.legacy_selected_summary is None):
                    self.phase='legacy_selected_header';return None
                self.context=self.control.read_verified_current_storage_v2(meter=meter,verify_files=False)
            if (self.current['stage']not in('READY','RELEASED')
                    or self.manifest['installation_id']!=p.installation_id
                    or tuple(self.manifest['cohort_namespaces'])!=(p.permission_anchor.namespace,)):
                raise AuthorityUnavailable('actual Owner metadata selected installation/namespace is unavailable')
            self.phase='recovery'
            return None
        with self._graph_snapshot(meter)as db:
            if self.phase=='recovery':
                if self.column is None:
                    row=_read_one(db,'SELECT schema,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',
                        namespace.as_tuple,meter)
                    if row is None:raise AuthorityUnavailable('actual Owner namespace recovery metadata absent')
                    self.schema,self.graph_revision=row
                    epoch=_read_one(db,'SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                    self.graph_epoch=NamespaceEpoch(*namespace.as_tuple,0 if epoch is None else epoch[0])
                    self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        role='graph',kind='recovery',namespace=namespace)
                if not self.column.advance(db,self.view,meter):return None
                self.recovery_json=self.column.text()
                self.metadata=GraphStore._decode_recovery((self.schema,self.recovery_json,self.graph_revision),namespace)
                if self.metadata is None:raise AuthorityUnavailable('actual Owner recovery metadata codec is absent')
                self.column=None;self.phase='grant'
                return None
            if self.phase=='grant':
                if self.column is None:
                    self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        role='graph',kind='owner_grant',namespace=namespace)
                if not self.column.advance(db,self.view,meter):return None
                self.grant_json=self.column.text();self.grant_metadata=self.column.metadata
                self.atom=(self.grant_metadata[0],self.grant_json,self.grant_metadata[1])
                self.column=None;self.phase='issue'
                return None
            if self.phase=='issue':
                if self.column is None:
                    self.issue_metadata=_read_one(db,'SELECT operation_id,request_digest,grant_id,grant_digest,'
                        'graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest '
                        'FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                    if self.issue_metadata is None:raise AuthorityUnavailable('actual immutable Owner issue proof absent')
                    self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        role='graph',kind='owner_issue_proof',namespace=namespace)
                if not self.column.advance(db,self.view,meter):return None
                self.issue_json=self.column.text();self.proof_row=(*self.issue_metadata,self.issue_json)
                self.column=None;self.phase='epochs'
                return None
            if self.phase=='epochs':
                self.epochs=_read_one(db,'SELECT access_epoch,delete_epoch FROM graph_authority_epochs '
                    'WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                if self.epochs is None or self.epochs[0]<1 or self.epochs[1]<0:
                    raise AuthorityUnavailable('actual Owner access/delete epochs unavailable')
                self.phase='final';return None
            if self.phase=='final':
                metadata=_read_one(db,'SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 '
                    'WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                epoch=_read_one(db,'SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                grant=_read_one(db,('SELECT revision,valid,value_cell_id FROM graph_atoms 'if len(self.grant_metadata)==3
                    else'SELECT revision,valid FROM graph_atoms ')+'WHERE token=? AND bot=? AND persona=?',
                    (owner_grant_key(*namespace.as_tuple).token,*namespace.as_tuple),meter)
                issue=_read_one(db,'SELECT operation_id,request_digest,grant_id,grant_digest,'
                    'graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest '
                    'FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                epochs=_read_one(db,'SELECT access_epoch,delete_epoch FROM graph_authority_epochs '
                    'WHERE bot=? AND persona=?',namespace.as_tuple,meter)
                if (metadata!=(self.schema,self.recovery_json,self.graph_revision)
                        or (0 if epoch is None else epoch[0])!=self.graph_epoch.revision
                        or grant!=self.grant_metadata or issue!=self.issue_metadata or epochs!=self.epochs):
                    raise AuthorityUnavailable('actual Owner Graph metadata/EOF identity changed before completion')
                # The Root fixed caller validator applies original authority/principal/Owner
                # and own-execution bridge contracts. This IO slice issues no permission.
                return (self.metadata,self.graph_epoch,self.atom,self.proof_row,self.epochs)
        raise AuthorityUnavailable('unregistered fixed Owner metadata Work phase')

    def advance(self,*,meter=None):
        if self.failed is not None:raise AuthorityUnavailable(self.failed)
        stamp=None if self.metadata is None else(self.metadata,self.graph_epoch)
        require_owner_location_caller_proof_v3(self.proof,phase='before',graph_stamp=stamp)
        if self.complete:
            return self.result.require_for_v3(self.proof)
        try:
            active=peek_current_c09_sql_meter_v3()
            if meter is not None and active is not meter:
                raise AuthorityUnavailable('Owner metadata cannot replace the actual reserved root meter')
            if active is None:
                with self.control.reserve_control_read_v3()as budget:
                    actual=require_c09_reserved_meter_v3(budget)
                    candidate=_owner_location_growth_step_v3(self,actual)
                    self.control.require_c09_retained_arena_v3(meter=actual)
            else:
                actual=require_c09_reserved_meter_v3(active.budget)
                if actual is not active:raise AuthorityUnavailable('Owner metadata borrowed meter differs from actual root')
                self.control.require_c09_retained_arena_v3(meter=actual)
                candidate=_owner_location_growth_step_v3(self,actual)
                self.control.require_c09_retained_arena_v3(meter=actual)
            stamp=None if self.metadata is None else(self.metadata,self.graph_epoch)
            require_owner_location_caller_proof_v3(self.proof,phase='after',graph_stamp=stamp)
            if self.pending_legacy_selected is not None:
                if active is not None:return dict(status='progress',phase='owner_location_quantum_commit')
                self._publish_legacy_selected_v3()
                return dict(status='progress',phase='owner_location_selection')
            if candidate is None:return dict(status='progress',phase='owner_location_'+self.phase)
            if active is not None:
                self.pending_facts=candidate
                return dict(status='progress',phase='owner_location_quantum_commit')
            return self._publish_graph_facts_v3(candidate)
        except BaseException as exc:
            self.failed=str(exc);self.column=None
            self.control._c09_retained_states_v3.discard(self)
            raise


    def _publish_graph_facts_v3(self,candidate):
        self.result=OwnerLocationGraphFactsV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self,*candidate,
            self.proof.selection_digest,self.current['pointer_version'],self.manifest['manifest_digest'])
        self.pending_facts=None;self.complete=True
        return self.result

    def _publish_legacy_selected_v3(self):
        summary=self.pending_legacy_selected
        if summary is None or self.legacy_reader is None or self.legacy_reader.result is not summary:
            raise AuthorityUnavailable('actual successful streamed legacy PREPARED boundary required')
        self.control._c09_selected_legacy_prepared_v2=summary
        self.legacy_selected_summary=summary;self.pending_legacy_selected=None
        self.legacy_reader=None;self.phase='selection'

    def complete_reserved_quantum_v3(self,proof):
        # Fixed consumer calls only after the actual outer reserved quantum exits successfully.
        # On an outer error it calls cancel_v3 instead; a partial return is never complete evidence.
        if (proof is not self.proof or self.pending_facts is None and self.pending_legacy_selected is None or self.failed is not None
                or peek_current_c09_sql_meter_v3()is not None):
            raise AuthorityUnavailable('Owner metadata completion lacks its successful actual quantum boundary')
        require_owner_location_caller_proof_v3(proof,phase='after',
            graph_stamp=None if self.metadata is None else(self.metadata,self.graph_epoch))
        if self.pending_legacy_selected is not None:
            self._publish_legacy_selected_v3()
            return dict(status='progress',phase='owner_location_selection')
        return self._publish_graph_facts_v3(self.pending_facts)

    def close_v3(self):
        # Normal release: completed immutable data remains, no fake failure is recorded.
        self.column=None;self.pending_facts=None;self.allocation_scan=None;self.pending_legacy_selected=None;self.legacy_reader=None
        self.control._c09_retained_states_v3.discard(self)
        if not self.complete:
            self.recovery_json=self.grant_json=self.issue_json=None

    def cancel_v3(self,error):
        self.failed=str(error);self.pending_facts=None;self.allocation_scan=None;self.column=None;self.pending_legacy_selected=None;self.legacy_reader=None
        self.recovery_json=self.grant_json=self.issue_json=None
        self.control._c09_retained_states_v3.discard(self)


def prepare_owner_location_read_work_v3(proof):
    require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=None)
    return OwnerLocationReadWorkV3(_OWNER_LOCATION_EDGE_ISSUER_V3,proof)


class _OwnerLocationAuthenticatedSpanV3:
    """One complete span of an already fully HMAC-authenticated legacy PREPARED."""
    def __init__(self,issuer,reader,field):
        from .c09_paged_recovery_facts_v2 import C09LegacyPreparedReaderV2
        if (issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or type(reader)is not C09LegacyPreparedReaderV2
                or reader.result is None or field not in('graph_certificate_original','graph_issue_original')):
            raise AuthorityUnavailable('actual authenticated legacy PREPARED identity span required')
        self.reader,self.field=reader,field;self.span=reader.cell.spans[(field,)]
        self.position=self.span[0];self.hash=sha256();self.complete=False;self.sha256=None

    def advance(self,control,meter):
        self.reader.result.require_current(meter=meter)
        with control._db()as db:
            if self.position<self.span[1]:
                size=min(16384,self.span[1]-self.position)
                self.hash.update(self.reader.cell.read(db,self.position,size,meter));self.position+=size
                return False
        self.sha256=self.hash.hexdigest();self.complete=True;return True




_OWNER_LEGACY_CERTIFICATE_EDGES_V3=WeakSet()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class OwnerLegacyCertificateEdgeV3:
    """Authenticated location metadata, distinct from a full V1 erasure certificate DTO."""
    issuer: InitVar[object]
    work: object
    prepared: object
    certificate_column: object
    prepared_certificate_span: object
    prepared_issue_span: object
    issue: AuthorityGraphRebaseIssuedV1
    core_issue_json: str
    prepared_issue_json: str
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    maintenance_generation: int
    old_incarnation: str
    new_incarnation: str
    accepted_receipt_digest: str
    barrier_receipt_digest: str
    frozen_inventory_digest: str
    prior_certificate_digest: str|None
    tombstone_root: str
    cold_read_digest: str
    certificate_digest: str
    certificate_schema: str='sylanne3.graph.c09_erasure_rebase.v1'
    schema: str='sylanne3.owner-location.legacy-certificate-edge.v3'

    def __post_init__(self,issuer):
        from .c09_graph_rebase_issue_v1 import verify_graph_rebase_issue_signature_v1
        from ..runtime.c09_storage_rebase_contract_v1 import _id,_digest,_number
        from dataclasses import fields
        if (issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3
                or self.work not in _OWNER_LOCATION_GRAPH_WORKS_V3
                or type(self.prepared)is not C09VerifiedLegacyPreparedSummaryV2
                or self.prepared._issuer is not _PREPARED_TOKEN_V3
                or self.prepared._control is not self.work.control
                or type(self.issue)is not AuthorityGraphRebaseIssuedV1
                or self.schema!='sylanne3.owner-location.legacy-certificate-edge.v3'
                or self.certificate_schema!='sylanne3.graph.c09_erasure_rebase.v1'):
            raise AuthorityUnavailable('actual authenticated legacy Owner location edge issuer required')
        column=self.certificate_column;span=self.prepared_certificate_span;issue_span=self.prepared_issue_span
        if (not column.complete or column.kind!='graph_certificate_v1' or not span.complete
                or span.field!='graph_certificate_original' or not issue_span.complete
                or issue_span.field!='graph_issue_original'
                or span.reader.result is not self.prepared or issue_span.reader.result is not self.prepared
                or column.sha256!=span.sha256 or column.length!=span.span[1]-span.span[0]
                or column.field_names!={f.name for f in fields(GraphErasureRebaseCertificateV1)}):
            raise AuthorityUnavailable('legacy certificate location lacks exact signed whole canonical bytes/span EOF')
        for name in('authority_id','installation_id','namespace','operation_id','old_incarnation','new_incarnation'):
            _id(getattr(self,name),name)
        for name in('accepted_receipt_digest','barrier_receipt_digest','frozen_inventory_digest',
                'tombstone_root','cold_read_digest','certificate_digest'):_digest(getattr(self,name),name)
        _number(self.maintenance_generation,'maintenance_generation')
        if self.maintenance_generation<1 or self.old_incarnation==self.new_incarnation:
            raise AuthorityUnavailable('legacy Owner location edge has no distinct installed generation')
        if self.prior_certificate_digest is not None:_digest(self.prior_certificate_digest,'prior_certificate_digest')
        header=column.header_values
        if any(header[name]!=getattr(self,name)for name in('authority_id','installation_id','namespace',
                'operation_id','maintenance_generation','old_incarnation','new_incarnation','accepted_receipt_digest',
                'barrier_receipt_digest','frozen_inventory_digest','prior_certificate_digest','tombstone_root',
                'cold_read_digest','certificate_digest')):
            raise AuthorityUnavailable('legacy Owner location projection differs from actual canonical certificate')
        verify_graph_rebase_issue_signature_v1(self.issue,self.work.control._key)
        if (self.issue.authority_id,self.issue.installation_id,self.issue.namespace,self.issue.operation_id,
                self.issue.maintenance_generation,self.issue.certificate_digest)!=                (self.authority_id,self.installation_id,self.namespace,self.operation_id,
                 self.maintenance_generation,self.certificate_digest):
            raise AuthorityUnavailable('legacy location certificate differs from actual signed Core issue')
        # Each old encoding keeps its own raw EOF SHA/HMAC. Chinese paths mean
        # PREPARED UTF-8 and Core ASCII original bytes need not have equal SHA.
        core=json.loads(self.core_issue_json);prepared=json.loads(self.prepared_issue_json)
        if (core!=prepared or core!=asdict(self.issue) and core!=json.loads(canonical_serialize(asdict(self.issue)))):
            raise AuthorityUnavailable('legacy issue semantic fields differ across their original codecs')
        if sha256(self.prepared_issue_json.encode('utf-8')).hexdigest()!=issue_span.sha256:
            raise AuthorityUnavailable('legacy issue decoded metadata did not come from actual signed span EOF')
        _OWNER_LEGACY_CERTIFICATE_EDGES_V3.add(self)

    def require_actual_location_edge_v3(self,work):
        if (self not in _OWNER_LEGACY_CERTIFICATE_EDGES_V3 or work is not self.work
                or work.failed is not None):
            raise AuthorityUnavailable('legacy Owner location edge lost its actual Work/original issuer')
        return self


def _issue_owner_legacy_certificate_edge_v3(work,prepared,column,certificate_span,issue_span,
        issue,core_issue_json,prepared_issue_json):
    header=column.header_values
    names=('authority_id','installation_id','namespace','operation_id','maintenance_generation',
        'old_incarnation','new_incarnation','accepted_receipt_digest','barrier_receipt_digest',
        'frozen_inventory_digest','prior_certificate_digest','tombstone_root','cold_read_digest','certificate_digest')
    return OwnerLegacyCertificateEdgeV3(_OWNER_LOCATION_EDGE_ISSUER_V3,work,prepared,column,
        certificate_span,issue_span,issue,core_issue_json,prepared_issue_json,**{name:header[name]for name in names})



from .c09_selected_history_v3 import _bounded, _read_one
from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
from .c09_prepared_storage_v3 import _read_original
from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_original_v1, verify_graph_rebase_issue_signature_v1
from .c09_graph_rebase_issue_v2 import _read_issue, _verify_signature, _wire as _issue_wire_v2
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_ticket_store import read_owner_migration_head_in_tx_v1
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .c09_graph_application_v1 import _read_selected_graph_ack_event_v3
from .erasure_closure_inventory import CleanupRunV2, _TABLES as _CLEANUP_TABLES_V3
from ..runtime.c09_paged_capture_contract_v2 import c09_paged_value_from_wire_v2, c09_paged_value_to_wire_v2

_OWNER_LOCATION_SOURCE_WORKS_V3=WeakSet()
_OWNER_LOCATION_EDGE_READ_WORKS_V3=WeakSet()
_OWNER_LOCATION_SOURCE_RESULTS_V3=WeakSet()
_OWNER_LOCATION_LEGACY_SELECTIONS_V3=WeakSet()
_OWNER_LOCATION_LEGACY_APPLIED_V3=WeakSet()


class _OwnerLocationLegacySelectionV3:
    # Own private location proof. It never masquerades as a selected V3 view.
    def __init__(self,issuer,work):
        from types import SimpleNamespace
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or work not in _OWNER_LOCATION_EDGE_READ_WORKS_V3:
            raise AuthorityUnavailable('actual legacy Owner location selection issuer required')
        graph=work.facts.work
        if (graph.view is not None or graph.context is None
                or graph.context._reader is not work.control
                or graph.manifest['schema'] not in ('sylanne3.c09.storage_manifest.v1','sylanne3.c09.storage_manifest.v2')
                or graph.current['stage']!='RELEASED'):
            raise AuthorityUnavailable('actual legacy RELEASED selection required')
        self.work=work;self.basis=self;self.control=work.control
        self.current=graph.current;self.manifest=graph.manifest;self.prepared=graph.context.prepared_original
        self.selection_digest=work.proof.selection_digest
        self.scope=SimpleNamespace(graph_namespace=canonical_serialize(work.proof.namespace.as_tuple))
        self.history_count=self.manifest['generation'];self.history_root=None;self.complete=False
        self.published=False
        self.original_caller=work.proof;self.permission_anchor=work.proof.permission_anchor
        self.graph_comparison_anchor=work.proof.graph_comparison_anchor
        self.read_cut=(self.current['pointer_version'],self.manifest['manifest_digest'],work.facts.graph_epoch)
        self.history_range=(1,self.manifest['generation'])
        self.last_prepared_raw_sha256=self.last_prepared_byte_count=None

    def require_current(self,*,meter):
        if self.work not in _OWNER_LOCATION_EDGE_READ_WORKS_V3 or self.work.failed is not None:
            raise AuthorityUnavailable('actual legacy location selection lost its original Work')
        return self.work.facts.work._require_selected(meter)


class _OwnerLocationLegacyAppliedV3:
    def __init__(self,issuer,work,release,ack):
        if (issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or work not in _OWNER_LOCATION_EDGE_READ_WORKS_V3
                or not work.history_eof or not work.view.complete):
            raise AuthorityUnavailable('actual complete legacy Owner ACK/history EOF required')
        self.work,self.view,self.release,self.ack=work,work.view,release,ack
        self.published=False
        self.closed_sequence=work.edge_closed_sequence
        self.suffix_start=ack['prior_applied_seq'];self.suffix_end=ack['deletion_seq']
        self.suffix_count=work.last_suffix_count;self.suffix_digest=(ack['cumulative_suffix_digest']
            if ack['schema']=='sylanne3.c09.cumulative-graph-ack.v1'else ack['suffix_eof_digest'])
        self.graph_receipt_digest=ack['graph_receipt_digest'];self.core_applied_state=None


class _OwnerLocationHistoricalEdgeReadV3:
    def __init__(self,issuer,work,reader,prepared):
        if (issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or work not in _OWNER_LOCATION_EDGE_READ_WORKS_V3
                or reader.result is not prepared or prepared._control is not work.control):
            raise AuthorityUnavailable('actual authenticated PREPARED reader and summary required')
        self.work,self.reader,self.prepared=work,reader,prepared
        self.phase='manifest';self.manifest_json=self.release_json=self.ack_json=None
        self.issue=self.certificate=self.column=None;self.certificate_span=self.issue_span=None
        self.prepared_issue_bytes=bytearray();self.core_issue_json=None
        self.pending=self.accepted=self.closed=None;self.mutation_ids=None;self.mutation_index=0
        self.receipts={};self.accepted_mutation_id=None;self.ack=None;self.suffix_seq=self.suffix_root=None;self.suffix_count=0
        self.suffix_hash=None;self.complete=False;self.result=None

    def advance(self,meter):
        p=self.prepared;w=self.work;control=w.control;op=p['operation_id'];ns=p['namespace']
        p.require_current(meter=meter);w._require_current(meter)
        if self.phase=='manifest':
            with control._db()as db:
                row=_bounded(db,meter).execute('SELECT manifest_json,issuer_id,key_id,signature,generation '
                    'FROM c09_storage_manifests_v1 WHERE manifest_digest=?',(p['new_manifest_digest'],)).fetchone()
            if row is None:raise AuthorityUnavailable('actual historical signed manifest absent')
            manifest=json.loads(row[0]);control._manifest(manifest)
            from .c09_storage_manifest_v2 import manifest_signature_domain
            signed=control.sign_original_v1(manifest_signature_domain(manifest),
                dict(schema=manifest_signature_domain(manifest),manifest=manifest,issuer_id=control.authority_id),'digest')
            if ((row[1],row[2],row[3],row[4])!=(control.authority_id,control.key_id,signed['signature'],p['maintenance_generation'])
                    or manifest['manifest_digest']!=p['new_manifest_digest']):
                raise AuthorityUnavailable('actual historical manifest signature or PREPARED identity differs')
            self.manifest_json=row[0];self.phase='issue';return None
        if self.phase=='issue':
            with w._role_snapshot('core',meter)as core:
                if type(p)is C09VerifiedLegacyPreparedSummaryV2:
                    self.issue=read_graph_rebase_issue_original_v1(_bounded(core,meter),ns,op)
                    if self.issue is None:raise AuthorityUnavailable('actual historical V1 Core issue absent')
                    verify_graph_rebase_issue_signature_v1(self.issue,control._key)
                    self.core_issue_json=canonical_serialize(asdict(self.issue))
                else:
                    self.issue=_read_issue(_bounded(core,meter),ns,op)
                    if self.issue is None:raise AuthorityUnavailable('actual historical V2 Core issue absent')
                    _verify_signature(self.issue,control._key)
                    self.core_issue_json=canonical_serialize(_issue_wire_v2(self.issue))
            self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,role='graph',
                kind='graph_certificate_v1'if type(p)is C09VerifiedLegacyPreparedSummaryV2 else'graph_certificate_v2',
                namespace=w.proof.namespace,operation_id=op)
            self.phase='certificate';return None
        if self.phase=='certificate':
            with w._role_snapshot('graph',meter)as graph:
                if not self.column.advance(graph,w.facts.work.view,meter):return None
                table='graph_c09_rebase_certificates_v1'if type(p)is C09VerifiedLegacyPreparedSummaryV2 else'graph_c09_rebase_certificates_v2'
                row=None if type(p)is C09VerifiedLegacyPreparedSummaryV2 else _read_one(graph,'SELECT issue_digest FROM '+table+
                    ' WHERE bot=? AND persona=? AND operation_id=?',(*w.proof.namespace.as_tuple,op),meter)
            issue_certificate_digest=(self.issue.certificate_digest if type(p)is C09VerifiedLegacyPreparedSummaryV2
                else self.issue.certificate.certificate_digest)
            if (issue_certificate_digest!=json.loads(self.manifest_json)['certificate_digest']
                    or type(p)is not C09VerifiedLegacyPreparedSummaryV2 and row!=(self.issue.issue_digest,)):
                raise AuthorityUnavailable('actual historical Graph certificate row differs from signed manifest/Core issue')
            if type(p)is C09VerifiedLegacyPreparedSummaryV2:
                self.certificate_span=_OwnerLocationAuthenticatedSpanV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                    self.reader,'graph_certificate_original')
                self.phase='legacy_certificate_span'
            else:
                self.certificate=c09_paged_value_from_wire_v2(json.loads(self.column.text()),GraphErasureRebaseCertificateV2)
                if self.certificate!=self.issue.certificate:
                    raise AuthorityUnavailable('actual historical Graph V2 certificate differs from signed Core issue')
                self.phase='paged_issue_original'
            return None
        if self.phase=='legacy_certificate_span':
            if not self.certificate_span.advance(control,meter):return None
            self.issue_span=_OwnerLocationAuthenticatedSpanV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self.reader,'graph_issue_original')
            self.phase='legacy_issue_span';return None
        if self.phase=='legacy_issue_span':
            span=self.issue_span
            if span.position<span.span[1]:
                size=min(16384,span.span[1]-span.position)
                if len(self.prepared_issue_bytes)+size>65536:
                    raise AuthorityUnavailable('actual V1 issue exceeds its registered metadata descriptor')
                with control._db()as db:chunk=self.reader.cell.read(db,span.position,size,meter)
                span.hash.update(chunk);self.prepared_issue_bytes.extend(chunk);span.position+=size
                return None
            span.sha256=span.hash.hexdigest();span.complete=True
            self.certificate=_issue_owner_legacy_certificate_edge_v3(w.facts.work,p,self.column,
                self.certificate_span,span,self.issue,self.core_issue_json,self.prepared_issue_bytes.decode('utf-8'))
            self.phase='release';return None
        if self.phase=='paged_issue_original':
            with control._db()as db:
                details=_read_original(control,db,op,'graph_issued_v2',p['graph_issue_original_digest'],meter)
            if details!=_issue_wire_v2(self.issue):
                raise AuthorityUnavailable('actual historical Control issue original differs from signed Core issue')
            self.phase='paged_mirror_original';return None
        if self.phase=='paged_mirror_original':
            with control._db()as db:
                details=_read_original(control,db,op,'graph_mirror_v2',p['graph_mirror_original_digest'],meter)
            member=next(item for item in json.loads(self.manifest_json)['members']if item['role']=='graph')
            if (set(details)!={'schema','scope_digest','certificate_digest','graph_issue_digest','target_path','target_identity','target_file_sha256','cold_read_digest'}
                    or details['schema']!='sylanne3.c09.graph-mirror-completion.v2'
                    or details['scope_digest']!=self.certificate.candidate.scope.scope_digest
                    or details['certificate_digest']!=self.certificate.certificate_digest
                    or details['graph_issue_digest']!=self.issue.issue_digest
                    or details['target_path']!=member['resolved_path']
                    or tuple(details['target_identity'])[:2]!=(member['device'],member['file_id'])
                    or details['target_file_sha256']!=member['prepared_sha256']):
                raise AuthorityUnavailable('actual historical Control mirror original differs from canonical Graph EOF')
            self.phase='release';return None
        if self.phase=='release':
            with control._db()as db:
                row=_bounded(db,meter).execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='RELEASED'",(op,)).fetchone()
            if row is None:raise AuthorityUnavailable('actual historical signed RELEASED event absent')
            event=json.loads(row[0]);control.verify_original_v1(event,'event_digest')
            release=event['details']['release_original'];control.verify_original_v1(release,'release_digest')
            if (release['operation_id']!=op or release['installation_id']!=control.installation_id
                    or release['manifest_digest']!=p['new_manifest_digest']
                    or release['storage_generation']!=p['maintenance_generation']or release['state']!='applied'):
                raise AuthorityUnavailable('actual historical RELEASED original scope differs')
            self.release_json=canonical_serialize(release);self.phase='accepted_locator';return None
        if self.phase=='accepted_locator':
            from .erasure_closure_inventory import AuthorityErasureClosureInventory
            with w._role_snapshot('core',meter)as core:
                run=AuthorityErasureClosureInventory._read_record(_bounded(core,meter),_CLEANUP_TABLES_V3[1],op,CleanupRunV2)
                if (run is None or run.namespace!=ns or run.accepted_receipt_digest!=p['accepted_receipt_digest']
                        or run.graph_barrier_receipt_digest!=p['barrier_receipt_digest']):
                    raise AuthorityUnavailable('actual historical accepted cleanup locator differs from signed PREPARED')
            self.accepted_mutation_id=run.accepted_mutation_id;self.phase='accepted_mutation';return None
        if self.phase=='accepted_mutation':
            with w._role_snapshot('core',meter)as core:
                saved=AuthorityV2FenceStore.mutation_locked(_bounded(core,meter),self.accepted_mutation_id)
                decoded=None if saved is None else AuthorityV2FenceStore._decode_mutation_row(saved)
                if (decoded is None or decoded[0]!='deletion'or decoded[2]is None
                        or canonical_digest(decoded[2])!=p['accepted_receipt_digest']):
                    raise AuthorityUnavailable('actual historical accepted mutation original absent/changed')
                self.accepted=decoded[2]
                ids=tuple(_bounded(core,meter).execute("SELECT mutation_id FROM authority_v2_mutations WHERE namespace=? AND operation_id=? AND mutation_kind='deletion' ORDER BY mutation_id LIMIT 4",
                    (ns,self.accepted.pending.permit.operation_id)))
            if len(ids)!=3:raise AuthorityUnavailable('actual historical exact three deletion entrance originals required')
            self.mutation_ids=tuple(row[0]for row in ids);self.phase='mutations';return None
        if self.phase=='mutations':
            mutation=self.mutation_ids[self.mutation_index]
            with w._role_snapshot('core',meter)as core:
                saved=AuthorityV2FenceStore.mutation_locked(_bounded(core,meter),mutation)
            decoded=None if saved is None else AuthorityV2FenceStore._decode_mutation_row(saved)
            if (decoded is None or decoded[0]!='deletion'or decoded[2]is None
                    or saved[1:3]!=(ns,decoded[1].permit.subject)
                    or decoded[1].deletion_operation_id!=op or decoded[1].target_phase not in('pending','accepted','closed')
                    or decoded[1].target_phase in self.receipts):
                raise AuthorityUnavailable('actual historical entrance mutation identity differs')
            self.receipts[decoded[1].target_phase]=decoded[2];self.mutation_index+=1
            if self.mutation_index==3:
                self.pending,self.closed=self.receipts['pending'],self.receipts['closed']
                if self.receipts['accepted']!=self.accepted:
                    raise AuthorityUnavailable('actual historical accepted receipt changed between exact reads')
                self.phase='closed_append'
            return None
        if self.phase=='closed_append':
            pending=self.closed.pending
            with w._role_snapshot('deletion',meter)as deletion:
                row=_read_one(deletion,'SELECT append_id,mutation_id,operation_id,phase,chain_digest FROM authority_deletion_v2_tail WHERE seq=?',
                    (pending.expected_deletion_seq,),meter)
            if (row!=(pending.expected_append_id,pending.mutation_id,op,'closed',pending.expected_append_digest)
                    or AuthorityV2DeletionGuard.expected_digest(pending)!=pending.expected_append_digest
                    or canonical_digest(self.closed)!=json.loads(self.release_json)['closed_digest']):
                raise AuthorityUnavailable('actual historical independent closed append differs')
            self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,role='graph',
                kind='graph_ack',namespace=w.proof.namespace,operation_id=op)
            self.phase='ack';return None
        if self.phase=='ack':
            with w._role_snapshot('graph',meter)as graph:
                if not self.column.advance(graph,w.facts.work.view,meter):return None
                row=_read_one(graph,'SELECT original_digest FROM graph_c09_cumulative_applications_v1 WHERE bot=? AND persona=? AND operation_id=?',
                    (*w.proof.namespace.as_tuple,op),meter)
            self.ack_json=self.column.text();ack=json.loads(self.ack_json)
            if row!=(ack['ack_digest'],)or canonical_digest({k:v for k,v in ack.items()if k!='ack_digest'})!=row[0]:
                raise AuthorityUnavailable('actual historical ACK canonical EOF commitment differs')
            if type(ack['prior_applied_seq'])is not int or not 0<=ack['prior_applied_seq']<ack['deletion_seq']:
                raise AuthorityUnavailable('actual historical ACK suffix interval differs')
            self.ack=ack;self.suffix_seq=ack['prior_applied_seq']
            if ack['schema']=='sylanne3.c09.cumulative-graph-ack.v1':
                if type(p)is C09VerifiedPagedPreparedSummaryV3:
                    raise AuthorityUnavailable('actual V3 prepared cannot claim a legacy ACK producer')
                self.suffix_hash=sha256();self.suffix_hash.update(b'[')
            elif ack['schema']=='sylanne3.c09.cumulative-graph-ack.v2'and type(p)is C09VerifiedPagedPreparedSummaryV3:
                selection=canonical_digest(('sylanne3.c09.selected-history-scope.v3',control.authority_id,control.installation_id,ns,
                    p['expected_pointer_version']+1,p['new_manifest_digest'],p['maintenance_generation'],p['prepared_digest']))
                if (ack['selection_digest']!=selection or ack['selected_history_count']!=p['maintenance_generation']
                        or ack['selected_history_root']!=w.next_history_root
                        or ack['suffix_algorithm']!='sylanne3.c09.applied-deletion-suffix.v2'):
                    raise AuthorityUnavailable('actual historical V3 ACK selected producer/history domain differs')
                self.suffix_root=canonical_digest(('sylanne3.c09.applied-deletion-suffix.v2',selection))
            else:raise AuthorityUnavailable('actual historical ACK version has no authenticated producer')
            w.qualified_operations[op]=self.certificate.certificate_digest
            self.phase='suffix';return None
        if self.phase=='suffix':
            with w._role_snapshot('deletion',meter)as deletion:
                row=_read_one(deletion,'SELECT seq,operation_id,phase,chain_digest FROM authority_deletion_v2_tail WHERE seq>? AND seq<=? ORDER BY seq LIMIT 1',
                    (self.suffix_seq,self.ack['deletion_seq']),meter)
            if row is not None:
                if (row[0]!=self.suffix_seq+1 or row[1]not in w.qualified_operations
                        or row[0]==self.ack['deletion_seq']and row[1:]!=(op,'closed',self.ack['deletion_digest'])):
                    raise AuthorityUnavailable('actual historical ACK suffix gap, uncertified operation or closed EOF differs')
                self.suffix_seq=row[0];self.suffix_count+=1
                if self.suffix_hash is not None:
                    if self.suffix_count>1:self.suffix_hash.update(b',')
                    self.suffix_hash.update(canonical_serialize(row).encode('utf-8'))
                else:self.suffix_root=canonical_digest((self.suffix_root,self.suffix_count,row))
                return None
            if self.suffix_seq!=self.ack['deletion_seq']or not self.suffix_count:
                raise AuthorityUnavailable('actual historical ACK suffix lacks complete EOF')
            if self.suffix_hash is not None:
                self.suffix_hash.update(b']')
                if self.suffix_hash.hexdigest()!=self.ack['cumulative_suffix_digest']:
                    raise AuthorityUnavailable('actual historical ACK v1 full tuple EOF digest differs')
            else:
                from .contract import JournalHead
                head=JournalHead(self.closed.after_anchor.deletion_journal_id,self.ack['deletion_seq'],self.ack['deletion_digest'])
                if (self.suffix_count!=self.ack['suffix_count']or self.suffix_root!=self.ack['suffix_root']
                        or canonical_digest((self.suffix_seq,head,self.suffix_root))!=self.ack['suffix_eof_digest']):
                    raise AuthorityUnavailable('actual historical ACK v2 suffix count/root/EOF differs')
            self.phase='effect';return None
        if self.phase=='effect':
            with w._role_snapshot('graph',meter)as graph:
                _read_selected_graph_ack_event_v3(graph,w.proof.namespace,self.ack,meter=meter)
            self.phase='core_effect';return None
        if self.phase in('core_effect','import_root'):
            if self.phase=='core_effect':
                event_digest=sha256(json.dumps((op,self.ack['deletion_seq'],self.ack['deletion_digest'],
                    'sha256:'+self.ack['graph_receipt_digest']),sort_keys=True,separators=(',',':')).encode()).hexdigest()
                with w._role_snapshot('core',meter)as core:
                    rows=tuple(_bounded(core,meter).execute("SELECT seq FROM authority_events WHERE namespace=? AND kind='scoped_erasure_applied' AND generation=? AND detail_digest=? LIMIT 2",
                        (ns,self.closed.after_anchor.activation_generation,event_digest)))
                if len(rows)!=1:raise AuthorityUnavailable('actual historical scoped application Core event absent/ambiguous')
                self.phase='import_root';return None
            legacy=type(p)is C09VerifiedLegacyPreparedSummaryV2
            c=self.certificate
            prior=(None if c.prior_certificate_digest is None else c.certificate_schema,c.prior_certificate_digest)if legacy else(c.prior_certificate_schema_or_none,c.prior_certificate_digest_or_none)
            if w.generation==0 and prior!=(None,None)and w.is_target:
                if w.import_root_reader is None:
                    w.import_root_reader=_OwnerLocationTargetImportRootReadV3(_OWNER_LOCATION_EDGE_ISSUER_V3,w,prior,p)
                    return None
                imported=w.import_root_reader.advance(meter)
                if imported is None:return None
                w.imported_root=imported;w.import_root_reader=None
                imported.require_for_v3(w,prior,p['old_manifest_digest'])
            if w.generation==0 and prior!=(None,None)and not w.is_target:
                raise AuthorityUnavailable('Source Owner location first certificate requires an independently authenticated predecessor; imported target genesis uses its separate target lineage')
            if w.last_certificate is not None and prior!=w.last_certificate:
                raise AuthorityUnavailable('actual historical prior certificate schema/digest does not join its authenticated predecessor')
            self.result=_issue_owner_location_edge_originals_v3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                view=w.view,prepared=p,certificate=c,issue=self.issue,manifest_json=self.manifest_json,
                release_json=self.release_json,ack_json=self.ack_json,pending=self.pending,accepted=self.accepted,closed=self.closed,
                graph_issue_original_digest=None if legacy else p['graph_issue_original_digest'],
                graph_mirror_original_digest=None if legacy else p['graph_mirror_original_digest'],
                legacy_prepared_certificate_digest=c.certificate_digest if legacy else None,
                legacy_prepared_issue_digest=self.issue.issue_digest if legacy else None,
                actual_prior_certificate_schema=prior[0],actual_prior_certificate_digest=prior[1],
                legacy_prepared_certificate_bytes_digest=self.certificate_span.sha256 if legacy else None,
                graph_certificate_bytes_digest=c.certificate_column.sha256 if legacy else sha256(canonical_serialize(c09_paged_value_to_wire_v2(c)).encode()).hexdigest(),
                legacy_prepared_issue_bytes_digest=self.issue_span.sha256 if legacy else None,
                core_issue_bytes_digest=sha256(self.core_issue_json.encode()).hexdigest(),
                imported_root=w.imported_root if w.is_target and w.generation==0 else None)
            self.complete=True;return self.result
        raise AuthorityUnavailable('unregistered actual historical Owner edge phase')


from weakref import WeakKeyDictionary
_OWNER_LOCATION_SOURCE_BY_FACTS_V3=WeakKeyDictionary()
_OWNER_LOCATION_SOURCE_FAILURES_V3=WeakKeyDictionary()


class _OwnerLocationSourceLineageWorkV3:
    def __init__(self,issuer,proof,facts):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual fixed Source Owner location Work issuer required')
        facts.require_for_v3(proof)
        service=proof.owner_service
        if (type(service)is not InstalledD12OwnerStorageAdmissionServiceV1
                or service.control is not proof.control or service.namespace_id!=proof.namespace
                or service.installation_id!=proof.installation_id or service.holder!=proof.holder
                or service.fences.core is not service.core
                or service.close_apply.control is not proof.control):
            raise AuthorityUnavailable('actual same-controller Source Owner service required')
        self.proof,self.facts,self.control,self.owner_service=proof,facts,proof.control,service
        self.head=proof.current_owner_head
        if (type(self.head)is not OwnerMigrationHeadV1 or self.head.state!='active'
                or self.head.guard.installation_id!=proof.installation_id
                or self.head.guard.namespace!=proof.namespace
                or self.head.guard.pending_revoke_operation_id is not None
                or self.head.guard.minimum_revocation_epoch or self.head.guard.minimum_revocation_revision):
            raise AuthorityUnavailable('actual current same-installation Source Owner head required')
        self.phase='source_head';self.failed=None;self.complete=False;self.pending_result=None
        self.pending_completion=False;self.result=None;self.lineage_facts=None;self.released=False;self.view=None;self.applied=None
        self.applied_reader=None;self.accumulator=None;self.reader=None;self.edge_reader=None
        self.generation=0;self.prior_prepared=self.prior_manifest=self.last_certificate=None;self.last_incarnation=None
        self.history_root=canonical_digest(('sylanne3.c09.selected-history-chain.v3',self.control.authority_id,self.control.installation_id))
        self.next_history_root=None;self.history_eof=False;self.qualified_operations={}
        self.last_release=self.last_ack=None;self.last_summary=None
        self.last_suffix_count=self.edge_closed_sequence=None;self.current_state=self.current_namespace_row=None
        self.same_origin=False;self.is_target=False;self.allocation_scan=None
        _OWNER_LOCATION_SOURCE_WORKS_V3.add(self)
        _OWNER_LOCATION_EDGE_READ_WORKS_V3.add(self)
        self.control.register_c09_retained_state_v3(self)
        try:
            self.facts.work._transfer_retained_owner_v3(self)
        except BaseException as exc:
            self.failed=str(exc)
            self.control._c09_retained_states_v3.discard(self)
            _OWNER_LOCATION_SOURCE_FAILURES_V3[self.facts]=self.failed
            raise

    def _require_current(self,meter):
        self.facts.require_for_v3(self.proof)
        self.facts.work._require_selected(meter)
        return require_owner_location_caller_proof_v3(self.proof,phase='before',
            graph_stamp=(self.facts.metadata,self.facts.graph_epoch))

    @contextmanager
    def _role_snapshot(self,role,meter):
        from contextlib import closing
        import sqlite3
        if role not in('core','graph','deletion'):
            raise AuthorityUnavailable('unregistered Source Owner location original role')
        self._require_current(meter)
        graph=self.facts.work
        if graph.view is not None:
            with graph.view.basis.read_database(role,meter=meter)as db:yield db
        else:
            member=next(item for item in graph.manifest['members']if item['role']==role)
            started=monotonic_ns()
            with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as db:
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                try:yield db
                finally:db.rollback()
            if monotonic_ns()-started>meter.budget.max_read_ns:
                raise AuthorityUnavailable('actual legacy Owner role snapshot exceeded its original read duration')
        self._require_current(meter)

    def _c09_retained_heap_bytes_v3(self,_seen=None):
        seen=set()if _seen is None else _seen;size=_owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)
        size+=self.facts.work._c09_retained_heap_bytes_v3(_seen=seen)
        if self.allocation_scan is not None:size+=self.allocation_scan.heap_v3(seen)
        size+=_owner_location_payload_heap_v3((self.head,self.qualified_operations,self.last_release,
            self.last_ack,self.prior_prepared,self.prior_manifest,self.last_certificate,
            self.pending_result,self.result,self.current_state,self.current_namespace_row,
            None if self.lineage_facts is None else self.lineage_facts.result),seen)
        if self.applied is not None:
            size+=_owner_location_payload_heap_v3((self.applied.release,self.applied.ack),seen)
        if self.applied_reader is not None:
            a=self.applied_reader;size+=_owner_heap_size_v3(a)
            size+=_owner_location_payload_heap_v3((a.release,a.issue,a.ack,a.closed),seen)
        if self.accumulator is not None:
            a=self.accumulator;size+=_owner_heap_size_v3(a)
            size+=_owner_location_payload_heap_v3((a.commitments,a.last_edge,a.origin_key),seen)
        if self.reader is not None:
            r=self.reader;size+=_owner_heap_size_v3(r)
            if hasattr(r,'header'):size+=_owner_location_payload_heap_v3(r.header,seen)
            if hasattr(r,'original'):size+=_owner_location_payload_heap_v3(r.original,seen)
            if hasattr(r,'cell'):
                c=r.cell;size+=_owner_heap_size_v3(c)
                size+=_owner_location_payload_heap_v3((c.spans,c.starts),seen)
                size+=_owner_location_parser_heap_v3(c.parser,seen)
        if self.edge_reader is not None:
            e=self.edge_reader;size+=_owner_heap_size_v3(e)
            size+=_owner_location_payload_heap_v3((e.prepared,e.manifest_json,e.release_json,e.ack_json,
                e.core_issue_json,e.prepared_issue_bytes,e.issue,
                e.certificate if type(e.certificate)is GraphErasureRebaseCertificateV2 else None,
                e.pending,e.accepted,e.closed,e.receipts,e.mutation_ids),seen)
            columns=(e.column,None if type(e.certificate)is not OwnerLegacyCertificateEdgeV3
                else e.certificate.certificate_column)
            for c in columns:
                if c is None or id(c)in seen:continue
                seen.add(id(c));size+=_owner_heap_size_v3(c)
                size+=_owner_location_payload_heap_v3((c.bytes,c.scalar,c.header_values,c.field_names,c.metadata,c.header),seen)
                size+=c.allocation.heap_v3(seen)
                if c.parser is not None:
                    size+=_owner_location_parser_heap_v3(c.parser,seen)
        return size

    def _advance(self,meter):
        self._require_current(meter)
        if self.phase=='source_head':
            with self._role_snapshot('core',meter)as core:
                actual=read_owner_migration_head_in_tx_v1(_bounded(core,meter),authority_namespace=self.owner_service.namespace)
            if actual!=self.head:
                raise AuthorityUnavailable('actual Source Owner Core head differs from retained header proof')
            grant=json.loads(self.facts.atom[1]);validate_owner_grant_v1(grant)
            if (self.facts.atom[0]!=1 or self.facts.atom[2]!=1
                    or _owner_wire_digest_v3(grant)!=self.head.grant_digest
                    or grant['principal']!=asdict(self.head.issue_operation.principal)
                    or grant['graph_incarnation']!=self.head.issue_proof.graph_incarnation
                    or json.loads(self.facts.proof_row[-1])!=json.loads(canonical_serialize(asdict(self.head.issue_proof)))):
                raise AuthorityUnavailable('actual immutable Source Owner grant/issue EOF differs from current Core original')
            req=self.facts.metadata.requirements
            if (grant['installation_id']!=self.proof.installation_id or grant['scope']!='/'.join(req.namespace.as_tuple)
                    or req.namespace!=self.proof.namespace or req.authority_namespace!=self.head.authority_namespace
                    or req.authority_id!=self.head.guard.authority_id or grant['activation_generation']!=req.activation_generation):
                raise AuthorityUnavailable('actual Source Owner grant/current Graph namespace or generation differs')
            self.same_origin=grant['graph_incarnation']==req.graph_incarnation
            if self.same_origin and self.facts.work.current['stage']=='READY':
                self.phase='final';return None
            if self.facts.work.current['stage']!='RELEASED':
                raise AuthorityUnavailable('moved Source Owner location requires actual RELEASED storage')
            self.view=self.facts.work.view
            if self.view is None:
                self.view=_OwnerLocationLegacySelectionV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self)
                if not self.same_origin:
                    self.accumulator=_OwnerLocationLineageAccumulatorV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        view=self.view,applied=None,metadata=self.facts.metadata,head=self.head,
                        source_grant_json=self.facts.atom[1],holder=self.proof.holder)
                self.phase='history'
            else:
                if type(self.view)is not VerifiedSelectedHistoryReadV3:
                    raise AuthorityUnavailable('actual Source selected history issuer differs')
                from .c09_close_apply_v1 import InstalledSelectedAppliedReadV3
                self.applied_reader=InstalledSelectedAppliedReadV3(self.control,self.view)
                self.phase='selected_applied'
            return None
        if self.phase=='selected_applied':
            result=self.applied_reader.advance(meter=meter)
            if type(result)is SelectedAppliedReadV3:
                self.applied=result
                if self.same_origin:
                    self.last_release=result.release;self.last_ack=result.ack;self.phase='mutable'
                else:
                    self.accumulator=_OwnerLocationLineageAccumulatorV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        view=self.view,applied=result,metadata=self.facts.metadata,head=self.head,
                        source_grant_json=self.facts.atom[1],holder=self.proof.holder)
                    self.phase='history'
                self.applied_reader=None
            return None
        if self.phase=='history':
            through=self.facts.work.manifest['generation']
            if self.reader is None:
                self.reader=begin_next_authenticated_prepared_reader_v2(self.control,
                    after_generation=self.generation,through_generation=through,meter=meter)
                if self.reader is not None:return None
                if self.reader is None:
                    if (self.generation!=through or self.prior_prepared!=self.view.basis.prepared['prepared_digest']
                            or self.prior_manifest!=self.view.basis.manifest['manifest_digest']
                            or self.last_certificate is None
                            or self.last_certificate[1]!=self.view.basis.manifest['certificate_digest']
                            or self.last_incarnation!=self.facts.metadata.requirements.graph_incarnation):
                        raise AuthorityUnavailable('actual Source Owner history EOF does not reach selected PREPARED')
                    self.history_eof=True
                    if type(self.view)is _OwnerLocationLegacySelectionV3:
                        self.view.history_root=self.history_root;self.view.complete=True
                        self.applied=_OwnerLocationLegacyAppliedV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self,
                            self.last_release,self.last_ack)
                        if self.accumulator is not None:self.accumulator.applied=self.applied
                    if self.accumulator is not None:self.lineage_facts=self.accumulator.finish(authenticated_stream_eof=True)
                    self.phase='mutable';return None
            if self.edge_reader is None:
                prepared=self.reader.advance(meter=meter)
                if prepared is None:return None
                if (prepared['maintenance_generation']!=self.generation+1
                        or prepared['prior_prepared_digest']!=self.prior_prepared
                        or self.prior_manifest is not None and prepared['old_manifest_digest']!=self.prior_manifest
                        or (prepared['authority_id'],prepared['installation_id'],prepared['namespace'])!=
                            (self.control.authority_id,self.control.installation_id,self.owner_service.namespace)):
                    raise AuthorityUnavailable('actual Source Owner history signed version/manifest chain differs')
                if self.generation==0:
                    with self.control._db()as db:
                        genesis=_read_one(db,'SELECT manifest_digest FROM c09_storage_manifests_v1 WHERE installation_id=? AND generation=0',
                            (self.control.installation_id,),meter)
                    if genesis!=(prepared['old_manifest_digest'],):
                        raise AuthorityUnavailable('actual Source Owner history does not start at installed genesis')
                self.next_history_root=canonical_digest(('sylanne3.c09.selected-history-member.v3',self.history_root,
                    prepared['maintenance_generation'],prepared['prepared_digest'],prepared['new_manifest_digest']))
                self.edge_reader=_OwnerLocationHistoricalEdgeReadV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self,self.reader,prepared)
                return None
            edge=self.edge_reader.advance(meter)
            if edge is not None:
                if self.accumulator is None:normal=_owner_location_lineage_edge_v3(edge)
                else:
                    self.accumulator.advance(edge);normal=self.accumulator.last_edge
                if self.last_incarnation is not None and normal.old_incarnation!=self.last_incarnation:
                    raise AuthorityUnavailable('actual historical Graph incarnation does not join its predecessor')
                self.last_incarnation=normal.new_incarnation
                self.generation=normal.maintenance_generation;self.prior_prepared=normal.prepared_digest
                self.prior_manifest=normal.new_manifest_digest;self.last_certificate=(normal.schema,normal.certificate_digest)
                self.history_root=self.next_history_root
                self.last_release=json.loads(edge.release_json);self.last_ack=json.loads(edge.ack_json)
                self.last_suffix_count=self.edge_reader.suffix_count;self.edge_closed_sequence=edge.closed.after_anchor.deletion_seq
                if type(self.view)is _OwnerLocationLegacySelectionV3:
                    from .c09_storage_control_v1 import canonical as control_canonical
                    if type(edge.prepared)is C09VerifiedLegacyPreparedSummaryV2:
                        cell=self.reader.cell
                        if not cell.complete or not cell.parser._finished:
                            raise AuthorityUnavailable('actual legacy PREPARED whole canonical EOF was not completed')
                        self.view.last_prepared_raw_sha256=cell.parser._sha256.hexdigest();self.view.last_prepared_byte_count=cell.parser.byte_count
                    else:
                        raw=control_canonical(dict(edge.prepared._header)).encode('utf-8')
                        self.view.last_prepared_raw_sha256=sha256(raw).hexdigest();self.view.last_prepared_byte_count=len(raw)
                self.edge_reader=self.reader=None
            return None
        if self.phase=='mutable':
            with self._role_snapshot('core',meter)as core:
                state=_read_one(core,'SELECT active_operation_id,aggregate_phase,applied_seq,applied_digest,applied_epoch FROM authority_scoped_erasure_v2 WHERE namespace=?',
                    (self.owner_service.namespace,),meter)
                live=_read_one(core,'SELECT deletion_phase,deletion_journal_id,deletion_seq,deletion_digest,execution_journal_id,revocation_epoch FROM authority_namespaces WHERE namespace=?',
                    (self.owner_service.namespace,),meter)
            release=self.last_release;req=self.facts.metadata.requirements
            if (state!=(None,'clear',release['applied_seq'],release['applied_digest'],release['applied_epoch'])
                    or live is None or live[0]!='clear' or live[1]!=req.deletion_journal_id
                    or live[2:4]!=(req.deletion_seq,req.deletion_digest)or live[4]!=req.execution_journal_id
                    or live[5]!=req.revocation_epoch or req.deletion_seq<release['applied_seq']):
                raise AuthorityUnavailable('actual Source current Core clear/applied/Graph requirements differ')
            self.current_state=state;self.current_namespace_row=live
            if type(self.applied)is _OwnerLocationLegacyAppliedV3:self.applied.core_applied_state=(state,live)
            self.phase='final';return None
        if self.phase=='final':
            with self._role_snapshot('core',meter)as core:
                actual=read_owner_migration_head_in_tx_v1(_bounded(core,meter),authority_namespace=self.owner_service.namespace)
            if actual!=self.head:
                raise AuthorityUnavailable('actual Source Owner head changed before location completion')
            graph=self.facts.work
            with graph._graph_snapshot(meter)as db:
                metadata=_read_one(db,'SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',
                    self.proof.namespace.as_tuple,meter)
                epoch=_read_one(db,'SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',self.proof.namespace.as_tuple,meter)
                grant=_read_one(db,('SELECT revision,valid,value_cell_id FROM graph_atoms 'if len(graph.grant_metadata)==3
                    else'SELECT revision,valid FROM graph_atoms ')+'WHERE token=? AND bot=? AND persona=?',
                    (owner_grant_key(*self.proof.namespace.as_tuple).token,*self.proof.namespace.as_tuple),meter)
                issue=_read_one(db,'SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',
                    self.proof.namespace.as_tuple,meter)
                epochs=_read_one(db,'SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',self.proof.namespace.as_tuple,meter)
            if (metadata!=(graph.schema,graph.recovery_json,graph.graph_revision)
                    or (0 if epoch is None else epoch[0])!=self.facts.graph_epoch.revision
                    or grant!=graph.grant_metadata or issue!=graph.issue_metadata or epochs!=self.facts.epochs):
                raise AuthorityUnavailable('actual Source Owner current Graph stamp/original locator changed before admission')
            require_owner_location_caller_proof_v3(self.proof,phase='after',
                graph_stamp=(self.facts.metadata,self.facts.graph_epoch))
            self.pending_result=None if self.lineage_facts is None else self.lineage_facts.result
            self.pending_completion=True;return dict(status='progress',phase='owner_location_quantum_commit')
        raise AuthorityUnavailable('unregistered actual Source Owner lineage Work phase')

    def advance(self,*,meter=None):
        if self.failed is not None:raise AuthorityUnavailable(self.failed)
        if self.complete:
            require_owner_location_caller_proof_v3(self.proof,phase='after',graph_stamp=(self.facts.metadata,self.facts.graph_epoch))
            return self.result
        active=peek_current_c09_sql_meter_v3()
        if meter is not None and active is not meter:
            raise AuthorityUnavailable('Source Owner lineage cannot replace its actual reserved root')
        try:
            if active is None:
                with self.control.reserve_control_read_v3()as budget:
                    actual=require_c09_reserved_meter_v3(budget)
                    result=_owner_location_growth_step_v3(self,actual)
                    self.control.require_c09_retained_arena_v3(meter=actual)
                if self.pending_completion:return self.complete_reserved_quantum_v3(self.proof)
            else:
                from .c09_storage_control_v1 import require_actual_c09_control_read_root_v3
                actual=require_actual_c09_control_read_root_v3(self.control,active)
                self.control.require_c09_retained_arena_v3(meter=actual)
                result=_owner_location_growth_step_v3(self,actual)
                self.control.require_c09_retained_arena_v3(meter=actual)
            if self.pending_completion:return result
            require_owner_location_caller_proof_v3(self.proof,phase='after',graph_stamp=(self.facts.metadata,self.facts.graph_epoch))
            return dict(status='progress',phase='owner_location_source_'+self.phase,
                generation=self.generation,edge_phase=None if self.edge_reader is None else self.edge_reader.phase)
        except BaseException as exc:
            self.cancel_v3(exc);raise

    def complete_reserved_quantum_v3(self,proof):
        if (proof is not self.proof or not self.pending_completion or self.failed is not None
                or peek_current_c09_sql_meter_v3()is not None):
            raise AuthorityUnavailable('Source Owner admission lacks successful actual quantum publication boundary')
        require_owner_location_caller_proof_v3(proof,phase='after',graph_stamp=(self.facts.metadata,self.facts.graph_epoch))
        self.result=self.pending_result;self.pending_result=None;self.pending_completion=False
        self.complete=True;self.phase='complete'
        _OWNER_LOCATION_SOURCE_RESULTS_V3.add(self)
        if type(self.view)is _OwnerLocationLegacySelectionV3:
            self.view.published=True;self.applied.published=True
            _OWNER_LOCATION_LEGACY_SELECTIONS_V3.add(self.view);_OWNER_LOCATION_LEGACY_APPLIED_V3.add(self.applied)
        self.reader=self.edge_reader=self.applied_reader=self.accumulator=None
        self.qualified_operations.clear()
        return self.result

    def close_v3(self):
        self.reader=self.edge_reader=self.applied_reader=self.accumulator=None;self.allocation_scan=None
        self.qualified_operations.clear();self.released=True
        if self.lineage_facts is not None:_OWNER_LOCATION_LINEAGE_FACTS_V3.discard(self.lineage_facts)
        if type(self.view)is _OwnerLocationLegacySelectionV3:_OWNER_LOCATION_LEGACY_SELECTIONS_V3.discard(self.view)
        if type(self.applied)is _OwnerLocationLegacyAppliedV3:_OWNER_LOCATION_LEGACY_APPLIED_V3.discard(self.applied)
        self.view=self.applied=self.last_summary=self.last_release=self.last_ack=self.lineage_facts=None
        self.result=None
        _OWNER_LOCATION_SOURCE_BY_FACTS_V3.pop(self.facts,None)
        self.control._c09_retained_states_v3.discard(self)

    def cancel_v3(self,error):
        if self.failed is None:self.failed=str(error)
        _OWNER_LOCATION_SOURCE_FAILURES_V3[self.facts]=self.failed
        self.pending_completion=False;self.pending_result=None;self.result=None
        self.close_v3()


def prepare_source_owner_location_lineage_v3(headerproof,facts):
    facts.require_for_v3(headerproof)
    failed=_OWNER_LOCATION_SOURCE_FAILURES_V3.get(facts)
    if failed is not None:raise AuthorityUnavailable(failed)
    work=_OWNER_LOCATION_SOURCE_BY_FACTS_V3.get(facts)
    if work is None:
        work=_OwnerLocationSourceLineageWorkV3(_OWNER_LOCATION_EDGE_ISSUER_V3,headerproof,facts)
        _OWNER_LOCATION_SOURCE_BY_FACTS_V3[facts]=work
    elif work.proof is not headerproof:
        raise AuthorityUnavailable('Source Owner lineage facts cannot change their actual header proof')
    if work.failed is not None:raise AuthorityUnavailable(work.failed)
    return work


def resolve_source_owner_storage_admission_from_completed_location_v3(headerproof,facts):
    facts.require_for_v3(headerproof)
    work=_OWNER_LOCATION_SOURCE_BY_FACTS_V3.get(facts)
    if (work is None or work.proof is not headerproof or work not in _OWNER_LOCATION_SOURCE_RESULTS_V3
            or not work.complete or work.failed is not None or work.released):
        raise AuthorityUnavailable('Source Owner location requires complete actual historical lineage/ACK EOF Work')
    require_owner_location_caller_proof_v3(headerproof,phase='after',graph_stamp=(facts.metadata,facts.graph_epoch))
    if work.result is not None and type(work.result)is not D12OwnerStorageAdmissionV1:
        raise AuthorityUnavailable('Source Owner location result is not its original admission wire type')
    return work.result



from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
from .v2_migration_store import AuthorityV2MigrationStore
from ..runtime.graph_migration_snapshot_v1 import TargetGraphImportReceiptV1,_hash as _migration_graph_hash_v3


def _require_actual_target_location_binding_v3(proof,facts,history,imported):
    # Actual CallerProof/session/key/migration qualifications remain Root factories.
    # This fixed comparison consumes complete Original EOF; it grants no scope.
    facts.require_for_v3(proof)
    service=proof.owner_service;head=proof.current_owner_head
    if (type(service)is not InstalledD12TargetOwnerAdmissionServiceV1
            or service.storage_continuation_reader is None
            or service.storage_continuation_reader.control is not proof.control
            or service.namespace_id!=proof.namespace or service.installation_id!=proof.installation_id
            or service.holder!=proof.holder or service.core is not service.migration.core
            or service.tickets._core is not service.core
            or type(history)is not MigrationStatusV2 or history.phase!='activated'
            or history.source_snapshot is None or history.target_recovery is None or history.target_permit is None
            or type(imported)is not TargetGraphImportReceiptV1
            or type(head)is not OwnerMigrationHeadV1 or head.state!='active'):
        raise AuthorityUnavailable('actual Target migration/Owner/service/read Original identities required')
    plan=history.plan;source=history.source_snapshot;target=history.target_recovery;req=facts.metadata.requirements
    if (plan.namespace_id!=proof.namespace or plan.namespace!=service.namespace
            or plan.target_installation_id!=service.installation_id or plan.target_holder!=service.holder
            or plan.source_installation_id!=head.guard.installation_id
            or head.authority_namespace!=service.namespace
            or history.source_permit.transfer_id!=plan.transfer_id
            or history.source_permit.installation_id!=plan.source_installation_id
            or history.source_permit.kind!='source_snapshot'
            or history.target_permit.installation_id!=plan.target_installation_id
            or history.target_permit.holder!=plan.target_holder or history.target_permit.kind!='target_recovery'
            or history.target_permit.transfer_id!=plan.transfer_id
            or source.permit_token!=history.source_permit.token
            or target.permit_token!=history.target_permit.token
            or target.target_generation!=history.target_permit.generation
            or (source.namespace,target.namespace,imported.namespace)!=(plan.namespace,plan.namespace,proof.namespace)
            or source.source_installation_id!=plan.source_installation_id
            or target.target_installation_id!=plan.target_installation_id
            or target.snapshot_digest!=source.snapshot_digest
            or imported.transfer_id!=plan.transfer_id or imported.snapshot_digest!=source.snapshot_digest
            or imported.closure_digest!=source.closure_digest
            or imported.source_graph_incarnation!=source.graph_incarnation
            or imported.source_graph_revision!=source.graph_revision
            or imported.graph_epoch!=source.graph_epoch
            or imported.target_graph_incarnation!=target.new_graph_incarnation
            or imported.target_activation_generation!=history.target_permit.generation
            or imported.graph_commit_digest!=target.graph_commit_digest
            or facts.metadata.graph_revision<imported.target_graph_revision
            or req.namespace!=plan.namespace_id or req.authority_namespace!=plan.namespace
            or req.authority_id!=head.guard.authority_id or req.activation_generation!=history.target_permit.generation):
        raise AuthorityUnavailable('Target exact source snapshot/import/activation/Owner location relation differs')
    anchor=proof.graph_comparison_anchor
    if (req.authority_id,req.authority_namespace,req.activation_generation,req.revocation_epoch,
            req.deletion_journal_id,req.deletion_seq,req.deletion_digest,
            req.execution_journal_id,req.execution_seq,req.execution_digest)!=(
            anchor.authority_id,anchor.namespace,anchor.activation_generation,anchor.revocation_epoch,
            anchor.deletion_journal_id,anchor.deletion_seq,anchor.deletion_digest,
            anchor.execution_journal_id,anchor.execution_seq,anchor.execution_digest):
        raise AuthorityUnavailable('Target current Graph comparison anchor differs from its actual caller proof')
    grant=json.loads(facts.atom[1]);validate_owner_grant_v1(grant)
    if (facts.atom[0]!=head.grant_revision or facts.atom[2]!=1
            or _owner_wire_digest_v3(grant)!=head.grant_digest
            or grant['installation_id']!=plan.source_installation_id
            or grant['scope']!='/'.join(plan.namespace_id.as_tuple)
            or grant['principal']!=asdict(head.issue_operation.principal)
            or grant['graph_incarnation']!=head.issue_proof.graph_incarnation
            or json.loads(facts.proof_row[-1])!=json.loads(canonical_serialize(asdict(head.issue_proof)))):
        raise AuthorityUnavailable('Target immutable source grant/Owner issue EOF differs; source identity is never relabelled')
    return service,head


class _OwnerLocationTargetImportReadV3:
    def __init__(self,issuer,work):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or work not in _OWNER_LOCATION_TARGET_WORKS_V3:
            raise AuthorityUnavailable('actual fixed Target import Original reader required')
        self.work=work;self.column=None;self.metadata=None;self.complete=False;self.result=None

    def advance(self,meter):
        w=self.work;history=w.history;ns=w.proof.namespace;transfer=history.plan.transfer_id
        with w._role_snapshot('graph',meter)as db:
            if self.column is None:
                self.metadata=_read_one(db,'SELECT snapshot_digest,closure_digest,source_graph_revision,target_graph_revision '
                    'FROM graph_migration_import_receipts_v1 WHERE bot=? AND persona=? AND transfer_id=?',
                    (*ns.as_tuple,transfer),meter)
                if self.metadata is None:raise AuthorityUnavailable('actual Target import Original absent')
                self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                    role='graph',kind='target_import',namespace=ns,transfer_id=transfer)
            if not self.column.advance(db,w.facts.work.view,meter):return None
        raw=json.loads(self.column.text())
        if set(raw)!=set(TargetGraphImportReceiptV1.__dataclass_fields__):
            raise AuthorityUnavailable('actual Target import Original has unknown fields')
        values=dict(raw);values['namespace']=NamespaceId(**values['namespace'])
        imported=TargetGraphImportReceiptV1(**values);body=asdict(imported);body.pop('graph_commit_digest')
        if (self.metadata!=(imported.snapshot_digest,imported.closure_digest,
                imported.source_graph_revision,imported.target_graph_revision)
                or imported.graph_commit_digest!=_migration_graph_hash_v3(body)):
            raise AuthorityUnavailable('actual Target import full canonical EOF commitment differs')
        _require_actual_target_location_binding_v3(w.proof,w.facts,history,imported)
        self.result=imported;self.complete=True;return imported



_OWNER_LOCATION_TARGET_WORKS_V3=WeakSet()
_OWNER_LOCATION_TARGET_BY_FACTS_V3=WeakKeyDictionary()
_OWNER_LOCATION_TARGET_FAILURES_V3=WeakKeyDictionary()
_OWNER_LOCATION_TARGET_RESULTS_V3=WeakSet()


class _OwnerLocationTargetLineageWorkV3(_OwnerLocationSourceLineageWorkV3):
    def __init__(self,issuer,proof,facts):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3:
            raise AuthorityUnavailable('actual fixed Target location Work issuer required')
        facts.require_for_v3(proof)
        service=proof.owner_service;head=proof.current_owner_head;history=proof.target_history
        if (type(service)is not InstalledD12TargetOwnerAdmissionServiceV1
                or service.storage_continuation_reader is None
                or service.storage_continuation_reader.control is not proof.control
                or service.storage_continuation_reader.close_apply.service.core is not service.core
                or service.namespace_id!=proof.namespace or service.installation_id!=proof.installation_id
                or service.holder!=proof.holder or service.core is not service.migration.core
                or type(head)is not OwnerMigrationHeadV1 or head.state!='active'
                or type(history)is not MigrationStatusV2 or history.phase!='activated'
                or head.guard.installation_id!=history.plan.source_installation_id
                or proof.target_role not in('public_session','background_existing','public_session_header','background_existing_header')):
            raise AuthorityUnavailable('actual Target controller/history/identity-role proof required')
        self.proof,self.facts,self.control,self.owner_service=proof,facts,proof.control,service
        self.head,self.history=head,history;self.phase='target_head';self.is_target=True
        self.failed=None;self.complete=False;self.pending_result=None;self.pending_completion=False
        self.result=self.lineage_facts=None;self.released=False;self.view=self.applied=None
        self.applied_reader=self.accumulator=self.reader=self.edge_reader=None
        self.generation=0;self.prior_prepared=self.prior_manifest=self.last_certificate=self.last_incarnation=None
        self.history_root=canonical_digest(('sylanne3.c09.selected-history-chain.v3',self.control.authority_id,self.control.installation_id))
        self.next_history_root=None;self.history_eof=False;self.qualified_operations={}
        self.last_release=self.last_ack=self.last_summary=None
        self.last_suffix_count=self.edge_closed_sequence=None;self.current_state=self.current_namespace_row=None
        self.same_origin=False;self.allocation_scan=None;self.import_reader=None;self.imported=None;self.import_root_reader=self.imported_root=None
        self.transfer_cursor='';self.transfer_candidate_count=0;self.transfer_pending=None
        _OWNER_LOCATION_TARGET_WORKS_V3.add(self)
        _OWNER_LOCATION_EDGE_READ_WORKS_V3.add(self)
        self.control.register_c09_retained_state_v3(self)
        try:
            self.facts.work._transfer_retained_owner_v3(self)
        except BaseException as exc:
            self.failed=str(exc)
            self.control._c09_retained_states_v3.discard(self)
            _OWNER_LOCATION_TARGET_FAILURES_V3[self.facts]=self.failed
            raise

    def _c09_retained_heap_bytes_v3(self):
        seen=set();size=super()._c09_retained_heap_bytes_v3(_seen=seen)
        size+=_owner_location_payload_heap_v3((self.history,self.imported,self.transfer_pending,
            self.transfer_cursor,self.transfer_candidate_count),seen)
        if self.import_reader is not None and self.import_reader.column is not None:
            c=self.import_reader.column
            size+=_owner_heap_size_v3(c)+_owner_location_payload_heap_v3((c.bytes,c.metadata),seen)
            size+=c.allocation.heap_v3(seen)
            if c.parser is not None:size+=_owner_location_parser_heap_v3(c.parser,seen)
        root=self.import_root_reader
        if root is not None:
            size+=_owner_heap_size_v3(root)+_owner_location_payload_heap_v3((root.source_set,root.activation_set,root.member,root.issue,root.prior,root.prepared),seen)
            c=root.column
            if c is not None:
                size+=_owner_heap_size_v3(c)+_owner_location_payload_heap_v3((c.bytes,c.scalar,c.header_values,c.field_names,c.metadata,c.header),seen)
                size+=c.allocation.heap_v3(seen)
                if c.parser is not None:size+=_owner_location_parser_heap_v3(c.parser,seen)
        root=self.imported_root
        if root is not None:
            size+=_owner_heap_size_v3(root)+_owner_location_payload_heap_v3((root.source_set,root.activation_set,root.member,root.issue,root.raw_sha256,root.raw_byte_count,root.old_manifest_digest),seen)
        return size

    def _advance(self,meter):
        self._require_current(meter)
        if self.phase=='target_head':
            with self._role_snapshot('core',meter)as core:
                actual=read_owner_migration_head_in_tx_v1(_bounded(core,meter),authority_namespace=self.owner_service.namespace)
            if actual!=self.head:
                raise AuthorityUnavailable('actual Target Core immutable Owner head differs from retained caller proof')
            self.phase='target_transfer_locator';return None
        if self.phase=='target_transfer_locator':
            with self._role_snapshot('core',meter)as core:
                row=_read_one(core,"SELECT transfer_id FROM authority_migration_v2_plans WHERE namespace=? AND phase='activated' AND transfer_id COLLATE BINARY>? ORDER BY transfer_id COLLATE BINARY LIMIT 1",
                    (self.owner_service.namespace,self.transfer_cursor),meter)
            if row is None:
                if self.transfer_candidate_count!=1:
                    raise AuthorityUnavailable('actual Target requires its unique activated history Original')
                self.import_reader=_OwnerLocationTargetImportReadV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self)
                self.phase='target_import';return None
            self.transfer_pending=row[0];self.phase='target_transfer_original';return None
        if self.phase=='target_transfer_original':
            with self._role_snapshot('core',meter)as core:
                actual=AuthorityV2MigrationStore.status_locked(_bounded(core,meter),self.transfer_pending)
            if actual is None:raise AuthorityUnavailable('actual Target migration Original disappeared during keyset EOF')
            if (actual.plan.target_installation_id==self.owner_service.installation_id
                    and actual.plan.target_holder==self.owner_service.holder
                    and actual.target_permit.generation==self.facts.metadata.requirements.activation_generation):
                if actual!=self.history:
                    raise AuthorityUnavailable('actual Target matching migration differs from its retained qualified history')
                self.transfer_candidate_count+=1
                if self.transfer_candidate_count>1:
                    raise AuthorityUnavailable('actual Target activated migration is ambiguous')
            self.transfer_cursor=self.transfer_pending;self.transfer_pending=None
            self.phase='target_transfer_locator';return None
        if self.phase=='target_import':
            imported=self.import_reader.advance(meter)
            if imported is None:return None
            self.imported=imported;self.import_reader=None
            _require_actual_target_location_binding_v3(self.proof,self.facts,self.history,imported)
            req=self.facts.metadata.requirements;origin=self.history.target_recovery.new_graph_incarnation
            self.same_origin=(req.graph_incarnation==origin and req.revocation_epoch==
                self.history.target_recovery.current_requirements.revocation_epoch)
            if self.same_origin and self.facts.work.current['stage']=='READY':
                self.phase='final';return None
            if self.facts.work.current['stage']!='RELEASED':
                raise AuthorityUnavailable('actual Target storage continuation requires RELEASED C09 selection')
            self.view=self.facts.work.view
            if self.view is None:
                self.view=_OwnerLocationLegacySelectionV3(_OWNER_LOCATION_EDGE_ISSUER_V3,self)
                if not self.same_origin:
                    self.accumulator=_OwnerLocationLineageAccumulatorV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        view=self.view,applied=None,metadata=self.facts.metadata,head=self.head,
                        source_grant_json=self.facts.atom[1],holder=self.proof.holder,history=self.history)
                self.phase='history'
            else:
                from .c09_close_apply_v1 import InstalledSelectedAppliedReadV3
                self.applied_reader=InstalledSelectedAppliedReadV3(self.control,self.view)
                self.phase='target_selected_applied'
            return None
        if self.phase=='target_selected_applied':
            result=self.applied_reader.advance(meter=meter)
            if type(result)is SelectedAppliedReadV3:
                self.applied=result
                if self.same_origin:
                    self.last_release=result.release;self.last_ack=result.ack;self.phase='mutable'
                else:
                    self.accumulator=_OwnerLocationLineageAccumulatorV3(_OWNER_LOCATION_EDGE_ISSUER_V3,
                        view=self.view,applied=result,metadata=self.facts.metadata,head=self.head,
                        source_grant_json=self.facts.atom[1],holder=self.proof.holder,history=self.history)
                    self.phase='history'
                self.applied_reader=None
            return None
        if self.phase=='final':
            _require_actual_target_location_binding_v3(self.proof,self.facts,self.history,self.imported)
        return super()._advance(meter)

    def complete_reserved_quantum_v3(self,proof):
        result=super().complete_reserved_quantum_v3(proof)
        _OWNER_LOCATION_SOURCE_RESULTS_V3.discard(self)
        _OWNER_LOCATION_TARGET_RESULTS_V3.add(self)
        return result

    def close_v3(self):
        self.import_reader=self.import_root_reader=None;self.transfer_pending=None
        super().close_v3()
        _OWNER_LOCATION_TARGET_BY_FACTS_V3.pop(self.facts,None)

    def cancel_v3(self,error):
        if self.failed is None:self.failed=str(error)
        _OWNER_LOCATION_TARGET_FAILURES_V3[self.facts]=self.failed
        self.pending_completion=False;self.pending_result=None;self.result=None
        self.close_v3()


def prepare_target_owner_location_lineage_v3(headerproof,facts):
    facts.require_for_v3(headerproof)
    failed=_OWNER_LOCATION_TARGET_FAILURES_V3.get(facts)
    if failed is not None:raise AuthorityUnavailable(failed)
    work=_OWNER_LOCATION_TARGET_BY_FACTS_V3.get(facts)
    if work is None:
        work=_OwnerLocationTargetLineageWorkV3(_OWNER_LOCATION_EDGE_ISSUER_V3,headerproof,facts)
        _OWNER_LOCATION_TARGET_BY_FACTS_V3[facts]=work
    elif work.proof is not headerproof:
        raise AuthorityUnavailable('Target location facts cannot change their actual caller proof')
    return work


def resolve_target_owner_storage_continuation_from_completed_location_v3(headerproof,facts):
    facts.require_for_v3(headerproof)
    work=_OWNER_LOCATION_TARGET_BY_FACTS_V3.get(facts)
    if (work is None or work.proof is not headerproof or work not in _OWNER_LOCATION_TARGET_RESULTS_V3
            or not work.complete or work.failed is not None or work.released):
        raise AuthorityUnavailable('Target location requires completed actual import/history/ACK EOF Work')
    require_owner_location_caller_proof_v3(headerproof,phase='after',graph_stamp=(facts.metadata,facts.graph_epoch))
    if work.result is not None and type(work.result)is not D12C09TargetContinuationV1:
        raise AuthorityUnavailable('Target location cannot return a Source storage admission')
    return work.result



_OWNER_LOCATION_TARGET_IMPORT_ROOTS_V3=WeakSet()

@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _OwnerLocationTargetImportRootV3:
    issuer: InitVar[object]
    work: object
    source_set: object
    activation_set: object
    member: object
    issue: object
    raw_sha256: str
    raw_byte_count: int
    old_manifest_digest: str
    def __post_init__(self,issuer):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or self.work not in _OWNER_LOCATION_TARGET_WORKS_V3:
            raise AuthorityUnavailable('actual Target imported certificate root issuer required')
        _OWNER_LOCATION_TARGET_IMPORT_ROOTS_V3.add(self)
    def require_for_v3(self,work,prior,old_manifest_digest):
        if (self not in _OWNER_LOCATION_TARGET_IMPORT_ROOTS_V3 or self.work is not work
                or work.failed is not None or (self.member.certificate_schema,self.member.certificate_digest)!=prior
                or self.old_manifest_digest!=old_manifest_digest
                or self.raw_sha256!=self.member.raw_sha256 or self.raw_byte_count!=self.member.raw_byte_count):
            raise AuthorityUnavailable('actual Target import-root Original/EOF/selected genesis relation differs')
        return self

class _OwnerLocationTargetImportRootReadV3:
    def __init__(self,issuer,work,prior,prepared):
        if issuer is not _OWNER_LOCATION_EDGE_ISSUER_V3 or work not in _OWNER_LOCATION_TARGET_WORKS_V3 or work.generation!=0:
            raise AuthorityUnavailable('actual first Target historical edge import-root reader required')
        self.work,self.prior,self.prepared=work,prior,prepared;self.phase='source_set'
        self.source_set=self.activation_set=self.member=self.issue=self.column=None
        self.complete=False;self.result=None
    def advance(self,meter):
        from .migration_snapshot_certificate_members_v1 import (
            read_snapshot_certificate_member_set_in_tx_v1,
            read_snapshot_certificate_member_by_original_in_tx_v1,
            read_activation_certificate_members_in_tx_v1,MigrationSnapshotCertificateSourceV1,
            _key as require_actual_migration_member_core_key_v3)
        from dataclasses import fields
        w=self.work;w._require_current(meter);h=w.history;plan=h.plan;source=h.source_snapshot;target=h.target_recovery
        core=w.owner_service.core
        if self.phase in('source_set','activation','member','issue'):
            with w._role_snapshot('core',meter)as db:
                bounded=_bounded(db,meter)
                if self.phase=='source_set':
                    self.source_set=read_snapshot_certificate_member_set_in_tx_v1(core,bounded,plan.namespace,plan.transfer_id)
                    s=self.source_set
                    if (s.authority_id,s.namespace,s.namespace_id,s.transfer_id,s.source_installation_id,
                            s.source_permit_token,s.source_permit_digest,s.source_permit_generation,
                            s.source_graph_incarnation,s.source_graph_revision,s.source_graph_epoch,
                            s.source_requirements_digest,s.snapshot_format,s.snapshot_digest,s.closure_digest)!=(
                            source.requirements.authority_id,plan.namespace,plan.namespace_id,plan.transfer_id,plan.source_installation_id,
                            h.source_permit.token,canonical_digest(h.source_permit),h.source_permit.generation,
                            source.graph_incarnation,source.graph_revision,source.graph_epoch,
                            canonical_digest(source.requirements),source.snapshot_format,source.snapshot_digest,source.closure_digest):
                        raise AuthorityUnavailable('actual signed import-root Source snapshot/permit Original differs')
                    self.phase='activation';return None
                if self.phase=='activation':
                    self.activation_set=read_activation_certificate_members_in_tx_v1(core,bounded,plan.namespace,plan.transfer_id)
                    a=self.activation_set;s=self.source_set;receipt=h.receipts[-1]
                    if (a.authority_id,a.namespace,a.namespace_id,a.transfer_id,a.source_set_digest,
                            a.source_set_signature_commitment,a.member_count,a.member_root,a.source_installation_id,
                            a.source_graph_incarnation,a.snapshot_digest,a.closure_digest,a.target_installation_id,
                            a.target_permit_token,a.target_permit_digest,a.target_generation,a.new_graph_incarnation,
                            a.graph_commit_digest,a.recovery_digest,a.activation_receipt_digest,a.activation_anchor_digest)!=(
                            s.authority_id,s.namespace,s.namespace_id,s.transfer_id,s.set_digest,
                            canonical_digest(s.signature),s.member_count,s.member_root,s.source_installation_id,
                            s.source_graph_incarnation,s.snapshot_digest,s.closure_digest,plan.target_installation_id,
                            h.target_permit.token,canonical_digest(h.target_permit),h.target_permit.generation,target.new_graph_incarnation,
                            w.imported.graph_commit_digest,canonical_digest(target),canonical_digest(receipt),canonical_digest(receipt.after_anchor)):
                        raise AuthorityUnavailable('actual Target activated member-set/import/receipt Original differs')
                    self.phase='member';return None
                if self.phase=='member':
                    self.member=read_snapshot_certificate_member_by_original_in_tx_v1(core,bounded,
                        plan.namespace,plan.transfer_id,*self.prior)
                    m=self.member;s=self.source_set
                    if (m is None or m.source_set_digest!=s.set_digest
                            or any(getattr(m,f.name)!=getattr(s,f.name)for f in fields(MigrationSnapshotCertificateSourceV1))
                            or m.certificate_key_columns!=('bot','persona','operation_id')
                            or m.certificate_key!=(*plan.namespace_id.as_tuple,m.operation_id)
                            or m.certificate_column!='certificate_json'
                            or m.certificate_table!=('graph_c09_rebase_certificates_v1'if self.prior[0]=='sylanne3.graph.c09_erasure_rebase.v1'
                                else'graph_c09_rebase_certificates_v2')
                            or (m.certificate_authority_id,m.certificate_installation_id,m.certificate_namespace)!=
                                (source.requirements.authority_id,plan.source_installation_id,plan.namespace)
                            or m.new_incarnation!=source.graph_incarnation):
                        raise AuthorityUnavailable('actual signed exported root certificate member differs')
                    self.phase='issue';return None
                m=self.member
                if m.certificate_schema=='sylanne3.graph.c09_erasure_rebase.v1':
                    self.issue=read_graph_rebase_issue_original_v1(bounded,plan.namespace,m.operation_id)
                    if self.issue is None:raise AuthorityUnavailable('actual imported V1 certificate Core issue absent')
                    verify_graph_rebase_issue_signature_v1(self.issue,require_actual_migration_member_core_key_v3(core))
                    identity=(self.issue.certificate_digest,self.issue.operation_id,self.issue.maintenance_generation,
                        m.old_incarnation,m.new_incarnation,self.issue.installation_id)
                    issuer_identity=(self.issue.authority_id,self.issue.installation_id,self.issue.namespace)
                else:
                    self.issue=_read_issue(bounded,plan.namespace,m.operation_id)
                    if self.issue is None:raise AuthorityUnavailable('actual imported V2 certificate Core issue absent')
                    _verify_signature(self.issue,require_actual_migration_member_core_key_v3(core));c=self.issue.certificate;sc=c.candidate.scope
                    identity=(c.certificate_digest,sc.operation_id,sc.maintenance_generation,
                        c.candidate.old_incarnation,c.candidate.new_incarnation,sc.installation_id)
                    issuer_identity=(sc.authority_id,sc.installation_id,sc.authority_namespace)
                if (identity!=(m.certificate_digest,m.operation_id,m.maintenance_generation,m.old_incarnation,
                            m.new_incarnation,plan.source_installation_id)
                        or issuer_identity!=
                            (m.certificate_authority_id,m.certificate_installation_id,m.certificate_namespace)
                        or self.issue.issue_digest!=m.core_issue_digest
                        or canonical_digest(self.issue.signature)!=m.core_issue_signature_commitment):
                    raise AuthorityUnavailable('actual imported root certificate and historical Core signature differ')
            self.column=_OwnerLocationCanonicalColumnV3(_OWNER_LOCATION_EDGE_ISSUER_V3,role='graph',
                kind='graph_certificate_v1'if self.prior[0]=='sylanne3.graph.c09_erasure_rebase.v1'else'graph_certificate_v2',
                namespace=w.proof.namespace,operation_id=self.member.operation_id)
            self.phase='certificate';return None
        if self.phase=='certificate':
            with w._role_snapshot('graph',meter)as db:
                if not self.column.advance(db,w.facts.work.view,meter):return None
                if self.member.certificate_issue_digest is not None:
                    mirror=_read_one(db,'SELECT issue_digest FROM graph_c09_rebase_certificates_v2 WHERE bot=? AND persona=? AND operation_id=?',
                        self.member.certificate_key,meter)
                    if mirror!=(self.member.certificate_issue_digest,):
                        raise AuthorityUnavailable('actual imported root Graph mirror issue differs')
            if (self.column.sha256,self.column.length)!=(self.member.raw_sha256,self.member.raw_byte_count):
                raise AuthorityUnavailable('actual imported root Graph canonical full EOF differs from signed snapshot member')
            if self.member.certificate_schema.endswith('.v1'):
                values=self.column.header_values
                if (values.get('certificate_digest'),values.get('operation_id'),values.get('old_incarnation'),
                        values.get('new_incarnation'),values.get('installation_id'))!=(self.member.certificate_digest,
                        self.member.operation_id,self.member.old_incarnation,self.member.new_incarnation,w.history.plan.source_installation_id):
                    raise AuthorityUnavailable('actual imported V1 root header differs from signed membership')
            else:
                value=c09_paged_value_from_wire_v2(json.loads(self.column.text()),GraphErasureRebaseCertificateV2)
                if value!=self.issue.certificate:
                    raise AuthorityUnavailable('actual imported V2 root full original differs from signed Core issue')
            self.phase='genesis_manifest';return None
        if self.phase=='genesis_manifest':
            with w.control._db()as db:
                row=_bounded(db,meter).execute('SELECT manifest_json,issuer_id,key_id,signature,generation FROM c09_storage_manifests_v1 WHERE manifest_digest=?',
                    (self.prepared['old_manifest_digest'],)).fetchone()
            if row is None:raise AuthorityUnavailable('actual Target imported signed genesis manifest absent')
            manifest=json.loads(row[0]);w.control._manifest(manifest)
            from .c09_storage_manifest_v2 import manifest_signature_domain
            signed=w.control.sign_original_v1(manifest_signature_domain(manifest),
                dict(schema=manifest_signature_domain(manifest),manifest=manifest,issuer_id=w.control.authority_id),'digest')
            if ((row[1],row[2],row[3],row[4])!=(w.control.authority_id,w.control.key_id,signed['signature'],0)
                    or manifest['manifest_digest']!=self.prepared['old_manifest_digest']
                    or manifest['installation_id']!=w.history.plan.target_installation_id
                    or manifest['prior_manifest_digest']is not None
                    or (manifest['certificate_digest'],manifest['graph_issue_digest'])not in((None,None),(self.member.certificate_digest,self.member.core_issue_digest))):
                raise AuthorityUnavailable('actual Target signed genesis manifest does not commit authenticated import root')
            self.result=_OwnerLocationTargetImportRootV3(_OWNER_LOCATION_EDGE_ISSUER_V3,w,self.source_set,
                self.activation_set,self.member,self.issue,self.column.sha256,self.column.length,manifest['manifest_digest'])
            self.complete=True;return self.result
        raise AuthorityUnavailable('actual Target imported certificate private reader phase differs')



from .c09_paged_recovery_facts_v2 import C09LegacyPreparedReaderV2
from sys import getsizeof as _owner_alloc_size_v3

class _OwnerLocationJSONAllocationScanV3:
    # Fixed IO only: sizing facts are not Original authentication or permissions.
    def __init__(self,owner,plans,key):
        self.owner,self.plans,self.key=owner,plans,key;self.index=0;self.position=0;self.total=None
        self.quote=self.escape=self.number=False
        self.objects=self.arrays=self.strings=self.numbers=self.keys=self.digits=self.bytes=self.literals=0
        self.complete=False;self.physical_total=None
    def _feed(self,raw):
        self.bytes+=len(raw)
        for byte in raw:
            if self.quote:
                if self.escape:self.escape=False
                elif byte==92:self.escape=True
                elif byte==34:self.quote=False
                continue
            if byte==34:self.quote=True;self.strings+=1;self.number=False
            elif byte==123:self.objects+=1;self.number=False
            elif byte==91:self.arrays+=1;self.number=False
            elif byte==58:self.keys+=1;self.number=False
            elif byte in b'-0123456789':
                if not self.number:self.numbers+=1;self.number=True
                if 48<=byte<=57:self.digits+=1
            elif byte in b'.eE+':pass
            elif byte in b'tfn':self.literals+=1;self.number=False
            else:self.number=False
    def advance(self,meter):
        if self.complete:return True
        role,table,column,where,args,start,end=self.plans[self.index]
        with (self.owner.control._db()if role=='control'else self.owner._role_snapshot(role,meter))as db:
            present=_read_one(db,'SELECT typeof('+column+') FROM '+table+' WHERE '+where+' LIMIT 1',args,meter)
            if present is None or present==('null',):
                self.index+=1;self.position=0;self.total=None;self.physical_total=None
                if self.index==len(self.plans):self.complete=True
                return self.complete
            with legacy_cell_read_transaction_v2(db):
                if self.total is None:
                    _,total,kind=read_legacy_sql_cell_fragment_v2(db,table=table,column=column,
                        where=where,parameters=args,start=0,length=0,meter=meter)
                    self.physical_total=total;self.total=total-start if end is None else end-start
                size=min(16384,self.total-self.position)
                raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table=table,column=column,
                    where=where,parameters=args,start=start+self.position,length=size,meter=meter)
            if kind not in('text','blob')or total!=self.physical_total:
                raise AuthorityUnavailable('actual Owner metadata sizing cell changed storage identity')
            self._feed(raw);self.position+=len(raw)
            if self.position==self.total:
                if self.quote or self.escape:
                    raise AuthorityUnavailable('actual Owner metadata sizing cell lacks JSON string EOF')
                self.number=False;self.index+=1;self.position=0;self.total=None
                if self.index==len(self.plans):self.complete=True
        return self.complete
    def decode_growth_bound_v3(self):
        if not self.complete:raise AuthorityUnavailable('actual Owner metadata complete allocation sizing required')
        pointer=8
        # CPython 3.12: dictionary capacity is below 4*pairs+8; reserve general
        # 24-byte entries and 8-byte indices even for its smaller Unicode layout.
        dictionaries=self.objects*(_owner_alloc_size_v3({})+8*(8+24))+self.keys*(4*8+3*24)
        # CPython append uses 4/8 slots for small lists; each array reserves
        # eight fixed slots plus two per contained JSON value.
        nodes=self.objects+self.arrays+self.strings+self.numbers+self.literals
        arrays=self.arrays*(_owner_alloc_size_v3([])+8*pointer)+nodes*2*pointer
        strings=self.strings*_owner_alloc_size_v3(chr(0x10000))+4*self.bytes
        integers=self.numbers*(_owner_alloc_size_v3(0)+4)+4*((self.digits+8)//9)
        # Parsed map, immutable typed construction and canonical commitment map
        # coexist at the actual decode/signature boundaries; strings may be shared
        # but all three copies are reserved. Typed node size follows the exact
        # registered DTO field ceiling, including a dictionary-backed DTO.
        fields=max(len(_owner_heap_fields_v3(kind))for kind in _OWNER_LOCATION_PAYLOAD_DTOS_V3)
        typed=self.objects*(2*_owner_alloc_size_v3({})+fields*(4*pointer+24))+self.arrays*_owner_alloc_size_v3(())+nodes*pointer
        return 3*(dictionaries+arrays+strings+integers)+typed+5*(4*self.bytes+_owner_alloc_size_v3(''))
    def heap_v3(self,seen):
        return _owner_alloc_size_v3(self)+_owner_alloc_size_v3(self.__dict__)+_owner_location_payload_heap_v3((self.plans,self.key),seen)


def _owner_location_fragment_growth_bound_v3():
    from ..runtime.c09_canonical_json_stream_v2 import MAX_DEPTH_V2,MAX_KEY_BYTES_V2,MAX_FRAGMENT_BYTES_V2
    pointer=8;depth=MAX_DEPTH_V2;key=MAX_KEY_BYTES_V2
    # Two full key strings per live container, its path tuple and registered
    # container fields; incremental key decoding retains at most key one-char
    # pieces, and one actual fragment plus old/new bytearray capacities coexist.
    frames=depth*(128+_owner_alloc_size_v3(())+depth*pointer+2*(_owner_alloc_size_v3(chr(0x10000))+4*key))
    decoder=key*(_owner_alloc_size_v3(chr(0x10000))+2*pointer)+4*key+2048
    fragments=2*((MAX_FRAGMENT_BYTES_V2*9+7)//8+8)+2*65536+4096
    return frames+decoder+fragments


def _owner_location_growth_key_v3(owner):
    if type(owner)is OwnerLocationReadWorkV3:
        r=owner.legacy_reader
        return(owner.phase,None if r is None else(r.phase,r.index))
    edge=owner.edge_reader;root=owner.import_root_reader if owner.is_target else None
    applied=owner.applied_reader
    return(owner.phase,None if edge is None else(edge.prepared['operation_id'],edge.phase,edge.mutation_index),
        None if root is None else(root.phase,root.prior),None if applied is None else applied.phase,
        owner.transfer_pending if owner.is_target else None,
        None if owner.reader is None else(getattr(owner.reader,'phase',None),getattr(owner.reader,'index',None)))


def _owner_location_allocation_plans_v3(owner,meter):
    # Every SQL locator is a fixed consumer's actual metadata Original; none is
    # supplied by a caller and no plan can name a Source content column.
    plans=[]
    def add(role,table,columns,where,args,start=0,end=None):
        for column in columns:plans.append((role,table,column,where,tuple(args),start,end))

    def compact(op,manifest_digest,version):
        add('control','c09_storage_operations_v'+str(version),('prepared_original_json',),
            'installation_id=? AND operation_id=?',(owner.control.installation_id,op))
        add('control','c09_storage_manifests_v1',('manifest_json',),'manifest_digest=?',(manifest_digest,))
        kinds=('capture_scope_v2','capture_facts_complete_v2','graph_issued_v2','graph_mirror_v2',
            'capture_role_complete_v2_core','capture_role_complete_v2_deletion',
            'capture_role_complete_v2_execution','capture_role_complete_v2_graph','frozen_inventory_complete_v2')
        for kind in kinds:
            add('control','c09_storage_build_originals_v1',('original_json',),
                'installation_id=? AND operation_id=? AND original_kind=?',(owner.control.installation_id,op,kind))
    if type(owner)is OwnerLocationReadWorkV3:
        if owner.phase=='selection':
            with owner.control._db()as db:current=owner.control._current(db)
            add('control','c09_storage_manifests_v1',('manifest_json',),'manifest_digest=?',(current['current_manifest_digest'],))
            with owner.control._db()as db:
                present=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_storage_operations_v2'",(),meter)
            if present is not None:
                with owner.control._db()as db:
                    row=_read_one(db,'SELECT operation_id FROM c09_storage_operations_v2 WHERE new_manifest_digest=?',(current['current_manifest_digest'],),meter)
                if row is not None:compact(row[0],current['current_manifest_digest'],2)
        elif owner.phase=='legacy_selected_header'and owner.legacy_reader is not None and owner.legacy_reader.phase=='header':
            r=owner.legacy_reader
            from .c09_paged_recovery_facts_v2 import _LEGACY_PREPARED_SUMMARY_FIELDS_V2
            names=tuple(sorted(_LEGACY_PREPARED_SUMMARY_FIELDS_V2))
            if r.index<len(names):
                start,end=r.cell.spans[(names[r.index],)]
                add('control',r.cell.table,(r.cell.column,),r.cell.where,r.cell.parameters,start,end)
        return tuple(plans)
    from .c09_paged_recovery_facts_v2 import _CompactPreparedReaderV2
    from .c09_prepared_storage_v3 import _CompactPreparedReaderV3
    namespace=owner.owner_service.namespace
    if type(owner.reader)in(_CompactPreparedReaderV2,_CompactPreparedReaderV3):
        compact(owner.reader.row[0],owner.reader.row[3],2 if type(owner.reader)is _CompactPreparedReaderV2 else 3)
    edge=owner.edge_reader;applied=owner.applied_reader
    if owner.reader is not None and type(owner.reader)is C09LegacyPreparedReaderV2 and owner.reader.phase=='header':
        r=owner.reader
        from .c09_paged_recovery_facts_v2 import _LEGACY_PREPARED_SUMMARY_FIELDS_V2
        names=tuple(sorted(_LEGACY_PREPARED_SUMMARY_FIELDS_V2))
        if r.index<len(names):
            start,end=r.cell.spans[(names[r.index],)]
            add('control',r.cell.table,(r.cell.column,),r.cell.where,r.cell.parameters,start,end)
    if edge is not None:
        p=edge.prepared;op=p['operation_id'];phase=edge.phase
        if phase=='manifest':add('control','c09_storage_manifests_v1',('manifest_json',),'manifest_digest=?',(p['new_manifest_digest'],))
        elif phase=='issue':
            if type(p)is C09VerifiedLegacyPreparedSummaryV2:
                with owner._role_snapshot('core',meter)as db:
                    row=_read_one(db,'SELECT operation_id FROM authority_c09_graph_rebase_issues_v1 WHERE namespace=?',(namespace,),meter)
                if row is not None and row[0]==op:add('core','authority_c09_graph_rebase_issues_v1',('issue_json',),'namespace=?',(namespace,))
                else:add('core','authority_c09_originals_archive_v1',('original_json',),"namespace=? AND operation_id=? AND original_kind='graph_issue'",(namespace,op))
            else:add('core','authority_c09_graph_rebase_issues_v2',('issue_json',),'namespace=? AND operation_id=?',(namespace,op))
        elif phase in('paged_issue_original','paged_mirror_original'):
            kind='graph_issued_v2'if phase=='paged_issue_original'else'graph_mirror_v2'
            add('control','c09_storage_build_originals_v1',('original_json',),'installation_id=? AND operation_id=? AND original_kind=?',(owner.control.installation_id,op,kind))
        elif phase=='release':add('control','c09_storage_events_v1',('event_json',),"operation_id=? AND stage='RELEASED'",(op,))
        elif phase=='accepted_locator':add('core',_CLEANUP_TABLES_V3[1],('run_json',),'operation_id=?',(op,))
        elif phase in('accepted_mutation','mutations'):
            mutation=edge.accepted_mutation_id if phase=='accepted_mutation'else edge.mutation_ids[edge.mutation_index]
            add('core','authority_v2_mutations',('conflict_keys_json','pending','receipt','updated_permit','deletion_evidence'),
                'mutation_id=?',(mutation,))
    if applied is not None:
        op=owner.view.basis.prepared['operation_id'];phase=applied.phase
        if phase=='release':add('control','c09_storage_events_v1',('event_json',),"operation_id=? AND stage='RELEASED'",(op,))
        elif phase=='issue':add('core','authority_c09_graph_rebase_issues_v2',('issue_json',),'namespace=? AND operation_id=?',(namespace,op))
        elif phase=='closed':add('core','authority_v2_mutations',('conflict_keys_json','pending','receipt','updated_permit','deletion_evidence'),
            'mutation_id=?',('c09-closed-mutation-'+canonical_digest((namespace,op))[:48],))
        elif phase=='ack':add('graph','graph_c09_cumulative_applications_v1',('original_json',),'bot=? AND persona=? AND operation_id=?',(*owner.proof.namespace.as_tuple,op))
    if owner.is_target:
        if owner.phase=='target_transfer_original':
            add('core','authority_migration_v2_plans',('plan_json','current_anchor_json','source_permit_json','target_permit_json','source_snapshot_json','target_recovery_json'),'transfer_id=?',(owner.transfer_pending,))
            for stage in('begun','revoked','target_prepared','activated'):
                add('core','authority_migration_v2_receipts',('receipt_json',),'transfer_id=? AND phase=?',(owner.transfer_pending,stage))
        root=owner.import_root_reader
        if root is not None:
            h=owner.history;args=(namespace,h.plan.transfer_id)
            if root.phase in('source_set','activation','member'):
                table='authority_migration_snapshot_certificate_members_v1'
                with owner._role_snapshot('core',meter)as db:
                    present=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,),meter)
                if present is None:return tuple(plans)
                kind='source_set'if root.phase=='source_set'else'activation_set'if root.phase=='activation'else'certificate'
                where='namespace=? AND transfer_id=? AND member_kind=?';values=(*args,kind)
                if kind!='certificate':where+=' AND member_key=?';values+=(kind,)
                if kind=='certificate':where+=' AND certificate_schema=? AND certificate_digest=?';values+=root.prior
                add('core',table,('original_json',),where,values)
                if kind=='certificate':add('core',table,('original_json',),"namespace=? AND transfer_id=? AND member_kind='source_set'",args)
            elif root.phase=='issue':
                m=root.member
                if m.certificate_schema.endswith('.v1'):
                    with owner._role_snapshot('core',meter)as db:
                        row=_read_one(db,'SELECT operation_id FROM authority_c09_graph_rebase_issues_v1 WHERE namespace=?',(namespace,),meter)
                    if row is not None and row[0]==m.operation_id:add('core','authority_c09_graph_rebase_issues_v1',('issue_json',),'namespace=?',(namespace,))
                    else:add('core','authority_c09_originals_archive_v1',('original_json',),"namespace=? AND operation_id=? AND original_kind='graph_issue'",(namespace,m.operation_id))
                else:add('core','authority_c09_graph_rebase_issues_v2',('issue_json',),'namespace=? AND operation_id=?',(namespace,m.operation_id))
            elif root.phase=='genesis_manifest':add('control','c09_storage_manifests_v1',('manifest_json',),'manifest_digest=?',(root.prepared['old_manifest_digest'],))
    return tuple(plans)


def _owner_location_growth_step_v3(owner,meter):
    key=_owner_location_growth_key_v3(owner);scan=owner.allocation_scan
    fragment=_owner_location_fragment_growth_bound_v3()
    if scan is None or scan.key!=key:
        reserve_owner_location_retained_growth_v3(owner.proof,fragment)
        try:
            owner.allocation_scan=None;scan=None
            plans=_owner_location_allocation_plans_v3(owner,meter)
            if plans:
                scan=_OwnerLocationJSONAllocationScanV3(owner,plans,key)
                owner.allocation_scan=scan;scan.advance(meter)
                return None
        finally:finish_owner_location_retained_growth_v3(owner.proof)
    elif not scan.complete:
        reserve_owner_location_retained_growth_v3(owner.proof,fragment)
        try:scan.advance(meter);return None
        finally:finish_owner_location_retained_growth_v3(owner.proof)
    bound=fragment+(0 if scan is None else scan.decode_growth_bound_v3())
    columns=[]
    if type(owner)is OwnerLocationReadWorkV3:
        columns.append(owner.column)
    else:
        if owner.edge_reader is not None:columns.append(owner.edge_reader.column)
        if owner.is_target:
            if owner.import_reader is not None:columns.append(owner.import_reader.column)
            if owner.import_root_reader is not None:columns.append(owner.import_root_reader.column)
        if owner.phase in('source_head','target_head','final'):
            # The current CallerProof has already authenticated this immutable
            # head; its parsed, typed and commitment copies coexist on recheck.
            bound+=6*_owner_location_payload_heap_v3(owner.head,set())
    for column in columns:
        if column is not None and column.length is not None and column.position==column.length and column.retain:
            column.allocation.complete=True;bound+=column.allocation.decode_growth_bound_v3()
    reserve_owner_location_retained_growth_v3(owner.proof,bound)
    try:
        result=owner._advance_graph(meter)if type(owner)is OwnerLocationReadWorkV3 else owner._advance(meter)
        if key!=_owner_location_growth_key_v3(owner)or result is not None:owner.allocation_scan=None
        return result
    finally:finish_owner_location_retained_growth_v3(owner.proof)

from contextvars import ContextVar
from .v2_owner_session import OwnerSessionLoginRequestV1
from .v2_model_egress_contract import ModelEgressIntentV1
_OWNER_LOCATION_PAYLOAD_DTOS_V3 = _OWNER_LOCATION_PAYLOAD_DTOS_V3 | frozenset((OwnerSessionLoginRequestV1,ModelEgressIntentV1))

_OWNER_MODEL_LOCATION_ENTRIES_V3 = WeakKeyDictionary()
_OWNER_MODEL_LOCATION_BOUND_V3 = ContextVar('sylanne_owner_model_location_v3', default=None)

class _OwnerModelLocationRetainedV3:
    def __init__(self, proof, control, grant, actor, login):
        self.proof, self.control, self.grant, self.actor, self.login = proof, control, grant, actor, login
    def _c09_retained_heap_bytes_v3(self):
        return _owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)+_owner_location_payload_heap_v3((self.grant,self.actor,self.login),set())

@dataclass(frozen=True, slots=True)
class _OwnerModelLocationReadV3:
    anchor: object
    head: object
    actor: object
    login: object
    metadata: object
    grant: object
    admission: object


def prepare_owner_location_for_model_graph_work_v3(work, *, installed_reader, owner_service):
    from .current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3)
    from .current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
    from .internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
    from .artifact_model_graph_v3 import InstalledArtifactDraftModelGraphReaderV3
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from ..graph_types import validate_owner_grant_v1
    if (type(work) is not AuthorityGraphReadWorkV3
            or type(owner_service) is not InstalledD12OwnerStorageAdmissionServiceV1
            or type(installed_reader) not in (InstalledLifeNumericModelGraphReaderV1,
                InstalledInternalLifeModelGraphReaderV2,InstalledArtifactDraftModelGraphReaderV3)
            or installed_reader.owner_storage is not owner_service
            or work.db.in_transaction):
        raise AuthorityUnavailable('model Owner location requires its actual installed reader before Graph SQL')
    require_actual_authority_graph_attachment_owner_v3(work)
    controller = work.controller.require_installed_v3()
    verifier = controller.verifier
    actual = (verifier._life_numeric_reader_v1 if type(installed_reader) is InstalledLifeNumericModelGraphReaderV1
        else verifier._artifact_model_reader_v3 if type(installed_reader)is InstalledArtifactDraftModelGraphReaderV3
        else verifier._internal_life_reader_v2)
    if (controller.kind != 'model' or actual is not installed_reader
            or controller.control is not owner_service.control
            or controller.fences is not owner_service.fences
            or controller.location._graph_db_path != owner_service.graph_path
            or work.namespace != owner_service.namespace_id):
        raise AuthorityUnavailable('model Owner location crossed its actual installed selected Graph')
    previous = _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work)
    if previous is not None:
        if previous[0] is not installed_reader or previous[1].owner_service is not owner_service:
            raise AuthorityUnavailable('model Owner location reader changed during its original Work')
        _require_owner_permission_outside_graph_v3(previous[1])
        return previous[4]
    fences = owner_service.fences
    fences.core._require(work.credential, 'owner_guard_read', owner_service.namespace, owner_service.holder)
    work._check_permission_v3()
    with fences._frozen() as (db, deletion, execution, _):
        anchor = fences._current_locked(db, deletion, execution)
        fences.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=anchor)
        if anchor != work.permit.pinned_anchor:
            raise AuthorityUnavailable('model Owner location original permission anchor changed')
        head = owner_service._head_in_tx(db)
        actor, login = owner_service._background_identity_in_tx(db, head)
    _require_owner_operation_v3(work.operation, db=work.db, namespace=work.namespace,
        control=owner_service.control)
    bundle=installed_reader.bundle
    if bundle is not verifier._artifact_draft_bundle:
        raise AuthorityUnavailable('Life model Owner reader crossed the installed bundle identity')
    caller_kind, model_source_phase = 'authority_model_header', None
    if type(installed_reader) is InstalledLifeNumericModelGraphReaderV1:
        from .life_numeric_source_read_v3 import require_authority_numeric_model_phase_v3
        model_source_phase = require_authority_numeric_model_phase_v3(work, installed_reader)
        caller_kind = 'authority_numeric_model_header'
    elif type(installed_reader) is InstalledInternalLifeModelGraphReaderV2:
        from .internal_life_model_source_read_v3 import require_internal_life_model_phase_v3
        caller_kind = 'authority_internal_life_model_header'
        model_source_phase = require_internal_life_model_phase_v3(work, installed_reader)
    elif type(installed_reader)is InstalledArtifactDraftModelGraphReaderV3:
        from .artifact_model_source_read_v3 import require_artifact_model_phase_v3
        caller_kind='authority_artifact_model_header'
        model_source_phase=require_artifact_model_phase_v3(work,installed_reader)
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        caller_kind, None, work.service, owner_service, controller, None,
        bundle, work.scope, None, head.issue_operation.principal,
        D12CurrentOwnerAuthorityV1(head.guard, None), head, work.operation, owner_service.control,
        work.selection_digest, work.namespace, owner_service.installation_id, owner_service.holder,
        anchor, anchor, work.credential, work.subject, work.permit, work, work.deadline_utc, get_ident(),
        model_source_phase=model_source_phase)
    graph_work = lineage = None
    try:
        graph_work = prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = graph_work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts = graph_work.result.require_for_v3(proof)
        lineage = prepare_source_owner_location_lineage_v3(proof, facts)
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = lineage.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        admission = resolve_source_owner_storage_admission_from_completed_location_v3(proof, facts)
        raw = facts.atom[1]
        scanner = _OwnerLocationJSONAllocationScanV3(lineage, (), ('model-owner-grant',))
        reserve_owner_location_retained_growth_v3(proof, 4 * len(raw) + _owner_alloc_size_v3(b''))
        try:
            encoded = raw.encode('utf-8')
            scanner._feed(encoded)
            scanner.complete = True
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof, scanner.decode_growth_bound_v3())
        try:
            grant = json.loads(raw)
            validate_owner_grant_v1(grant)
            decoded = _OwnerModelLocationRetainedV3(proof, owner_service.control, grant, actor, login)
            register_owner_location_retained_state_v3(proof, decoded)
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _OwnerModelLocationReadV3(anchor, head, actor, login, facts.metadata, grant, admission)
        _OWNER_MODEL_LOCATION_ENTRIES_V3[work] = (installed_reader, proof, facts, lineage, entry, decoded)
        return entry
    except BaseException as error:
        if lineage is not None: lineage.cancel_v3(error)
        elif graph_work is not None: graph_work.cancel_v3(error)
        proof.release_v3()
        raise


@contextmanager
def bind_owner_location_for_model_graph_work_v3(work):
    from .original_foreground_source_read_v3 import original_foreground_work_v3,bind_original_foreground_owner_quantum_v3
    if original_foreground_work_v3(work)is not None:
        with bind_original_foreground_owner_quantum_v3(work):yield
        return
    if work.controller.kind == 'named_joint':
        from .named_joint_binding_source_read_v3 import require_named_joint_authority_work_v3
        actual = require_named_joint_authority_work_v3(work)
        state = _NAMED_JOINT_OWNER_LOCATION_ENTRIES_V3.get(work)
        if state is None:
            if not actual.metadata_only or actual.current_self is not None:
                raise AuthorityUnavailable('Named Joint Source phase has no current independent Owner EOF')
            yield
            return
        proof, facts = state[1:3]
        require_owner_location_caller_proof_v3(proof, phase='before'); facts.require_for_v3(proof)
        yield
        require_owner_location_caller_proof_v3(proof, phase='after'); facts.require_for_v3(proof)
        return
    if work.controller.kind=='habit':
        state=_HABIT_OWNER_LOCATION_ENTRIES_V3.get(work)
        if state is None:raise AuthorityUnavailable('Habit current Owner EOF is absent')
        proof,facts=state[1:3]
        require_owner_location_caller_proof_v3(proof,phase='before');facts.require_for_v3(proof)
        yield
        require_owner_location_caller_proof_v3(proof,phase='after');facts.require_for_v3(proof)
        return
    from .life_numeric_source_read_v3 import require_numeric_result_source_bridge_v3
    bridge=require_numeric_result_source_bridge_v3(work)
    if bridge is not None:
        token=_OWNER_MODEL_LOCATION_BOUND_V3.set((work,bridge['owner_state']))
        try:
            yield
            require_numeric_result_source_bridge_v3(work)
        finally:_OWNER_MODEL_LOCATION_BOUND_V3.reset(token)
        return
    state = _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work)
    if state is None:
        yield
        return
    proof, facts = state[1:3]
    require_owner_location_caller_proof_v3(proof, phase='before')
    facts.require_for_v3(proof)
    token = _OWNER_MODEL_LOCATION_BOUND_V3.set((work, state))
    try:
        yield
        require_owner_location_caller_proof_v3(proof, phase='after')
        facts.require_for_v3(proof)
    finally:
        _OWNER_MODEL_LOCATION_BOUND_V3.reset(token)


def require_owner_location_for_model_graph_read_v3(db, *, installed_reader, intent):
    bound = _OWNER_MODEL_LOCATION_BOUND_V3.get()
    if bound is None:
        raise AuthorityUnavailable('Life model Owner read lacks its original actual Work binding')
    work,state=bound[:2]
    bound_db=work.db if len(bound)==2 else bound[2]
    if (_OWNER_MODEL_LOCATION_ENTRIES_V3.get(work) is not state or state[0] is not installed_reader
            or bound_db is not db or work.request is not intent or not db.in_transaction):
        raise AuthorityUnavailable('Life model Owner read crossed its actual Work, reader or original intent')
    work._actual()
    from .life_numeric_source_read_v3 import require_numeric_result_source_bridge_v3
    bridge=require_numeric_result_source_bridge_v3(work)
    if bridge is not None:
        if state is not bridge['owner_state']:raise AuthorityUnavailable('Numeric result Owner bridge changed its actual completed entry')
        return state[4]
    proof, facts = state[1:3]
    require_owner_location_caller_proof_v3(proof, phase='after')
    facts.require_for_v3(proof)
    return state[4]


def release_owner_location_for_model_graph_work_v3(work):
    from .original_foreground_source_read_v3 import original_foreground_work_v3
    if original_foreground_work_v3(work)is not None:
        from .original_foreground_owner_location_v3 import release_original_foreground_owner_v3
        release_original_foreground_owner_v3(work)
        return
    if work.controller.kind == 'named_joint':
        state = _NAMED_JOINT_OWNER_LOCATION_ENTRIES_V3.pop(work, None)
        if state is not None:
            state[3].close_v3(); state[1].release_v3()
        return
    if work.controller.kind=='habit':
        state=_HABIT_OWNER_LOCATION_ENTRIES_V3.pop(work,None)
        if state is not None:
            state[3].close_v3();state[1].release_v3()
        return
    from .life_numeric_source_read_v3 import require_numeric_result_source_bridge_v3
    if require_numeric_result_source_bridge_v3(work)is not None:
        _OWNER_MODEL_LOCATION_ENTRIES_V3.pop(work,None)
        return
    release_owner_location_for_contact_work_v3(work)
    state = _OWNER_MODEL_LOCATION_ENTRIES_V3.pop(work, None)
    if state is not None:
        try:
            state[3].close_v3()
        finally:
            state[1].release_v3()


def prepare_owner_location_for_model_quantum_v3(work):
    from .original_foreground_source_read_v3 import original_foreground_work_v3,prepare_original_foreground_owner_quantum_v3
    if original_foreground_work_v3(work)is not None:
        return prepare_original_foreground_owner_quantum_v3(work)
    if work.controller.kind == 'named_joint':
        from .named_joint_binding_source_read_v3 import require_named_joint_authority_work_v3
        state = require_named_joint_authority_work_v3(work)
        if state.current_self is None:
            if not state.metadata_only:
                raise AuthorityUnavailable('Named Joint body cannot precede actual Self/Owner qualification')
            return
        return prepare_owner_location_for_named_joint_graph_work_v3(work)
    if work.controller.kind=='habit':
        return prepare_owner_location_for_habit_graph_work_v3(work)
    if work.controller.kind in ('foreground_mesh','owner_task_mesh'):
        from .foreground_mesh_source_read_v3 import prepare_foreground_mesh_owner_quantum_v3
        prepare_foreground_mesh_owner_quantum_v3(work)
        return
    from .artifact_model_result_source_v3 import require_artifact_result_source_bridge_v3
    artifact_result=require_artifact_result_source_bridge_v3(work,observe=True)
    if artifact_result is not None:
        from .artifact_model_graph_v3 import observe_artifact_model_core_state_v3
        from .artifact_model_finished_producer_v3 import observe_artifact_finished_producers_v3
        observe_artifact_model_core_state_v3(work,artifact_result[0]._graph_reader)
        observe_artifact_finished_producers_v3(work)
        return
    from .life_numeric_source_read_v3 import require_numeric_result_source_bridge_v3
    if require_numeric_result_source_bridge_v3(work,observe=True)is not None:return
    from .contact_model_work_v3 import ModelContactReadSelectorV3
    from .contact_background_graph_v3 import ContactBackgroundSelectorV3
    if type(getattr(work,'contact_selector',None))in(ModelContactReadSelectorV3,ContactBackgroundSelectorV3):
        if type(work.contact_selector)is ModelContactReadSelectorV3:
            from .contact_model_work_v3 import require_model_contact_work_v3
            owner=require_model_contact_work_v3(work)[0][4].owner_service
        else:
            from .contact_background_graph_v3 import require_contact_background_work_v3
            owner=require_contact_background_work_v3(work)[0]._policy.owner_service
        return observe_owner_location_for_contact_v3(owner,work)
    if work.controller.kind != 'model':
        return
    kind = work.owner_model_work_kind
    verifier = work.controller.verifier
    if kind == 'd06.encode_internal_life_numeric':
        reader = verifier._life_numeric_reader_v1
    elif kind == 'd06.encode_internal_life_content':
        reader = verifier._internal_life_reader_v2
    elif kind == 'artifact_draft_v1':
        reader=verifier._artifact_model_reader_v3
    else:
        return
    if reader is None:
        raise AuthorityUnavailable('actual Life model Owner reader is not installed')
    entry = prepare_owner_location_for_model_graph_work_v3(work, installed_reader=reader,
        owner_service=reader.owner_storage)
    state = _OWNER_MODEL_LOCATION_ENTRIES_V3[work]
    if kind=='artifact_draft_v1':
        from .artifact_model_graph_v3 import observe_artifact_model_core_state_v3
        observe_artifact_model_core_state_v3(work,reader)
        from .artifact_model_finished_producer_v3 import observe_artifact_finished_producers_v3
        observe_artifact_finished_producers_v3(work)
    if kind == 'd06.encode_internal_life_numeric':
        from .life_numeric_source_read_v3 import numeric_authority_source_reader_v3, prepare_authority_numeric_source_read_v3
        if numeric_authority_source_reader_v3(work) is None:
            prepare_authority_numeric_source_read_v3(work, installed_reader=reader, owner_entry=entry)
    with reader.owner_storage.fences._frozen() as (db, deletion, execution, _):
        owner = reader.owner_storage
        if (owner.fences._current_locked(db, deletion, execution) != entry.anchor
                or owner._head_in_tx(db) != entry.head
                or owner._background_identity_in_tx(db, entry.head) != (entry.actor, entry.login)):
            raise AuthorityUnavailable('model Owner paired identity changed outside its Graph read')
    return entry

from .v2_contract import FencePermitV2
from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,
    begin_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3)

_OWNER_LOCATION_AUTHORITY_CALLS_V3=WeakSet()
_OWNER_LOCATION_AUTHORITY_KINDS_V3=frozenset(('authority_numeric_location','authority_root_location',
    'authority_series_location','authority_life_location','authority_offline_location',
    'authority_source_fence_location','authority_target_public_location','authority_target_background_location',
    'authority_life_numeric_result','authority_life_content_result','authority_artifact_model_result',
    'authority_natural_self_location','authority_c04_self_location','authority_conditioned_child_location'))


def _owner_location_actual_service_v3(service,kind):
    from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
    from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    from .d04_series_service_v1 import AuthorityD04SeriesServiceV1
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from .d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
    from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
    from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1,ArtifactDraftModelResultReadRequestV1,ArtifactDraftModelResultReadRequestV2
    from .internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
    from .v2_self_identity_service import AuthorityV2SelfIdentityService
    from .current_conditioned_child_v1 import InstalledCurrentConditionedChildV1
    types={'authority_conditioned_child_location':InstalledCurrentConditionedChildV1,'authority_numeric_location':AuthorityD04NumericServiceV3,
        'authority_root_location':AuthorityD04RootExecutionServiceV3,
        'authority_series_location':AuthorityD04SeriesServiceV1,
        'authority_life_location':AuthorityD11LifeServiceV1,
        'authority_offline_location':AuthorityD11OfflineTickServiceV1,
        'authority_source_fence_location':InstalledD12OwnerStorageAdmissionServiceV1,
        'authority_target_public_location':InstalledD12TargetOwnerAdmissionServiceV1,
        'authority_target_background_location':InstalledD12TargetOwnerAdmissionServiceV1,
        'authority_life_numeric_result':InstalledLifeNumericModelResultServiceV1,
        'authority_life_content_result':InstalledInternalLifeModelResultServiceV2,
        'authority_artifact_model_result':AuthorityArtifactDraftModelResultServiceV1,
        'authority_natural_self_location':AuthorityV2SelfIdentityService,
        'authority_c04_self_location':AuthorityV2SelfIdentityService}
    if type(service) is not types[kind]:
        raise AuthorityUnavailable('Owner location requires the exact installed authority service')
    return service


class _AuthorityOwnerLocationCallV3:
    def __init__(self,issuer,*,service,kind,owner_service,credential,subject,permit,
            permission_anchor,comparison_anchor,head,history,deadline_utc,
            actor=None,session_token=None,session_request=None):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Owner location call requires its actual registered producer')
        _owner_location_actual_service_v3(service,kind)
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
        if (type(owner_service) not in (InstalledD12OwnerStorageAdmissionServiceV1,
                InstalledD12TargetOwnerAdmissionServiceV1) or type(permit) is not FencePermitV2
                or subject!=permit.subject or permit.holder!=owner_service.holder
                or permit.namespace!=owner_service.namespace):
            raise AuthorityUnavailable('Owner metadata call crossed its real permit or installed Owner service')
        self.service,self.kind,self.owner_service=service,kind,owner_service
        self.controller=self;self.credential,self.subject,self.permit=credential,subject,permit
        self.namespace,self.request=owner_service.namespace_id,permit
        self.permission_anchor,self.comparison_anchor,self.head,self.history=permission_anchor,comparison_anchor,head,history
        self.actor,self.session_token,self.session_request=actor,session_token,session_request
        self.deadline_utc=deadline_utc;self.thread=get_ident();self.closed=False
        self.db=self.handle=self.operation=None
        control=(owner_service.control if type(owner_service) is InstalledD12OwnerStorageAdmissionServiceV1
            else owner_service.storage_continuation_reader.control)
        if (control is not owner_service.core._c09_storage_reader_v1
                or control.installation_id!=owner_service.installation_id):
            raise AuthorityUnavailable('Owner call crossed its actual selected Core installation')
        self.control=control;self.scope=None;self.proof=None;self.decoded_grant=None;self.location=None;self.consumer_records=None
        self._check_permission_v3()
        from .daemon import _bootstrap_control_quantum_v3
        path=(owner_service.graph_path if type(owner_service) is InstalledD12OwnerStorageAdmissionServiceV1
            else owner_service.target_graph)
        try:
            with _bootstrap_control_quantum_v3(control):
                self.db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,isolation_level=None)
                self.db.execute('PRAGMA query_only=ON')
                self.handle=bind_runtime_database_from_control_v3(self.db,control=control,role='graph')
            if self.handle is None:
                raise AuthorityUnavailable('physical_owner_retention_operation_unavailable')
            self.operation=begin_runtime_storage_operation_v3(self.db,permit.operation_id,deadline_utc)
            if (self.operation is None or self.operation.handle is not self.handle
                    or self.operation.pool is not self.handle.pool
                    or self.operation.selection_digest!=self.handle.selection_digest):
                raise AuthorityUnavailable('Owner call crossed its original shared retention pool or selected storage')
            self.selection_digest=self.operation.selection_digest
            _OWNER_LOCATION_AUTHORITY_CALLS_V3.add(self)
        except BaseException:
            self.release_v3()
            raise

    def _require_components_v3(self):
        owner=self.owner_service;service=self.service
        if self.kind=='authority_series_location':
            if service.bridge is not service.numeric.bridge or service.namespace!=service.numeric.namespace:
                raise AuthorityUnavailable('series Owner call changed its numeric installation')
            service=service.numeric
        if self.kind in ('authority_numeric_location','authority_root_location','authority_series_location'):
            selected=service.target_owner_service or service.storage_owner_service
            if (selected is not owner or service.bridge.core is not owner.core or service.owner_tickets is not owner.tickets
                    or service.namespace!=owner.namespace_id or service.installation_id!=owner.installation_id
                    or service.graph_path!=(owner.graph_path if self.history is None else owner.target_graph)
                    or service.bridge.fences is not owner.fences.fences
                    or service.bridge.deletion is not owner.fences.deletion
                    or service.bridge.journal is not owner.fences.execution):
                raise AuthorityUnavailable('numeric Owner call changed its actual Core/fences/Graph/Owner composition')
        elif self.kind in ('authority_life_location','authority_offline_location'):
            if (service.owner_service is not owner or service.bridge.core is not owner.core
                    or service.fences is not owner.fences or service.owner_tickets is not owner.tickets
                    or service.namespace!=owner.namespace_id or service.installation_id!=owner.installation_id
                    or service.graph_path!=(owner.graph_path if self.history is None else owner.target_graph)):
                raise AuthorityUnavailable('Life Owner call changed its actual Core/fences/Graph/Owner composition')
        elif self.kind in ('authority_natural_self_location','authority_c04_self_location','authority_conditioned_child_location'):
            if (service._core is not owner.core or service._fences is not owner.fences
                    or service._owner_storage is not owner or service._graph._path!=owner.graph_path
                    or service._source_location._control is not self.control):
                raise AuthorityUnavailable('Self Owner call changed its actual Source composition')
        elif self.kind in ('authority_life_numeric_result','authority_life_content_result','authority_artifact_model_result'):
            if (service._fences is not owner.fences or service._store._db is not owner.core._db
                    or service._graph_reader.owner_storage is not owner or service._path!=owner.graph_path
                    or service._location._control is not self.control):
                raise AuthorityUnavailable('Life result Owner call changed its actual installed Source composition')
        elif service is not owner:
            raise AuthorityUnavailable('Owner fence metadata call changed its actual installed service')
        if owner.core._c09_storage_reader_v1 is not self.control:
            raise AuthorityUnavailable('Owner metadata call changed its actual selected Control')

    def require_installed_v3(self):
        _owner_location_actual_service_v3(self.service,self.kind)
        self._require_components_v3()
        if self not in _OWNER_LOCATION_AUTHORITY_CALLS_V3 or self.closed or get_ident()!=self.thread:
            raise AuthorityUnavailable('Owner metadata installed call ended')
        return self

    def _actual(self):
        self.require_installed_v3()
        if (self.operation.closed or self.operation.pool is not self.handle.pool
                or self.operation.selection_digest!=self.selection_digest
                or self.handle.context._reader is not self.control):
            raise AuthorityUnavailable('Owner metadata lost its real retained selected operation')
        return self

    def _check_permission_v3(self):
        if self.closed or get_ident()!=self.thread:
            raise AuthorityUnavailable('Owner metadata original call ended')
        owner=self.owner_service
        self._require_components_v3()
        if owner.core._db.in_transaction or self.db is not None and self.db.in_transaction:
            raise AuthorityUnavailable('Owner metadata observations must precede Core and Graph SQL')
        owner.core._require(self.credential,'owner_guard_read',owner.namespace,owner.holder)
        if self.kind in('authority_source_fence_location','authority_target_public_location','authority_target_background_location',
                'authority_life_numeric_result','authority_life_content_result','authority_artifact_model_result'):
            if self.kind in ('authority_life_numeric_result','authority_life_content_result','authority_artifact_model_result'):
                original=_OWNER_LIFE_RESULT_INVOCATIONS_V3.get(self.service,{}).get(self.permit.operation_id)
                if (original is None or original[0] is not self.credential or original[2]!=self.permit
                        or self.service._inflight_deliveries.get(self.permit.operation_id)!=self.permit
                        or self.service._graph_reader.owner_storage is not owner):
                    raise AuthorityUnavailable('Life result metadata original read invocation ended')
            owner.fences._require_permit(credential=self.credential,subject=self.subject,permit=self.permit)
        elif self.kind in ('authority_natural_self_location','authority_c04_self_location','authority_conditioned_child_location'):
            if self.kind=='authority_conditioned_child_location':
                from .current_conditioned_child_v1 import require_current_conditioned_core_call_v1
                invocation=self.service._calls.get(self.permit.operation_id)
                if invocation is None:raise AuthorityUnavailable('conditioned Owner EOF lost its actual Core invocation')
                require_current_conditioned_core_call_v1(self.service,credential=self.credential,subject=self.subject,
                    permit=self.permit,selector=invocation[3])
            if (self.service._core is not owner.core or self.service._fences is not owner.fences
                    or self.service._owner_storage is not owner or self.service._graph._path!=owner.graph_path):
                raise AuthorityUnavailable('Self Owner metadata crossed its installed Source components')
            owner.core._require(self.credential,'self_identity_read',owner.namespace,owner.holder)
            owner.fences.validate_fence(credential=self.credential,subject=self.subject,permit=self.permit)
        else:
            owner.core._require(self.credential,'execution' if self.kind in('authority_life_location','authority_offline_location')
                else 'current',owner.namespace)
        with owner.fences._frozen() as (db,deletion,execution,_):
            anchor=owner.fences._current_locked(db,deletion,execution,holder=owner.holder,generation=self.permit.generation)
            owner.fences.fences.validate_fence_locked(db,self.permit,subject=self.subject,current_anchor=anchor)
            head=owner.tickets.current_migration_head_in_tx(db,authority_namespace=owner.namespace)
            if anchor!=self.permission_anchor or head!=self.head:
                raise AuthorityUnavailable('Owner metadata original permission or authorization head changed')
            if self.history is None:
                if owner._head_in_tx(db)!=head:raise AuthorityUnavailable('source Owner metadata head changed')
                if self.actor is None:owner._background_identity_in_tx(db,head)
                else:
                    owner.sessions.require_current_in_tx(db,token=self.session_token,request=self.session_request)
                    owner.sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=owner.namespace,
                        installation_id=owner.installation_id,actor_id=self.actor,principal=self.session_request.principal)
            else:
                if owner._current_transfer(db,generation=anchor.activation_generation)!=self.history:
                    raise AuthorityUnavailable('Target Owner metadata activated history changed')
                if self.kind=='authority_target_public_location':
                    owner._current_session(db,actor=self.actor,token=self.session_token,request=self.session_request)
        if self.deadline_utc is not None and self.clock()>=self.deadline_utc:
            raise AuthorityUnavailable('Owner metadata exceeded its original bound deadline')

    def clock(self):
        service=self.service.numeric if self.kind=='authority_series_location' else self.service
        return service._clock()

    def _c09_retained_heap_bytes_v3(self):
        seen=set()
        return (_owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)
            +_owner_location_payload_heap_v3((self.decoded_grant,self.location,self.request,self.namespace,
                self.permission_anchor,self.comparison_anchor,self.head,self.history,self.selection_digest,
                self.subject,self.deadline_utc,self.kind,self.thread,self.closed,self.consumer_records),seen))

    def release_v3(self):
        if self.closed:return
        self.closed=True;_OWNER_LOCATION_AUTHORITY_CALLS_V3.discard(self)
        try:
            if self.operation is not None:finish_runtime_storage_operation_v3(self.operation)
        finally:
            try:
                if self.handle is not None:self.handle.close()
            finally:
                if self.db is not None:self.db.close()


def _owner_location_complete_service_v3(caller,*,kind,owner_service,credential,permit,
        permission_anchor,comparison_anchor,head,history=None,deadline_utc=None,
        actor=None,session_token=None,session_request=None):
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from ..graph_types import validate_owner_grant_v1
    call=_AuthorityOwnerLocationCallV3(_OWNER_CALLER_ISSUER_V3,service=caller,kind=kind,
        owner_service=owner_service,credential=credential,subject=permit.subject,permit=permit,
        permission_anchor=permission_anchor,comparison_anchor=comparison_anchor,head=head,history=history,
        deadline_utc=deadline_utc,actor=actor,session_token=session_token,session_request=session_request)
    proof=graph_work=lineage=None;published=False
    invocation=_OWNER_LOCATION_SERVICE_INVOCATION_V3.get()
    if invocation is None or invocation[0] is not caller:
        call.release_v3()
        raise AuthorityUnavailable('Owner metadata collector requires its actual service consumer lifetime')
    call.consumer_records=invocation[1]
    try:
        proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,kind,None,caller,owner_service,call,None,
            None,None,None,head.issue_operation.principal,D12CurrentOwnerAuthorityV1(head.guard,None),head,
            call.operation,call.control,call.selection_digest,call.namespace,owner_service.installation_id,
            owner_service.holder,permission_anchor,comparison_anchor,credential,permit.subject,permit,
            call,deadline_utc,get_ident(),target_history=history,
            target_role=None if history is None else ('public_session_header' if kind=='authority_target_public_location' else 'background_existing_header'))
        call.proof=proof
        register_owner_location_retained_state_v3(proof,call)
        graph_work=prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof) as meter:progress=graph_work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase')=='owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts=graph_work.result.require_for_v3(proof)
        lineage=(prepare_source_owner_location_lineage_v3(proof,facts) if history is None
            else prepare_target_owner_location_lineage_v3(proof,facts))
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof) as meter:progress=lineage.advance(meter=meter)
            if type(progress) is dict and progress.get('phase')=='owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        if history is None:
            admission=resolve_source_owner_storage_admission_from_completed_location_v3(proof,facts)
        else:
            admission=resolve_target_owner_storage_continuation_from_completed_location_v3(proof,facts)
        raw=facts.atom[1];scan=_OwnerLocationJSONAllocationScanV3(lineage,(),('current-owner-grant',))
        reserve_owner_location_retained_growth_v3(proof,4*len(raw)+_owner_alloc_size_v3(b''))
        try:scan._feed(raw.encode('utf-8'));scan.complete=True
        finally:finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof,scan.decode_growth_bound_v3())
        try:
            grant=json.loads(raw);validate_owner_grant_v1(grant)
            call.decoded_grant=grant
        finally:finish_owner_location_retained_growth_v3(proof)
        call._check_permission_v3()
        reserve_owner_location_retained_growth_v3(proof,
            4*_owner_alloc_size_v3(())+32*8+_owner_alloc_size_v3([])+8*8)
        try:
            call.location=((facts.metadata,grant,admission) if history is None else
                (facts.metadata,facts.atom[0],head.grant_digest,lineage.imported,admission))
            invocation[1].append((call,proof,lineage))
        finally:finish_owner_location_retained_growth_v3(proof)
        published=True
        return call.location
    except BaseException as error:
        if lineage is not None:lineage.cancel_v3(error)
        elif graph_work is not None:graph_work.cancel_v3(error)
        raise
    finally:
        if not published:
            if lineage is not None:lineage.close_v3()
            elif graph_work is not None:graph_work.close_v3()
            if proof is not None:proof.release_v3()
            call.release_v3()


_OWNER_LOCATION_SERVICE_INVOCATION_V3=ContextVar('sylanne_owner_location_service_invocation_v3',default=None)

@contextmanager
def _owner_location_service_invocation_v3(service):
    prior=_OWNER_LOCATION_SERVICE_INVOCATION_V3.get()
    if prior is not None and prior[0] is service:
        yield
        return
    state=(service,[])
    token=_OWNER_LOCATION_SERVICE_INVOCATION_V3.set(state)
    try:
        yield
    finally:
        _OWNER_LOCATION_SERVICE_INVOCATION_V3.reset(token)
        for call,proof,lineage in reversed(state[1]):
            try:
                lineage.close_v3()
            finally:
                try:proof.release_v3()
                finally:call.release_v3()
        state[1].clear()


def _owner_numeric_deadline_v3(binding):
    from datetime import datetime
    from .d04_numeric_contract_v3 import D04NumericBindingV3
    from .d04_root_execution_contract_v3 import D04RootExecutionBindingV3
    if type(binding) not in (D04NumericBindingV3,D04RootExecutionBindingV3):
        raise AuthorityUnavailable('Owner numeric deadline requires the actual original typed binding')
    return datetime.fromisoformat(binding.deadline_utc.replace('Z','+00:00')).timestamp()


def _owner_location_execution_locator_v3(service):
    # This fixed two-scalar locator chooses the already authenticated own-execution
    # comparison. The actual full recovery column still must pass its canonical EOF.
    from contextlib import closing
    from .daemon import _bootstrap_control_quantum_v3
    from .d04_series_service_v1 import AuthorityD04SeriesServiceV1
    actual=service.numeric if type(service) is AuthorityD04SeriesServiceV1 else service
    control=actual.bridge.core._c09_storage_reader_v1
    with _bootstrap_control_quantum_v3(control) as meter:
        with closing(sqlite3.connect(actual.graph_path.as_uri()+'?mode=ro',uri=True,isolation_level=None)) as db:
            db.execute('PRAGMA query_only=ON')
            row=_read_one(db,"SELECT json_extract(requirements_json,'$.execution_seq'),"
                "json_extract(requirements_json,'$.execution_digest') FROM graph_recovery_metadata_v2 "
                'WHERE bot=? AND persona=?',actual.namespace.as_tuple,meter)
    if row is None or type(row[0]) is not int or type(row[1]) is not str:
        raise AuthorityUnavailable('Owner own-execution metadata locator is absent')
    return row
def prepare_owner_location_for_numeric_v3(service, *, permit, binding=None, original_binding=None):
    self=service
    _owner_location_actual_service_v3(self,'authority_numeric_location')
    from .d04_numeric_journal_v3 import read_numeric_rows_locked_v3
    if original_binding is not None and original_binding!=binding:
        raise AuthorityUnavailable('Owner numeric original binding differs')
    if binding is not None:self._binding_scope(binding)
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    if self.target_owner_service is None and self.storage_owner_service is not None:
        return _prepare_numeric_source_location_v3(self,permit,binding)
    if self.target_owner_service is None:
        selectors=self._read_source_owner_selectors(binding) if binding is not None else ()
        with self.bridge.core._tx() as db:
            head=self.owner_tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)
            if head is None or head.state!="active":
                raise AuthorityUnavailable("numeric current Owner head unavailable")
            if binding is not None:self._require_accepting_owners_locked(db,binding,selectors)
            return D12CurrentOwnerAuthorityV1(head.guard,None)
    target=self.target_owner_service
    if binding is None:
        return target.get_current_background_owner_authority_for_fence_v1(
            credential=self.credential,subject=permit.subject,permit=permit)[0]
    # A target Graph intentionally retains its before-head during its own
    # numeric claim/terminal appends. Only this actual installed numeric
    # service may prove that bounded interval; ordinary target reads remain
    # exact-current and never fall back on a failed authorization.
    with self._frozen() as (db,deletion,execution):
        anchor,holder=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
        _,claim,_,claim_row,terminal_row=read_numeric_rows_locked_v3(self.bridge.journal,binding)
        head=self.owner_tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)
        if head is None or head.state!="active" or holder!=target.holder:
            raise AuthorityUnavailable("numeric target current holder/Owner changed")
        history=target._current_transfer(db,generation=anchor.activation_generation)
        if claim is not None:
            self._verify_claim(binding,claim)
            original,_=self._gate_locked(db,binding,"claim")
            before=original.pinned_anchor
        else:
            before=anchor
    graph_head=_owner_location_execution_locator_v3(self)
    
    if graph_head==(anchor.execution_seq,anchor.execution_digest):
        location_anchor=anchor
    else:
        last=terminal_row or claim_row
        if (claim is None or last is None or not self._same_location_epoch(before,anchor)
                or graph_head!=(before.execution_seq,before.execution_digest)
                or claim_row[0]!=before.execution_seq+1
                or terminal_row is not None and (terminal_row[0]!=claim_row[0]+1 or terminal_row[5]!=claim_row[6])
                or (anchor.execution_seq,anchor.execution_digest)!=(last[0],last[6])):
            raise AuthorityUnavailable("target numeric identity cannot bridge unrelated execution")
        location_anchor=before
    location=_owner_location_complete_service_v3(self,kind='authority_numeric_location',owner_service=target,credential=self.credential,permit=permit,permission_anchor=anchor,comparison_anchor=location_anchor,head=head,history=history,deadline_utc=_owner_numeric_deadline_v3(binding))
    graph_metadata,revision,grant_digest,imported,continuation=location
    with self._frozen() as (db,deletion,execution):
        current,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
        if current!=anchor or target.tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)!=head:
            raise AuthorityUnavailable("target numeric identity changed after location read")
        return target._current_background_identity_for_verified_location_in_tx_v1(db,head=head,history=history,
            metadata=graph_metadata,revision=revision,grant_digest=grant_digest,imported=imported,
            continuation=continuation,anchor=current)

def _prepare_numeric_source_location_v3(self,permit,binding):
    from .d04_numeric_journal_v3 import read_numeric_rows_locked_v3
    """Actual source C09 identity over only this consumed execution prefix."""
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    service=self.storage_owner_service
    if binding is None:return service.get_current_background_owner_authority_for_fence_v1(credential=self.credential,subject=permit.subject,permit=permit)[0]
    with self._frozen() as (db,deletion,execution):
        anchor,holder=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
        _,claim,_,claim_row,terminal_row=read_numeric_rows_locked_v3(self.bridge.journal,binding)
        head=service._head_in_tx(db)
        if holder!=service.holder:raise AuthorityUnavailable("source storage Owner holder changed")
        service._background_identity_in_tx(db,head)
        if claim is not None:
            self._verify_claim(binding,claim);source,_=self._gate_locked(db,binding,"claim");before=source.pinned_anchor
        else:before=anchor
    graph_head=_owner_location_execution_locator_v3(self)
    if graph_head==(anchor.execution_seq,anchor.execution_digest):location_anchor=anchor
    else:
        last=terminal_row or claim_row
        if (claim is None or last is None or not self._same_location_epoch(before,anchor)
                or graph_head!=(before.execution_seq,before.execution_digest)
                or claim_row[0]!=before.execution_seq+1
                or terminal_row is not None and (terminal_row[0]!=claim_row[0]+1 or terminal_row[5]!=claim_row[6])
                or (anchor.execution_seq,anchor.execution_digest)!=(last[0],last[6])):
            raise AuthorityUnavailable("source storage Owner cannot skip unrelated execution")
        location_anchor=before
    _,grant,admission=_owner_location_complete_service_v3(self,kind='authority_numeric_location',owner_service=service,credential=self.credential,permit=permit,permission_anchor=anchor,comparison_anchor=location_anchor,head=head,deadline_utc=_owner_numeric_deadline_v3(binding))
    if head.grant_digest.removeprefix("sha256:")!=binding.owner_grant_digest:
        raise AuthorityUnavailable("source storage original Owner grant changed")
    with self._frozen() as (db,deletion,execution):
        current,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
        if current!=anchor or service._head_in_tx(db)!=head:raise AuthorityUnavailable("source storage Owner changed after independent graph read")
        service._background_identity_in_tx(db,head)
    return D12CurrentOwnerAuthorityV1(head.guard,None,admission)

def prepare_owner_location_for_root_execution_v3(service, *, permit, binding=None, original_binding=None):
    self=service
    _owner_location_actual_service_v3(self,'authority_root_location')
    from .d04_root_execution_journal_v3 import read_root_execution_rows_locked_v3
    if original_binding is not None and original_binding!=binding:
        raise AuthorityUnavailable('Owner numeric original binding differs')
    if binding is not None:self._binding_scope(binding)
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    if self.target_owner_service is None and self.storage_owner_service is not None:
        return _prepare_root_source_location_v3(self,permit,binding)
    if self.target_owner_service is None:
        selectors=self._read_root_basis(binding) if binding is not None else None
        with self.bridge.core._tx() as db:
            head=self.owner_tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)
            if head is None or head.state!="active":
                raise AuthorityUnavailable("root current Owner head unavailable")
            if binding is not None:self._require_root_accepting_owner_locked(db,binding,selectors)
            return D12CurrentOwnerAuthorityV1(head.guard,None)
    target=self.target_owner_service
    if binding is None:
        return target.get_current_background_owner_authority_for_fence_v1(
            credential=self.credential,subject=permit.subject,permit=permit)[0]
    # A target Graph intentionally retains its before-head during its own
    # root claim/terminal appends. Only this actual installed root
    # service may prove that bounded interval; ordinary target reads remain
    # exact-current and never fall back on a failed authorization.
    with self._frozen() as (db,deletion,execution):
        anchor,holder=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
        _,claim,_,claim_row,terminal_row=read_root_execution_rows_locked_v3(self.bridge.journal,binding)
        head=self.owner_tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)
        if head is None or head.state!="active" or holder!=target.holder:
            raise AuthorityUnavailable("root target current holder/Owner changed")
        history=target._current_transfer(db,generation=anchor.activation_generation)
        if claim is not None:
            self._verify_claim(binding,claim)
            original,_=self._gate_locked(db,binding,"claim")
            before=original.pinned_anchor
        else:
            before=anchor
    graph_head=_owner_location_execution_locator_v3(self)
    
    if graph_head==(anchor.execution_seq,anchor.execution_digest):
        location_anchor=anchor
    else:
        last=terminal_row or claim_row
        if (claim is None or last is None or not self._same_location_epoch(before,anchor)
                or graph_head!=(before.execution_seq,before.execution_digest)
                or claim_row[0]!=before.execution_seq+1
                or terminal_row is not None and (terminal_row[0]!=claim_row[0]+1 or terminal_row[5]!=claim_row[6])
                or (anchor.execution_seq,anchor.execution_digest)!=(last[0],last[6])):
            raise AuthorityUnavailable("target root identity cannot bridge unrelated execution")
        location_anchor=before
    location=_owner_location_complete_service_v3(self,kind='authority_root_location',owner_service=target,credential=self.credential,permit=permit,permission_anchor=anchor,comparison_anchor=location_anchor,head=head,history=history,deadline_utc=_owner_numeric_deadline_v3(binding))
    graph_metadata,revision,grant_digest,imported,continuation=location
    with self._frozen() as (db,deletion,execution):
        current,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
        if current!=anchor or target.tickets.current_migration_head_in_tx(db,authority_namespace=self.bridge.namespace)!=head:
            raise AuthorityUnavailable("target root identity changed after location read")
        return target._current_background_identity_for_verified_location_in_tx_v1(db,head=head,history=history,
            metadata=graph_metadata,revision=revision,grant_digest=grant_digest,imported=imported,
            continuation=continuation,anchor=current)

def _prepare_root_source_location_v3(self,permit,binding):
    from .d04_root_execution_journal_v3 import read_root_execution_rows_locked_v3
    """Actual source C09 identity over only this consumed execution prefix."""
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    service=self.storage_owner_service
    if binding is None:return service.get_current_background_owner_authority_for_fence_v1(credential=self.credential,subject=permit.subject,permit=permit)[0]
    with self._frozen() as (db,deletion,execution):
        anchor,holder=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
        _,claim,_,claim_row,terminal_row=read_root_execution_rows_locked_v3(self.bridge.journal,binding)
        head=service._head_in_tx(db)
        if holder!=service.holder:raise AuthorityUnavailable("source storage Owner holder changed")
        service._background_identity_in_tx(db,head)
        if claim is not None:
            self._verify_claim(binding,claim);source,_=self._gate_locked(db,binding,"claim");before=source.pinned_anchor
        else:before=anchor
    graph_head=_owner_location_execution_locator_v3(self)
    if graph_head==(anchor.execution_seq,anchor.execution_digest):location_anchor=anchor
    else:
        last=terminal_row or claim_row
        if (claim is None or last is None or not self._same_location_epoch(before,anchor)
                or graph_head!=(before.execution_seq,before.execution_digest)
                or claim_row[0]!=before.execution_seq+1
                or terminal_row is not None and (terminal_row[0]!=claim_row[0]+1 or terminal_row[5]!=claim_row[6])
                or (anchor.execution_seq,anchor.execution_digest)!=(last[0],last[6])):
            raise AuthorityUnavailable("source storage Owner cannot skip unrelated execution")
        location_anchor=before
    _,grant,admission=_owner_location_complete_service_v3(self,kind='authority_root_location',owner_service=service,credential=self.credential,permit=permit,permission_anchor=anchor,comparison_anchor=location_anchor,head=head,deadline_utc=_owner_numeric_deadline_v3(binding))
    if head.grant_digest.removeprefix("sha256:")!=binding.owner_grant_digest:
        raise AuthorityUnavailable("source storage original Owner grant changed")
    with self._frozen() as (db,deletion,execution):
        current,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
        self.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
        if current!=anchor or service._head_in_tx(db)!=head:raise AuthorityUnavailable("source storage Owner changed after independent graph read")
        service._background_identity_in_tx(db,head)
    return D12CurrentOwnerAuthorityV1(head.guard,None,admission)

def prepare_owner_location_for_series_v3(service, *, permit, binding, original_binding):
    self=service
    _owner_location_actual_service_v3(self,'authority_series_location')
    from .d04_series_journal_v1 import read_series_rows_locked_v1
    from .d04_series_contract_v1 import gate_id
    self._binding(binding)
    self.numeric._binding_scope(original_binding)
    target = self.numeric.target_owner_service
    storage = self.numeric.storage_owner_service if target is None else None
    service = target or storage
    if service is None:
        return self.numeric._owner_observation(permit, original_binding)
    with self.numeric._frozen() as (db, deletion, execution):
        anchor, holder = self.numeric._current_anchor_locked(db, deletion, execution, action="accounting")
        self.bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
        _, claim, _, first, last = read_series_rows_locked_v1(self.bridge.journal, binding)
        head = (self.numeric.owner_tickets.current_migration_head_in_tx(db, authority_namespace=self.bridge.namespace)
            if target is not None else storage._head_in_tx(db))
        if head is None or (target is not None and head.state != "active") or holder != service.holder:
            raise AuthorityUnavailable("series current storage Owner/holder changed")
        history = None if target is None else target._current_transfer(db, generation=anchor.activation_generation)
        if claim is None:
            before = anchor
        else:
            self._claim(binding, claim)
            stored = self.bridge.fences._row(db, gate_id(binding, "claim"))
            before = self.bridge.fences._permit(stored).pinned_anchor
    graph_head = _owner_location_execution_locator_v3(self)
    location_anchor = anchor
    if graph_head != (anchor.execution_seq, anchor.execution_digest):
        tail = last or first
        if (claim is None or tail is None or not self.numeric._same_location_epoch(before, anchor)
                or graph_head != (before.execution_seq, before.execution_digest)
                or first[0] != before.execution_seq + 1
                or last is not None and (last[0] != first[0] + 1 or last[5] != first[6])
                or (anchor.execution_seq, anchor.execution_digest) != (tail[0], tail[6])):
            raise AuthorityUnavailable("series Owner cannot bridge another execution")
        location_anchor = before
    location = _owner_location_complete_service_v3(self,kind='authority_series_location',owner_service=service,
        credential=self.numeric.credential,permit=permit,permission_anchor=anchor,comparison_anchor=location_anchor,
        head=head,history=history,deadline_utc=_owner_numeric_deadline_v3(binding.numeric))
    with self.numeric._frozen() as (db, deletion, execution):
        current, _ = self.numeric._current_anchor_locked(db, deletion, execution, action="accounting")
        self.bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=current)
        current_head = (self.numeric.owner_tickets.current_migration_head_in_tx(db, authority_namespace=self.bridge.namespace)
            if target is not None else storage._head_in_tx(db))
        if current != anchor or current_head != head:
            raise AuthorityUnavailable("series Owner changed after actual location read")
        if target is not None:
            graph_metadata, revision, grant_digest, imported, continuation = location
            return target._current_background_identity_for_verified_location_in_tx_v1(db, head=head, history=history,
                metadata=graph_metadata, revision=revision, grant_digest=grant_digest, imported=imported,
                continuation=continuation, anchor=current)
        storage._background_identity_in_tx(db, head)
        from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
        return D12CurrentOwnerAuthorityV1(head.guard, None, location[2])

def prepare_owner_location_for_life_bridge_v3(service, *, binding, permit, before):
    _owner_location_actual_service_v3(service,'authority_life_location')
    from .d11_life_bridge_v1 import _originals_locked,_same_location
    if (binding.namespace!=service.namespace or binding.installation_id!=service.installation_id
            or binding.authority_namespace!=service.bridge.namespace):
        raise AuthorityUnavailable('Owner life original binding crossed its actual installation')
    """Read actual source/target Owner over this authenticated own interval."""
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    owner_service = service.owner_service
    with service._frozen() as (db, deletion, execution, _):
        anchor, holder = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=anchor)
        actual_before, _, _ = _originals_locked(service, db, binding, execution)
        if actual_before != before or not _same_location(before, anchor) or holder != owner_service.holder:
            raise AuthorityUnavailable("life current Owner location changed")
        head = service.owner_tickets.current_migration_head_in_tx(db, authority_namespace=service.bridge.namespace)
        if head is None or head.state != "active":
            raise AuthorityUnavailable("life current Owner head unavailable")
        if type(owner_service) is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner_service._head_in_tx(db) != head:
                raise AuthorityUnavailable("life source Owner differs")
            actor, _ = owner_service._background_identity_in_tx(db, head)
            history = None
        else:
            history = owner_service._current_transfer(db, generation=anchor.activation_generation)
            actor = None
    if history is None:
        _, _, admission = _owner_location_complete_service_v3(service,kind='authority_life_location',
            owner_service=owner_service,credential=service.credential,permit=permit,
            permission_anchor=anchor,comparison_anchor=before,head=head)
        observed = D12CurrentOwnerAuthorityV1(head.guard, None, admission)
    else:
        location = _owner_location_complete_service_v3(service,kind='authority_life_location',
            owner_service=owner_service,credential=service.credential,permit=permit,
            permission_anchor=anchor,comparison_anchor=before,head=head,history=history)
    with service._frozen() as (db, deletion, execution, _):
        current, _ = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=current)
        if current != anchor or service.owner_tickets.current_migration_head_in_tx(db,
                authority_namespace=service.bridge.namespace) != head:
            raise AuthorityUnavailable("life Owner changed during independent location read")
        if history is None:
            if owner_service._background_identity_in_tx(db, head)[0] != actor:
                raise AuthorityUnavailable("life source Owner actor changed")
        else:
            metadata, revision, grant_digest, imported, continuation = location
            observed = owner_service._current_background_identity_for_verified_location_in_tx_v1(db,
                head=head, history=history, metadata=metadata, revision=revision,
                grant_digest=grant_digest, imported=imported, continuation=continuation, anchor=current)
            actor = owner_service.sessions._current_pairing_source.current_principal_binding(
                authority_namespace=service.bridge.namespace, installation_id=service.installation_id,
                principal=head.issue_operation.principal)
            if actor is None:
                raise AuthorityUnavailable("life target current Owner actor unavailable")
    return observed, actor.actor_id

def prepare_owner_location_for_offline_bridge_v3(service, *, binding, permit, before):
    _owner_location_actual_service_v3(service,'authority_offline_location')
    from .d11_offline_tick_bridge_v1 import _originals_locked,_same_location
    if (binding.namespace!=service.namespace or binding.installation_id!=service.installation_id
            or binding.authority_namespace!=service.bridge.namespace):
        raise AuthorityUnavailable('Owner life original binding crossed its actual installation')
    """Read actual source/target Owner over this authenticated own interval."""
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    owner_service = service.owner_service
    with service._frozen() as (db, deletion, execution, _):
        anchor, holder = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=anchor)
        actual_before, _, _ = _originals_locked(service, db, binding, execution)
        if actual_before != before or not _same_location(before, anchor) or holder != owner_service.holder:
            raise AuthorityUnavailable("offline current Owner location changed")
        head = service.owner_tickets.current_migration_head_in_tx(db, authority_namespace=service.bridge.namespace)
        if head is None or head.state != "active":
            raise AuthorityUnavailable("offline current Owner head unavailable")
        if type(owner_service) is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner_service._head_in_tx(db) != head:
                raise AuthorityUnavailable("offline source Owner differs")
            actor, _ = owner_service._background_identity_in_tx(db, head)
            history = None
        else:
            history = owner_service._current_transfer(db, generation=anchor.activation_generation)
            actor = None
    if history is None:
        _, _, admission = _owner_location_complete_service_v3(service,kind='authority_offline_location',
            owner_service=owner_service,credential=service.credential,permit=permit,
            permission_anchor=anchor,comparison_anchor=before,head=head)
        observed = D12CurrentOwnerAuthorityV1(head.guard, None, admission)
    else:
        location = _owner_location_complete_service_v3(service,kind='authority_offline_location',
            owner_service=owner_service,credential=service.credential,permit=permit,
            permission_anchor=anchor,comparison_anchor=before,head=head,history=history)
    with service._frozen() as (db, deletion, execution, _):
        current, _ = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=current)
        if current != anchor or service.owner_tickets.current_migration_head_in_tx(db,
                authority_namespace=service.bridge.namespace) != head:
            raise AuthorityUnavailable("offline Owner changed during independent location read")
        if history is None:
            if owner_service._background_identity_in_tx(db, head)[0] != actor:
                raise AuthorityUnavailable("offline source Owner actor changed")
        else:
            metadata, revision, grant_digest, imported, continuation = location
            observed = owner_service._current_background_identity_for_verified_location_in_tx_v1(db,
                head=head, history=history, metadata=metadata, revision=revision,
                grant_digest=grant_digest, imported=imported, continuation=continuation, anchor=current)
            actor = owner_service.sessions._current_pairing_source.current_principal_binding(
                authority_namespace=service.bridge.namespace, installation_id=service.installation_id,
                principal=head.issue_operation.principal)
            if actor is None:
                raise AuthorityUnavailable("offline target current Owner actor unavailable")
    return observed, actor.actor_id


def prepare_current_owner_location_for_source_fence_v3(owner_service, *, credential, subject, permit, head,
        actor=None,session_token=None,session_request=None):
    _owner_location_actual_service_v3(owner_service,'authority_source_fence_location')
    if subject!=permit.subject:raise AuthorityUnavailable('Source Owner original subject changed')
    guard=owner_service.tickets.get_current_guard(credential=credential,
        authority_namespace=owner_service.namespace,installation_id=owner_service.installation_id,
        subject=subject,permit=permit,owner_actor_id=actor,owner_session_token=session_token,
        owner_session_request=session_request)
    with owner_service.core._tx() as db:
        if owner_service._head_in_tx(db)!=head or head.guard!=guard:
            raise AuthorityUnavailable('Source Owner metadata original current guard changed')
    return _owner_location_complete_service_v3(owner_service,kind='authority_source_fence_location',
        owner_service=owner_service,credential=credential,permit=permit,
        permission_anchor=permit.pinned_anchor,comparison_anchor=permit.pinned_anchor,head=head,
        actor=actor,session_token=session_token,session_request=session_request)


def prepare_current_owner_location_for_target_public_fence_v3(owner_service, *, credential,subject,
        permit,head,history,actor,session_token,session_request):
    _owner_location_actual_service_v3(owner_service,'authority_target_public_location')
    if subject!=permit.subject:raise AuthorityUnavailable('Target Owner original subject changed')
    with owner_service.fences._frozen() as (db,deletion,execution,_):
        anchor=owner_service.fences._current_locked(db,deletion,execution,
            holder=owner_service.holder,generation=permit.generation)
        owner_service.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        owner_service._current_session(db,actor=actor,token=session_token,request=session_request)
        if (anchor!=permit.pinned_anchor or owner_service.tickets.current_migration_head_in_tx(db,
                authority_namespace=owner_service.namespace)!=head or head.state!='active'
                or owner_service._current_transfer(db,generation=anchor.activation_generation)!=history
                or head.issue_operation.principal!=session_request.principal):
            raise AuthorityUnavailable('Target Owner metadata current public session/history changed')
    return _owner_location_complete_service_v3(owner_service,kind='authority_target_public_location',
        owner_service=owner_service,credential=credential,permit=permit,permission_anchor=anchor,
        comparison_anchor=anchor,head=head,history=history,actor=actor,
        session_token=session_token,session_request=session_request)


def prepare_current_owner_location_for_target_background_fence_v3(owner_service, *,credential,subject,
        permit,head,history):
    _owner_location_actual_service_v3(owner_service,'authority_target_background_location')
    if subject!=permit.subject:raise AuthorityUnavailable('Target Owner background original subject changed')
    return _owner_location_complete_service_v3(owner_service,kind='authority_target_background_location',
        owner_service=owner_service,credential=credential,permit=permit,
        permission_anchor=permit.pinned_anchor,comparison_anchor=permit.pinned_anchor,
        head=head,history=history)

def prepare_owner_location_for_natural_self_v3(*,self_service,model_service,credential,subject,permit,intent):
    _owner_location_actual_service_v3(self_service,'authority_natural_self_location')
    from .natural_model_self_v1 import _NaturalModelSelfRequestV1,_NaturalModelSelfV1,_KEY
    from ..domains.d03.self_perspective import SelfIdentityMapping
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
    _,_,admission=_owner_location_complete_service_v3(self_service,kind='authority_natural_self_location',
        owner_service=owner_reader,credential=credential,permit=permit,
        permission_anchor=anchor,comparison_anchor=anchor,head=owner_head)
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


def prepare_owner_location_for_conditioned_child_v1(service,*,credential,subject,permit,request,current_self):
    from .current_conditioned_child_v1 import require_current_conditioned_core_call_v1
    require_current_conditioned_core_call_v1(service,credential=credential,subject=subject,permit=permit,selector=request)
    owner=service._owner_storage
    if owner.core._db.in_transaction:raise AuthorityUnavailable('conditioned Owner EOF requires Core observation outside SQL')
    with owner.fences._frozen()as(db,deletion,execution,_):
        anchor=owner.fences._current_locked(db,deletion,execution,holder=owner.holder,generation=permit.generation)
        owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        head=owner._head_in_tx(db);owner._background_identity_in_tx(db,head)
        if(anchor!=permit.pinned_anchor or head.guard.authorization_head!=current_self.owner_authorization_head
                or head.guard.authorization_revision!=current_self.owner_authorization_revision):
            raise AuthorityUnavailable('conditioned child current Self and complete Owner head differ')
    location=_owner_location_complete_service_v3(service,kind='authority_conditioned_child_location',
        owner_service=owner,credential=credential,permit=permit,permission_anchor=anchor,comparison_anchor=anchor,
        head=head,deadline_utc=request.original_deadline_utc)
    invocation=_OWNER_LOCATION_SERVICE_INVOCATION_V3.get()
    if invocation is None or invocation[0]is not service or not invocation[1]:
        raise AuthorityUnavailable('conditioned Owner EOF has no actual retained service lifetime')
    call,proof,lineage=invocation[1][-1]
    if call.service is not service or call.permit!=permit or call.location is not location:
        raise AuthorityUnavailable('conditioned Owner EOF changed its actual call or completed grant')
    return(location,call,proof,lineage)

def prepare_owner_location_for_c04_self_v3(service,*,credential,reader,binding,permit):
    self=service
    _owner_location_actual_service_v3(self,'authority_c04_self_location')
    from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
    """Closed Authority-internal read for the installed C04 exclusive claim."""
    from .c04_current_execution_v3 import InstalledC04CurrentReaderV3
    from .internal_work_contract import InternalWorkBindingV1
    from .c04_exclusive_execution_v3 import _operation
    from ..host.installed_d06_build import ALGORITHM_ID_V4
    if (type(reader) is not InstalledC04CurrentReaderV3
            or reader.foreground_observer is None
            or reader.foreground_observer.self_identity is not self
            or reader.namespace != self._namespace_id
            or reader.graph_path != self._graph._path
            or type(binding) is not InternalWorkBindingV1
            or binding.algorithm_ref != ALGORITHM_ID_V4
            or binding.namespace != self._fences.namespace
            or type(permit) is not FencePermitV2
            or permit.subject != "c04-exclusive:" + binding.binding_digest
            or permit.operation != "write"
            or permit.operation_id != _operation(binding, "claim")
            or permit.generation != binding.activation_generation):
        raise AuthorityUnavailable("Self C04 identity read crossed its installed exclusive claim")
    request = SelfIdentityCurrentRequestV1(
        permit.authority_id, self._fences.namespace, self._namespace_id,
        self._installation_id, self._manifest_digest, binding.operation_id, permit)
    self._core._require(credential, "self_identity_read",
                        request.authority_namespace, self._holder)
    location_reader, owner_reader = self._source_location, self._owner_storage
    if location_reader is None or owner_reader is None:
        raise AuthorityUnavailable("Self C04 lacks its actual installed current storage readers")
    # Read-only internal observation. The caller cannot open/finish a fence,
    # mutate an Owner grant, or borrow the public Host read subject.
    location = location_reader._observe(purpose="business", credential=credential,
        subject=permit.subject, permit=permit)
    with self._fences._frozen() as (db, deletion, execution, history):
        before = self._read_locked(db, deletion, execution, history,
            credential, permit.subject, request, location)
        owner_head = owner_reader._head_in_tx(db)
        owner_reader._background_identity_in_tx(db, owner_head)
    if before is None:
        return None
    head, guard, anchor, epoch = before
    if owner_head.guard != guard:
        raise AuthorityUnavailable("Self C04 storage Owner head differs")
    _,_,admission=_owner_location_complete_service_v3(self,kind='authority_c04_self_location',
        owner_service=owner_reader,credential=credential,permit=permit,
        permission_anchor=anchor,comparison_anchor=anchor,head=owner_head)
    current_graph = self._graph.current(request.namespace, anchor, request.installation_id, guard,
        source_location=location_reader, location_observation=location,
        storage_admission=admission, holder=self._holder)
    if current_graph is None:
        raise AuthorityUnavailable("Self C04 current D01 role/storage identity is unavailable")
    with self._fences._frozen() as (db, deletion, execution, history):
        after = self._read_locked(db, deletion, execution, history,
            credential, permit.subject, request, location)
        if after != before or owner_reader._head_in_tx(db) != owner_head:
            raise AuthorityUnavailable("Self C04 mapping or Owner changed during actual graph read")
        owner_reader._background_identity_in_tx(db, owner_head)
    return self._current_value(request, head, guard, anchor, current_graph, admission)

_OWNER_LIFE_RESULT_INVOCATIONS_V3=WeakKeyDictionary()
_OWNER_LIFE_RESULT_ENTRIES_V3=WeakKeyDictionary()

def register_owner_location_for_life_model_result_v3(service,*,credential,request,permit):
    from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
    from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1,ArtifactDraftModelResultReadRequestV1,ArtifactDraftModelResultReadRequestV2
    from .internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
    from .current_life_numeric_v1 import LifeNumericModelResultReadRequestV1
    from .internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2
    expected=(LifeNumericModelResultReadRequestV1 if type(service) is InstalledLifeNumericModelResultServiceV1
        else InternalLifeModelResultReadRequestV2 if type(service) is InstalledInternalLifeModelResultServiceV2
        else type(request) if type(service)is AuthorityArtifactDraftModelResultServiceV1 and type(request)in{
            ArtifactDraftModelResultReadRequestV1,ArtifactDraftModelResultReadRequestV2}else None)
    if (expected is None or type(request) is not expected or type(permit) is not FencePermitV2
            or permit.operation!='read' or permit.operation_id!=request.read_attempt_id
            or permit.subject!=service._read_subject or permit.holder!=service._holder
            or service._inflight_deliveries.get(request.read_attempt_id)!=permit
            or service._graph_reader.owner_storage.fences is not service._fences):
        raise AuthorityUnavailable('Life result Owner metadata requires its real in-flight read producer')
    service._fences.validate_fence(credential=credential,subject=service._read_subject,permit=permit)
    _OWNER_LIFE_RESULT_INVOCATIONS_V3.setdefault(service,{})[request.read_attempt_id]=(credential,request,permit)


def release_owner_location_for_life_model_result_invocation_v3(service,read_attempt_id):
    registered=_OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service)
    if registered is not None:
        registered.pop(read_attempt_id,None)
        if not registered:_OWNER_LIFE_RESULT_INVOCATIONS_V3.pop(service,None)


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _LifeModelResultOwnerEntryV3:
    issuer: InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('actual Life result Owner entry issuer required')

    @contextmanager
    def bind_for_read_v3(self,db,*,installed_reader,intent):
        state=_OWNER_LIFE_RESULT_ENTRIES_V3.get(self)
        if (state is None or state[0] is not installed_reader or state[5].request is not intent
                or db.in_transaction):
            raise AuthorityUnavailable('Life result Owner entry crossed its real reader/request')
        reader,proof,facts,lineage,entry,call=state
        call._check_permission_v3();facts.require_for_v3(proof)
        from .daemon import _bootstrap_control_quantum_v3
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with _bootstrap_control_quantum_v3(call.control):
            handle=bind_runtime_database_from_control_v3(db,control=call.control,role='graph')
        if handle is None:
            raise AuthorityUnavailable('physical_owner_retention_operation_unavailable')
        if handle.pool is not call.operation.pool or handle.selection_digest!=call.selection_digest:
            handle.close()
            raise AuthorityUnavailable('Life result Owner crossed its actual selected retention pool')
        token=None
        try:
            with bind_runtime_storage_operation_v3(call.operation,db):
                with runtime_storage_quantum_v3(db):
                    token=_OWNER_MODEL_LOCATION_BOUND_V3.set((call,state,db))
                    try:yield
                    finally:
                        _OWNER_MODEL_LOCATION_BOUND_V3.reset(token)
                        token=None
            call._check_permission_v3();facts.require_for_v3(proof)
        finally:
            if token is not None:_OWNER_MODEL_LOCATION_BOUND_V3.reset(token)
            handle.close()

    def release_v3(self):
        state=_OWNER_LIFE_RESULT_ENTRIES_V3.pop(self,None)
        if state is not None:
            call=state[5]
            _OWNER_MODEL_LOCATION_ENTRIES_V3.pop(call,None)
            try:state[3].close_v3()
            finally:
                try:state[1].release_v3()
                finally:call.release_v3()


def prepare_owner_location_for_life_model_result_v3(service,*,intent,read_attempt_id):
    from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
    from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1,ArtifactDraftModelResultReadRequestV1,ArtifactDraftModelResultReadRequestV2
    from .internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
    from .v2_model_egress_contract import ModelEgressIntentV1
    if type(service) not in (InstalledLifeNumericModelResultServiceV1,InstalledInternalLifeModelResultServiceV2,AuthorityArtifactDraftModelResultServiceV1):
        raise AuthorityUnavailable('exact installed Life result service required')
    registered=_OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service,{}).get(read_attempt_id)
    if registered is None or type(intent) is not ModelEgressIntentV1:
        raise AuthorityUnavailable('Life result lacks its actual registered original read invocation')
    credential,request,permit=registered
    if service._inflight_deliveries.get(read_attempt_id)!=permit or intent.call_id!=request.call_id:
        raise AuthorityUnavailable('Life result original in-flight permit or call changed')
    owner=service._graph_reader.owner_storage
    owner.core._require(credential,'owner_guard_read',owner.namespace,owner.holder)
    with owner.fences._frozen() as (db,deletion,execution,_):
        anchor=owner.fences._current_locked(db,deletion,execution)
        owner.fences.fences.validate_fence_locked(db,permit,subject=service._read_subject,current_anchor=anchor)
        if anchor!=permit.pinned_anchor:raise AuthorityUnavailable('Life result original read anchor changed')
        head=owner._head_in_tx(db);actor,login=owner._background_identity_in_tx(db,head)
    kind=('authority_life_numeric_result' if type(service) is InstalledLifeNumericModelResultServiceV1
        else 'authority_artifact_model_result'if type(service)is AuthorityArtifactDraftModelResultServiceV1
        else 'authority_life_content_result')
    call=_AuthorityOwnerLocationCallV3(_OWNER_CALLER_ISSUER_V3,service=service,kind=kind,owner_service=owner,
        credential=credential,subject=service._read_subject,permit=permit,permission_anchor=anchor,
        comparison_anchor=anchor,head=head,history=None,deadline_utc=None)
    call.request=intent;call.result_read_attempt_id=read_attempt_id
    proof=graph_work=lineage=None
    try:
        proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,kind,None,service,owner,call,None,
            service._graph_reader.bundle,None,None,head.issue_operation.principal,D12CurrentOwnerAuthorityV1(head.guard,None),
            head,call.operation,call.control,call.selection_digest,call.namespace,owner.installation_id,owner.holder,
            anchor,anchor,credential,service._read_subject,permit,call,None,get_ident())
        call.proof=proof;register_owner_location_retained_state_v3(proof,call)
        graph_work=prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof) as meter:progress=graph_work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase')=='owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts=graph_work.result.require_for_v3(proof)
        lineage=prepare_source_owner_location_lineage_v3(proof,facts)
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof) as meter:progress=lineage.advance(meter=meter)
            if type(progress) is dict and progress.get('phase')=='owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        admission=resolve_source_owner_storage_admission_from_completed_location_v3(proof,facts)
        scan=_OwnerLocationJSONAllocationScanV3(lineage,(),('result-owner-grant',));raw=facts.atom[1]
        reserve_owner_location_retained_growth_v3(proof,4*len(raw)+_owner_alloc_size_v3(b''))
        try:scan._feed(raw.encode('utf-8'));scan.complete=True
        finally:finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof,scan.decode_growth_bound_v3())
        try:
            grant=json.loads(raw);call.decoded_grant=grant
            entry=_OwnerModelLocationReadV3(anchor,head,actor,login,facts.metadata,grant,admission)
            call.location=tuple(getattr(entry,name) for name in ('anchor','head','actor','login','metadata','grant','admission'))
        finally:finish_owner_location_retained_growth_v3(proof)
        call._check_permission_v3()
        result=_LifeModelResultOwnerEntryV3(_OWNER_CALLER_ISSUER_V3)
        state=(service._graph_reader,proof,facts,lineage,entry,call)
        _OWNER_LIFE_RESULT_ENTRIES_V3[result]=state
        _OWNER_MODEL_LOCATION_ENTRIES_V3[call]=state
        return result
    except BaseException as error:
        if lineage is not None:lineage.cancel_v3(error)
        elif graph_work is not None:graph_work.cancel_v3(error)
        if proof is not None:proof.release_v3()
        call.release_v3()
        raise



# Contact metadata callers borrow their actual Authority Work's retained operation.
_OWNER_CONTACT_LOCATION_ENTRIES_V3 = WeakKeyDictionary()

def _require_contact_owner_components_v3(owner_service,work):
    from .current_authority_graph_read_v3 import (AuthorityGraphReadWorkV3,
        require_actual_authority_graph_attachment_owner_v3)
    from .contact_model_work_v3 import ModelContactReadSelectorV3,require_model_contact_work_v3
    from .contact_background_graph_v3 import (ContactBackgroundSelectorV3,ContactPlanLocatorEOFV3,
        require_contact_background_work_v3)
    from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    if type(work)is not AuthorityGraphReadWorkV3:
        raise AuthorityUnavailable('Contact Owner requires its actual Authority Work')
    require_actual_authority_graph_attachment_owner_v3(work)
    controller=work.controller.require_installed_v3()
    selector=work.contact_selector
    if type(selector)is ModelContactReadSelectorV3:
        pair,selector,intent,operation,scope,permit=require_model_contact_work_v3(work)
        service,policy,location=pair[0],pair[4],pair[5]
        binding=(pair,selector,intent,operation,scope,permit)
    elif type(selector)is ContactBackgroundSelectorV3:
        saved=require_contact_background_work_v3(work)
        service,actual_controller,location,issuer,actual_policy,selector,operation,scope,permit,credential,subject=saved
        policy=service._policy
        if (actual_controller is not controller or location is not service._location
                or issuer is not service._issuer or actual_policy is not work.contact_policy
                or credential is not work.credential or subject!=work.subject
                or type(work.contact_locator)is not ContactPlanLocatorEOFV3 or work.contact_locator.work is not work):
            raise AuthorityUnavailable('Contact Owner background metadata changed its actual installed producer')
        binding=saved
    else:
        raise AuthorityUnavailable('Contact Owner has another actual registered selector')
    if (type(service)is not InstalledContactModelResultServiceV2
            or owner_service is not policy.owner_service or service._policy is not policy
            or service._location is not location or controller.location is not location
            or controller.fences is not owner_service.fences or policy.core is not owner_service.core
            or policy.fences is not owner_service.fences or policy.tickets is not owner_service.tickets
            or selector.namespace!=work.namespace or work.namespace!=owner_service.namespace_id
            or work.subject!=permit.subject or permit.holder!=owner_service.holder
            or permit.namespace!=owner_service.namespace or scope is not work.scope
            or operation is not work.operation or permit!=work.permit):
        raise AuthorityUnavailable('Contact Owner crossed its actual policy/permit/selected Graph')
    if type(owner_service)is InstalledD12OwnerStorageAdmissionServiceV1:
        control=owner_service.control;path=owner_service.graph_path
    elif type(owner_service)is InstalledD12TargetOwnerAdmissionServiceV1:
        if owner_service.storage_continuation_reader is None:
            raise AuthorityUnavailable('Contact Target Owner has no actual continuation reader')
        control=owner_service.storage_continuation_reader.control;path=owner_service.target_graph
    else:
        raise AuthorityUnavailable('Contact requires its actual Source or Target Owner service')
    if (controller.control is not control or owner_service.core._c09_storage_reader_v1 is not control
            or service._path!=path or location._graph_db_path!=path
            or owner_service.installation_id!=service._installation_id
            or owner_service.holder!=service._holder):
        raise AuthorityUnavailable('Contact Owner changed its actual selected installation')
    _require_owner_operation_v3(operation,db=work.db,namespace=work.namespace,control=control)
    return binding,service,policy,location,control

class _ContactOwnerLocationCallerV3:
    def __init__(self,issuer,owner_service,work,*,anchor,head,history,actor,login):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Contact Owner metadata requires its private caller factory')
        self.binding,self.service,self.policy,self.location,self.control=_require_contact_owner_components_v3(owner_service,work)
        self.work=ref(work);self.owner_service=owner_service;self.controller=work.controller
        self.db,self.operation,self.scope=work.db,work.operation,work.scope
        self.permit,self.credential,self.subject=work.permit,work.credential,work.subject
        self.namespace,self.selection_digest=work.namespace,work.selection_digest
        self.anchor,self.head,self.history,self.actor,self.login=anchor,head,history,actor,login
        self.deadline_utc=work.deadline_utc;self.thread=get_ident()
        self.proof=self.facts=self.lineage=self.grant=self.observed=None
        self.closed=False
    def _actual(self):
        work=self.work()
        if (work is None or self.closed or get_ident()!=self.thread
                or _OWNER_CONTACT_LOCATION_ENTRIES_V3.get(work)is not self
                or self.binding!=_require_contact_owner_components_v3(self.owner_service,work)[0]
                or self.operation is not work.operation or self.scope is not work.scope
                or self.db is not work.db or self.permit!=work.permit or self.credential is not work.credential
                or self.selection_digest!=work.selection_digest
                or work.deadline_utc is None or work.deadline_utc>self.deadline_utc):
            raise AuthorityUnavailable('Contact Owner metadata lost its exact current Work or original bound')
        return work
    def _check_permission_v3(self):
        work=self._actual();owner=self.owner_service
        if self.db.in_transaction or owner.core._db.in_transaction:
            raise AuthorityUnavailable('Contact Owner observations must precede Graph and Core transactions')
        work._check_permission_v3()
        owner.core._require(self.credential,'owner_guard_read',owner.namespace,owner.holder)
        with owner.fences._frozen()as(db,deletion,execution,_):
            anchor=owner.fences._current_locked(db,deletion,execution,
                holder=owner.holder,generation=self.permit.generation)
            self._require_current_core_v3(db,anchor)
    def _require_current_core_v3(self,db,anchor):
        self._actual();owner=self.owner_service
        if db is not owner.core._db or not db.in_transaction:
            raise AuthorityUnavailable('Contact Owner current check needs its actual pinned Core transaction')
        owner.fences.fences.validate_fence_locked(db,self.permit,subject=self.subject,current_anchor=anchor)
        head=owner.tickets.current_migration_head_in_tx(db,authority_namespace=owner.namespace)
        if anchor!=self.anchor or head!=self.head or head is None or head.state!='active':
            raise AuthorityUnavailable('Contact Owner current permission/head changed')
        if self.history is None:
            if owner._head_in_tx(db)!=head or owner._background_identity_in_tx(db,head)!=(self.actor,self.login):
                raise AuthorityUnavailable('Contact Source Owner current actor/key changed')
            if self.observed is not None and self.observed.guard!=head.guard:
                raise AuthorityUnavailable('Contact Source Owner observation changed its actual guard')
        else:
            if owner._current_transfer(db,generation=anchor.activation_generation)!=self.history:
                raise AuthorityUnavailable('Contact Target Owner activated history changed')
            if self.observed is not None:
                current=owner._current_background_identity_for_verified_location_in_tx_v1(db,
                    head=head,history=self.history,metadata=self.facts.metadata,revision=self.facts.atom[0],
                    grant_digest=head.grant_digest,imported=self.lineage.imported,
                    continuation=self.observed.storage_admission,anchor=anchor)
                if current.guard!=self.observed.guard or current.target_admission!=self.observed.target_admission:
                    raise AuthorityUnavailable('Contact Target Owner signed admission or paired key changed')
        if self.controller.clock()>=self.work().deadline_utc:
            raise AuthorityUnavailable('Contact Owner exceeded its actual current original deadline')
        return self.observed
    def _c09_retained_heap_bytes_v3(self):
        seen=set()
        return (_owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)
            +_owner_location_payload_heap_v3((self.binding,self.anchor,self.head,self.history,self.actor,
                self.login,self.grant,self.observed,self.namespace,self.subject,self.deadline_utc),seen))
    def release_v3(self):
        if self.closed:return
        self.closed=True
        work=self.work()
        if work is not None and _OWNER_CONTACT_LOCATION_ENTRIES_V3.get(work)is self:
            _OWNER_CONTACT_LOCATION_ENTRIES_V3.pop(work,None)
        if self.lineage is not None:self.lineage.close_v3()
        elif self.facts is not None:self.facts.work.close_v3()
        if self.proof is not None:self.proof.release_v3()
        self.binding=self.facts=self.lineage=self.grant=self.observed=None

def _require_contact_owner_caller_proof_v3(proof,graph_stamp):
    call=proof.request
    if (type(call)is not _ContactOwnerLocationCallerV3 or call.proof is not proof
            or proof.owner_service is not call.owner_service or proof.controller is not call.controller
            or proof.service is not call.work().service or proof.retained_operation is not call.operation
            or proof.scope is not call.scope or proof.original_permit!=call.permit
            or proof.current_owner_head!=call.head or proof.permission_anchor!=call.anchor
            or proof.graph_comparison_anchor!=call.anchor or proof.target_history!=call.history
            or proof.control is not call.control or proof.selection_digest!=call.selection_digest):
        raise AuthorityUnavailable('Contact Owner proof crossed its exact private caller')
    work=call._actual()
    if graph_stamp is not None:
        metadata,epoch=graph_stamp;req=metadata.requirements;anchor=call.anchor
        if (req.namespace!=work.namespace or req.authority_namespace!=anchor.namespace
                or any(getattr(req,name)!=getattr(anchor,name)for name in(
                    'authority_id','activation_generation','revocation_epoch','deletion_journal_id',
                    'deletion_seq','deletion_digest','execution_journal_id','execution_seq','execution_digest'))):
            raise AuthorityUnavailable('Contact Owner metadata changed its actual permission comparison anchor')
        from .contact_model_work_v3 import ModelContactReadSelectorV3
        if type(work.contact_selector)is ModelContactReadSelectorV3 and work.contact_selector.role=='model':
            intent=work.contact_intent
            if(metadata.graph_revision,epoch.revision)!=(intent.graph_revision,intent.graph_epoch):
                raise AuthorityUnavailable('Contact model Owner changed its original model Graph version')
    return call

def observe_owner_location_for_contact_v3(owner_service,work):
    """Complete bodyless Owner/Source or Target location EOF in this actual Work."""
    _require_contact_owner_components_v3(owner_service,work)
    if work.db.in_transaction or owner_service.core._db.in_transaction:
        raise AuthorityUnavailable('Contact Owner metadata must be observed outside Graph/Core SQL')
    prior=_OWNER_CONTACT_LOCATION_ENTRIES_V3.get(work)
    if prior is not None:
        prior._check_permission_v3()
        if prior.observed is None:raise AuthorityUnavailable('Contact Owner original observation did not complete')
        return prior.observed
    work._check_permission_v3()
    owner_service.core._require(work.credential,'owner_guard_read',owner_service.namespace,owner_service.holder)
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    with owner_service.fences._frozen()as(db,deletion,execution,_):
        anchor=owner_service.fences._current_locked(db,deletion,execution,
            holder=owner_service.holder,generation=work.permit.generation)
        owner_service.fences.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
        if anchor!=work.permit.pinned_anchor:
            raise AuthorityUnavailable('Contact original Owner permission anchor changed')
        head=owner_service.tickets.current_migration_head_in_tx(db,authority_namespace=owner_service.namespace)
        if head is None or head.state!='active':raise AuthorityUnavailable('Contact actual current Owner head is absent')
        if type(owner_service)is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner_service._head_in_tx(db)!=head:raise AuthorityUnavailable('Contact Source current Owner changed')
            actor,login=owner_service._background_identity_in_tx(db,head);history=None
        else:
            history=owner_service._current_transfer(db,generation=anchor.activation_generation);actor=login=None
    call=_ContactOwnerLocationCallerV3(_OWNER_CALLER_ISSUER_V3,owner_service,work,
        anchor=anchor,head=head,history=history,actor=actor,login=login)
    _OWNER_CONTACT_LOCATION_ENTRIES_V3[work]=call
    graph_work=None
    try:
        proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,'authority_contact_location',None,work.service,
            owner_service,work.controller,None,None,work.scope,None,head.issue_operation.principal,
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
        raw=facts.atom[1];scan=_OwnerLocationJSONAllocationScanV3(lineage,(),('contact-owner-grant',))
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
        elif work.graph_stamp!=stamp:raise AuthorityUnavailable('Contact Owner location changed the actual selected Graph epoch')
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

def require_owner_location_observation_current_for_contact_v3(owner_service,work,observed,core_db):
    """Recheck the same private observation using only the caller's Core TX."""
    call=_OWNER_CONTACT_LOCATION_ENTRIES_V3.get(work)
    if call is None or call.owner_service is not owner_service or call.observed is not observed:
        raise AuthorityUnavailable('Contact current Owner observation has no actual completed private caller')
    call._actual()
    if call.facts is None or call.lineage is None or not call.lineage.complete:
        raise AuthorityUnavailable('Contact Owner/Source or Target location EOF is incomplete')
    if (core_db is not owner_service.core._db or not core_db.in_transaction or work.db.in_transaction):
        raise AuthorityUnavailable('Contact current Owner check must be Core-only after Graph rollback')
    # The actual permit's anchor is independently re-observed in this same Core TX.
    row=owner_service.fences.core._row(core_db,owner_service.namespace)
    if (row[0]!=owner_service.holder or row[1]!=work.permit.generation or row[2]!='active'
            or row[3]is not None or row[4]is not None or row[9]!='clear'):
        raise AuthorityUnavailable('Contact current Core namespace is no longer settled for its original holder')
    anchor=owner_service.fences.core._anchor(core_db,owner_service.namespace,row)
    return call._require_current_core_v3(core_db,anchor)

def release_owner_location_for_contact_work_v3(work):
    call=_OWNER_CONTACT_LOCATION_ENTRIES_V3.get(work)
    if call is not None:call.release_v3()


def create_goal_management_owner_caller_proof_v3(invocation):
    from .owner_goal_cancellation_v1 import GoalManagementInvocationV1,require_goal_management_invocation_v1
    if type(invocation) is not GoalManagementInvocationV1:
        raise AuthorityUnavailable('Goal management Owner facts require their actual private invocation')
    require_goal_management_invocation_v1(invocation,phase='before')
    _require_owner_operation_v3(invocation.retained_operation,db=invocation.actual_db,
        namespace=invocation.namespace,control=invocation.control)
    if (invocation.retained_operation.selection_digest!=invocation.selection_digest
            or invocation.retained_operation.deadline_utc!=invocation.registered_deadline_utc
            or invocation.current_owner_head.guard!=invocation.current_owner_guard
            or invocation.current_owner_head.issue_operation.principal!=invocation.principal):
        raise AuthorityUnavailable('Goal management Owner metadata crossed its original current admission')
    return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        'goal_management_metadata',None,invocation.service,invocation.owner_service,None,None,
        invocation.bundle,None,None,invocation.principal,None,invocation.current_owner_head,
        invocation.retained_operation,invocation.control,invocation.selection_digest,invocation.namespace,
        invocation.installation_id,invocation.holder,invocation.current_anchor,invocation.current_anchor,
        invocation.credential,invocation.subject,None,invocation,invocation.registered_deadline_utc,get_ident())

_METHOD_OWNER_READ_ENTRIES_V3=WeakKeyDictionary()
_METHOD_OWNER_READ_OPERATIONS_V3=frozenset(('freeze_general_growth_intent_v1',
    'register_general_growth_trial_start_v1','derive_general_growth_trial_v1','adopt_general_growth_v1'))


_NUMERIC_METHOD_OWNER_READ_OPERATIONS_V3=frozenset({
    "prepare_internal_life_numeric_context","prepare_internal_life_numeric",
    "acquire_internal_life_numeric","adopt_internal_life_numeric",
    "prepare_internal_life_numeric_drive","prepare_internal_life_numeric_joint",
    "prepare_internal_life_interval_baseline","adopt_internal_life_numeric_trace"})


_OWNER_JOB_CANCEL_READ_OPERATIONS_V3=frozenset({"cancel_current_owner_job_v3"})
_NUMERIC_PAID_WRITE_OWNER_OPERATIONS_V3=frozenset({"prepare_current_life_numeric_result_read_v3","record_current_life_numeric_paid_result_v3"})

_NUMERIC_HOST_READ_OPERATIONS_V3=frozenset({
    "read_current_life_numeric_identity_v3","read_current_life_numeric_model_draft_v3",
    "qualify_current_life_numeric_candidate_v3","read_current_life_numeric_joint_prepared_v3","read_current_life_numeric_trace_v3"})

def _require_host_method_owner_reader_v3(reader):
    from ..runtime.current_method_learning_read_v3 import _MethodLearningReadV3,_READERS,METHOD_LEARNING_WORK_KIND_V3
    from ..host.authority_profile import AdminInstallationBundle
    if type(reader)is not _MethodLearningReadV3 or reader not in _READERS:
        raise AuthorityUnavailable('Method Owner metadata requires its exact private ordinary READ')
    if reader.operation_kind in _NUMERIC_PAID_WRITE_OWNER_OPERATIONS_V3:
        from ..runtime.current_life_numeric_paid_write_v3 import require_numeric_paid_write_work_v3
        require_numeric_paid_write_work_v3(reader)
    if reader.operation_kind in _OWNER_JOB_CANCEL_READ_OPERATIONS_V3:
        from ..runtime.current_owner_job_cancel_v3 import require_current_job_cancel_work_v3
        require_current_job_cancel_work_v3(reader)
    if reader.operation_kind in _NUMERIC_HOST_READ_OPERATIONS_V3:
        from ..runtime.current_life_numeric_read_v3 import require_numeric_read_work_v3
        require_numeric_read_work_v3(reader)
    from ..runtime.current_beta1_source_read_v3 import beta1_source_operation_v3,beta1_source_work_kind_v3,beta1_source_reader_work_kind_v3,require_current_beta1_source_work_v3
    own_source=beta1_source_operation_v3(reader.operation_kind)
    if own_source:require_current_beta1_source_work_v3(reader)
    graph=reader.graph;store=graph._GraphCoordinator__store;scope=reader.fence.scope
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or type(assembly.admin_bundle)is not AdminInstallationBundle:
        raise AuthorityUnavailable('Method Owner metadata requires the actual installed bundle')
    bundle=assembly.admin_bundle;policy=bundle.installation_policy;port=graph._GraphCoordinator__content_fence_v2
    reader.work._require_invocation(graph)
    provisional=_host_method_owner_read_provisional_v3(reader)
    if (not own_source and reader.operation_kind not in (_METHOD_OWNER_READ_OPERATIONS_V3 | _NUMERIC_METHOD_OWNER_READ_OPERATIONS_V3 | _NUMERIC_HOST_READ_OPERATIONS_V3 | _OWNER_JOB_CANCEL_READ_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OWNER_OPERATIONS_V3)
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.kind!=(beta1_source_reader_work_kind_v3(reader)if own_source else "current_life_numeric_paid_write_v3" if reader.operation_kind in _NUMERIC_PAID_WRITE_OWNER_OPERATIONS_V3 else "current_owner_job_cancel_v3" if reader.operation_kind in _OWNER_JOB_CANCEL_READ_OPERATIONS_V3 else "current_life_numeric_read_v3" if reader.operation_kind in _NUMERIC_HOST_READ_OPERATIONS_V3 else METHOD_LEARNING_WORK_KIND_V3) or reader.work.coordinator is not graph
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or reader.runtime.graph is not graph or reader.operation.closed or reader.read_finished
            or reader.session_proof is None or reader.background_followup is not None
            or reader.background_host_lifecycle is not None or reader.background_offline is not None
            or scope.operation!='read' or scope.namespace!=reader.authority.namespace
            or reader.namespace!=policy.namespace or scope.namespace!=policy.namespace
            or scope.authority_namespace!=policy.authority_namespace
            or scope.permit.holder!=policy.administrator_holder
            or port.installation_grant.installation_id!=policy.installation_id
            or reader.fence.authority!=reader.authority or reader.fence.owner_session_proof!=reader.session_proof
            or (not provisional and (reader.fence.observed_guard!=reader.owner_guard
                or reader.fence.observed_owner!=reader.owner_binding))
            or reader.fence.owner_binding is not None or reader.fence.owner_principal is not None
            or reader.operation.operation_id!=reader.operation_id
            or reader.operation.deadline_utc!=reader.deadline_utc
            or reader.work.deadline_utc!=reader.operation.deadline_utc
            or reader.work.selection_digest!=reader.operation.selection_digest):
        raise AuthorityUnavailable('Method Owner caller left its original Work/READ/session/installation')
    control=_require_owner_operation_v3(reader.operation,db=store._db,namespace=reader.namespace)
    token,request=reader.session_proof
    if request.principal!=reader.owner_binding.principal:
        raise AuthorityUnavailable('Method Owner original session principal differs')
    return graph,port,bundle,scope,control,request.principal


def _observe_host_method_owner_authority_v3(reader):
    from ..runtime.first_ingress_v2 import trusted_upper
    from time import monotonic
    graph,port,bundle,scope,control,principal=_require_host_method_owner_reader_v3(reader)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable('Method Owner permission observation must precede Graph SQL')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Method Owner original READ permit changed')
    token,request=reader.session_proof
    if graph._current_owner_principal(reader.authority.actor,reader.namespace)!=principal:
        raise AuthorityUnavailable('Method Owner current actor pairing changed')
    observed=port.get_current_owner_authority_for_fence_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=reader.authority.actor,owner_session_token=token,owner_session_request=request)
    if (type(observed)is not tuple or len(observed)!=2 or type(observed[0])is not D12CurrentOwnerAuthorityV1
            or observed[1]!=scope.permit):
        raise AuthorityUnavailable('Method Owner session lacks its actual current Authority observation')
    current=observed[0];guard=current.guard;binding=reader.owner_binding
    provisional=_host_method_owner_read_provisional_v3(reader)
    if (not provisional and (guard!=reader.owner_guard or guard!=reader.fence.observed_guard)
            or guard.authority_id!=scope.pinned_anchor.authority_id or guard.namespace!=reader.namespace
            or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id!=port.installation_grant.installation_id)):
        raise AuthorityUnavailable('Method Owner original guard/head/revocation/installation changed')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if ((reader.operation.deadline_utc is not None and now>=reader.operation.deadline_utc)
            or monotonic()>=reader.initial_monotonic_deadline):
        raise AuthorityUnavailable('Method Owner metadata exceeded its original UTC/monotonic deadline')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Method Owner original READ permit changed after session observation')
    return current


def _require_host_method_owner_caller_v3(proof):
    reader=proof.request
    graph,port,bundle,scope,control,principal=_require_host_method_owner_reader_v3(reader)
    if (proof.graph is not graph or proof.service is not reader.runtime or proof.port is not port
            or proof.bundle is not bundle or proof.scope is not scope or proof.authority!=reader.authority
            or proof.principal!=principal or proof.control is not control
            or (not _host_method_owner_read_provisional_v3(reader)
                and proof.current_owner_authority.guard!=reader.owner_guard)
            or proof.retained_operation is not reader.operation or proof.original_permit!=scope.permit
            or proof.permission_anchor!=scope.pinned_anchor or proof.graph_comparison_anchor!=scope.pinned_anchor
            or proof.namespace!=reader.namespace or proof.installation_id!=bundle.installation_policy.installation_id
            or proof.holder!=bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Method Owner metadata proof crossed its actual private READ')


def _host_method_owner_binding_from_facts_v3(proof,facts):
    reader=proof.request;current=proof.current_owner_authority;scope=proof.scope
    facts.require_for_v3(proof)
    metadata=facts.metadata;req=metadata.requirements
    if (req.namespace!=reader.namespace or metadata.graph_revision!=scope.graph_revision
            or facts.graph_epoch!=scope.graph_epoch or req.authority_namespace!=scope.authority_namespace
            or not proof.graph._anchor_matches(req,scope.pinned_anchor)):
        raise AuthorityUnavailable('Method Owner fixed EOF lost its original Graph scope/location')
    binding=proof.graph._owner_graph_binding_from_current_metadata_v3(reader.authority,proof.principal,
        metadata=metadata,graph_epoch=facts.graph_epoch,atom=facts.atom,proof_row=facts.proof_row,
        epochs=facts.epochs,target_admission=current.target_admission,
        storage_admission=current.storage_admission,current_guard=current.guard)
    provisional=_host_method_owner_read_provisional_v3(reader)
    if binding!=reader.owner_binding or not provisional and binding!=reader.fence.observed_owner:
        raise AuthorityUnavailable('Method Owner full fixed EOF binding differs from its original READ')
    guard=current.guard
    if (guard.authorization_revision!=binding.authorization_revision or guard.authorization_head!=binding.authorization_head
            or guard.minimum_revocation_revision!=0 or guard.minimum_revocation_epoch!=binding.revocation_epoch
            or guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('Method Owner fixed EOF authorization or revocation changed')
    if provisional:
        reader.owner_binding=binding
        reader.owner_guard=guard
        reader.fence.observed_owner=binding
        reader.fence.observed_guard=guard
    return binding


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _HostMethodOwnerReadEntryV3:
    issuer: InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Method Owner entry requires its actual READ producer')
    def require_for_v3(self,reader):
        state=_METHOD_OWNER_READ_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable('Method Owner entry left its actual original reader')
        proof,work,facts=state
        require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=reader.graph_stamp)
        return _host_method_owner_binding_from_facts_v3(proof,facts)
    def release_v3(self):
        state=_METHOD_OWNER_READ_ENTRIES_V3.pop(self,None)
        if state is not None:
            proof,work,_=state
            try:work.close_v3()
            finally:proof.release_v3()

    def require_permission_v3(self,reader):
        state=_METHOD_OWNER_READ_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable('Method Owner permission left actual reader')
        proof,work,facts=state
        _require_owner_permission_outside_graph_v3(proof)
        with reader.store._lock:
            require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=reader.graph_stamp)
            return _host_method_owner_binding_from_facts_v3(proof,facts)


def prepare_current_host_method_owner_read_entry_v3(reader):
    graph,port,bundle,scope,control,principal=_require_host_method_owner_reader_v3(reader)
    current=_observe_host_method_owner_authority_v3(reader)
    policy=bundle.installation_policy
    proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='host_method_owner_read',graph=graph,service=reader.runtime,owner_service=None,controller=None,
        port=port,bundle=bundle,scope=scope,authority=reader.authority,principal=principal,
        current_owner_authority=current,current_owner_head=None,retained_operation=reader.operation,
        control=control,selection_digest=reader.operation.selection_digest,namespace=reader.namespace,
        installation_id=policy.installation_id,holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor,graph_comparison_anchor=scope.pinned_anchor,
        credential=None,subject=scope.permit.subject,original_permit=scope.permit,
        request=reader,deadline_utc=reader.operation.deadline_utc,thread=get_ident())
    work=None
    try:
        work=prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof)as meter:
                progress=work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts=work.result.require_for_v3(proof)
        _host_method_owner_binding_from_facts_v3(proof,facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry=_HostMethodOwnerReadEntryV3(_OWNER_CALLER_ISSUER_V3)
        _METHOD_OWNER_READ_ENTRIES_V3[entry]=(proof,work,facts)
        return entry
    except BaseException as exc:
        if work is not None:work.cancel_v3(exc)
        proof.release_v3()
        raise





_SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3 = WeakKeyDictionary()
_SEMANTIC_BACKGROUND_OWNER_IDENTITIES_V3 = WeakKeyDictionary()
_SEMANTIC_BACKGROUND_OWNER_ACLS_V3 = WeakKeyDictionary()
_SEMANTIC_BACKGROUND_OWNER_KINDS_V3 = frozenset((
    'host_artifact_model_dispatch_read','host_named_joint_source_read', 'host_conditioned_source_read', 'host_habit_source_read', 'host_semantic_recovery_read'))


def _semantic_background_owner_identity_v3(reader):
    kind = reader.work.kind
    if kind == 'current_world_source_read_v3':
        from ..runtime.named_joint_source_work_v3 import named_joint_background_owner_identity_v3
        state,cause_digest=named_joint_background_owner_identity_v3(reader)
        return 'host_named_joint_source_read',state,cause_digest
    if kind == 'current_conditioned_self_source_read_v3':
        from ..runtime.current_conditioned_self_read_v3 import (
            require_conditioned_background_owner_identity_v3, condition_followup_cause_metadata_v3)
        state = require_conditioned_background_owner_identity_v3(reader)
        cause = condition_followup_cause_metadata_v3(reader)
        caller_kind = 'host_conditioned_source_read'
    elif kind == 'current_habit_source_read_v3':
        from ..runtime.current_habit_source_read_v3 import (
            require_habit_background_owner_identity_v3, habit_background_cause_metadata_v3)
        state = require_habit_background_owner_identity_v3(reader)
        cause = habit_background_cause_metadata_v3(reader)
        caller_kind = 'host_habit_source_read'
    elif kind=='domain_background_read_v3'and reader.kind=='artifact_model_dispatch':
        from ..runtime.artifact_host_dispatch_source_v3 import (
            require_artifact_host_dispatch_owner_identity_v3,artifact_host_dispatch_owner_cause_v3)
        state=require_artifact_host_dispatch_owner_identity_v3(reader)
        cause=artifact_host_dispatch_owner_cause_v3(reader)
        caller_kind='host_artifact_model_dispatch_read'
    elif kind == 'domain_background_read_v3' and reader.kind == 'semantic_recovery':
        from ..runtime.semantic_recovery_source_v3 import (
            require_semantic_recovery_owner_identity_v3, semantic_recovery_owner_cause_metadata_v3)
        state = require_semantic_recovery_owner_identity_v3(reader)
        cause = semantic_recovery_owner_cause_metadata_v3(reader)
        caller_kind = 'host_semantic_recovery_read'
    else:
        raise AuthorityUnavailable('unregistered semantic background Owner producer')
    return caller_kind, state, canonical_digest(cause)


def _require_semantic_background_owner_reader_v3(reader):
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    from ..graph_worker import GraphStorageWorkV3
    from math import isfinite
    kind, state, cause_digest = _semantic_background_owner_identity_v3(reader)
    graph = reader.graph
    store = graph._GraphCoordinator__store
    scope = reader.fence.scope
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or type(assembly.admin_bundle) is not AdminInstallationBundle:
        raise AuthorityUnavailable('semantic background Owner requires the actual installed bundle')
    bundle = assembly.admin_bundle
    policy = bundle.installation_policy
    port = graph._GraphCoordinator__content_fence_v2
    if (type(port) is not V2FencePort or type(reader.work) is not GraphStorageWorkV3
            or reader.work.state is not reader or reader.work.coordinator is not graph
            or reader.work.operation is not reader.operation
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or reader.runtime.graph is not graph or reader.operation.closed or reader.read_finished
            or reader.session_proof is not None or reader.fence.owner_session_proof is not None
            or reader.fence.owner_binding is not None or reader.fence.owner_principal is not None
            or scope.operation != 'read' or scope.namespace != reader.namespace
            or reader.authority.namespace != reader.namespace or reader.fence.authority != reader.authority
            or reader.namespace != policy.namespace or scope.authority_namespace != policy.authority_namespace
            or scope.permit.holder != policy.administrator_holder
            or port.installation_grant.installation_id != policy.installation_id
            or reader.operation.operation_id != reader.operation_id
            or reader.work.operation_id != reader.operation_id
            or reader.operation.deadline_utc is None or not isfinite(reader.operation.deadline_utc)
            or reader.work.deadline_utc != reader.operation.deadline_utc
            or reader.work.selection_digest != reader.operation.selection_digest
            or reader.selection_digest != reader.operation.selection_digest
            or not isfinite(reader.initial_monotonic_deadline)):
        raise AuthorityUnavailable('semantic background Owner left its actual originating READ')
    reader.work._require_invocation(graph)
    control = _require_owner_operation_v3(reader.operation, db=store._db, namespace=reader.namespace)
    return graph, port, bundle, scope, control, (kind, state, cause_digest)


def _observe_semantic_background_owner_authority_v3(reader):
    from ..runtime.first_ingress_v2 import trusted_upper
    from time import monotonic
    graph, port, bundle, scope, control, identity = _require_semantic_background_owner_reader_v3(reader)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable('semantic background Owner observation must precede Graph SQL')
    if port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('semantic background Owner original READ permit changed')
    observed = port.get_current_background_owner_authority_for_fence_v1(
        namespace=reader.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
    if (type(observed) is not tuple or len(observed) != 2
            or type(observed[0]) is not D12CurrentOwnerAuthorityV1 or observed[1] != scope.permit):
        raise AuthorityUnavailable('semantic background Owner has no paired current Authority')
    current = observed[0]
    guard = current.guard
    binding = reader.owner_binding
    if (guard.namespace != reader.namespace or guard.authority_id != scope.pinned_anchor.authority_id
            or guard.minimum_revocation_revision != 0 or guard.pending_revoke_operation_id is not None
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id != port.installation_grant.installation_id)
            or (binding is not None and (guard.authorization_revision != binding.authorization_revision
                or guard.authorization_head != binding.authorization_head
                or guard.minimum_revocation_epoch != binding.revocation_epoch))
            or (reader.owner_guard is not None and guard != reader.owner_guard)
            or (reader.fence.observed_guard is not None and guard != reader.fence.observed_guard)):
        raise AuthorityUnavailable('semantic background Owner head/revocation/location changed')
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now >= reader.operation.deadline_utc or monotonic() >= reader.initial_monotonic_deadline:
        raise AuthorityUnavailable('semantic background Owner exceeded its original UTC/monotonic deadline')
    if port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('semantic background Owner permit changed after observation')
    return current


def _require_semantic_background_owner_caller_v3(proof):
    reader = proof.request
    graph, port, bundle, scope, control, identity = _require_semantic_background_owner_reader_v3(reader)
    if (_SEMANTIC_BACKGROUND_OWNER_IDENTITIES_V3.get(proof) != identity
            or proof.kind != identity[0] or proof.graph is not graph or proof.service is not reader.runtime
            or proof.port is not port or proof.bundle is not bundle or proof.scope is not scope
            or proof.control is not control or proof.retained_operation is not reader.operation
            or proof.authority != reader.authority or proof.principal is not None
            or proof.namespace != reader.namespace
            or proof.original_permit != scope.permit or proof.subject != scope.permit.subject
            or proof.selection_digest != reader.selection_digest
            or proof.deadline_utc != reader.operation.deadline_utc
            or proof.permission_anchor != scope.pinned_anchor
            or proof.graph_comparison_anchor != scope.pinned_anchor
            or proof.installation_id != bundle.installation_policy.installation_id
            or proof.holder != bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('semantic background Owner proof crossed its actual producer or READ')


def _pin_semantic_background_owner_acl_v3(proof, facts):
    import json
    from ..graph_types import owner_grant_key, validate_owner_grant_v1
    reader = proof.request
    facts.require_for_v3(proof)
    if proof.graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable('semantic background principal pairing must precede Graph SQL')
    if proof in _SEMANTIC_BACKGROUND_OWNER_ACLS_V3:
        raise AuthorityUnavailable('semantic background Owner ACL already pinned')
    grant = json.loads(facts.atom[1])
    validate_owner_grant_v1(grant)
    principal = OwnerPrincipalV1(**grant['principal'])
    pairing = proof.port.current_owner_principal_binding(namespace=proof.namespace,
        authority_namespace=proof.scope.authority_namespace, principal=principal)
    if (pairing is None or pairing.principal != principal
            or pairing.installation_id != proof.installation_id):
        raise AuthorityUnavailable('semantic background Owner principal is no longer paired')
    authority = AuthorityContext(pairing.actor_id, 'd12', owner_grant_key(*proof.namespace.as_tuple).token,
        proof.namespace, ('d11',), reader.authority.purpose, reader.authority.audience,
        grant['issuer_ref'], proof.scope.generation)
    _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[proof] = (authority, principal)


def _semantic_background_owner_binding_from_facts_v3(proof, facts):
    reader = proof.request
    facts.require_for_v3(proof)
    acl = _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.get(proof)
    if acl is None:
        raise AuthorityUnavailable('semantic background Owner principal has not completed actual EOF/pairing')
    authority, principal = acl
    metadata = facts.metadata
    req = metadata.requirements
    scope = proof.scope
    current = proof.current_owner_authority
    if (req.namespace != reader.namespace or metadata.graph_revision != scope.graph_revision
            or facts.graph_epoch != scope.graph_epoch or req.authority_namespace != scope.authority_namespace
            or not proof.graph._anchor_matches(req, scope.pinned_anchor)):
        raise AuthorityUnavailable('semantic background Owner fixed EOF crossed its Graph location')
    binding = proof.graph._owner_graph_binding_from_current_metadata_v3(
        authority, principal, metadata=metadata, graph_epoch=facts.graph_epoch,
        atom=facts.atom, proof_row=facts.proof_row, epochs=facts.epochs,
        target_admission=current.target_admission, storage_admission=current.storage_admission,
        current_guard=current.guard)
    guard = current.guard
    if (guard.authorization_head != binding.authorization_head
            or guard.authorization_revision != binding.authorization_revision
            or guard.minimum_revocation_revision != 0 or guard.minimum_revocation_epoch != binding.revocation_epoch
            or guard.pending_revoke_operation_id is not None
            or (reader.owner_binding is not None and reader.owner_binding != binding)
            or (reader.fence.observed_owner is not None and reader.fence.observed_owner != binding)):
        raise AuthorityUnavailable('semantic background Owner full EOF authorization differs')
    return binding


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class _HostSemanticBackgroundOwnerReadEntryV3:
    issuer: InitVar[object]
    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('semantic background Owner entry requires its private producer')
    def require_for_v3(self, reader):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable('semantic background Owner entry left its originating reader')
        proof, work, facts = state
        require_owner_location_caller_proof_v3(proof, phase='before', graph_stamp=reader.graph_stamp)
        return _semantic_background_owner_binding_from_facts_v3(proof, facts)
    def require_permission_v3(self, reader):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable('semantic background Owner permission left its originating reader')
        proof, work, facts = state
        _require_owner_permission_outside_graph_v3(proof)
        with reader.store._lock:
            require_owner_location_caller_proof_v3(proof, phase='before', graph_stamp=reader.graph_stamp)
            return _semantic_background_owner_binding_from_facts_v3(proof, facts)
    @property
    def owner_acl_authority(self):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None:
            raise AuthorityUnavailable('semantic background Owner entry was released')
        return _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[state[0]][0]
    @property
    def owner_principal(self):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None:
            raise AuthorityUnavailable('semantic background Owner entry was released')
        return _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[state[0]][1]
    @property
    def current_owner_guard(self):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None:
            raise AuthorityUnavailable('semantic background Owner entry was released')
        return state[0].current_owner_authority.guard
    def grant_value_v3(self, reader):
        state=_SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.get(self)
        if state is None or state[0].request is not reader:
            raise AuthorityUnavailable('Named Joint Owner grant lost its exact actual EOF entry')
        self.require_permission_v3(reader)
        value=json.loads(state[2].atom[1])
        from ..runtime.dispatch_current_inventory_v3 import _heap
        reader.operation.retain(_heap(value)+1024)
        return value
    def release_v3(self):
        state = _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3.pop(self, None)
        if state is not None:
            proof, work, facts = state
            try:
                work.close_v3()
            finally:
                _SEMANTIC_BACKGROUND_OWNER_IDENTITIES_V3.pop(proof, None)
                _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.pop(proof, None)
                proof.release_v3()


def prepare_current_host_semantic_background_owner_read_entry_v3(reader):
    graph, port, bundle, scope, control, identity = _require_semantic_background_owner_reader_v3(reader)
    current = _observe_semantic_background_owner_authority_v3(reader)
    policy = bundle.installation_policy
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind=identity[0], graph=graph, service=reader.runtime, owner_service=None, controller=None,
        port=port, bundle=bundle, scope=scope, authority=reader.authority, principal=None,
        current_owner_authority=current, current_owner_head=None, retained_operation=reader.operation,
        control=control, selection_digest=reader.selection_digest, namespace=reader.namespace,
        installation_id=policy.installation_id, holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor, graph_comparison_anchor=scope.pinned_anchor,
        credential=None, subject=scope.permit.subject, original_permit=scope.permit,
        request=reader, deadline_utc=reader.operation.deadline_utc, thread=get_ident())
    _SEMANTIC_BACKGROUND_OWNER_IDENTITIES_V3[proof] = identity
    work = None
    try:
        work = prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts = work.result.require_for_v3(proof)
        _pin_semantic_background_owner_acl_v3(proof, facts)
        _semantic_background_owner_binding_from_facts_v3(proof, facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _HostSemanticBackgroundOwnerReadEntryV3(_OWNER_CALLER_ISSUER_V3)
        _SEMANTIC_BACKGROUND_OWNER_ENTRIES_V3[entry] = (proof, work, facts)
        return entry
    except BaseException as exc:
        if work is not None:
            work.cancel_v3(exc)
        _SEMANTIC_BACKGROUND_OWNER_IDENTITIES_V3.pop(proof, None)
        _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.pop(proof, None)
        proof.release_v3()
        raise


def _semantic_write_owner_kind_v3(issued):
    from ..runtime.named_joint_binding_issuance_v1 import _IssuedNamedJointBindingV1
    if type(issued)is _IssuedNamedJointBindingV1:return 'host_named_joint_write_source'
    from ..runtime.habit_activity_issuance_v1 import _IssuedHabitActivityV1
    from ..runtime.conditioned_child_issuance_v1 import _IssuedConditionedChildV1
    if type(issued) is _IssuedHabitActivityV1:
        return 'host_habit_write_source'
    if type(issued) is _IssuedConditionedChildV1:
        return 'host_conditioned_write_source'
    from ..runtime.habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    if type(issued) is _IssuedHabitMaintenanceV1:
        return 'host_habit_maintenance_write_source'
    raise AuthorityUnavailable('unregistered private semantic WRITE issuer')


def _require_semantic_write_issuance_v3(issued, graph, scope):
    kind = _semantic_write_owner_kind_v3(issued)
    if kind == 'host_named_joint_write_source':
        from ..runtime.named_joint_binding_issuance_v1 import require_named_joint_issuance_v1
        return require_named_joint_issuance_v1(issued,graph,scope)
    if kind == 'host_habit_write_source':
        from ..runtime.habit_activity_issuance_v1 import require_habit_activity_issuance_v1
        return require_habit_activity_issuance_v1(issued, graph, scope)
    if kind == 'host_habit_maintenance_write_source':
        from ..runtime.habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
        return require_habit_maintenance_issuance_v1(issued, graph, scope)
    from ..runtime.conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
    return require_conditioned_child_issuance_v1(issued, graph, scope)


def _require_semantic_write_source_identity_v3(reader, scope, issued):
    kind = _semantic_write_owner_kind_v3(issued)
    if kind == 'host_named_joint_write_source':
        from ..runtime.named_joint_binding_issuance_v1 import require_named_joint_write_owner_identity_v3
        return require_named_joint_write_owner_identity_v3(reader,scope,issued)
    if kind == 'host_habit_write_source':
        from ..runtime.current_habit_source_read_v3 import require_habit_write_owner_identity_v3
        return require_habit_write_owner_identity_v3(reader, scope, issued)
    if kind == 'host_habit_maintenance_write_source':
        from ..runtime.habit_maintenance_source_v3 import require_habit_maintenance_write_owner_identity_v3
        return require_habit_maintenance_write_owner_identity_v3(reader, scope, issued)
    from ..runtime.current_conditioned_self_read_v3 import require_conditioned_write_owner_identity_v3
    return require_conditioned_write_owner_identity_v3(reader, scope, issued)


_SEMANTIC_WRITE_OWNER_CALLERS_V3 = WeakKeyDictionary()
_SEMANTIC_WRITE_OWNER_ENTRIES_V3 = WeakKeyDictionary()


def _require_semantic_write_owner_source_v3(reader, scope, issued):
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    from math import isfinite
    state = _require_semantic_write_source_identity_v3(reader, scope, issued)
    graph = reader.graph
    store = graph._GraphCoordinator__store
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or type(assembly.admin_bundle) is not AdminInstallationBundle:
        raise AuthorityUnavailable('Semantic WRITE Owner needs the actual installed bundle')
    bundle, port = assembly.admin_bundle, graph._GraphCoordinator__content_fence_v2
    evidence = _require_semantic_write_issuance_v3(issued, graph, scope)
    policy = bundle.installation_policy
    if (type(port) is not V2FencePort or type(scope) is not FenceScope or scope.operation != 'write'
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or reader.namespace != scope.namespace or scope.namespace != policy.namespace
            or scope.authority_namespace != policy.authority_namespace
            or scope.permit.holder != policy.administrator_holder
            or port.installation_grant.installation_id != policy.installation_id
            or reader.operation.closed or not reader.read_finished
            or reader.operation.deadline_utc is None or not isfinite(reader.operation.deadline_utc)
            or not isfinite(reader.initial_monotonic_deadline)
            or evidence.current_self.permit != scope.permit
            or reader.authority.namespace != scope.namespace
            or reader.authority.actor != evidence.current_self.self_entity_ref
            or reader.authority.activation_generation != scope.generation):
        raise AuthorityUnavailable('Semantic WRITE Owner left its actual private current Source/permit')
    control = _require_owner_operation_v3(reader.operation, db=store._db, namespace=reader.namespace)
    return graph, port, bundle, evidence, control, state


def _observe_semantic_write_owner_authority_v3(reader, scope, issued):
    from ..runtime.first_ingress_v2 import trusted_upper
    from time import monotonic
    graph, port, bundle, evidence, control, state = _require_semantic_write_owner_source_v3(reader, scope, issued)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable('Semantic WRITE Owner observation must precede SQL')
    if port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('Semantic original WRITE permit changed')
    current, permit = port.get_current_background_owner_authority_for_fence_v1(
        namespace=scope.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
    if (type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit
            or current.guard.namespace != scope.namespace
            or current.guard.authority_id != scope.pinned_anchor.authority_id
            or current.guard.minimum_revocation_revision != 0
            or current.guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('Semantic WRITE has no current paired Owner authority')
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    from ..runtime.habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    if type(issued) is _IssuedHabitMaintenanceV1:
        from ..runtime.habit_control_issuance_v1 import habit_control_deadline_v1
        deadline = habit_control_deadline_v1(issued, reader)
    else:
        deadline = min(reader.operation.deadline_utc, evidence.valid_until_utc)
    if (now >= deadline
            or monotonic() >= reader.initial_monotonic_deadline
            or port.validate_fence(scope) != scope.permit):
        raise AuthorityUnavailable('Semantic WRITE Owner exceeded its original lifetime or permit')
    return current


def _require_semantic_write_owner_caller_v3(proof):
    reader, scope, issued, original_state = _SEMANTIC_WRITE_OWNER_CALLERS_V3[proof]
    graph, port, bundle, evidence, control, state = _require_semantic_write_owner_source_v3(reader, scope, issued)
    if (state is not original_state or proof.kind != _semantic_write_owner_kind_v3(issued)
            or proof.request is not reader or proof.graph is not graph or proof.scope is not scope
            or proof.service is not reader.runtime or proof.port is not port or proof.bundle is not bundle
            or proof.control is not control or proof.retained_operation is not reader.operation
            or proof.principal is not None or proof.authority != reader.authority
            or proof.selection_digest != reader.operation.selection_digest
            or proof.original_permit != scope.permit or proof.permission_anchor != scope.pinned_anchor
            or proof.graph_comparison_anchor != scope.pinned_anchor
            or proof.namespace != scope.namespace or proof.subject != scope.permit.subject
            or proof.deadline_utc != reader.operation.deadline_utc
            or proof.installation_id != bundle.installation_policy.installation_id
            or proof.holder != bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Semantic WRITE Owner proof crossed its private current issuance')


def _semantic_write_owner_binding_from_facts_v3(proof, facts):
    from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
    from ..graph_types import owner_grant_key
    reader, scope, issued, state = _SEMANTIC_WRITE_OWNER_CALLERS_V3[proof]
    facts.require_for_v3(proof)
    authority, principal = _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[proof]
    metadata, current = facts.metadata, proof.current_owner_authority
    if (metadata.requirements.namespace != scope.namespace or metadata.graph_revision != scope.graph_revision
            or facts.graph_epoch != scope.graph_epoch
            or metadata.requirements.authority_namespace != scope.authority_namespace
            or not proof.graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise AuthorityUnavailable('Semantic WRITE Owner EOF crossed its exact current Graph location')
    binding = proof.graph._owner_graph_binding_from_current_metadata_v3(authority, principal,
        metadata=metadata, graph_epoch=facts.graph_epoch, atom=facts.atom, proof_row=facts.proof_row,
        epochs=facts.epochs, target_admission=current.target_admission,
        storage_admission=current.storage_admission, current_guard=current.guard)
    evidence = _require_semantic_write_issuance_v3(issued, proof.graph, scope)
    guard = ProductionOwnerGuardV1(owner_grant_key(*scope.namespace.as_tuple).token,
        binding.grant_revision, binding.grant_digest.removeprefix('sha256:'),
        binding.authorization_head.removeprefix('sha256:'))
    expected = evidence.owner_guard
    if proof.kind=='host_named_joint_write_source':
        state=_require_semantic_write_source_identity_v3(reader,scope,issued)
        expected_rights=state.work.graph_stamp[1:]
    else:expected_rights=(evidence.access_epoch,evidence.delete_epoch)
    if ((guard.grant_ref, guard.grant_revision, guard.grant_digest.removeprefix('sha256:'),
            guard.owner_head_digest.removeprefix('sha256:')) !=
            (expected.grant_ref, expected.grant_revision, expected.grant_digest.removeprefix('sha256:'),
                expected.owner_head_digest.removeprefix('sha256:'))
            or (binding.access_epoch, binding.delete_epoch) != expected_rights
            or current.guard.authorization_head != binding.authorization_head
            or current.guard.authorization_revision != binding.authorization_revision
            or current.guard.minimum_revocation_epoch != binding.revocation_epoch):
        raise AuthorityUnavailable('Semantic WRITE Owner EOF differs from actual Core current guard/rights')
    return binding


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class _HostSemanticWriteOwnerReadEntryV3:
    issuer: InitVar[object]
    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Semantic WRITE Owner entry requires its private producer')
    def require_for_v3(self, reader):
        proof, work, facts = _SEMANTIC_WRITE_OWNER_ENTRIES_V3[self]
        if proof.request is not reader:
            raise AuthorityUnavailable('Semantic WRITE Owner entry crossed its actual Source reader')
        require_owner_location_caller_proof_v3(proof, phase='before')
        return _semantic_write_owner_binding_from_facts_v3(proof, facts)
    def require_permission_v3(self, reader):
        proof, work, facts = _SEMANTIC_WRITE_OWNER_ENTRIES_V3[self]
        if proof.request is not reader:
            raise AuthorityUnavailable('Semantic WRITE Owner permission crossed its Source reader')
        _require_owner_permission_outside_graph_v3(proof)
        with reader.store._lock:
            return self.require_for_v3(reader)
    @property
    def owner_acl_authority(self):
        return _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[_SEMANTIC_WRITE_OWNER_ENTRIES_V3[self][0]][0]
    @property
    def owner_principal(self):
        return _SEMANTIC_BACKGROUND_OWNER_ACLS_V3[_SEMANTIC_WRITE_OWNER_ENTRIES_V3[self][0]][1]
    @property
    def current_owner_guard(self):
        return _SEMANTIC_WRITE_OWNER_ENTRIES_V3[self][0].current_owner_authority.guard
    def release_v3(self):
        state = _SEMANTIC_WRITE_OWNER_ENTRIES_V3.pop(self, None)
        if state is not None:
            proof, work, facts = state
            try:
                work.close_v3()
            finally:
                _SEMANTIC_WRITE_OWNER_CALLERS_V3.pop(proof, None)
                _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.pop(proof, None)
                proof.release_v3()


def _prepare_current_host_semantic_write_owner_read_entry_v3(reader, scope, issued):
    graph, port, bundle, evidence, control, state = _require_semantic_write_owner_source_v3(reader, scope, issued)
    current = _observe_semantic_write_owner_authority_v3(reader, scope, issued)
    policy = bundle.installation_policy
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind=_semantic_write_owner_kind_v3(issued), graph=graph, service=reader.runtime, owner_service=None, controller=None,
        port=port, bundle=bundle, scope=scope, authority=reader.authority, principal=None,
        current_owner_authority=current, current_owner_head=None, retained_operation=reader.operation,
        control=control, selection_digest=reader.operation.selection_digest, namespace=scope.namespace,
        installation_id=policy.installation_id, holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor, graph_comparison_anchor=scope.pinned_anchor,
        credential=None, subject=scope.permit.subject, original_permit=scope.permit,
        request=reader, deadline_utc=reader.operation.deadline_utc, thread=get_ident())
    _SEMANTIC_WRITE_OWNER_CALLERS_V3[proof] = (reader, scope, issued, state)
    work = None
    try:
        work = prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts = work.result.require_for_v3(proof)
        _pin_semantic_background_owner_acl_v3(proof, facts)
        _semantic_write_owner_binding_from_facts_v3(proof, facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _HostSemanticWriteOwnerReadEntryV3(_OWNER_CALLER_ISSUER_V3)
        _SEMANTIC_WRITE_OWNER_ENTRIES_V3[entry] = (proof, work, facts)
        return entry
    except BaseException as exc:
        if work is not None:
            work.cancel_v3(exc)
        _SEMANTIC_WRITE_OWNER_CALLERS_V3.pop(proof, None)
        _SEMANTIC_BACKGROUND_OWNER_ACLS_V3.pop(proof, None)
        proof.release_v3()
        raise


def prepare_current_host_habit_write_owner_read_entry_v3(reader, scope, issued):
    if _semantic_write_owner_kind_v3(issued) != 'host_habit_write_source':
        raise AuthorityUnavailable('Semantic WRITE Owner requires the Habit private current issuer')
    return _prepare_current_host_semantic_write_owner_read_entry_v3(reader, scope, issued)


def prepare_current_host_conditioned_child_owner_write_entry_v3(reader, *, scope, issued):
    if _semantic_write_owner_kind_v3(issued) != 'host_conditioned_write_source':
        raise AuthorityUnavailable('Self child WRITE Owner requires its private Core child issuer')
    return _prepare_current_host_semantic_write_owner_read_entry_v3(reader, scope, issued)

def prepare_current_host_named_joint_owner_write_entry_v3(reader, *, scope, issued):
    if _semantic_write_owner_kind_v3(issued) != 'host_named_joint_write_source':
        raise AuthorityUnavailable('Named Joint WRITE Owner requires its exact private Core issuer')
    return _prepare_current_host_semantic_write_owner_read_entry_v3(reader,scope,issued)


_CONTACT_OWNER_SOURCE_ENTRIES_V3 = WeakKeyDictionary()
_CONTACT_OWNER_SOURCE_KINDS_V3 = frozenset(('host_contact_owner_read','host_contact_owner_write'))


def _require_contact_owner_source_components_v3(state,write=None):
    from ..runtime.contact_host_stage_work_v3 import ContactHostStageReadWorkV3,_HOST_IDENTITIES
    from ..runtime.contact_host_source_v3 import require_contact_host_work_v3
    from ..runtime.contact_owner_command_source_v3 import require_contact_owner_command_source_v3
    from ..host.authority_profile import AdminInstallationBundle
    if (type(state)is not ContactHostStageReadWorkV3 or _HOST_IDENTITIES.get(state)!=
            (state.service,state.graph,state.db,state.selector,state.operation,state.selection_digest)):
        raise AuthorityUnavailable('Contact Owner metadata requires its exact private Host Source Work')
    require_contact_host_work_v3(state)
    command=require_contact_owner_command_source_v3(state.owner_command,state=state)
    service,graph=state.service,state.graph
    bundle=service.bundle;port=service.port;scope=state.scope
    if write is not None:
        from ..runtime.contact_owner_command_source_v3 import require_contact_owner_source_write_birth_v3
        require_contact_owner_source_write_birth_v3(write)
        if write.state is not state or write.command is not command:
            raise AuthorityUnavailable('Contact Owner WRITE metadata changed its original Source command')
        scope=write.scope
    policy=bundle.installation_policy
    if (type(bundle)is not AdminInstallationBundle or graph._GraphCoordinator__contact_model_runtime_v2 is not service
            or service.store is not graph._GraphCoordinator__store or service.store._db is not state.db
            or graph._GraphCoordinator__content_fence_v2 is not port
            or scope.namespace!=state.namespace or state.namespace!=policy.namespace
            or scope.authority_namespace!=policy.authority_namespace
            or scope.generation!=command.authority.activation_generation
            or scope.permit.holder!=policy.administrator_holder
            or port.installation_grant.installation_id!=policy.installation_id
            or state.operation.operation_id!=state.operation_id or state.work.operation is not state.operation
            or state.work.kind!='contact_host_stage_read_v3'
            or state.work.selection_digest!=state.operation.selection_digest
            or state.work.deadline_utc!=state.operation.deadline_utc
            or state.operation.deadline_utc is None
            or (scope.operation!='read' if write is None else scope.operation!='write')
            or (write is None and (scope is not state.fence.scope or state.fence.authority is not command.authority
                or (state.fence.metadata,state.fence.epoch)!=state.graph_stamp))
            or (write is not None and (scope is state.scope or scope.permit is state.scope.permit))):
        raise AuthorityUnavailable('Contact Owner metadata left its actual READ or independent fresh WRITE')
    control=_require_owner_operation_v3(state.operation,db=state.db,namespace=state.namespace)
    token,request=command.owner_session_proof
    if request.principal!=command.owner.principal:
        raise AuthorityUnavailable('Contact Owner original signed session principal changed')
    return command,graph,port,bundle,scope,control,request.principal


def _observe_contact_owner_source_authority_v3(state,write=None):
    from ..runtime.first_ingress_v2 import trusted_upper
    command,graph,port,bundle,scope,control,principal=_require_contact_owner_source_components_v3(state,write)
    if state.db.in_transaction:
        raise AuthorityUnavailable('Contact Owner Source admission must precede Graph SQL')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Contact Owner original permit changed')
    token,request=command.owner_session_proof
    if graph._current_owner_principal(command.authority.actor,state.namespace)!=principal:
        raise AuthorityUnavailable('Contact Owner current actor pairing changed')
    observed=port.get_current_owner_authority_for_fence_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=command.authority.actor,owner_session_token=token,owner_session_request=request)
    if (type(observed)is not tuple or len(observed)!=2 or type(observed[0])is not D12CurrentOwnerAuthorityV1
            or observed[1]!=scope.permit):
        raise AuthorityUnavailable('Contact Owner session lacks its actual current Authority observation')
    current=observed[0];guard=current.guard;binding=command.owner
    if (guard.authority_id!=scope.pinned_anchor.authority_id or guard.namespace!=state.namespace
            or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id!=port.installation_grant.installation_id)
            or (write is not None and (guard!=write.guard or write.owner!=binding))):
        raise AuthorityUnavailable('Contact Owner original guard/head/revocation/installation changed')
    if trusted_upper(port.read_ingress_clock(bundle.ingress_clock))>=state.operation.deadline_utc:
        raise AuthorityUnavailable('Contact Owner Source exceeded its original deadline')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Contact Owner permit changed after its session observation')
    return current


def _require_contact_owner_source_caller_v3(proof):
    state,write=proof.request
    command,graph,port,bundle,scope,control,principal=_require_contact_owner_source_components_v3(state,write)
    kind='host_contact_owner_read' if write is None else 'host_contact_owner_write'
    if (proof.kind!=kind or proof.graph is not graph or proof.service is not state.service
            or proof.port is not port or proof.bundle is not bundle or proof.scope is not scope
            or proof.authority is not command.authority or proof.principal!=principal
            or proof.control is not control or proof.retained_operation is not state.operation
            or proof.original_permit!=scope.permit or proof.permission_anchor!=scope.pinned_anchor
            or proof.graph_comparison_anchor!=scope.pinned_anchor or proof.namespace!=state.namespace
            or proof.selection_digest!=state.operation.selection_digest
            or proof.installation_id!=bundle.installation_policy.installation_id
            or proof.holder!=bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Contact Owner proof crossed its actual private READ/fresh WRITE')


def _contact_owner_source_binding_from_facts_v3(proof,facts):
    state,write=proof.request
    command,graph,port,bundle,scope,control,principal=_require_contact_owner_source_components_v3(state,write)
    facts.require_for_v3(proof)
    metadata=facts.metadata;req=metadata.requirements
    if (req.namespace!=state.namespace or metadata.graph_revision!=scope.graph_revision
            or facts.graph_epoch!=scope.graph_epoch or req.authority_namespace!=scope.authority_namespace
            or not graph._anchor_matches(req,scope.pinned_anchor)):
        raise AuthorityUnavailable('Contact Owner fixed EOF lost its original Graph scope/location')
    current=proof.current_owner_authority;guard=current.guard
    binding=graph._owner_graph_binding_from_current_metadata_v3(command.authority,principal,
        metadata=metadata,graph_epoch=facts.graph_epoch,atom=facts.atom,proof_row=facts.proof_row,
        epochs=facts.epochs,target_admission=current.target_admission,
        storage_admission=current.storage_admission,current_guard=guard)
    if (binding!=command.owner or (write is not None and (binding!=write.owner or guard!=write.guard))
            or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('Contact Owner full fixed EOF differs from its original session/guard')
    return guard,binding


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _ContactOwnerSourceEntryV3:
    issuer: InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Contact Owner entry requires its actual private Source command')
    def require_for_v3(self,state,*,write=None):
        registered=_CONTACT_OWNER_SOURCE_ENTRIES_V3.get(self)
        if registered is None or registered[0].request!=(state,write):
            raise AuthorityUnavailable('Contact Owner entry left its actual original READ/fresh WRITE')
        proof,work,facts=registered
        require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=(facts.metadata,facts.graph_epoch))
        return _contact_owner_source_binding_from_facts_v3(proof,facts)
    def observe_current_v3(self,state,*,write=None):
        registered=_CONTACT_OWNER_SOURCE_ENTRIES_V3.get(self)
        if registered is None or registered[0].request!=(state,write):
            raise AuthorityUnavailable('Contact Owner observation left its actual original Source command')
        _require_owner_permission_outside_graph_v3(registered[0])
        return self.require_for_v3(state,write=write)
    def release_v3(self):
        registered=_CONTACT_OWNER_SOURCE_ENTRIES_V3.pop(self,None)
        if registered is not None:
            proof,work,_=registered
            try:work.close_v3()
            finally:proof.release_v3()


def _prepare_contact_owner_source_entry_v3(state,write):
    command,graph,port,bundle,scope,control,principal=_require_contact_owner_source_components_v3(state,write)
    current=_observe_contact_owner_source_authority_v3(state,write)
    policy=bundle.installation_policy
    proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='host_contact_owner_read' if write is None else 'host_contact_owner_write',
        graph=graph,service=state.service,owner_service=None,controller=None,port=port,bundle=bundle,
        scope=scope,authority=command.authority,principal=principal,current_owner_authority=current,
        current_owner_head=None,retained_operation=state.operation,control=control,
        selection_digest=state.operation.selection_digest,namespace=state.namespace,
        installation_id=policy.installation_id,holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor,graph_comparison_anchor=scope.pinned_anchor,credential=None,
        subject=scope.permit.subject,original_permit=scope.permit,request=(state,write),
        deadline_utc=state.operation.deadline_utc,thread=get_ident())
    work=None
    try:
        work=prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts=work.result.require_for_v3(proof)
        _contact_owner_source_binding_from_facts_v3(proof,facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry=_ContactOwnerSourceEntryV3(_OWNER_CALLER_ISSUER_V3)
        _CONTACT_OWNER_SOURCE_ENTRIES_V3[entry]=(proof,work,facts)
        return entry
    except BaseException as exc:
        if work is not None:work.cancel_v3(exc)
        proof.release_v3()
        raise


def prepare_current_contact_owner_source_read_entry_v3(state):
    return _prepare_contact_owner_source_entry_v3(state,None)


def prepare_current_contact_owner_source_write_entry_v3(write):
    from ..runtime.contact_owner_command_source_v3 import require_contact_owner_source_write_birth_v3
    require_contact_owner_source_write_birth_v3(write)
    return _prepare_contact_owner_source_entry_v3(write.state,write)

def create_artifact_no_dispatch_owner_caller_proof_v3(invocation):
    from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import (
        ActualArtifactNoDispatchMetadataInvocationV1, require_artifact_no_dispatch_metadata_invocation_v1)
    if type(invocation) is not ActualArtifactNoDispatchMetadataInvocationV1:
        raise AuthorityUnavailable('Artifact financial Owner facts require their actual private invocation')
    require_artifact_no_dispatch_metadata_invocation_v1(invocation,phase='before')
    _require_owner_operation_v3(invocation.retained_operation,db=invocation.actual_db,
        namespace=invocation.namespace,control=invocation.control)
    if (invocation.retained_operation.selection_digest!=invocation.selection_digest
            or invocation.retained_operation.deadline_utc!=invocation.registered_deadline_utc
            or invocation.current_owner_head.guard!=invocation.current_owner_guard
            or invocation.current_owner_head.issue_operation.principal!=invocation.principal):
        raise AuthorityUnavailable('Artifact financial Owner metadata left its original current grant')
    return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='artifact_no_dispatch_metadata',graph=invocation.graph,service=invocation.runtime,
        owner_service=None,controller=None,port=invocation.port,bundle=invocation.bundle,
        scope=None,authority=None,principal=invocation.principal,current_owner_authority=None,
        current_owner_head=invocation.current_owner_head,retained_operation=invocation.retained_operation,
        control=invocation.control,selection_digest=invocation.selection_digest,namespace=invocation.namespace,
        installation_id=invocation.installation_id,holder=invocation.holder,
        permission_anchor=invocation.current_anchor,graph_comparison_anchor=invocation.current_anchor,
        credential=None,subject=invocation.grant.subject,original_permit=invocation.grant,
        request=invocation,deadline_utc=invocation.registered_deadline_utc,thread=get_ident())



def _host_method_owner_read_provisional_v3(reader):
    from ..runtime.current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    from ..runtime.current_beta1_source_read_v3 import beta1_source_operation_v3
    return (type(reader)is _MethodLearningReadV3 and reader in _READERS
        and (beta1_source_operation_v3(reader.operation_kind)or reader.operation_kind in (_METHOD_OWNER_READ_OPERATIONS_V3 | _NUMERIC_METHOD_OWNER_READ_OPERATIONS_V3 | _NUMERIC_HOST_READ_OPERATIONS_V3 | _OWNER_JOB_CANCEL_READ_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OWNER_OPERATIONS_V3))
        and reader.owner_guard is None and reader.fence.observed_guard is None
        and reader.fence.observed_owner is None and reader.fence.owner_binding is None
        and reader.fence.owner_principal is None and reader.fence.fence_observer is None
        and reader.general_owner_entry is None and not reader.graph_eof and not reader.inventory_sealed
        and not reader.inputs_sealed and not reader.read_finished
        and reader.work is not None and reader.work.state is reader
        and reader.work.operation is reader.operation and reader.work.coordinator is reader.graph
        and reader.session_proof is not None and reader.fence.owner_session_proof==reader.session_proof)


_OWNER_LEASE_READ_ENTRIES_V3 = WeakKeyDictionary()


def _require_host_owner_lease_reader_v3(reader):
    from ..runtime.owner_lease_metadata_read_v3 import require_current_owner_lease_reader_v3
    require_current_owner_lease_reader_v3(reader)
    graph=reader.graph;port=graph._GraphCoordinator__content_fence_v2
    scope=reader.read_scope;bundle=reader.bundle
    control=_require_owner_operation_v3(reader.operation,db=reader.db,namespace=reader.namespace)
    return graph,port,bundle,scope,control,reader.owner_principal


def _observe_host_owner_lease_authority_v3(reader):
    from ..runtime.first_ingress_v2 import trusted_upper
    graph,port,bundle,scope,control,principal=_require_host_owner_lease_reader_v3(reader)
    if reader.db.in_transaction:
        raise AuthorityUnavailable('Owner lease/view current admission must precede Graph SQL')
    from ..host.authority_profile import require_current_owner_metadata_installation_v3
    require_current_owner_metadata_installation_v3(graph,expected_bundle=bundle)
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Owner lease/view original READ permit changed')
    token,request=reader.owner_session_proof
    if graph._current_owner_principal(reader.authority.actor,reader.namespace)!=principal:
        raise AuthorityUnavailable('Owner lease/view current pairing changed')
    observed=port.get_current_owner_authority_for_fence_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=reader.authority.actor,owner_session_token=token,owner_session_request=request)
    if (type(observed)is not tuple or len(observed)!=2 or type(observed[0])is not D12CurrentOwnerAuthorityV1
            or observed[1]!=scope.permit):
        raise AuthorityUnavailable('Owner lease/view lacks its actual current signed-session Authority')
    current=observed[0];guard=current.guard
    if (guard.authority_id!=scope.pinned_anchor.authority_id or guard.namespace!=reader.namespace
            or guard.minimum_revocation_revision!=0 or guard.pending_revoke_operation_id is not None
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id!=port.installation_grant.installation_id)):
        raise AuthorityUnavailable('Owner lease/view current guard/revocation/installation changed')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if reader.operation.deadline_utc is not None and now>=reader.operation.deadline_utc:
        raise AuthorityUnavailable('Owner lease/view exceeded its original operation deadline')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Owner lease/view original READ changed after session observation')
    return current


def _require_host_owner_lease_caller_v3(proof):
    reader=proof.request
    graph,port,bundle,scope,control,principal=_require_host_owner_lease_reader_v3(reader)
    if (proof.kind!='host_owner_lease_read' or proof.graph is not graph or proof.service is not graph
            or proof.port is not port or proof.bundle is not bundle or proof.scope is not scope
            or proof.authority is not reader.authority or proof.principal!=principal
            or proof.retained_operation is not reader.operation or proof.control is not control
            or proof.selection_digest!=reader.operation.selection_digest
            or proof.original_permit!=scope.permit or proof.permission_anchor!=scope.pinned_anchor
            or proof.graph_comparison_anchor!=scope.pinned_anchor or proof.namespace!=reader.namespace
            or proof.installation_id!=bundle.installation_policy.installation_id
            or proof.holder!=bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Owner lease/view proof crossed another private original READ')


def _host_owner_lease_binding_from_facts_v3(proof,facts):
    reader=proof.request;scope=proof.scope;current=proof.current_owner_authority;guard=current.guard
    facts.require_for_v3(proof)
    metadata=facts.metadata;req=metadata.requirements
    if (req.namespace!=reader.namespace or metadata.graph_revision!=scope.graph_revision
            or facts.graph_epoch!=scope.graph_epoch or req.authority_namespace!=scope.authority_namespace
            or not proof.graph._anchor_matches(req,scope.pinned_anchor)):
        raise AuthorityUnavailable('Owner lease/view fixed EOF lost its original scope/location')
    binding=proof.graph._owner_graph_binding_from_current_metadata_v3(reader.authority,proof.principal,
        metadata=metadata,graph_epoch=facts.graph_epoch,atom=facts.atom,proof_row=facts.proof_row,
        epochs=facts.epochs,target_admission=current.target_admission,
        storage_admission=current.storage_admission,current_guard=guard)
    if (binding.principal!=reader.owner_principal or binding.actor!=reader.authority.actor
            or binding.namespace!=reader.namespace or binding.purpose!=reader.authority.purpose
            or reader.authority.audience!=(binding.audience,)
            or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('Owner lease/view complete binding differs from original session/guard')
    return binding


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _HostOwnerLeaseReadEntryV3:
    issuer: InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Owner lease/view entry requires the actual Graph metadata producer')
    def require_for_v3(self,reader):
        registered=_OWNER_LEASE_READ_ENTRIES_V3.get(self)
        if registered is None or registered[0].request is not reader:
            raise AuthorityUnavailable('Owner lease/view entry left its private original reader')
        proof,work,facts=registered
        require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=reader.graph_stamp)
        return _host_owner_lease_binding_from_facts_v3(proof,facts)
    def require_permission_v3(self,reader):
        registered=_OWNER_LEASE_READ_ENTRIES_V3.get(self)
        if registered is None or registered[0].request is not reader:
            raise AuthorityUnavailable('Owner lease/view observation left its private original reader')
        _require_owner_permission_outside_graph_v3(registered[0])
        self.require_for_v3(reader)
        return registered[0].current_owner_authority.guard
    def release_v3(self):
        registered=_OWNER_LEASE_READ_ENTRIES_V3.pop(self,None)
        if registered is not None:
            proof,work,_=registered
            try:work.close_v3()
            finally:proof.release_v3()


def prepare_current_host_owner_lease_read_entry_v3(reader):
    graph,port,bundle,scope,control,principal=_require_host_owner_lease_reader_v3(reader)
    current=_observe_host_owner_lease_authority_v3(reader);policy=bundle.installation_policy
    proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='host_owner_lease_read',graph=graph,service=graph,owner_service=None,controller=None,
        port=port,bundle=bundle,scope=scope,authority=reader.authority,principal=principal,
        current_owner_authority=current,current_owner_head=None,retained_operation=reader.operation,
        control=control,selection_digest=reader.operation.selection_digest,namespace=reader.namespace,
        installation_id=policy.installation_id,holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor,graph_comparison_anchor=scope.pinned_anchor,credential=None,
        subject=scope.permit.subject,original_permit=scope.permit,request=reader,
        deadline_utc=reader.operation.deadline_utc,thread=get_ident())
    work=None
    try:
        work=prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts=work.result.require_for_v3(proof)
        _host_owner_lease_binding_from_facts_v3(proof,facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry=_HostOwnerLeaseReadEntryV3(_OWNER_CALLER_ISSUER_V3)
        _OWNER_LEASE_READ_ENTRIES_V3[entry]=(proof,work,facts)
        return entry
    except BaseException as exc:
        if work is not None:work.cancel_v3(exc)
        proof.release_v3()
        raise


_BETA1_FIXTURE_OWNER_ENTRIES_V3 = WeakKeyDictionary()


def _require_host_beta1_fixture_owner_reader_v3(reader):
    from ..graph_worker import _require_beta1_engineering_metadata_provider_v3
    from ..host.authority_profile import AdminInstallationBundle
    provider=_require_beta1_engineering_metadata_provider_v3(reader.graph)
    provider.require_current_beta1_fixture_evidence_reader_v3(reader)
    graph=reader.graph;port=graph._GraphCoordinator__content_fence_v2;bundle=reader.bundle
    from ..host.authority_profile import current_owner_metadata_installation_v3
    actual_bundle,package_root,verified=current_owner_metadata_installation_v3(graph,expected_bundle=bundle)
    namespace=reader.authority.namespace;scope=reader.read_scope;binding=reader.expected_owner_binding
    record=graph._GraphCoordinator__leases.get(reader.lease)
    if record is None:
        raise AuthorityUnavailable('Beta1 evidence lacks its actual completed Owner lease')
    graph._authorize(reader.lease,reader.authority,record[4],owner_read=True)
    if (type(bundle)is not AdminInstallationBundle or actual_bundle is not bundle
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or reader.store is not graph._GraphCoordinator__store or reader.db is not reader.store._db
            or reader.package_root!=package_root or reader.manifest_digest!=bundle.installation_policy.manifest_digest
            or graph._GraphCoordinator__owner_leases.get(reader.lease)is not binding
            or graph._GraphCoordinator__owner_session_proofs.get(reader.lease)is not reader.owner_session_proof
            or reader.owner_principal!=binding.principal or binding.actor!=reader.authority.actor
            or scope.operation!='read' or scope.namespace!=namespace or namespace!=bundle.installation_policy.namespace
            or scope.authority_namespace!=bundle.installation_policy.authority_namespace
            or scope.permit.holder!=bundle.installation_policy.administrator_holder
            or port.installation_grant.installation_id!=bundle.installation_policy.installation_id
            or reader.fence.authority is not reader.authority or reader.read_scope is not reader.fence.scope
            or reader.graph_stamp!=(reader.fence.metadata,reader.fence.epoch)
            or reader.fence.owner_binding is not None or reader.fence.owner_principal is not None
            or reader.fence.fence_observer is not None
            or reader.operation.deadline_utc is None
            or reader.operation.deadline_utc>reader.original_deadline_utc
            or reader.original_deadline_utc>bundle.installation_policy.root_grant.valid_until_utc):
        raise AuthorityUnavailable('Beta1 evidence Owner metadata left its actual selected Reader/install/lease')
    control=_require_owner_operation_v3(reader.operation,db=reader.db,namespace=namespace)
    return graph,port,bundle,scope,control,reader.owner_principal


def _observe_host_beta1_fixture_owner_authority_v3(reader):
    from ..runtime.first_ingress_v2 import trusted_upper
    from ..host.v2_fence_port import VerifiedIngressClockV2
    graph,port,bundle,scope,control,principal=_require_host_beta1_fixture_owner_reader_v3(reader)
    if reader.db.in_transaction:
        raise AuthorityUnavailable('Beta1 evidence Owner admission must precede Graph SQL')
    from ..host.authority_profile import require_current_owner_metadata_installation_v3
    require_current_owner_metadata_installation_v3(graph,expected_bundle=bundle)
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Beta1 evidence original READ permit changed')
    token,request=reader.owner_session_proof
    if request.principal!=principal or graph._current_owner_principal(reader.authority.actor,reader.authority.namespace)!=principal:
        raise AuthorityUnavailable('Beta1 evidence current Owner pairing differs from its original session')
    observed=port.get_current_owner_authority_for_fence_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=reader.authority.actor,owner_session_token=token,owner_session_request=request)
    if (type(observed)is not tuple or len(observed)!=2 or type(observed[0])is not D12CurrentOwnerAuthorityV1
            or observed[1]!=scope.permit):
        raise AuthorityUnavailable('Beta1 evidence lacks its actual current signed-session Authority')
    current=observed[0];guard=current.guard;binding=reader.expected_owner_binding
    if (guard.authority_id!=scope.pinned_anchor.authority_id or guard.namespace!=reader.authority.namespace
            or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id!=port.installation_grant.installation_id)):
        raise AuthorityUnavailable('Beta1 evidence original Owner guard/head/revocation/location changed')
    clock=port.read_ingress_clock(bundle.ingress_clock);initial=reader.initial_clock
    if (type(clock)is not VerifiedIngressClockV2 or type(initial)is not VerifiedIngressClockV2
            or clock.sample.authority_id!=initial.sample.authority_id
            or clock.sample.installation_id!=initial.sample.installation_id
            or clock.sample.source_id!=initial.sample.source_id or clock.sample.epoch!=initial.sample.epoch
            or clock.sample.monotonic_seconds<initial.sample.monotonic_seconds
            or clock.monotonic_before_seconds<initial.monotonic_after_seconds
            or clock.sample.source_id!=bundle.ingress_clock.source_id
            or clock.sample.utc_error_seconds>bundle.ingress_clock.max_utc_error_seconds
            or trusted_upper(clock)>=reader.operation.deadline_utc):
        raise AuthorityUnavailable('Beta1 evidence actual clock/original deadline changed')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Beta1 evidence original READ changed after session observation')
    return current


def _require_host_beta1_fixture_owner_caller_v3(proof):
    reader=proof.request
    graph,port,bundle,scope,control,principal=_require_host_beta1_fixture_owner_reader_v3(reader)
    if (proof.kind!='host_beta1_fixture_evidence_read' or proof.graph is not graph
            or proof.service is not reader.runtime or proof.port is not port or proof.bundle is not bundle
            or proof.scope is not scope or proof.authority is not reader.authority or proof.principal!=principal
            or proof.retained_operation is not reader.operation or proof.control is not control
            or proof.selection_digest!=reader.operation.selection_digest or proof.original_permit!=scope.permit
            or proof.permission_anchor!=scope.pinned_anchor or proof.graph_comparison_anchor!=scope.pinned_anchor
            or proof.namespace!=reader.authority.namespace
            or proof.installation_id!=bundle.installation_policy.installation_id
            or proof.holder!=bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Beta1 evidence Owner proof crossed another private Reader/operation')


def _host_beta1_fixture_owner_binding_from_facts_v3(proof,facts):
    reader=proof.request;scope=proof.scope;current=proof.current_owner_authority;guard=current.guard
    facts.require_for_v3(proof)
    metadata=facts.metadata;req=metadata.requirements
    if (req.namespace!=reader.authority.namespace or metadata.graph_revision!=scope.graph_revision
            or facts.graph_epoch!=scope.graph_epoch or req.authority_namespace!=scope.authority_namespace
            or not proof.graph._anchor_matches(req,scope.pinned_anchor)):
        raise AuthorityUnavailable('Beta1 evidence fixed Owner EOF lost its original scope/location')
    binding=proof.graph._owner_graph_binding_from_current_metadata_v3(reader.authority,proof.principal,
        metadata=metadata,graph_epoch=facts.graph_epoch,atom=facts.atom,proof_row=facts.proof_row,
        epochs=facts.epochs,target_admission=current.target_admission,
        storage_admission=current.storage_admission,current_guard=guard)
    if (binding!=reader.expected_owner_binding or guard.authorization_revision!=binding.authorization_revision
            or guard.authorization_head!=binding.authorization_head or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=binding.revocation_epoch or guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('Beta1 evidence full Owner binding differs from its actual lease/guard')
    return binding


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _HostBeta1FixtureOwnerEntryV3:
    issuer: InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Beta1 evidence Owner entry requires its actual private Reader')
    def require_for_v3(self,reader):
        registered=_BETA1_FIXTURE_OWNER_ENTRIES_V3.get(self)
        if registered is None or registered[0].request is not reader:
            raise AuthorityUnavailable('Beta1 evidence Owner entry left its original Reader')
        proof,work,facts=registered
        require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=reader.graph_stamp)
        return _host_beta1_fixture_owner_binding_from_facts_v3(proof,facts)
    def require_permission_v3(self,reader):
        registered=_BETA1_FIXTURE_OWNER_ENTRIES_V3.get(self)
        if registered is None or registered[0].request is not reader:
            raise AuthorityUnavailable('Beta1 evidence Owner observation left its original Reader')
        _require_owner_permission_outside_graph_v3(registered[0])
        return self.require_for_v3(reader)
    def release_v3(self):
        registered=_BETA1_FIXTURE_OWNER_ENTRIES_V3.pop(self,None)
        if registered is not None:
            proof,work,_=registered
            try:work.close_v3()
            finally:proof.release_v3()


def prepare_current_host_beta1_fixture_evidence_owner_entry_v3(reader):
    graph,port,bundle,scope,control,principal=_require_host_beta1_fixture_owner_reader_v3(reader)
    current=_observe_host_beta1_fixture_owner_authority_v3(reader);policy=bundle.installation_policy
    proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='host_beta1_fixture_evidence_read',graph=graph,service=reader.runtime,owner_service=None,controller=None,
        port=port,bundle=bundle,scope=scope,authority=reader.authority,principal=principal,
        current_owner_authority=current,current_owner_head=None,retained_operation=reader.operation,
        control=control,selection_digest=reader.operation.selection_digest,namespace=reader.authority.namespace,
        installation_id=policy.installation_id,holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor,graph_comparison_anchor=scope.pinned_anchor,credential=None,
        subject=scope.permit.subject,original_permit=scope.permit,request=reader,
        deadline_utc=reader.operation.deadline_utc,thread=get_ident())
    work=None
    try:
        work=prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts=work.result.require_for_v3(proof)
        _host_beta1_fixture_owner_binding_from_facts_v3(proof,facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry=_HostBeta1FixtureOwnerEntryV3(_OWNER_CALLER_ISSUER_V3)
        _BETA1_FIXTURE_OWNER_ENTRIES_V3[entry]=(proof,work,facts)
        return entry
    except BaseException as exc:
        if work is not None:work.cancel_v3(exc)
        proof.release_v3()
        raise


def create_goal_projection_owner_caller_proof_v3(invocation):
    from .goal_projection_metadata_invocation_v1 import (
        GoalProjectionMetadataInvocationV1,require_goal_projection_metadata_invocation_v1,
        require_goal_projection_committed_bridge_v1)
    if type(invocation) is not GoalProjectionMetadataInvocationV1:
        raise AuthorityUnavailable('Goal projection Owner facts require their actual private WRITE invocation')
    require_goal_projection_metadata_invocation_v1(invocation,phase='before')
    require_goal_projection_committed_bridge_v1(invocation)
    _require_owner_operation_v3(invocation.retained_operation,db=invocation.actual_db,
        namespace=invocation.namespace,control=invocation.control)
    if (invocation.retained_operation.selection_digest!=invocation.selection_digest
            or invocation.retained_operation.deadline_utc!=invocation.registered_deadline_utc
            or invocation.current_owner_head.guard!=invocation.current_owner_guard
            or invocation.current_owner_head.issue_operation.principal!=invocation.principal
            or invocation.scope is not invocation.original_permit
            or invocation.scope.operation!={'projection_write':'write','projection_lookup':'read'}.get(invocation.scope_kind)
            or invocation.scope.operation_id!=invocation.metadata_operation_id
            or invocation.retained_operation.operation_id!=invocation.metadata_operation_id):
        raise AuthorityUnavailable('Goal projection Owner metadata left its actual current WRITE admission')
    return OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        kind='goal_projection_metadata',graph=None,service=invocation.service,owner_service=invocation.owner_service,
        controller=None,port=None,bundle=invocation.bundle,scope=invocation.original_permit,authority=None,
        principal=invocation.principal,current_owner_authority=None,current_owner_head=invocation.current_owner_head,
        retained_operation=invocation.retained_operation,control=invocation.control,selection_digest=invocation.selection_digest,
        namespace=invocation.namespace,installation_id=invocation.installation_id,holder=invocation.holder,
        permission_anchor=invocation.current_anchor,graph_comparison_anchor=invocation.current_anchor,
        credential=invocation.credential,subject=invocation.subject,original_permit=invocation.original_permit,
        request=invocation,deadline_utc=invocation.registered_deadline_utc,thread=get_ident())


_CONTACT_DISPATCH_OWNER_KINDS_V1 = frozenset(('host_contact_dispatch_identity_read', 'host_contact_dispatch_text_read'))
_CONTACT_DISPATCH_OWNER_ENTRIES_V1 = WeakKeyDictionary()


def _require_contact_dispatch_owner_reader_v1(state, kind):
    from ..runtime.contact_dispatch_host_read_v1 import (
        require_contact_dispatch_identity_work_v3, require_contact_dispatch_text_work_v1)
    from ..host.authority_profile import AdminInstallationBundle, current_owner_metadata_installation_v3
    if kind == 'host_contact_dispatch_identity_read':
        require_contact_dispatch_identity_work_v3(state)
    elif kind == 'host_contact_dispatch_text_read':
        require_contact_dispatch_text_work_v1(state)
    else:
        raise AuthorityUnavailable('Contact dispatch Owner caller has no registered recipe')
    graph, service, scope = state.graph, state.service, state.read_scope
    port = graph._GraphCoordinator__content_fence_v2
    bundle, _, _ = current_owner_metadata_installation_v3(graph, expected_bundle=service.bundle)
    policy = bundle.installation_policy
    original = state.expected_owner_binding
    session = state.owner_session_proof
    graph._authorize(state.lease, state.authority, frozenset({'d08','d09','d10','d11'}), owner_read=True)
    if (type(bundle) is not AdminInstallationBundle or bundle is not service.bundle
            or graph._GraphCoordinator__contact_model_runtime_v2 is not service
            or service.graph is not graph or service.store is not state.store or state.db is not state.store._db
            or graph._GraphCoordinator__owner_leases.get(state.lease) is not original
            or graph._GraphCoordinator__owner_session_proofs.get(state.lease) is not session
            or state.authority.actor != original.actor or state.authority.namespace != state.namespace
            or session is None or session[1].principal != original.principal
            or scope.operation != 'read' or scope.namespace != state.namespace or state.namespace != policy.namespace
            or scope.authority_namespace != policy.authority_namespace
            or scope.generation != state.authority.activation_generation
            or scope.permit.holder != policy.administrator_holder
            or scope.permit.subject != port.installation_grant.subject
            or port.installation_grant.installation_id != policy.installation_id
            or state.fence.authority is not state.authority or state.fence.scope is not scope
            or state.fence.owner_session_proof is not session
            or state.fence.owner_binding is not None or state.fence.owner_principal is not None
            or state.graph_stamp != (state.fence.metadata, state.fence.epoch)
            or state.operation.closed or state.work.operation is not state.operation
            or state.operation.selection_digest != state.selection_digest
            or state.work.selection_digest != state.selection_digest
            or state.work.deadline_utc != state.operation.deadline_utc):
        raise AuthorityUnavailable('Contact dispatch Owner caller left its actual lease/session/READ/installation')
    control = _require_owner_operation_v3(state.operation, db=state.db, namespace=state.namespace)
    return graph, port, bundle, scope, control, original.principal


def _observe_contact_dispatch_owner_authority_v1(state, kind):
    from ..runtime.first_ingress_v2 import trusted_upper
    from time import monotonic
    graph, port, bundle, scope, control, principal = _require_contact_dispatch_owner_reader_v1(state, kind)
    if state.db.in_transaction or state.store._lock._is_owned():
        raise AuthorityUnavailable('Contact dispatch Owner observation must precede Graph SQL/lock')
    if port.validate_fence(scope) != scope.permit or graph._current_owner_principal(state.authority.actor,state.namespace) != principal:
        raise AuthorityUnavailable('Contact dispatch current READ/actor pairing changed')
    token, request = state.owner_session_proof
    current, permit = port.get_current_owner_authority_for_fence_v1(
        namespace=state.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit,
        owner_actor_id=state.authority.actor, owner_session_token=token, owner_session_request=request)
    if type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit:
        raise AuthorityUnavailable('Contact dispatch Owner lacks its actual current Authority observation')
    binding, guard = state.expected_owner_binding, current.guard
    if (guard.authorization_revision != binding.authorization_revision
            or guard.authorization_head != binding.authorization_head
            or guard.minimum_revocation_revision != 0 or guard.minimum_revocation_epoch != binding.revocation_epoch
            or guard.pending_revoke_operation_id is not None
            or guard.namespace != state.namespace or guard.authority_id != scope.pinned_anchor.authority_id
            or (current.target_admission is None and current.storage_admission is None
                and guard.installation_id != bundle.installation_policy.installation_id)):
        raise AuthorityUnavailable('Contact dispatch current Owner head/revocation/installation changed')
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if kind == 'host_contact_dispatch_identity_read':
        if state.operation.deadline_utc is not None or state.initial_monotonic_deadline is not None:
            raise AuthorityUnavailable('Contact identity uses the original Owner lease/view READ without an added content TTL')
    else:
        from math import isfinite
        if (type(state.operation.deadline_utc) not in (int,float) or not isfinite(state.operation.deadline_utc)
                or type(state.initial_monotonic_deadline) not in (int,float) or not isfinite(state.initial_monotonic_deadline)):
            raise AuthorityUnavailable('Contact text requires its original finite UTC/monotonic content deadline')
    if (state.operation.deadline_utc is not None and now >= state.operation.deadline_utc
            or state.initial_monotonic_deadline is not None and monotonic() >= state.initial_monotonic_deadline):
        raise AuthorityUnavailable('Contact dispatch Owner EOF exceeded the original READ deadline')
    if port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('Contact dispatch READ changed during current Owner observation')
    return current


def _require_contact_dispatch_owner_caller_v1(proof):
    state = proof.request
    graph,port,bundle,scope,control,principal = _require_contact_dispatch_owner_reader_v1(state, proof.kind)
    if (proof.graph is not graph or proof.service is not state.service or proof.port is not port
            or proof.bundle is not bundle or proof.scope is not scope or proof.principal != principal
            or proof.authority is not state.authority or proof.retained_operation is not state.operation
            or proof.control is not control or proof.namespace != state.namespace
            or proof.original_permit != scope.permit or proof.permission_anchor != scope.pinned_anchor
            or proof.graph_comparison_anchor != scope.pinned_anchor
            or proof.installation_id != bundle.installation_policy.installation_id
            or proof.holder != bundle.installation_policy.administrator_holder):
        raise AuthorityUnavailable('Contact dispatch Owner proof escaped its actual private Work')


def _contact_dispatch_owner_binding_from_facts_v1(proof, facts):
    state, current, scope = proof.request, proof.current_owner_authority, proof.scope
    facts.require_for_v3(proof)
    metadata = facts.metadata
    if (metadata.requirements.namespace != state.namespace or metadata.graph_revision != scope.graph_revision
            or facts.graph_epoch != scope.graph_epoch
            or not state.graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise AuthorityUnavailable('Contact dispatch Owner metadata EOF lost its actual Graph location/stamp')
    binding = state.graph._owner_graph_binding_from_current_metadata_v3(state.authority, proof.principal,
        metadata=metadata, graph_epoch=facts.graph_epoch, atom=facts.atom, proof_row=facts.proof_row,
        epochs=facts.epochs, target_admission=current.target_admission, storage_admission=current.storage_admission,
        current_guard=current.guard)
    if binding != state.expected_owner_binding:
        raise AuthorityUnavailable('Contact dispatch full Owner metadata differs from its actual registered lease')
    return binding


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class _ContactDispatchOwnerEntryV1:
    issuer: InitVar[object]
    def __post_init__(self, issuer):
        if issuer is not _OWNER_CALLER_ISSUER_V3:
            raise AuthorityUnavailable('Contact dispatch Owner entry requires its actual private producer')
    def require_for_v3(self, state):
        saved = _CONTACT_DISPATCH_OWNER_ENTRIES_V1.get(self)
        if saved is None or saved[0].request is not state:
            raise AuthorityUnavailable('Contact dispatch Owner entry left its original Work')
        proof, work, facts = saved
        require_owner_location_caller_proof_v3(proof, phase='before', graph_stamp=state.graph_stamp)
        return _contact_dispatch_owner_binding_from_facts_v1(proof, facts)
    def require_permission_v3(self, state):
        saved = _CONTACT_DISPATCH_OWNER_ENTRIES_V1.get(self)
        if saved is None or saved[0].request is not state:
            raise AuthorityUnavailable('Contact dispatch Owner permission left its original Work')
        proof, work, facts = saved
        _require_owner_permission_outside_graph_v3(proof)
        with state.store._lock:
            require_owner_location_caller_proof_v3(proof, phase='before', graph_stamp=state.graph_stamp)
            _contact_dispatch_owner_binding_from_facts_v1(proof, facts)
        return proof.current_owner_authority.guard
    def release_v3(self):
        saved = _CONTACT_DISPATCH_OWNER_ENTRIES_V1.pop(self, None)
        if saved is not None:
            proof, work, facts = saved
            try: work.close_v3()
            finally: proof.release_v3()


def _prepare_contact_dispatch_owner_entry_v1(state, kind):
    graph,port,bundle,scope,control,principal = _require_contact_dispatch_owner_reader_v1(state, kind)
    current = _observe_contact_dispatch_owner_authority_v1(state, kind)
    policy = bundle.installation_policy
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3, kind=kind, graph=graph, service=state.service,
        owner_service=None, controller=None, port=port, bundle=bundle, scope=scope, authority=state.authority,
        principal=principal, current_owner_authority=current, current_owner_head=None,
        retained_operation=state.operation, control=control, selection_digest=state.selection_digest,
        namespace=state.namespace, installation_id=policy.installation_id, holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor, graph_comparison_anchor=scope.pinned_anchor,
        credential=None, subject=scope.permit.subject, original_permit=scope.permit, request=state,
        deadline_utc=state.operation.deadline_utc, thread=get_ident())
    work = None
    try:
        work = prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof) as meter: progress = work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts = work.result.require_for_v3(proof)
        _contact_dispatch_owner_binding_from_facts_v1(proof, facts)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _ContactDispatchOwnerEntryV1(_OWNER_CALLER_ISSUER_V3)
        _CONTACT_DISPATCH_OWNER_ENTRIES_V1[entry] = (proof, work, facts)
        return entry
    except BaseException as exc:
        if work is not None: work.cancel_v3(exc)
        proof.release_v3()
        raise


def prepare_current_host_contact_dispatch_identity_owner_entry_v3(state):
    return _prepare_contact_dispatch_owner_entry_v1(state, 'host_contact_dispatch_identity_read')


def prepare_current_host_contact_dispatch_text_owner_entry_v3(state):
    return _prepare_contact_dispatch_owner_entry_v1(state, 'host_contact_dispatch_text_read')


_HABIT_OWNER_LOCATION_ENTRIES_V3=WeakKeyDictionary()
@dataclass(frozen=True,slots=True)
class _HabitOwnerLocationReadV3:
    anchor:object
    head:object
    actor:object
    login:object
    metadata:object
    grant:object
    admission:object
class _HabitOwnerLocationRetainedV3:
    def __init__(self,proof,control,grant,actor,login):
        self.proof,self.control,self.grant,self.actor,self.login=proof,control,grant,actor,login
    def _c09_retained_heap_bytes_v3(self):
        return _owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)+_owner_location_payload_heap_v3((self.grant,self.actor,self.login),set())

def _require_habit_owner_caller_v3(proof,graph_stamp=None):
    from .habit_authority_source_read_v3 import require_habit_authority_work_v3
    state=require_habit_authority_work_v3(proof.request);w=state.work;s=state.service;o=s.self_identity._owner_storage
    if(proof.service is not s or proof.owner_service is not o or proof.controller is not w.controller
            or proof.retained_operation is not w.operation or proof.scope is not w.scope
            or proof.original_permit!=w.permit or proof.bundle is not s.installed_bundle
            or proof.control is not o.control or proof.namespace!=w.namespace or proof.installation_id!=o.installation_id
            or proof.current_owner_head.guard!=proof.current_owner_authority.guard):
        raise AuthorityUnavailable('Habit Owner EOF crossed its independent actual Core Work')
    _require_owner_operation_v3(w.operation,db=w.db,namespace=w.namespace,control=o.control)
    if graph_stamp is not None:
        metadata,epoch=graph_stamp
        if(metadata.requirements.namespace!=w.namespace or metadata.graph_revision!=state.current_self.graph_revision
                or epoch.revision!=state.current_self.graph_epoch):
            raise AuthorityUnavailable('Habit current Owner EOF differs from same-permit actual Self Graph stamp')

def prepare_owner_location_for_habit_graph_work_v3(work):
    from .habit_authority_source_read_v3 import require_habit_authority_work_v3
    from ..graph_types import validate_owner_grant_v1
    state=require_habit_authority_work_v3(work);service=state.service
    owner_service=service.self_identity._owner_storage
    if work.db.in_transaction:raise AuthorityUnavailable('Habit Owner observation must precede Graph SQL')
    controller=work.controller.require_installed_v3()
    if(controller.control is not owner_service.control or controller.fences is not owner_service.fences
            or controller.location._graph_db_path!=owner_service.graph_path or work.namespace!=owner_service.namespace_id):
        raise AuthorityUnavailable('Habit actual installed selected Graph/Owner tuple differs')
    previous = _HABIT_OWNER_LOCATION_ENTRIES_V3.get(work)
    if previous is not None:
        if previous[0] is not service or previous[1].owner_service is not owner_service:
            raise AuthorityUnavailable('model Owner location reader changed during its original Work')
        _require_owner_permission_outside_graph_v3(previous[1])
        return previous[4]
    fences = owner_service.fences
    fences.core._require(work.credential, 'owner_guard_read', owner_service.namespace, owner_service.holder)
    work._check_permission_v3()
    with fences._frozen() as (db, deletion, execution, _):
        anchor = fences._current_locked(db, deletion, execution)
        fences.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=anchor)
        if anchor != work.permit.pinned_anchor:
            raise AuthorityUnavailable('model Owner location original permission anchor changed')
        head = owner_service._head_in_tx(db)
        actor, login = owner_service._background_identity_in_tx(db, head)
    _require_owner_operation_v3(work.operation, db=work.db, namespace=work.namespace,
        control=owner_service.control)
    bundle=service.installed_bundle
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        'authority_habit_header', None, work.service, owner_service, controller, None,
        bundle, work.scope, None, head.issue_operation.principal,
        D12CurrentOwnerAuthorityV1(head.guard, None), head, work.operation, owner_service.control,
        work.selection_digest, work.namespace, owner_service.installation_id, owner_service.holder,
        anchor, anchor, work.credential, work.subject, work.permit, work, work.deadline_utc, get_ident())
    graph_work = lineage = None
    try:
        graph_work = prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = graph_work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts = graph_work.result.require_for_v3(proof)
        lineage = prepare_source_owner_location_lineage_v3(proof, facts)
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = lineage.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        admission = resolve_source_owner_storage_admission_from_completed_location_v3(proof, facts)
        raw = facts.atom[1]
        scanner = _OwnerLocationJSONAllocationScanV3(lineage, (), ('model-owner-grant',))
        reserve_owner_location_retained_growth_v3(proof, 4 * len(raw) + _owner_alloc_size_v3(b''))
        try:
            encoded = raw.encode('utf-8')
            scanner._feed(encoded)
            scanner.complete = True
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof, scanner.decode_growth_bound_v3())
        try:
            grant = json.loads(raw)
            validate_owner_grant_v1(grant)
            decoded = _HabitOwnerLocationRetainedV3(proof, owner_service.control, grant, actor, login)
            register_owner_location_retained_state_v3(proof, decoded)
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _HabitOwnerLocationReadV3(anchor, head, actor, login, facts.metadata, grant, admission)
        _HABIT_OWNER_LOCATION_ENTRIES_V3[work] = (service, proof, facts, lineage, entry, decoded)
        return entry
    except BaseException as error:
        if lineage is not None: lineage.cancel_v3(error)
        elif graph_work is not None: graph_work.cancel_v3(error)
        proof.release_v3()
        raise


_NAMED_JOINT_OWNER_LOCATION_ENTRIES_V3=WeakKeyDictionary()
@dataclass(frozen=True,slots=True)
class _NamedJointOwnerLocationReadV3:
    anchor:object
    head:object
    actor:object
    login:object
    metadata:object
    grant:object
    admission:object
class _NamedJointOwnerLocationRetainedV3:
    def __init__(self,proof,control,grant,actor,login):
        self.proof,self.control,self.grant,self.actor,self.login=proof,control,grant,actor,login
    def _c09_retained_heap_bytes_v3(self):
        return _owner_heap_size_v3(self)+_owner_heap_size_v3(self.__dict__)+_owner_location_payload_heap_v3((self.grant,self.actor,self.login),set())

def _require_named_joint_owner_caller_v3(proof,graph_stamp=None):
    from .named_joint_binding_source_read_v3 import require_named_joint_authority_work_v3
    state=require_named_joint_authority_work_v3(proof.request);w=state.work;s=state.service;o=s.self_identity._owner_storage
    if(proof.service is not s or proof.owner_service is not o or proof.controller is not w.controller
            or proof.retained_operation is not w.operation or proof.scope is not w.scope
            or proof.original_permit!=w.permit or proof.bundle is not s.installed_bundle
            or proof.control is not o.control or proof.namespace!=w.namespace or proof.installation_id!=o.installation_id
            or proof.current_owner_head.guard!=proof.current_owner_authority.guard):
        raise AuthorityUnavailable('Named Joint Owner EOF crossed its independent actual Core Work')
    _require_owner_operation_v3(w.operation,db=w.db,namespace=w.namespace,control=o.control)
    if graph_stamp is not None:
        metadata,epoch=graph_stamp
        if(metadata.requirements.namespace!=w.namespace or metadata.graph_revision!=state.current_self.graph_revision
                or epoch.revision!=state.current_self.graph_epoch):
            raise AuthorityUnavailable('Named Joint current Owner EOF differs from same-permit actual Self Graph stamp')

def prepare_owner_location_for_named_joint_graph_work_v3(work):
    from .named_joint_binding_source_read_v3 import require_named_joint_authority_work_v3
    from ..graph_types import validate_owner_grant_v1
    state=require_named_joint_authority_work_v3(work);service=state.service
    owner_service=service.self_identity._owner_storage
    if work.db.in_transaction:raise AuthorityUnavailable('Named Joint Owner observation must precede Graph SQL')
    controller=work.controller.require_installed_v3()
    if(controller.control is not owner_service.control or controller.fences is not owner_service.fences
            or controller.location._graph_db_path!=owner_service.graph_path or work.namespace!=owner_service.namespace_id):
        raise AuthorityUnavailable('Named Joint actual installed selected Graph/Owner tuple differs')
    previous = _NAMED_JOINT_OWNER_LOCATION_ENTRIES_V3.get(work)
    if previous is not None:
        if previous[0] is not service or previous[1].owner_service is not owner_service:
            raise AuthorityUnavailable('model Owner location reader changed during its original Work')
        _require_owner_permission_outside_graph_v3(previous[1])
        return previous[4]
    fences = owner_service.fences
    fences.core._require(work.credential, 'owner_guard_read', owner_service.namespace, owner_service.holder)
    work._check_permission_v3()
    with fences._frozen() as (db, deletion, execution, _):
        anchor = fences._current_locked(db, deletion, execution)
        fences.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=anchor)
        if anchor != work.permit.pinned_anchor:
            raise AuthorityUnavailable('model Owner location original permission anchor changed')
        head = owner_service._head_in_tx(db)
        actor, login = owner_service._background_identity_in_tx(db, head)
    _require_owner_operation_v3(work.operation, db=work.db, namespace=work.namespace,
        control=owner_service.control)
    bundle=service.installed_bundle
    proof = OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,
        'authority_named_joint_header', None, work.service, owner_service, controller, None,
        bundle, work.scope, None, head.issue_operation.principal,
        D12CurrentOwnerAuthorityV1(head.guard, None), head, work.operation, owner_service.control,
        work.selection_digest, work.namespace, owner_service.installation_id, owner_service.holder,
        anchor, anchor, work.credential, work.subject, work.permit, work, work.deadline_utc, get_ident())
    graph_work = lineage = None
    try:
        graph_work = prepare_owner_location_read_work_v3(proof)
        while not graph_work.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = graph_work.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                graph_work.complete_reserved_quantum_v3(proof)
        facts = graph_work.result.require_for_v3(proof)
        lineage = prepare_source_owner_location_lineage_v3(proof, facts)
        while not lineage.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                progress = lineage.advance(meter=meter)
            if type(progress) is dict and progress.get('phase') == 'owner_location_quantum_commit':
                lineage.complete_reserved_quantum_v3(proof)
        admission = resolve_source_owner_storage_admission_from_completed_location_v3(proof, facts)
        raw = facts.atom[1]
        scanner = _OwnerLocationJSONAllocationScanV3(lineage, (), ('model-owner-grant',))
        reserve_owner_location_retained_growth_v3(proof, 4 * len(raw) + _owner_alloc_size_v3(b''))
        try:
            encoded = raw.encode('utf-8')
            scanner._feed(encoded)
            scanner.complete = True
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        reserve_owner_location_retained_growth_v3(proof, scanner.decode_growth_bound_v3())
        try:
            grant = json.loads(raw)
            validate_owner_grant_v1(grant)
            decoded = _NamedJointOwnerLocationRetainedV3(proof, owner_service.control, grant, actor, login)
            register_owner_location_retained_state_v3(proof, decoded)
        finally:
            encoded = None
            finish_owner_location_retained_growth_v3(proof)
        _require_owner_permission_outside_graph_v3(proof)
        entry = _NamedJointOwnerLocationReadV3(anchor, head, actor, login, facts.metadata, grant, admission)
        _NAMED_JOINT_OWNER_LOCATION_ENTRIES_V3[work] = (service, proof, facts, lineage, entry, decoded)
        return entry
    except BaseException as error:
        if lineage is not None: lineage.cancel_v3(error)
        elif graph_work is not None: graph_work.cancel_v3(error)
        proof.release_v3()
        raise


def prepare_current_host_habit_maintenance_write_owner_read_entry_v3(reader, scope, issued):
    if _semantic_write_owner_kind_v3(issued) != 'host_habit_maintenance_write_source':
        raise AuthorityUnavailable('Habit maintenance Owner requires its own actual private current issuer')
    return _prepare_current_host_semantic_write_owner_read_entry_v3(reader, scope, issued)
