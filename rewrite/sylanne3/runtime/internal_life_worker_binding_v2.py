"""Separate Owner authorization and installed TLS execution identities.

These public codecs describe originals; only the installed runtime can issue
the private, short-lived witness. A signed binding is never current authority.
"""
from dataclasses import dataclass, fields
import math

from ..authority_service.contract import identifier
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOwnerGuardV1
from .d06_internal_life_episode_v2 import EPISODE, _sha
from ..graph_types import AtomKey, owner_grant_key


@dataclass(frozen=True, slots=True)
class InternalLifeWorkerBindingV2:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    worker_subject: str
    installation_grant_digest: str
    owner_principal: OwnerPrincipalV1
    owner_actor: str
    owner_lease_digest: str
    owner_guard: ProductionOwnerGuardV1
    target_admission_digest: str
    storage_admission_digest: str
    prepared_digest: str
    occurrence_digest: str
    episode_ref: str
    job_id: str
    prepare_operation_id: str
    acquire_operation_id: str
    call_id: str
    quote_digest: str
    reservation_digest: str
    permit_commitment: str
    scope_commitment: str
    graph_revision: int
    graph_epoch: int
    activation_generation: int
    graph_incarnation: str
    deadline_utc: float
    purpose: str = 'consolidation'
    schema: str = 'd06.internal-life-worker-binding.v2'

    def __post_init__(self):
        if (self.schema != 'd06.internal-life-worker-binding.v2' or self.purpose != 'consolidation'
                or type(self.namespace) is not NamespaceId
                or type(self.owner_principal) is not OwnerPrincipalV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1):
            raise ValueError('Life worker binding requires its closed dual-role scope')
        for name in ('installation_id','worker_subject','owner_actor','job_id',
                     'prepare_operation_id','acquire_operation_id','call_id','graph_incarnation'):
            identifier(getattr(self,name),name)
        for name in ('manifest_digest','installation_grant_digest','owner_lease_digest',
                     'target_admission_digest','storage_admission_digest','prepared_digest',
                     'occurrence_digest','quote_digest','reservation_digest','permit_commitment','scope_commitment'):
            _sha(getattr(self,name))
        for name in ('graph_revision','graph_epoch','activation_generation'):
            if type(getattr(self,name)) is not int or getattr(self,name)<1:
                raise ValueError('Life worker binding requires strict positive versions')
        if (type(self.deadline_utc) not in (int,float) or not math.isfinite(self.deadline_utc)
                or self.deadline_utc<=0):
            raise ValueError('Life worker binding requires its original finite deadline')
        key=AtomKey.from_token(self.episode_ref)
        grant=AtomKey.from_token(self.owner_guard.grant_ref)
        suffix=self.job_id.removeprefix('life-content-job:')
        if (key.type_name!=EPISODE or NamespaceId.from_key(key)!=self.namespace
                or grant!=owner_grant_key(*self.namespace.as_tuple)
                or len(suffix)!=48 or any(c not in '0123456789abcdef' for c in suffix)
                or self.job_id!='life-content-job:'+suffix
                or (self.prepare_operation_id,self.acquire_operation_id,self.call_id)!=
                   tuple('life-content-'+p+':'+suffix for p in ('prepare','acquire','call'))):
            raise ValueError('Life worker binding changed its immutable occurrence once locators')

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))


def decode_internal_life_worker_binding_v2(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw) is not dict or set(raw)!={f.name for f in fields(InternalLifeWorkerBindingV2)}:
        raise ValueError('Life worker binding fields/version differ')
    value=decode_typed_production_value_v1(raw,InternalLifeWorkerBindingV2)
    from ..domains.d01.production_operations_v1 import plain_v1
    if canonical_serialize(raw)!=canonical_serialize(plain_v1(value)):
        raise ValueError('Life worker binding has noncanonical closed values')
    return value


@dataclass(frozen=True, slots=True)
class InternalLifeWorkerFrameV2:
    owner_frame: CurrentOperationFrameV1
    binding: InternalLifeWorkerBindingV2
    schema: str = 'd06.internal-life-worker-frame.v2'

    def __post_init__(self):
        if (self.schema!='d06.internal-life-worker-frame.v2'
                or type(self.owner_frame) is not CurrentOperationFrameV1
                or type(self.binding) is not InternalLifeWorkerBindingV2):
            raise TypeError('Life worker frame requires exact separate Owner and worker roles')
        f,b=self.owner_frame,self.binding
        if (f.envelope.authority.namespace!=b.namespace or f.envelope.authority.actor!=b.owner_actor
                or f.owner_guard!=b.owner_guard or f.activation_generation!=b.activation_generation
                or f.envelope.identity.operation_id!=b.acquire_operation_id
                or f.envelope.identity.phase!='acquire_internal_life_content_v2'
                or f.envelope.authority.purpose!=b.purpose
                or len(f.envelope.version_guard.query_epochs)!=1
                or f.envelope.version_guard.query_epochs[0].revision!=b.graph_epoch
                or not f.now_utc<b.deadline_utc<=f.envelope.deadline_utc):
            raise ValueError('Life worker frame does not match its authenticated Owner command')


@dataclass(frozen=True, slots=True)
class _InstalledLifeWorkerIssuanceV2:
    runtime: object
    scope: object
    guard: object
    owner: object
    bundle: object
    grant: object


_ISSUED={}


def owner_lease_commitment_v2(owner):
    """Complete Life-local lease commitment without changing generic JSON."""
    from ..graph_coordinator import OwnerLeaseBindingV1
    if type(owner) is not OwnerLeaseBindingV1:
        raise TypeError('Life worker requires the actual complete Owner lease')
    value={field.name:getattr(owner,field.name) for field in fields(owner)}
    for name in ('capabilities','purposes','audiences'):
        if type(value[name]) is not frozenset or any(type(item) is not str for item in value[name]):
            raise TypeError('Life worker Owner lease has noncanonical finite grant sets')
        value[name]=tuple(sorted(value[name]))
    return canonical_digest(value)


def issue_installed_life_worker_v2(runtime,scope,guard,owner):
    """Called by the exact runtime's original Owner fence context, before SQL."""
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from ..graph_coordinator import OwnerLeaseBindingV1
    from ..host.v2_fence_port import V2FencePort
    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_contracts import FenceScope
    from ..model_broker.internal_life_content_v1 import WORK_KIND
    if (type(runtime) is not InstalledDomainOperationRuntimeV1 or type(scope) is not FenceScope
            or type(owner) is not OwnerLeaseBindingV1 or type(guard) is not OwnerAuthorizationGuardV1):
        raise ValueError('Life worker issuer requires its actual installed Owner fence')
    runtime._current();graph=runtime.graph;port=graph._GraphCoordinator__content_fence_v2
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if type(port) is not V2FencePort or assembly is None:
        raise ValueError('Life worker has no authenticated installation port')
    bundle=assembly.admin_bundle;grant=port.installation_grant
    policy=bundle.installation_policy
    if (type(bundle.model_workflows) not in (AdminModelWorkflowsV3,AdminModelWorkflowsV4,AdminModelWorkflowsV5,AdminModelWorkflowsV6,AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9) or bundle.model_workflows.life_content is None
            or bundle.model_workflows.life_content.work_kind!=WORK_KIND
            or WORK_KIND not in policy.root_grant.allowed_work_kinds
            or (grant.authority_id,grant.installation_id,grant.manifest_digest,grant.administrator_holder)!=
               (policy.expected_authority_id,policy.installation_id,policy.manifest_digest,policy.administrator_holder)
            or (scope.namespace,scope.authority_namespace,scope.permit.subject,scope.permit.holder)!=
               (policy.namespace,policy.authority_namespace,grant.subject,grant.administrator_holder)
            or scope.operation!='write' or scope.permit.operation!='write'
            or scope.pinned_anchor!=scope.permit.pinned_anchor
            or owner.namespace!=scope.namespace or guard.namespace!=scope.namespace
            or guard.installation_id!=grant.installation_id or guard.authority_id!=grant.authority_id
            or owner.authorization_head!=guard.authorization_head
            or owner.authorization_revision!=guard.authorization_revision
            or owner.revocation_epoch!=guard.minimum_revocation_epoch
            or guard.minimum_revocation_revision!=0
            or guard.pending_revoke_operation_id is not None
            or 'workbench.create' not in owner.capabilities
            or 'consolidation' not in owner.purposes
            or port.validate_fence(scope)!=scope.permit):
        raise ValueError('Life worker delegation is outside actual Owner and installation capabilities')
    issued=_InstalledLifeWorkerIssuanceV2(runtime,scope,guard,owner,bundle,grant)
    _ISSUED[id(issued)]=issued
    return issued


def require_installed_life_worker_v2(issued,runtime,frame=None):
    if (type(issued) is not _InstalledLifeWorkerIssuanceV2 or _ISSUED.get(id(issued)) is not issued
            or issued.runtime is not runtime or getattr(runtime,'_active_internal_life_worker_v2',None) is not issued):
        raise ValueError('Life worker needs the exact active installed dual-role issuance')
    runtime._current();graph=runtime.graph
    if (graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not issued.bundle
            or graph._GraphCoordinator__content_fence_v2.installation_grant!=issued.grant):
        raise ValueError('Life worker actual installation identity changed')
    if frame is not None and (type(frame) is not CurrentOperationFrameV1
            or frame.envelope.authority.actor!=issued.owner.actor
            or frame.owner_guard.owner_head_digest!=issued.owner.authorization_head.removeprefix('sha256:')
            or frame.envelope.authority.namespace!=issued.scope.namespace
            or frame.activation_generation!=issued.scope.generation):
        raise ValueError('Life worker Owner frame does not match its real delegation')
    return issued


def release_installed_life_worker_v2(issued):
    if _ISSUED.get(id(issued)) is issued:
        _ISSUED.pop(id(issued))
