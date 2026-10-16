"""Dedicated named prospective Joint registration; no public foreground admission."""
from dataclasses import dataclass, fields
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from ..graph_types import AtomKey, GraphVersion
from ..runtime.joint_window_management_v1 import ManagedWindowArgumentV1, managed_window_argument_from_wire_v1
from ..runtime.joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1, JointContactProspectiveBindingV1, decode_joint_binding_v1
from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1
from ..runtime.issuers import BudgetLeaseGrant
from .v2_contract import FencePermitV2
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from .contract import AuthorityUnavailable

OPERATION = 'input:register_joint_node_execution_binding_v1'


def named_joint_binding_operation_id_v1(namespace, argument, command):
    return 'named-joint-binding:' + named_joint_command_digest_v1(namespace,argument,command)[:48]


def named_joint_command_digest_v1(namespace, argument, command):
    from ..domains.d01.production_operations_v1 import plain_v1
    if (type(namespace) is not NamespaceId or type(argument) is not ManagedWindowArgumentV1
            or type(command) is not RegisterJointNodeExecutionBindingRequestV1
            or type(command.binding) not in {JointArtifactProspectiveBindingV1, JointContactProspectiveBindingV1}):
        raise TypeError('Named Joint registration requires its exact prospective command')
    return canonical_digest(('d10.named-joint-binding-command.v1', namespace, OPERATION,
        plain_v1(argument), plain_v1(command)))


@dataclass(frozen=True, slots=True)
class NamedJointBindingSelectorV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    operation_kind: str
    argument: ManagedWindowArgumentV1
    command: RegisterJointNodeExecutionBindingRequestV1
    request_digest: str
    schema: str = 'd10.named-joint-binding-selector.v1'

    def __post_init__(self):
        if (self.schema != 'd10.named-joint-binding-selector.v1' or type(self.namespace) is not NamespaceId
                or self.operation_kind != OPERATION or not self.installation_id
                or self.operation_id != named_joint_binding_operation_id_v1(self.namespace,self.argument,self.command)
                or type(self.argument) is not ManagedWindowArgumentV1
                or self.request_digest != named_joint_command_digest_v1(self.namespace, self.argument, self.command)
                or self.command.binding.namespace != self.namespace
                or NamespaceId.from_key(AtomKey.from_token(self.argument.window_ref)) != self.namespace
                or self.argument.executor_kind not in {'draft_file', 'contact'}):
            raise ValueError('Named Joint selector changed its actual fixed scope/argument/command')
        binding = self.command.binding
        executor, ref, digest = ('draft_file', binding.task_scope_ref, binding.task_scope_digest) if type(binding) is JointArtifactProspectiveBindingV1 else ('contact', binding.prospective_original_ref, binding.prospective_original_digest)
        from ..domains.d01.production_operations_v1 import plain_v1
        if (executor, ref, digest, canonical_digest(plain_v1(self.command))) != (
                self.argument.executor_kind, self.argument.typed_input_original_ref,
                self.argument.typed_input_original_digest, self.argument.typed_request_digest):
            raise ValueError('Named Joint command does not equal the immutable Window node input')


@dataclass(frozen=True, slots=True)
class NamedJointExecutorOriginalV1:
    role: str
    original_ref: str
    original_digest: str
    producer_operation_id: str
    producer_original_digest: str
    producer_receipt_digest: str

    def __post_init__(self):
        if self.role not in {'objective', 'task_scope', 'draft_root', 'c02_cycle', 'prospective_birth', 'joint_preparation', 'contact_plan', 'contact_cause'} or not self.original_ref or not self.producer_operation_id:
            raise ValueError('Named Joint executor original has no fixed role or real producer')
        for digest in (self.original_digest, self.producer_original_digest, self.producer_receipt_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Named Joint original needs its exact positive producer commitments')


@dataclass(frozen=True, slots=True)
class NamedJointBindingCurrentV1:
    request: NamedJointBindingSelectorV1
    permit: FencePermitV2
    current_self: AuthorityCurrentSelfIdentityV1
    owner_guard: ProductionOwnerGuardV1
    window_head: GraphVersion
    window_digest: str
    window_producer_ref: str
    window_producer_digest: str
    long_plan_head: GraphVersion
    long_plan_digest: str
    long_plan_producer_ref: str
    long_plan_producer_digest: str
    node_digest: str
    typed_input_original_ref: str
    typed_input_original_digest: str
    binding_digest: str
    executor_originals: tuple[NamedJointExecutorOriginalV1, ...]
    parent_grant: BudgetLeaseGrant
    original_deadline_utc: float
    valid_until_utc: float
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    source_closure: tuple[GraphVersion, ...]
    source_purpose_groups: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]
    source_proof_digest: str
    guard_inventory_digest: str
    observed_at_utc: float
    prior_window_head: GraphVersion | None
    prior_qualification_ref: str | None
    prior_qualification_digest: str | None
    prior_result_versions_digest: str | None
    schema: str = 'd10.named-joint-binding-current.v1'

    def __post_init__(self):
        if (self.schema != 'd10.named-joint-binding-current.v1' or type(self.request) is not NamedJointBindingSelectorV1
                or type(self.permit) is not FencePermitV2 or self.permit.operation not in {'read', 'write'}
                or type(self.current_self) is not AuthorityCurrentSelfIdentityV1 or self.current_self.permit != self.permit
                or type(self.owner_guard) is not ProductionOwnerGuardV1 or type(self.parent_grant) is not BudgetLeaseGrant
                or self.window_head.key.token != self.request.argument.window_ref
                or self.window_head.revision != self.request.argument.window_revision
                or self.long_plan_head.key.type_name != 'd08.long_term_plan.v1'
                or self.typed_input_original_ref != self.request.argument.typed_input_original_ref
                or self.typed_input_original_digest != self.request.argument.typed_input_original_digest
                or self.binding_digest != self.request.command.binding.digest
                or not self.observed_at_utc < self.valid_until_utc <= self.original_deadline_utc
                or self.original_deadline_utc > self.parent_grant.valid_until_utc):
            raise ValueError('Named Joint current observation changed its exact original scope or lifetime')
        roles = {'objective', 'task_scope', 'draft_root', 'c02_cycle'} if self.request.argument.executor_kind == 'draft_file' else {'prospective_birth', 'joint_preparation', 'contact_plan', 'contact_cause'}
        if (type(self.executor_originals) is not tuple or len(self.executor_originals) != len(roles)
                or {item.role for item in self.executor_originals} != roles
                or any(type(item) is not NamedJointExecutorOriginalV1 for item in self.executor_originals)):
            raise ValueError('Named Joint current evidence has no complete closed executor original set')
        prior = (self.prior_window_head, self.prior_qualification_ref, self.prior_qualification_digest, self.prior_result_versions_digest)
        if not (all(v is None for v in prior) or type(prior[0]) is GraphVersion and all(type(v) is str and v for v in prior[1:])):
            raise ValueError('Named Joint successor needs its actual current prior qualification as one complete group')
        for version in (*self.read_versions, *self.source_closure, self.window_head, self.long_plan_head):
            if type(version) is not GraphVersion or NamespaceId.from_key(version.key) != self.request.namespace:
                raise ValueError('Named Joint evidence crossed actual namespace/version')
        for digest in (self.window_digest, self.window_producer_digest, self.long_plan_digest,
                self.long_plan_producer_digest, self.node_digest, self.binding_digest,
                self.source_proof_digest, self.guard_inventory_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Named Joint current commitment is not an actual SHA256')

    def require_for_v3(self, *, request, permit, installation_id, authority_namespace):
        if (self.request != request or self.permit != permit or self.current_self.installation_id != installation_id
                or self.current_self.authority_namespace != authority_namespace):
            raise AuthorityUnavailable('Named Joint paired result changed its actual request/permit/installation')
        return self


def named_joint_selector_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value) is not NamedJointBindingSelectorV1:
        raise TypeError('exact named Joint selector required')
    return plain_v1(value)


def named_joint_selector_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(NamedJointBindingSelectorV1)}:
        raise ValueError('Named Joint selector exact field set differs')
    command = raw['command']
    if type(command) is not dict or set(command) != {'binding'}:
        raise ValueError('Named Joint command must be the exact prospective registration')
    value = NamedJointBindingSelectorV1(**{**raw, 'namespace': NamespaceId(**raw['namespace']),
        'argument': managed_window_argument_from_wire_v1(raw['argument']),
        'command': RegisterJointNodeExecutionBindingRequestV1(decode_joint_binding_v1(command['binding']))})
    if named_joint_selector_to_wire_v1(value) != raw:
        raise ValueError('Named Joint selector canonical wire differs')
    return value


def named_joint_current_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value) is not NamedJointBindingCurrentV1:
        raise TypeError('exact current named Joint observation required')
    return plain_v1(value)


def named_joint_current_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw) is not dict or set(raw) != {f.name for f in fields(NamedJointBindingCurrentV1)}:
        raise ValueError('Named Joint current exact field set differs')
    value = decode_typed_production_value_v1(raw, NamedJointBindingCurrentV1)
    if named_joint_current_to_wire_v1(value) != raw:
        raise ValueError('Named Joint current canonical wire differs')
    return value


class InstalledCurrentNamedJointBindingV1:
    def __init__(self, *, self_identity_service, budget_issuer, clock_provider, installed_bundle, package_root):
        from .v2_self_identity_service import AuthorityV2SelfIdentityService
        from .linux_clock_v1 import LinuxKernelClockProviderV1
        from ..runtime.issuers import D11BudgetJobIssuer
        from ..host.authority_profile import AdminInstallationBundle
        if (type(self_identity_service) is not AuthorityV2SelfIdentityService or type(budget_issuer) is not D11BudgetJobIssuer
                or type(clock_provider) is not LinuxKernelClockProviderV1 or type(installed_bundle) is not AdminInstallationBundle
                or installed_bundle.installation_policy.namespace != self_identity_service._namespace_id
                or installed_bundle.installation_policy.manifest_digest != self_identity_service._manifest_digest):
            raise TypeError('Named Joint service requires its actual paired Self/Owner/Source/Root installation')
        self.self_identity, self.issuer, self.clock, self.installed_bundle = self_identity_service, budget_issuer, clock_provider, installed_bundle
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        self.artifact_build=read_installed_d11_life_build_v1(package_root,installed_bundle.installation_policy.manifest_digest,recipe_id="artifact_draft_v1")
        self.source_note_original_services=(None,None)
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self, service=self, source_location=self_identity_service._source_location)

    def current(self, *, credential, subject, permit, request):
        from .current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,observe_named_source_note_current_v1
        if type(request)is NamedJointSourceNoteSelectorV1:return observe_named_source_note_current_v1(self,credential=credential,subject=subject,permit=permit,request=request)
        from .named_joint_binding_source_read_v3 import prepare_current_named_joint_inputs_v3
        if (type(request) is not NamedJointBindingSelectorV1 or type(permit) is not FencePermitV2
                or permit.operation not in {'read', 'write'} or subject != self.self_identity._read_subject
                or request.installation_id != self.installed_bundle.installation_policy.installation_id
                or request.namespace != self.self_identity._namespace_id
                or permit.operation == 'write' and permit.operation_id != request.operation_id):
            raise AuthorityUnavailable('Named Joint current requires its actual exact installed paired Scope')
        inputs = prepare_current_named_joint_inputs_v3(self, credential=credential, subject=subject, permit=permit, request=request)
        try:
            return inputs.current(), permit
        finally:
            inputs.release_v3()
