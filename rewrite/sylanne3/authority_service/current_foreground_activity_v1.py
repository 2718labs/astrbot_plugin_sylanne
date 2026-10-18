"""Independent current foreground facts under the existing Authority fence.

No permission table is created. The actual self service, Owner storage and
C09 qualifier are the same installed objects used by the existing Authority.
The returned audit DTO is not a live credential; Host retains its paired-port
issued handle and the final source/admission services still arbitrate effects.
"""
from ..runtime.foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3

from .contract import AuthorityUnavailable
from .current_authority_graph_read_v3 import authority_current_json_v3
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from .v2_contract import FencePermitV2
from .linux_clock_v1 import LinuxKernelClockProviderV1
from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
from ..domains.d03.self_perspective import self_mapping_key
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1, foreground_cycle_ids_v1, WORK_KIND
from ..runtime.jobs import get_job
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime.ingress_observation import read_committed_ingress_identity
from ..runtime.d11_life_preparation_v1 import _read
from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, DraftFileIdentityV1, draft_from_wire_v1
from ..runtime.d11_types import runtime_job_key
from ..runtime.d11_types import job_graph_write
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2

_DOMAINS = {
    "serve_concern":"d07",
    "prepare_personal_candidate_eligibility_v1": "d08", "adopt_personal_candidate_eligibility_v1": "d08",
    "derive_ingress_artifact_task_scope_v1": "d10",
    "await_existing_artifact_revision_v1": "d10",
    "select_existing_artifact_continuation_v1": "d08", "revise_existing_artifact_v1": "d08",
    "prepare_ingress_c04_v1": "d06", "adopt_ingress_c04_v1": "d06",
    "prepare_ingress_recall_need_v1": "d07",
    "adopt_current_task_no_search_v1": "d07",
    "adopt_current_c1_method_conditions_v1": "d07",
    "quote_current_method_choices_v1": "d02",
    "select_ingress_recall_seed_v1": "d06",
    "prepare_ingress_recall_model_v1": "d07",
    "acquire_ingress_recall_model_v1": "d11",
    "prepare_ingress_recall_result_read_v1": "d07",
    "finish_ingress_recall_model_v1": "d11",
    "adopt_ingress_recall_model_v1": "d07",
    "create_foreground_cycle_v2": "d11",
    "create_source_note_foreground_cycle_v1": "d11", "prepare_selected_source_note_action_v2": "d08",
    "prepare_source_note_body": "d02", "input:register_life_plan_v2": "d10", "adopt_relationship_revision_v2": "d05",
    "input:register_artifact_task_text_extent": "d08", "input:register_artifact_phase_postcondition_policy_v1": "d08",
    "prepare_personal_candidates_v1": "d08", "select_personal_step_v2": "d08",
    "checkpoint_foreground_cycle_v2": "d11", "checkpoint_source_note_foreground_cycle_v1": "d11",
    "wake_artifact_draft_cycle_v1": "d11", "wake_artifact_draft_cycle_v2": "d11",
    "prepare_artifact_draft_model_v2": "d11", "acquire_artifact_draft_model_v2": "d11",
    "adopt_artifact_draft_content_v2": "d06", "verify_artifact_draft_phase_v2": "d11",
    "propose_artifact_draft_phase_action_v2": "d08",
    "finish_artifact_receipt_cycle_v1": "d11",
    "derive_artifact_completion_receipt_v1": "d06",
    "register_artifact_phase_postcondition_contract_v1": "d08", "observe_artifact_phase_postconditions_v1": "d11", "prepare_artifact_phase_observation_v1": "d07",
    "revise_artifact_task_plan_v2": "d08", "activate_artifact_task_project_checkpoint_v2": "d10",
    "activate_artifact_task_project_checkpoint_v1": "d10", "register_artifact_task_milestone_v2": "d08",
    "prepare_artifact_draft_model": "d11", "acquire_artifact_draft_model": "d11", "adopt_artifact_draft_content": "d06",
    "compose_artifact_goal_plan": "d08", "create_artifact_project": "d10", "prepare_artifact_draft_project_context": "d03",
    "propose_artifact_draft_action": "d08", "prepare_artifact_draft_body": "d02", "focus_life_project": "d07",
    "input:register_artifact_draft_plan_v3": "d10", "input:register_artifact_phase_draft_plan_v2": "d10", "prepare_life": "d10",
    "input:register_life_outcome_v2": "d10", "advance_life": "d10",
    "create_foreground_cycle": "d11", "acquire_foreground_cycle": "d11", "checkpoint_foreground_cycle": "d11", "wake_foreground_cycle": "d11",
    "create_artifact_task_plan_v1": "d08", "create_artifact_task_project_v1": "d10", "initialize_artifact_task_project_checkpoint_v1": "d10", "create_personal_plan": "d08", "revise_personal_plan": "d08", "select_personal_step": "d08", "settle_personal_goal": "d08",
    "initialize_project_checkpoint": "d10", "refresh_project_checkpoint": "d10", "settle_project_checkpoint": "d10",
}


_METHOD_FACT_OPERATIONS_V1=frozenset({'adopt_current_task_no_search_v1','adopt_current_c1_method_conditions_v1','quote_current_method_choices_v1'})

_INTERNAL_PREPARATION_DOMAINS_V2={'input:freeze_values':'d01','evaluate_values':'d01'}
_INTERNAL_PREPARATION_PARENT_OPERATION_V2='input:freeze_artifact_candidate_preparation_v1'

def foreground_allowed_write_domains_v1(operation_kind):
    if operation_kind == "derive_ingress_artifact_task_scope_v1":
        return ("d06","d08","d10","d11")
    if operation_kind == "settle_personal_goal":
        return ("d08","d10","d11")
    if operation_kind == "await_existing_artifact_revision_v1":
        return ("d10",)
    if operation_kind == "revise_existing_artifact_v1":
        return ("d08", "d10", "d11")
    if operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        return ("d02", "d04", "d06", "d07", "d11")
    if operation_kind in {"prepare_ingress_recall_model_v1","serve_concern"}:
        return ("d02", "d07", "d11")
    if operation_kind == "advance_life":
        return ("d02", "d06", "d10", "d11")
    domain = ('d08' if operation_kind==_INTERNAL_PREPARATION_PARENT_OPERATION_V2 else
        _INTERNAL_PREPARATION_DOMAINS_V2[operation_kind] if operation_kind in _INTERNAL_PREPARATION_DOMAINS_V2 else _DOMAINS[operation_kind])
    return (domain,) if domain == "d11" else (domain, "d11")


def foreground_typed_command_digest_v1(operation, request):
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    if installed_operation_v1(operation.operation_kind) != operation or type(request) is not operation.request_type:
        raise TypeError("foreground command requires its actual installed exact request")
    expected_domain=('d08' if operation.operation_kind==_INTERNAL_PREPARATION_PARENT_OPERATION_V2 else
        _DOMAINS.get(operation.operation_kind, _INTERNAL_PREPARATION_DOMAINS_V2.get(operation.operation_kind)))
    if expected_domain != operation.domain:
        raise ValueError("foreground operation has no closed installed domain admission")
    return canonical_digest(("sylanne.foreground-typed-command.v1", operation.domain, operation.operation_kind, request))


@dataclass(frozen=True, slots=True)
class ForegroundActivityRequestV1:
    namespace: NamespaceId
    installation_id: str
    ingress_operation_id: str
    c02_operation_id: str
    cue_source_ref: str
    plan_source_ref: str
    cycle_job_ref: str
    expected_cycle_revision: int
    expected_cancel_generation: int
    activity_id: str
    operation_id: str
    operation_kind: str
    request_digest: str
    parent_budget_lease_ref: str
    purpose: str
    audiences: tuple[str, ...]
    requested_deadline_utc: float
    plan_ref: str | None = None
    draft_root_registration_ref: str | None = None
    worker_holder: str | None = None
    worker_fence: int | None = None
    worker_lease_expires_utc: str | None = None
    schema: str = "d11.foreground-activity-request.v1"

    def __post_init__(self):
        if (self.schema != "d11.foreground-activity-request.v1" or type(self.namespace) is not NamespaceId
                or self.operation_kind not in _DOMAINS
                or AtomKey.from_token(self.cycle_job_ref).type_name != "runtime.job"
                or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in (self.cue_source_ref, self.plan_source_ref))
                or any(type(n) is not int or n < 0 for n in (self.expected_cycle_revision, self.expected_cancel_generation))
                or type(self.audiences) is not tuple or not self.audiences or len(self.audiences) > 32
                or len(self.request_digest) != 64):
            raise ValueError("foreground request must use its finite registered selectors")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("foreground selector exceeds its descriptor bound")


from ..runtime.artifact_phase_postconditions_v1 import ArtifactPreparationChildSelectorV1
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1


@dataclass(frozen=True, slots=True)
class ForegroundActivityRequestV2:
    namespace: NamespaceId
    installation_id: str
    ingress_operation_id: str
    c02_operation_id: str
    cue_source_ref: str
    plan_source_ref: str
    cycle_job_ref: str
    expected_cycle_revision: int
    expected_cancel_generation: int
    activity_id: str
    operation_id: str
    operation_kind: str
    request_digest: str
    parent_budget_lease_ref: str
    purpose: str
    audiences: tuple[str, ...]
    requested_deadline_utc: float
    preparation_child: ArtifactPreparationChildSelectorV1
    preparation_parent_digest: str
    plan_ref: str | None = None
    draft_root_registration_ref: str | None = None
    worker_holder: str | None = None
    worker_fence: int | None = None
    worker_lease_expires_utc: str | None = None
    schema: str = 'd11.foreground-activity-request.v2'

    def __post_init__(self):
        from ..host.authority_profile import artifact_candidate_preparation_dependency_contract_v1
        children=dict(artifact_candidate_preparation_dependency_contract_v1().internal_children)
        if (self.schema!='d11.foreground-activity-request.v2' or type(self.namespace) is not NamespaceId
                or type(self.preparation_child) is not ArtifactPreparationChildSelectorV1
                or self.operation_kind not in _INTERNAL_PREPARATION_DOMAINS_V2
                or self.operation_kind!=children[self.preparation_child.child_slot]
                or AtomKey.from_token(self.cycle_job_ref).type_name!='runtime.job'
                or any(AtomKey.from_token(ref).type_name!='memory.source' for ref in (self.cue_source_ref,self.plan_source_ref))
                or any(type(n) is not int or n<0 for n in (self.expected_cycle_revision,self.expected_cancel_generation))
                or type(self.audiences) is not tuple or not self.audiences or len(self.audiences)>32
                or type(self.preparation_parent_digest) is not str or len(self.preparation_parent_digest)!=64
                or any(c not in '0123456789abcdef' for c in self.preparation_parent_digest)
                or len(self.request_digest)!=64 or self.plan_ref is None or self.draft_root_registration_ref is None):
            raise ValueError('V2 foreground child must bind its exact signed parent, slot and actual typed input')
        if len(canonical_serialize(self).encode('utf-8'))>65536:
            raise ValueError('V2 foreground child selector exceeds its descriptor bound')


@dataclass(frozen=True,slots=True)
class ForegroundActivityPreparationParentRequestV2:
    namespace: NamespaceId
    installation_id: str
    ingress_operation_id: str
    c02_operation_id: str
    cue_source_ref: str
    plan_source_ref: str
    cycle_job_ref: str
    expected_cycle_revision: int
    expected_cancel_generation: int
    activity_id: str
    operation_id: str
    operation_kind: str
    request_digest: str
    parent_budget_lease_ref: str
    purpose: str
    audiences: tuple[str, ...]
    requested_deadline_utc: float
    preparation_task: ArtifactDraftTaskSelectorV1
    plan_ref: str | None = None
    draft_root_registration_ref: str | None = None
    worker_holder: str | None = None
    worker_fence: int | None = None
    worker_lease_expires_utc: str | None = None
    schema: str = 'd11.foreground-preparation-parent-request.v2'

    def __post_init__(self):
        if (self.schema!='d11.foreground-preparation-parent-request.v2' or type(self.namespace) is not NamespaceId
                or self.operation_kind!=_INTERNAL_PREPARATION_PARENT_OPERATION_V2
                or type(self.preparation_task) is not ArtifactDraftTaskSelectorV1
                or (self.preparation_task.namespace,self.preparation_task.c02_operation_id,self.preparation_task.root_registration_ref,self.preparation_task.cycle_job_ref)!=
                    (self.namespace,self.c02_operation_id,self.draft_root_registration_ref,self.cycle_job_ref)
                or any(AtomKey.from_token(ref).type_name!='memory.source' for ref in (self.cue_source_ref,self.plan_source_ref))
                or any(type(n) is not int or n<0 for n in (self.expected_cycle_revision,self.expected_cancel_generation))
                or type(self.audiences) is not tuple or not self.audiences or len(self.audiences)>32
                or len(self.request_digest)!=64 or self.plan_ref is None):
            raise ValueError('preparation start must select its exact current approved Self task before Parent W01')
        if len(canonical_serialize(self).encode('utf-8'))>65536:
            raise ValueError('preparation parent request exceeds its descriptor bound')


@dataclass(frozen=True,slots=True)
class ForegroundActivityEvidenceV2:
    request: ForegroundActivityRequestV2 | ForegroundActivityPreparationParentRequestV2
    current_self: AuthorityCurrentSelfIdentityV1
    owner_guard: ProductionOwnerGuardV1
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch
    allowed_write_domains: tuple[str, ...]
    valid_until_utc: str
    root_capability: DraftRootCapabilityV1 | None
    access_epoch: int
    delete_epoch: int
    schema: str = 'd11.foreground-activity-evidence.v2'

    def __post_init__(self):
        if (self.schema!='d11.foreground-activity-evidence.v2' or type(self.request) not in {ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}
                or type(self.current_self) is not AuthorityCurrentSelfIdentityV1 or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.query_epoch) is not QueryEpoch or type(self.read_versions) is not tuple or len(self.read_versions)>128
                or any(type(row) is not GraphVersion for row in self.read_versions)
                or self.allowed_write_domains!=foreground_allowed_write_domains_v1(self.request.operation_kind)
                or self.root_capability is not None and type(self.root_capability) is not DraftRootCapabilityV1):
            raise ValueError('V2 foreground evidence must retain exact actual parent-bound child observations')


def foreground_fence_operation_id_v2(request):
    if type(request) not in {ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}:raise TypeError('V2 fence identity requires its exact registered preparation request')
    return 'foreground-domain-v2-'+canonical_digest(request)[:48]


def foreground_to_wire_v2(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    names={ForegroundActivityRequestV2:'foreground_request',ForegroundActivityPreparationParentRequestV2:'parent_request',ForegroundActivityEvidenceV2:'foreground_evidence'}
    if type(value) not in names:raise TypeError('unregistered V2 foreground wire type')
    kind=('parent_evidence' if type(value) is ForegroundActivityEvidenceV2 and type(value.request) is ForegroundActivityPreparationParentRequestV2 else names[type(value)])
    return {'schema':'d11.foreground-wire.v2','kind':kind,'value':plain_v1(value)}


def foreground_from_wire_v2(raw,expected_type):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    classes={'foreground_request':ForegroundActivityRequestV2,'foreground_evidence':ForegroundActivityEvidenceV2,
        'parent_request':ForegroundActivityPreparationParentRequestV2,'parent_evidence':ForegroundActivityEvidenceV2}
    if (type(raw) is not dict or set(raw)!={'schema','kind','value'} or raw['schema']!='d11.foreground-wire.v2'
            or classes.get(raw['kind']) is not expected_type or expected_type not in classes.values()):
        raise ValueError('V2 foreground exact wire schema/type differs')
    value=decode_typed_production_value_v1(raw['value'],expected_type)
    if foreground_to_wire_v2(value)!=raw:raise ValueError('V2 foreground wire changed under its closed canonical codec')
    return value


@dataclass(frozen=True, slots=True)
class ForegroundActivityEvidenceV1:
    request: ForegroundActivityRequestV1
    current_self: AuthorityCurrentSelfIdentityV1
    owner_guard: ProductionOwnerGuardV1
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch
    allowed_write_domains: tuple[str, ...]
    valid_until_utc: str
    root_capability: DraftRootCapabilityV1 | None
    access_epoch: int
    delete_epoch: int
    schema: str = "d11.foreground-activity-evidence.v1"

    def __post_init__(self):
        if (self.schema != "d11.foreground-activity-evidence.v1" or type(self.request) is not ForegroundActivityRequestV1
                or type(self.current_self) is not AuthorityCurrentSelfIdentityV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1 or type(self.query_epoch) is not QueryEpoch
                or type(self.read_versions) is not tuple or len(self.read_versions) > 128
                or any(type(row) is not GraphVersion for row in self.read_versions)
                or self.allowed_write_domains != foreground_allowed_write_domains_v1(self.request.operation_kind)
                or self.root_capability is not None and type(self.root_capability) is not DraftRootCapabilityV1):
            raise ValueError("foreground evidence must retain its real exact typed observations")


def foreground_fence_operation_id_v1(request):
    if type(request) is not ForegroundActivityRequestV1:
        raise TypeError("foreground fence identity requires its exact registered request")
    return "foreground-domain-" + canonical_digest(request)[:48]


@dataclass(frozen=True, slots=True)
class DraftRootRegistrationRequestV1:
    namespace: NamespaceId
    source_ref: str
    resource_id: str
    filenames: tuple[str, ...]
    max_bytes: int
    valid_until_utc: str
    operation_id: str
    purpose: str
    audiences: tuple[str, ...]

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or not self.resource_id or not self.operation_id or type(self.filenames) is not tuple
                or not 1 <= len(self.filenames) <= 32 or len(set(self.filenames)) != len(self.filenames)
                or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 524288):
            raise ValueError("root registration must be an explicit finite Owner setup request")
        if not self.purpose or type(self.audiences) is not tuple or not self.audiences or len(self.audiences) > 32:
            raise ValueError("root setup requires its explicit current source purpose/audiences")


@dataclass(frozen=True, slots=True)
class DraftRootRegistrationEvidenceV1:
    request: DraftRootRegistrationRequestV1
    owner_actor_ref: str
    owner_guard: ProductionOwnerGuardV1
    capability: DraftRootCapabilityV1
    permit: FencePermitV2
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch


def draft_root_registration_operation_digest_v1(request, owner_actor_ref):
    if type(request) is not DraftRootRegistrationRequestV1 or not owner_actor_ref:
        raise TypeError("root setup digest needs its actual typed Owner command")
    return canonical_digest(("d11.explicit-draft-root-setup.v1", request.namespace, owner_actor_ref, request))


def _source_family_current_sql_v1(db, *, namespace, roots, purpose, audiences,
                                  streaming_qualified=None, streaming_scope=None,
                                  streaming_graph_stamp=None):
    """Shared exact source/access/correction closure for activity and Owner setup."""
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    from ..runtime.artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .artifact_model_source_read_v3 import artifact_model_source_family_v3
    model_sources=artifact_model_source_family_v3(db,namespace=namespace,roots=roots,purpose=purpose,audiences=audiences)
    if model_sources is not None:return model_sources
    from .foreground_mesh_source_read_v3 import foreground_mesh_source_family_v3
    mesh_sources = foreground_mesh_source_family_v3(db,namespace=namespace,roots=roots,purpose=purpose,audiences=audiences)
    if mesh_sources is not None:
        return mesh_sources
    if streaming_qualified is not None:
        from ..runtime.source_correction_read_v3 import _SourceFamilyQualificationV3
        if type(streaming_qualified) is not _SourceFamilyQualificationV3:
            raise AuthorityUnavailable("actual completed streaming Source family qualification required")
        return streaming_qualified.require_for(db, namespace=namespace, roots=roots,
            purpose=purpose, audiences=audiences, read_scope=streaming_scope,
            graph_stamp=streaming_graph_stamp)
    versions, active, done = {}, set(), set()
    def atom(key, required=True):
        if NamespaceId.from_key(key) != namespace:
            raise AuthorityUnavailable("foreground source family crossed namespace")
        row = _artifact_receipt_sql_v1(db,"SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*namespace.as_tuple, key.token)).fetchone()
        versions[key] = 0 if row is None else row[0]
        if required and (row is None or row[2] != 1):
            raise AuthorityUnavailable("foreground current source family member is absent")
        return None if row is None else background_json_loads_v3(row[1])
    def visit(ref):
        if ref in active:
            raise AuthorityUnavailable("foreground source ancestry is cyclic")
        if ref in done:
            return
        if len(done) + len(active) >= 32:
            raise AuthorityUnavailable("foreground source closure exceeds its bounded window")
        key = AtomKey.from_token(ref)
        record = SourceRecord.from_dict(atom(key))
        if key != source_key(*namespace.as_tuple, record.source_id):
            raise AuthorityUnavailable("foreground Source key/payload identity differs")
        access = atom(access_key(*namespace.as_tuple, record.source_id))
        correction = source_correction_head_key(namespace, record.source_id)
        atom(correction, required=False)
        if (versions[correction] or access["source_id"] != record.source_id or access["status"] != "active"
                or purpose not in record.purposes or purpose not in access["purposes"]
                or not set(audiences) <= set(record.audiences) or not set(audiences) <= set(access["audiences"])):
            raise AuthorityUnavailable("foreground current source/access/correction qualification is denied")
        active.add(ref)
        for parent in record.parent_source_ids:
            visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        done.add(ref)
    for root in roots:
        visit(root)
    return tuple(GraphVersion(key, revision) for key, revision in sorted(versions.items(), key=lambda row: row[0].token))


class InstalledCurrentForegroundActivityV1:
    def __init__(self, *, self_identity_service, budget_issuer, clock_provider, filesystem_manifest=None, installed_bundle=None):
        if (type(self_identity_service) is not AuthorityV2SelfIdentityService
                or type(budget_issuer) is not D11BudgetJobIssuer
                or type(clock_provider) is not LinuxKernelClockProviderV1
                or self_identity_service._source_location is None or self_identity_service._owner_storage is None):
            raise TypeError("foreground requires the actual shared self/C09/Owner/budget/clock composition")
        self.self_identity = self_identity_service
        self.issuer, self.clock = budget_issuer, clock_provider
        if filesystem_manifest is not None and (type(filesystem_manifest) is not InstallationFilesystemManifestV2
                or filesystem_manifest.installation_id != self_identity_service._installation_id
                or filesystem_manifest.namespace != self_identity_service._fences.namespace):
            raise TypeError("foreground draft setup must use the protected installed C09 resource inventory")
        self.filesystem_manifest = filesystem_manifest
        if installed_bundle is not None:
            from ..host.authority_profile import AdminInstallationBundle
            if type(installed_bundle) is not AdminInstallationBundle:
                raise TypeError("foreground draft requires its actual installed typed bundle")
        self.installed_bundle = installed_bundle
        self._owner_stop_reply_service_v1 = None
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self,service=self,source_location=self_identity_service._source_location)


    def install_owner_stop_reply_service_v1(self, service):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(service) is not InstalledOwnerStopReplyServiceV1 or self._owner_stop_reply_service_v1 is not None
                or service.core is not self.self_identity._core or service.fences is not self.self_identity._fences
                or service.issuer is not self.issuer or service.namespace_id != self.self_identity._namespace_id):
            raise TypeError("foreground barrier needs the actual same-Core/fence/issuer StopReply service")
        self._owner_stop_reply_service_v1 = service

    def _observe_current_reply_scope_for_message_v1(self, *, authority_namespace, activity_id, effect_id,
            operation_id=None):
        from ..runtime.foreground_cycle_v1 import WORK_KIND, _read_reply_natural_metadata_v1, _read_reply_message_metadata_v1
        bundle = self.installed_bundle
        if bundle is None or WORK_KIND not in bundle.installation_policy.root_grant.allowed_work_kinds:
            return None
        service = self._owner_stop_reply_service_v1
        if service is None or authority_namespace != self.self_identity._fences.namespace:
            raise AuthorityUnavailable("message reply barrier lacks its actual installed namespace service")
        context, storage, _ = service._storage()
        ns = service.namespace_id
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            jobs = db.execute("SELECT job_id,operation_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                "AND activity_id=? AND effect_id=? AND work_kind='message' LIMIT 2",
                (*ns.as_tuple, activity_id, effect_id)).fetchall()
            if len(jobs) != 1 or (operation_id is not None and jobs[0][1] != operation_id):
                raise AuthorityUnavailable("message reply barrier lacks its unique actual final child job")
            committed = db.execute("SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
                "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, jobs[0][1])).fetchone()
            if committed is None or committed[:2] != (activity_id, effect_id):
                raise AuthorityUnavailable("message reply barrier lacks its actual adopted operation")
            actual_receipt = json.loads(committed[2])
            if "natural_dispatch_candidate" not in actual_receipt:
                from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
                original = read_adopted_domain_operation_v1(db, ns, jobs[0][1])
                if original is not None and original["operation_kind"] in {
                        "prepare_contact_dispatch", "prepare_contact_dispatch_v2", "prepare_contact_dispatch_v3"}:
                    return None
                candidate = actual_receipt.get("dispatch_candidate")
                if (type(candidate) is dict and candidate.get("schema") == "sylanne.d11.dispatch_candidate.v1"
                        and candidate.get("status") in {"source_hold", "source_qualified"}
                        and type(candidate.get("refs")) is list and len(candidate["refs"]) == 4):
                    return None
                raise AuthorityUnavailable("message technical family lacks its actual registered immutable producer")
            generation_refs = db.execute("SELECT json_extract(value,'$.paid_review.generation_original_operation_id') "
                "FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? AND valid=1 "
                "AND json_extract(value,'$.schema') IN ('d09.natural_verified_segment_batch.v2',"
                "'d09.natural_verified_segment_batch.v3') LIMIT 2", (*ns.as_tuple, jobs[0][1])).fetchall()
            if len(generation_refs) != 1:
                raise AuthorityUnavailable("message reply barrier lacks its immutable reviewed batch")
            parents = db.execute("SELECT parent_original_id FROM graph_natural_generation_preparations_v2 "
                "WHERE bot=? AND persona=? AND original_operation_id=? LIMIT 2",
                (*ns.as_tuple, generation_refs[0][0])).fetchall()
            if len(parents) != 1:
                raise AuthorityUnavailable("message reply barrier lacks its sealed actual C02 parent")
            c02_operation_id = parents[0][0]
            generation = _read_reply_natural_metadata_v1(db, ns, c02_operation_id, "generation")
            review = _read_reply_natural_metadata_v1(db, ns, c02_operation_id, "review")
            if generation is None or review is None:
                raise AuthorityUnavailable("message reply barrier generation/review originals are missing")
            matches = [job for job, _, _ in _read_reply_message_metadata_v1(db, namespace=ns,
                generation_seal=generation[0], review_seal=review[0]) if job.job_id == jobs[0][0]]
            if len(matches) != 1:
                raise AuthorityUnavailable("message reply barrier does not match the exact adopted whole batch")
        context.require_current("business")
        return service.observe_actual_reply_scope_v1(c02_operation_id=c02_operation_id)

    def observe_current_reply_scope_for_message_prepare_v1(self, *, namespace, permit, footprint):
        from .v2_contract import RecoveryConstraintFootprint
        with self.self_identity._core._lock:
            authority_id = self.self_identity._core._id(self.self_identity._core._db)
        if (type(permit) is not FencePermitV2 or type(footprint) is not RecoveryConstraintFootprint
                or permit.namespace != namespace or footprint.namespace != namespace
                or permit.authority_id != authority_id
                or not footprint.effect_id):
            raise AuthorityUnavailable("message reply scope requires the actual typed namespace/permit/footprint")
        return self._observe_current_reply_scope_for_message_v1(authority_namespace=namespace,
            activity_id=footprint.activity_id, effect_id=footprint.effect_id)

    def observe_current_reply_scope_for_message_claim_v1(self, binding):
        from .v2_contract import ExecutionBindingV2
        from ..graph_coordinator import namespace_ref
        if type(binding) is not ExecutionBindingV2 or binding.graph_namespace != namespace_ref(self.self_identity._namespace_id):
            raise TypeError("message reply scope requires its actual closed execution binding")
        return self._observe_current_reply_scope_for_message_v1(authority_namespace=binding.origin.namespace,
            activity_id=binding.origin.activity_id, effect_id=binding.origin.effect_id,
            operation_id=binding.origin.operation_id)

    def register_draft_root(self, *, credential, subject, permit, request,
            owner_actor_ref, owner_session_token, owner_session_request):
        """Explicit genuine Owner setup, separate from all ordinary activity calls."""
        service = self.self_identity
        if (type(request) is not DraftRootRegistrationRequestV1 or request.namespace != service._namespace_id
                or type(permit) is not FencePermitV2 or permit.operation != "write"
                or self.filesystem_manifest is None):
            raise AuthorityUnavailable("root registration needs its real installed resource and write fence")
        owner, observed = service._owner_storage.get_current_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=permit, actor=owner_actor_ref,
            session_token=owner_session_token, session_request=owner_session_request)
        if observed != permit:
            raise AuthorityUnavailable("root setup actual Owner session/fence differs")
        location = service._source_location.observe_business_for_fence_v1(credential=credential, subject=subject, permit=permit)
        if (location.context.manifest["inventory_manifest_digest"] != self.filesystem_manifest.manifest_digest
                or self.filesystem_manifest.authority_id != permit.authority_id):
            raise AuthorityUnavailable("root setup inventory is not the actual signed current C09 inventory")
        resources = tuple(resource for resource in self.filesystem_manifest.resources if resource.resource_id == request.resource_id)
        if (len(resources) != 1 or resources[0].kind != "export"
                or not {"jobs_drafts", "imports_exports"} <= set(resources[0].content_coverage)):
            raise AuthorityUnavailable("root setup target is not a registered draft/export carrier")
        reading = self.clock()
        until = datetime.fromisoformat(request.valid_until_utc.replace("Z", "+00:00")).timestamp()
        if not reading.utc_seconds + reading.utc_error_seconds < until:
            raise AuthorityUnavailable("root setup explicit authorization is expired")
        path = Path(location.graph_db_path)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            service._source_location.require_graph_snapshot_v1(db, location, graph_db_path=path)
            attempt = db.execute("SELECT request_digest FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
                (*request.namespace.as_tuple, request.operation_id)).fetchone()
            if attempt != (draft_root_registration_operation_digest_v1(request, owner_actor_ref),):
                raise AuthorityUnavailable("root setup request is not the actual explicit Owner operation intent")
            grant_key = owner_grant_key(*request.namespace.as_tuple)
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (grant_key.token,)).fetchone()
            source = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (request.source_ref,)).fetchone()
            if row is None or row[2] != 1 or source is None or source[1] != 1:
                raise AuthorityUnavailable("root setup lacks the actual current Owner grant/permission Source")
            value = json.loads(row[1])
            if request.purpose not in value["purposes"] or not set(request.audiences) <= set(value["audiences"]):
                raise AuthorityUnavailable("root setup purpose/audiences exceed the actual upstream Owner grant")
            record = SourceRecord.from_dict(json.loads(source[0]))
            ingress = read_committed_ingress_identity(db, request.namespace, record.source_id)
            if ingress is None or "workbench.create" not in value["capabilities"]:
                raise AuthorityUnavailable("root setup permission Source is not an actual observed ingress")
            guard = ProductionOwnerGuardV1(grant_key.token, row[0], canonical_digest(value),
                owner.guard.authorization_head.removeprefix("sha256:"))
            source_versions = _source_family_current_sql_v1(db, namespace=request.namespace,
                roots=(request.source_ref,), purpose=request.purpose, audiences=request.audiences)
            epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", request.namespace.as_tuple).fetchone()[0]
            read_versions = (GraphVersion(grant_key, row[0]), *source_versions)
        from .c09_storage_control_v1 import _directory_path
        from .d11_artifact_draft_executor_v1 import _pinned_root
        directory = _directory_path(Path(resources[0].path))
        stat = directory.stat(follow_symlinks=False)
        identity = DraftFileIdentityV1(stat.st_dev, stat.st_ino)
        with _pinned_root(directory, identity):
            registration_ref = "draft-root:" + canonical_digest((request.namespace, request.operation_id,
                request.resource_id, request.source_ref))[:48]
            capability = DraftRootCapabilityV1(service._installation_id, service._manifest_digest,
                request.resource_id, registration_ref, identity, request.filenames, request.max_bytes,
                request.valid_until_utc, request.source_ref, guard.grant_ref, guard.grant_revision, guard.grant_digest)
        after, after_permit = service._owner_storage.get_current_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=permit, actor=owner_actor_ref,
            session_token=owner_session_token, session_request=owner_session_request)
        if after_permit != permit or after.guard != owner.guard:
            raise AuthorityUnavailable("root setup current Owner changed during actual resource observation")
        return DraftRootRegistrationEvidenceV1(request, owner_actor_ref, guard, capability, permit,
            read_versions, QueryEpoch(request.namespace, "namespace", epoch)), permit

    def current(self, *, credential, subject, permit, request):
        service = self.self_identity
        request_types={ForegroundActivityRequestV1,ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}
        if type(request) not in request_types:raise AuthorityUnavailable('unregistered foreground request version')
        fence_id=(foreground_fence_operation_id_v1(request) if type(request) is ForegroundActivityRequestV1 else foreground_fence_operation_id_v2(request))
        if (type(permit) is not FencePermitV2
                or request.namespace != service._namespace_id or request.installation_id != service._installation_id
                or permit.operation != "write" or subject != service._read_subject
                or permit.operation_id != fence_id):
            raise AuthorityUnavailable("foreground actual installation/Host subject/write fence differs")
        stop_service = self._owner_stop_reply_service_v1
        if stop_service is None:
            raise AuthorityUnavailable("foreground admission lacks its actual installed Core reply barrier")
        stop_service.require_reply_cycle_not_retired_v1(c02_operation_id=request.c02_operation_id)
        service._fences.validate_fence(credential=credential, subject=subject, permit=permit)
        from .original_foreground_source_read_v3 import observe_original_activity_current_v3
        result,job_value=observe_original_activity_current_v3(self,credential=credential,subject=subject,permit=permit,request=request)
        if job_value is None:
            context, _, _ = stop_service._storage()
            with stop_service.core._tx() as core_db:
                stop_service.require_reply_cycle_not_retired_in_tx_v1(core_db, context=context,
                    c02_operation_id=request.c02_operation_id)
        else:
            from .owner_stop_reply_v1 import require_reply_scope_not_stopped_in_tx_v1
            actual_scope = stop_service.observe_actual_reply_scope_v1(c02_operation_id=request.c02_operation_id)
            with stop_service.core._tx() as core_db:
                require_reply_scope_not_stopped_in_tx_v1(core_db, authority_namespace=service._fences.namespace,
                    installation_id=service._installation_id, activation_generation=permit.generation,
                    actual_cycle_identity=actual_scope, action="foreground")
        service._fences.validate_fence(credential=credential, subject=subject, permit=permit)
        return result, permit

    def _read_current_graph_v3(self, db, *, credential, subject, permit, request, current_self, current_owner, location, now):
        service = self.self_identity
        path = Path(location.graph_db_path)
        from .current_authority_graph_read_v3 import authority_current_json_v3
        from .foreground_mesh_source_read_v3 import read_foreground_mesh_point_v3 as read_authority_current_point_v3
        from .foreground_mesh_source_read_v3 import read_foreground_mesh_c02_history_v3
        if db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", request.namespace.as_tuple).fetchone() != (current_self.graph_epoch,):
            raise AuthorityUnavailable("foreground actual Graph query epoch differs from the independent self read")
        versions = {}
        def atom(ref, required=True):
            key = AtomKey.from_token(ref) if type(ref) is str else ref
            if NamespaceId.from_key(key) != request.namespace:
                raise AuthorityUnavailable("foreground read crossed its actual namespace")
            row = read_authority_current_point_v3(db, table="graph_atoms", columns=("revision","value","valid"),
                key_columns=("token","bot","persona"), key=(key.token,*request.namespace.as_tuple),
                legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                    (*request.namespace.as_tuple,key.token)).fetchone())
            revision = 0 if row is None else row[0]
            versions[key] = revision
            if required and (row is None or not row[2]):
                raise AuthorityUnavailable("foreground current required head is absent")
            return None if row is None else authority_current_json_v3(row[1])
        owner_key = owner_grant_key(*request.namespace.as_tuple)
        owner = atom(owner_key)
        if (request.purpose not in owner["purposes"] or not set(request.audiences) <= set(owner["audiences"])
                or "workbench.create" not in owner["capabilities"]):
            raise AuthorityUnavailable("foreground purpose/audience exceeds the real upstream grant")
        mapping = atom(self_mapping_key(request.namespace))
        from ..domains.d01.production_operations_v1 import plain_v1
        if mapping != plain_v1(self_identity_mapping_from_current(current_self)):
            raise AuthorityUnavailable("foreground actual Graph self mapping differs from independent Authority")
        cue = atom(request.cue_source_ref)
        ingress = read_committed_ingress_identity(db, request.namespace, SourceRecord.from_dict(cue).source_id)
        if ingress is None or json.loads(ingress.identity_json)["operation_id"] != request.ingress_operation_id:
            raise AuthorityUnavailable("foreground cue lacks its original four-ledger ingress witness")
        c02 = read_authority_current_point_v3(db, table="graph_bundle_operations", columns=("digest","receipt_json"),
            key_columns=("bot","persona","operation_id"), key=(*request.namespace.as_tuple,request.c02_operation_id),
            legacy_reader=lambda: db.execute("SELECT digest,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*request.namespace.as_tuple,request.c02_operation_id)).fetchone())
        if c02 is None or "first_ingress_c02" not in authority_current_json_v3(c02[1]):
            raise AuthorityUnavailable("foreground requires an actual adopted C02 original")
        episode_refs = set()
        for token, revision, encoded in read_foreground_mesh_c02_history_v3(db, namespace=request.namespace, operation_id=request.c02_operation_id,
                legacy_reader=lambda: tuple(db.execute("SELECT token,revision,value FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? AND valid=1",
                    (*request.namespace.as_tuple,request.c02_operation_id)))):
            key = AtomKey.from_token(token)
            if key.type_name == "memory.episode.v1" and request.cue_source_ref in authority_current_json_v3(encoded)["source_refs"]:
                current = atom(key)
                if current != authority_current_json_v3(encoded) or versions[key] != revision:
                    raise AuthorityUnavailable("foreground C02 cue episode changed")
                episode_refs.add(key.token)
        trace_refs = []
        for token, revision, encoded in read_foreground_mesh_c02_history_v3(db, namespace=request.namespace, operation_id=request.c02_operation_id,
                legacy_reader=lambda: tuple(db.execute("SELECT token,revision,value FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? AND valid=1",
                    (*request.namespace.as_tuple,request.c02_operation_id)))):
            key = AtomKey.from_token(token)
            if key.type_name == "memory.subjective_trace.v2" and authority_current_json_v3(encoded)["episode_ref"] in episode_refs:
                current = atom(key)
                if current != authority_current_json_v3(encoded) or versions[key] != revision:
                    raise AuthorityUnavailable("foreground C02 subjective trace changed")
                trace_refs.append(key.token)
        if len(episode_refs) != 1 or len(trace_refs) != 1:
            raise AuthorityUnavailable("foreground C02 episode does not belong to the actual cue")
        job_value = atom(request.cycle_job_ref, required=request.expected_cycle_revision > 0)
        job_key = AtomKey.from_token(request.cycle_job_ref)
        activity_id, job_id = foreground_cycle_ids_v1(request.namespace, request.c02_operation_id)
        c04_selection = None
        if request.operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
            from ..runtime.c04_foreground_selection_v4 import qualify_self_c04_foreground_v4
            c04_selection, c04_ids, c04_versions = qualify_self_c04_foreground_v4(
                db, request=request, bundle=self.installed_bundle, issuer=self.issuer)
            versions.update(c04_versions)
        expected_activity = activity_id if c04_selection is None else c04_selection.child_activity_id
        if request.activity_id != expected_activity or job_key != runtime_job_key(*request.namespace.as_tuple, activity_id, job_id):
            raise AuthorityUnavailable("foreground cycle must retain its stable adopted C02 identity")
        if versions[job_key] != request.expected_cycle_revision:
            raise AuthorityUnavailable("foreground cycle CAS revision changed")
        deadline = request.requested_deadline_utc
        from ..runtime.source_note_foreground_v1 import (OPERATION as NOTE_CREATE_OPERATION,
            ForegroundSourceNoteContinuationV1, qualify_source_note_foreground_v1)
        note_job = None if job_value is None else get_job(db, job_key.name)
        note_mode = (request.operation_kind == NOTE_CREATE_OPERATION or note_job is not None
            and type(foreground_cycle_from_wire_v1(note_job.continuation)) is ForegroundSourceNoteContinuationV1)
        note_authorization = None
        if request.operation_kind in {"prepare_selected_source_note_action_v2", "prepare_source_note_body",
                "input:register_life_plan_v2", "checkpoint_source_note_foreground_cycle_v1"} and not note_mode:
            raise AuthorityUnavailable("SourceNote named Self operation requires its actual SourceNote responsibility")
        if note_mode:
            note_guard = ProductionOwnerGuardV1(owner_key.token, versions[owner_key], canonical_digest(owner),
                current_owner.guard.authorization_head.removeprefix("sha256:"))
            note_authorization = qualify_source_note_foreground_v1(db, request=request, job=note_job,
                issuer=self.issuer, installed_bundle=self.installed_bundle, owner_guard=note_guard,
                now_utc=now, atom=atom)
            deadline = min(deadline, note_authorization.original_deadline_utc)
        if request.operation_kind == "prepare_ingress_recall_model_v1":
            from ..runtime.d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
            if (request.operation_id != ingress_recall_model_ids_v1(
                    request.namespace, request.c02_operation_id)["prepare"]
                    or request.purpose != ("consolidation" if note_mode or request.draft_root_registration_ref is not None else "context")):
                raise AuthorityUnavailable("Self C3 changed its fixed identity/purpose")
        if job_value is not None:
            if request.operation_kind in {"create_foreground_cycle", "create_foreground_cycle_v2", "derive_ingress_artifact_task_scope_v1", "create_source_note_foreground_cycle_v1"}:
                raise AuthorityUnavailable("foreground create requires its observed absent cycle target")
            job = get_job(db, job_key.name)
            continuation = foreground_cycle_from_wire_v1(job.continuation)
            if (job.work_kind != WORK_KIND or job.activity_id != activity_id or job.budget_ref != request.parent_budget_lease_ref
                    or job.cancel_epoch != request.expected_cancel_generation or job.cancel_epoch
                    or continuation.c02_operation_id != request.c02_operation_id
                    or continuation.source_ref != request.cue_source_ref):
                raise AuthorityUnavailable("foreground cycle origin/control generation differs")
            if job_graph_write(job).value != job_value or job.phase in {"completed", "failed", "cancelled", "draining"}:
                raise AuthorityUnavailable("foreground actual SQL/Graph job is terminal, draining or inconsistent")
            if request.operation_kind in {"wake_foreground_cycle", "wake_artifact_draft_cycle_v1", "wake_artifact_draft_cycle_v2"}:
                if job.phase not in {"waiting", "deferred"}:
                    raise AuthorityUnavailable("foreground wake requires its original waiting/deferred job")
            elif request.operation_kind == "acquire_foreground_cycle":
                if job.phase != "queued" or job.lease_holder is not None:
                    raise AuthorityUnavailable("foreground acquire requires its actual queued unleased job")
            elif request.operation_kind in {"prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
                from ..runtime.d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
                from ..runtime.d07_ingress_recall_result_v1 import ingress_recall_result_operation_id_v1, ADOPT_OPERATION
                from ..runtime.d07_execution_v1 import D07IngressRecallPreparedV1, read_prepared_d07_execution_v1
                original = read_prepared_d07_execution_v1(db, self.issuer, request.namespace,
                    ingress_recall_model_ids_v1(request.namespace, request.c02_operation_id)["job"])
                if (type(original) is not D07IngressRecallPreparedV1
                        or job.phase not in {"waiting", "deferred"}
                        or original.cycle_job_ref != request.cycle_job_ref
                        or request.operation_id != ingress_recall_result_operation_id_v1(
                            request.namespace, request.c02_operation_id, request.operation_kind)):
                    raise AuthorityUnavailable("Self C3 result needs its exact unretired parent/preparation")
                child = get_job(db, original.job_id)
                required_phase = "completed" if request.operation_kind == ADOPT_OPERATION else "running"
                if (child.phase != required_phase or child.fence != 1 or child.cancel_epoch
                        or atom(job_graph_write(child).key) != job_graph_write(child).value
                        or required_phase == "running" and (child.lease_expires_utc is None
                            or now >= datetime.fromisoformat(child.lease_expires_utc.replace("Z", "+00:00")).timestamp())):
                    raise AuthorityUnavailable("Self C3 result has no current actual worker/terminal")
            elif request.operation_kind == "adopt_ingress_c04_v1":
                from ..runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
                from ..runtime.c04_frozen_association_original_v3 import read_c04_frozen_association_original_v4
                from ..runtime.c04_ingress_preparation_v4 import require_current_self_c04_parent_v4
                prepared = read_c04_internal_work_prepared_v1(db, request.namespace, c04_ids["prepare"])
                work = read_c04_frozen_association_original_v4(db, request.namespace, prepared.binding)
                require_current_self_c04_parent_v4(db, namespace=request.namespace,
                    binding=prepared.binding, work=work, prepared=prepared, installed_bundle=self.installed_bundle,
                    issuer=self.issuer, current_self=current_self, now_utc=now)
            elif request.operation_kind == "acquire_ingress_recall_model_v1":
                from ..runtime.d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
                from ..runtime.d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1
                from ..runtime.d07_execution_v1 import D07IngressRecallPreparedV1, read_prepared_d07_execution_v1
                original = read_prepared_d07_execution_v1(db, self.issuer, request.namespace,
                    ingress_recall_model_ids_v1(request.namespace, request.c02_operation_id)["job"])
                if (type(original) is not D07IngressRecallPreparedV1
                        or job.phase not in {"waiting", "deferred"}
                        or request.operation_id != ingress_recall_acquire_operation_id_v1(request.namespace, request.c02_operation_id)
                        or original.cycle_job_ref != request.cycle_job_ref):
                    raise AuthorityUnavailable("Self C3 acquire needs its original waiting cycle/preparation")
                child = get_job(db, original.job_id)
                if (child.phase != "queued" or child.fence or child.cancel_epoch
                        or child.lease_holder is not None or child.result_ref is not None
                        or atom(job_graph_write(child).key) != job_graph_write(child).value):
                    raise AuthorityUnavailable("Self C3 acquire changed its actual once queued job")
            elif request.operation_kind == 'acquire_artifact_draft_model_v2':
                from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV2
                if (type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3} or job.phase != 'waiting'
                        or job.lease_holder is not None or job.lease_expires_utc is not None):
                    raise AuthorityUnavailable('phase acquisition requires its actual released waiting current group')
            elif request.operation_kind == "acquire_artifact_draft_model":
                if job.phase not in {"waiting", "deferred"}:
                    raise AuthorityUnavailable("C4 acquire requires the original released waiting cycle")
                from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1, artifact_draft_model_ids_v1
                from ..runtime.d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v1
                selector = artifact_draft_task_selector_v1(request.namespace, c02_operation_id=request.c02_operation_id,
                    root_registration_ref=request.draft_root_registration_ref)
                prepared = read_artifact_draft_prepared_v1(db, namespace=request.namespace, issuer=self.issuer, selector=selector)
                if prepared is None:
                    raise AuthorityUnavailable("C4 acquire has no actual committed prepared original")
                model_job = get_job(db, prepared.job_id)
                if (model_job.phase != "queued" or model_job.fence or model_job.cancel_epoch
                        or model_job.lease_holder is not None or model_job.result_ref is not None
                        or request.operation_id != artifact_draft_model_ids_v1(selector)["acquire"]):
                    raise AuthorityUnavailable("C4 acquire changed its actual once queued job")
                if atom(job_graph_write(model_job).key) != job_graph_write(model_job).value:
                    raise AuthorityUnavailable("C4 acquire actual SQL/Graph worker job differs")
            elif (job.phase != "running" or (job.lease_holder, job.fence, job.lease_expires_utc) !=
                    (request.worker_holder, request.worker_fence, request.worker_lease_expires_utc)
                    or job.lease_expires_utc is None or now >= datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp()):
                raise AuthorityUnavailable("foreground work needs its actual unexpired worker holder/fence/lease")
            deadline = min(deadline, datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp())
        elif request.operation_kind not in {"create_foreground_cycle", "create_foreground_cycle_v2", "derive_ingress_artifact_task_scope_v1", "create_source_note_foreground_cycle_v1"} or request.expected_cancel_generation:
            raise AuthorityUnavailable("only explicit cycle creation may use its observed absent target")
        permitted_sources = {request.cue_source_ref}
        artifact_operations = {"await_existing_artifact_revision_v1", "select_existing_artifact_continuation_v1", "revise_existing_artifact_v1", "wake_artifact_draft_cycle_v1", "prepare_artifact_draft_model", "acquire_artifact_draft_model", "adopt_artifact_draft_content",
            "compose_artifact_goal_plan", "create_artifact_project", "prepare_artifact_draft_project_context",
            "propose_artifact_draft_action", "prepare_artifact_draft_body", "input:register_artifact_draft_plan_v3", "prepare_life"}
        artifact_operations.update(_ARTIFACT_PHASE_OPERATIONS_V2 | _ARTIFACT_PHASE_FILE_OPERATIONS_V2 | _ARTIFACT_INITIAL_TASK_OPERATIONS_V1 | _ARTIFACT_PREDECISION_OPERATIONS_V2 | _ARTIFACT_AMENDMENT_PLAN_OPERATIONS_V2 | _METHOD_FACT_OPERATIONS_V1)
        if request.draft_root_registration_ref is not None:
            artifact_operations.update(("finish_artifact_receipt_cycle_v1", "derive_artifact_completion_receipt_v1", "initialize_project_checkpoint", "refresh_project_checkpoint", "settle_project_checkpoint",
                "input:register_life_outcome_v2", "advance_life", "settle_personal_goal"))
        if note_mode:
            permitted_sources.update(note_authorization.source_refs)
        elif type(request) in {ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}:
            guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                current_owner.guard.authorization_head.removeprefix('sha256:'))
            sources,preparation_deadline=_qualify_artifact_preparation_foreground_v2(db,request=request,job=job,
                continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                current_self=current_self,owner_guard=guard,now=now,atom=atom)
            permitted_sources.update(sources);deadline=min(deadline,preparation_deadline)
        elif request.operation_kind in artifact_operations:
            if request.draft_root_registration_ref is None or self.installed_bundle is None:
                raise AuthorityUnavailable("artifact stage needs actual installed task policy and registered root")
            from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV2
            phase_file = (job_value is not None and type(continuation.call_plan) in {ForegroundCallPlanV2,ForegroundCallPlanV3}
                and request.operation_kind in _ARTIFACT_PHASE_FILE_OPERATIONS_V2)
            if request.operation_kind in _METHOD_FACT_OPERATIONS_V1:
                from ..runtime.d02_method_readiness_v1 import qualify_current_method_foreground_v1
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,method_deadline=qualify_current_method_foreground_v1(db,request=request,job=job,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    current_self=current_self,owner_guard=guard,now=now,atom=atom)
                permitted_sources.update(sources);deadline=min(deadline,method_deadline)
            elif request.operation_kind=='finish_artifact_receipt_cycle_v1':
                from ..runtime.artifact_receipt_completion_v1 import qualify_artifact_receipt_completion_foreground_v1
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,receipt_deadline=qualify_artifact_receipt_completion_foreground_v1(db,request=request,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    owner_guard=guard,now_utc=now)
                permitted_sources.update(sources);deadline=min(deadline,receipt_deadline)
            elif request.operation_kind=='derive_artifact_completion_receipt_v1':
                from ..runtime.artifact_completion_receipt_v1 import qualify_artifact_completion_receipt_foreground_v1
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,receipt_deadline=qualify_artifact_completion_receipt_foreground_v1(db,request=request,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    owner_guard=guard,now_utc=now)
                permitted_sources.update(sources);deadline=min(deadline,receipt_deadline)
            elif (job_value is not None and type(continuation.call_plan) in {ForegroundCallPlanV2,ForegroundCallPlanV3}
                    and request.operation_kind in _ARTIFACT_PHASE_FINAL_OPERATIONS_V2):
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,final_deadline=_qualify_artifact_method_final_foreground_v2(db,request=request,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    owner_guard=guard,now=now,atom=atom)
                permitted_sources.update(sources);deadline=min(deadline,final_deadline)
            elif request.operation_kind in _ARTIFACT_AMENDMENT_PLAN_OPERATIONS_V2:
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,task_deadline=_qualify_artifact_task_plan_revision_foreground_v2(db,request=request,job=job,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    current_self=current_self,owner_guard=guard,now=now,atom=atom)
                permitted_sources.update(sources);deadline=min(deadline,task_deadline)
            elif request.operation_kind in _ARTIFACT_PREDECISION_OPERATIONS_V2:
                guard=ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources,task_deadline=_qualify_artifact_task_predecision_foreground_v2(db,request=request,job=job,
                    continuation=continuation,issuer=self.issuer,installed_bundle=self.installed_bundle,
                    current_self=current_self,owner_guard=guard,now=now,atom=atom)
                permitted_sources.update(sources);deadline=min(deadline,task_deadline)
            elif request.operation_kind in _ARTIFACT_INITIAL_TASK_OPERATIONS_V1:
                guard = ProductionOwnerGuardV1(owner_key.token, versions[owner_key], canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources, task_deadline = _qualify_artifact_initial_task_foreground_v1(db, request=request, job=job,
                    continuation=continuation, issuer=self.issuer, installed_bundle=self.installed_bundle,
                    owner_guard=guard, now=now, atom=atom)
                permitted_sources.update(sources)
                deadline = min(deadline, task_deadline)
            elif request.operation_kind in _ARTIFACT_PHASE_OPERATIONS_V2 or phase_file:
                guard = ProductionOwnerGuardV1(owner_key.token, versions[owner_key], canonical_digest(owner),
                    current_owner.guard.authorization_head.removeprefix('sha256:'))
                sources, phase_deadline = _qualify_artifact_phase_foreground_v2(db, request=request, job=job,
                    continuation=continuation, issuer=self.issuer, installed_bundle=self.installed_bundle,
                    current_self=current_self, owner_guard=guard, now=now, atom=atom)
                permitted_sources.update(sources)
                deadline = min(deadline, phase_deadline)
            else:
                from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1, artifact_draft_model_ids_v1
                selector = artifact_draft_task_selector_v1(request.namespace, c02_operation_id=request.c02_operation_id,
                    root_registration_ref=request.draft_root_registration_ref)
                ids = artifact_draft_model_ids_v1(selector)
                if request.operation_kind in {"prepare_artifact_draft_model", "acquire_artifact_draft_model", "adopt_artifact_draft_content"}:
                    expected = ids[{"prepare_artifact_draft_model": "prepare", "acquire_artifact_draft_model": "acquire", "adopt_artifact_draft_content": "adopt"}[request.operation_kind]]
                    if request.operation_id != expected:
                        raise AuthorityUnavailable("artifact stage changed its original fixed operation identity")
                if request.operation_kind in {"await_existing_artifact_revision_v1", "select_existing_artifact_continuation_v1", "revise_existing_artifact_v1"}:
                    from ..runtime.artifact_continuation_originals_v1 import (
                        discover_existing_artifact_continuation_request_v1, artifact_continuation_operation_id_v1)
                    from ..runtime.domain_production_registry_v1 import installed_operation_v1
                    actual = discover_existing_artifact_continuation_request_v1(db, namespace=request.namespace,
                        selector=selector, issuer=self.issuer)
                    from ..runtime.artifact_wait_checkpoint_v1 import artifact_wait_operation_id_v1
                    expected = (artifact_wait_operation_id_v1(selector)
                        if request.operation_kind == "await_existing_artifact_revision_v1"
                        else artifact_continuation_operation_id_v1(selector,
                            revision=request.operation_kind == "revise_existing_artifact_v1"))
                    if (actual is None or request.operation_id != expected
                            or request.request_digest != foreground_typed_command_digest_v1(
                                installed_operation_v1(request.operation_kind), actual)):
                        raise AuthorityUnavailable("artifact continuation differs from actual unique project/file selection")
                if request.operation_kind not in {"prepare_artifact_draft_model", "acquire_artifact_draft_model", "adopt_artifact_draft_content", "wake_artifact_draft_cycle_v1", "await_existing_artifact_revision_v1", "select_existing_artifact_continuation_v1"}:
                    from ..runtime.d11_artifact_draft_content_v1 import artifact_draft_content_from_wire_v1, ArtifactDraftContentAdoptionV1
                    adopted = _read(db, issuer=self.issuer, namespace=request.namespace, kind="c4_adopted", ref=ids["adopt"])
                    if adopted is None:
                        raise AuthorityUnavailable("artifact continuation has no actual adopted paid content")
                    content = artifact_draft_content_from_wire_v1(adopted[0], ArtifactDraftContentAdoptionV1)
                    if content.selector != selector or content.task_source.ref != request.cue_source_ref:
                        raise AuthorityUnavailable("artifact adopted content belongs to another actual task")
                    permitted_sources.update(content.content.source_refs)
        if request.operation_kind=="prepare_artifact_draft_project_context":
            from ..host.authority_profile import AdminArtifactDraftPolicyV2
            if type(self.installed_bundle.artifact_draft) is AdminArtifactDraftPolicyV2:
                from ..runtime.artifact_continuation_originals_v1 import artifact_control_keys_for_task_v1
                from ..runtime.d03_life_project_context_v1 import PrepareArtifactDraftProjectContextRequestV1
                from ..runtime.domain_production_registry_v1 import installed_operation_v1
                standing=self.installed_bundle.artifact_draft.standing_scope
                keys=artifact_control_keys_for_task_v1(db,namespace=request.namespace,c02_operation_id=request.c02_operation_id,
                    root_registration_ref=request.draft_root_registration_ref)
                atom(keys[2]);atom(keys[3])
                body=PrepareArtifactDraftProjectContextRequestV1(keys[2].token,keys[3].token,
                    request.cue_source_ref,standing.social_role,standing.norm_refs)
                if request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body):
                    raise AuthorityUnavailable("Self project role differs from initial installed standing selection")
        if request.plan_ref is not None:
            plan = atom(request.plan_ref)
            if AtomKey.from_token(request.plan_ref).type_name != "d08.personal_plan.v1":
                raise AuthorityUnavailable("foreground current task source expansion needs its adopted personal plan")
            permitted_sources.update(plan["source_refs"])
        if request.plan_source_ref not in permitted_sources:
            raise AuthorityUnavailable("foreground source is outside the already adopted task closure")
        source_versions = _source_family_current_sql_v1(db, namespace=request.namespace,
            roots=tuple(sorted(permitted_sources)),
            purpose=request.purpose, audiences=request.audiences)
        for version in source_versions:
            versions[version.key] = version.revision
        grant = self.issuer.current_budget_grant(db, request.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        require_budget_family_admissible(db, grant.lease_id)
        if (lease.state != "active" or (grant.bot_id, grant.persona_id) != request.namespace.as_tuple
                or WORK_KIND not in grant.allowed_work_kinds):
            raise AuthorityUnavailable("foreground original signed root budget does not cover internal cycle work")
        if not note_mode and request.operation_kind in artifact_operations | {"derive_ingress_artifact_task_scope_v1"} and not {"artifact_draft_v1", "d10.life.artifact_draft.v1"} <= set(grant.allowed_work_kinds):
            raise AuthorityUnavailable("artifact stages exceed the actual current signed model/file grant")
        current_guard = ProductionOwnerGuardV1(owner_key.token, versions[owner_key], canonical_digest(owner),
            current_owner.guard.authorization_head.removeprefix("sha256:"))
        from ..runtime.foreground_cycle_v1 import (CreateForegroundCycleRequestV2, derive_current_foreground_responsibility_v1,
            foreground_post_c02_cause_ref_v1, require_current_foreground_responsibility_v1)
        if request.operation_kind == "create_source_note_foreground_cycle_v1":
            from ..runtime.source_note_foreground_v1 import (CreateSourceNoteForegroundCycleRequestV1,
                derive_source_note_foreground_responsibility_v1)
            from ..runtime.foreground_cycle_v1 import InstalledForegroundCycleReadersV1
            responsibility, authorization = derive_source_note_foreground_responsibility_v1(db, namespace=request.namespace,
                request=CreateSourceNoteForegroundCycleRequestV1(note_authorization.original_ref),
                installed_readers=InstalledForegroundCycleReadersV1(self.issuer, self.installed_bundle),
                owner_guard=current_guard, parent_budget_lease_ref=request.parent_budget_lease_ref,
                purpose=request.purpose, audiences=request.audiences, now_utc=now)
            if request.requested_deadline_utc != responsibility.deadline_utc:
                raise AuthorityUnavailable("SourceNote initial request changed its immutable authorized causal deadline")
            deadline = responsibility.deadline_utc
        elif request.operation_kind == "create_foreground_cycle_v2":
            from ..runtime.artifact_receipt_allocation_v3 import select_initial_foreground_reply_budget_ids_v3
            from ..runtime.domain_production_registry_v1 import installed_operation_v1
            cause_ref = request.draft_root_registration_ref or foreground_post_c02_cause_ref_v1(request.namespace, request.c02_operation_id)
            body = CreateForegroundCycleRequestV2(request.c02_operation_id, request.cue_source_ref,
                select_initial_foreground_reply_budget_ids_v3(request.namespace, request.c02_operation_id,
                    installed_bundle=self.installed_bundle, draft_root_registration_ref=request.draft_root_registration_ref)[0],
                cause_original_ref=cause_ref, draft_root_registration_ref=request.draft_root_registration_ref)
            if request.request_digest != foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind), body):
                raise AuthorityUnavailable("new cycle request differs from its fixed actual cause/root body")
            responsibility = derive_current_foreground_responsibility_v1(db, namespace=request.namespace, request=body,
                installed_bundle=self.installed_bundle, issuer=self.issuer, owner_guard=current_guard,
                parent_budget_lease_ref=request.parent_budget_lease_ref, purpose=request.purpose, audiences=request.audiences, now_utc=now)
            if request.requested_deadline_utc != responsibility.deadline_utc:
                raise AuthorityUnavailable("new cycle requested window differs from its actual immutable responsibility")
            deadline = responsibility.deadline_utc
        elif job_value is not None:
            require_current_foreground_responsibility_v1(db, namespace=request.namespace, job=job,
                installed_bundle=self.installed_bundle, issuer=self.issuer, owner_guard=current_guard,
                purpose=request.purpose, audiences=request.audiences, now_utc=now)
        deadline = min(deadline, grant.valid_until_utc)
        root = None
        if request.operation_kind == "derive_ingress_artifact_task_scope_v1":
            from ..runtime.ingress_artifact_task_scope_v1 import (DeriveIngressArtifactTaskScopeRequestV1,
                derive_task_scope_candidate_v1,active_task_objectives_v1)
            from ..runtime.domain_production_registry_v1 import installed_operation_v1
            from .c09_storage_control_v1 import _directory_path
            from .d11_artifact_draft_executor_v1 import _pinned_root
            body=DeriveIngressArtifactTaskScopeRequestV1(request.c02_operation_id,request.cue_source_ref)
            if (request.draft_root_registration_ref is not None or request.purpose!="consolidation"
                    or request.plan_source_ref!=request.cue_source_ref
                    or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)):
                raise AuthorityUnavailable("Self task derivation changed its exact C02/Source body")
            resources=tuple(r for r in self.filesystem_manifest.resources
                if r.resource_id==self.installed_bundle.artifact_draft.tool_scope.resource_id)
            if (self.filesystem_manifest.authority_id!=permit.authority_id
                    or location.context.manifest["inventory_manifest_digest"]!=self.filesystem_manifest.manifest_digest
                    or len(resources)!=1 or resources[0].kind!="export"
                    or not {"jobs_drafts","imports_exports"}<=set(resources[0].content_coverage)):
                raise AuthorityUnavailable("Self task scope lacks its actual signed C09 draft/export resource")
            directory=_directory_path(Path(resources[0].path));stat=directory.stat(follow_symlinks=False)
            identity=DraftFileIdentityV1(stat.st_dev,stat.st_ino)
            with _pinned_root(directory,identity):
                task,objective=derive_task_scope_candidate_v1(db,bundle=self.installed_bundle,issuer=self.issuer,
                    request=body,owner_guard=current_guard,root_identity=identity,now_utc=now)
            for obj in active_task_objectives_v1(db,request.namespace,self.issuer):atom(obj.goal_ref)
            if objective is not None:
                atom(objective.goal_ref,required=task.task_kind=="continue")
                atom(objective.plan_ref,required=task.task_kind=="continue")
            root=task.root
            root_deadline=datetime.fromisoformat(root.valid_until_utc.replace("Z","+00:00")).timestamp()
            if request.requested_deadline_utc!=root_deadline:
                raise AuthorityUnavailable("Self task root deadline differs from original installed intersection")
            deadline=min(deadline,root_deadline)
        elif request.draft_root_registration_ref is not None:
            original = _read(db, issuer=self.issuer, namespace=request.namespace,
                kind="draft_root_capability", ref=request.draft_root_registration_ref)
            if original is None:
                raise AuthorityUnavailable("foreground root requires its actual prior authorized registration")
            root = draft_from_wire_v1(original[0], DraftRootCapabilityV1)
            if (root.source_ref != (request.cue_source_ref if type(request) in {ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2} or request.operation_kind in _ARTIFACT_PHASE_OPERATIONS_V2 | _ARTIFACT_INITIAL_TASK_OPERATIONS_V1 | _ARTIFACT_PREDECISION_OPERATIONS_V2 | _ARTIFACT_AMENDMENT_PLAN_OPERATIONS_V2 or (job_value is not None and type(continuation.call_plan) in {ForegroundCallPlanV2,ForegroundCallPlanV3} and request.operation_kind in _ARTIFACT_PHASE_FILE_OPERATIONS_V2 | _ARTIFACT_PHASE_FINAL_OPERATIONS_V2) else request.plan_source_ref) or root.installation_id != service._installation_id
                    or root.manifest_digest != service._manifest_digest or root.owner_grant_ref != owner_key.token
                    or root.owner_grant_revision != versions[owner_key] or root.owner_grant_digest != canonical_digest(owner)):
                raise AuthorityUnavailable("foreground draft root belongs to another original scope")
            deadline = min(deadline, datetime.fromisoformat(root.valid_until_utc.replace("Z", "+00:00")).timestamp())
        if not now < deadline:
            raise AuthorityUnavailable("foreground original deadline is expired or unverifiable")
        evidence_type=ForegroundActivityEvidenceV1 if type(request) is ForegroundActivityRequestV1 else ForegroundActivityEvidenceV2
        result = evidence_type(request, current_self,
            ProductionOwnerGuardV1(owner_key.token, versions[owner_key], canonical_digest(owner),
                current_owner.guard.authorization_head.removeprefix("sha256:")),
            tuple(GraphVersion(key, revision) for key, revision in sorted(versions.items(), key=lambda row: row[0].token)),
            QueryEpoch(request.namespace, "namespace", current_self.graph_epoch), foreground_allowed_write_domains_v1(request.operation_kind),
            datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z"), root,
            *db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                request.namespace.as_tuple).fetchone())
        return result, job_value

    def current_mesh_v1(self, *, credential, subject, permit, request):
        from .current_foreground_mesh_v1 import observe_current_personal_mesh_v1
        return observe_current_personal_mesh_v1(self, credential=credential, subject=subject, permit=permit, request=request)



_WIRE_TYPES = {"foreground_request": ForegroundActivityRequestV1, "foreground_evidence": ForegroundActivityEvidenceV1,
    "draft_root_request": DraftRootRegistrationRequestV1, "draft_root_evidence": DraftRootRegistrationEvidenceV1}


def foreground_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    names = {cls: name for name, cls in _WIRE_TYPES.items()}
    if type(value) not in names:
        raise TypeError("unregistered foreground wire type")
    return {"schema": "d11.foreground-wire.v1", "kind": names[type(value)], "value": plain_v1(value)}


def foreground_from_wire_v1(raw, expected_type):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if (type(raw) is not dict or set(raw) != {"schema", "kind", "value"} or raw["schema"] != "d11.foreground-wire.v1"
            or _WIRE_TYPES.get(raw["kind"]) is not expected_type or expected_type not in _WIRE_TYPES.values()):
        raise ValueError("foreground exact wire schema/type differs")
    value = decode_typed_production_value_v1(raw["value"], expected_type)
    if canonical_serialize(foreground_to_wire_v1(value)) != canonical_serialize(raw):
        raise ValueError("foreground wire changed under its closed canonical codec")
    return value


_ARTIFACT_PHASE_FILE_OPERATIONS_V2 = frozenset({'prepare_artifact_draft_body', 'input:register_artifact_phase_draft_plan_v2', 'prepare_life'})


_ARTIFACT_INITIAL_TASK_OPERATIONS_V1 = frozenset({'create_artifact_task_plan_v1','create_artifact_task_project_v1','initialize_artifact_task_project_checkpoint_v1'})
_ARTIFACT_AMENDMENT_PLAN_OPERATIONS_V2=frozenset({'revise_artifact_task_plan_v2'})


def _qualify_artifact_initial_task_foreground_v1(db, *, request, job, continuation, issuer, installed_bundle, owner_guard, now, atom):
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from ..runtime.d08_personal_plan_v1 import (InstalledD08PersonalPlanReadersV1, CreateCurrentArtifactTaskPlanRequestV1,
        _initial_artifact_task_plan_basis_v1, artifact_task_initial_plan_operation_id_v1)
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV1
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.d11_offline_originals_v1 import _utc
    if (request.operation_kind not in _ARTIFACT_INITIAL_TASK_OPERATIONS_V1 or job is None
            or type(continuation.call_plan) is not ForegroundCallPlanV1 or request.purpose != 'consolidation'):
        raise AuthorityUnavailable('initial task Plan needs the actual preDecision task cycle')
    task = artifact_draft_task_selector_v1(request.namespace, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.draft_root_registration_ref)
    body = CreateCurrentArtifactTaskPlanRequestV1(task)
    readers = InstalledD08PersonalPlanReadersV1(issuer=issuer, resource_issuer=issuer.resource_issuer,installed_bundle=installed_bundle)
    keys, goal, objective_ref, objective, scope_ref, scope, root, producer = _initial_artifact_task_plan_basis_v1(db,
        namespace=request.namespace, request=body, installed_readers=readers)
    if (task.cycle_job_ref != request.cycle_job_ref or continuation.c02_operation_id != task.c02_operation_id
            or continuation.source_ref != request.cue_source_ref or root.source_ref != request.cue_source_ref
            or request.plan_ref not in {None, objective.plan_ref}
            or (root.installation_id, root.manifest_digest) != (installed_bundle.installation_policy.installation_id, installed_bundle.installation_policy.manifest_digest)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
                (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)
            or goal.state != 'active' or atom(keys[0]) != json.loads(canonical_serialize(goal))
            or request.operation_kind=='create_artifact_task_plan_v1' and atom(keys[1], required=False) is not None):
        raise AuthorityUnavailable('initial task Plan changed its actual previous Goal/root/Source or absent Plan target')
    expected_operation=artifact_task_initial_plan_operation_id_v1(task)
    if request.operation_kind!='create_artifact_task_plan_v1':
        from ..runtime.d10_project_checkpoint_v1 import (_task_project_basis_v1,CreateCurrentArtifactTaskProjectRequestV1,
            InitializeCurrentArtifactTaskProjectCheckpointRequestV1,artifact_task_project_operation_id_v1,
            artifact_task_checkpoint_initialization_operation_id_v1,require_artifact_task_project_original_v1,
            project_checkpoint_key_v1)
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        actual=_task_project_basis_v1(db,namespace=request.namespace,task=task,issuer=issuer)
        if actual[6]!=root or actual[7]!=job:raise AuthorityUnavailable('task project changed actual current task root/cycle')
        atom(keys[1]);atom(actual[1].key)
        if request.operation_kind=='create_artifact_task_project_v1':
            if atom(keys[2],required=False) is not None:raise AuthorityUnavailable('task project cannot replace its actual previous definition')
            recipe=atom(keys[3],required=False)
            if recipe is not None and recipe!=actual[-1]['recipe_value']:raise AuthorityUnavailable('task recipe differs from actual declared original')
            body=CreateCurrentArtifactTaskProjectRequestV1(task);expected_operation=artifact_task_project_operation_id_v1(task)
        else:
            original=read_adopted_domain_operation_v1(db,request.namespace,artifact_task_project_operation_id_v1(task))
            if original is None:raise AuthorityUnavailable('task checkpoint requires actual adopted initial project')
            basis=require_artifact_task_project_original_v1(db,namespace=request.namespace,original=original)
            if atom(keys[2])!=basis['project_value'] or atom(keys[3])!=basis['recipe_value']:
                raise AuthorityUnavailable('task checkpoint changed real project/recipe originals')
            if atom(project_checkpoint_key_v1(request.namespace,keys[2].token),required=False) is not None:
                raise AuthorityUnavailable('task checkpoint cannot replace its actual waiting target')
            body=InitializeCurrentArtifactTaskProjectCheckpointRequestV1(task);expected_operation=artifact_task_checkpoint_initialization_operation_id_v1(task)
    source = atom(objective.source_ref)
    source_row = db.execute('SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*request.namespace.as_tuple, objective.source_ref)).fetchone()
    if source_row is None or (source_row[0], canonical_digest(source)) != (objective.source_revision, objective.source_digest):
        raise AuthorityUnavailable('initial task Plan changed the registered objective Source head')
    deadline = min(objective.valid_until_utc, _utc(root.valid_until_utc).timestamp(), _utc(job.deadline_utc).timestamp())
    if (request.operation_id != expected_operation
            or request.request_digest != foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind), body)
            or not now < deadline):
        raise AuthorityUnavailable('initial task Plan command changed its fixed typed request or original deadline')
    return {objective.source_ref}, deadline


_ARTIFACT_PHASE_OPERATIONS_V2 = frozenset({'serve_concern', "prepare_artifact_phase_observation_v1", 'prepare_artifact_draft_model_v2', 'acquire_artifact_draft_model_v2',
    'adopt_artifact_draft_content_v2', 'verify_artifact_draft_phase_v2', 'wake_artifact_draft_cycle_v2',
    'propose_artifact_draft_phase_action_v2', 'register_artifact_phase_postcondition_contract_v1', 'observe_artifact_phase_postconditions_v1',
    'activate_artifact_task_project_checkpoint_v1','activate_artifact_task_project_checkpoint_v2','register_artifact_task_milestone_v2'})


def _qualify_artifact_phase_foreground_v2(db, *, request, job, continuation, issuer, installed_bundle, current_self, owner_guard, now, atom):
    """Rebuild exact phase commands from actual signed current task originals."""
    from .foreground_mesh_source_read_v3 import read_foreground_mesh_point_v3 as _original_graph_point_v3
    from ..model_broker.artifact_draft_v1 import (ArtifactDraftPhaseSelectorV2, artifact_draft_model_ids_v2,
        artifact_draft_file_ids_v2, artifact_draft_phase_original_ref_v2)
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV2, require_protected_reply_budget_v1
    from ..runtime.d11_artifact_draft_model_v1 import (PrepareArtifactDraftModelRequestV2, AcquireArtifactDraftModelRequestV2,
        read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2, read_artifact_draft_model_request_v2,
        require_current_artifact_phase_group_v2, installed_artifact_draft_workflow_v2,
        _read_artifact_phase_selected_originals_v2, _require_artifact_phase_candidate_current_sql_v2,
        _require_completed_artifact_phase_candidate_current_sql_v2,
        _current_artifact_phase_parameters_v2, read_current_artifact_draft_attempt_v2)
    from ..runtime.d11_artifact_draft_content_v1 import (AdoptArtifactDraftContentRequestV2,
        VerifyArtifactDraftPhaseRequestV2, _read_phase_content_adoption_original_v2, _read_actual_phase_file_v2,
        require_current_artifact_prior_content_v2)
    from ..runtime.foreground_cycle_v1 import WakeArtifactDraftCycleRequestV2, artifact_draft_phase_wake_operation_id_v2
    from ..runtime.d08_personal_plan_v1 import ProposeCurrentArtifactPhaseActionRequestV2, artifact_phase_action_keys_v2
    from ..runtime.d02_life_body_preparation_v1 import PrepareArtifactDraftBodyRequestV1, life_body_preparation_original_from_wire_v1
    from ..runtime.domain_production_inputs_v1 import RegisterCurrentPhaseDraftFilePlanInputRequestV2
    from ..runtime.d11_life_product_adapter_v1 import artifact_phase_draft_plan_ref_v2, artifact_phase_draft_plan_registration_operation_id_v2
    from ..runtime.d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
    from ..runtime.d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..runtime.d11_life_preparation_v1 import TABLE
    from ..runtime.d11_offline_originals_v1 import _utc
    from ..host.authority_profile import is_installed_artifact_draft_phase_slot_v2
    from ..domains.d01.production_operations_v1 import plain_v1
    from .v2_model_egress_wire import from_wire
    from .v2_model_egress_contract import ModelEgressIntentV1
    if (request.operation_kind not in _ARTIFACT_PHASE_OPERATIONS_V2 | _ARTIFACT_PHASE_FILE_OPERATIONS_V2 or job is None
            or type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}):
        raise AuthorityUnavailable('phase admission requires the actual current versioned cycle method group')
    group = continuation.call_plan.phase_group; selector = group.selector
    if (type(selector) is not ArtifactDraftPhaseSelectorV2 or (not selector.generation and request.operation_kind not in {'serve_concern', "prepare_artifact_phase_observation_v1", 'verify_artifact_draft_phase_v2','observe_artifact_phase_postconditions_v1','register_artifact_task_milestone_v2'})
            or selector.task.namespace != request.namespace or selector.task.c02_operation_id != request.c02_operation_id
            or selector.task.cycle_job_ref != request.cycle_job_ref or selector.task.root_registration_ref != request.draft_root_registration_ref
            or request.plan_ref != selector.plan_ref or request.purpose != ('proposal'if request.operation_kind=='serve_concern'else'consolidation')
            or job.budget_ref != request.parent_budget_lease_ref
            or continuation.call_plan.parent_budget_lease_ref != request.parent_budget_lease_ref):
        raise AuthorityUnavailable('phase admission changed its adopted method/Plan/task/root/purpose/parent lease')
    from ..runtime.d11_artifact_draft_content_v1 import actual_artifact_phase_content_selector_v2
    model_selector = actual_artifact_phase_content_selector_v2(db, namespace=request.namespace, selector=selector, issuer=issuer)
    new_work = request.operation_kind in _ARTIFACT_PHASE_FILE_OPERATIONS_V2 | {
        'prepare_artifact_draft_model_v2', 'acquire_artifact_draft_model_v2',
        'propose_artifact_draft_phase_action_v2', 'register_artifact_phase_postcondition_contract_v1',
        'activate_artifact_task_project_checkpoint_v1', 'activate_artifact_task_project_checkpoint_v2'}
    if new_work:
        from ..runtime.d08_project_control_v1 import require_current_project_plan_for_new_work_v1
        require_current_project_plan_for_new_work_v1(db, namespace=request.namespace, plan_ref=selector.plan_ref)
    workflow = installed_artifact_draft_workflow_v2(installed_bundle)
    if not is_installed_artifact_draft_phase_slot_v2(installed_bundle, workflow) or not set(request.audiences) <= set(workflow.audiences):
        raise AuthorityUnavailable('phase admission changed actual installed phase workflow/audience')
    require_current_artifact_phase_group_v2(db, namespace=request.namespace, group=group, issuer=issuer)
    require_protected_reply_budget_v1(db, namespace=request.namespace, plan=continuation.call_plan, issuer=issuer, now_utc=now,
        installed_bundle=installed_bundle, owner_guard=owner_guard)
    current_candidate = (_require_completed_artifact_phase_candidate_current_sql_v2
        if request.operation_kind in _ARTIFACT_PHASE_FILE_OPERATIONS_V2 | {'serve_concern', "prepare_artifact_phase_observation_v1", 'propose_artifact_draft_phase_action_v2','verify_artifact_draft_phase_v2','observe_artifact_phase_postconditions_v1','register_artifact_task_milestone_v2'}
        else _require_artifact_phase_candidate_current_sql_v2)
    chosen = current_candidate(db, selector=model_selector, issuer=issuer, now=now,
        owner_guard=owner_guard, audiences=request.audiences, installed_bundle=installed_bundle)
    contract = None
    if request.operation_kind not in {'register_artifact_phase_postcondition_contract_v1','activate_artifact_task_project_checkpoint_v1','activate_artifact_task_project_checkpoint_v2'}:
        from ..runtime.artifact_phase_postconditions_v1 import readonly_current_artifact_phase_postcondition_contract_v1
        contract = readonly_current_artifact_phase_postcondition_contract_v1(db, namespace=request.namespace,
            selector=selector, issuer=issuer, now_utc=now, owner_guard=owner_guard, installed_bundle=installed_bundle)
    completed_changes = {}
    if current_candidate is _require_completed_artifact_phase_candidate_current_sql_v2:
        from ..runtime.d08_personal_candidate_v1 import readonly_current_completed_artifact_phase_facts_v1
        _, actual_chosen, _, changes, _ = readonly_current_completed_artifact_phase_facts_v1(db,
            namespace=request.namespace, selector=model_selector, issuer=issuer, now_utc=now,
            owner_guard=owner_guard, installed_bundle=installed_bundle)
        if actual_chosen != chosen: raise AuthorityUnavailable('actual completed phase facts changed selected parameters')
        for before,after,digest in changes:
            if before.key != after.key or NamespaceId.from_key(before.key) != request.namespace:
                raise AuthorityUnavailable('actual completed phase delta crossed namespace/key')
            historical = _original_graph_point_v3(db,table='graph_history',columns=('value','valid'),key_columns=('token','revision'),key=(after.key.token,after.revision),legacy_reader=lambda:db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',(after.key.token,after.revision)).fetchone())
            if historical is None or historical[1] != 1 or canonical_digest(authority_current_json_v3(historical[0])) != digest:
                raise AuthorityUnavailable('actual completed phase delta lost receipt historical bytes')
            completed_changes.setdefault(before.key.token, []).append((before.revision,after.revision))
    def admitted_frozen_revision(ref, before, current):
        seen = set()
        while before != current:
            if before in seen: return False
            seen.add(before)
            steps = tuple(after for previous,after in completed_changes.get(ref, ()) if previous == before)
            if len(steps) != 1 or steps[0] <= before or steps[0] > current: return False
            before = steps[0]
        return True
    prepared_set, _, _ = _read_artifact_phase_selected_originals_v2(db, selector=model_selector, issuer=issuer)
    for version in (*prepared_set.read_versions, *prepared_set.need.read_versions, *chosen.eligibility.read_versions, *chosen.price.read_versions):
        atom(version.key, required=version.revision > 0)
    extent, target, prior = _current_artifact_phase_parameters_v2(db, selector=model_selector, chosen=chosen, issuer=issuer)
    if prior is not None:
        require_current_artifact_prior_content_v2(db, namespace=request.namespace, selector=model_selector, prior=prior, issuer=issuer)
        atom(prior.source_head.ref)
    ids = artifact_draft_model_ids_v2(model_selector)
    prepared = read_artifact_draft_prepared_v2(db, namespace=request.namespace, selector=model_selector, issuer=issuer)
    content = None; permitted = set(prepared_set.source_refs)
    deadline = min(prepared_set.need.original_deadline_utc, chosen.future_identity.deadline_utc)
    if request.operation_kind=='activate_artifact_task_project_checkpoint_v2':
        from ..runtime.d10_project_checkpoint_v1 import (ActivateCurrentArtifactTaskProjectCheckpointRequestV2,
            artifact_task_checkpoint_activation_operation_id_v2,project_checkpoint_key_v1)
        from ..runtime.d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
        revision=read_adopted_domain_operation_v1(db,request.namespace,artifact_task_plan_revision_operation_id_v2(selector.task))
        actual_plan,checkpoint=require_artifact_task_plan_revision_original_v2(db,namespace=request.namespace,original=revision)
        key=project_checkpoint_key_v1(request.namespace,checkpoint.project_ref)
        if (selector.phase_index!=0 or checkpoint.state!='waiting' or checkpoint.next_step is not None
                or atom(key)!=json.loads(canonical_serialize(checkpoint)) or selector.plan_revision!=actual_plan.revision
                or atom(selector.plan_ref)!=json.loads(canonical_serialize(actual_plan))):
            raise AuthorityUnavailable('amended checkpoint activation lost exact own Plan/waiting predecessor')
        body=ActivateCurrentArtifactTaskProjectCheckpointRequestV2(selector)
        expected=artifact_task_checkpoint_activation_operation_id_v2(selector)
    elif request.operation_kind=='activate_artifact_task_project_checkpoint_v1':
        from ..runtime.d10_project_checkpoint_v1 import (ActivateCurrentArtifactTaskProjectCheckpointRequestV1,
            artifact_task_checkpoint_activation_operation_id_v1,artifact_task_checkpoint_initialization_operation_id_v1,
            require_artifact_task_checkpoint_original_v1,project_checkpoint_key_v1)
        original=read_adopted_domain_operation_v1(db,request.namespace,artifact_task_checkpoint_initialization_operation_id_v1(selector.task))
        if original is None:raise AuthorityUnavailable('selected checkpoint activation requires its actual waiting initialization')
        checkpoint,basis=require_artifact_task_checkpoint_original_v1(db,namespace=request.namespace,original=original)
        key=project_checkpoint_key_v1(request.namespace,checkpoint.project_ref)
        row=db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        if (selector.phase_index!=0 or checkpoint.state!='waiting' or checkpoint.next_step is not None
                or row is None or row[0]!=1 or atom(key)!=json.loads(canonical_serialize(checkpoint))
                or selector.plan_ref!=checkpoint.plan_ref):
            raise AuthorityUnavailable('selected checkpoint activation changed actual waiting target and adopted method Plan')
        body=ActivateCurrentArtifactTaskProjectCheckpointRequestV1(selector)
        expected=artifact_task_checkpoint_activation_operation_id_v1(selector)
    elif request.operation_kind=='register_artifact_task_milestone_v2':
        from ..runtime.artifact_task_observer_v1 import RegisterCurrentArtifactTaskMilestoneRequestV2,artifact_task_milestone_registration_operation_id_v2
        from ..runtime.d11_artifact_draft_content_v1 import require_current_artifact_method_completion_v2
        require_current_artifact_method_completion_v2(db,namespace=request.namespace,continuation=continuation,
            issuer=issuer,now_utc=now,owner_guard=owner_guard,installed_bundle=installed_bundle)
        body=RegisterCurrentArtifactTaskMilestoneRequestV2(selector);expected=artifact_task_milestone_registration_operation_id_v2(selector)
    elif request.operation_kind == 'register_artifact_phase_postcondition_contract_v1':
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
        from ..runtime.artifact_phase_postconditions_v1 import (POLICY_KIND, CONTRACT_KIND,
            RegisterArtifactPhasePostconditionContractRequestV1, require_artifact_phase_postcondition_history_v1,
            artifact_phase_postcondition_contract_ref_v1, artifact_phase_contract_registration_operation_id_v1,
            _current_policy_sql_v1, _require_before_first_generation_v1)
        if type(chosen.binding) is not ArtifactPhaseCandidateBindingV3 or selector.phase_index != 0 or not selector.generation:
            raise AuthorityUnavailable('contract registration needs its actual first selected V3 method')
        policy_row = _read(db, issuer=issuer, namespace=request.namespace, kind=POLICY_KIND, ref=chosen.binding.postcondition_policy_ref)
        if policy_row is None or canonical_digest(policy_row[0]) != chosen.binding.postcondition_policy_digest:
            raise AuthorityUnavailable('contract registration lost the actual preDecision signed policy')
        policy = require_artifact_phase_postcondition_history_v1(db, namespace=request.namespace, kind=POLICY_KIND,
            original_ref=chosen.binding.postcondition_policy_ref, producing_operation_id=policy_row[1], raw=policy_row[0], issuer=issuer)
        _current_policy_sql_v1(db, policy=policy, issuer=issuer, now_utc=now, owner_guard=owner_guard, installed_bundle=installed_bundle)
        if (policy.request.goal_ref, policy.request.plan_ref, policy.request.task, policy.request.method_ref,
                policy.request.extent_original_ref, policy.extent_original_digest) != (
                prepared_set.goal_head.key.token, selector.plan_ref, selector.task, selector.method_ref,
                chosen.binding.extent_original_ref, chosen.binding.extent_original_digest):
            raise AuthorityUnavailable('contract registration changed the adopted binding policy or actual Goal/Plan/extent')
        _require_before_first_generation_v1(db, selector.task, before_operation_id=ids['prepare'])
        if prepared is not None or _read(db, issuer=issuer, namespace=request.namespace, kind=CONTRACT_KIND,
                ref=artifact_phase_postcondition_contract_ref_v1(selector)) is not None:
            raise AuthorityUnavailable('contract registration cannot replace an actual original method contract')
        body = RegisterArtifactPhasePostconditionContractRequestV1(selector, policy.original_ref)
        expected = artifact_phase_contract_registration_operation_id_v1(selector)
        deadline = min(deadline, policy.original_deadline_utc)
    elif request.operation_kind == 'prepare_artifact_draft_model_v2':
        body = PrepareArtifactDraftModelRequestV2(selector); expected = ids['prepare']
        if prepared is not None or any(row.call_id == ids['call'] for row in continuation.call_plan.attempts):
            raise AuthorityUnavailable('phase preparation cannot replace an actual existing once attempt')
    else:
        if prepared is None: raise AuthorityUnavailable('phase command lacks its actual signed preparation')
        frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=issuer)
        from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
        if (type(frozen) is not ArtifactDraftInputV3 or
                (frozen.postcondition_contract_ref, frozen.postcondition_contract_digest) != (contract.original_ref, contract.digest)):
            raise AuthorityUnavailable('phase foreground frozen material lost its preregistered contract')
        if (prepared.selector != model_selector or prepared.actor_ref != current_self.self_entity_ref
                or prepared.owner_guard != owner_guard or prepared.parent_budget_lease_ref != request.parent_budget_lease_ref
                or (prepared.installation_id, prepared.manifest_digest, prepared.activation_generation) !=
                    (installed_bundle.installation_policy.installation_id, installed_bundle.installation_policy.manifest_digest,
                     current_self.activation_generation)
                or prepared.workflow_digest != canonical_digest(plain_v1(workflow))
                or (frozen.extent, frozen.target, frozen.prior_content) != (extent, target, prior)
                or frozen.task_source_ref != request.cue_source_ref):
            raise AuthorityUnavailable('phase actual prepared input/installation/Owner/Self/config/count differs')
        for version in frozen.source_read_versions:
            atom(version.key, required=version.revision > 0)
            row = db.execute('SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
                (*request.namespace.as_tuple, version.key.token)).fetchone()
            if not admitted_frozen_revision(version.key.token, version.revision, 0 if row is None else row[0]):
                raise AuthorityUnavailable('phase frozen positive/negative current input changed')
        for source in frozen.sources:
            if canonical_digest(atom(source.ref)) != source.value_digest:
                raise AuthorityUnavailable('phase frozen actual Source bytes changed')
        child = get_job(db, prepared.job_id)
        if (child.work_kind != 'artifact_draft_v1' or child.operation_id != prepared.operation_id
                or child.continuation != {'schema':'d11.artifact-draft-phase-model-job.v2',
                    'selector':plain_v1(selector), 'prepared_digest':prepared.digest}
                or atom(job_graph_write(child).key) != job_graph_write(child).value):
            raise AuthorityUnavailable('phase actual signed worker SQL/Graph differs')
        quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, 1)
        reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
            (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
        if (canonical_digest(quote) != prepared.quote_digest or quote.work_kind != 'artifact_draft_v1' or now >= quote.valid_until_utc
                or quote.operation_id != prepared.operation_id
                or quote.parent_budget_lease_ref != prepared.parent_budget_lease_ref
                or any(amount > workflow.quote_ceiling.get(dimension,0) for dimension,amount in quote.ceiling.items())
                or reservation is None or reservation[:2] != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)))):
            raise AuthorityUnavailable('phase original signed quote/reservation differs')
        deadline = min(deadline, frozen.deadline_utc, _utc(prepared.deadline_utc).timestamp())
        permitted.update(source.ref for source in frozen.sources)
        if request.operation_kind == 'acquire_artifact_draft_model_v2':
            body = AcquireArtifactDraftModelRequestV2(selector); expected = ids['acquire']
            if (child.phase, child.fence, child.cancel_epoch, child.lease_holder, child.result_ref) != ('queued', 0, 0, None, None) or reservation[2] != 'reserved':
                raise AuthorityUnavailable('phase worker acquisition is not its actual original queued once job')
        else:
            acquired = read_artifact_draft_model_request_v2(db, prepared=prepared, issuer=issuer)
            call = _read(db, issuer=issuer, namespace=request.namespace, kind='c4_phase_call', ref=prepared.call_id)
            if call is None: raise AuthorityUnavailable('phase terminal command lacks actual sealed original call')
            intent = from_wire(call[0], ModelEgressIntentV1)
            if (intent.call_id, intent.job_id, intent.binding_digest, intent.request_digest) != (
                    prepared.call_id, prepared.job_id, prepared.digest, acquired.digest):
                raise AuthorityUnavailable('phase terminal command changed original sealed call binding')
            attempts = tuple(row for row in continuation.call_plan.attempts if row.call_id == prepared.call_id)
            if len(attempts) != 1 or read_current_artifact_draft_attempt_v2(db, namespace=request.namespace,
                    continuation=continuation, attempt=attempts[0], issuer=issuer).state != 'completed':
                raise AuthorityUnavailable('phase terminal command has no actual paid completed result')
            if request.operation_kind == 'adopt_artifact_draft_content_v2':
                body = AdoptArtifactDraftContentRequestV2(selector); expected = ids['adopt']
                if (child.phase, child.fence, child.cancel_epoch, child.lease_holder, child.result_ref) != ('running', 1, 0, prepared.worker_subject, None):
                    raise AuthorityUnavailable('phase content cannot adopt from another/unknown/cancelled worker')
            elif request.operation_kind == 'propose_artifact_draft_phase_action_v2':
                content, _, _, scope = _read_phase_content_adoption_original_v2(db, namespace=request.namespace, selector=selector, issuer=issuer)
                if (scope.actor_ref != current_self.self_entity_ref
                        or (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest) !=
                            (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)
                        or (content.extent, content.target) != (extent, target)):
                    raise AuthorityUnavailable('phase file Action lost actual adopted content/current Owner/Self/extent')
                permitted.update(content.content.source_refs)
                atom(content.content.content.ref)
                atom(prepared_set.goal_head.key)
                goal = atom(prepared_set.goal_head.key)
                plan = atom(prepared_set.plan_head.key)
                if (goal['state'] != 'active' or plan['state'] != 'active' or plan['goal_ref'] != prepared_set.goal_head.key.token
                        or len(tuple(node for node in plan['nodes'] if node['node_id'] == chosen.binding.node_id
                            and node['owner_ref'] == plan['actor_ref'] and node['action_kind'] == 'artifact_draft_v1'
                            and not node['pending_original_effects'] and not node['carried_forward_verified'])) != 1):
                    raise AuthorityUnavailable('phase file Action requires actual unexecuted chosen active Goal/Plan node')
                for key in artifact_phase_action_keys_v2(selector):
                    if atom(key, required=False) is not None:
                        raise AuthorityUnavailable('phase Action cannot replace its actual once action/cancellation')
                body = ProposeCurrentArtifactPhaseActionRequestV2(selector)
                expected = artifact_draft_file_ids_v2(selector)['action_operation']
            elif request.operation_kind in _ARTIFACT_PHASE_FILE_OPERATIONS_V2:
                content, _, _, _ = _read_phase_content_adoption_original_v2(db, namespace=request.namespace, selector=selector, issuer=issuer)
                permitted.update(content.content.source_refs)
                file_ids = artifact_draft_file_ids_v2(selector)
                action_key = artifact_phase_action_keys_v2(selector)[0]
                action = atom(action_key)
                actual_revision=_original_graph_point_v3(db,table='graph_atoms',columns=('revision',),key_columns=('token','bot','persona'),key=(action_key.token,*request.namespace.as_tuple),legacy_reader=lambda:db.execute('SELECT revision FROM graph_atoms WHERE token=?',(action_key.token,)).fetchone())[0]
                action_history = _original_graph_point_v3(db,table='graph_history',columns=('event_id','value','valid'),key_columns=('token','revision'),key=(action_key.token,actual_revision),legacy_reader=lambda:db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(action_key.token,actual_revision)).fetchone())
                producer = None if action_history is None else read_adopted_domain_operation_v1(db, request.namespace, action_history[0])
                if (action_history is None or action_history[2] != 1 or authority_current_json_v3(action_history[1]) != action
                        or producer is None or (producer['domain'],producer['operation_kind']) != ('d08','propose_artifact_draft_phase_action_v2')
                        or producer['payload']['request'] != plain_v1(ProposeCurrentArtifactPhaseActionRequestV2(selector))
                        or producer['payload']['provenance']['artifact_phase_content_adoption'] != plain_v1(content)
                        or (action['identity']['operation_id'],action['identity']['effect_id'],action['identity']['attempt_id']) !=
                            (file_ids['action_operation'],file_ids['effect'],file_ids['attempt'])):
                    raise AuthorityUnavailable('phase file step lacks its actual signed once Action A/content producer')
                body_policy = installed_bundle.artifact_draft.body_policy
                body_request = PrepareArtifactDraftBodyRequestV1(action_key.token, body_policy.policy_ref,
                    body_policy.policy_version, body_policy.effect_component_policy_ref, body_policy.cpu_ceiling_ms)
                if request.operation_kind == 'prepare_artifact_draft_body':
                    body = body_request; expected = 'd02-life-body:' + file_ids['action_operation']
                else:
                    body_ref = 'life-body:d02-life-body:' + file_ids['action_operation']
                    body_row = _read(db, issuer=issuer, namespace=request.namespace, kind='life_body_preparation', ref=body_ref)
                    if body_row is None: raise AuthorityUnavailable('phase file step lacks actual Body B original')
                    component = life_body_preparation_original_from_wire_v1(body_row[0])
                    body_original = read_adopted_domain_operation_v1(db, request.namespace, body_row[1])
                    if (body_original is None or (body_original['domain'],body_original['operation_kind']) != ('d02','prepare_artifact_draft_body')
                            or body_original['payload']['request'] != plain_v1(body_request)
                            or component.action_intent_ref != action_key.token):
                        raise AuthorityUnavailable('phase Body B differs from actual current Action/installed policy producer')
                    if request.operation_kind == 'input:register_artifact_phase_draft_plan_v2':
                        body = RegisterCurrentPhaseDraftFilePlanInputRequestV2(selector)
                        expected = artifact_phase_draft_plan_registration_operation_id_v2(selector)
                    else:
                        plan_ref = artifact_phase_draft_plan_ref_v2(selector)
                        plan_row = _read(db, issuer=issuer, namespace=request.namespace, kind='plan', ref=plan_ref)
                        if plan_row is None: raise AuthorityUnavailable('phase Life prepare lacks actual registered selector file plan')
                        plan = draft_from_wire_v1(plan_row[0], RegisteredDraftFilePlanV3)
                        plan_original = read_adopted_domain_operation_v1(db, request.namespace, plan_row[1])
                        if (plan_original is None or plan_row[1] != artifact_phase_draft_plan_registration_operation_id_v2(selector)
                                or plan_original['operation_kind'] != 'input:register_artifact_phase_draft_plan_v2'
                                or plan_original['payload']['request'] != plain_v1(RegisterCurrentPhaseDraftFilePlanInputRequestV2(selector))
                                or (plan.target,plan.content,plan.operation_id,plan.effect_id,plan.attempt_id,plan.execution_call_id) !=
                                    (content.target,content.content,file_ids['action_operation'],file_ids['effect'],file_ids['attempt'],file_ids['execution_call'])):
                            raise AuthorityUnavailable('phase Life file plan changed actual Action/Body/content/root once chain')
                        body = PrepareCurrentLifeRequestV1(plan_ref, artifact_draft_phase_original_ref_v2(selector)+':file-prepare')
                        expected = body.prepare_operation_id
            elif request.operation_kind in {'serve_concern', "prepare_artifact_phase_observation_v1", 'verify_artifact_draft_phase_v2','observe_artifact_phase_postconditions_v1','register_artifact_task_milestone_v2'}:
                content, _, _, _ = _read_phase_content_adoption_original_v2(db, namespace=request.namespace, selector=model_selector, issuer=issuer)
                permitted.update(content.content.source_refs)
                file_ids = artifact_draft_file_ids_v2(model_selector)
                rows = db.execute('SELECT original_ref FROM ' + TABLE + " WHERE bot=? AND persona=? AND kind='adopted_life' "
                    "AND json_extract(payload_json,'$.terminal.binding.effect_id')=? LIMIT 2", (*request.namespace.as_tuple, file_ids['effect'])).fetchall()
                if len(rows) != 1: raise AuthorityUnavailable('phase verification requires its unique actual completed file effect')
                _read_actual_phase_file_v2(db, namespace=request.namespace, selector=model_selector, adoption=content, result_ref=rows[0][0], issuer=issuer)
                assessment_refs = ()
                if request.operation_kind=='prepare_artifact_phase_observation_v1':
                    from ..runtime.artifact_phase_observation_v1 import PrepareArtifactPhaseObservationRequestV1
                    from ..runtime.foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1,ForegroundCallPlanV3
                    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
                    observer=require_current_artifact_phase_observer_v2(installed_bundle)
                    if selector.generation or type(continuation.call_plan)is not ForegroundCallPlanV3:
                        raise AuthorityUnavailable('observation preparation requires its explicit current V3 check phase')
                    if(continuation.call_plan.observer_policy_ref,continuation.call_plan.observer_policy_digest)!=(observer.asset_ref,observer.asset_digest):
                        raise AuthorityUnavailable('observation preparation changed its installed observer commitment')
                    condition='tone'if selector.phase_kind=='sample_check'else'task_semantics'
                    body=PrepareArtifactPhaseObservationRequestV1(selector,contract.original_ref,rows[0][0],condition)
                    expected=artifact_observation_ids_v1(selector,condition)['prepare']
                elif request.operation_kind=='serve_concern':
                    from ..runtime.artifact_phase_observation_v1 import current_artifact_observation_concern_command_v1
                    basis,body=current_artifact_observation_concern_command_v1(db,selector=selector,issuer=issuer,
                        installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now)
                    expected=basis.ids['operation'];deadline=min(deadline,basis.original_deadline_utc)
                    permitted.update(basis.source_refs)
                    for source_head,digest in basis.source_heads:
                        value=atom(source_head.key)
                        if canonical_digest(value)!=digest:
                            raise AuthorityUnavailable('observation command changed an original task/content Source')
                elif request.operation_kind == 'observe_artifact_phase_postconditions_v1':
                    from ..runtime.artifact_phase_postconditions_v1 import (ASSESSMENT_KIND,
                        ObserveArtifactPhasePostconditionsRequestV1, artifact_phase_assessment_original_ref_v1,
                        artifact_phase_assessment_operation_id_v1)
                    if selector.generation or _read(db, issuer=issuer, namespace=request.namespace, kind=ASSESSMENT_KIND,
                            ref=artifact_phase_assessment_original_ref_v1(selector)) is not None:
                        raise AuthorityUnavailable('observation cannot replace its actual immutable check assessment')
                    from ..runtime.artifact_phase_postconditions_v1 import artifact_phase_expected_observer_refs_v1
                    body = ObserveArtifactPhasePostconditionsRequestV1(selector, rows[0][0], contract.original_ref,
                        artifact_phase_expected_observer_refs_v1(contract,selector))
                    expected = artifact_phase_assessment_operation_id_v1(selector)
                elif not selector.generation:
                    from ..runtime.artifact_phase_postconditions_v1 import (artifact_phase_assessment_original_ref_v1,
                        read_current_artifact_phase_assessment_v1)
                    assessment_ref = artifact_phase_assessment_original_ref_v1(selector)
                    assessment = read_current_artifact_phase_assessment_v1(db, namespace=request.namespace,
                        original_ref=assessment_ref, issuer=issuer, now_utc=now, owner_guard=owner_guard, installed_bundle=installed_bundle)
                    from ..runtime.d11_artifact_draft_content_v1 import _require_actual_artifact_phase_assessment_v1
                    _, _, file_original, readback = _read_actual_phase_file_v2(db, namespace=request.namespace,
                        selector=model_selector, adoption=content, result_ref=rows[0][0], issuer=issuer)
                    _require_actual_artifact_phase_assessment_v1(selector=selector, content_selector=model_selector,
                        contract=contract, assessment=assessment, adoption=content, file_result_ref=rows[0][0],
                        file_result_digest=canonical_digest(file_original), readback=readback)
                    assessment_refs = (assessment.original_ref,)
                if request.operation_kind == 'verify_artifact_draft_phase_v2':
                    body = VerifyArtifactDraftPhaseRequestV2(selector, rows[0][0], assessment_refs)
                    expected = artifact_draft_phase_original_ref_v2(selector) + ':verify'
            else:
                dedupe = canonical_digest((request.namespace, ids['prepare'], 'd11', 'artifact_draft_phase_model_queued'))
                body = WakeArtifactDraftCycleRequestV2(selector, dedupe); expected = artifact_draft_phase_wake_operation_id_v2(selector)
                if ((child.phase, child.fence, child.cancel_epoch, child.lease_holder, child.result_ref) !=
                        ('running', 1, 0, prepared.worker_subject, None)
                        or job.phase != 'waiting' or job.lease_holder is not None or job.lease_expires_utc is not None
                        or continuation.wait is None or continuation.wait.event_kind not in {'artifact_draft_phase_model_queued','artifact_draft_phase_model_terminal'}):
                    raise AuthorityUnavailable('phase wake changed actual released waiting parent')
                cause = read_adopted_domain_operation_v1(db, request.namespace, ids['prepare'])
                event = db.execute('SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state FROM graph_domain_production_outbox_v1 '
                    'WHERE bot=? AND persona=? AND dedupe_key=?', (*request.namespace.as_tuple, dedupe)).fetchone()
                if (cause is None or event != (ids['prepare'], 'd11', 'artifact_draft_phase_model_queued',
                        'd11-current:' + cause['original_digest'][:48], cause['original_digest'], 'pending')):
                    raise AuthorityUnavailable('phase wake lost exact original queued cause/disposition')
    if (request.operation_id != expected or request.request_digest != foreground_typed_command_digest_v1(
            installed_operation_v1(request.operation_kind), body) or not now < deadline):
        raise AuthorityUnavailable('phase foreground command digest/once identity/original deadline differs')
    atom(selector.plan_ref); atom(selector.decision_ref)
    return permitted, deadline


_ARTIFACT_PHASE_FINAL_OPERATIONS_V2=frozenset({'finish_artifact_receipt_cycle_v1','derive_artifact_completion_receipt_v1','input:register_life_outcome_v2','advance_life','settle_project_checkpoint','settle_personal_goal'})


def _qualify_artifact_method_final_foreground_v2(db, *, request, continuation, issuer, installed_bundle, owner_guard, now, atom):
    from ..runtime.d11_artifact_draft_content_v1 import (read_current_artifact_phase_verified_v2,artifact_method_final_operation_ids_v2,
        _read_phase_content_adoption_original_v2,_read_actual_phase_file_v2)
    from ..runtime.artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2,read_current_artifact_task_milestone_v2
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.domain_production_inputs_v1 import RegisterCurrentLifeOutcomeInputRequestV2
    from ..runtime.d11_life_contract_v1 import RegisteredLifeOutcomeV2
    from ..runtime.d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    from ..runtime.d10_project_checkpoint_v1 import SettleCurrentProjectCheckpointRequestV1
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from ..domains.d08.production_operations_v1 import observed_action_outcome_key_v1
    from ..domains.d08.execution import _decode_intent
    from ..runtime.d11_types import runtime_cost_settlement_key
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    selector=continuation.call_plan.phase_group.selector;ids=artifact_method_final_operation_ids_v2(selector)
    milestone=read_current_artifact_task_milestone_v2(db,namespace=request.namespace,original_ref=artifact_task_milestone_original_ref_v2(selector),issuer=issuer)
    if (milestone.ordered_phase_originals!=continuation.call_plan.phase_group.completed_phase_originals
            or milestone.owner_guard!=owner_guard or now>=milestone.original_deadline_utc or continuation.pending_effect_refs):
        raise AuthorityUnavailable('method final operation lost current disclosed complete milestone or original scope')
    verified=read_current_artifact_phase_verified_v2(db,namespace=request.namespace,selector=selector,issuer=issuer)
    if (verified.original_ref,verified.digest)!=(milestone.full_check_original_ref,milestone.full_check_original_digest):
        raise AuthorityUnavailable('method final operation changed its actual signed full check')
    if request.plan_ref!=selector.plan_ref or milestone.selector!=selector:
        raise AuthorityUnavailable('method final operation changed its actual selected Plan or semantic milestone')
    adoption,_,_,_=_read_phase_content_adoption_original_v2(db,namespace=request.namespace,selector=verified.content_selector,issuer=issuer)
    prepared,terminal,_,_=_read_actual_phase_file_v2(db,namespace=request.namespace,selector=verified.content_selector,adoption=adoption,
        result_ref=verified.readback_original_ref,issuer=issuer)
    project_ref=prepared.plan.project.ref
    if project_ref!=milestone.project_ref:raise AuthorityUnavailable('method final file belongs to another actual project')
    if request.operation_kind=='input:register_life_outcome_v2':
        action_key=AtomKey.from_token(prepared.plan.action_intent.ref);action=_decode_intent(atom(action_key))
        body=RegisterCurrentLifeOutcomeInputRequestV2(ids['outcome_ref'],RegisteredLifeOutcomeV2(
            terminal.binding.plan_original_ref,observed_action_outcome_key_v1(action_key,action).token,terminal.claim.original_ref,
            terminal.original_ref,terminal.binding.artifact_ref,terminal.payload.artifact_digest,
            (runtime_cost_settlement_key(*request.namespace.as_tuple,terminal.binding.activity_id,terminal.binding.reservation_operation_id).token,)))
        expected=ids['outcome_register']
    elif request.operation_kind=='advance_life':
        original=_read(db,issuer=issuer,namespace=request.namespace,kind='outcome',ref=ids['outcome_ref'])
        if original is None:raise AuthorityUnavailable('method progress requires its actual registered full-file outcome')
        from ..runtime.d11_life_contract_v1 import life_from_wire_v1
        outcome=life_from_wire_v1(original[0],RegisteredLifeOutcomeV2)
        if (outcome.artifact_ref,outcome.artifact_digest,outcome.terminal_original_ref)!=(
                terminal.binding.artifact_ref,terminal.payload.artifact_digest,terminal.original_ref):
            raise AuthorityUnavailable('method progress substituted another paid full-file terminal outcome')
        body=AdvanceCurrentLifeRequestV1(project_ref,ids['outcome_ref']);expected=ids['advance']
    else:
        from ..runtime.domain_background_read_v3 import background_inventory_v3
        rows=tuple((item.key.token,item.revision,item.value)for item in background_inventory_v3(db,request.namespace,'d10.life_progress.v1',valid_only=True)if item.value['effect_id']==terminal.binding.effect_id)
        if len(rows)!=1:raise AuthorityUnavailable('method final operation requires its unique actual same-effect D10 progress')
        progress_ref=rows[0][0];progress=atom(progress_ref)
        if (progress['project_ref'],progress['artifact_ref'])!=(project_ref,terminal.binding.artifact_ref):
            raise AuthorityUnavailable('method final progress changed actual project/full-file identity')
        if request.operation_kind=='settle_project_checkpoint':
            key=project_checkpoint_key_v1(request.namespace,project_ref);checkpoint=atom(key)
            revision=db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0]
            body=SettleCurrentProjectCheckpointRequestV1(project_ref,selector.plan_ref,progress_ref,None,revision);expected=ids['project_settle']
        else:
            goal_ref=milestone.goal_ref;goal=atom(goal_ref);plan=atom(selector.plan_ref)
            revisions=tuple(db.execute('SELECT revision FROM graph_atoms WHERE token=?',(ref,)).fetchone()[0] for ref in (goal_ref,selector.plan_ref))
            if plan['goal_ref']!=goal_ref or goal['state']!='active':raise AuthorityUnavailable('method Goal settlement changed actual unfinished Goal/Plan')
            body=SettleCurrentPersonalGoalRequestV1(goal_ref,selector.plan_ref,progress_ref,*revisions);expected=ids['goal']
    if request.operation_id!=expected or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body):
        raise AuthorityUnavailable('method final operation changed its fixed actual typed request')
    return set(adoption.content.source_refs),milestone.original_deadline_utc


_ARTIFACT_PREDECISION_OPERATIONS_V2=frozenset({'prepare_personal_candidate_eligibility_v1', 'adopt_personal_candidate_eligibility_v1', 'input:register_artifact_task_text_extent',
    'input:register_artifact_phase_postcondition_policy_v1','prepare_personal_candidates_v1','select_personal_step_v2'})


def _qualify_artifact_task_predecision_foreground_v2(db, *, request, job, continuation, issuer, installed_bundle,
        current_self, owner_guard, now, atom):
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from ..runtime.d08_personal_candidate_v1 import (CurrentArtifactTaskChoiceRequestV2,
        readonly_current_artifact_task_predecision_requests_v2,readonly_current_artifact_task_choice_material_v2)
    from ..runtime.artifact_phase_postconditions_v1 import (readonly_current_task_predecision_facts_v2,
        readonly_current_artifact_phase_policy_basis_v1,artifact_phase_policy_registration_operation_id_v1)
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2,PreparedPersonalCandidateSetV1
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV1
    if (request.operation_kind not in _ARTIFACT_PREDECISION_OPERATIONS_V2 or job is None
            or type(continuation.call_plan) is not ForegroundCallPlanV1 or request.purpose!='consolidation'):
        raise AuthorityUnavailable('preDecision Self operations require their actual preDecision foreground task cycle')
    task=artifact_draft_task_selector_v1(request.namespace,c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.draft_root_registration_ref)
    pre=readonly_current_artifact_task_predecision_requests_v2(db,namespace=request.namespace,
        request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
    ids=dict(pre.ids);method=None
    access_epoch,delete_epoch=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',request.namespace.as_tuple).fetchone()
    if request.operation_kind=='input:register_artifact_task_text_extent':
        body=pre.extent_request;expected=ids['extent']
    elif request.operation_kind=='input:register_artifact_phase_postcondition_policy_v1':
        operation=installed_operation_v1(request.operation_kind)
        matches=tuple(q for q in pre.policy_requests if foreground_typed_command_digest_v1(operation,q)==request.request_digest)
        if len(matches)!=1:raise AuthorityUnavailable('Self policy registration changed actual bounded method/observer/extent request')
        body=matches[0];method=body.method_ref
        # The exact original basis is rebuilt by the shared formal Policy reader.
        policy=readonly_current_artifact_phase_policy_basis_v1(db,namespace=request.namespace,request=body,
            issuer=issuer,bundle=installed_bundle,owner_guard=owner_guard,now_utc=now,
            parent_budget_lease_ref=request.parent_budget_lease_ref,actor_ref=current_self.self_entity_ref,
            purpose=request.purpose,audiences=request.audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
        expected=artifact_phase_policy_registration_operation_id_v1(policy)
    elif request.operation_kind in {'prepare_personal_candidate_eligibility_v1','adopt_personal_candidate_eligibility_v1'}:
        from ..runtime.personal_candidate_eligibility_v1 import PersonalEligibilityRequestV1, personal_eligibility_request_id_v1
        material=readonly_current_artifact_task_choice_material_v2(db,namespace=request.namespace,
            request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
        body=PersonalEligibilityRequestV1(material.prepare_request)
        expected=personal_eligibility_request_id_v1(db,request.namespace,material.prepare_request,
            prepare=request.operation_kind=='prepare_personal_candidate_eligibility_v1')
    elif request.operation_kind=='prepare_personal_candidates_v1':
        material=readonly_current_artifact_task_choice_material_v2(db,namespace=request.namespace,
            request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
        body=material.prepare_request;expected=ids['prepare']
    else:
        prepared_original=read_adopted_domain_operation_v1(db,request.namespace,ids['prepare'])
        if prepared_original is None or (prepared_original['domain'],prepared_original['operation_kind'])!=('d08','prepare_personal_candidates_v1'):
            raise AuthorityUnavailable('Self selection requires its actual immutable candidate preparation')
        prepared=decode_typed_production_value_v1(prepared_original['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
        material=readonly_current_artifact_task_choice_material_v2(db,namespace=request.namespace,
            request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
        if (prepared_original['payload']['request']!=json.loads(canonical_serialize(material.prepare_request))
                or (prepared.plan_head,prepared.goal_head)!=(pre.plan_head,pre.goal_head)
                or prepared.selection_operation_id!=ids['select'] or prepared.parent_budget_lease_ref!=request.parent_budget_lease_ref
                or prepared_original['payload']['owner_guard']!=json.loads(canonical_serialize(owner_guard))):
            raise AuthorityUnavailable('Self selection changed actual task parameters/Plan/Goal/Owner/budget')
        for version in prepared.read_versions:
            atom(version.key,required=version.revision>0)
            actual=db.execute('SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
                (*request.namespace.as_tuple,version.key.token)).fetchone()
            if (0 if actual is None else actual[0])!=version.revision:
                raise AuthorityUnavailable('Self selection lost actual candidate preparation current heads')
        body=SelectCurrentPersonalStepRequestV2(pre.plan_head.key.token,pre.goal_head.key.token,ids['prepare']);expected=ids['select']
    if (request.operation_id!=expected or request.plan_ref!=pre.plan_head.key.token
            or request.cue_source_ref!=continuation.source_ref or request.cycle_job_ref!=task.cycle_job_ref
            or job.budget_ref!=request.parent_budget_lease_ref
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)):
        raise AuthorityUnavailable('Self preDecision command changed its actual factory request/fixed identity/task cycle')
    approval=readonly_current_task_predecision_facts_v2(db,namespace=request.namespace,task=task,
        operation='prepare_personal_candidates_v1' if request.operation_kind in {'prepare_personal_candidate_eligibility_v1','adopt_personal_candidate_eligibility_v1'} else request.operation_kind,method_ref=method,actor_ref=current_self.self_entity_ref,bundle=installed_bundle,
        issuer=issuer,owner_guard=owner_guard,now_utc=now,purpose=request.purpose,audiences=request.audiences,
        access_epoch=access_epoch,delete_epoch=delete_epoch)
    if request.operation_kind=='prepare_personal_candidates_v1':
        from ..runtime.artifact_phase_postconditions_v1 import (ArtifactStandingPredecisionApprovalOriginalV3,
            artifact_candidate_preparation_parent_ref_v1,readonly_current_artifact_preparation_completion_v1)
        if type(approval) is ArtifactStandingPredecisionApprovalOriginalV3:
            parent_ref=artifact_candidate_preparation_parent_ref_v1(task,pre.plan_head)
            parent=readonly_current_artifact_preparation_completion_v1(db,namespace=request.namespace,
                request=ArtifactPreparationChildSelectorV1(parent_ref,'evaluate'),actor_ref=current_self.self_entity_ref,
                bundle=installed_bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now,purpose=request.purpose,
                audiences=request.audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
            if parent.parent_prepare_operation_id!=request.operation_id:
                raise AuthorityUnavailable('candidate prepare belongs to another immutable Parent completion')
    plan=atom(pre.plan_head.key);atom(pre.goal_head.key)
    return tuple(dict.fromkeys((request.cue_source_ref,*plan['source_refs']))),approval.original_deadline_utc



def _qualify_artifact_task_plan_revision_foreground_v2(db, *, request, job, continuation, issuer, installed_bundle,
        current_self, owner_guard, now, atom):
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from ..runtime.d08_personal_plan_v1 import (ReviseCurrentArtifactTaskPlanRequestV2,
        artifact_task_plan_revision_basis_v2,artifact_task_plan_revision_operation_id_v2)
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV1
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.d11_offline_originals_v1 import _utc
    if request.operation_kind!='revise_artifact_task_plan_v2' or job is None or type(continuation.call_plan) is not ForegroundCallPlanV1:
        raise AuthorityUnavailable('task Plan revision requires its actual ordinary amendment foreground cycle')
    task=artifact_draft_task_selector_v1(request.namespace,c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.draft_root_registration_ref)
    body=ReviseCurrentArtifactTaskPlanRequestV2(task)
    objective,scope,producer,amendment,amendment_ref,amendment_key,previous,settled,completion,goal,plan,checkpoint=artifact_task_plan_revision_basis_v2(
        db,namespace=request.namespace,request=body,issuer=issuer)
    from ..runtime.ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    root=scope.root;policy=installed_bundle.installation_policy
    if (request.operation_id!=artifact_task_plan_revision_operation_id_v2(task)
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)
            or request.plan_ref!=plan.key.token or request.cue_source_ref!=amendment.source_ref
            or request.cycle_job_ref!=task.cycle_job_ref or request.purpose!='consolidation'
            or job.budget_ref!=request.parent_budget_lease_ref
            or (type(scope) is not IngressArtifactTaskScopeOriginalV3 and completion.owner_guard!=owner_guard)
            or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(owner_guard.grant_ref,owner_guard.grant_revision,owner_guard.grant_digest)
            or (root.installation_id,root.manifest_digest)!=(policy.installation_id,policy.manifest_digest)):
        raise AuthorityUnavailable('task Plan revision changed its actual amendment/partial history/Owner/installation/fixed request')
    for original_atom in (goal,plan,checkpoint):
        if atom(original_atom.key)!=original_atom.value:raise AuthorityUnavailable('task Plan revision lost exact current partial heads')
    atom(amendment_key);atom(amendment.source_ref);atom(previous.source_head.key)
    from ..runtime.artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    from ..runtime.ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=request.namespace,
        scope=scope,objective=objective,issuer=issuer,bundle=installed_bundle,owner_guard=owner_guard,
        now_utc=now,parent_budget_lease_ref=request.parent_budget_lease_ref)
    prior_deadline=authorization_deadline if type(scope) is IngressArtifactTaskScopeOriginalV3 else completion.original_deadline_utc
    deadline=min(authorization_deadline,prior_deadline,_utc(root.valid_until_utc).timestamp())
    if now>=deadline:raise AuthorityUnavailable('task Plan revision cannot renew its original objective/root deadline')
    return tuple(dict.fromkeys((*plan.value['source_refs'],amendment.source_ref,previous.source_head.key.token))),deadline



def _qualify_artifact_preparation_foreground_v2(db, *, request, job, continuation, issuer, installed_bundle,
        current_self, owner_guard, now, atom):
    from ..runtime.artifact_phase_postconditions_v1 import (_preparation_current_basis_v1,
        readonly_current_artifact_preparation_child_facts_v1,FreezeArtifactCandidatePreparationRequestV1,
        artifact_candidate_preparation_parent_operation_id_v1)
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    if (type(request) not in {ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}
            or installed_bundle is None or job is None or type(continuation.call_plan) is not ForegroundCallPlanV1
            or request.purpose!='consolidation'):
        raise AuthorityUnavailable('internal preparation requires exact V2, actual installed preDecision task and private parent pipeline')
    epochs=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',request.namespace.as_tuple).fetchone()
    kwargs=dict(namespace=request.namespace,actor_ref=current_self.self_entity_ref,bundle=installed_bundle,issuer=issuer,
        owner_guard=owner_guard,now_utc=now,purpose=request.purpose,audiences=request.audiences,
        access_epoch=epochs[0],delete_epoch=epochs[1])
    if type(request) is ForegroundActivityPreparationParentRequestV2:
        task=request.preparation_task
        material,approval,scope_ref,scope,source_head,lease,grant,deadline,children=_preparation_current_basis_v1(db,task=task,**kwargs)
        body=FreezeArtifactCandidatePreparationRequestV1(task)
        expected=artifact_candidate_preparation_parent_operation_id_v1(task,material.plan_head)
        source_ref=source_head.key.token;plan_head=material.plan_head;goal_head=material.goal_head
        parent_lease=lease.lease_id
    else:
        facts=readonly_current_artifact_preparation_child_facts_v1(db,request=request.preparation_child,**kwargs)
        parent=facts.parent;task=parent.request.task
        if parent.digest!=request.preparation_parent_digest:
            raise AuthorityUnavailable('internal child changed the actual signed Parent original digest')
        if (facts.operation_kind,facts.operation_id)!=(request.operation_kind,request.operation_id):
            raise AuthorityUnavailable('internal child changed its exact approved fixed slot operation')
        body=facts.request;expected=facts.operation_id;deadline=parent.original_deadline_utc
        source_ref=parent.source_head.key.token;plan_head=parent.plan_head;goal_head=parent.goal_head
        parent_lease=parent.parent_budget_lease_ref
    actual_task=artifact_draft_task_selector_v1(request.namespace,c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.draft_root_registration_ref)
    if (actual_task!=task or request.cycle_job_ref!=task.cycle_job_ref or request.operation_id!=expected
            or request.plan_ref!=plan_head.key.token or request.cue_source_ref!=source_ref or continuation.source_ref!=source_ref
            or (request.parent_budget_lease_ref,job.budget_ref)!=(parent_lease,parent_lease)
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)):
        raise AuthorityUnavailable('internal preparation changed actual task/Source/Plan/budget/current typed material')
    plan=atom(plan_head.key);atom(goal_head.key);atom(source_ref)
    if now>=deadline:raise AuthorityUnavailable('internal preparation cannot revive its original Parent deadline')
    return tuple(dict.fromkeys((source_ref,*plan['source_refs']))),deadline
