"""C4 preparation and once worker on the existing Life originals/jobs/budget."""

from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
from dataclasses import asdict,dataclass, fields, field, replace
from datetime import datetime, timezone
import json

from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1, ArtifactDraftInputV1,
    ArtifactDraftSourceV1, artifact_draft_from_wire_v1, artifact_draft_model_ids_v1,
    WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST)
from ..runtime_contracts import NamespaceId, GraphVersion, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, DraftFileTargetV1, draft_from_wire_v1
from .d11_life_preparation_v1 import _read, _record
from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, _adopted_c02_v1
from .foreground_call_plan_v1 import require_protected_reply_budget_v1, ForegroundModelAttemptV1, ForegroundCallPlanV1
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .jobs import PersistentJob, create_job, get_job, plan_job_acquire, _utc, _utc_text
from .d11_types import job_graph_write, runtime_job_key, D11RuntimeProvider, D11_PROPOSAL_SCHEMA
from .issuers import D11BudgetJobIssuer, ResourceQuote
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..runtime_contracts import schema_hash
from .d11_types import TYPE_SCHEMA_HASHES

C4_ORIGINAL_KINDS = frozenset({"c4_frozen","c4_prepared","c4_request","c4_call","c4_result","c4_paid","c4_adopted"})
C4_MODEL_PROPOSAL_SCHEMA="d11.artifact-draft-model.proposal.v1"
C4_MODEL_PROPOSAL_HASH=schema_hash({"schema":C4_MODEL_PROPOSAL_SCHEMA,"job_schema_hash":TYPE_SCHEMA_HASHES["runtime.job"],
    "transitions":("prepare_once_and_cycle_wait","self_acquires_actual_tls_worker_once","actual_paid_authored_source_completes_job")})


@dataclass(frozen=True, slots=True)
class PrepareArtifactDraftModelRequestV1:
    selector: ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftTaskSelectorV1:raise TypeError("exact C4 task selector required")


@dataclass(frozen=True, slots=True)
class AcquireArtifactDraftModelRequestV1:
    selector: ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftTaskSelectorV1:raise TypeError("exact C4 task selector required")


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelPreparedV1:
    selector: ArtifactDraftTaskSelectorV1
    installation_id: str
    manifest_digest: str
    activation_generation: int
    activity_id: str
    actor_ref: str
    worker_subject: str
    frozen_ref: str
    frozen_digest: str
    workflow_digest: str
    provider_config_digest: str
    job_id: str
    operation_id: str
    acquire_operation_id: str
    call_id: str
    quote_id: str
    quote_digest: str
    reservation_digest: str
    parent_budget_lease_ref: str
    audiences: tuple[str, ...]
    deadline_utc: str
    cancel_generation: int
    owner_guard_digest: str
    owner_guard:ProductionOwnerGuardV1
    schema: str = "d11.artifact-draft-model-prepared.v1"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest, _text
        if (self.schema != "d11.artifact-draft-model-prepared.v1"
                or type(self.selector) is not ArtifactDraftTaskSelectorV1
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.cancel_generation) is not int or self.cancel_generation != 0
                or type(self.audiences) is not tuple or not self.audiences or len(set(self.audiences)) != len(self.audiences)):
            raise ValueError("exact C4 prepared version/generation/scope required")
        for name in ("manifest_digest","frozen_digest","workflow_digest","provider_config_digest","quote_digest","reservation_digest","owner_guard_digest"):
            _digest(getattr(self,name))
        for name in ("installation_id","activity_id","actor_ref","worker_subject","parent_budget_lease_ref"):_text(getattr(self,name),name)
        if not self.worker_subject.startswith("mtls:sha256:"):raise ValueError("C4 worker must be the actual installed TLS subject")
        ids = artifact_draft_model_ids_v1(self.selector)
        if (self.frozen_ref,self.job_id,self.operation_id,self.acquire_operation_id,self.call_id,self.quote_id) != (
                ids["frozen"],ids["job"],ids["prepare"],ids["acquire"],ids["call"],ids["quote"]):
            raise ValueError("C4 prepared changed the original once identities")
        _utc(self.deadline_utc,"deadline_utc")
        if type(self.owner_guard) is not ProductionOwnerGuardV1 or canonical_digest(plain_v1(self.owner_guard))!=self.owner_guard_digest:
            raise ValueError("C4 prepared changed its actual foreground upstream Owner guard")
        if len(canonical_serialize(plain_v1(self)).encode()) > 65536:raise ValueError("C4 prepared metadata exceeds64KiB")

    @property
    def namespace(self):return self.selector.namespace

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelRequestOriginalV1:
    prepared_digest: str
    request_digest: str
    request_json: str
    schema: str = "d11.artifact-draft-model-request.v1"

    def __post_init__(self):
        from .natural_reply_job_v2 import _request_from_wire
        from ..model_broker.artifact_draft_v1 import artifact_draft_provider_messages_v1, _digest
        _digest(self.prepared_digest);_digest(self.request_digest)
        if self.schema != "d11.artifact-draft-model-request.v1" or len(self.request_json.encode()) > 65536:
            raise ValueError("C4 acquired request metadata/wire exceeds its exact bound")
        request = _request_from_wire(self.request_json)
        artifact_draft_provider_messages_v1(request)
        if request.digest != self.request_digest:raise ValueError("C4 acquired request digest differs")


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelStageV1:
    frame: object
    stage: object
    prepared: ArtifactDraftModelPreparedV1
    frozen: ArtifactDraftInputV1
    job: PersistentJob
    model_request: object | None
    before_cycle: PersistentJob | None
    after_cycle: PersistentJob | None
    quote: ResourceQuote | None = None
    before_job: PersistentJob | None = None


@dataclass(frozen=True, slots=True)
class InstalledArtifactDraftModelReadersV1:
    issuer: D11BudgetJobIssuer
    installed_bundle: object
    model_runtime: "InstalledArtifactDraftModelRuntimeV1 | None" = None
    owner_assignment_guard: object = None

    def __post_init__(self):
        from ..host.authority_profile import AdminInstallationBundle
        if type(self.issuer) is not D11BudgetJobIssuer or type(self.installed_bundle) is not AdminInstallationBundle:
            raise TypeError("C4 needs the actual installed signed issuer/bundle")
        if self.model_runtime is not None and type(self.model_runtime) is not InstalledArtifactDraftModelRuntimeV1:
            raise TypeError("C4 paired originals require the concrete installed runtime")
        if self.owner_assignment_guard is not None:
            from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
            if type(self.owner_assignment_guard) is not OwnerAuthorizationGuardV1:
                raise TypeError("project role choice requires its actual paired Owner guard")

    @property
    def resource_issuer(self):return self.issuer.resource_issuer


def installed_artifact_draft_workflow_v1(bundle):
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    from ..host.authority_profile import AdminInstallationBundle, AdminModelWorkflowV2
    if type(bundle) is not AdminInstallationBundle or type(bundle.model_workflows) not in (AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
        raise MissingProductionOriginalV1("explicit_installed_artifact_draft_workflows_v4")
    workflow = bundle.model_workflows.artifact_draft
    if (type(workflow) is not AdminModelWorkflowV2
            or (workflow.work_kind,workflow.purpose,workflow.template_version) != (WORK_KIND,"consolidation",TEMPLATE_VERSION)
            or set(workflow.quote_ceiling) != {"input_tokens","output_tokens","model_tokens","model_microusd"}
            or workflow.quote_ceiling["input_tokens"] > 10000 or workflow.quote_ceiling["output_tokens"] > 2000
            or workflow.max_output_tokens > 2000):
        raise MissingProductionOriginalV1("finite_explicit_artifact_draft_model_slot")
    return workflow


from ..host.authority_profile import is_installed_artifact_draft_slot_v1


def artifact_draft_model_from_wire_v1(raw, kind):
    if kind not in {PrepareArtifactDraftModelRequestV1,AcquireArtifactDraftModelRequestV1,
            ArtifactDraftModelPreparedV1,ArtifactDraftModelRequestOriginalV1}:
        raise ValueError("unregistered C4 technical codec")
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:raise ValueError("closed C4 technical fields differ")
    data = dict(raw)
    if "selector" in data:data["selector"] = artifact_draft_from_wire_v1(data["selector"],ArtifactDraftTaskSelectorV1)
    if kind is ArtifactDraftModelPreparedV1:
        data["audiences"] = tuple(data["audiences"])
        data["owner_guard"]=ProductionOwnerGuardV1(**data["owner_guard"])
    result = kind(**data)
    if plain_v1(result) != raw:raise ValueError("noncanonical C4 technical wire")
    return result


def decode_artifact_draft_original_v1(kind,raw):
    """Closed existing-Life-table variants for registered readers and C09."""
    if kind=="c4_frozen":return artifact_draft_from_wire_v1(raw,ArtifactDraftInputV1)
    if kind=="c4_prepared":return artifact_draft_model_from_wire_v1(raw,ArtifactDraftModelPreparedV1)
    if kind=="c4_request":return artifact_draft_model_from_wire_v1(raw,ArtifactDraftModelRequestOriginalV1)
    if kind=="c4_call":
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        return from_wire(raw,ModelEgressIntentV1)
    if kind=="c4_result":
        from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadV1,artifact_draft_model_result_from_wire_v1
        return artifact_draft_model_result_from_wire_v1(raw,ArtifactDraftModelResultReadV1)
    if kind=="c4_paid":
        from .model_cost_settlement import OriginalModelCostCommitV1
        from ..model_broker.artifact_draft_v1 import _digest,_text
        if type(raw) is not dict or set(raw)!={f.name for f in fields(OriginalModelCostCommitV1)}:
            raise ValueError("C4 original cost commit fields differ")
        value=OriginalModelCostCommitV1(**raw)
        if (value.schema!="sylanne.d11.original-model-cost-commit.v1" or value.status!="committed" or value.quote_version!=1
                or any(type(n) is not int or n<1 for n in (value.commit_seq,value.graph_revision,value.graph_epoch))):
            raise ValueError("C4 original cost commit has another state/version")
        for name in ("terminal_receipt_digest","budget_receipt_digest"):_digest(getattr(value,name))
        for name in ("operation_id","call_id","quote_id","cost_ref"):_text(getattr(value,name),name)
        if AtomKey.from_token(value.cost_ref).type_name!="runtime.cost_settlement":raise ValueError("C4 paid original lost actual cost ref")
        return value
    if kind=="c4_adopted":
        from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1,artifact_draft_content_from_wire_v1
        return artifact_draft_content_from_wire_v1(raw,ArtifactDraftContentAdoptionV1)
    raise ValueError("unregistered C4 original technical kind")


def read_artifact_draft_prepared_v1(db, *, namespace, issuer, selector):
    ids = artifact_draft_model_ids_v1(selector)
    original = _read(db,issuer=issuer,namespace=namespace,kind="c4_prepared",ref=ids["job"])
    if original is None:return None
    prepared = artifact_draft_model_from_wire_v1(original[0],ArtifactDraftModelPreparedV1)
    if prepared.selector != selector or original[1] != prepared.operation_id:raise ValueError("C4 prepared selector/commit changed")
    return prepared


def read_artifact_draft_frozen_v1(db, *, prepared, issuer):
    row = _read(db,issuer=issuer,namespace=prepared.namespace,kind="c4_frozen",ref=prepared.frozen_ref)
    if row is None:raise MissingProductionOriginalV1("actual_committed_c4_frozen_input")
    frozen = artifact_draft_from_wire_v1(row[0],ArtifactDraftInputV1)
    if frozen.digest != prepared.frozen_digest or frozen.selector != prepared.selector:
        raise ValueError("C4 frozen input changed from its exact prepared seal")
    return frozen


def read_plan_artifact_draft_model_v1(db,*,namespace,operation_kind,request):
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d03.self_perspective import self_mapping_key
    if type(request) not in {PrepareArtifactDraftModelRequestV1,AcquireArtifactDraftModelRequestV1}:
        raise TypeError("registered C4 model readplan request required")
    selector=request.selector;ids=artifact_draft_model_ids_v1(selector)
    cycle=get_job(db,AtomKey.from_token(selector.cycle_job_ref).name)
    cont=foreground_cycle_from_wire_v1(cycle.continuation)
    keys=[AtomKey.from_token(selector.cycle_job_ref),runtime_job_key(*namespace.as_tuple,cycle.activity_id,ids["job"]),
        self_mapping_key(namespace),owner_grant_key(*namespace.as_tuple)]
    originals=[selector.root_registration_ref,selector.c02_operation_id]
    if type(request) is AcquireArtifactDraftModelRequestV1:originals.extend((ids["job"],ids["frozen"]))
    base=production_read_plan_v1((),keys,(cont.source_ref,),originals)
    from .artifact_continuation_originals_v1 import (read_selected_artifact_continuation_request_v1,
        read_plan_existing_artifact_continuation_v1)
    selected = read_selected_artifact_continuation_request_v1(db, namespace=namespace, selector=selector)
    if selected is not None:
        extra = read_plan_existing_artifact_continuation_v1(db, namespace=namespace, request=selected[0])
        base = production_read_plan_v1((*base.fixed_type_ids, *extra.fixed_type_ids),
            (*base.exact_keys, *extra.exact_keys), (*base.source_roots, *extra.source_roots),
            (*base.required_original_refs, *extra.required_original_refs))
    if type(request) is PrepareArtifactDraftModelRequestV1:
        from .d10_project_checkpoint_v1 import read_plan_current_project_capacity_v1
        capacity=read_plan_current_project_capacity_v1(db,namespace=namespace,selector=request.selector)
        return production_read_plan_v1((*base.fixed_type_ids,*capacity.fixed_type_ids),(*base.exact_keys,*capacity.exact_keys),
            (*base.source_roots,*capacity.source_roots),(*base.required_original_refs,*capacity.required_original_refs))
    return base


def _current_task(db, *, frame, selector, readers, require_running_cycle=True):
    from ..domains.d03.self_perspective import self_mapping_key
    from ..domains.d03.self_identity_qualification import SelfIdentityMapping
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(readers) is not InstalledArtifactDraftModelReadersV1 or selector.namespace != frame.envelope.authority.namespace:
        raise TypeError("C4 requires its exact installed current task readers")
    read = CurrentDomainReadV1(frame);read.check(db)
    cycle = get_job(db,AtomKey.from_token(selector.cycle_job_ref).name)
    atom = read.head(db,selector.cycle_job_ref,required=True)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    if (atom.value != job_graph_write(cycle).value or continuation.c02_operation_id != selector.c02_operation_id
            or cycle.cancel_epoch or continuation.cancel_generation
            or require_running_cycle and (cycle.phase != "running" or cycle.lease_holder != frame.envelope.authority.actor)
            or cycle.phase in {"completed","failed","cancelled","draining","pending_confirmation"}
            or frame.now_utc >= _utc(cycle.deadline_utc,"deadline_utc").timestamp()):
        raise ValueError("C4 original task/cycle/cancel/deadline is not current")
    _adopted_c02_v1(db,selector.namespace,selector.c02_operation_id)
    require_protected_reply_budget_v1(db,namespace=selector.namespace,plan=continuation.call_plan,
        issuer=readers.issuer,now_utc=frame.now_utc,installed_bundle=readers.installed_bundle,owner_guard=frame.owner_guard)
    root_row = _read(db,issuer=readers.issuer,namespace=selector.namespace,kind="draft_root_capability",ref=selector.root_registration_ref)
    if root_row is None:raise MissingProductionOriginalV1("actual_registered_c4_draft_root")
    root = draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
    read.original(root.registration_ref,kind="d11.life_draft_root_capability",digest=canonical_digest(root_row[0]))
    policy = readers.installed_bundle.installation_policy
    runtime=readers.model_runtime
    if runtime is None or (runtime.client_grant.installation_id,runtime.client_grant.manifest_digest)!= (
            policy.installation_id,policy.manifest_digest):raise MissingProductionOriginalV1("actual_same_installation_c4_tls_worker")
    if (root.source_ref != continuation.source_ref or len(root.filenames) != 1
            or (root.installation_id,root.manifest_digest) != (policy.installation_id,policy.manifest_digest)
            or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest) !=
               (frame.owner_guard.grant_ref,frame.owner_guard.grant_revision,frame.owner_guard.grant_digest)
            or frame.now_utc >= __import__("sylanne3.runtime.d11_offline_originals_v1",fromlist=["_utc"])._utc(root.valid_until_utc).timestamp()):
        raise ValueError("C4 explicit unique root/Source/upstream Owner scope changed")
    from .ingress_artifact_task_scope_v1 import (task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,
        IngressArtifactTaskScopeOriginalV3,ArtifactTaskObjectiveV1,_decode)
    scope_row=_read(db,issuer=readers.issuer,namespace=selector.namespace,kind="artifact_task_scope",ref=task_scope_ref_v1(root.registration_ref))
    if scope_row is not None:
        scope=_decode(scope_row[0],IngressArtifactTaskScopeOriginalV1)
        if type(scope) is IngressArtifactTaskScopeOriginalV3:
            from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
            objective_row=_read(db,issuer=readers.issuer,namespace=selector.namespace,kind="artifact_task_objective",ref=scope.objective_ref)
            resolve_artifact_task_authorization_deadline_v2(db,namespace=selector.namespace,scope=scope,
                objective=_decode(objective_row[0],ArtifactTaskObjectiveV1),issuer=readers.issuer,
                bundle=readers.installed_bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
                parent_budget_lease_ref=cycle.budget_ref)
    family = read.source_family(db,(continuation.source_ref,),purpose="consolidation")
    mapping_atom = read.head(db,self_mapping_key(selector.namespace),required=True)
    mapping = decode_typed_production_value_v1(mapping_atom.value,SelfIdentityMapping)
    if mapping.status != "active" or mapping.self_entity_ref != frame.envelope.authority.actor:
        raise MissingProductionOriginalV1("actual_current_artifact_draft_self")
    read.original(mapping.certification_ref,kind="d03.current_self_identity")
    return read,cycle,continuation,root,family,mapping_atom,mapping


def _prepare_artifact_draft_model(db, *, frame, request, installed_readers, phase):
    request_type = PrepareArtifactDraftModelRequestV2 if phase else PrepareArtifactDraftModelRequestV1
    if type(request) is not request_type: raise TypeError('exact generation preparation request required')
    selector, readers = (request.selector.task if phase else request.selector), installed_readers
    phase_selector = request.selector if phase else None
    from .joint_node_execution_v1 import require_joint_artifact_frame_gate_v1
    require_joint_artifact_frame_gate_v1(db, frame=frame, selector=request.selector, issuer=readers.issuer)
    if phase:
        selected_material, chosen, _ = _selected_artifact_phase_candidate_v2(db, frame=frame, selector=phase_selector, readers=readers)
        phase_extent, phase_target, phase_prior = _current_artifact_phase_parameters_v2(db,
            selector=phase_selector, chosen=chosen, issuer=readers.issuer)
        from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,IngressArtifactTaskScopeOriginalV3,_decode
        task_scope_row=_read(db,issuer=readers.issuer,namespace=selector.namespace,kind="artifact_task_scope",ref=task_scope_ref_v1(selector.root_registration_ref))
        generation_cap=None
        if task_scope_row is not None:
            task_scope=_decode(task_scope_row[0],IngressArtifactTaskScopeOriginalV1)
            if type(task_scope) is IngressArtifactTaskScopeOriginalV3:generation_cap=task_scope.continuation_authorization.maximum_artifact_version
        require_artifact_method_physical_version_capacity_v2(selector=phase_selector,prior=phase_prior,
            installed_bundle=readers.installed_bundle,maximum_artifact_version=generation_cap)
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
        from .artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_contract_v1
        if type(chosen.binding) is not ArtifactPhaseCandidateBindingV3:
            raise MissingProductionOriginalV1('actual_predecision_postcondition_policy_commitment')
        contract = read_current_artifact_phase_postcondition_contract_v1(db, frame=frame,
            selector=phase_selector, installed_readers=readers)
        model_ids = artifact_draft_model_ids_v2
        read_prepared = read_artifact_draft_prepared_v2
        prepared_type, stage_type = ArtifactDraftModelPreparedV2, ArtifactDraftModelStageV2
        workflow = installed_artifact_draft_workflow_v2(readers.installed_bundle)
    else:
        model_ids = artifact_draft_model_ids_v1
        read_prepared = read_artifact_draft_prepared_v1
        prepared_type, stage_type = ArtifactDraftModelPreparedV1, ArtifactDraftModelStageV1
        workflow = installed_artifact_draft_workflow_v1(readers.installed_bundle)
    read,cycle,continuation,root,family,mapping_atom,mapping = _current_task(db,frame=frame,selector=selector,readers=readers)
    from .d10_project_checkpoint_v1 import require_current_artifact_project_capacity_v1
    require_current_artifact_project_capacity_v1(db,frame=frame,selector=selector,installed_readers=readers)
    ids = model_ids(request.selector)
    if phase:
        plan = continuation.call_plan
        if type(plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3} or plan.phase_group.selector != phase_selector:
            raise MissingProductionOriginalV1('actual_current_foreground_phase_group')
        require_current_artifact_phase_group_v2(db, namespace=selector.namespace, group=plan.phase_group, issuer=readers.issuer)
        if len(plan.phase_group.completed_phase_originals) != phase_selector.phase_index:
            raise ValueError('generation phase is already independently verified')
    if frame.envelope.identity.operation_id != ids["prepare"] or frame.envelope.authority.purpose != "consolidation":
        raise ValueError("C4 preparation must retain its fixed original operation/purpose")
    if any(row.slot == "C4" and (not phase or row.call_id == ids["call"]) for row in continuation.call_plan.attempts):
        raise ValueError("C4 preparation cannot replace an original draft model attempt")
    from .foreground_cycle_v1 import _current_attempt_original_v1
    for attempt in continuation.call_plan.attempts:
        if attempt.slot == "C3":
            actual = _current_attempt_original_v1(db, namespace=selector.namespace,
                continuation=continuation, attempt=attempt, issuer=readers.issuer)
            if actual.state != "completed" or actual != attempt:
                raise ValueError("C4 requires the exact completed original C3; pending or unknown calls cannot be replaced")
    if read_prepared(db,namespace=selector.namespace,issuer=readers.issuer,selector=request.selector) is not None:
        raise ValueError("C4 preparation already exists; replay its actual original receipt")
    grant = readers.issuer.current_budget_grant(db,continuation.call_plan.parent_budget_lease_ref)
    lease = get_budget_lease(db,grant.lease_id);require_budget_family_admissible(db,lease.lease_id)
    if phase:
        from .d02_artifact_phase_price_v1 import read_current_artifact_phase_reservation_ceiling_v1
        ceiling = dict(read_current_artifact_phase_reservation_ceiling_v1(db, frame=frame, selector=phase_selector,
            chosen=chosen, installed_readers=readers))
    else:
        ceiling = dict(workflow.quote_ceiling)
    if phase:
        limits = artifact_draft_phase_token_limits_v2(phase_selector)
        if (set(ceiling) != set(workflow.quote_ceiling)
                or any(amount > workflow.quote_ceiling.get(name, 0) for name, amount in ceiling.items())
                or any(ceiling[name] > amount for name, amount in limits.items())):
            raise ValueError('phase quote exceeds actual installed finite phase workflow')
    if (WORK_KIND not in grant.allowed_work_kinds or frame.envelope.parent_budget_lease_ref != lease.lease_id
            or not set(frame.envelope.authority.audience) <= set(workflow.audiences)
            or any(amount > grant.max_ceiling.get(dimension,0) or amount > lease.available(dimension)
                for dimension,amount in ceiling.items())):
        raise MissingProductionOriginalV1("actual_remaining_root_c4_budget_after_protected_reply_allocation")
    deadline = min(frame.envelope.deadline_utc,grant.valid_until_utc,_utc(cycle.deadline_utc,"deadline_utc").timestamp(),
        __import__("sylanne3.runtime.d11_offline_originals_v1",fromlist=["_utc"])._utc(root.valid_until_utc).timestamp())
    if phase: deadline = min(deadline, chosen.future_identity.deadline_utc)
    if frame.now_utc + workflow.timeout_seconds >= deadline:raise MissingProductionOriginalV1("unexpired_original_c4_deadline")
    from .artifact_continuation_originals_v1 import current_selected_artifact_target_v1
    selected = current_selected_artifact_target_v1(db, frame=frame, selector=selector,
        root=root, installed_readers=readers)
    target = (selected[1] if selected is not None else DraftFileTargetV1(
        root.resource_id,root.registration_ref,canonical_digest(plain_v1(root)),root.root_identity,
        root.filenames[0],"create",0,None,None,None,root.max_bytes))
    if phase: target = phase_target
    from ..host.authority_profile import require_installed_artifact_target_v2
    require_installed_artifact_target_v2(readers.installed_bundle.artifact_draft, root, target)
    if phase and phase_prior is not None:
        prior = phase_prior
        prior_ref = prior.source_head.ref
        family = {**family, **read.source_family(db, (prior_ref,), purpose='consolidation')}
        from .d11_artifact_draft_content_v1 import require_current_artifact_prior_content_v2
        require_current_artifact_prior_content_v2(db, namespace=selector.namespace, selector=phase_selector,
            prior=prior, issuer=readers.issuer)
    if phase:
        from .method_pair_shared_input_v1 import method_pair_read_inputs_v1, require_current_method_pair_shared_input_v1
        experiment_ref, _pair_plan = method_pair_read_inputs_v1(db, namespace=selector.namespace,
            goal_ref=selected_material.goal_head.key.token)
        if experiment_ref is not None:
            pair_inputs = require_current_method_pair_shared_input_v1(db, read=read,
                experiment_ref=experiment_ref, goal_ref=selected_material.goal_head.key.token, issuer=readers.issuer)
            if pair_inputs is None:
                raise MissingProductionOriginalV1("actual_current_registered_method_pair_shared_input")
            family = {**family, **pair_inputs[1]}
    from .artifact_frame_control_reads_v3 import artifact_model_business_read_versions_v3
    business_versions=artifact_model_business_read_versions_v3(db,frame)
    sources = tuple(ArtifactDraftSourceV1(ref,read.head(db,ref,required=True).revision,
        canonical_digest(record.to_dict()),record) for ref,record in sorted(family.items()))
    input_type = ArtifactDraftInputV3 if phase else ArtifactDraftInputV1
    frozen = input_type(request.selector,continuation.source_ref,mapping.self_entity_ref,canonical_digest(mapping_atom.value),
        target.root_registration_digest,target,sources,
        tuple(v for v in business_versions if not v.key.type_name.startswith(("runtime.","d02."))),
        frame.snapshot.epochs[0].revision,frame.envelope.version_guard.access_epoch,frame.envelope.version_guard.delete_epoch,deadline,
        **({"extent":phase_extent,"prior_content":phase_prior,
            "postcondition_contract_ref":contract.original_ref,"postcondition_contract_digest":contract.digest} if phase else {}))
    policy = readers.installed_bundle.installation_policy
    quote = ResourceQuote(ids["quote"],1,*selector.namespace.as_tuple,cycle.activity_id,ids["prepare"],None,
        lease.lease_id,WORK_KIND,ids["snapshot"],deadline,workflow.provider_config_ref,
        runtime_job_key(*selector.namespace.as_tuple,cycle.activity_id,ids["job"]).token,(),(),ceiling,None,deadline)
    reservation = canonical_digest(("d11.artifact-draft-phase-model-reservation.v2" if phase else "d11.artifact-draft-model-reservation.v1",request.selector,frozen.digest,quote,frame.owner_guard))
    prepared = prepared_type(request.selector,policy.installation_id,policy.manifest_digest,frame.activation_generation,
        cycle.activity_id,mapping.self_entity_ref,readers.model_runtime.client_grant.subject,
        ids["frozen"],frozen.digest,canonical_digest(plain_v1(workflow)),workflow.provider_config_digest,
        ids["job"],ids["prepare"],ids["acquire"],ids["call"],ids["quote"],canonical_digest(quote),reservation,
        lease.lease_id,frame.envelope.authority.audience,_utc_text(datetime.fromtimestamp(deadline,timezone.utc)),
        cycle.cancel_epoch,canonical_digest(plain_v1(frame.owner_guard)),frame.owner_guard)
    job = PersistentJob(ids["job"],ids["prepare"],cycle.activity_id,None,*selector.namespace.as_tuple,ids["snapshot"],
        "queued",WORK_KIND,{"schema":"d11.artifact-draft-phase-model-job.v2" if phase else "d11.artifact-draft-model-job.v1","selector":plain_v1(request.selector),"prepared_digest":prepared.digest},
        None,prepared.deadline_utc,lease.lease_id,workflow.provider_config_ref,{"resource_quote":ids["quote"]+":1"},None,None,0,0,{},None)
    attempt_type = ForegroundModelAttemptV2 if phase else ForegroundModelAttemptV1
    attempt = attempt_type("C4",prepared.call_id,None,prepared.operation_id,reservation,lease.lease_id,
        ceiling["input_tokens"],ceiling["output_tokens"],"reserved",
        **({"phase_selector":phase_selector} if phase else {}))
    from .foreground_cycle_v1 import ForegroundWaitV1
    plan = replace(continuation.call_plan,attempts=(*continuation.call_plan.attempts,attempt))
    wait = ForegroundWaitV1("d11","artifact_draft_phase_model_terminal" if phase else "artifact_draft_model_terminal",(),
        QueryEpoch(selector.namespace,"foreground:"+cycle.job_id,frame.snapshot.epochs[0].revision),
        continuation.wait.consume_cursor if continuation.wait is not None else 0,None)
    after_continuation = replace(continuation,stage="draft_content",call_plan=plan,wait=wait)
    after_cycle = replace(cycle,phase="waiting",continuation=plain_v1(after_continuation),wake_condition=plain_v1(wait),
        lease_holder=None,lease_expires_utc=None)
    stage = stage_result_v1(frame,"d11","prepare_artifact_draft_model_v2" if phase else "prepare_artifact_draft_model",request,
        writes=(job_graph_write(job),job_graph_write(after_cycle)),
        provenance={"prepared":prepared,"frozen_ref":prepared.frozen_ref,"frozen_digest":frozen.digest,
            "before_cycle":cycle,"after_cycle":after_cycle},receiver_events=(("d11","artifact_draft_phase_model_queued" if phase else "artifact_draft_model_queued"),),
        proposal_schema=C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 if phase else C4_MODEL_PROPOSAL_SCHEMA,
        proposal_hash=C4_PHASE_MODEL_PROPOSAL_HASH_V2 if phase else C4_MODEL_PROPOSAL_HASH)
    return stage_type(frame,stage,prepared,frozen,job,None,cycle,after_cycle,quote,None)


def prepare_current_artifact_draft_model_v1(db, *, frame, request, installed_readers):
    return _prepare_artifact_draft_model(db, frame=frame, request=request, installed_readers=installed_readers, phase=False)


def prepare_current_artifact_draft_model_v2(db, *, frame, request, installed_readers):
    return _prepare_artifact_draft_model(db, frame=frame, request=request, installed_readers=installed_readers, phase=True)


def _acquire_artifact_draft_model(db, *, frame, request, installed_readers, phase):
    request_type = AcquireArtifactDraftModelRequestV2 if phase else AcquireArtifactDraftModelRequestV1
    if type(request) is not request_type: raise TypeError('exact once generation acquisition request required')
    selector = request.selector.task if phase else request.selector
    if phase:
        selected_material, _, _ = _selected_artifact_phase_candidate_v2(db, frame=frame,
            selector=request.selector, readers=installed_readers)
    read_prepared = read_artifact_draft_prepared_v2 if phase else read_artifact_draft_prepared_v1
    read_frozen = read_artifact_draft_frozen_v2 if phase else read_artifact_draft_frozen_v1
    read_workflow = installed_artifact_draft_workflow_v2 if phase else installed_artifact_draft_workflow_v1
    original_type = ArtifactDraftModelRequestOriginalV2 if phase else ArtifactDraftModelRequestOriginalV1
    stage_type = ArtifactDraftModelStageV2 if phase else ArtifactDraftModelStageV1
    read,cycle,continuation,root,family,mapping_atom,mapping = _current_task(db,frame=frame,selector=selector,
        readers=installed_readers,require_running_cycle=False)
    prepared = read_prepared(db,namespace=selector.namespace,issuer=installed_readers.issuer,selector=request.selector)
    if prepared is None:raise MissingProductionOriginalV1("actual_committed_c4_prepared")
    frozen = read_frozen(db,prepared=prepared,issuer=installed_readers.issuer)
    workflow = read_workflow(installed_readers.installed_bundle)
    require_artifact_draft_inputs_current_v1(db,prepared=prepared,frozen=frozen,frame=frame,readers=installed_readers)
    if phase:
        from .method_pair_shared_input_v1 import method_pair_read_inputs_v1, require_current_method_pair_shared_input_v1
        experiment_ref, _pair_plan = method_pair_read_inputs_v1(db, namespace=selector.namespace,
            goal_ref=selected_material.goal_head.key.token)
        if experiment_ref is not None:
            pair_inputs = require_current_method_pair_shared_input_v1(db, read=read,
                experiment_ref=experiment_ref, goal_ref=selected_material.goal_head.key.token, issuer=installed_readers.issuer)
            if pair_inputs is None:
                raise MissingProductionOriginalV1("actual_current_registered_method_pair_shared_input")
            pair, common_family = pair_inputs
            committed = tuple(source for source in frozen.sources if source.ref == pair.common_source_head.key.token)
            if (len(committed) != 1 or committed[0].revision != pair.common_source_head.revision
                    or committed[0].value_digest != pair.common_source_digest
                    or committed[0].record != common_family[pair.common_source_head.key.token]):
                raise ValueError("C4 acquire did not freeze the actual authorized common Source bytes")
    job = get_job(db,prepared.job_id)
    if (frame.envelope.identity.operation_id != prepared.acquire_operation_id or job.phase != "queued" or job.fence != 0
            or job.cancel_epoch or job.result_ref is not None):raise ValueError("C4 once job cannot reacquire or change its original")
    before_job=job
    job = plan_job_acquire(job,prepared.worker_subject,now_utc=_utc_text(datetime.fromtimestamp(frame.now_utc,timezone.utc)),
        lease_seconds=min(3600,int(workflow.timeout_seconds)+120,max(1,int(frozen.deadline_utc-frame.now_utc))))
    if _utc(job.lease_expires_utc,"lease_expires_utc") > _utc(prepared.deadline_utc,"deadline_utc"):
        raise ValueError("C4 acquired worker lease exceeds original absolute deadline")
    from ..model_broker.broker import ModelCallRequest
    from .reply_model_job import reply_request_wire_v1
    from .artifact_frame_control_reads_v3 import artifact_model_business_read_versions_v3
    business_versions=artifact_model_business_read_versions_v3(db,frame)
    guard = replace(frame.envelope.version_guard,read_versions=tuple(
        GraphVersion(v.key,v.revision+1) if v.key == job_graph_write(job).key else v for v in business_versions),
        query_epochs=tuple(QueryEpoch(v.namespace,v.scope_ref,v.revision+1) for v in frame.envelope.version_guard.query_epochs),
        resource_lease_versions=(VersionedRef(prepared.quote_id,1),))
    envelope = replace(frame.envelope,identity=replace(frame.envelope.identity,phase=WORK_KIND),
        authority=replace(frame.envelope.authority,actor=prepared.worker_subject,worker_fence=job.fence),version_guard=guard,
        deadline_utc=min(frame.envelope.deadline_utc,frozen.deadline_utc))
    model = ModelCallRequest(envelope,prepared.call_id,workflow.provider_id,workflow.model_id,
        frozenset(workflow.required_capabilities),workflow.privacy_tier,TEMPLATE_DIGEST_V2 if phase else TEMPLATE_DIGEST,
        frozen.wire,workflow.timeout_seconds,min(workflow.max_output_tokens, artifact_draft_phase_token_limits_v2(request.selector)["output_tokens"])
        if phase else workflow.max_output_tokens)
    if not phase: original_type(prepared.digest,model.digest,canonical_serialize(reply_request_wire_v1(envelope,model)))
    stage = stage_result_v1(frame,"d11","acquire_artifact_draft_model_v2" if phase else "acquire_artifact_draft_model",request,writes=(job_graph_write(job),),
        provenance={"prepared_digest":prepared.digest,"request_digest":model.digest,"job":job},
        proposal_schema=C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 if phase else C4_MODEL_PROPOSAL_SCHEMA,
        proposal_hash=C4_PHASE_MODEL_PROPOSAL_HASH_V2 if phase else C4_MODEL_PROPOSAL_HASH)
    return stage_type(frame,stage,prepared,frozen,job,model,None,None,None,before_job)


def acquire_current_artifact_draft_model_v1(db, *, frame, request, installed_readers):
    return _acquire_artifact_draft_model(db, frame=frame, request=request, installed_readers=installed_readers, phase=False)


def acquire_current_artifact_draft_model_v2(db, *, frame, request, installed_readers):
    base = _acquire_artifact_draft_model(db, frame=frame, request=request, installed_readers=installed_readers, phase=True)
    runtime = installed_readers.model_runtime
    active = None if runtime is None else runtime._active_artifact_phase_count_stage_v2
    if active is None: return base
    if type(active) is not tuple or len(active) != 3:
        raise TypeError('actual phase acquisition count material differs from closed stage/pair/time')
    expected, pair, current_now = active
    sealed = seal_counted_artifact_phase_stage_v2(db, frozen_stage=base, count_pair=pair,
        installed_readers=installed_readers, now_utc=current_now)
    if sealed != expected: raise ValueError('actual compiler changed original counted sealed phase stage')
    return sealed


def apply_artifact_draft_model_stage_v1(witness,graph,db,installed_readers):
    """Existing privately validated foreground once hook, before Graph writes."""
    from .domain_production_commit_v1 import _ACTIVE,_FOREGROUND_VALIDATED,_FOREGROUND_APPLIED,_require_foreground_witness_v1
    from .jobs import _save_job,_record_operation
    if (type(witness.stage) not in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2} or _ACTIVE.get(id(witness)) is not witness
            or _FOREGROUND_VALIDATED.get(id(witness)) is not witness or id(witness) in _FOREGROUND_APPLIED
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError("C4 once apply requires the real privately validated existing W01 witness")
    _require_foreground_witness_v1(witness,graph,db,witness.bundle)
    s=witness.stage;p=s.prepared;ids=_artifact_model_ids(p)
    phase = _artifact_model_phase_v2(p)
    if type(s) is not (ArtifactDraftModelStageV2 if phase else ArtifactDraftModelStageV1):
        raise TypeError('exact prepared/stage variant required')
    prepare_kind = 'prepare_artifact_draft_model_v2' if phase else 'prepare_artifact_draft_model'
    acquire_kind = 'acquire_artifact_draft_model_v2' if phase else 'acquire_artifact_draft_model'
    if witness.operation.operation_kind==prepare_kind:
        rebuilt=_prepare_artifact_draft_model(db,frame=s.frame,request=witness.request,installed_readers=installed_readers,phase=phase)
        if rebuilt!=s:raise ValueError("C4 current pure preparation changed before final once apply")
        installed_readers.resource_issuer.issue_quote(db,s.quote)
        reserve_budget(db,p.parent_budget_lease_ref,p.operation_id,p.reservation_digest,dict(s.quote.ceiling))
        create_job(db,s.job,"create:"+p.operation_id,p.reservation_digest)
        _record(db,issuer=installed_readers.issuer,namespace=p.namespace,kind=_artifact_model_original_kind(p,"frozen"),ref=p.frozen_ref,operation_id=p.operation_id,value=s.frozen)
        _record(db,issuer=installed_readers.issuer,namespace=p.namespace,kind=_artifact_model_original_kind(p,"prepared"),ref=p.job_id,operation_id=p.operation_id,value=p)
        if get_job(db,s.before_cycle.job_id)!=s.before_cycle:raise ValueError("C4 cycle changed before atomic wait/release")
        _save_job(db,s.after_cycle)
        _record_operation(db,s.after_cycle,p.operation_id,"checkpoint",canonical_digest(plain_v1(s.after_cycle)))
    elif witness.operation.operation_kind==acquire_kind:
        if phase:
            runtime = installed_readers.model_runtime
            active = None if runtime is None else runtime._active_artifact_phase_count_stage_v2
            if type(active) is not tuple or len(active) != 3:
                raise MissingProductionOriginalV1('actual_double_counted_frozen_stage_before_acquire')
            frozen_stage, count_pair, current_now = active
            if frozen_stage != s:
                raise ValueError('actual counted phase stage differs from privately validated W01 stage')
            validate_frozen_artifact_phase_count_stage_in_transaction_v2(db, frozen_stage=frozen_stage,
                count_pair=count_pair, installed_readers=installed_readers, now_utc=current_now)
        rebuilt=_acquire_artifact_draft_model(db,frame=s.frame,request=witness.request,installed_readers=installed_readers,phase=phase)
        if phase:
            rebuilt=seal_counted_artifact_phase_stage_v2(db, frozen_stage=rebuilt, count_pair=count_pair,
                installed_readers=installed_readers, now_utc=current_now)
        if rebuilt!=s:raise ValueError("C4 current pure acquisition changed before final once apply")
        if get_job(db,p.job_id)!=s.before_job:raise ValueError("C4 queued original changed before acquire once")
        _save_job(db,s.job)
        _record_operation(db,s.job,p.acquire_operation_id,"acquire",canonical_digest(plain_v1(s.job)))
        from .reply_model_job import reply_request_wire_v1
        metadata = {}
        if phase:
            raw = json.loads(s.stage.original_payload_json)['provenance']['actual_count_proof']
            metadata['actual_count_proof'] = artifact_draft_phase_count_proof_from_wire_v2(raw)
        original=(ArtifactDraftModelRequestOriginalV2 if phase else ArtifactDraftModelRequestOriginalV1)(p.digest,s.model_request.digest,
            canonical_serialize(reply_request_wire_v1(s.model_request.envelope,s.model_request)), **metadata)
        _record(db,issuer=installed_readers.issuer,namespace=p.namespace,kind=_artifact_model_original_kind(p,"request"),ref=ids["request"],operation_id=p.acquire_operation_id,value=original)
    else:raise ValueError("unregistered C4 model once-apply operation")
    _FOREGROUND_APPLIED[id(witness)]=witness
    return True


def require_artifact_draft_model_commit_v1(witness,graph,db,bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_require_foreground_witness_v1
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.bundle is not bundle or type(witness.stage) not in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2}
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or witness.stage.frame is not witness.frame or witness.stage.stage.proposals!=bundle.proposals):
        raise ValueError("C4 exact dual-role model commit requires the actual existing foreground witness")
    _require_foreground_witness_v1(witness,graph,db,bundle)
    return witness


def validate_artifact_draft_model_proposal_v1(proposal,snapshot,stage):
    from ..runtime_contracts import DomainProposal
    from ..graph_types import GraphSnapshot
    if (type(proposal) is not DomainProposal or type(snapshot) is not GraphSnapshot or type(stage) not in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2}
            or (proposal.domain,proposal.proposal_schema,proposal.proposal_schema_hash)!=("d11", C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 if type(stage) is ArtifactDraftModelStageV2 else C4_MODEL_PROPOSAL_SCHEMA,
                C4_PHASE_MODEL_PROPOSAL_HASH_V2 if type(stage) is ArtifactDraftModelStageV2 else C4_MODEL_PROPOSAL_HASH)
            or proposal.envelope!=stage.frame.envelope or proposal.envelope.authority.actor!=stage.prepared.actor_ref):
        raise ValueError("C4 proposal requires its exact self/once-worker closed schema")
    job_write=job_graph_write(stage.job)
    if stage.before_job is None:
        expected=(job_write,job_graph_write(stage.after_cycle))
        before=snapshot.get(job_graph_write(stage.before_cycle).key)
        absent=snapshot.get(job_write.key)
        if (stage.job.phase!="queued" or stage.job.fence or stage.job.lease_holder is not None
                or before is None or not before.valid or before.value!=job_graph_write(stage.before_cycle).value
                or absent is None or absent.revision!=0 or stage.after_cycle.phase!="waiting"
                or stage.after_cycle.lease_holder is not None or stage.after_cycle.lease_expires_utc is not None):
            raise ValueError("C4 prepare changed original cycle instead of exact queued/wait/release transition")
    else:
        expected=(job_write,)
        before=snapshot.get(job_write.key)
        if (before is None or not before.valid or before.value!=job_graph_write(stage.before_job).value
                or stage.before_job.phase!="queued" or stage.before_job.fence or stage.before_job.cancel_epoch
                or stage.job.phase!="running" or stage.job.fence!=1 or stage.job.cancel_epoch
                or stage.job.lease_holder!=stage.prepared.worker_subject):
            raise ValueError("C4 worker acquisition is not actual self-to-TLS queued/fence-zero transition")
        fixed=replace(stage.before_job,phase="running",fence=1,lease_holder=stage.prepared.worker_subject,
            lease_expires_utc=stage.job.lease_expires_utc)
        if fixed!=stage.job:raise ValueError("C4 worker changed fields outside its exact once acquire")
    if proposal.typed_writes!=expected:raise ValueError("C4 proposal contains an unrelated model/cycle write")
    return proposal


def require_artifact_draft_inputs_current_v1(db, *, prepared, frozen, frame, readers):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    read = CurrentDomainReadV1(frame);read.check(db)
    policy = readers.installed_bundle.installation_policy
    phase = _artifact_model_phase_v2(prepared)
    selector = prepared.selector.task if phase else prepared.selector
    from .joint_node_execution_v1 import require_joint_artifact_frame_gate_v1
    require_joint_artifact_frame_gate_v1(db, frame=frame, selector=prepared.selector, issuer=readers.issuer)
    workflow = (installed_artifact_draft_workflow_v2 if phase else installed_artifact_draft_workflow_v1)(readers.installed_bundle)
    if phase:
        _selected_artifact_phase_candidate_v2(db, frame=frame, selector=prepared.selector, readers=readers)
        from .artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_contract_v1
        contract = read_current_artifact_phase_postcondition_contract_v1(db, frame=frame,
            selector=prepared.selector, installed_readers=readers)
        if (type(frozen) is not ArtifactDraftInputV3 or
                (frozen.postcondition_contract_ref, frozen.postcondition_contract_digest) != (contract.original_ref, contract.digest)):
            raise ValueError('phase frozen material lost its actual preregistered postcondition contract')
    if ((prepared.installation_id,prepared.manifest_digest,prepared.activation_generation,prepared.actor_ref) !=
            (policy.installation_id,policy.manifest_digest,frame.activation_generation,frame.envelope.authority.actor)
            or prepared.owner_guard_digest != canonical_digest(plain_v1(frame.owner_guard))
            or prepared.workflow_digest != canonical_digest(plain_v1(workflow))
            or frame.now_utc >= _utc(prepared.deadline_utc,"deadline_utc").timestamp()):
        raise ValueError("C4 installation/self/upstream Owner/config/original deadline changed")
    _, _, _, root, _, _, _ = _current_task(db, frame=frame, selector=selector,
        readers=readers, require_running_cycle=False)
    from .artifact_continuation_originals_v1 import require_selected_artifact_target_sql_v1
    if phase:
        if frozen.prior_content is not None:
            from .d11_artifact_draft_content_v1 import require_current_artifact_prior_content_v2
            require_current_artifact_prior_content_v2(db, namespace=prepared.namespace, selector=prepared.selector,
                prior=frozen.prior_content, issuer=readers.issuer)
    else:
        require_selected_artifact_target_sql_v1(db, namespace=prepared.namespace, selector=selector,
            root=root, target=frozen.target, issuer=readers.issuer)
    read.source_family(db,(frozen.task_source_ref,),purpose="consolidation")
    for version in frozen.source_read_versions:
        atom = read.head(db,version.key)
        if atom.revision != version.revision:raise ValueError("C4 positive or negative input changed")
    for source in frozen.sources:
        atom = read.head(db,source.ref,required=True)
        if (atom.revision,canonical_digest(atom.value)) != (source.revision,source.value_digest):
            raise ValueError("C4 original Source bytes changed")
    quote = readers.resource_issuer.original_signed_quote(db,prepared.quote_id,1)
    if canonical_digest(quote) != prepared.quote_digest or quote.work_kind != WORK_KIND:
        raise ValueError("C4 actual signed model quote changed")
    require_budget_family_admissible(db,prepared.parent_budget_lease_ref)
    row = _artifact_receipt_sql_v1(db,"SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (prepared.parent_budget_lease_ref,prepared.operation_id)).fetchone()
    if row != (prepared.reservation_digest,canonical_serialize(dict(quote.ceiling)),"reserved"):
        raise ValueError("C4 original once reservation is not current")


def read_artifact_draft_model_request_v1(db, *, prepared, issuer):
    from .natural_reply_job_v2 import _request_from_wire
    row = _read(db,issuer=issuer,namespace=prepared.namespace,kind="c4_request",
        ref=artifact_draft_model_ids_v1(prepared.selector)["request"])
    if row is None:raise MissingProductionOriginalV1("actual_committed_c4_acquired_request")
    original = artifact_draft_model_from_wire_v1(row[0],ArtifactDraftModelRequestOriginalV1)
    if original.prepared_digest != prepared.digest or row[1] != prepared.acquire_operation_id:
        raise ValueError("C4 acquired request crossed prepared/predecessor commit")
    from ..authority_service.artifact_model_source_read_v3 import read_bound_artifact_model_request_v3
    handled,request=read_bound_artifact_model_request_v3(db,prepared,original)
    if handled:return request
    return _request_from_wire(original.request_json)


def read_current_artifact_draft_attempt_v1(db,*,namespace,continuation,attempt,issuer):
    """Foreground slot reads real prepared/cost/result originals, never a flag."""
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_life_preparation_v1 import TABLE
    rows=_artifact_receipt_sql_v1(db,"SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='c4_prepared' "
        "AND json_extract(payload_json,'$.call_id')=? LIMIT 2",(*namespace.as_tuple,attempt.call_id)).fetchall()
    if len(rows)!=1:raise MissingProductionOriginalV1("unique_actual_foreground_c4_prepared")
    original=_read(db,issuer=issuer,namespace=namespace,kind="c4_prepared",ref=rows[0][0])
    p=artifact_draft_model_from_wire_v1(original[0],ArtifactDraftModelPreparedV1)
    if (p.selector.c02_operation_id!=continuation.c02_operation_id or p.parent_budget_lease_ref!=continuation.call_plan.parent_budget_lease_ref
            or attempt.original_call_id is not None or (attempt.reservation_operation_id,attempt.reservation_digest)!=(p.operation_id,p.reservation_digest)
            or attempt.budget_lease_ref!=p.parent_budget_lease_ref):
        raise ValueError("foreground C4 slot changed its original C02/root/reservation")
    quote=issuer.resource_issuer.original_signed_quote(db,p.quote_id,1)
    if quote.work_kind!=WORK_KIND or canonical_digest(quote)!=p.quote_digest:raise ValueError("C4 original finite quote changed")
    reserved=_artifact_receipt_sql_v1(db,"SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (p.parent_budget_lease_ref,p.operation_id)).fetchone()
    if reserved is None or reserved[0]!=p.reservation_digest:raise ValueError("C4 original reservation absent")
    ids=artifact_draft_model_ids_v1(p.selector)
    paid=_read(db,issuer=issuer,namespace=namespace,kind="c4_paid",ref=ids["paid"])
    result=_read(db,issuer=issuer,namespace=namespace,kind="c4_result",ref=ids["result"])
    state,terminal_ref="reserved",None
    if result is not None:
        from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadV1,artifact_draft_model_result_from_wire_v1
        actual=artifact_draft_model_result_from_wire_v1(result[0],ArtifactDraftModelResultReadV1)
        if (paid is None or paid[0]["terminal_receipt_digest"]!=canonical_digest(asdict(actual.terminal_receipt))
                or actual.request.binding_digest!=p.digest):raise ValueError("C4 actual terminal/result lost its paid original")
        state,terminal_ref="completed",ids["result"]
    elif paid is not None or reserved[1] in {"unknown","partial_unknown","unconfirmed"}:
        state="unknown"
    return ForegroundModelAttemptV1("C4",p.call_id,None,p.operation_id,p.reservation_digest,p.parent_budget_lease_ref,
        quote.ceiling["input_tokens"],quote.ceiling["output_tokens"],state,terminal_ref)


def artifact_draft_model_draft_v1(db, *, prepared, issuer, metadata, epoch):
    from .joint_node_execution_v1 import require_joint_prepared_artifact_gate_v1
    require_joint_prepared_artifact_gate_v1(db, prepared=prepared, issuer=issuer)
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
    request = _artifact_model_request(db,prepared=prepared,issuer=issuer)
    job = get_job(db,prepared.job_id)
    quote = issuer.resource_issuer.original_signed_quote(db,prepared.quote_id,1)
    if (job.phase != "running" or job.fence != 1 or job.cancel_epoch or job.lease_holder != request.envelope.authority.actor
            or request.envelope.authority.worker_fence != job.fence):raise ValueError("C4 actual acquired model worker changed")
    versions = request.envelope.version_guard.read_versions
    sources = tuple(sorted((v.key.owner.subject,v.revision) for v in versions if v.key.type_name == "memory.source" and v.revision>0))
    accesses = tuple(sorted((v.key.owner.subject,v.revision) for v in versions if v.key.type_name == "memory.access" and v.revision>0))
    target = metadata.requirements
    return ModelEgressDraftV1(target.authority_id,target.authority_namespace,job.lease_holder,prepared.acquire_operation_id,
        prepared.call_id,request.digest,job.job_id,job.fence,tuple(ref for ref,_ in sources),sources,accesses,
        request.envelope.version_guard.access_epoch,request.envelope.version_guard.delete_epoch,epoch.revision,metadata.graph_revision,
        target.activation_generation,target.revocation_epoch,target.deletion_seq,target.execution_seq,prepared.parent_budget_lease_ref,
        prepared.operation_id,prepared.reservation_digest,tuple(sorted(quote.ceiling.items())),request.provider_id,request.model_id,
        prepared.provider_config_digest,request.max_output_tokens,
        acquire_operation_id=prepared.acquire_operation_id,binding_digest=prepared.digest)


def seal_artifact_draft_model_call_v1(db,*,prepared,intent,permit,issuer,graph,runtime,data_certificate,now):
    from .artifact_host_seal_data_v3 import compare_artifact_host_seal_data_in_transaction_v3
    from ..authority_service.v2_model_egress_wire import to_wire
    certificate=compare_artifact_host_seal_data_in_transaction_v3(data_certificate,graph,runtime,prepared,
        intent=intent,permit=permit,now=now)
    if db is not certificate.store._db or issuer is not runtime.issuer:
        raise ValueError('C4 actual model seal changed its installed storage/issuer')
    return _record(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,'call'),
        ref=prepared.call_id,operation_id=prepared.acquire_operation_id,value=to_wire(intent))

def settle_artifact_draft_original_cost_v1(db,*,prepared,fact,issuer):
    """Use existing financial originals; no current Source or result body read."""
    from .model_cost_settlement import (OriginalModelCostFactV1,prepare_original_model_cost_plan,
        apply_original_model_budget_in_transaction)
    from ..authority_service.v2_model_egress_wire import to_wire
    if type(fact) is not OriginalModelCostFactV1:raise TypeError("actual paired C4 terminal cost fact required")
    sealed=_read(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,"call"),ref=prepared.call_id)
    if sealed is None or sealed[0]!=to_wire(fact.intent):raise ValueError("C4 cost crossed original sealed call")
    ids=_artifact_model_ids(prepared)
    prior=_read(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,"paid"),ref=ids["paid"])
    if prior is not None:return prior[0],None
    plan=prepare_original_model_cost_plan(db,issuer.resource_issuer,prepared.namespace,fact,
        quote_id=prepared.quote_id,quote_version=1,work_kind=WORK_KIND)
    applied=apply_original_model_budget_in_transaction(db,issuer.resource_issuer,plan,fact)
    return plan,applied


def require_artifact_draft_paid_terminal_identity_v1(*,prepared,fact,commit,result):
    """Pure equality for the actual paired paid/result tuple; grants no permission."""
    from .model_cost_settlement import OriginalModelCostCommitV1,OriginalModelCostFactV1,original_model_cost_operation_id_v1
    from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadV1,ArtifactDraftModelResultReadV2
    expected_type=ArtifactDraftModelResultReadV2 if _artifact_model_phase_v2(prepared)else ArtifactDraftModelResultReadV1
    if(type(commit)is not OriginalModelCostCommitV1 or type(fact)is not OriginalModelCostFactV1
            or commit.status!='committed'or type(result)is not expected_type or fact.recovery.state!='observed' or fact.intent.worker_fence!=1
            or commit.operation_id!=original_model_cost_operation_id_v1(prepared.namespace,prepared.call_id)
            or(commit.call_id,commit.quote_id,commit.quote_version,commit.terminal_receipt_digest)!=(
                prepared.call_id,prepared.quote_id,1,canonical_digest(asdict(fact.receipt)))
            or result.terminal_receipt!=fact.receipt or result.observation.status!='completed'
            or result.observation.digest!=fact.receipt.observation_digest
            or(result.request.authority_id,result.request.authority_namespace)!=(fact.intent.authority_id,fact.intent.namespace)
            or(fact.intent.acquire_operation_id,fact.intent.subject,fact.intent.authority_activation_generation,
                fact.intent.budget_reservation_digest,fact.intent.provider_config_digest)!=(prepared.acquire_operation_id,
                    prepared.worker_subject,prepared.activation_generation,prepared.reservation_digest,prepared.provider_config_digest)
            or(result.request.selector,result.request.namespace,result.request.installation_id,result.request.job_id,
                result.request.acquire_operation_id,result.request.original_operation_id,result.request.call_id,
                result.request.binding_digest,result.request.model_request_digest,result.request.consumer_operation_id)!=(
                prepared.selector,prepared.namespace,prepared.installation_id,prepared.job_id,prepared.acquire_operation_id,
                prepared.operation_id,prepared.call_id,prepared.digest,fact.intent.request_digest,_artifact_model_ids(prepared)['adopt'])
            or(fact.intent.job_id,fact.intent.call_id,fact.intent.binding_digest,fact.intent.budget_lease_id,
                fact.intent.budget_reservation_operation_id)!=(prepared.job_id,prepared.call_id,prepared.digest,
                    prepared.parent_budget_lease_ref,prepared.operation_id)):
        raise ValueError('C4 actual paired completed result/paid terminal identities differ')


def record_artifact_draft_paid_after_cost_cas_v1(db,*,prepared,fact,commit,issuer,result=None):
    if result is not None:
        require_artifact_draft_paid_terminal_identity_v1(prepared=prepared,fact=fact,commit=commit,result=result)
        from .artifact_host_result_archive_source_v3 import append_bound_artifact_paid_result_v3
        return append_bound_artifact_paid_result_v3(db,prepared=prepared,fact=fact,commit=commit,result=result,issuer=issuer)
    from .model_cost_settlement import OriginalModelCostCommitV1,original_model_cost_operation_id_v1
    if (type(commit) is not OriginalModelCostCommitV1 or commit.status!="committed"
            or commit.operation_id!=original_model_cost_operation_id_v1(prepared.namespace,prepared.call_id)
            or (commit.call_id,commit.quote_id,commit.quote_version,commit.terminal_receipt_digest)!=
               (prepared.call_id,prepared.quote_id,1,canonical_digest(asdict(fact.receipt)))):
        raise ValueError("C4 paid original requires actual once model cost CAS")
    from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
    if require_c4_model_cost_original_commit_v1(db,namespace=prepared.namespace,operation_id=commit.operation_id)!=commit:
        raise ValueError("C4 paid original differs from actual existing model-cost commit")
    budget=db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
        (prepared.parent_budget_lease_ref,prepared.operation_id)).fetchone()
    if budget is None or canonical_digest(json.loads(budget[0]))!=commit.budget_receipt_digest:
        raise ValueError("C4 paid original lost actual settled budget receipt")
    cost=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? ORDER BY revision DESC LIMIT 1",(commit.cost_ref,)).fetchone()
    if cost is None or cost[0]!=commit.operation_id or cost[2]!=1:raise ValueError("C4 actual cost CAS member absent")
    ids=_artifact_model_ids(prepared)
    original=_record(db,issuer=issuer,namespace=prepared.namespace,kind=_artifact_model_original_kind(prepared,"paid"),ref=ids["paid"],operation_id=commit.operation_id,value=commit)
    return original


class InstalledArtifactDraftModelRuntimeV1:
    """Existing worker/paired model adapter, no scheduler or new authority ledger."""
    def __init__(self,*,graph,bootstrap,bundle,worker,authority_client,client_grant,context,owner_loop):
        from ..graph_coordinator import GraphCoordinator
        from ..host.authority_client import AuthorityClient
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime_contracts import InstallationGrantV2
        if (type(graph) is not GraphCoordinator or type(bundle) is not AdminInstallationBundle
                or type(authority_client) is not AuthorityClient or type(client_grant) is not InstallationGrantV2):
            raise TypeError("C4 needs the actual installed Graph/worker/paired model client")
        graph._admin(bootstrap)
        self.graph,self.bootstrap,self.bundle,self.worker=graph,bootstrap,bundle,worker
        self.authority_client,self.client_grant=authority_client,client_grant
        self.context,self.owner_loop=context,owner_loop
        self.issuer=graph._GraphCoordinator__d11_issuer
        self._adapters={};self._cost_facts={};self._results={};self._paid={}
        self._no_dispatch_witnesses_v1 = {}
        self._active_artifact_phase_count_stage_v2 = None

    def _read_dispatch_v1(self,graph,job_id):
        from .artifact_host_dispatch_source_v3 import (ArtifactHostDispatchReadSelectorV1,
            prepare_current_artifact_host_dispatch_read_v1)
        policy=self.bundle.installation_policy
        selector=ArtifactHostDispatchReadSelectorV1(policy.namespace,policy.installation_id,job_id)
        return prepare_current_artifact_host_dispatch_read_v1(graph,self,selector)

    def _read_dispatch_original_v1(self,graph,job_id):
        from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
        graph._admin(self.bootstrap)
        db=graph._GraphCoordinator__store._db
        with graph._GraphCoordinator__store._lock:
            if db.in_transaction:raise ValueError("C4 execution read requires independent SQL snapshot")
            _artifact_receipt_sql_v1(db,"BEGIN")
            try:
                job=get_job(db,job_id)
                schema = job.continuation['schema']
                if schema not in {'d11.artifact-draft-model-job.v1', 'd11.artifact-draft-phase-model-job.v2'}:
                    raise ValueError('worker job is not an exact registered artifact model variant')
                phase = schema == 'd11.artifact-draft-phase-model-job.v2'
                selector = (artifact_draft_from_wire_v2(job.continuation['selector'], ArtifactDraftPhaseSelectorV2)
                    if phase else artifact_draft_from_wire_v1(job.continuation['selector'], ArtifactDraftTaskSelectorV1))
                namespace = selector.task.namespace if phase else selector.namespace
                read_prepared = read_artifact_draft_prepared_v2 if phase else read_artifact_draft_prepared_v1
                prepared=read_prepared(db,namespace=namespace,issuer=self.issuer,selector=selector)
                if prepared is None:raise MissingProductionOriginalV1("actual_c4_model_prepared")
                request=_artifact_model_request(db,prepared=prepared,issuer=self.issuer)
                metadata,epoch=graph._v2_graph_stamp(namespace)
                draft=artifact_draft_model_draft_v1(db,prepared=prepared,issuer=self.issuer,metadata=metadata,epoch=epoch)
                call=_read(db,issuer=self.issuer,namespace=namespace,kind=_artifact_model_original_kind(prepared,"call"),ref=prepared.call_id)
                from ..authority_service.v2_model_egress_wire import from_wire
                from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
                intent=None if call is None else from_wire(call[0],ModelEgressIntentV1)
                from .restore_anchor import RestoreAnchor
                a=metadata.requirements
                anchor=RestoreAnchor(a.authority_id,a.authority_namespace,a.activation_generation,a.deletion_journal_id,
                    a.deletion_seq,a.deletion_digest,a.execution_journal_id,a.execution_seq,a.execution_digest,a.revocation_epoch,a.anchor_nonce)
                return prepared,request,draft,anchor,intent
            finally:db.rollback()

    def read_cached_adoption_originals_v1(self,prepared):
        result,paid=self._results.get(prepared.job_id),self._paid.get(prepared.job_id)
        if result is None or paid is None:raise MissingProductionOriginalV1("paired_current_c4_result_and_actual_once_cost_commit")
        return result,paid

    def _read_original_cost_task_v1(self, graph, *, c02_operation_id):
        """Read only original job/call commitments; withdrawn Sources confer no body eligibility."""
        from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
        graph._admin(self.bootstrap)
        from .foreground_cycle_v1 import foreground_cycle_ids_v1
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        ns = self.bundle.installation_policy.namespace
        store = graph._GraphCoordinator__store
        with store._lock:
            db = store._db
            _artifact_receipt_sql_v1(db,"BEGIN")
            try:
                cycle = get_job(db, foreground_cycle_ids_v1(ns, c02_operation_id)[1])
                responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=ns,
                    job=cycle, issuer=self.issuer)
                if responsibility is None or responsibility.root_registration_ref is None:
                    return None
                selector = artifact_draft_task_selector_v1(ns, c02_operation_id=c02_operation_id,
                    root_registration_ref=responsibility.root_registration_ref)
                prepared = read_artifact_draft_prepared_v1(db, namespace=ns, issuer=self.issuer, selector=selector)
                if prepared is None:
                    return None
                call = _read(db, issuer=self.issuer, namespace=ns, kind="c4_call", ref=prepared.call_id)
                if call is None:
                    return None
                intent = from_wire(call[0], ModelEgressIntentV1)
                if (intent.call_id, intent.job_id, intent.binding_digest) != (prepared.call_id, prepared.job_id, prepared.digest):
                    raise ValueError("historical C4 expense differs from its original sealed call")
                return prepared, intent
            finally:
                db.rollback()

    def _read_original_phase_cost_tasks_v2(self, graph, *, c02_operation_id):
        """Original once costs remain collectible after Source/Owner withdrawal."""
        from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
        from .d11_life_preparation_v1 import TABLE
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        graph._admin(self.bootstrap)
        namespace = self.bundle.installation_policy.namespace
        store = graph._GraphCoordinator__store
        with store._lock:
            db = store._db
            _artifact_receipt_sql_v1(db,'BEGIN')
            try:
                rows = _artifact_receipt_sql_v1(db,'SELECT original_ref FROM ' + TABLE +
                    " WHERE bot=? AND persona=? AND kind='c4_phase_prepared' "
                    "AND json_extract(payload_json,'$.selector.task.c02_operation_id')=? ORDER BY original_ref LIMIT 3",
                    (*namespace.as_tuple, c02_operation_id)).fetchall()
                if len(rows) > 2: raise ValueError('original method exceeded its two physical generation phases')
                tasks = []
                for ref, in rows:
                    row = _read(db, issuer=self.issuer, namespace=namespace, kind='c4_phase_prepared', ref=ref)
                    prepared = artifact_draft_model_from_wire_v2(row[0], ArtifactDraftModelPreparedV2)
                    if (prepared.selector.task.c02_operation_id != c02_operation_id
                            or (prepared.installation_id, prepared.manifest_digest) !=
                            (self.client_grant.installation_id, self.client_grant.manifest_digest)):
                        raise ValueError('original phase expense crossed task/installation')
                    call = _read(db, issuer=self.issuer, namespace=namespace, kind='c4_phase_call', ref=prepared.call_id)
                    if call is None: continue
                    intent = from_wire(call[0], ModelEgressIntentV1)
                    if (intent.call_id, intent.job_id, intent.binding_digest) != (prepared.call_id, prepared.job_id, prepared.digest):
                        raise ValueError('original phase expense changed its sealed actual call')
                    tasks.append((prepared, intent))
                return tuple(tasks)
            finally:
                db.rollback()

    def read_cached_cost_fact_v1(self,job_id):
        fact=self._cost_facts.get(job_id)
        if fact is None:raise MissingProductionOriginalV1("paired_content_free_c4_terminal_cost_fact")
        return fact


    def read_cached_no_dispatch_witness_v1(self, job_id):
        from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
        value = self._no_dispatch_witnesses_v1.get(job_id)
        if value is None or type(value[0]) is not ModelNoDispatchWitnessV1:
            raise MissingProductionOriginalV1("actual_paired_core_no_dispatch_witness_before_zero_settlement")
        witness, basis = value
        if witness.request.intent.job_id != job_id or basis.namespace != self.bundle.installation_policy.namespace:
            raise ValueError("actual cached Core no-dispatch tuple changed its original scope")
        witness.require_signature_v1(self.issuer._signer)
        return value

    def _read_original_no_dispatch_basis_v1(self, graph, prepared):
        from .artifact_no_dispatch_metadata_read_v1 import (
            prepare_current_original_artifact_financial_snapshot_v1,
            derive_artifact_no_dispatch_basis_from_financial_originals_v1)
        from .first_ingress_v2 import trusted_upper
        graph._admin(self.bootstrap)
        originals=prepare_current_original_artifact_financial_snapshot_v1(graph,runtime=self,job_id=prepared.job_id)
        if originals is None or originals.prepared!=prepared:
            raise MissingProductionOriginalV1("actual_original_core_artifact_financial_tuple")
        now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(self.bundle.ingress_clock))
        basis=derive_artifact_no_dispatch_basis_from_financial_originals_v1(originals,now=now)
        if originals.settlement is not None:
            from ..authority_service.v2_model_egress_wire import from_wire
            from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
            witness=from_wire(json.loads(originals.settlement.witness_json),ModelNoDispatchWitnessV1)
            self._no_dispatch_witnesses_v1[prepared.job_id]=(witness,basis)
        return basis


    def _read_next_original_no_dispatch_task_v1(self, graph, *, after):
        """Cold cursor is issued by Core over actual original model identities."""
        from .artifact_no_dispatch_metadata_read_v1 import prepare_current_original_artifact_financial_snapshot_v1
        graph._admin(self.bootstrap)
        originals=prepare_current_original_artifact_financial_snapshot_v1(graph,runtime=self,after_call_id=after)
        if originals is None:return None
        return originals.intent.call_id,(originals.prepared,originals.intent)



async def recover_original_artifact_draft_model_cost_v1(runtime, *, c02_operation_id):
    """Converge the original financial fact without model/result/Source body delivery."""
    from .model_cost_settlement import read_original_model_cost
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:
        raise TypeError("actual installed C4 runtime required")
    task = await runtime.worker.call(lambda graph: runtime._read_original_cost_task_v1(graph,
        c02_operation_id=c02_operation_id))
    if task is None:
        return {"status": "original_call_absent"}
    prepared, intent = task
    no_dispatch = await reconcile_original_artifact_no_dispatch_v1(runtime, prepared=prepared, intent=intent)
    if no_dispatch is not None:
        return {"status": "original_no_dispatch_cost_recorded", "call_id": intent.call_id}
    facts = await runtime.authority_client.model_terminal_fact_v2(runtime.bundle, runtime.client_grant, intent=intent)
    fact = read_original_model_cost(lambda _intent: facts, intent)
    runtime._cost_facts[prepared.job_id] = fact
    if fact.recovery.state != "observed":
        return {"status": "original_terminal_unknown", "call_id": intent.call_id}
    paid = await runtime.worker.call(lambda graph: graph.reconcile_current_artifact_draft_model_cost_v1(
        runtime.bootstrap, runtime.bundle, prepared=prepared))
    runtime._paid[prepared.job_id] = paid
    return {"status": "original_cost_recorded", "call_id": intent.call_id}


async def execute_prepared_artifact_draft_model_v1(runtime,*,job_id):
    import asyncio
    from ..host.astrbot_model_call import AstrBotModelProvider, LocalModelCapacityDeniedV1
    from ..host.model_egress_executor import HostModelEgressExecutor
    from ..model_broker.broker import ModelProviderDescriptor
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:raise TypeError("actual installed C4 runtime required")
    if runtime.owner_loop is not asyncio.get_running_loop():raise RuntimeError("C4 worker must run on its actual AstrBot loop")
    dispatch_lease=None
    try:
        from ..graph_worker import OwnedGraphStorageResultV3
        from ..authority_service.contract import AuthorityUnavailable
        dispatch=await runtime.worker.call(lambda graph:runtime._read_dispatch_v1(graph,job_id))
        if type(dispatch)is not OwnedGraphStorageResultV3:
            raise AuthorityUnavailable('C4 dispatch requires the actual finalized Source READ result ownership')
        (p,request,draft,anchor,sealed,dispatch_certificate),dispatch_lease=dispatch.take_value_v3()
        phase = _artifact_model_phase_v2(p)
        workflow = (installed_artifact_draft_workflow_v2 if phase else installed_artifact_draft_workflow_v1)(runtime.bundle)
        if len(p.audiences)!=1:raise MissingProductionOriginalV1("unique_actual_c4_host_conversation_audience")
        audience=json.loads(p.audiences[0])
        if type(audience) is not list or len(audience)!=2 or any(type(item) is not str or not item for item in audience):
            raise ValueError("C4 original AstrBot session audience is not the installed exact pair")
        runtime.graph.local_module_admission.require_v1(("d06","d10","d11"),"model:artifact_draft")
        descriptor=ModelProviderDescriptor(workflow.provider_id,"astrbot-openai-official-v1",workflow.model_id,
            frozenset({"text"}),frozenset({workflow.purpose}),frozenset({workflow.privacy_tier}),workflow.provider_config_ref,"unknown",False,False)
        adapter=runtime._adapters.get(job_id)
        if adapter is None:
            adapter=AstrBotModelProvider(context=runtime.context,host_loop=runtime.owner_loop,trusted_umo=audience[0],
                descriptor=descriptor,admin_model=workflow,installation_bundle=runtime.bundle)
            runtime._adapters[job_id]=adapter
        executor=HostModelEgressExecutor(authority=runtime.authority_client,bundle=runtime.bundle,grant=runtime.client_grant,
            adapter=adapter,local_module_admission=runtime.graph.local_module_admission)
        if sealed is None:
            try:
                record,permit=await executor.prepare_once(draft=draft,expected_anchor=anchor,request=request)
            except LocalModelCapacityDeniedV1:
                return {"status":"model_capacity_hold","job_id":job_id,"call_id":p.call_id}
        else:
            record,permit=await runtime.authority_client.model_recover_fenced_v1(runtime.bundle,runtime.client_grant,intent=sealed)
            draft,anchor=ModelEgressDraftV1.from_intent(sealed),permit.pinned_anchor
        if ModelEgressDraftV1.from_intent(record.intent)!=draft or permit.pinned_anchor!=anchor:
            raise ValueError("C4 paired model original differs from fixed frozen call")
        if record.state=="prepared":
            # Goal's shared W01 consumer calls the concrete seal helper above.
            await runtime.worker.call(lambda graph:graph.seal_current_artifact_draft_model_call_v1(
                runtime.bootstrap,runtime.bundle,prepared=p,intent=record.intent,permit=permit,data_certificate=dispatch_certificate))
            terminal=await executor.execute_once(intent=record.intent,expected_anchor=anchor,request=request,artifact_draft_original=p)
            if terminal is None:return {"status":"original_terminal_unknown","job_id":job_id,"call_id":p.call_id}
        elif record.state!="observed":
            return {"status":"original_terminal_unknown","job_id":job_id,"call_id":p.call_id}
        facts=await runtime.authority_client.model_terminal_fact_v2(runtime.bundle,runtime.client_grant,intent=record.intent)
        from .model_cost_settlement import read_original_model_cost
        fact=read_original_model_cost(lambda _intent:facts,record.intent)
        runtime._cost_facts[job_id]=fact
        # Existing accounting W01 bridge commits the real financial originals.
        paid=await runtime.worker.call(lambda graph:graph.reconcile_current_artifact_draft_model_cost_v1(
            runtime.bootstrap,runtime.bundle,prepared=p))
        runtime._paid[job_id]=paid
        if fact.recovery.state!="observed":return {"status":"original_terminal_unknown","job_id":job_id,"call_id":p.call_id}
        from ..authority_service.d11_artifact_draft_model_v1 import (ArtifactDraftModelResultReadRequestV1,
            ArtifactDraftModelResultReadRequestV2, ArtifactDraftModelResultReadV1, ArtifactDraftModelResultReadV2)
        request_type = ArtifactDraftModelResultReadRequestV2 if phase else ArtifactDraftModelResultReadRequestV1
        rr=request_type(record.intent.authority_id,record.intent.namespace,p.namespace,p.installation_id,
            p.selector,p.job_id,p.acquire_operation_id,p.operation_id,p.call_id,p.digest,record.intent.request_digest,
            _artifact_model_ids(p)["adopt"],
            "artifact-draft-phase-read:"+p.selector.identity_digest[:40] if phase else "artifact-draft-read:"+p.selector.digest[:40])
        # A dedicated closed paired result method is a shared client/mtls seam.
        reader = (runtime.authority_client.artifact_draft_model_result_read_v2 if phase
            else runtime.authority_client.artifact_draft_model_result_read_v1)
        result=await reader(runtime.bundle,runtime.client_grant,read_request=rr)
        if type(result) is not (ArtifactDraftModelResultReadV2 if phase else ArtifactDraftModelResultReadV1) or result.request!=rr or result.terminal_receipt!=fact.receipt:
            raise ValueError("C4 actual paired result/paid terminal differs")
        runtime._results[job_id]=result
        archived=await runtime.worker.call(lambda graph:graph.record_current_artifact_draft_model_result_v1(
            runtime.bootstrap,runtime.bundle,prepared=p))
        if type(archived)is not OwnedGraphStorageResultV3:
            raise AuthorityUnavailable('C4 result archive requires the actual finalized Source Work receipt ownership')
        archive_lease=None
        try:
            archive_receipt,archive_lease=archived.take_value_v3()
            fields={'status','job_id','paid_original_ref','historical_delivery_read_attempt_id',
                'current_archive_read_operation_id','current_archive_read_permit_digest'}
            if(type(archive_receipt)is not dict or set(archive_receipt)!=fields
                    or(archive_receipt['status'],archive_receipt['job_id'],archive_receipt['paid_original_ref'],
                        archive_receipt['historical_delivery_read_attempt_id'])!=('recorded',p.job_id,_artifact_model_ids(p)['paid'],rr.read_attempt_id)
                    or type(archive_receipt['current_archive_read_operation_id'])is not str
                    or not archive_receipt['current_archive_read_operation_id'].startswith('artifact-result-archive-read:')
                    or not archive_receipt['current_archive_read_operation_id'].endswith(':business')
                    or type(archive_receipt['current_archive_read_permit_digest'])is not str
                    or len(archive_receipt['current_archive_read_permit_digest'])!=64):
                raise AuthorityUnavailable('C4 finalized archive receipt changed its actual result/delivery/READ identity')
        finally:
            if archive_lease is None:archived.release_v3()
            else:archive_lease.release()
        return {"status":"actual_terminal_and_cost_recorded","job_id":job_id,"call_id":p.call_id}
    finally:
        try:
            runtime._results.pop(job_id,None)
            runtime._adapters.pop(job_id,None)
        finally:
            if dispatch_lease is not None:dispatch_lease.release()


# Exact method phases share the existing W01, Life original and cost-CAS paths.
from ..model_broker.artifact_draft_v1 import (ArtifactDraftPhaseSelectorV2, ArtifactDraftInputV2, ArtifactDraftInputV3, artifact_draft_input_from_wire_v2,
    ArtifactDraftTextExtentV2, ArtifactDraftPriorContentCommitmentV2, artifact_draft_from_wire_v2,
    artifact_draft_model_ids_v2, artifact_draft_phase_original_ref_v2,
    artifact_draft_phase_sequence_v2, artifact_draft_phase_token_limits_v2, TEMPLATE_DIGEST_V2)
from .foreground_call_plan_v1 import (ForegroundArtifactPhaseGroupV2, ForegroundModelAttemptV2, ForegroundCallPlanV2)

C4_PHASE_ORIGINAL_KINDS_V2 = frozenset('c4_phase_' + part for part in
    ('frozen','prepared','request','call','result','paid','adopted','verified'))
C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 = 'd11.artifact-draft-phase-model.proposal.v2'
C4_PHASE_MODEL_PROPOSAL_HASH_V2 = schema_hash({'schema': C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2,
    'job_schema_hash': TYPE_SCHEMA_HASHES['runtime.job'],
    'transitions': ('actual_adopted_method_phase_prepare', 'self_acquires_actual_tls_worker_once',
        'actual_paid_authored_phase_source')})

@dataclass(frozen=True, slots=True)
class PrepareArtifactDraftModelRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2:raise TypeError("exact C4 task selector required")


@dataclass(frozen=True, slots=True)
class AcquireArtifactDraftModelRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2:raise TypeError("exact C4 task selector required")


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelPreparedV2:
    selector: ArtifactDraftPhaseSelectorV2
    installation_id: str
    manifest_digest: str
    activation_generation: int
    activity_id: str
    actor_ref: str
    worker_subject: str
    frozen_ref: str
    frozen_digest: str
    workflow_digest: str
    provider_config_digest: str
    job_id: str
    operation_id: str
    acquire_operation_id: str
    call_id: str
    quote_id: str
    quote_digest: str
    reservation_digest: str
    parent_budget_lease_ref: str
    audiences: tuple[str, ...]
    deadline_utc: str
    cancel_generation: int
    owner_guard_digest: str
    owner_guard:ProductionOwnerGuardV1
    schema: str = "d11.artifact-draft-phase-model-prepared.v2"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest, _text
        if (self.schema != "d11.artifact-draft-phase-model-prepared.v2"
                or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.cancel_generation) is not int or self.cancel_generation != 0
                or type(self.audiences) is not tuple or not self.audiences or len(set(self.audiences)) != len(self.audiences)):
            raise ValueError("exact C4 prepared version/generation/scope required")
        for name in ("manifest_digest","frozen_digest","workflow_digest","provider_config_digest","quote_digest","reservation_digest","owner_guard_digest"):
            _digest(getattr(self,name))
        for name in ("installation_id","activity_id","actor_ref","worker_subject","parent_budget_lease_ref"):_text(getattr(self,name),name)
        if not self.worker_subject.startswith("mtls:sha256:"):raise ValueError("C4 worker must be the actual installed TLS subject")
        ids = artifact_draft_model_ids_v2(self.selector)
        if (self.frozen_ref,self.job_id,self.operation_id,self.acquire_operation_id,self.call_id,self.quote_id) != (
                ids["frozen"],ids["job"],ids["prepare"],ids["acquire"],ids["call"],ids["quote"]):
            raise ValueError("C4 prepared changed the original once identities")
        _utc(self.deadline_utc,"deadline_utc")
        if type(self.owner_guard) is not ProductionOwnerGuardV1 or canonical_digest(plain_v1(self.owner_guard))!=self.owner_guard_digest:
            raise ValueError("C4 prepared changed its actual foreground upstream Owner guard")
        if len(canonical_serialize(plain_v1(self)).encode()) > 65536:raise ValueError("C4 prepared metadata exceeds64KiB")

    @property
    def namespace(self):return self.selector.task.namespace

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelRequestOriginalV2:
    prepared_digest: str
    request_digest: str
    request_json: str
    actual_count_proof: "ArtifactDraftPhaseCountProofV2" = field(kw_only=True)
    schema: str = "d11.artifact-draft-phase-model-request.v2"

    def __post_init__(self):
        from .natural_reply_job_v2 import _request_from_wire
        from ..model_broker.artifact_draft_v1 import artifact_draft_provider_messages_v2, _digest
        _digest(self.prepared_digest);_digest(self.request_digest)
        if self.schema != "d11.artifact-draft-phase-model-request.v2" or len(self.request_json.encode()) > 65536:
            raise ValueError("C4 acquired request metadata/wire exceeds its exact bound")
        request = _request_from_wire(self.request_json)
        artifact_draft_provider_messages_v2(request)
        if request.digest != self.request_digest:raise ValueError("C4 acquired request digest differs")
        if type(self.actual_count_proof) is not ArtifactDraftPhaseCountProofV2:
            raise TypeError('phase request original requires actual durable signed count facts')
        _restore_actual_phase_count_proof_v2(self.actual_count_proof, request)


@dataclass(frozen=True, slots=True)
class ArtifactDraftModelStageV2:
    frame: object
    stage: object
    prepared: ArtifactDraftModelPreparedV2
    frozen: ArtifactDraftInputV2 | ArtifactDraftInputV3
    job: PersistentJob
    model_request: object | None
    before_cycle: PersistentJob | None
    after_cycle: PersistentJob | None
    quote: ResourceQuote | None = None
    before_job: PersistentJob | None = None



def installed_artifact_draft_workflow_v2(bundle):
    from ..host.authority_profile import is_installed_artifact_draft_phase_slot_v2
    workflow = bundle.artifact_draft.phase_model_workflow
    if not is_installed_artifact_draft_phase_slot_v2(bundle, workflow):
        raise MissingProductionOriginalV1('actual_installed_artifact_draft_phase_workflow')
    return workflow


def artifact_draft_model_from_wire_v2(raw, kind):
    if kind not in {PrepareArtifactDraftModelRequestV2, AcquireArtifactDraftModelRequestV2,
            ArtifactDraftModelPreparedV2, ArtifactDraftModelRequestOriginalV2}:
        raise ValueError('unregistered phase technical codec')
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError('closed phase technical fields differ')
    data = dict(raw)
    if 'selector' in data:
        data['selector'] = artifact_draft_from_wire_v2(data['selector'], ArtifactDraftPhaseSelectorV2)
    if kind is ArtifactDraftModelPreparedV2:
        data['audiences'] = tuple(data['audiences'])
        data['owner_guard'] = ProductionOwnerGuardV1(**data['owner_guard'])
    if kind is ArtifactDraftModelRequestOriginalV2:
        data['actual_count_proof'] = artifact_draft_phase_count_proof_from_wire_v2(data['actual_count_proof'])
    result = kind(**data)
    if plain_v1(result) != raw: raise ValueError('noncanonical phase technical wire')
    return result


def read_artifact_draft_prepared_v2(db, *, namespace, issuer, selector):
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.task.namespace != namespace:
        raise TypeError('exact namespace generation phase required')
    ids = artifact_draft_model_ids_v2(selector)
    original = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_prepared', ref=ids['job'])
    if original is None: return None
    prepared = artifact_draft_model_from_wire_v2(original[0], ArtifactDraftModelPreparedV2)
    if prepared.selector != selector or original[1] != prepared.operation_id:
        raise ValueError('phase prepared selector/commit changed')
    return prepared


def require_artifact_phase_frozen_contract_history_v3(db, *, namespace, frozen, issuer=None, read_original=None):
    from .d11_life_preparation_v1 import TABLE
    from .artifact_phase_postconditions_v1 import CONTRACT_KIND, require_artifact_phase_postcondition_history_v1
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    if type(frozen) is not ArtifactDraftInputV3 or frozen.selector.task.namespace != namespace:
        raise MissingProductionOriginalV1('actual_frozen_preregistered_phase_contract_commitment')
    from .artifact_phase_postconditions_v1 import _history_life_payload_point_v2
    row = _history_life_payload_point_v2(db,('payload_json','payload_digest','producing_operation_id'),
        namespace=namespace,kind=CONTRACT_KIND,ref=frozen.postcondition_contract_ref,
        issuer=issuer,read_original=read_original)
    if row is None or row[1] != frozen.postcondition_contract_digest:
        raise MissingProductionOriginalV1('actual_preregistered_phase_contract_original')
    raw = json.loads(row[0])
    contract = require_artifact_phase_postcondition_history_v1(db, namespace=namespace, kind=CONTRACT_KIND,
        original_ref=frozen.postcondition_contract_ref, producing_operation_id=row[2], raw=raw, issuer=issuer, read_original=read_original)
    if (contract.digest != frozen.postcondition_contract_digest or
            foreground_artifact_phase_group_identity_v2(contract.selector) != foreground_artifact_phase_group_identity_v2(frozen.selector)):
        raise ValueError('phase frozen material changed its actual preregistered method contract')
    return contract


def read_artifact_draft_frozen_v2(db, *, prepared, issuer):
    row = _read(db, issuer=issuer, namespace=prepared.namespace, kind='c4_phase_frozen', ref=prepared.frozen_ref)
    if row is None: raise MissingProductionOriginalV1('actual_committed_phase_frozen_input')
    frozen = artifact_draft_input_from_wire_v2(row[0])
    if frozen.digest != prepared.frozen_digest or frozen.selector != prepared.selector:
        raise ValueError('phase frozen input differs from prepared seal')
    return frozen


def read_artifact_draft_model_request_v2(db, *, prepared, issuer):
    from .natural_reply_job_v2 import _request_from_wire
    row = _read(db, issuer=issuer, namespace=prepared.namespace, kind='c4_phase_request',
        ref=artifact_draft_model_ids_v2(prepared.selector)['request'])
    if row is None: raise MissingProductionOriginalV1('actual_committed_phase_acquired_request')
    original = artifact_draft_model_from_wire_v2(row[0], ArtifactDraftModelRequestOriginalV2)
    if original.prepared_digest != prepared.digest or row[1] != prepared.acquire_operation_id:
        raise ValueError('phase request crossed prepared/once commit')
    require_saved_artifact_phase_count_original_v2(db, prepared=prepared, issuer=issuer)
    from ..authority_service.artifact_model_source_read_v3 import read_bound_artifact_model_request_v3
    handled,request=read_bound_artifact_model_request_v3(db,prepared,original)
    if handled:return request
    return _request_from_wire(original.request_json)


def decode_artifact_draft_original_v2(kind, raw):
    if kind == 'c4_phase_frozen': return artifact_draft_input_from_wire_v2(raw)
    if kind == 'c4_phase_prepared': return artifact_draft_model_from_wire_v2(raw, ArtifactDraftModelPreparedV2)
    if kind == 'c4_phase_request': return artifact_draft_model_from_wire_v2(raw, ArtifactDraftModelRequestOriginalV2)
    if kind in {'c4_phase_call', 'c4_phase_paid'}:
        return decode_artifact_draft_original_v1(kind.replace('c4_phase_', 'c4_'), raw)
    if kind == 'c4_phase_result':
        from ..authority_service.d11_artifact_draft_model_v1 import (ArtifactDraftModelResultReadV2,
            artifact_draft_model_result_from_wire_v2)
        return artifact_draft_model_result_from_wire_v2(raw, ArtifactDraftModelResultReadV2)
    if kind in {'c4_phase_adopted', 'c4_phase_verified'}:
        from .d11_artifact_draft_content_v1 import decode_artifact_draft_phase_content_original_v2
        return decode_artifact_draft_phase_content_original_v2(kind, raw)
    raise ValueError('unregistered phase original kind')


def _artifact_phase_selection_history_locator_v2(db, selector):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    ns=selector.task.namespace
    for ref,revision,digest in ((selector.decision_ref,selector.decision_revision,selector.decision_digest),
            (selector.plan_ref,selector.plan_revision,selector.plan_digest)):
        from .domain_background_read_v3 import background_history_v3,background_json_loads_v3
        history=background_history_v3(db,ref,revision)
        if history is None or history[2]!=1 or canonical_digest(background_json_loads_v3(history[1]))!=digest:
            raise MissingProductionOriginalV1('actual_phase_control_signed_adoption_history')
        adoption=read_adopted_domain_operation_v1(db,ns,history[0])
        key=AtomKey.from_token(ref)
        if adoption is None or not any(v.key==key and v.revision==revision for v in adoption['receipt'].write_versions):
            raise ValueError('phase control head lost actual W01 adoption member')
        if ref==selector.decision_ref:
            if (adoption['domain'],adoption['operation_kind'])!=('d08','select_personal_step_v2'):
                raise ValueError('phase Decision was not adopted by the actual personal choice')
            decision=background_json_loads_v3(history[1]);selection=adoption
    preparation_id=selection['payload']['provenance']['prepared_candidates_operation_id']
    return ConsumePersonalDecisionRequestV1(selector.decision_ref,preparation_id),selection,decision


def _artifact_phase_selection_locator_v2(db, selector):
    ns=selector.task.namespace
    for ref,revision,digest in ((selector.decision_ref,selector.decision_revision,selector.decision_digest),
            (selector.plan_ref,selector.plan_revision,selector.plan_digest)):
        from .domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3
        row=background_graph_head_v3(db,ns,ref)
        if row is None or row[0]!=revision or row[2]!=1 or canonical_digest(background_json_loads_v3(row[1]))!=digest:
            raise MissingProductionOriginalV1('current_actual_adopted_phase_control_heads')
    return _artifact_phase_selection_history_locator_v2(db,selector)


def _read_artifact_phase_selected_from_locator_v2(db, *, selector, issuer, locator):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1, ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    namespace = selector.task.namespace
    request, selected, decision = locator
    original = read_adopted_domain_operation_v1(db, namespace, request.prepared_candidates_operation_id)
    if original is None or (original['domain'], original['operation_kind']) != ('d08', 'prepare_personal_candidates_v1'):
        raise MissingProductionOriginalV1('actual_adopted_phase_candidate_preparation')
    prepared = decode_typed_production_value_v1(original['payload']['provenance']['prepared_candidates'], PreparedPersonalCandidateSetV1)
    chosen = tuple(row for row in prepared.candidates if row.future_identity.action_ref == decision['chosen_action_ref'])
    if (len(chosen) != 1 or type(chosen[0].binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}
            or chosen[0].eligibility.hard_status != 'eligible' or chosen[0].price is None
            or prepared.future_decision_ref != selector.decision_ref
            or prepared.selection_operation_id != selected['receipt'].operation_id
            or prepared.plan_head.key.token != selector.plan_ref or prepared.plan_head.revision != selector.plan_revision
            or not prepared.need.complete or prepared.need.new_c3_required or prepared.need.meaningful_gaps):
        raise MissingProductionOriginalV1('actual_selected_current_method_and_complete_need')
    binding = chosen[0].binding
    if (binding.task, binding.method_ref) != (selector.task, selector.method_ref):
        raise ValueError('phase group differs from the actually chosen task/method')
    from ..authority_service.named_joint_binding_body_v1 import named_joint_selected_price_v1
    named_joint_selected_price_v1(db,selector,selected,prepared,chosen[0])
    from .artifact_host_dispatch_source_v3 import register_artifact_host_selected_price_v3
    register_artifact_host_selected_price_v3(db,prepared=prepared,chosen=chosen[0],selected=selected)
    from ..authority_service.artifact_model_original_family_v3 import admit_artifact_candidate_family_v3
    admit_artifact_candidate_family_v3(db,prepared=prepared,chosen=chosen[0],selected=selected)
    quote = issuer.resource_issuer.original_signed_quote(db, chosen[0].quote_ref, 1)
    if canonical_digest(quote) != chosen[0].quote_digest or tuple(sorted(quote.ceiling.items())) != chosen[0].quote_ceiling:
        raise ValueError('phase choice lost its actual signed prospective price')
    return prepared, chosen[0], original



def require_artifact_phase_plan_control_qualification_v2(db, *, selector, binding, issuer):
    from .ingress_artifact_task_scope_v1 import (task_scope_ref_v1,IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3,
        _decode as task_decode,require_task_scope_archive_v1)
    from .artifact_task_text_extent_v1 import ArtifactTaskTextExtentOriginalV2,require_artifact_task_text_extent_history_v1
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    plan_key=AtomKey.from_token(selector.plan_ref);decision_key=AtomKey.from_token(selector.decision_ref)
    cycle_key=AtomKey.from_token(selector.task.cycle_job_ref);ns=selector.task.namespace
    if decision_key.owner!=cycle_key.owner or plan_key.owner.kind!='activity' or NamespaceId.from_key(plan_key)!=ns:
        raise ValueError('phase control changed actual current Decision activity or Plan namespace/type')
    if plan_key.owner==cycle_key.owner:return
    if type(binding) is not ArtifactPhaseCandidateBindingV3:
        raise MissingProductionOriginalV1('actual_registered_amendment_binding_for_cross_activity_Plan')
    row=_read(db,issuer=issuer,namespace=ns,kind='artifact_task_scope',ref=task_scope_ref_v1(selector.task.root_registration_ref))
    if row is None:raise MissingProductionOriginalV1('actual_cross_activity_continued_TaskScope')
    scope=task_decode(row[0],IngressArtifactTaskScopeOriginalV2)
    producer=read_adopted_domain_operation_v1(db,ns,row[1])
    require_task_scope_archive_v1(db,namespace=ns,root=scope.root,producer=producer)
    if type(scope) not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3} or scope.task_kind!='continue' or scope.c02_operation_id!=selector.task.c02_operation_id:
        raise ValueError('cross activity Plan is only qualified by its actual ordinary amendment TaskScope')
    extent_row=_read(db,issuer=issuer,namespace=ns,kind='artifact_task_text_extent',ref=binding.extent_original_ref)
    if extent_row is None or canonical_digest(extent_row[0])!=binding.extent_original_digest:
        raise MissingProductionOriginalV1('actual_cross_activity_registered_amended_extent')
    extent=require_artifact_task_text_extent_history_v1(db,namespace=ns,original_ref=binding.extent_original_ref,
        producing_operation_id=extent_row[1],raw=extent_row[0])
    if type(extent) is not ArtifactTaskTextExtentOriginalV2:raise ValueError('cross activity Plan cannot borrow an initial extent')
    basis=extent.basis
    revision=read_adopted_domain_operation_v1(db,ns,artifact_task_plan_revision_operation_id_v2(selector.task))
    plan,_=require_artifact_task_plan_revision_original_v2(db,namespace=ns,original=revision)
    if (basis.task!=selector.task or basis.plan_head!=GraphVersion(plan_key,selector.plan_revision)
            or basis.plan_digest!=selector.plan_digest or canonical_digest(plain_v1(plan))!=selector.plan_digest
            or (basis.plan_revision_operation_id,basis.plan_revision_original_digest)!=(revision['receipt'].operation_id,revision['original_digest'])
            or basis.task_scope_ref!=task_scope_ref_v1(selector.task.root_registration_ref)
            or basis.task_scope_digest!=canonical_digest(row[0]) or basis.root!=scope.root):
        raise ValueError('cross activity Plan changed its signed same-task revision/Basis/Scope/Plan head')
    actual=read_current_amendment_v1(db,namespace=ns,root_registration_ref=selector.task.root_registration_ref,issuer=issuer)
    if actual is None or (actual[1],canonical_digest(plain_v1(actual[0])))!=(basis.amendment_original_ref,basis.amendment_original_digest):
        raise ValueError('cross activity Plan lost its actual current ordinary user amendment')
    guard=basis.owner_guard
    from .domain_background_read_v3 import background_graph_head_v3
    owner=background_graph_head_v3(db,ns,guard.grant_ref)
    if owner is None or owner[2]!=1 or (owner[0],canonical_digest(json.loads(owner[1])))!=(guard.grant_revision,guard.grant_digest):
        raise MissingProductionOriginalV1('current_Owner_access_to_same_task_amendment_Plan')
    for head,digest in ((basis.amendment_source_head,basis.amendment_source_digest),(basis.previous_content_head,basis.previous_content_digest)):
        from ..authority_service.named_joint_binding_body_v1 import named_joint_source_commitment_v1
        if named_joint_source_commitment_v1(db,ns,head,digest):continue
        source=background_graph_head_v3(db,ns,head.key.token)
        if source is None or source[2]!=1 or (source[0],canonical_digest(json.loads(source[1])))!=(head.revision,digest):
            raise MissingProductionOriginalV1('current_actual_amendment_and_previous_full_file_Source')
        _source_family_current_sql_v1(db,namespace=ns,roots=(head.key.token,),purpose='consolidation',audiences=tuple(json.loads(source[1])['audiences']))


def _read_artifact_phase_selected_originals_v2(db, *, selector, issuer):
    value=_read_artifact_phase_selected_from_locator_v2(db,selector=selector,issuer=issuer,
        locator=_artifact_phase_selection_locator_v2(db,selector))
    require_artifact_phase_plan_control_qualification_v2(db,selector=selector,binding=value[1].binding,issuer=issuer)
    return value


def read_artifact_phase_selected_history_v2(db, *, selector, issuer):
    """Read a completed immutable selection for disclosed history; grant no new phase."""
    from .artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2,read_current_artifact_task_milestone_v2
    from .d11_artifact_draft_content_v1 import artifact_method_settlement_operation_id_v2,require_artifact_method_settlement_history_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    ns=selector.task.namespace
    milestone=read_current_artifact_task_milestone_v2(db,namespace=ns,original_ref=artifact_task_milestone_original_ref_v2(selector),issuer=issuer)
    completed=read_adopted_domain_operation_v1(db,ns,artifact_method_settlement_operation_id_v2(selector))
    if completed is None:raise MissingProductionOriginalV1('actual_completed_selection_same_W01_history')
    history=require_artifact_method_settlement_history_v2(db,namespace=ns,original=completed,raw=completed['payload']['provenance']['artifact_method_completion'])
    if history.selector!=selector or history.milestone_original_ref!=milestone.original_ref:
        raise ValueError('completed selection history changed its same actual method/milestone')
    return _read_artifact_phase_selected_from_locator_v2(db,selector=selector,issuer=issuer,
        locator=_artifact_phase_selection_history_locator_v2(db,selector))


def require_current_artifact_phase_group_v2(db, *, namespace, group, issuer, installed_bundle=None, owner_guard=None):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_artifact_draft_content_v1 import (read_current_artifact_phase_verified_v2,
        artifact_method_settlement_operation_id_v2, read_current_completed_artifact_method_history_v2)
    if (not db.in_transaction or type(issuer) is not D11BudgetJobIssuer
            or type(group) is not ForegroundArtifactPhaseGroupV2 or group.selector.task.namespace != namespace):
        raise TypeError('phase group needs the actual current signed namespace reader')
    selector = group.selector
    completed = read_adopted_domain_operation_v1(db, namespace, artifact_method_settlement_operation_id_v2(selector))
    if completed is not None:
        history, _ = read_current_completed_artifact_method_history_v2(db, namespace=namespace, selector=selector,
            issuer=issuer, installed_bundle=installed_bundle, owner_guard=owner_guard)
        if history.ordered_phase_originals != group.completed_phase_originals:
            raise ValueError('completed phase group changed its exact signed verified prefix')
        return group
    _read_artifact_phase_selected_originals_v2(db, selector=selector, issuer=issuer)
    phases = artifact_draft_phase_sequence_v2(selector.method_ref)
    for index, (ref, digest) in enumerate(group.completed_phase_originals):
        prior = group.completed_phase_originals[index - 1] if index else (None, None)
        phase = replace(selector, phase_index=index, phase_kind=phases[index],
            prev_phase_original_ref=prior[0], prev_phase_original_digest=prior[1])
        verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=phase, issuer=issuer)
        if ref != artifact_draft_phase_original_ref_v2(phase) + ':verified' or canonical_digest(plain_v1(verified)) != digest:
            raise ValueError('phase group lost its exact independently verified prefix')
    return group


def _selected_artifact_phase_candidate_v2(db, *, frame, selector, readers):
    from .d08_personal_candidate_v1 import (InstalledPersonalCandidateReadersV1,
        _phase_preparation_transition_v1, _read_selected_after_phase_transition)
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    from .d08_project_control_v1 import require_current_project_plan_for_new_work_v1
    require_current_project_plan_for_new_work_v1(db, namespace=selector.task.namespace, plan_ref=selector.plan_ref)
    runtime = readers.model_runtime
    if runtime is None: raise MissingProductionOriginalV1('actual_same_installed_phase_model_runtime')
    domain_runtime = runtime.graph._GraphCoordinator__domain_production_runtime_v1
    personal = getattr(domain_runtime, '_personal_candidate_readers_v1', None)
    if type(personal) is not InstalledPersonalCandidateReadersV1:
        raise MissingProductionOriginalV1('actual_installed_personal_method_readers')
    request, _, _ = _artifact_phase_selection_locator_v2(db, selector)
    personal = personal.current()
    with _phase_preparation_transition_v1(db, frame=frame, request=request, phase_selector=selector,
            installed_readers=personal) as transition:
        prepared, chosen, original = _read_selected_after_phase_transition(db, frame=frame, request=request,
            installed_readers=personal, transition=transition)
    binding = chosen.binding
    if type(binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} or (binding.task, binding.method_ref) != (selector.task, selector.method_ref):
        raise ValueError('model phase changed selected method parameters')
    _current_artifact_phase_parameters_v2(db, selector=selector, chosen=chosen, issuer=readers.issuer)
    return prepared, chosen, original


def read_plan_artifact_draft_model_v2(db, *, namespace, operation_kind, request, installed_readers=None):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
    from ..domains.d03.self_perspective import self_mapping_key
    from .d10_project_checkpoint_v1 import read_plan_current_project_capacity_v1
    if type(request) not in {PrepareArtifactDraftModelRequestV2, AcquireArtifactDraftModelRequestV2}:
        raise TypeError('exact phase model request required')
    phase = request.selector; task = phase.task; ids = artifact_draft_model_ids_v2(phase)
    cycle = get_job(db, AtomKey.from_token(task.cycle_job_ref).name)
    cont = foreground_cycle_from_wire_v1(cycle.continuation)
    selected, _, _ = _artifact_phase_selection_locator_v2(db, phase)
    personal = None
    if installed_readers is not None and installed_readers.model_runtime is not None:
        personal = getattr(installed_readers.model_runtime.graph._GraphCoordinator__domain_production_runtime_v1,
            '_personal_candidate_readers_v1', None)
    extra = read_plan_personal_candidates_v1(db, namespace=namespace, activity_id=cycle.activity_id,
        request=selected, installed_readers=personal)
    if personal is not None:
        from .d08_personal_candidate_v1 import _read_plan_phase_preparation_transition_v1
        transition = _read_plan_phase_preparation_transition_v1(db, namespace=namespace,
            phase_selector=phase, installed_readers=personal.current())
        extra = production_read_plan_v1((*extra.fixed_type_ids, *transition.fixed_type_ids),
            (*extra.exact_keys, *transition.exact_keys), (*extra.source_roots, *transition.source_roots),
            (*extra.required_original_refs, *transition.required_original_refs))
    from .artifact_phase_postconditions_v1 import read_plan_current_artifact_phase_postcondition_contract_v1
    contract_plan = read_plan_current_artifact_phase_postcondition_contract_v1(db, namespace=namespace,
        selector=phase, installed_readers=installed_readers)
    extra = production_read_plan_v1((*extra.fixed_type_ids, *contract_plan.fixed_type_ids),
        (*extra.exact_keys, *contract_plan.exact_keys), (*extra.source_roots, *contract_plan.source_roots),
        (*extra.required_original_refs, *contract_plan.required_original_refs))
    from .method_pair_shared_input_v1 import method_pair_read_inputs_v1
    from .domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3
    actual_plan = background_graph_head_v3(db, namespace, phase.plan_ref)
    if actual_plan is None or actual_plan[2] != 1:
        raise MissingProductionOriginalV1("actual_current_method_pair_task_Plan")
    _, pair_plan = method_pair_read_inputs_v1(db, namespace=namespace,
        goal_ref=background_json_loads_v3(actual_plan[1])["goal_ref"])
    extra = production_read_plan_v1((*extra.fixed_type_ids, *pair_plan.fixed_type_ids),
        (*extra.exact_keys, *pair_plan.exact_keys), (*extra.source_roots, *pair_plan.source_roots),
        (*extra.required_original_refs, *pair_plan.required_original_refs))
    capacity = read_plan_current_project_capacity_v1(db, namespace=namespace, selector=task)
    originals = [task.root_registration_ref, task.c02_operation_id]
    if type(request) is AcquireArtifactDraftModelRequestV2: originals.extend((ids['job'], ids['frozen']))
    if phase.prev_phase_original_ref is not None: originals.append(phase.prev_phase_original_ref)
    return production_read_plan_v1((*extra.fixed_type_ids, *capacity.fixed_type_ids),
        (*extra.exact_keys, *capacity.exact_keys, AtomKey.from_token(task.cycle_job_ref),
            runtime_job_key(*namespace.as_tuple, cycle.activity_id, ids['job']), self_mapping_key(namespace),
            AtomKey.from_token(phase.decision_ref), AtomKey.from_token(phase.plan_ref), owner_grant_key(*namespace.as_tuple)),
        (*extra.source_roots, *capacity.source_roots, cont.source_ref),
        (*extra.required_original_refs, *capacity.required_original_refs, *originals))


def read_current_artifact_draft_attempt_v2(db, *, namespace, continuation, attempt, issuer):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    if type(attempt) is not ForegroundModelAttemptV2:
        raise TypeError('actual generation phase physical attempt required')
    p = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=issuer, selector=attempt.phase_selector)
    if p is None: raise MissingProductionOriginalV1('actual_phase_prepared_for_physical_attempt')
    if (p.selector.task.c02_operation_id != continuation.c02_operation_id
            or p.parent_budget_lease_ref != continuation.call_plan.parent_budget_lease_ref
            or (attempt.reservation_operation_id, attempt.reservation_digest, attempt.budget_lease_ref) !=
                (p.operation_id, p.reservation_digest, p.parent_budget_lease_ref)):
        raise ValueError('phase attempt changed its original task/root/reservation')
    quote = issuer.resource_issuer.original_signed_quote(db, p.quote_id, 1)
    if canonical_digest(quote) != p.quote_digest or quote.work_kind != WORK_KIND:
        raise ValueError('phase physical attempt changed its signed quote')
    reserved = _artifact_receipt_sql_v1(db,'SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (p.parent_budget_lease_ref, p.operation_id)).fetchone()
    if reserved is None or reserved[0] != p.reservation_digest: raise ValueError('actual phase reservation absent')
    ids = artifact_draft_model_ids_v2(p.selector)
    paid = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_paid', ref=ids['paid'])
    result = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_result', ref=ids['result'])
    state, terminal_ref = 'reserved', None
    if result is not None:
        actual = decode_artifact_draft_original_v2('c4_phase_result', result[0])
        if (paid is None or paid[0]['terminal_receipt_digest'] != canonical_digest(asdict(actual.terminal_receipt))
                or actual.request.binding_digest != p.digest or actual.request.selector != p.selector):
            raise ValueError('actual phase result lost its original paid terminal')
        state, terminal_ref = 'completed', ids['result']
    elif paid is not None or reserved[1] in {'unknown', 'partial_unknown', 'unconfirmed'}:
        state = 'unknown'
    return ForegroundModelAttemptV2('C4', p.call_id, None, p.operation_id, p.reservation_digest, p.parent_budget_lease_ref,
        quote.ceiling['input_tokens'], quote.ceiling['output_tokens'], state, terminal_ref, phase_selector=p.selector)


def _artifact_model_phase_v2(prepared):
    if type(prepared) not in {ArtifactDraftModelPreparedV1, ArtifactDraftModelPreparedV2}:
        raise TypeError('exact registered prepared model original required')
    return type(prepared) is ArtifactDraftModelPreparedV2


def _artifact_model_ids(prepared):
    return (artifact_draft_model_ids_v2 if _artifact_model_phase_v2(prepared) else artifact_draft_model_ids_v1)(prepared.selector)


def _artifact_model_original_kind(prepared, suffix):
    return ('c4_phase_' if _artifact_model_phase_v2(prepared) else 'c4_') + suffix


def _artifact_model_request(db, *, prepared, issuer):
    return (read_artifact_draft_model_request_v2 if _artifact_model_phase_v2(prepared) else read_artifact_draft_model_request_v1)(
        db, prepared=prepared, issuer=issuer)


def apply_artifact_draft_model_stage_v2(witness, graph, db, installed_readers):
    if type(witness.stage) is not ArtifactDraftModelStageV2: raise TypeError('exact phase stage required')
    return apply_artifact_draft_model_stage_v1(witness, graph, db, installed_readers)


def require_artifact_draft_model_commit_v2(witness, graph, db, bundle):
    if type(witness.stage) is not ArtifactDraftModelStageV2: raise TypeError('exact phase stage required')
    return require_artifact_draft_model_commit_v1(witness, graph, db, bundle)


def validate_artifact_draft_model_proposal_v2(proposal, snapshot, stage):
    if type(stage) is not ArtifactDraftModelStageV2: raise TypeError('exact phase stage required')
    return validate_artifact_draft_model_proposal_v1(proposal, snapshot, stage)


def _require_artifact_phase_candidate_current_sql(db, *, selector, issuer, now, owner_guard, audiences, installed_bundle, phase_state):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3,artifact_model_current_type_versions_v3
    """Authenticate adopted finite proof and re-read all hard evidence in the pinned Graph.

    Runtime cycle/job heads advance through their explicit once gates above;
    every domain/Source/Owner head and full inventory remains exact.
    """
    from ..host.authority_profile import is_installed_artifact_draft_phase_slot_v2
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    prepared, chosen, original = _read_artifact_phase_selected_originals_v2(db, selector=selector, issuer=issuer)
    namespace = selector.task.namespace
    if phase_state == 'selected':
        from .d08_project_control_v1 import require_current_project_plan_for_new_work_v1
        require_current_project_plan_for_new_work_v1(db, namespace=namespace, plan_ref=selector.plan_ref)
    transitions = {}
    if phase_state == 'completed':
        from .d08_personal_candidate_v1 import readonly_current_completed_artifact_phase_facts_v1
        actual, selected, adoption, changes, producers = readonly_current_completed_artifact_phase_facts_v1(db,
            namespace=namespace, selector=selector, issuer=issuer, now_utc=now,
            owner_guard=owner_guard, installed_bundle=installed_bundle)
        if actual != prepared or selected != chosen:
            raise ValueError('completed phase current facts changed actual selected Decision/parameters')
        for before, after, digest in changes:
            if (type(before) is not GraphVersion or type(after) is not GraphVersion or before.key != after.key
                    or NamespaceId.from_key(before.key) != namespace or after.revision <= before.revision):
                raise ValueError('completed phase facts have no exact namespace once-version advance')
            history = artifact_model_graph_point_v3(db,('value', 'valid'),token=after.key.token,revision=after.revision)
            if history is None or history[1] != 1 or background_json_digest_v3(history[0],background_json_loads_v3(history[0])) != digest:
                raise ValueError('completed phase delta lost actual historical W01 bytes')
            transitions.setdefault(before.key.token, []).append((before.revision,after.revision))
    elif phase_state != 'selected':
        raise ValueError('unregistered phase current-reader state')
    from .d08_personal_candidate_v1 import readonly_current_artifact_task_choice_checkpoint_delta_v2
    checkpoint_delta=readonly_current_artifact_task_choice_checkpoint_delta_v2(db,namespace=namespace,
        selector=selector,issuer=issuer,prepared_candidates=prepared)
    if checkpoint_delta is not None:
        before,after,digest,operation_id,original_digest,node=checkpoint_delta
        history=artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=after.key.token,revision=after.revision)
        if (before.key!=after.key or after.revision!=before.revision+1 or NamespaceId.from_key(before.key)!=namespace
                or history is None or history[0]!=operation_id or history[2]!=1 or background_json_digest_v3(history[1],background_json_loads_v3(history[1]))!=digest):
            raise ValueError('selected checkpoint qualification lost its exact actual W01 successor')
        step=(before.revision,after.revision)
        if step not in transitions.setdefault(before.key.token,[]):transitions[before.key.token].append(step)
    def admitted_change(ref, before, after):
        if before == after: return True
        seen = set()
        while before != after:
            if before in seen: return False
            seen.add(before)
            steps = tuple(next_revision for revision,next_revision in transitions.get(ref, ()) if revision == before)
            if len(steps) != 1 or steps[0] > after: return False
            before = steps[0]
        return True
    if ((prepared.owner_grant_ref, prepared.owner_grant_revision, prepared.owner_grant_digest) !=
            (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)
            or now >= min(prepared.need.original_deadline_utc, chosen.future_identity.deadline_utc)
            or prepared.need.new_c3_required or prepared.need.meaningful_gaps or not prepared.need.complete):
        raise MissingProductionOriginalV1('actual_current_phase_owner_need_scope_deadline')
    rights = _artifact_receipt_sql_v1(db,'SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',
        namespace.as_tuple).fetchone()
    if rights != (prepared.access_epoch, prepared.delete_epoch):
        raise ValueError('phase Need/choice current Source rights changed')
    versions = {version.key.token: version for version in prepared.read_versions}
    for evidence in (prepared.need, chosen.eligibility, chosen.price):
        for version in evidence.read_versions:
            old = versions.get(version.key.token)
            if old is not None and old != version: raise ValueError('phase original hard evidence versions conflict')
            versions[version.key.token] = version
        for coverage in evidence.query_coverage:
            rows = artifact_model_current_type_versions_v3(db,namespace,coverage.type_id,limit=1025)
            actual = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in rows)
            previous = {version.key.token:version.revision for version in coverage.row_versions}
            current = {version.key.token:version.revision for version in actual}
            if (not coverage.complete or any(ref not in current or not admitted_change(ref, revision, current[ref])
                    for ref,revision in previous.items())
                    or any(ref not in previous and not admitted_change(ref, 0, revision) for ref,revision in current.items())):
                raise MissingProductionOriginalV1('phase_complete_current_hard_inventory')
    cycle = get_job(db, AtomKey.from_token(selector.task.cycle_job_ref).name)
    cycle_atom = artifact_model_graph_point_v3(db,('value', 'valid'),token=selector.task.cycle_job_ref)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle_atom is None or cycle_atom[1] != 1 or background_json_loads_v3(cycle_atom[0]) != job_graph_write(cycle).value
            or cycle.cancel_epoch or continuation.cancel_generation
            or continuation.c02_operation_id != selector.task.c02_operation_id
            or type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}
            or continuation.call_plan.phase_group.selector != selector):
        raise ValueError('phase mutable cycle is not its actual SQL/Graph once transition')
    phase_keys = {}
    phases = artifact_draft_phase_sequence_v2(selector.method_ref)
    prefix = continuation.call_plan.phase_group.completed_phase_originals
    for index in range(selector.phase_index + 1):
        if phases[index] not in {'tone_sample', 'full'}: continue
        prior = prefix[index - 1] if index else (None, None)
        phase_selector = replace(selector, phase_index=index, phase_kind=phases[index],
            prev_phase_original_ref=prior[0], prev_phase_original_digest=prior[1])
        ids = artifact_draft_model_ids_v2(phase_selector)
        phase_keys[runtime_job_key(*namespace.as_tuple, cycle.activity_id, ids['job']).token] = phase_selector
    for version in versions.values():
        if version.key.token == selector.task.cycle_job_ref:
            continue
        if version.key.token in phase_keys:
            expected_phase = phase_keys[version.key.token]
            phase_prepared = read_artifact_draft_prepared_v2(db, namespace=namespace, selector=expected_phase, issuer=issuer)
            if phase_prepared is not None:
                phase_job = get_job(db, phase_prepared.job_id)
                atom = artifact_model_graph_point_v3(db,('value', 'valid'),token=version.key.token)
                if (atom is None or atom[1] != 1 or background_json_loads_v3(atom[0]) != job_graph_write(phase_job).value
                        or phase_job.operation_id != phase_prepared.operation_id or phase_job.cancel_epoch
                        or phase_job.continuation != {'schema':'d11.artifact-draft-phase-model-job.v2',
                            'selector':plain_v1(expected_phase), 'prepared_digest':phase_prepared.digest}):
                    raise ValueError('phase mutable job differs from actual signed SQL/Graph once original')
                continue
        row = artifact_model_graph_point_v3(db,('revision', 'valid'),token=version.key.token)
        revision = 0 if row is None else row[0]
        if version.key.token == prepared.future_decision_ref and version.revision == 0:
            if revision != selector.decision_revision: raise ValueError('phase adopted Decision head changed')
        elif not admitted_change(version.key.token, version.revision, revision) or version.revision and row[1] != 1:
            raise MissingProductionOriginalV1('phase_current_original_positive_negative_evidence')
    current_owner = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=owner_guard.grant_ref)
    if (current_owner is None or current_owner[0] != owner_guard.grant_revision or current_owner[2] != 1
            or background_json_digest_v3(current_owner[1],background_json_loads_v3(current_owner[1])) != owner_guard.grant_digest):
        raise ValueError('phase current upstream Owner grant changed')
    _source_family_current_sql_v1(db, namespace=namespace, roots=prepared.source_refs,
        purpose='consolidation', audiences=audiences)
    workflow = installed_artifact_draft_workflow_v2(installed_bundle)
    if not is_installed_artifact_draft_phase_slot_v2(installed_bundle, workflow):
        raise MissingProductionOriginalV1('current_installed_phase_policy')
    quote = issuer.resource_issuer.original_signed_quote(db, chosen.quote_ref, 1)
    limits = artifact_draft_phase_token_limits_v2(selector)
    if (now >= quote.valid_until_utc or quote.work_kind != WORK_KIND
            or any(amount > workflow.quote_ceiling.get(name, 0) for name, amount in quote.ceiling.items())
            or any(quote.ceiling.get(name, 0) > amount for name, amount in limits.items())
            or chosen.price.template_version != workflow.template_version):
        raise ValueError('phase current signed prospective quote/config exceeded')
    return chosen



def _require_artifact_phase_candidate_current_sql_v2(db, *, selector, issuer, now, owner_guard, audiences, installed_bundle):
    return _require_artifact_phase_candidate_current_sql(db, selector=selector, issuer=issuer, now=now,
        owner_guard=owner_guard, audiences=audiences, installed_bundle=installed_bundle, phase_state='selected')


def _require_completed_artifact_phase_candidate_current_sql_v2(db, *, selector, issuer, now, owner_guard, audiences, installed_bundle):
    return _require_artifact_phase_candidate_current_sql(db, selector=selector, issuer=issuer, now=now,
        owner_guard=owner_guard, audiences=audiences, installed_bundle=installed_bundle, phase_state='completed')


async def execute_prepared_artifact_draft_model_v2(runtime, *, job_id):
    return await execute_prepared_artifact_draft_model_v1(runtime, job_id=job_id)


async def recover_original_artifact_draft_model_cost_v2(runtime, *, c02_operation_id):
    from .model_cost_settlement import read_original_model_cost
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:
        raise TypeError('actual installed phase runtime required')
    tasks = await runtime.worker.call(lambda graph: runtime._read_original_phase_cost_tasks_v2(graph,
        c02_operation_id=c02_operation_id))
    results = []
    for prepared, intent in tasks:
        no_dispatch = await reconcile_original_artifact_no_dispatch_v1(runtime, prepared=prepared, intent=intent)
        if no_dispatch is not None:
            results.append({"status": "original_no_dispatch_cost_recorded", "call_id": intent.call_id})
            continue
        facts = await runtime.authority_client.model_terminal_fact_v2(runtime.bundle, runtime.client_grant, intent=intent)
        fact = read_original_model_cost(lambda _intent: facts, intent)
        runtime._cost_facts[prepared.job_id] = fact
        if fact.recovery.state != 'observed':
            results.append({'status':'original_terminal_unknown', 'call_id':intent.call_id})
            continue
        paid = await runtime.worker.call(lambda graph: graph.reconcile_current_artifact_draft_model_cost_v1(
            runtime.bootstrap, runtime.bundle, prepared=prepared))
        runtime._paid[prepared.job_id] = paid
        results.append({'status':'original_cost_recorded', 'call_id':intent.call_id})
    return tuple(results)


def require_artifact_method_physical_version_capacity_v2(*, selector, prior, installed_bundle,maximum_artifact_version=None):
    from ..host.authority_profile import AdminArtifactDraftToolScopeV1,AdminArtifactDraftToolScopeV2
    scope=installed_bundle.artifact_draft.tool_scope
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftToolScopeV3
    if type(scope) in {AdminArtifactDraftToolScopeV2,AdminArtifactDraftToolScopeV3}:
        cap=scope.maximum_artifact_version
    elif type(scope) is AdminArtifactDraftToolScopeV1:
        cap=1
    else:
        raise TypeError('actual installed artifact file scope required')
    if maximum_artifact_version is not None:cap=min(cap,maximum_artifact_version)
    current=0 if prior is None else prior.verified_readback.version
    phases=artifact_draft_phase_sequence_v2(selector.method_ref)
    required=current+sum(kind in {'tone_sample','full'} for kind in phases[selector.phase_index:])
    if required>cap:
        raise MissingProductionOriginalV1(f'artifact_method_physical_version_scope:current={current},cap={cap},required={required}')
    return required


def _current_artifact_phase_parameters_v2(db, *, selector, chosen, issuer):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    from .d11_artifact_draft_content_v1 import (read_current_artifact_phase_verified_v2,
        artifact_draft_phase_verification_from_wire_v2, ArtifactDraftPhaseVerifiedOriginalV2,
        require_current_artifact_prior_content_v2)
    from ..runtime_contracts import VersionedRef
    binding = chosen.binding
    if type(binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} or (
            binding.task, binding.method_ref) != (selector.task, selector.method_ref):
        raise ValueError('generation phase changed the actually adopted whole method')
    if (binding.phase_index, binding.phase_kind) == (selector.phase_index, selector.phase_kind):
        if (binding.prev_phase_original_ref, binding.prev_phase_original_digest) != (
                selector.prev_phase_original_ref, selector.prev_phase_original_digest):
            raise ValueError('selected generation changed its authenticated predecessor')
        if binding.prior_content is not None:
            require_current_artifact_prior_content_v2(db, namespace=selector.task.namespace, selector=selector,
                prior=binding.prior_content, issuer=issuer)
        return binding.extent, binding.target, binding.prior_content
    if (type(binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} or binding.phase_index != 0
            or binding.phase_kind != 'tone_sample' or selector.phase_kind != 'full' or selector.phase_index != 2):
        raise MissingProductionOriginalV1('registered_selected_later_phase_parameters')
    row = _read(db, namespace=selector.task.namespace, issuer=issuer, kind='c4_phase_verified', ref=selector.prev_phase_original_ref)
    if row is None or canonical_digest(row[0]) != selector.prev_phase_original_digest:
        raise MissingProductionOriginalV1('actual_qualified_previous_sample_check')
    previous = artifact_draft_phase_verification_from_wire_v2(row[0], ArtifactDraftPhaseVerifiedOriginalV2)
    verified = read_current_artifact_phase_verified_v2(db, namespace=selector.task.namespace, selector=previous.selector, issuer=issuer)
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    if (previous.selector.phase_kind != 'sample_check' or previous.selector.phase_index != 1
            or not verified.method_qualified or foreground_artifact_phase_group_identity_v2(previous.selector) !=
                foreground_artifact_phase_group_identity_v2(selector) or verified.full_extent != binding.full_extent
            or (verified.extent_original_ref, verified.extent_original_digest) !=
                (binding.extent_original_ref, binding.extent_original_digest)):
        raise ValueError('later full phase lost actual qualified sample and original whole-method extent')
    readback = verified.readback
    target = DraftFileTargetV1(binding.target.root_resource_id, binding.target.root_registration_ref,
        binding.target.root_registration_digest, binding.target.root_identity, binding.target.filename, 'replace',
        readback.version, readback.content_digest, readback.file_identity, readback.effect_marker, binding.target.max_bytes)
    prior = ArtifactDraftPriorContentCommitmentV2(VersionedRef(verified.source_head.key.token, verified.source_head.revision),
        verified.source_value_digest, verified.original_ref, verified.digest, readback)
    require_current_artifact_prior_content_v2(db, namespace=selector.task.namespace, selector=selector, prior=prior, issuer=issuer)
    return binding.full_extent, target, prior


def freeze_actual_artifact_phase_count_stage_in_transaction_v2(db, *, frame, request, installed_readers):
    """Read-only prospective queued-to-running stage; this acquires nothing."""
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    if (not db.in_transaction or type(request) is not AcquireArtifactDraftModelRequestV2
            or type(installed_readers) is not InstalledArtifactDraftModelReadersV1):
        raise TypeError('actual phase count freeze needs exact current acquisition frame/request/readers')
    stage = _acquire_artifact_draft_model(db, frame=frame, request=request, installed_readers=installed_readers, phase=True)
    _, chosen, _ = _selected_artifact_phase_candidate_v2(db, frame=frame, selector=request.selector, readers=installed_readers)
    if type(chosen.binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
        raise MissingProductionOriginalV1('actual_committed_whole_method_text_extent_before_count')
    extent, target, prior = _current_artifact_phase_parameters_v2(db, selector=request.selector, chosen=chosen, issuer=installed_readers.issuer)
    binding = replace(chosen.binding, phase_index=request.selector.phase_index, phase_kind=request.selector.phase_kind,
        extent=extent, target=target, prior_content=prior, prev_phase_original_ref=request.selector.prev_phase_original_ref,
        prev_phase_original_digest=request.selector.prev_phase_original_digest)
    return frame, stage, binding


def validate_frozen_artifact_phase_count_stage_in_transaction_v2(db, *, frozen_stage, count_pair, installed_readers, now_utc):
    """Verify real outside counts/current dependencies, retaining the original body."""
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d02_artifact_phase_price_v1 import ArtifactPhaseCountPairV1, verify_frozen_artifact_phase_count_pair_in_transaction_v1
    import math
    if (not db.in_transaction or type(frozen_stage) is not ArtifactDraftModelStageV2
            or type(count_pair) is not ArtifactPhaseCountPairV1 or type(installed_readers) is not InstalledArtifactDraftModelReadersV1
            or frozen_stage.before_job is None or frozen_stage.model_request is None
            or type(now_utc) not in {float, int} or not math.isfinite(now_utc) or now_utc < frozen_stage.frame.now_utc):
        raise TypeError('actual frozen acquisition stage, signed count pair and current trusted time required')
    stage = _unseal_actual_phase_count_stage_v2(frozen_stage); p = stage.prepared; model = stage.model_request
    _, rebuilt, binding = freeze_actual_artifact_phase_count_stage_in_transaction_v2(db,
        frame=stage.frame, request=AcquireArtifactDraftModelRequestV2(p.selector), installed_readers=installed_readers)
    if rebuilt != stage:
        raise MissingProductionOriginalV1('same_actual_frozen_model_body_and_expected_once_transition')
    if (stage.job.lease_expires_utc is None or now_utc >= min(model.envelope.deadline_utc, stage.frozen.deadline_utc,
            _utc(p.deadline_utc, 'deadline_utc').timestamp(), _utc(stage.job.lease_expires_utc, 'lease_expires_utc').timestamp())):
        raise MissingProductionOriginalV1('original_counted_phase_stage_deadline_or_worker_lease_expired')
    # This temporary read view checks Source expiry with fresh trusted time.
    # It is never serialized into the counted request or submitted W01 stage.
    fresh_frame = replace(stage.frame, now_utc=now_utc)
    require_artifact_draft_inputs_current_v1(db, prepared=p, frozen=stage.frozen, frame=fresh_frame, readers=installed_readers)
    if get_job(db, p.job_id) != stage.before_job:
        raise MissingProductionOriginalV1('actual_queued_phase_job_before_final_counted_once_acquire')
    initial, final = verify_frozen_artifact_phase_count_pair_in_transaction_v1(db, frozen_stage=stage,
        count_pair=count_pair, installed_readers=installed_readers, now_utc=now_utc)
    if (initial.input_kind != 'actual' or final.input_kind != 'actual'
            or initial.candidate_parameter_digest != binding.digest or final.candidate_parameter_digest != binding.digest):
        raise ValueError('phase counts were not for this actual current phase binding/body')
    quote = installed_readers.resource_issuer.original_signed_quote(db, p.quote_id, 1)
    reserved = _artifact_receipt_sql_v1(db,'SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (p.parent_budget_lease_ref, p.operation_id)).fetchone()
    grant = installed_readers.issuer.current_budget_grant(db, p.parent_budget_lease_ref)
    require_budget_family_admissible(db, p.parent_budget_lease_ref)
    if (canonical_digest(quote) != p.quote_digest or reserved != (p.reservation_digest, canonical_serialize(dict(quote.ceiling)), 'reserved')
            or now_utc >= min(quote.valid_until_utc, grant.valid_until_utc)
            or any(amount > grant.max_ceiling.get(name, 0) for name, amount in quote.ceiling.items())):
        raise MissingProductionOriginalV1('actual_original_reserved_phase_quote_and_current_grant')
    upper = max(initial.upper_tokens, final.upper_tokens)
    ceiling = quote.ceiling
    if (upper > ceiling.get('input_tokens', 0) or model.max_output_tokens > ceiling.get('output_tokens', 0)
            or upper + model.max_output_tokens > ceiling.get('model_tokens', 0)):
        raise MissingProductionOriginalV1('actual_phase_count_exceeds_original_reserved_ceiling')
    return frozen_stage


@dataclass(frozen=True, slots=True)
class ArtifactDraftPhaseCountProofV2:
    common_request_json: str
    initial_nonce: str
    initial_frozen_at_utc: float
    final_nonce: str
    final_frozen_at_utc: float
    initial_envelope_json: str
    final_envelope_json: str
    counter_policy_json: str
    billing_policy_json: str | None
    counted_base_stage_digest: str
    schema: str = 'd11.artifact-draft-phase-count-proof.v2'

    def __post_init__(self):
        from ..model_broker.artifact_phase_count_v1 import (ArtifactPhaseCountRequestV1,
            artifact_phase_counter_policy_from_payload_v1, artifact_phase_count_evidence_from_wire_v1)
        from ..model_broker.provider_billing_receipt_v1 import provider_billing_policy_from_wire_v1
        from ..model_broker.artifact_draft_v1 import _digest
        expected = {item.name for item in fields(ArtifactPhaseCountRequestV1)} - {'provider_request_json','nonce','frozen_at_utc'}
        common = json.loads(self.common_request_json)
        if (self.schema != 'd11.artifact-draft-phase-count-proof.v2' or type(common) is not dict or set(common) != expected
                or common['input_kind'] != 'actual' or canonical_serialize(common) != self.common_request_json
                or self.initial_nonce == self.final_nonce):
            raise ValueError('compact phase proof retains exactly one actual request scope and two independent nonces')
        policy_raw = json.loads(self.counter_policy_json)
        if canonical_serialize(policy_raw) != self.counter_policy_json:
            raise ValueError('compact counter policy bytes changed')
        policy = artifact_phase_counter_policy_from_payload_v1(policy_raw)
        if common['policy_digest'] != policy.digest:
            raise ValueError('compact counter proof changed its actual installed policy commitment')
        if self.billing_policy_json is not None:
            billing_raw = json.loads(self.billing_policy_json)
            if canonical_serialize(billing_raw) != self.billing_policy_json:
                raise ValueError('compact billing policy bytes changed')
            provider_billing_policy_from_wire_v1(billing_raw)
        _digest(self.counted_base_stage_digest)
        for encoded in (self.initial_envelope_json, self.final_envelope_json):
            envelope = json.loads(encoded)
            if type(envelope) is not dict or set(envelope) != {'payload','signature_hex'} or canonical_serialize(envelope) != encoded:
                raise ValueError('compact proof lost its actual signed counter envelope')
            artifact_phase_count_evidence_from_wire_v1(envelope['payload'])
        if len(canonical_serialize(plain_v1(self)).encode()) > 65536:
            raise ValueError('compact count proof exceeds original metadata bound')

    @property
    def digest(self): return canonical_digest(plain_v1(self))


def artifact_draft_phase_count_proof_from_wire_v2(raw):
    if type(raw) is not dict or set(raw) != {item.name for item in fields(ArtifactDraftPhaseCountProofV2)}:
        raise ValueError('closed compact phase count proof fields differ')
    value = ArtifactDraftPhaseCountProofV2(**raw)
    if plain_v1(value) != raw: raise ValueError('noncanonical compact phase count proof')
    return value


def _restore_actual_phase_count_proof_v2(proof, model_request, *, now_utc=None):
    from ..model_broker.artifact_phase_count_v1 import (artifact_phase_counter_policy_from_payload_v1,
        artifact_phase_count_request_from_wire_v1, artifact_phase_provider_request_v1)
    from ..model_broker.provider_billing_receipt_v1 import provider_billing_policy_from_wire_v1
    from ..authority_service.artifact_phase_counter_v1 import require_independent_actual_phase_counts_v1
    policy_raw = json.loads(proof.counter_policy_json)
    policy = artifact_phase_counter_policy_from_payload_v1(policy_raw)
    billing = None if proof.billing_policy_json is None else provider_billing_policy_from_wire_v1(json.loads(proof.billing_policy_json))
    body = canonical_serialize(artifact_phase_provider_request_v1(model_request, billing_policy=billing))
    common = json.loads(proof.common_request_json)
    initial = artifact_phase_count_request_from_wire_v1({**common,'provider_request_json':body,
        'nonce':proof.initial_nonce,'frozen_at_utc':proof.initial_frozen_at_utc})
    final = artifact_phase_count_request_from_wire_v1({**common,'provider_request_json':body,
        'nonce':proof.final_nonce,'frozen_at_utc':proof.final_frozen_at_utc})
    envelopes = (json.loads(proof.initial_envelope_json), json.loads(proof.final_envelope_json))
    verification_now = max(envelope['payload']['counted_at_utc'] for envelope in envelopes) if now_utc is None else now_utc
    evidence = require_independent_actual_phase_counts_v1(policy, initial_request=initial, initial_envelope=envelopes[0],
        final_request=final, final_envelope=envelopes[1], now_utc=verification_now)
    return policy, billing, initial, final, evidence


def _compact_actual_phase_count_pair_v2(count_pair, installed_readers):
    from .d02_artifact_phase_price_v1 import _installed_phase_count_policy_v1
    initial = plain_v1(count_pair.initial_request); final = plain_v1(count_pair.final_request)
    for name in ('provider_request_json','nonce','frozen_at_utc'):
        initial.pop(name); final.pop(name)
    if initial != final: raise ValueError('actual count pair changed frozen request scope instead of only nonce/time')
    policy = _installed_phase_count_policy_v1(installed_readers)
    billing = installed_readers.installed_bundle.provider_billing_policy_v1
    return ArtifactDraftPhaseCountProofV2(canonical_serialize(initial), count_pair.initial_request.nonce,
        count_pair.initial_request.frozen_at_utc, count_pair.final_request.nonce, count_pair.final_request.frozen_at_utc,
        count_pair.initial_envelope_json, count_pair.final_envelope_json, canonical_serialize(plain_v1(policy)),
        None if billing is None else canonical_serialize(plain_v1(billing)), count_pair.frozen_stage_digest)


def _unseal_actual_phase_count_stage_v2(stage):
    raw = json.loads(stage.stage.original_payload_json)
    proof = raw['provenance'].pop('actual_count_proof', None)
    if proof is None: return stage
    return replace(stage, stage=replace(stage.stage, original_payload_json=canonical_serialize(raw), original_digest=canonical_digest(raw)))


def seal_counted_artifact_phase_stage_v2(db, *, frozen_stage, count_pair, installed_readers, now_utc):
    """Add actual durable count facts without altering the counted model request."""
    base = _unseal_actual_phase_count_stage_v2(frozen_stage)
    validate_frozen_artifact_phase_count_stage_in_transaction_v2(db, frozen_stage=base, count_pair=count_pair,
        installed_readers=installed_readers, now_utc=now_utc)
    proof = _compact_actual_phase_count_pair_v2(count_pair, installed_readers)
    _restore_actual_phase_count_proof_v2(proof, base.model_request, now_utc=now_utc)
    raw = json.loads(base.stage.original_payload_json)
    raw['provenance']['actual_count_proof'] = plain_v1(proof)
    return replace(base, stage=replace(base.stage, original_payload_json=canonical_serialize(raw), original_digest=canonical_digest(raw)))


def require_saved_artifact_phase_count_original_v2(db, *, prepared, issuer, now_utc=None, installed_bundle=None):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .natural_reply_job_v2 import _request_from_wire
    if type(prepared) is not ArtifactDraftModelPreparedV2:
        raise TypeError('actual signed phase prepared original required for cold count audit')
    row = _read(db, issuer=issuer, namespace=prepared.namespace, kind='c4_phase_request',
        ref=artifact_draft_model_ids_v2(prepared.selector)['request'])
    if row is None: raise MissingProductionOriginalV1('actual_acquired_phase_request_and_durable_count_proof')
    request_original = artifact_draft_model_from_wire_v2(row[0], ArtifactDraftModelRequestOriginalV2)
    original = read_adopted_domain_operation_v1(db, prepared.namespace, row[1])
    proof = request_original.actual_count_proof
    if (row[1] != prepared.acquire_operation_id or request_original.prepared_digest != prepared.digest
            or original is None or (original['domain'], original['operation_kind']) != ('d11','acquire_artifact_draft_model_v2')
            or original['payload']['provenance']['actual_count_proof'] != plain_v1(proof)
            or original['payload']['provenance']['prepared_digest'] != prepared.digest
            or original['payload']['provenance']['request_digest'] != request_original.request_digest):
        raise ValueError('durable actual count proof has no exact actual acquired W01 request producer')
    model = _request_from_wire(request_original.request_json)
    policy, billing, initial, final, evidence = _restore_actual_phase_count_proof_v2(proof, model, now_utc=now_utc)
    if (initial.namespace != prepared.namespace or initial.installation_id != prepared.installation_id
            or initial.manifest_digest != prepared.manifest_digest or initial.provider_config_digest != prepared.provider_config_digest
            or (initial.owner_grant_ref, initial.owner_grant_revision, initial.owner_grant_digest) !=
                (prepared.owner_guard.grant_ref, prepared.owner_guard.grant_revision, prepared.owner_guard.grant_digest)
            or initial.frozen_material_digest != prepared.frozen_digest
            or tuple(initial.read_versions) != tuple(sorted((version.key.token,version.revision) for version in original['read_versions']))
            or initial.frozen_at_utc != original['payload']['now_utc']):
        raise ValueError('durable phase count changed actual original Owner/Source/read scope/material/time')
    from .artifact_host_dispatch_source_v3 import _bound_state_v3
    from .domain_background_read_v3 import background_history_v3,background_json_loads_v3
    host_source=_bound_state_v3(db)
    for ref, revision, digest in initial.source_versions:
        history = (artifact_model_graph_point_v3(db,('value','valid'),token=ref,revision=revision)
            if host_source is None else background_history_v3(db,ref,revision,columns=('value','valid')))
        if (history is None or history[1] != 1
                or canonical_digest((json.loads if host_source is None else background_json_loads_v3)(history[0])) != digest):
            raise ValueError('durable counter Source commitment lost its actual original historical bytes')
    if installed_bundle is not None:
        configured = installed_bundle.artifact_phase_counter
        configured_billing = installed_bundle.provider_billing_policy_v1
        if configured != policy or configured_billing != billing:
            raise ValueError('actual phase count policy/billing snapshot differs from current installed objects')
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, 1)
    if (canonical_digest(quote) != prepared.quote_digest or max(item.upper_tokens for item in evidence) > quote.ceiling['input_tokens']
            or model.max_output_tokens > quote.ceiling['output_tokens']
            or max(item.upper_tokens for item in evidence) + model.max_output_tokens > quote.ceiling['model_tokens']):
        raise ValueError('durable actual count exceeded its original signed reserved quote')
    return proof


@dataclass(frozen=True, slots=True)
class ArtifactNoDispatchCancellationBasisV1:
    namespace: NamespaceId
    job_id: str
    prepared_digest: str
    original_deadline_utc: str
    kind: str
    cause_ref: str
    cause_revision: int
    cause_digest: str
    observed_at_utc: float
    schema: str = "d11.artifact-no-dispatch-cancellation-basis.v1"

    def __post_init__(self):
        from .d11_offline_originals_v1 import _utc
        if (self.schema != "d11.artifact-no-dispatch-cancellation-basis.v1" or type(self.namespace) is not NamespaceId
                or self.kind not in {"original_model_deadline_expired","actual_core_goal_cancel_requested"}):
            raise ValueError("closed actual Artifact model cancellation basis required")
        import math
        deadline = _utc(self.original_deadline_utc).timestamp()
        if type(self.observed_at_utc) not in (int, float) or not math.isfinite(self.observed_at_utc) or self.kind=="original_model_deadline_expired" and self.observed_at_utc < deadline:
            raise ValueError("actual qualified clock must observe original model deadline expiry")
        if len(self.prepared_digest) != 64 or len(self.cause_digest) != 64 or self.cause_revision < 1:
            raise ValueError("actual signed preparation/cancellation commitments required")


@dataclass(frozen=True, slots=True)
class ArtifactModelNoDispatchSettlementV1:
    namespace: NamespaceId
    selector: object
    prepared_digest: str
    witness_json: str
    witness_digest: str
    cancellation: ArtifactNoDispatchCancellationBasisV1
    cost_commit: object
    source_refs: tuple[str, ...]
    before_job_digest: str
    after_job_digest: str
    original_ref: str
    schema: str = "d11.artifact-model-no-dispatch-settlement.v1"


def artifact_model_no_dispatch_original_ref_v1(prepared):
    return "artifact-model-no-dispatch:" + canonical_digest((prepared.namespace, prepared.job_id, prepared.digest))


def derive_artifact_no_dispatch_cancellation_basis_v1(db, *, prepared, issuer, now):
    """Expiry uses the signed financial original and actual qualified clock."""
    from .d11_offline_originals_v1 import _utc
    task = prepared.selector.task if type(prepared.selector) is ArtifactDraftPhaseSelectorV2 else prepared.selector
    if now < _utc(prepared.deadline_utc).timestamp():
        raise MissingProductionOriginalV1("registered_metadata_only_artifact_cancellation_original_producer")
    return ArtifactNoDispatchCancellationBasisV1(task.namespace, prepared.job_id, prepared.digest, prepared.deadline_utc,
        "original_model_deadline_expired", prepared.job_id, 1, prepared.digest, now)


def require_artifact_no_dispatch_cancellation_basis_v1(db, *, runtime, witness, basis, now):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .artifact_no_dispatch_metadata_read_v1 import require_bound_artifact_no_dispatch_financial_snapshot_v1
    from .d08_personal_plan_v1 import artifact_phase_action_keys_v2,artifact_draft_action_keys_v1
    originals=require_bound_artifact_no_dispatch_financial_snapshot_v1(db,runtime=runtime,witness=witness,basis=basis,now=now)
    prepared=originals.prepared
    selector=prepared.selector
    phase=prepared.schema=="d11.artifact-draft-phase-model-prepared.v2"
    if phase and not selector.generation:return prepared
    key=(artifact_phase_action_keys_v2(selector)[0] if phase else artifact_draft_action_keys_v1(basis.namespace,
        c02_operation_id=selector.c02_operation_id,root_registration_ref=selector.root_registration_ref)[0])
    if _artifact_receipt_sql_v1(db,"SELECT revision FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token,*basis.namespace.as_tuple)).fetchone() is not None:
        raise MissingProductionOriginalV1("pre_action_c4_no_dispatch_cannot_replace_an_actual_action")
    return prepared


def stage_artifact_no_dispatch_job_v1(db, *, runtime, witness, basis, now):
    from dataclasses import replace
    from .jobs import _save_job,_record_operation
    from .d11_types import job_graph_write
    from .artifact_no_dispatch_metadata_read_v1 import require_bound_artifact_no_dispatch_job_v1
    prepared=require_artifact_no_dispatch_cancellation_basis_v1(db,runtime=runtime,witness=witness,basis=basis,now=now)
    before=require_bound_artifact_no_dispatch_job_v1(db,runtime=runtime,witness=witness,basis=basis,now=now)
    if (before.phase!="running" or before.fence!=witness.request.intent.worker_fence
            or before.lease_holder!=prepared.worker_subject or before.result_ref is not None
            or before.operation_id!=prepared.operation_id):
        raise MissingProductionOriginalV1("actual_acquired_original_c4_job_before_unsent_cancellation")
    cancellation_id="c4-no-dispatch-cancel:"+canonical_digest((prepared.namespace,prepared.job_id,witness.digest))
    # Fixed original cancellation matches cancel_job/transition_job semantics:
    # advance the held fence, then acknowledge cancellation without a result.
    after=replace(before,phase="cancelled",cancel_epoch=before.cancel_epoch+1,fence=before.fence+1,
        lease_holder=None,lease_expires_utc=None,wake_condition=None,result_ref=None)
    _save_job(db,after)
    _record_operation(db,after,cancellation_id,"cancel",canonical_digest((witness.digest,plain_v1(basis))))
    return prepared,before,after,job_graph_write(after)


def record_artifact_no_dispatch_after_cost_cas_v1(db, *, runtime, staged_job, witness, basis, commit):
    from .model_cost_settlement import OriginalModelNoDispatchCostCommitV1
    from ..authority_service.v2_model_egress_wire import to_wire
    if not db.in_transaction or type(commit) is not OriginalModelNoDispatchCostCommitV1 or commit.status != "committed":
        raise ValueError("actual same C4 no-dispatch cost/job graph CAS required")
    prepared, before, after, job_write = staged_job
    if (commit.call_id != prepared.call_id or commit.quote_id != prepared.quote_id or commit.quote_version != 1
            or commit.witness_digest != witness.digest):
        raise ValueError("C4 zero settlement changed the actual original witness/quote")
    ref = artifact_model_no_dispatch_original_ref_v1(prepared)
    value = ArtifactModelNoDispatchSettlementV1(prepared.namespace, prepared.selector, prepared.digest,
        canonical_serialize(to_wire(witness)), witness.digest, basis, commit, tuple(witness.request.intent.source_refs),
        canonical_digest(plain_v1(before)), canonical_digest(plain_v1(after)), ref)
    return _record(db, issuer=runtime.issuer, namespace=prepared.namespace,
        kind="c4_phase_no_dispatch" if _artifact_model_phase_v2(prepared) else "c4_no_dispatch",
        ref=ref, operation_id=commit.operation_id, value=value)



def decode_artifact_model_no_dispatch_v1(raw):
    from dataclasses import fields
    from .model_cost_settlement import OriginalModelNoDispatchCostCommitV1
    from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1, artifact_draft_from_wire_v2
    from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
    from ..authority_service.v2_model_egress_wire import from_wire, to_wire
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ArtifactModelNoDispatchSettlementV1)}:
        raise ValueError("closed C4 no-dispatch original fields differ")
    data = dict(raw); data["namespace"] = NamespaceId(**data["namespace"])
    phase = data["selector"].get("schema") == "d11.artifact-draft-phase-selector.v2"
    data["selector"] = (artifact_draft_from_wire_v2(data["selector"], ArtifactDraftPhaseSelectorV2) if phase else
        artifact_draft_from_wire_v1(data["selector"], ArtifactDraftTaskSelectorV1))
    data["cancellation"] = ArtifactNoDispatchCancellationBasisV1(**{
        **data["cancellation"], "namespace": NamespaceId(**data["cancellation"]["namespace"])})
    data["cost_commit"] = OriginalModelNoDispatchCostCommitV1(**data["cost_commit"])
    data["source_refs"] = tuple(data["source_refs"])
    value = ArtifactModelNoDispatchSettlementV1(**data)
    witness_raw = json.loads(value.witness_json); witness = from_wire(witness_raw, ModelNoDispatchWitnessV1)
    commit = value.cost_commit
    if (plain_v1(value) != raw or canonical_serialize(witness_raw) != value.witness_json
            or to_wire(witness) != witness_raw or value.witness_digest != witness.digest
            or value.cancellation.prepared_digest != value.prepared_digest
            or value.cancellation.original_deadline_utc != witness.request.requested_deadline_utc
            or value.cancellation.cause_ref != witness.request.requested_cancel_cause_ref
            or tuple(witness.request.intent.source_refs) != value.source_refs
            or commit.schema != "sylanne.d11.original-model-no-dispatch-cost-commit.v1"
            or commit.status != "committed" or commit.witness_digest != witness.digest
            or commit.call_id != witness.request.intent.call_id or commit.quote_version != 1
            or value.namespace != value.cancellation.namespace):
        raise ValueError("actual C4 no-dispatch settlement changed its independent Core/local identities")
    return value


def read_artifact_model_no_dispatch_settlement_v1(db, *, prepared, issuer):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
    from ..authority_service.v2_model_egress_wire import from_wire
    from .d11_types import RuntimeCostSettlement, reconcile_runtime_write, job_graph_write
    from ..graph_types import GraphWrite
    from .jobs import get_job
    ref = artifact_model_no_dispatch_original_ref_v1(prepared)
    kind = "c4_phase_no_dispatch" if _artifact_model_phase_v2(prepared) else "c4_no_dispatch"
    saved = _read(db, issuer=issuer, namespace=prepared.namespace, kind=kind, ref=ref)
    if saved is None: return None
    value = decode_artifact_model_no_dispatch_v1(saved[0])
    witness = from_wire(background_json_loads_v3(value.witness_json), ModelNoDispatchWitnessV1)
    witness.require_signature_v1(issuer._signer)
    commit = value.cost_commit
    if (value.selector != prepared.selector or value.prepared_digest != prepared.digest
            or value.original_ref != ref or saved[1] != commit.operation_id
            or commit.operation_id != original_model_no_dispatch_cost_operation_id_v1(prepared.namespace, prepared.call_id)):
        raise ValueError("C4 no-dispatch record lost its exact actual original producer")
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    receipt_row = _producer_original_point_v3(db, table="graph_bundle_operations", columns=("commit_seq", "receipt_json"),
        key_columns=("bot", "persona", "operation_id"), key=(*prepared.namespace.as_tuple, commit.operation_id),
        legacy_reader=lambda: _artifact_receipt_sql_v1(db,"SELECT commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*prepared.namespace.as_tuple, commit.operation_id)).fetchone())
    from .domain_background_read_v3 import background_json_loads_v3
    receipt = None if receipt_row is None else background_json_loads_v3(receipt_row[1])
    if (receipt is None or receipt_row[0] != commit.commit_seq or receipt["original_model_no_dispatch_cost"] != plain_v1(commit)
            or receipt["no_dispatch_witness_digest"] != witness.digest):
        raise ValueError("C4 no-dispatch settlement lost actual once cost CAS")
    job = get_job(db, prepared.job_id)
    if (job.phase != "cancelled" or job.result_ref is not None or canonical_digest(plain_v1(job)) != value.after_job_digest
            or job.operation_id != prepared.operation_id):
        raise ValueError("C4 no-dispatch signed original differs from its actual cancelled job")
    cost_key = AtomKey.from_token(commit.cost_ref)
    cost_row = _producer_original_point_v3(db, table="graph_atoms", columns=("value", "valid"),
        key_columns=("token", "bot", "persona"), key=(cost_key.token, *prepared.namespace.as_tuple),
        legacy_reader=lambda: _artifact_receipt_sql_v1(db,"SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (cost_key.token, *prepared.namespace.as_tuple)).fetchone())
    if cost_row is None or cost_row[1] != 1:
        raise ValueError("C4 no-dispatch cost graph member absent")
    cost_value = background_json_loads_v3(cost_row[0])
    cost = RuntimeCostSettlement(**cost_value)
    reconcile_runtime_write(db, GraphWrite(cost_key, cost_value))
    projection = job_graph_write(job)
    reconcile_runtime_write(db, projection)
    if (cost.budget_receipt_digest != commit.budget_receipt_digest or cost.status != "settled"
            or cost.actual != {unit: 0 for unit, _ in witness.request.intent.budget_ceiling}
            or cost.unconfirmed or cost.lease_id != witness.request.intent.budget_lease_id):
        raise ValueError("C4 no-dispatch zero settlement differs from its actual original budget receipt")
    return value


def original_model_no_dispatch_cost_operation_id_v1(namespace, call_id):
    from .model_cost_settlement import original_model_cost_operation_id_v1
    return original_model_cost_operation_id_v1(namespace, call_id)


async def reconcile_original_artifact_no_dispatch_v1(runtime, *, prepared, intent):
    """Recover this original unsent call; no new call, Source, fee or attempt."""
    from ..authority_service.v2_model_egress_contract import ModelNoDispatchClosureRequestV1
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:
        raise TypeError("actual installed original C4 controller required")
    try:
        basis = await runtime.worker.call(lambda graph: runtime._read_original_no_dispatch_basis_v1(graph, prepared))
    except MissingProductionOriginalV1:
        return None
    prior = runtime._no_dispatch_witnesses_v1.get(prepared.job_id)
    if prior is None:
        recovery, original_permit = await runtime.authority_client.model_recover_fenced_v1(runtime.bundle, runtime.client_grant, intent=intent)
        if recovery.intent != intent:
            raise ValueError("C4 cancellation recovery changed its actual original Core call")
        if recovery.state != "prepared":
            return None
        anchor = await runtime.worker.call(lambda graph: graph._GraphCoordinator__content_fence_v2.current_anchor(
            namespace=prepared.namespace, authority_namespace=intent.namespace))
        closure = ModelNoDispatchClosureRequestV1(intent, runtime.bundle.installation_policy.installation_id,
            runtime.client_grant.administrator_holder, anchor, prepared.deadline_utc, basis.cause_ref)
        witness = await runtime.authority_client.model_no_dispatch_witness_v1(
            runtime.bundle, runtime.client_grant, closure_request=closure)
        witness.require_signature_v1(runtime.issuer._signer)
        if (witness.request.intent != intent or witness.request.identity_digest != closure.identity_digest
                or witness.original_permit != original_permit):
            raise ValueError("actual Core no-dispatch response changed its original C4 closure")
        runtime._no_dispatch_witnesses_v1[prepared.job_id] = witness, basis
    try:
        return await runtime.worker.call(lambda graph: graph._commit_original_artifact_no_dispatch_cost_v1(
            runtime.bootstrap, prepared.namespace, intent, quote_id=prepared.quote_id, quote_version=1,
            work_kind="artifact_draft_v1"))
    finally:
        runtime._no_dispatch_witnesses_v1.pop(prepared.job_id, None)


async def resume_original_artifact_no_dispatch_v1(runtime):
    """Cold convergence reads original calls after Source/Owner withdrawal."""
    from .d11_offline_originals_v1 import _utc
    from .first_ingress_v2 import trusted_upper
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:
        raise TypeError("actual installed C4 controller required")
    now = await runtime.worker.call(lambda graph: trusted_upper(
        graph._GraphCoordinator__content_fence_v2.read_ingress_clock(runtime.bundle.ingress_clock)))
    after, next_deadline = "", None
    while not runtime.context._artifact_draft_stopping_v1:
        item = await runtime.worker.call(lambda graph: runtime._read_next_original_no_dispatch_task_v1(graph, after=after))
        if item is None: return None if next_deadline is None else max(0.001, next_deadline - now)
        after, task = item
        if task is not None:
            prepared, intent = task
            deadline = _utc(prepared.deadline_utc).timestamp()
            if now < deadline:
                next_deadline = deadline if next_deadline is None else min(next_deadline, deadline)
            else:
                await reconcile_original_artifact_no_dispatch_v1(runtime, prepared=prepared, intent=intent)
    return None

