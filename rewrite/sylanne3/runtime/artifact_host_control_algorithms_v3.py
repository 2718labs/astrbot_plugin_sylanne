"""Fixed Artifact control algorithms on one actual current Source Work.

Metadata projections never impersonate Frozen/Source DTOs. Non-generation
verification retains its existing complete semantic checks after Source EOF.
"""
from dataclasses import asdict,dataclass,replace
from datetime import datetime
from ..authority_service.contract import AuthorityUnavailable
import json
from ..runtime_contracts import canonical_digest,canonical_serialize
from .domain_background_read_v3 import background_json_loads_v3
from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3


def artifact_control_metadata_paths_v3(profile,path):
    if not path:return True
    if profile=='control_target_mode':
        fields=(('schema',),('selector',),('task_source_ref',),('current_self_ref',),('current_self_digest',),
            ('root_registration_digest',),('target','mode'),('source_read_versions',),('source_query_epoch',),
            ('access_epoch',),('delete_epoch',),('deadline_utc',),('prior_content',),
            ('postcondition_contract_ref',),('postcondition_contract_digest',))
        return any(path[:len(prefix)]==prefix or prefix[:len(path)]==path for prefix in fields)
    if profile=='control_phase_status':
        fields={'schema','namespace','selector','prepared_digest','request_digest','request','terminal_receipt',
            'authority_id','authority_namespace','operation_id','call_id','job_id','quote_id','quote_version',
            'intent_digest','binding_digest','subject','worker_fence','provider_id','model_id','provider_config_digest',
            'budget_lease_id','budget_reservation_operation_id','budget_reservation_digest','budget_ceiling',
            'source_refs','source_revisions','access_revisions','owner_grant_revision','owner_grant_digest',
            'authority_activation_generation','authority_revocation_epoch','authority_deletion_seq','authority_execution_seq',
            'graph_revision','graph_epoch','access_epoch','delete_epoch','max_output_tokens','acquire_operation_id',
            'terminal_receipt_digest','budget_receipt_digest','commit_seq','cost_ref','status',
            'content','task_source','paid_original_ref','paid_original_digest','result_original_ref','result_original_digest',
            'model_terminal_digest','activity_scope_ref','activity_scope_digest','original_deadline_utc',
            'algorithm_build_digest','postcondition_build_digest','adoption_operation_id','extent','full_extent',
            'extent_original_ref','extent_original_digest'}
        return path[0]in fields or path[0]=='observation'and(len(path)==1 or path[1]=='status')
    raise ValueError('unregistered Artifact control metadata profile')


def _read_phase_target_metadata_v3(state,prepared):
    from ..authority_service.contract import AuthorityUnavailable
    from ..domains.d01.production_operations_v1 import plain_v1
    value=state.signed_metadata_v3('c4_phase_frozen',prepared.frozen_ref,'control_target_mode')
    if(value is None or value['selector']!=plain_v1(prepared.selector)
            or state.signed_metadata_digest_v3('c4_phase_frozen',prepared.frozen_ref,'control_target_mode')!=prepared.frozen_digest
            or value['task_source_ref']not in state.root_source_metadata
            or value['deadline_utc']>datetime.fromisoformat(prepared.deadline_utc.replace('Z','+00:00')).timestamp()):
        raise AuthorityUnavailable('Artifact control target lost its exact signed prepared/frozen binding')
    return value


def _read_phase_status_metadata_v3(state,phase,prepared,ids):
    from ..authority_service.contract import AuthorityUnavailable
    from ..domains.d01.production_operations_v1 import plain_v1
    from .model_cost_settlement import original_model_cost_operation_id_v1
    values={name:state.signed_metadata_v3('c4_phase_'+kind,ids[name],'control_phase_status')
        for kind,name in (('request','request'),('call','call'),('paid','paid'),('result','result'),('adopted','adopt'))}
    if prepared is None:
        if any(value is not None for value in values.values()):
            raise AuthorityUnavailable('Artifact control phase state has no original signed preparation')
        return values
    request,call,paid,result,adopted=(values[name]for name in ('request','call','paid','result','adopt'))
    if request is not None and(request['schema']!='d11.artifact-draft-phase-model-request.v2'
            or request['prepared_digest']!=prepared.digest):
        raise AuthorityUnavailable('Artifact control acquired request crossed its actual preparation')
    if call is not None and(request is None or call['job_id']!=prepared.job_id or call['call_id']!=prepared.call_id
            or call['operation_id']!=prepared.acquire_operation_id or call['acquire_operation_id']!=prepared.acquire_operation_id
            or call['binding_digest']!=prepared.digest or call['request_digest']!=request['request_digest']
            or call['budget_lease_id']!=prepared.parent_budget_lease_ref):
        raise AuthorityUnavailable('Artifact control call lost its exact acquired request/job/Root')
    if paid is not None and(call is None or paid['status']!='committed' or paid['call_id']!=prepared.call_id
            or paid['quote_id']!=prepared.quote_id or paid['quote_version']!=1
            or paid['operation_id']!=original_model_cost_operation_id_v1(prepared.namespace,prepared.call_id)):
        raise AuthorityUnavailable('Artifact control paid state lost its actual original cost commit')
    if result is not None and(paid is None or result['request']['selector']!=plain_v1(phase)
            or result['request']['binding_digest']!=prepared.digest
            or (result['request']['namespace'],result['request']['installation_id'],result['request']['job_id'],
                result['request']['acquire_operation_id'],result['request']['original_operation_id'],
                result['request']['call_id'],result['request']['model_request_digest'],result['request']['consumer_operation_id'])!=(
                plain_v1(prepared.namespace),prepared.installation_id,prepared.job_id,prepared.acquire_operation_id,
                prepared.operation_id,prepared.call_id,request['request_digest'],ids['adopt'])
            or result['terminal_receipt']['installation_id']!=prepared.installation_id
            or result['terminal_receipt']['call_id']!=prepared.call_id
            or result['terminal_receipt']['request_digest']!=request['request_digest']
            or result['observation']['status']!='completed'
            or canonical_digest(result['terminal_receipt'])!=paid['terminal_receipt_digest']):
        raise AuthorityUnavailable('Artifact control result lost its actual paid terminal/request')
    if adopted is not None and(result is None or adopted['selector']!=plain_v1(phase)
            or adopted['prepared_digest']!=prepared.digest or adopted['paid_original_ref']!=ids['paid']
            or adopted['result_original_ref']!=ids['result']
            or adopted['paid_original_digest']!=state.signed_metadata_digest_v3('c4_phase_paid',ids['paid'],'control_phase_status')
            or adopted['result_original_digest']!=state.signed_metadata_digest_v3('c4_phase_result',ids['result'],'control_phase_status')):
        raise AuthorityUnavailable('Artifact control adoption lost its real paid/result predecessor EOF')
    return values



@dataclass(frozen=True,slots=True)
class ArtifactControlCommandV3:
    operation_kind:str
    request:object
    after:str='return'
    preparation_task:object=None


@dataclass(frozen=True,slots=True)
class ArtifactControlValueV3:
    value:object


@dataclass(frozen=True,slots=True)
class ArtifactControlNextV3:
    entry_kind:str
    stage:str
    arguments:tuple=()
    completed_receipts:tuple|None=None


_ENTRY_FIELDS_V3={'read_current_ingress_recall_resume_v1':(), 'advance_current_post_c02_ingress_c04_v4':(), 'prepare_post_c02_artifact_task_scope_v1': (), 'prepare_post_c02_foreground_cycle_v1': (), 'prepare_source_note_foreground_cycle_v1': ('authorization_original_ref',), 'prepare_selected_source_note_action_v2': ('decision_ref', 'prepared_candidates_operation_id'), 'acquire_post_c02_foreground_cycle_v1': (), '_read_post_c02_foreground_cycle_v1': (), 'checkpoint_post_c02_foreground_wait_v1': (), 'read_current_post_c02_foreground_mode_v1': (), 'read_current_post_c02_artifact_draft_resume_v1': (), 'run_current_post_c02_artifact_task_setup_v1': ('operation_kind',), 'read_current_post_c02_artifact_task_choice_material_v3': ('complete',), 'prepare_current_post_c02_artifact_task_structure_v3': (), 'read_current_post_c02_artifact_method_prerequisites_v1': ('material',), 'run_current_post_c02_artifact_preparation_step_v1': ('operation_kind', 'request'), 'finish_current_artifact_receipt_cycle_v1': (), 'prepare_current_artifact_completion_source_v1': (), 'run_current_post_c02_artifact_phase_operation_v2': ('operation_kind',), 'begin_current_artifact_method_group_v3': ('prepared_candidates_operation_id',), 'read_current_artifact_phase_observation_progress_v3': (), 'checkpoint_current_artifact_phase_v2': (), 'run_current_post_c02_artifact_method_final_operation_v2': ('operation_kind',), 'read_current_artifact_method_finalization_progress_v2': (), 'read_current_completed_artifact_method_v2': (), 'prepare_current_post_c02_recall_need_v1': (), 'run_current_post_c02_task_no_search_v1': (), 'run_current_post_c02_ingress_recall_model_operation_v1': ('operation_kind',), 'select_current_post_c02_ingress_recall_seed_v1': (), 'run_current_post_c02_ingress_c04_operation_v4': ('operation_kind',), 'run_current_post_c02_artifact_draft_operation_v1': ('operation_kind',)}

_ENTRY_STAGES_V3=frozenset({'start','cycle_root','structure_0','structure_1','structure_2',
    'draft_wait','draft_select','draft_prepare','draft_role','draft_action','post_result','wake_acquire'})
_AFTER_STAGES_V3=frozenset({'return','cycle_root','structure_0','structure_1','structure_2',
    'draft_select','draft_prepare','draft_role','wake_acquire','wake_finish','recall_need','no_search','c03_selection','completion_source'})


def require_artifact_entry_descriptor_v3(selector):
    from .artifact_host_control_metadata_v3 import ArtifactEntryPrepareSelectorV3
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    if(type(selector)is not ArtifactEntryPrepareSelectorV3 or selector.entry_kind not in _ENTRY_FIELDS_V3
            or selector.stage not in _ENTRY_STAGES_V3 or type(selector.arguments)is not tuple
            or len(selector.arguments)>8 or len(dict(selector.arguments))!=len(selector.arguments)
            or set(dict(selector.arguments))!=set(_ENTRY_FIELDS_V3[selector.entry_kind])):
        raise ValueError('Artifact control entry changed its closed registered recipe or exact arguments')
    source=AtomKey.from_token(selector.source_ref)
    if source.type_name!='memory.source'or NamespaceId.from_key(source)!=selector.namespace:
        raise ValueError('Artifact entry Source crossed its actual namespace')
    if type(selector.completed_receipts)is not tuple or len(selector.completed_receipts)>6:
        raise ValueError('Artifact control continuation exceeded its fixed completed-stage receipts')
    for operation,digest in selector.completed_receipts:
        if type(operation)is not str or not operation or type(digest)is not str or len(digest)!=64:
            raise ValueError('Artifact completed stage lost its actual receipt locator')
    return selector


def require_artifact_post_commit_descriptor_v3(selector):
    from .artifact_host_control_metadata_v3 import ArtifactPostCommitReadSelectorV3
    from ..graph_types import GraphVersion
    from ..runtime_contracts import NamespaceId
    from math import isfinite
    if(type(selector)is not ArtifactPostCommitReadSelectorV3 or selector.entry_kind not in _ENTRY_FIELDS_V3
            or selector.stage not in _AFTER_STAGES_V3 or type(selector.arguments)is not tuple
            or type(selector.completed_receipts)is not tuple or len(selector.completed_receipts)>6
            or type(selector.business_deadline_utc)not in(int,float)or not isfinite(selector.business_deadline_utc)):
        raise ValueError('Artifact receipt continuation changed its closed original stage')
    for digest in(selector.request_digest,selector.receipt_digest,selector.command_digest):
        if type(digest)is not str or len(digest)!=64 or any(c not in '0123456789abcdef'for c in digest):
            raise ValueError('Artifact receipt requires actual immutable request and W01 commitments')
    if(type(selector.write_versions)is not tuple or len(selector.write_versions)>1024
            or any(type(v)is not GraphVersion or NamespaceId.from_key(v.key)!=selector.namespace for v in selector.write_versions)):
        raise ValueError('Artifact receipt changed its actual finite namespace write set')
    from .domain_production_registry_v1 import installed_operation_v1
    installed_operation_v1(selector.operation_kind)
    return selector


def _control_original_receipt_v3(reader,state,operation_id):
    from ..authority_service.contract import AuthorityUnavailable
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    db=reader.db;ns=reader.namespace
    original=read_adopted_domain_operation_v1(db,ns,operation_id)
    if original is None:raise AuthorityUnavailable('Artifact control lacks its actual committed Domain Original')
    roots=tuple(v.key.token for v in original['read_versions']if v.key.type_name=='memory.source')
    if reader.selector.source_ref not in roots or not set(roots)<=set(state.root_source_metadata):
        raise AuthorityUnavailable('Artifact receipt readset lacks its own complete current Source qualification')
    if original['payload']['authority']['actor']!=reader.current_self.self_entity_ref:
        raise AuthorityUnavailable('Artifact receipt belongs to another actual current Self actor')
    saved=_producer_original_point_v3(db,table='graph_owner_domain_attempts_v3',columns=('request_digest','receipt_json'),
        key_columns=('bot','persona','operation_id'),key=(*ns.as_tuple,operation_id),
        legacy_reader=lambda:(_ for _ in ()).throw(AuthorityUnavailable('Actual control receipt cannot use a legacy attachment')))
    if saved is None or saved[1]is None:raise AuthorityUnavailable('Artifact receipt has no actual saved mechanical W01 result')
    result=background_json_loads_v3(saved[1])
    if(result.get('schema')!='sylanne.domain-production-receipt.v1'
            or result.get('original_digest')!=original['original_digest']
            or result.get('receipt_digest')!=canonical_digest(original['receipt'])
            or result.get('operation_id')!=operation_id):
        raise AuthorityUnavailable('Artifact receipt differs from its actual original W01 and typed commit')
    return result,original,saved[0]


def read_artifact_cycle_receipt_v3(reader,state):
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .jobs import get_job
    from ..authority_service.contract import AuthorityUnavailable
    db=reader.db;ns=reader.namespace;q=reader.selector
    with reader.store._lock:
        db.execute('BEGIN')
        try:
            job=get_job(db,foreground_cycle_ids_v1(ns,q.c02_operation_id)[1])
            result,original,_=_control_original_receipt_v3(reader,state,job.operation_id)
            if original['operation_kind']not in {'create_foreground_cycle','create_foreground_cycle_v2','create_source_note_foreground_cycle_v1'}:
                raise AuthorityUnavailable('Artifact cycle lost its exact immutable creation producer')
            return result
        finally:db.rollback()


def read_artifact_foreground_selector_v3(reader,state,*,operation_kind=None,request=None):
    from ..graph_coordinator import UnavailableGuard,AuthorityDenied
    self=reader.graph
    bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    selected=state.selector
    c02_operation_id,source_ref=selected.c02_operation_id,selected.source_ref
    if operation_kind is None:operation_kind,request=selected.operation_kind,selected.request
    """Selectors come from actual committed input/job/root facts, without issuing authority."""
    self._admin(bootstrap)
    from ..host.authority_profile import AdminInstallationBundle
    from ..authority_service.current_foreground_activity_v1 import ForegroundActivityRequestV1, foreground_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, _adopted_c02_v1
    from .jobs import get_job
    from .d11_types import runtime_job_key

    if (type(installed_bundle) is not AdminInstallationBundle
            or self._GraphCoordinator__d04_installed_joint_assembly is None
            or self._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not installed_bundle):
        raise UnavailableGuard("foreground caller needs the actual installed production bundle; HOLD")
    policy, operation = installed_bundle.installation_policy, installed_operation_v1(operation_kind)
    ns = policy.namespace
    policy_now = None
    if operation_kind == "input:register_artifact_phase_postcondition_policy_v1":
        from .first_ingress_v2 import trusted_upper
        policy_now = trusted_upper(self._GraphCoordinator__content_fence_v2.read_ingress_clock(self._GraphCoordinator__scene_clock_policy))
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            root = state.seed.budget.grant
            if root != policy.root_grant or "d11.foreground_cycle.v1" not in root.allowed_work_kinds:
                raise UnavailableGuard("actual installed root has no foreground activity allowance; HOLD")
            _adopted_c02_v1(db, ns, c02_operation_id)
            source_metadata = state.source_metadata_v3(source_ref)
            if source_metadata['source_id']!=state.seed.identity[0]:
                raise UnavailableGuard("foreground cue differs from its actual committed ingress identity; HOLD")
            identity={'visibility':state.seed.identity[5],'operation_id':state.seed.ingress_op,
                'conversation_ref':state.audiences[0]}
            if identity["visibility"] != "private":
                raise UnavailableGuard("foreground private reply cycle has another original audience; HOLD")
            activity_id, job_id = foreground_cycle_ids_v1(ns, c02_operation_id)
            key = runtime_job_key(*ns.as_tuple, activity_id, job_id)
            head = state.control_point_v3('graph_atoms',('revision',),('token',),(key.token,))
            revision = 0 if head is None else head[0]
            job = None if head is None else get_job(db, job_id)
            archived = state.control_point_v3('graph_first_ingress_c02_committed_seals_v2',('seal_json',),('bot','persona','operation_id'),(*ns.as_tuple,c02_operation_id))
            if archived is None:
                raise UnavailableGuard("foreground input lacks its actual immutable C02 deadline; HOLD")
            seal = background_json_loads_v3(archived[0])
            original_deadline = min(root.valid_until_utc, seal["root_grant_valid_until_utc"], seal["business_deadline_utc"])
            deadline = original_deadline if job is None else datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp()
            root_ref = None
            purpose = "context"
            if operation_kind == "create_source_note_foreground_cycle_v1":
                from .source_note_foreground_v1 import CreateSourceNoteForegroundCycleRequestV1
                from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1, NOTE_WORK_KIND
                if type(request) is not CreateSourceNoteForegroundCycleRequestV1 or job is not None:
                    raise UnavailableGuard("SourceNote initial responsibility cannot replace an existing foreground cycle; HOLD")
                saved_note = read_source_note_task_authorization_v1(db, namespace=ns,
                    original_ref=request.authorization_original_ref, issuer=self._GraphCoordinator__d11_issuer)
                if saved_note is None:
                    raise UnavailableGuard("actual signed Owner SourceNote task authorization is missing; HOLD")
                note = saved_note[0]
                if (note.request.c02_operation_id, note.request.source_ref, note.parent_budget_lease_ref) != (
                        c02_operation_id, source_ref, root.lease_id) or NOTE_WORK_KIND not in root.allowed_work_kinds:
                    raise UnavailableGuard("SourceNote task differs from its actual C02/cue/original allowed root; HOLD")
                deadline = min(note.original_deadline_utc, original_deadline)
                if deadline != note.original_deadline_utc:
                    raise UnavailableGuard("SourceNote authorization exceeds the original sealed C02 deadline; HOLD")
                purpose = "consolidation"
            elif operation_kind == "create_foreground_cycle_v2":
                from .foreground_cycle_v1 import CreateForegroundCycleRequestV2
                from .c09_life_originals_v1 import read_foreground_post_c02_cause_original_v1
                from .d11_life_preparation_v1 import _read
                from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
                if type(request) is not CreateForegroundCycleRequestV2 or installed_bundle.foreground is None:
                    raise UnavailableGuard("explicit installed foreground responsibility is not configured; HOLD")
                root_ref = request.draft_root_registration_ref
                if root_ref is None:
                    natural = installed_bundle.foreground.deadline_policy.natural
                    if natural is None:
                        raise UnavailableGuard("explicit natural causal window is not configured; HOLD")
                    cause = read_foreground_post_c02_cause_original_v1(db, namespace=ns, issuer=self._GraphCoordinator__d11_issuer,
                        original_ref=request.cause_original_ref)
                    deadline = min(cause.cause_frozen_at_utc + natural.window_seconds, root.valid_until_utc)
                else:
                    signed = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind="draft_root_capability", ref=root_ref)
                    if signed is None:
                        raise UnavailableGuard("actual adopted draft root setup is missing; HOLD")
                    capability_root = draft_from_wire_v1(signed[0], DraftRootCapabilityV1)
                    deadline = min(datetime.fromisoformat(capability_root.valid_until_utc.replace("Z", "+00:00")).timestamp(), root.valid_until_utc)
                    purpose = "consolidation"
            elif operation_kind == "derive_ingress_artifact_task_scope_v1":
                from .ingress_artifact_task_scope_v1 import standing_artifact_policy_v1
                standing=standing_artifact_policy_v1(installed_bundle)
                purpose="consolidation"
                deadline=min(original_deadline,source_metadata['recorded_at']+standing.root_window_seconds,standing.valid_until_utc)
                from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
                intent=read_c1_task_intent_original_v1(db,namespace=ns,c02_operation_id=c02_operation_id,issuer=self._GraphCoordinator__d11_issuer)
                if intent is not None and intent.intent.kind=="continue":
                    tool=installed_bundle.artifact_draft.tool_scope
                    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4,select_paired_tool_scope_v3
                    if type(installed_bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:
                        tool=select_paired_tool_scope_v3(installed_bundle.artifact_draft,intent.intent.filename)
                    targets=[obj for obj in state.active_task_objective_metadata_v3()
                        if (obj['root_resource_id'],obj['filename'])==(tool.resource_id,tool.filename)]
                    if len(targets)!=1:raise UnavailableGuard("unique actual unfinished task is absent; HOLD")
                    from ..host.authority_profile import AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3
                    if type(standing) not in {AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3}:
                        deadline=min(deadline,targets[0]['valid_until_utc'])
                    # This selector issues no authorization. Approved-scope candidates
                    # must subsequently pass the Authority's current Owner/Source/
                    # waiting-checkpoint and prospective generation qualification.
            elif job is not None:
                from .foreground_cycle_v1 import ForegroundCycleContinuationV2, foreground_cycle_from_wire_v1
                from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
                from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
                active_continuation = foreground_cycle_from_wire_v1(job.continuation)
                if type(active_continuation) in {ForegroundCycleContinuationV2, ForegroundSourceNoteContinuationV1}:
                    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=ns, job=job, issuer=self._GraphCoordinator__d11_issuer)
                    root_ref = responsibility.root_registration_ref
                    purpose = "consolidation" if type(active_continuation) is ForegroundSourceNoteContinuationV1 or root_ref is not None else "context"
            if operation_kind in {"create_foreground_cycle_v2", "create_source_note_foreground_cycle_v1"}:
                from .foreground_cycle_v1 import foreground_deadline_utc_v1
                deadline = foreground_deadline_utc_v1(deadline)
            create = operation_kind in {"create_foreground_cycle", "create_foreground_cycle_v2", "derive_ingress_artifact_task_scope_v1", "create_source_note_foreground_cycle_v1"}
            if create:
                revision, cancel, holder, fence, expires = 0, 0, None, None, None
            else:
                if job is None:
                    raise UnavailableGuard("foreground continuation requires its actual existing cycle; HOLD")
                cancel, holder, fence, expires = job.cancel_epoch, job.lease_holder, job.fence, job.lease_expires_utc
            operation_id = "foreground-op:" + canonical_digest((ns, c02_operation_id, operation_kind, request))[:40]
            if operation_kind in {"prepare_personal_candidate_eligibility_v1", "adopt_personal_candidate_eligibility_v1"}:
                from .personal_candidate_eligibility_v1 import personal_eligibility_request_id_v1
                operation_id = personal_eligibility_request_id_v1(db, ns, request.candidates,
                    prepare=operation_kind == "prepare_personal_candidate_eligibility_v1")
            if operation_kind == "prepare_ingress_recall_need_v1":
                from .d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1
                operation_id = ingress_recall_need_operation_id_v1(ns, c02_operation_id)
            elif operation_kind == "adopt_current_task_no_search_v1":
                from .d07_task_history_v1 import task_no_search_operation_id_v1
                operation_id = task_no_search_operation_id_v1(ns, c02_operation_id)
            elif operation_kind == "quote_current_method_choices_v1":
                from .d02_method_readiness_v1 import method_readiness_operation_id_v1
                from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2, _readonly_current_artifact_task_choice_basis_v2
                basis = _readonly_current_artifact_task_choice_basis_v2(db, namespace=ns,
                    request=CurrentArtifactTaskChoiceRequestV2(request.task), issuer=self._GraphCoordinator__d11_issuer)
                operation_id = method_readiness_operation_id_v1(request.task, basis[4])
            elif operation_kind == "select_ingress_recall_seed_v1":
                from .d06_ingress_c03_selection_v1 import ingress_c03_selection_operation_id_v1
                operation_id = ingress_c03_selection_operation_id_v1(ns, c02_operation_id)
            elif operation_kind == "prepare_ingress_recall_model_v1":
                from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
                operation_id = ingress_recall_model_ids_v1(ns, c02_operation_id)["prepare"]
            elif operation_kind == "acquire_ingress_recall_model_v1":
                from .d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1
                operation_id = ingress_recall_acquire_operation_id_v1(ns, c02_operation_id)
            elif operation_kind in {"prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
                from .d07_ingress_recall_result_v1 import ingress_recall_result_operation_id_v1
                operation_id = ingress_recall_result_operation_id_v1(ns, c02_operation_id, operation_kind)
            if operation_kind == "await_existing_artifact_revision_v1":
                from .artifact_wait_checkpoint_v1 import artifact_wait_operation_id_v1
                operation_id = artifact_wait_operation_id_v1(request.selector)
            if operation_kind in {"select_existing_artifact_continuation_v1", "revise_existing_artifact_v1"}:
                from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
                operation_id = artifact_continuation_operation_id_v1(request.selector,
                    revision=operation_kind == "revise_existing_artifact_v1")
            note_continuation = (job is not None and job.continuation.get("schema") == "d11.foreground-source-note-continuation.v1")
            if operation_kind in {"prepare_personal_candidates_v1", "select_personal_step_v2"} and note_continuation:
                from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
                from .domain_production_erasure_v1 import decode_typed_production_value_v1
                if operation_kind == "prepare_personal_candidates_v1":
                    operation_id = "source-note-candidates:" + canonical_digest((ns, c02_operation_id, request))[:40]
                else:
                    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
                    actual_prepared = read_adopted_domain_operation_v1(db, ns, request.prepared_candidates_operation_id)
                    if actual_prepared is None or actual_prepared["operation_kind"] != "prepare_personal_candidates_v1":
                        raise UnavailableGuard("SourceNote selection lacks its actual preparation; HOLD")
                    frozen = decode_typed_production_value_v1(actual_prepared["payload"]["provenance"]["prepared_candidates"], PreparedPersonalCandidateSetV1)
                    operation_id = frozen.selection_operation_id
            elif operation_kind in {"input:register_artifact_task_text_extent", "prepare_personal_candidates_v1", "select_personal_step_v2"}:
                from .d08_personal_candidate_v1 import (CurrentArtifactTaskChoiceRequestV2, artifact_task_choice_ids_v2,
                    _readonly_current_artifact_task_choice_basis_v2)
                from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
                task = artifact_draft_task_selector_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=root_ref)
                basis = _readonly_current_artifact_task_choice_basis_v2(db, namespace=ns,
                    request=CurrentArtifactTaskChoiceRequestV2(task), issuer=self._GraphCoordinator__d11_issuer)
                choice_ids = artifact_task_choice_ids_v2(task, basis[4])
                operation_id = choice_ids[{"input:register_artifact_task_text_extent": "extent",
                    "prepare_personal_candidates_v1": "prepare", "select_personal_step_v2": "select"}[operation_kind]]
            internal_material = None
            internal_parent = None
            internal_slot = None
            if operation_kind in {"input:freeze_artifact_candidate_preparation_v1", "input:freeze_values", "evaluate_values"} and not note_continuation:
                from .d08_personal_candidate_v1 import (CurrentArtifactTaskChoiceRequestV2,
                    readonly_current_artifact_task_choice_material_v2)
                from .artifact_phase_postconditions_v1 import (require_candidate_preparation_parent_handle_v1,
                    artifact_candidate_preparation_parent_operation_id_v1, artifact_candidate_preparation_parent_ref_v1,
                    PREPARATION_PARENT_KIND_V1, _original as read_preparation_original)
                from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
                from ..domains.d01.production_operations_v1 import plain_v1
                task = artifact_draft_task_selector_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=root_ref)
                internal_material = readonly_current_artifact_task_choice_material_v2(db, namespace=ns,
                    request=CurrentArtifactTaskChoiceRequestV2(task), issuer=self._GraphCoordinator__d11_issuer)
                require_candidate_preparation_parent_handle_v1(self, task=task,
                    material_digest=canonical_digest(plain_v1(internal_material)))
                if operation_kind == "input:freeze_artifact_candidate_preparation_v1":
                    from .artifact_phase_postconditions_v1 import FreezeArtifactCandidatePreparationRequestV1
                    if type(request) is not FreezeArtifactCandidatePreparationRequestV1 or request.task != task:
                        raise AuthorityDenied("parent start changed its actual bounded task")
                    operation_id = artifact_candidate_preparation_parent_operation_id_v1(task, internal_material.plan_head)
                else:
                    internal_slot = "freeze" if operation_kind == "input:freeze_values" else "evaluate"
                    actual_request = internal_material.freeze_request if internal_slot == "freeze" else internal_material.evaluate_request
                    if type(request) is not type(actual_request) or request != actual_request:
                        raise AuthorityDenied("internal child changed its actual parent material")
                    internal_parent, _ = read_preparation_original(db, namespace=ns, kind=PREPARATION_PARENT_KIND_V1,
                        ref=artifact_candidate_preparation_parent_ref_v1(task, internal_material.plan_head), issuer=self._GraphCoordinator__d11_issuer)
                    operation_id = dict(internal_material.ids)[internal_slot]
            if operation_kind == "input:register_artifact_phase_postcondition_policy_v1":
                from .artifact_phase_postconditions_v1 import (readonly_current_artifact_phase_policy_basis_v1,
                    artifact_phase_policy_registration_operation_id_v1)
                from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
                from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
                if job is None:
                    raise UnavailableGuard("Policy identity requires its actual current task cycle; HOLD")
                responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=ns,
                    job=job, issuer=self._GraphCoordinator__d11_issuer)
                mapping_row = state.control_point_v3('graph_atoms',('value','valid'),('token',),(self_mapping_key(ns).token,))
                if responsibility is None or mapping_row is None or mapping_row[1] != 1:
                    raise UnavailableGuard("Policy identity lost actual Self/Owner responsibility; HOLD")
                mapping = SelfIdentityMapping(**background_json_loads_v3(mapping_row[0]))
                if mapping.status != "active":
                    raise UnavailableGuard("Policy identity requires the actual active Self; HOLD")
                access_epoch, delete_epoch = state.control_point_v3('graph_authority_epochs',('access_epoch','delete_epoch'),('bot','persona'),ns.as_tuple)
                value = readonly_current_artifact_phase_policy_basis_v1(db, namespace=ns, request=request,
                    issuer=self._GraphCoordinator__d11_issuer, bundle=installed_bundle, owner_guard=responsibility.owner_guard,
                    now_utc=policy_now, parent_budget_lease_ref=job.budget_ref, actor_ref=mapping.self_entity_ref,
                    purpose=purpose, audiences=(identity["conversation_ref"],), access_epoch=access_epoch, delete_epoch=delete_epoch)
                operation_id = artifact_phase_policy_registration_operation_id_v1(value)
            if operation_kind == "create_artifact_task_plan_v1":
                from .d08_personal_plan_v1 import artifact_task_initial_plan_operation_id_v1
                operation_id = artifact_task_initial_plan_operation_id_v1(request.task)
            elif operation_kind == "create_artifact_task_project_v1":
                from .d10_project_checkpoint_v1 import artifact_task_project_operation_id_v1
                operation_id = artifact_task_project_operation_id_v1(request.task)
            elif operation_kind == "initialize_artifact_task_project_checkpoint_v1":
                from .d10_project_checkpoint_v1 import artifact_task_checkpoint_initialization_operation_id_v1
                operation_id = artifact_task_checkpoint_initialization_operation_id_v1(request.task)
            elif operation_kind == "activate_artifact_task_project_checkpoint_v1":
                from .d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v1
                operation_id = artifact_task_checkpoint_activation_operation_id_v1(request.selector)
            elif operation_kind == "revise_artifact_task_plan_v2":
                from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2
                operation_id = artifact_task_plan_revision_operation_id_v2(request.task)
            elif operation_kind == "activate_artifact_task_project_checkpoint_v2":
                from .d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v2
                operation_id = artifact_task_checkpoint_activation_operation_id_v2(request.selector)
            elif operation_kind == "register_artifact_task_milestone_v2":
                from .artifact_task_observer_v1 import artifact_task_milestone_registration_operation_id_v2
                operation_id = artifact_task_milestone_registration_operation_id_v2(request.selector)
            if operation_kind in {"prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2", "adopt_artifact_draft_content_v2"}:
                from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
                phase_ids = artifact_draft_model_ids_v2(request.selector)
                operation_id = phase_ids[{"prepare_artifact_draft_model_v2": "prepare",
                    "acquire_artifact_draft_model_v2": "acquire", "adopt_artifact_draft_content_v2": "adopt"}[operation_kind]]
            elif operation_kind == "register_artifact_phase_postcondition_contract_v1":
                from .artifact_phase_postconditions_v1 import artifact_phase_contract_registration_operation_id_v1
                operation_id = artifact_phase_contract_registration_operation_id_v1(request.selector)
            elif operation_kind=='serve_concern':
                from .artifact_phase_observation_v1 import read_artifact_phase_observation_basis_v1
                from .d07_execution_v1 import read_current_d07_semantic_question_v1
                from .artifact_phase_observation_v1 import ArtifactPhaseObservationQuestionV1
                question=read_current_d07_semantic_question_v1(db,self._GraphCoordinator__d11_issuer,ns,request.trigger_original_ref)
                if type(question)is not ArtifactPhaseObservationQuestionV1 or request.category!='background':
                    raise UnavailableGuard('Self concern requires its actual producer-issued Artifact question; HOLD')
                basis=read_artifact_phase_observation_basis_v1(db,namespace=ns,original_ref=question.observation_basis_ref,issuer=self._GraphCoordinator__d11_issuer)
                if basis is None or basis.question!=question or basis.request.selector.task.c02_operation_id!=c02_operation_id:
                    raise UnavailableGuard('Self concern lost its actual same-task observation basis; HOLD')
                operation_id=basis.ids['operation'];deadline=min(deadline,basis.original_deadline_utc);purpose='proposal'
            elif operation_kind == "finish_artifact_receipt_cycle_v1":
                from .artifact_receipt_completion_v1 import finish_operation_id_v1
                operation_id=finish_operation_id_v1(request.selector)
            elif operation_kind == "derive_artifact_completion_receipt_v1":
                from .artifact_completion_receipt_v1 import receipt_ids_v1
                operation_id=receipt_ids_v1(request.selector)['producer']
            elif operation_kind == "prepare_artifact_phase_observation_v1":
                from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1
                operation_id=artifact_observation_ids_v1(request.selector,request.condition_id)['prepare']
            elif operation_kind == "observe_artifact_phase_postconditions_v1":
                from .artifact_phase_postconditions_v1 import artifact_phase_assessment_operation_id_v1
                operation_id = artifact_phase_assessment_operation_id_v1(request.selector)
            elif operation_kind == "verify_artifact_draft_phase_v2":
                from ..model_broker.artifact_draft_v1 import artifact_draft_phase_original_ref_v2
                operation_id = artifact_draft_phase_original_ref_v2(request.selector) + ":verify"
            elif operation_kind == "wake_artifact_draft_cycle_v2":
                from .foreground_cycle_v1 import artifact_draft_phase_wake_operation_id_v2
                operation_id = artifact_draft_phase_wake_operation_id_v2(request.selector)
            if operation_kind in {"prepare_artifact_draft_model", "acquire_artifact_draft_model", "adopt_artifact_draft_content"}:
                from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
                ids = artifact_draft_model_ids_v1(request.selector)
                operation_id = ids[{"prepare_artifact_draft_model": "prepare", "acquire_artifact_draft_model": "acquire",
                    "adopt_artifact_draft_content": "adopt"}[operation_kind]]
            elif operation_kind == "propose_artifact_draft_phase_action_v2":
                from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
                operation_id = artifact_draft_file_ids_v2(request.selector)["action_operation"]
            elif operation_kind == "input:register_artifact_phase_draft_plan_v2":
                from .d11_life_product_adapter_v1 import artifact_phase_draft_plan_registration_operation_id_v2
                operation_id = artifact_phase_draft_plan_registration_operation_id_v2(request.selector)
            elif operation_kind in {"propose_artifact_draft_action", "prepare_artifact_draft_body"}:
                from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
                ids = artifact_draft_file_ids_v1(ns, c02_operation_id=c02_operation_id, root_registration_ref=root_ref)
                if operation_kind == "prepare_artifact_draft_body":
                    from .d08_life_admission_v1 import require_draft_action_root_v1
                    body_root = require_draft_action_root_v1(db, namespace=ns,
                        action_intent_ref=request.action_intent_ref, issuer=self._GraphCoordinator__d11_issuer)
                    if body_root.activity_id != activity_id:
                        raise UnavailableGuard("Body Action root has another actual cycle; HOLD")
                    operation_id = "d02-life-body:" + body_root.action_operation_id
                else:
                    operation_id = ids["action_operation"]
            elif operation_kind == "prepare_selected_source_note_action_v2":
                from .d08_source_note_action_v1 import selected_source_note_binding_from_originals_v2
                frozen, selected_note, selected_original = selected_source_note_binding_from_originals_v2(db, namespace=ns, request=request)
                future_note = selected_note.future_identity
                if job is None or not note_continuation or future_note.activity_id != activity_id or future_note.parent_budget_lease_ref != root.lease_id:
                    raise UnavailableGuard("selected SourceNote dispatcher changed its actual task/activity/root; HOLD")
                operation_id = future_note.action_operation_id
                deadline = future_note.deadline_utc
                if deadline > datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp():
                    raise UnavailableGuard("selected SourceNote future deadline exceeds its original cycle; HOLD")
            elif operation_kind == "prepare_life":
                operation_id = request.prepare_operation_id
            elif operation_kind == "input:register_artifact_draft_plan_v3":
                from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
                operation_id = "artifact-draft-plan-register:" + artifact_draft_task_selector_v1(ns,
                    c02_operation_id=c02_operation_id, root_registration_ref=root_ref).digest[:40]
            if operation_kind in {"input:register_life_outcome_v2", "advance_life", "settle_project_checkpoint", "settle_personal_goal"} and job is not None:
                from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
                from .foreground_call_plan_v1 import ForegroundCallPlanV2
                final_plan = foreground_cycle_from_wire_v1(job.continuation).call_plan
                if type(final_plan) in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
                    from .d11_artifact_draft_content_v1 import artifact_method_final_operation_ids_v2
                    from .artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2, read_current_artifact_task_milestone_v2
                    final_phase = final_plan.phase_group.selector
                    read_current_artifact_task_milestone_v2(db, namespace=ns,
                        original_ref=artifact_task_milestone_original_ref_v2(final_phase), issuer=self._GraphCoordinator__d11_issuer)
                    final_ids = artifact_method_final_operation_ids_v2(final_phase)
                    operation_id = final_ids[{"input:register_life_outcome_v2": "outcome_register", "advance_life": "advance",
                        "settle_project_checkpoint": "project_settle", "settle_personal_goal": "goal"}[operation_kind]]
            if operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
                from .c04_ingress_preparation_v4 import _selection
                from .c04_self_scope_v4 import ingress_c04_ids_v4
                selected, original, _ = _selection(db, ns, request)
                ids = ingress_c04_ids_v4(ns, c02_operation_id, original["original_digest"])
                activity_id = selected.child_activity_id
                operation_id = ids["prepare" if operation_kind == "prepare_ingress_c04_v1" else "adopt"]
                purpose = selected.purpose
            if internal_material is not None:
                from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV2,
                    ForegroundActivityPreparationParentRequestV2)
                from .artifact_phase_postconditions_v1 import ArtifactPreparationChildSelectorV1
                values = dict(namespace=ns, installation_id=policy.installation_id, ingress_operation_id=identity["operation_id"],
                    c02_operation_id=c02_operation_id, cue_source_ref=source_ref, plan_source_ref=source_ref, cycle_job_ref=key.token,
                    expected_cycle_revision=revision, expected_cancel_generation=cancel, activity_id=activity_id,
                    operation_id=operation_id, operation_kind=operation_kind,
                    request_digest=foreground_typed_command_digest_v1(operation, request), parent_budget_lease_ref=root.lease_id,
                    purpose=purpose, audiences=(identity["conversation_ref"],), requested_deadline_utc=deadline,
                    plan_ref=internal_material.plan_head.key.token, draft_root_registration_ref=root_ref,
                    worker_holder=holder, worker_fence=fence, worker_lease_expires_utc=expires)
                if internal_parent is None:
                    selector = ForegroundActivityPreparationParentRequestV2(**values, preparation_task=internal_material.selector)
                else:
                    selector = ForegroundActivityRequestV2(**values,
                        preparation_child=ArtifactPreparationChildSelectorV1(internal_parent.original_ref, internal_slot),
                        preparation_parent_digest=internal_parent.digest)
            else:
                selector = ForegroundActivityRequestV1(ns, policy.installation_id, identity["operation_id"], c02_operation_id,
                    source_ref, source_ref, key.token, revision, cancel, activity_id, operation_id, operation_kind,
                    foreground_typed_command_digest_v1(operation, request), root.lease_id,
                    purpose, (identity["conversation_ref"],), deadline, draft_root_registration_ref=root_ref,
                    worker_holder=holder, worker_fence=fence, worker_lease_expires_utc=expires)
            if operation_kind in {"prepare_personal_candidate_eligibility_v1", "adopt_personal_candidate_eligibility_v1"}:
                selector = replace(selector, plan_ref=request.candidates.plan_ref)
            elif operation_kind in {"prepare_personal_candidates_v1", "select_personal_step_v2"}:
                selector = replace(selector, plan_ref=request.plan_ref)
            else:
                from ..authority_service.current_foreground_activity_v1 import _ARTIFACT_PHASE_OPERATIONS_V2,_ARTIFACT_PHASE_FILE_OPERATIONS_V2
                if operation_kind in _ARTIFACT_PHASE_OPERATIONS_V2|_ARTIFACT_PHASE_FILE_OPERATIONS_V2|{'finish_artifact_receipt_cycle_v1','derive_artifact_completion_receipt_v1'}:
                    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
                    from .foreground_call_plan_v1 import ForegroundCallPlanV2
                    plan=foreground_cycle_from_wire_v1(job.continuation).call_plan
                    if type(plan)not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
                        raise UnavailableGuard('phase selector needs its actual selected method plan; HOLD')
                    selector=replace(selector,plan_ref=plan.phase_group.selector.plan_ref)
            db.rollback()
            return selector
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise


def read_artifact_phase_resume_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph
    bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    selected=state.selector
    c02_operation_id,source_ref=selected.c02_operation_id,selected.source_ref
    """Read the actual selected phase and its signed once originals."""
    self._admin(bootstrap)
    # This Work already completed current Owner/Self and the complete Source closure.
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV1, ForegroundCallPlanV2
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2,
        require_current_artifact_phase_group_v2)
    from .d11_life_preparation_v1 import _read
    from .jobs import get_job
    from ..model_broker.artifact_draft_v1 import (artifact_draft_model_ids_v2, artifact_draft_phase_original_ref_v2,
        artifact_draft_phase_sequence_v2)
    ns = installed_bundle.installation_policy.namespace
    from .first_ingress_v2 import trusted_upper
    current_now = trusted_upper(self._GraphCoordinator__content_fence_v2.read_ingress_clock(self._GraphCoordinator__scene_clock_policy))
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            cycle = get_job(db, foreground_cycle_ids_v1(ns, c02_operation_id)[1])
            continuation = foreground_cycle_from_wire_v1(cycle.continuation)
            if type(continuation.call_plan) is ForegroundCallPlanV1:
                return None
            if type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
                raise UnavailableGuard("unregistered artifact phase call plan; HOLD")
            responsibility = read_original_foreground_responsibility_for_c09_v1(db,
                namespace=ns, job=cycle, issuer=self._GraphCoordinator__d11_issuer)
            group = continuation.call_plan.phase_group
            require_current_artifact_phase_group_v2(db, namespace=ns, group=group, issuer=self._GraphCoordinator__d11_issuer)
            phase = group.selector
            if (responsibility is None or continuation.source_ref != source_ref
                    or phase.task.namespace != ns or phase.task.c02_operation_id != c02_operation_id
                    or phase.task.root_registration_ref != responsibility.root_registration_ref):
                raise UnavailableGuard("actual phase task/Source/responsibility differs; HOLD")
            complete = len(group.completed_phase_originals) == len(artifact_draft_phase_sequence_v2(phase.method_ref))
            checkpoint_activated = self._read_current_artifact_task_checkpoint_activation_v1(db,
                namespace=ns, phase=phase)
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2
            amended = read_adopted_domain_operation_v1(db, ns, artifact_task_plan_revision_operation_id_v2(phase.task)) is not None
            checkpoint_activation_operation = ("activate_artifact_task_project_checkpoint_v2" if amended
                else "activate_artifact_task_project_checkpoint_v1")
            from .artifact_phase_postconditions_v1 import CONTRACT_KIND, artifact_phase_postcondition_contract_ref_v1
            contract_ref = artifact_phase_postcondition_contract_ref_v1(phase)
            contract = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind=CONTRACT_KIND, ref=contract_ref)
            if not phase.generation:
                from .d11_artifact_draft_content_v1 import read_current_artifact_phase_check_inputs_v2
                check_request, assessment = read_current_artifact_phase_check_inputs_v2(db, namespace=ns,
                    selector=phase, issuer=self._GraphCoordinator__d11_issuer, now_utc=current_now,
                    owner_guard=responsibility.owner_guard, installed_bundle=installed_bundle)
                ref = artifact_draft_phase_original_ref_v2(phase) + ":verified"
                verified = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind="c4_phase_verified", ref=ref)
                if verified is not None:
                    from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
                    read_current_artifact_phase_verified_v2(db, namespace=ns, selector=phase, issuer=self._GraphCoordinator__d11_issuer)
                return {"schema": "d11.artifact-draft-phase-resume.v2", "selector": phase,
                    "c02_operation_id": c02_operation_id, "source_ref": source_ref, "generation": False,
                    "cycle_job_id": cycle.job_id, "cycle_phase": cycle.phase,
                    "cycle_cancel_generation": cycle.cancel_epoch, "verified": verified is not None,
                    "phase_group_complete": complete, "checkpoint_activated": checkpoint_activated, "contract_registered": contract is not None,
                    "assessment_registered": assessment is not None, "assessment_request": check_request,
                    "assessment_statuses": () if assessment is None else tuple(row.status for row in assessment.results)}
            ids = artifact_draft_model_ids_v2(phase)
            prepared = read_artifact_draft_prepared_v2(db, namespace=ns, selector=phase, issuer=self._GraphCoordinator__d11_issuer)
            frozen = None if prepared is None else _read_phase_target_metadata_v3(state,prepared)
            job = None if prepared is None else get_job(db, prepared.job_id)
            originals = _read_phase_status_metadata_v3(state,phase,prepared,ids)
            verified_ref = artifact_draft_phase_original_ref_v2(phase) + ":verified"
            verified = _read(db, issuer=self._GraphCoordinator__d11_issuer, namespace=ns, kind="c4_phase_verified", ref=verified_ref)
            if prepared is None and any(value is not None for value in originals.values()):
                raise UnavailableGuard("phase originals lost actual prepared selector; HOLD")
            return {"schema": "d11.artifact-draft-phase-resume.v2", "selector": phase,
                "c02_operation_id": c02_operation_id, "source_ref": source_ref,
                "cycle_job_id": cycle.job_id, "cycle_phase": cycle.phase,
                "cycle_cancel_generation": cycle.cancel_epoch, "cycle_deadline_utc": cycle.deadline_utc,
                "model_job_id": ids["job"], "model_phase": None if job is None else job.phase,
                "model_cancel_generation": None if job is None else job.cancel_epoch,
                "prepared": prepared is not None, "target_mode": None if frozen is None else frozen['target']['mode'],
                "request_sealed": originals["request"] is not None, "call_sealed": originals["call"] is not None,
                "paid": originals["paid"] is not None, "result": originals["result"] is not None,
                "adopted": originals["adopt"] is not None, "verified": verified is not None,
                "phase_group_complete": complete, "generation": True, "checkpoint_activated": checkpoint_activated,
                "checkpoint_activation_operation": checkpoint_activation_operation, "contract_registered": contract is not None}
        finally:
            db.rollback()


def _read_control_mode_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    self._admin(bootstrap)
    read_artifact_cycle_receipt_v3(reader,state)
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .jobs import get_job
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            cycle = get_job(db, foreground_cycle_ids_v1(ns, c02_operation_id)[1])
            responsibility = read_original_foreground_responsibility_for_c09_v1(db,
                namespace=ns, job=cycle, issuer=self._GraphCoordinator__d11_issuer)
            mode = ("legacy" if responsibility is None else "draft"
                if responsibility.root_registration_ref is not None else "natural")
            db.rollback()
            return {"schema": "d11.foreground-mode.v1", "mode": mode,
                "cycle_job_id": cycle.job_id, "cycle_phase": cycle.phase}
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise


def _read_control_observation_progress_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Read actual basis/job/paid adoption originals, never infer execution from preparation."""
    self._admin(bootstrap)
    if self._GraphCoordinator__d04_installed_joint_assembly is None or self._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not installed_bundle:
        raise UnavailableGuard('Artifact observation progress needs its actual installation; HOLD')
    current=read_artifact_phase_resume_v3(reader,state)
    if current is None or current['generation']:
        raise UnavailableGuard('observation progress requires its actual current check phase; HOLD')
    from .artifact_phase_observation_v1 import read_artifact_phase_observation_basis_v1
    from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1
    from .d07_execution_v1 import read_prepared_d07_execution_v1
    from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    from .artifact_phase_observation_result_v1 import read_artifact_phase_semantic_observations_v1
    from .artifact_phase_postconditions_v1 import CONTRACT_KIND,_original
    from .jobs import get_job
    phase=current['selector'];ns=phase.task.namespace
    condition='tone'if phase.phase_kind=='sample_check'else'task_semantics'
    ids=artifact_observation_ids_v1(phase,condition)
    with self._GraphCoordinator__store._lock:
        db=self._GraphCoordinator__store._db;db.execute('BEGIN')
        try:
            basis=read_artifact_phase_observation_basis_v1(db,namespace=ns,original_ref=ids['basis'],issuer=self._GraphCoordinator__d11_issuer)
            if basis is None:return {'basis_prepared':False,'job':None,'observation_complete':False}
            prepared=read_prepared_d07_execution_v1(db,self._GraphCoordinator__d11_issuer,ns,ids['job'])
            if prepared is None:return {'basis_prepared':True,'job':None,'observation_complete':False}
            if type(prepared)is not D07ArtifactObservationPreparedV3 or prepared.observation_basis_digest!=basis.digest:
                raise UnavailableGuard('observation progress found another prepared producer/basis; HOLD')
            job=get_job(db,prepared.job_id)
            if job.cancel_epoch or job.phase in {'cancelled','failed','draining','pending_confirmation'}:
                return {'basis_prepared':True,'job':job,'observation_complete':False}
            if job.phase!='completed':return {'basis_prepared':True,'job':job,'observation_complete':False}
            contract,_=_original(db,namespace=ns,kind=CONTRACT_KIND,ref=basis.request.contract_ref,issuer=self._GraphCoordinator__d11_issuer)
            observed=read_artifact_phase_semantic_observations_v1(db,namespace=ns,selector=phase,contract=contract,
                observer_original_refs=current['assessment_request'].observer_original_refs,issuer=self._GraphCoordinator__d11_issuer)
            return {'basis_prepared':True,'job':job,'observation_complete':True,
                'statuses':tuple(item.status for item in observed.values())}
        finally:db.rollback()


def _read_control_finalization_progress_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Readonly completion checkpoint, never an execution permit."""
    self._admin(bootstrap)
    if self._GraphCoordinator__d04_installed_joint_assembly is None or self._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not installed_bundle:
        raise UnavailableGuard("method progress requires its actual installation; HOLD")
    read_artifact_cycle_receipt_v3(reader,state)
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .jobs import get_job
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
    namespace = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            job = get_job(db, foreground_cycle_ids_v1(namespace, c02_operation_id)[1])
            plan = foreground_cycle_from_wire_v1(job.continuation).call_plan
            if type(plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
                return None
            group = plan.phase_group
            if len(group.completed_phase_originals) != len(artifact_draft_phase_sequence_v2(group.selector.method_ref)):
                return None
            verified = read_current_artifact_phase_verified_v2(db, namespace=namespace,
                selector=group.selector, issuer=self._GraphCoordinator__d11_issuer)
            if not verified.method_qualified or group.completed_phase_originals[-1] != (verified.original_ref, verified.digest):
                raise UnavailableGuard("method progress changed actual complete final check; HOLD")
            from .artifact_task_observer_v1 import (artifact_task_milestone_original_ref_v2,
                artifact_task_milestone_registration_operation_id_v2, read_current_artifact_task_milestone_v2)
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            milestone_adoption = read_adopted_domain_operation_v1(db, namespace,
                artifact_task_milestone_registration_operation_id_v2(group.selector))
            registered = None
            if milestone_adoption is not None:
                milestone = read_current_artifact_task_milestone_v2(db, namespace=namespace,
                    original_ref=artifact_task_milestone_original_ref_v2(group.selector), issuer=self._GraphCoordinator__d11_issuer)
                if milestone.selector != group.selector or milestone.ordered_phase_originals != group.completed_phase_originals:
                    raise UnavailableGuard("saved method milestone changed its actual complete group; HOLD")
                registered = {"coverage": "complete", "receipt": asdict(milestone_adoption["receipt"]),
                    "produced_originals": ({"kind": "d11.life_artifact_task_milestone_v2",
                        "original_ref": milestone.original_ref, "original_digest": milestone.digest},)}
            return {"status": "artifact_phase_check_verified", "selector": group.selector,
                "registered_milestone": registered, "c02_operation_id": c02_operation_id, "source_ref": source_ref}
        finally:
            db.rollback()


def _read_control_completed_method_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Disclose one actual completed history receipt without issuing any new work."""
    self._admin(bootstrap)
    if self._GraphCoordinator__d04_installed_joint_assembly is None or self._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not installed_bundle:
        raise UnavailableGuard("completed method disclosure requires its actual installation; HOLD")
    read_artifact_cycle_receipt_v3(reader,state)
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .d11_artifact_draft_content_v1 import (artifact_method_settlement_operation_id_v2,
        read_current_completed_artifact_method_history_v2)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .jobs import get_job
    namespace = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            cycle = get_job(db, foreground_cycle_ids_v1(namespace, c02_operation_id)[1])
            continuation = foreground_cycle_from_wire_v1(cycle.continuation)
            if type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
                return None
            phase = continuation.call_plan.phase_group.selector
            original = read_adopted_domain_operation_v1(db, namespace, artifact_method_settlement_operation_id_v2(phase))
            if original is None:
                return None
            responsibility = read_original_foreground_responsibility_for_c09_v1(db,
                namespace=namespace, job=cycle, issuer=self._GraphCoordinator__d11_issuer)
            if responsibility is None or responsibility.source_ref != source_ref:
                raise UnavailableGuard("completed method disclosure lost its actual responsibility Source; HOLD")
            history, receipt = read_current_completed_artifact_method_history_v2(db,
                namespace=namespace, selector=phase, issuer=self._GraphCoordinator__d11_issuer,
                owner_guard=responsibility.owner_guard, installed_bundle=installed_bundle)
            return {"status": "artifact_method_settlement_history", "history_state": history.state,
                "selector": phase, "original_receipt": receipt, "history": history,
                "c02_operation_id": c02_operation_id, "source_ref": source_ref}
        finally:
            db.rollback()


from .artifact_host_control_recipes_v3 import (
    artifact_control_attachment_recipe_v3,artifact_control_point_recipe_v3,artifact_control_signed_recipe_v3)


def normalize_artifact_entry_arguments_v3(entry_kind,arguments):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as typed
    values=dict(arguments)
    if len(values)!=len(arguments)or set(values)!=set(_ENTRY_FIELDS_V3[entry_kind]):
        raise ValueError('Artifact control wire changed its exact registered argument fields')
    if entry_kind=='read_current_post_c02_artifact_method_prerequisites_v1':
        from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceMaterialV2
        if type(values['material'])is not CurrentArtifactTaskChoiceMaterialV2:
            from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
            from ..graph_types import GraphVersion
            from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
            from .domain_production_inputs_v1 import FreezeCurrentValuesInputRequestV1
            from ..domains.d01.production_operations_v1 import EvaluateCurrentValuesRequestV1
            raw=values['material']
            if type(raw)is not dict or set(raw)!=set(CurrentArtifactTaskChoiceMaterialV2.__dataclass_fields__):
                raise ValueError('Exact actual task choice material fields required')
            ids=raw['ids']
            if type(ids)is not list or any(type(row)is not list or len(row)!=2 or any(type(v)is not str for v in row)for row in ids):
                raise ValueError('Task material IDs changed its closed string-pair wire')
            values['material']=CurrentArtifactTaskChoiceMaterialV2(typed(raw['selector'],ArtifactDraftTaskSelectorV1),
                tuple(tuple(row)for row in ids),typed(raw['goal_head'],GraphVersion),typed(raw['plan_head'],GraphVersion),
                typed(raw['prepare_request'],PrepareCurrentPersonalCandidatesRequestV1),
                typed(raw['freeze_request'],FreezeCurrentValuesInputRequestV1),typed(raw['evaluate_request'],EvaluateCurrentValuesRequestV1))
    elif entry_kind=='run_current_post_c02_artifact_preparation_step_v1':
        from .domain_production_registry_v1 import installed_operation_v1
        cls=installed_operation_v1(values['operation_kind']).request_type
        if type(values['request'])is not cls:values['request']=typed(values['request'],cls)
    return tuple((name,values[name])for name in _ENTRY_FIELDS_V3[entry_kind])


def read_artifact_entry_prepare_v3(reader,state):
    from .artifact_host_control_entry_v3 import seal_artifact_control_command_v3
    from . import artifact_host_task_entry_recipes_v3 as task
    from . import artifact_host_cycle_recall_recipes_v3 as cycle
    from . import artifact_host_phase_entry_recipes_v3 as phase
    from . import artifact_host_draft_entry_recipes_v3 as draft
    q=require_artifact_entry_descriptor_v3(state.selector)
    for operation,digest in q.completed_receipts:
        with reader.store._lock:
            reader.db.execute('BEGIN')
            try:prior,_,_=_control_original_receipt_v3(reader,state,operation)
            finally:reader.db.rollback()
        if prior['receipt_digest']!=digest:
            raise AuthorityUnavailable('Artifact continuation changed an actually completed predecessor receipt')
    read_recipes={
        'read_current_ingress_recall_resume_v1':read_artifact_ingress_recall_resume_v3,
        'advance_current_post_c02_ingress_c04_v4':read_artifact_ingress_c04_native_input_v3,
        '_read_post_c02_foreground_cycle_v1':read_artifact_cycle_receipt_v3,
        'read_current_post_c02_foreground_mode_v1':_read_control_mode_v3,
        'read_current_post_c02_artifact_draft_resume_v1':draft.read_artifact_draft_resume_v3,
        'read_current_artifact_phase_observation_progress_v3':_read_control_observation_progress_v3,
        'read_current_artifact_method_finalization_progress_v2':_read_control_finalization_progress_v3,
        'read_current_completed_artifact_method_v2':_read_control_completed_method_v3}
    if q.entry_kind in read_recipes:
        if q.stage!='start':raise ValueError('Read-only Artifact entry has no WRITE continuation stage')
        return ArtifactControlValueV3(read_recipes[q.entry_kind](reader,state))
    if q.entry_kind in task._TASK_ENTRIES_V3:
        result=task.artifact_host_task_entry_recipe_v3(reader,state)
    elif q.entry_kind in draft._ENTRY_KINDS_V3:
        result=draft.artifact_host_draft_entry_recipe_v3(reader,state)
    else:
        name='_entry_'+q.entry_kind
        recipes={
            'prepare_post_c02_artifact_task_scope_v1':cycle._entry_prepare_post_c02_artifact_task_scope_v1,
            'prepare_post_c02_foreground_cycle_v1':cycle._entry_prepare_post_c02_foreground_cycle_v1,
            'prepare_source_note_foreground_cycle_v1':cycle._entry_prepare_source_note_foreground_cycle_v1,
            'prepare_selected_source_note_action_v2':cycle._entry_prepare_selected_source_note_action_v2,
            'acquire_post_c02_foreground_cycle_v1':cycle._entry_acquire_post_c02_foreground_cycle_v1,
            'checkpoint_post_c02_foreground_wait_v1':cycle._entry_checkpoint_post_c02_foreground_wait_v1,
            'prepare_current_post_c02_recall_need_v1':cycle._entry_prepare_current_post_c02_recall_need_v1,
            'run_current_post_c02_ingress_recall_model_operation_v1':cycle._entry_run_current_post_c02_ingress_recall_model_operation_v1,
            'select_current_post_c02_ingress_recall_seed_v1':cycle._entry_select_current_post_c02_ingress_recall_seed_v1,
            'run_current_post_c02_ingress_c04_operation_v4':cycle._entry_run_current_post_c02_ingress_c04_operation_v4,
            'prepare_current_post_c02_artifact_task_structure_v3':cycle._entry_prepare_current_post_c02_artifact_task_structure_v3,
            'run_current_post_c02_artifact_phase_operation_v2':phase._entry_run_current_post_c02_artifact_phase_operation_v2,
            'finish_current_artifact_receipt_cycle_v1':phase._entry_finish_current_artifact_receipt_cycle_v1,
            'prepare_current_artifact_completion_source_v1':phase._entry_prepare_current_artifact_completion_source_v1}
        result=recipes[q.entry_kind](reader,state)
    if q.entry_kind=='acquire_post_c02_foreground_cycle_v1'and q.stage=='wake_acquire':
        if type(result)is ArtifactControlCommandV3:
            result=replace(result,after='wake_finish')
        elif type(result)is ArtifactControlValueV3:
            result=ArtifactControlValueV3(_wake_acquisition_result_v3(reader,state,result.value))
    if type(result)is ArtifactControlCommandV3:
        return seal_artifact_control_command_v3(reader,state,result,arguments=q.arguments)
    if type(result)not in {ArtifactControlValueV3,ArtifactControlNextV3}:
        raise AuthorityUnavailable('Artifact entry has no exact registered terminal result')
    return result


def read_artifact_post_commit_v3(reader,state):
    from .artifact_host_control_metadata_v3 import ArtifactPostCommitReadSelectorV3
    from ..authority_service.contract import AuthorityUnavailable
    q=state.selector
    if type(q)is not ArtifactPostCommitReadSelectorV3:raise TypeError('Exact actual receipt READ selector required')
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:result,original,selector_digest=_control_original_receipt_v3(reader,state,q.operation_id)
        finally:reader.db.rollback()
    receipt=original['receipt']
    if canonical_digest(original['payload']['request'])!=q.command_digest:
        raise AuthorityUnavailable('Artifact receipt changed its actual immutable typed command body')
    if (original['operation_kind']!=q.operation_kind or selector_digest!=q.request_digest
            or canonical_digest(receipt)!=q.receipt_digest or receipt.write_versions!=q.write_versions):
        raise AuthorityUnavailable('Artifact post-commit READ changed its actual command/receipt/write versions')
    for operation,digest in q.completed_receipts:
        with reader.store._lock:
            reader.db.execute('BEGIN')
            try:prior,_,_=_control_original_receipt_v3(reader,state,operation)
            finally:reader.db.rollback()
        if prior['receipt_digest']!=digest:raise AuthorityUnavailable('Artifact post-commit predecessor receipt changed')
    if q.stage=='return':return ArtifactControlValueV3(result)
    if q.stage=='wake_finish':return ArtifactControlValueV3(_wake_acquisition_result_v3(reader,state,result))
    if result.get('coverage')!='complete':
        return ArtifactControlValueV3({'status':'held','operation_kind':q.operation_kind,'original':result,
            'c02_operation_id':q.c02_operation_id,'source_ref':q.source_ref})
    complete=(*q.completed_receipts,(q.operation_id,q.receipt_digest))
    if len(complete)>6:raise AuthorityUnavailable('Artifact finite predecessor sequence exceeded its original stage bound')
    if q.stage=='cycle_root':
        return ArtifactControlNextV3('prepare_post_c02_foreground_cycle_v1','cycle_root',(),complete)
    if q.stage.startswith('structure_'):
        from .artifact_host_cycle_recall_recipes_v3 import artifact_task_structure_stage_count_v3
        index=int(q.stage[-1]);count=artifact_task_structure_stage_count_v3(reader,state)
        if index+1<count:
            return ArtifactControlNextV3(q.entry_kind,'structure_'+str(index+1),q.arguments,complete)
        return ArtifactControlValueV3({'status':'task_structure_prepared','original':result,
            'c02_operation_id':q.c02_operation_id,'source_ref':q.source_ref})
    if q.stage=='wake_acquire':
        return ArtifactControlNextV3('acquire_post_c02_foreground_cycle_v1','wake_acquire',(),complete)
    if q.stage=='recall_need':
        from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
        from ..domains.d01.production_operations_v1 import plain_v1
        with reader.store._lock:
            reader.db.execute('BEGIN')
            try:need=read_adopted_ingress_recall_need_v1(reader.db,namespace=reader.namespace,c02_operation_id=q.c02_operation_id)
            finally:reader.db.rollback()
        if need is None or need.source_ref!=q.source_ref:
            raise AuthorityUnavailable('Recall Need lost its actual adopted C02/Source original')
        return ArtifactControlValueV3({'receipt':result,'need':plain_v1(need)})
    if q.stage=='c03_selection':
        from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
        from ..domains.d01.production_operations_v1 import plain_v1
        with reader.store._lock:
            reader.db.execute('BEGIN')
            try:saved=read_adopted_ingress_c03_selection_v1(reader.db,namespace=reader.namespace,c02_operation_id=q.c02_operation_id)
            finally:reader.db.rollback()
        if saved is None:raise AuthorityUnavailable('C03 selection lost its actual adopted metadata receipt')
        value,origin,bridge=saved
        return ArtifactControlValueV3({'receipt':result,'selection':plain_v1(value),
            'original_ref':'d06-current:'+origin['original_digest'][:48],
            'original_digest':origin['original_digest'],'query_commit_bridge':bridge})
    if q.stage=='completion_source':
        from .artifact_host_phase_entry_recipes_v3 import _completion_source_values_v3
        completed=_read_control_completed_method_v3(reader,state)
        if completed is None or completed['history_state']!='satisfied':
            raise AuthorityUnavailable('Completion Source lost its actual satisfied method history')
        return ArtifactControlValueV3(_completion_source_values_v3(reader,state,completed))
    from .artifact_host_draft_entry_recipes_v3 import artifact_host_draft_post_recipe_v3
    return artifact_host_draft_post_recipe_v3(reader,state,result,original,complete)


def _wake_acquisition_result_v3(reader,state,acquired):
    q=state.selector
    if not q.completed_receipts:raise AuthorityUnavailable('Phase acquisition lost its actual preceding wake receipt')
    operation,digest=q.completed_receipts[-1]
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:wake,original,_=_control_original_receipt_v3(reader,state,operation)
        finally:reader.db.rollback()
    if original['operation_kind']not in {'wake_artifact_draft_cycle_v1','wake_artifact_draft_cycle_v2'}or wake['receipt_digest']!=digest:
        raise AuthorityUnavailable('Phase acquisition changed its exact completed wake operation')
    return {'wake':wake,'acquisition':acquired}


def read_artifact_ingress_recall_resume_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Qualify disclosure through the existing current Source/Self read protocol."""
    read_artifact_cycle_receipt_v3(reader,state)
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
    from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
    from .d07_execution_v1 import read_prepared_d07_execution_v1, D07IngressRecallPreparedV1
    from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .jobs import get_job
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            need = read_adopted_ingress_recall_need_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            ids = ingress_recall_model_ids_v1(ns, c02_operation_id)
            prepared = read_prepared_d07_execution_v1(db, self._GraphCoordinator__d11_issuer, ns, ids["job"])
            if (need is None or type(prepared) is not D07IngressRecallPreparedV1
                    or need.source_ref != source_ref or prepared.cycle_job_ref != need.cycle_job_ref
                    or prepared.c02_operation_id != c02_operation_id):
                raise UnavailableGuard("cold recall requires the actual original Self C3 preparation; HOLD")
            parent = get_job(db, foreground_cycle_ids_v1(ns, c02_operation_id)[1])
            routing = read_adopted_ingress_recall_routing_v1(db, namespace=ns,
                c02_operation_id=c02_operation_id, issuer=self._GraphCoordinator__d11_issuer)
            selection = read_adopted_ingress_c03_selection_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            c04 = None
            if selection is not None:
                c04_ids = ingress_c04_ids_v4(ns, c02_operation_id, selection[1]["original_digest"])
                c04 = read_c04_internal_work_prepared_v1(db, ns, c04_ids["prepare"])
            return {"need": need, "prepared": prepared, "routing": routing, "selection": selection,
                "c04_prepared": c04, "parent_phase": parent.phase, "c3_job": get_job(db, prepared.job_id)}
        finally:
            db.rollback()


def read_artifact_ingress_c04_native_input_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Read actual C03/C04 originals and issue an execution locator after Source EOF."""
    self._admin(bootstrap)
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    from .c04_ingress_preparation_v4 import ADOPT_OPERATION
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            actual = read_adopted_ingress_c03_selection_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            if actual is None or actual[0].cue_source_ref != source_ref:
                raise UnavailableGuard("Self C04 advance lost its actual C03 parent; HOLD")
            value, original, _ = actual
            ids = ingress_c04_ids_v4(ns, c02_operation_id, original["original_digest"])
            prepared = read_c04_internal_work_prepared_v1(db, ns, ids["prepare"])
            adopted = read_adopted_domain_operation_v1(db, ns, ids["adopt"])
            if adopted is not None:
                if adopted["operation_kind"] != ADOPT_OPERATION:
                    raise ValueError("Self C04 adopted original changed its producer")
                return {"status": "recollection_adopted", "operation_id": ids["adopt"],
                    "receipt_digest": canonical_digest(adopted["receipt"]), "replayed": True}
            if prepared is None:
                raise UnavailableGuard("Self C04 actual frozen preparation is absent; HOLD")
        finally:
            db.rollback()

    from .c04_ingress_preparation_v4 import issue_current_ingress_c04_native_locator_v3
    locator=issue_current_ingress_c04_native_locator_v3(self,installed_bundle,prepared=prepared,
        c02_operation_id=c02_operation_id,source_ref=source_ref,selection_original_digest=original['original_digest'],
        adopt_operation_id=ids['adopt'],original_deadline_utc=state.seed.business_deadline_v3())
    return {'status':'native_ready','locator':locator}



def artifact_post_commit_selector_from_wire_v3(raw):
    """Closed ephemeral control wire; the production Original codec stays strict."""
    from .artifact_host_control_metadata_v3 import ArtifactPostCommitReadSelectorV3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as typed
    from ..runtime_contracts import NamespaceId
    from ..graph_types import GraphVersion
    if type(raw)is not dict or set(raw)!=set(ArtifactPostCommitReadSelectorV3.__dataclass_fields__):
        raise ValueError('Exact Artifact post-commit locator fields required')
    args=normalize_artifact_entry_arguments_v3(raw['entry_kind'],raw['arguments'])
    return ArtifactPostCommitReadSelectorV3(namespace=typed(raw['namespace'],NamespaceId),
        installation_id=raw['installation_id'],c02_operation_id=raw['c02_operation_id'],source_ref=raw['source_ref'],
        entry_kind=raw['entry_kind'],arguments=args,stage=raw['stage'],
        completed_receipts=tuple(tuple(row)for row in raw['completed_receipts']),
        operation_id=raw['operation_id'],operation_kind=raw['operation_kind'],request_digest=raw['request_digest'],
        command_digest=raw['command_digest'],receipt_digest=raw['receipt_digest'],
        write_versions=tuple(typed(v,GraphVersion)for v in raw['write_versions']),business_deadline_utc=raw['business_deadline_utc'])
