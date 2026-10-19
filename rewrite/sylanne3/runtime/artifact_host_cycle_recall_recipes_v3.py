"""Finite C02 entry recipes. They only read and describe one registered command."""
from dataclasses import replace
from ..runtime_contracts import canonical_digest,canonical_serialize
from .domain_background_read_v3 import background_json_loads_v3
from .artifact_host_control_algorithms_v3 import (ArtifactControlCommandV3,ArtifactControlValueV3,ArtifactControlNextV3,
    read_artifact_cycle_receipt_v3,read_artifact_phase_resume_v3)
from ..graph_coordinator import UnavailableGuard


def _entry_prepare_source_note_foreground_cycle_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    values=dict(state.selector.arguments)
    authorization_original_ref=values['authorization_original_ref']
    """Initial-only actual Owner task authorization consumed by the independent Self kernel."""
    self._admin(bootstrap)
    from ..host.authority_profile import AdminInstallationBundle
    if (type(installed_bundle) is not AdminInstallationBundle
            or self._GraphCoordinator__d04_installed_joint_assembly is None
            or self._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not installed_bundle):
        raise UnavailableGuard("SourceNote initial dispatcher needs its actual installed production bundle; HOLD")
    from .source_note_foreground_v1 import CreateSourceNoteForegroundCycleRequestV1, OPERATION
    from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db; db.execute("BEGIN")
        try:
            saved = read_source_note_task_authorization_v1(db, namespace=ns,
                original_ref=authorization_original_ref, issuer=self._GraphCoordinator__d11_issuer)
            if saved is None or (saved[0].request.c02_operation_id, saved[0].request.source_ref) != (c02_operation_id, source_ref):
                raise UnavailableGuard("SourceNote initial dispatcher requires its exact actual Owner C02/task authorization; HOLD")
        finally:
            db.rollback()
    request = CreateSourceNoteForegroundCycleRequestV1(authorization_original_ref)
    return ArtifactControlCommandV3("create_source_note_foreground_cycle_v1",request,after='return')


def _entry_prepare_selected_source_note_action_v2(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    values=dict(state.selector.arguments)
    decision_ref=values['decision_ref']
    prepared_candidates_operation_id=values['prepared_candidates_operation_id']
    self._admin(bootstrap)
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    request = ConsumePersonalDecisionRequestV1(decision_ref, prepared_candidates_operation_id)
    return ArtifactControlCommandV3("prepare_selected_source_note_action_v2",request,after='return')


def _entry_checkpoint_post_c02_foreground_wait_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    self._admin(bootstrap)
    from .foreground_cycle_v1 import (CheckpointForegroundCycleRequestV1, CheckpointForegroundCycleRequestV2,
        ForegroundCycleContinuationV2, ForegroundWaitV1,
        foreground_cycle_ids_v1, foreground_cycle_from_wire_v1, read_observed_foreground_call_plan_v1)
    from .jobs import get_job
    from .d11_types import runtime_job_key
    from ..runtime_contracts import QueryEpoch, VersionedRef
    from .source_note_foreground_v1 import (ForegroundSourceNoteContinuationV1,
        CheckpointSourceNoteForegroundCycleRequestV1)
    ns = installed_bundle.installation_policy.namespace
    activity_id, job_id = foreground_cycle_ids_v1(ns, c02_operation_id)
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            job = get_job(db, job_id)
            before = foreground_cycle_from_wire_v1(job.continuation)
            _, epoch = self._v2_graph_stamp(ns)
            if job.phase != "running" or job.lease_holder is None:
                raise UnavailableGuard("foreground waiting must checkpoint its actual running worker; HOLD")
            source = state.control_point_v3('graph_atoms',('revision','valid'),('token',),(source_ref,))
            if source is None or source[1] != 1:
                raise UnavailableGuard("foreground waiting current original Source is absent; HOLD")
            if type(before) in {ForegroundCycleContinuationV2, ForegroundSourceNoteContinuationV1}:
                from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
                responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=ns,
                    job=job, issuer=self._GraphCoordinator__d11_issuer)
                if responsibility is None:
                    raise UnavailableGuard("foreground waiting lacks its actual responsibility Owner; HOLD")
                observed = read_observed_foreground_call_plan_v1(db, namespace=ns, continuation=before,
                    issuer=self._GraphCoordinator__d11_issuer, installed_bundle=installed_bundle, owner_guard=responsibility.owner_guard)
            else:
                observed = read_observed_foreground_call_plan_v1(db, namespace=ns, continuation=before, issuer=self._GraphCoordinator__d11_issuer)
            wait = ForegroundWaitV1("d08", "personal_step_requires_current_final_admission",
                (VersionedRef(source_ref, source[0]),), QueryEpoch(ns, "namespace", epoch.revision), before.stage_cursor)
            current = replace(before, call_plan=observed, wait=wait)
            request_type = (CheckpointSourceNoteForegroundCycleRequestV1 if type(current) is ForegroundSourceNoteContinuationV1 else
                CheckpointForegroundCycleRequestV2 if type(current) is ForegroundCycleContinuationV2 else CheckpointForegroundCycleRequestV1)
            operation_kind = ("checkpoint_source_note_foreground_cycle_v1" if request_type is CheckpointSourceNoteForegroundCycleRequestV1 else
                "checkpoint_foreground_cycle_v2" if request_type is CheckpointForegroundCycleRequestV2 else "checkpoint_foreground_cycle")
            request = request_type(runtime_job_key(*ns.as_tuple, activity_id, job_id).token,
                job.lease_holder, job.fence, current)
            db.rollback()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
    return ArtifactControlCommandV3(operation_kind,request,after='return')


def _entry_prepare_current_post_c02_recall_need_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Ordinary installed entry into the actual privately issued Self need producer."""
    self._admin(bootstrap)
    from .d06_ingress_recall_v1 import (PrepareIngressRecallNeedRequestV1,
        read_adopted_ingress_recall_need_v1, NEED_OPERATION)
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .d11_types import runtime_job_key
    from ..host.authority_profile import AdminD06RecallPolicyV1
    from ..domains.d01.production_operations_v1 import plain_v1
    policy = installed_bundle.d06_recall
    if type(policy) is not AdminD06RecallPolicyV1:
        raise UnavailableGuard("explicit installed ingress recall policy is absent; HOLD")
    ns = installed_bundle.installation_policy.namespace
    activity, job_id = foreground_cycle_ids_v1(ns, c02_operation_id)
    request = PrepareIngressRecallNeedRequestV1(c02_operation_id, source_ref,
        runtime_job_key(*ns.as_tuple, activity, job_id).token, policy.policy_digest)
    return ArtifactControlCommandV3(NEED_OPERATION,request,after='recall_need')


def _entry_run_current_post_c02_ingress_recall_model_operation_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    values=dict(state.selector.arguments)
    operation_kind=values['operation_kind']
    """Only registered Self C3 preparation/acquisition from the original ordinary ingress."""
    self._admin(bootstrap)
    from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
    from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1, OPERATION
    from .d07_ingress_recall_acquisition_v1 import ACQUIRE_OPERATION
    from .d07_ingress_recall_result_v1 import OPERATIONS
    if operation_kind not in {OPERATION, ACQUIRE_OPERATION, *OPERATIONS}:
        raise ValueError("Self C3 caller cannot select another business operation")
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            need = read_adopted_ingress_recall_need_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            if need is None or need.source_ref != source_ref:
                raise UnavailableGuard("Self C3 lacks its actual ordinary ingress Need; HOLD")
            request = PrepareIngressRecallModelRequestV1(c02_operation_id, source_ref,
                need.cycle_job_ref, need.policy_digest, canonical_digest(need))
        finally:
            db.rollback()
    return ArtifactControlCommandV3(operation_kind,request,after='return')


def _entry_select_current_post_c02_ingress_recall_seed_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """One registered C03 selection from an actual adopted Self routing original."""
    self._admin(bootstrap)
    from .d06_ingress_c03_read_v1 import SelectIngressRecallSeedRequestV1, OPERATION
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            need = read_adopted_ingress_recall_need_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            if need is None or need.source_ref != source_ref:
                raise UnavailableGuard("C03 lacks its actual current ingress Need; HOLD")
            request = SelectIngressRecallSeedRequestV1(c02_operation_id, source_ref, need.cycle_job_ref,
                need.policy_digest, canonical_digest(need))
        finally:
            db.rollback()
    return ArtifactControlCommandV3(OPERATION,request,after='c03_selection')


def _entry_run_current_post_c02_ingress_c04_operation_v4(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    values=dict(state.selector.arguments)
    operation_kind=values['operation_kind']
    """The actual C03 selection chooses one fixed Self C04 prepare/adopt command."""
    self._admin(bootstrap)
    from .c04_self_scope_v4 import PrepareIngressC04RequestV1, PREPARE_OPERATION
    from .c04_ingress_preparation_v4 import ADOPT_OPERATION
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    if operation_kind not in {PREPARE_OPERATION, ADOPT_OPERATION}:
        raise ValueError("unregistered Self C04 operation")
    ns = installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db = self._GraphCoordinator__store._db
        db.execute("BEGIN")
        try:
            actual = read_adopted_ingress_c03_selection_v1(db, namespace=ns, c02_operation_id=c02_operation_id)
            if actual is None:
                raise UnavailableGuard("Self C04 needs its actual adopted C03 selection; HOLD")
            value, original, _ = actual
            if value.cue_source_ref != source_ref or value.selected_source_ref is None:
                raise UnavailableGuard("Self C04 has no actual positive historical selection; HOLD")
            request = PrepareIngressC04RequestV1(c02_operation_id, value.cycle_job_ref, source_ref,
                "d06-current:" + original["original_digest"][:48], canonical_digest(value),
                installed_bundle.d06_recall.policy_digest)
        finally:
            db.rollback()
    return ArtifactControlCommandV3(operation_kind,request,after='return')


def _task_scope_recipe_v3(reader,state):
    from ..host.authority_profile import AdminArtifactDraftPolicyV2,AdminArtifactDraftPolicyV3
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from .ingress_artifact_task_scope_v1 import DeriveIngressArtifactTaskScopeRequestV1,OPERATION
    if type(reader.bundle.artifact_draft)not in {AdminArtifactDraftPolicyV2,AdminArtifactDraftPolicyV3,AdminArtifactDraftPairedPolicyV4}:
        return ArtifactControlValueV3(None)
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:
            intent=read_c1_task_intent_original_v1(reader.db,namespace=reader.namespace,
                c02_operation_id=state.selector.c02_operation_id,issuer=reader.graph._GraphCoordinator__d11_issuer)
        finally:reader.db.rollback()
    roots=state.root_registrations_for_source_v3()
    if intent is not None and not roots:
        return ArtifactControlCommandV3(OPERATION,DeriveIngressArtifactTaskScopeRequestV1(
            state.selector.c02_operation_id,state.selector.source_ref))
    return ArtifactControlValueV3(None)


def _entry_prepare_post_c02_artifact_task_scope_v1(reader,state):
    return _task_scope_recipe_v3(reader,state)


def _entry_prepare_post_c02_foreground_cycle_v1(reader,state):
    from .foreground_cycle_v1 import CreateForegroundCycleRequestV2,foreground_post_c02_cause_ref_v1
    from .artifact_receipt_allocation_v3 import select_initial_foreground_reply_budget_ids_v3
    if state.selector.stage=='start':
        preliminary=_task_scope_recipe_v3(reader,state)
        if type(preliminary)is ArtifactControlCommandV3:return replace(preliminary,after='cycle_root')
    roots=state.root_registrations_for_source_v3()
    if len(roots)>1:raise UnavailableGuard('one task Source has conflicting signed Root setup originals; HOLD')
    root_ref=roots[0]if roots else None;q=state.selector
    child_id=select_initial_foreground_reply_budget_ids_v3(reader.namespace,q.c02_operation_id,
        installed_bundle=reader.bundle,draft_root_registration_ref=root_ref)[0]
    request=CreateForegroundCycleRequestV2(q.c02_operation_id,q.source_ref,child_id,
        cause_original_ref=root_ref or foreground_post_c02_cause_ref_v1(reader.namespace,q.c02_operation_id),
        draft_root_registration_ref=root_ref)
    return ArtifactControlCommandV3('create_foreground_cycle_v2',request)


def _entry_acquire_post_c02_foreground_cycle_v1(reader,state):
    from .foreground_cycle_v1 import foreground_cycle_ids_v1,AcquireForegroundCycleRequestV1
    from .d11_types import runtime_job_key
    from .jobs import get_job
    q=state.selector;activity,job_id=foreground_cycle_ids_v1(reader.namespace,q.c02_operation_id)
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:job=get_job(reader.db,job_id)
        finally:reader.db.rollback()
    self_ref=reader.current_self.self_entity_ref
    if job.phase=='running':
        if job.lease_holder!=self_ref:raise UnavailableGuard('foreground worker belongs to another original holder; HOLD')
        return ArtifactControlValueV3(read_artifact_cycle_receipt_v3(reader,state))
    generation,review=reader.bundle.model_workflows.natural_generation,reader.bundle.model_workflows.natural_review
    if generation is None or review is None:
        raise UnavailableGuard('foreground worker requires its actual installed reply workflows; HOLD')
    lease_seconds=min(3600,int(generation.timeout_seconds+review.timeout_seconds+120))
    request=AcquireForegroundCycleRequestV1(runtime_job_key(*reader.namespace.as_tuple,activity,job_id).token,
        self_ref,lease_seconds)
    return ArtifactControlCommandV3('acquire_foreground_cycle',request)


def _entry_prepare_current_post_c02_artifact_task_structure_v3(reader,state):
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .jobs import get_job
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV1,
        task_scope_ref_v1,_decode,require_task_scope_archive_v1)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d08_personal_plan_v1 import CreateCurrentArtifactTaskPlanRequestV1,ReviseCurrentArtifactTaskPlanRequestV2
    from .d10_project_checkpoint_v1 import CreateCurrentArtifactTaskProjectRequestV1,InitializeCurrentArtifactTaskProjectCheckpointRequestV1
    read_artifact_cycle_receipt_v3(reader,state);q=state.selector;ns=reader.namespace
    with reader.store._lock:
        db=reader.db;db.execute('BEGIN')
        try:
            cycle=get_job(db,foreground_cycle_ids_v1(ns,q.c02_operation_id)[1])
            responsibility=read_original_foreground_responsibility_for_c09_v1(db,namespace=ns,job=cycle,issuer=reader.graph._GraphCoordinator__d11_issuer)
            if responsibility is None or responsibility.source_ref!=q.source_ref or responsibility.root_registration_ref is None:
                raise UnavailableGuard('task structure lost its actual Source/Root responsibility; HOLD')
            saved=_read(db,issuer=reader.graph._GraphCoordinator__d11_issuer,namespace=ns,kind='artifact_task_scope',
                ref=task_scope_ref_v1(responsibility.root_registration_ref))
            if saved is None:raise UnavailableGuard('task structure requires its actual signed TaskScope; HOLD')
            scope=_decode(saved[0],IngressArtifactTaskScopeOriginalV1)
            producer=read_adopted_domain_operation_v1(db,ns,saved[1])
            require_task_scope_archive_v1(db,namespace=ns,root=scope.root,producer=producer)
        finally:db.rollback()
    task=artifact_draft_task_selector_v1(ns,c02_operation_id=q.c02_operation_id,root_registration_ref=scope.root.registration_ref)
    if scope.task_kind=='continue':operations=(('revise_artifact_task_plan_v2',ReviseCurrentArtifactTaskPlanRequestV2),)
    elif scope.task_kind=='draft_then_corrected_revision':operations=(('create_artifact_task_plan_v1',CreateCurrentArtifactTaskPlanRequestV1),
        ('create_artifact_task_project_v1',CreateCurrentArtifactTaskProjectRequestV1),
        ('initialize_artifact_task_project_checkpoint_v1',InitializeCurrentArtifactTaskProjectCheckpointRequestV1))
    else:return ArtifactControlValueV3({'status':'single_artifact_task','c02_operation_id':q.c02_operation_id,'source_ref':q.source_ref})
    index=0 if q.stage=='start'else {'structure_0':0,'structure_1':1,'structure_2':2}[q.stage]
    if index>=len(operations):raise ValueError('task structure stage crossed its actual task kind')
    operation,cls=operations[index]
    return ArtifactControlCommandV3(operation,cls(task),after='structure_'+str(index))


def artifact_task_structure_stage_count_v3(reader,state):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,_decode,IngressArtifactTaskScopeOriginalV1
    roots=state.root_registrations_for_source_v3()
    if len(roots)!=1:raise UnavailableGuard('Task structure continuation lost its unique actual Root')
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:saved=_read(reader.db,issuer=reader.graph._GraphCoordinator__d11_issuer,namespace=reader.namespace,
            kind='artifact_task_scope',ref=task_scope_ref_v1(roots[0]))
        finally:reader.db.rollback()
    if saved is None:raise UnavailableGuard('Task structure continuation lost actual signed Scope')
    scope=_decode(saved[0],IngressArtifactTaskScopeOriginalV1);q=state.selector
    if scope.c02_operation_id!=q.c02_operation_id or scope.source_ref!=q.source_ref:
        raise UnavailableGuard('Task structure continuation crossed actual C02/Source')
    return {'continue':1,'draft_then_corrected_revision':3}[scope.task_kind]
