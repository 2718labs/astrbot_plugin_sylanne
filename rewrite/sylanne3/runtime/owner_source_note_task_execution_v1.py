"""Closed Self execution of an independently signed Owner SourceNote task.

Only Root's active paired issuance handle supplies current Core evidence. The
stages propose one existing PersistentJob carrier, never C02 or a CallPlan,
and mutate its SQL projection only inside the same W01 business transaction.
"""
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.self_perspective import self_mapping_key
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d11_life_preparation_v1 import _read, _record
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, runtime_job_key, job_graph_write
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .owner_source_note_task_contract_v1 import (
    CREATE_OPERATION, ACQUIRE_OPERATION, CHECKPOINT_OPERATION, RESPONSIBILITY_KIND, TASK_WORK_KIND, TASK_STEPS,
    CreateOwnerSourceNoteTaskRequestV1, AcquireOwnerSourceNoteTaskRequestV1, CheckpointOwnerSourceNoteTaskRequestV1,
    OwnerSourceNoteTaskResponsibilityV2, OwnerSourceNoteTaskContinuationV2, owner_source_note_task_ids_v1,
    owner_source_note_task_from_wire_v1)
from .owner_source_note_task_v1 import (
    read_owner_source_note_task_authorization_v2, require_current_owner_source_note_task_authorization_v2)
from .jobs import (PersistentJob, get_job, create_job, acquire_job, plan_job_acquire, _utc, _utc_text,
    _job_dict, _job_from_dict, _save_job, _record_operation)

_READERS_KEY = object()
OPERATIONS = {CREATE_OPERATION: CreateOwnerSourceNoteTaskRequestV1,
    ACQUIRE_OPERATION: AcquireOwnerSourceNoteTaskRequestV1, CHECKPOINT_OPERATION: CheckpointOwnerSourceNoteTaskRequestV1}


class InstalledOwnerSourceNoteTaskExecutionReadersV1:
    def __init__(self, key, *, graph, scope, issued):
        if key is not _READERS_KEY: raise TypeError("Owner task execution uses the actual installed Self factory")
        self.graph, self.scope, self.issued = graph, scope, issued
        self.issuer = graph._GraphCoordinator__d11_issuer
        self.installed_bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        self.body_quote_authority = graph._GraphCoordinator__body_quote_authority

    def current(self):
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        return require_owner_source_note_task_issuance_v1(self.issued, self.graph, self.scope)


def install_owner_source_note_task_execution_readers_v1(graph, *, scope, owner_guard, owner_binding=None, owner_task_issuance):
    from ..graph_coordinator import GraphCoordinator
    from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
    if type(graph) is not GraphCoordinator or owner_binding is not None:
        raise TypeError("Owner task worker is independently qualified Self, not an Owner lease")
    evidence = require_owner_source_note_task_issuance_v1(owner_task_issuance, graph, scope)
    if (evidence.current_self.namespace != scope.namespace
            or evidence.owner_guard.owner_head_digest != owner_guard.authorization_head.removeprefix("sha256:")):
        raise ValueError("Owner task readers changed their actual current namespace/Owner")
    return InstalledOwnerSourceNoteTaskExecutionReadersV1(_READERS_KEY, graph=graph, scope=scope, issued=owner_task_issuance)


def _actual_inputs(db, *, frame, request, readers, operation_kind):
    from ..authority_service.current_owner_source_note_task_v1 import (
        OwnerTaskActivityEvidenceV1, owner_task_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    if (type(readers) is not InstalledOwnerSourceNoteTaskExecutionReadersV1
            or type(request) is not OPERATIONS[operation_kind]):
        raise TypeError("exact current installed Owner task execution request/readers required")
    read = CurrentDomainReadV1(frame); read.check(db)
    evidence = readers.current()
    if (type(evidence) is not OwnerTaskActivityEvidenceV1 or evidence.request.operation_kind != operation_kind
            or evidence.request.operation_id != frame.envelope.identity.operation_id
            or evidence.request.request_digest != owner_task_typed_command_digest_v1(installed_operation_v1(operation_kind), request)
            or evidence.current_self.permit != readers.scope.permit or evidence.owner_guard != frame.owner_guard
            or evidence.current_self.self_entity_ref != frame.envelope.authority.actor
            or evidence.current_self.activation_generation != frame.activation_generation
            or frame.envelope.parent_budget_lease_ref != evidence.authorization.cause.parent_budget_lease_ref
            or _utc(evidence.valid_until_utc, "Owner task deadline").timestamp() != frame.envelope.deadline_utc
            or frame.now_utc >= evidence.authorization.cause.original_deadline_utc):
        raise ValueError("Owner task stage lost its actual Core command, fixed Self, Owner, original Root or deadline")
    for version in evidence.read_versions:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("actual_current_Owner_task_Core_read_version")
    saved = read_owner_source_note_task_authorization_v2(db, namespace=frame.envelope.authority.namespace,
        original_ref=evidence.authorization.original_ref, issuer=readers.issuer)
    if saved is None or saved[0] != evidence.authorization:
        raise MissingProductionOriginalV1("actual_signed_Owner_task_authorization_for_execution")
    auth = saved[0]
    if operation_kind == CHECKPOINT_OPERATION and request.continuation.step == "completed":
        completion = evidence.completed_settlement
        if completion is None:
            raise MissingProductionOriginalV1("actual_completed_Owner_task_settlement")
        require_current_owner_source_note_task_authorization_v2(db, frame=frame, authorization=auth,
            issuer=readers.issuer, installed_bundle=readers.installed_bundle, body_quote_authority=readers.body_quote_authority,
            completed_settlement=completion)
    else:
        if evidence.completed_settlement is not None:
            raise ValueError("Owner task completed proof never authorizes new work or another checkpoint phase")
        require_current_owner_source_note_task_authorization_v2(db, frame=frame, authorization=auth,
            issuer=readers.issuer, installed_bundle=readers.installed_bundle, body_quote_authority=readers.body_quote_authority)
    read.original(auth.original_ref); read.original(auth.cause.original_ref)
    return read, evidence, auth


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteTaskStageV1:
    frame: object
    request: object
    before_job: PersistentJob | None
    after_job: PersistentJob
    responsibility: OwnerSourceNoteTaskResponsibilityV2
    stage: object


def _stage(frame, request, before, after, responsibility, kind):
    value = stage_result_v1(frame, "d11", kind, request,
        writes=(job_graph_write(after),), provenance={"before_job": before, "after_job": after,
            "owner_task_responsibility": responsibility}, proposal_schema=D11_PROPOSAL_SCHEMA,
        proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return OwnerSourceNoteTaskStageV1(frame, request, before, after, responsibility, value)


def stage_create_owner_source_note_task_v1(db, *, frame, request, installed_readers):
    read, evidence, auth = _actual_inputs(db, frame=frame, request=request, readers=installed_readers, operation_kind=CREATE_OPERATION)
    ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
    key = runtime_job_key(*auth.cause.namespace.as_tuple, ids["activity_id"], ids["job_id"])
    if (request.authorization_original_ref != auth.original_ref or evidence.request.task_job_ref != key.token
            or evidence.request.expected_job_revision != 0 or evidence.current_job_digest is not None
            or frame.envelope.identity.operation_id != ids["create_operation_id"]
            or frame.envelope.identity.activity_id != ids["activity_id"] or read.head(db, key).revision
            or db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?", (ids["job_id"],)).fetchone() is not None):
        raise ValueError("Owner task creation cannot replace or reuse an existing task identity")
    mapping = read.head(db, self_mapping_key(auth.cause.namespace), required=True)
    if mapping.value["self_entity_ref"] != evidence.current_self.self_entity_ref or mapping.value["status"] != "active":
        raise ValueError("Owner task creation needs its actual current certified Self mapping")
    responsibility = OwnerSourceNoteTaskResponsibilityV2(auth.cause.namespace, auth.cause.installation_id,
        auth.cause.owner_operation_id, auth.cause.original_ref, auth.cause.digest, auth.original_ref, auth.digest,
        frame.owner_guard, GraphVersion(mapping.key, mapping.revision), canonical_digest(mapping.value),
        evidence.current_self.self_entity_ref, auth.cause.parent_budget_lease_ref, auth.cause.original_deadline_utc, auth.source_refs)
    continuation = OwnerSourceNoteTaskContinuationV2(auth.cause.original_ref, auth.cause.digest, auth.original_ref,
        auth.digest, ids["responsibility_ref"], responsibility.digest, "qualify", (), (), None, 0, auth.source_refs)
    after = PersistentJob(ids["job_id"], ids["create_operation_id"], ids["activity_id"], None,
        *auth.cause.namespace.as_tuple, "owner-note-snapshot:" + canonical_digest(auth)[:40], "queued", TASK_WORK_KIND,
        plain_v1(continuation), None, _utc_text(datetime.fromtimestamp(auth.cause.original_deadline_utc, timezone.utc)),
        auth.cause.parent_budget_lease_ref, "owner-note-resource:" + canonical_digest(auth)[:40], {"d11.personal-semantic-mesh":"1"}, None, None, 0, 0, {}, None)
    return verify_owner_source_note_task_stage_v1(_stage(frame, request, None, after, responsibility, CREATE_OPERATION))


def read_owner_source_note_task_responsibility_v2(db, *, namespace, original_ref, issuer):
    saved = _read(db, issuer=issuer, namespace=namespace, kind=RESPONSIBILITY_KIND, ref=original_ref)
    if saved is None: return None
    responsibility = owner_source_note_task_from_wire_v1(saved[0], OwnerSourceNoteTaskResponsibilityV2)
    authorization = read_owner_source_note_task_authorization_v2(db, namespace=namespace,
        original_ref=responsibility.authorization_original_ref, issuer=issuer)
    actual = read_adopted_domain_operation_v1(db, namespace, saved[1])
    ids = owner_source_note_task_ids_v1(namespace, responsibility.owner_operation_id)
    key = runtime_job_key(*namespace.as_tuple, ids["activity_id"], ids["job_id"])
    if (responsibility.namespace != namespace or original_ref != ids["responsibility_ref"]
            or saved[1] != ids["create_operation_id"] or actual is None or actual["domain"] != "d11"
            or actual["operation_kind"] != CREATE_OPERATION or authorization is None
            or responsibility.authorization_original_digest != authorization[0].digest
            or responsibility.cause_original_ref != authorization[0].cause.original_ref
            or responsibility.cause_original_digest != authorization[0].cause.digest
            or responsibility.owner_guard != authorization[0].cause.owner_guard
            or actual["payload"]["provenance"]["owner_task_responsibility"] != saved[0]
            or len(actual["receipt"].write_versions) != 1 or actual["receipt"].write_versions[0].key != key
            or actual["receipt"].write_versions[0].revision != 1):
        raise ValueError("Owner task responsibility is not its actual signed same-W01 creation")
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1", (key.token,)).fetchone()
    initial_job = decode_owner_source_note_task_job_v1(actual["payload"]["provenance"]["after_job"], namespace=namespace)
    if (history is None or history[0] != ids["create_operation_id"] or history[2] != 1
            or json.loads(history[1]) != job_graph_write(initial_job).value):
        raise ValueError("Owner task responsibility lost its exact initial job history member")
    return responsibility, authorization[0], actual


def require_current_owner_source_note_task_job_v1(db, *, frame, request, readers, operation_kind):
    read, evidence, auth = _actual_inputs(db, frame=frame, request=request, readers=readers, operation_kind=operation_kind)
    key = AtomKey.from_token(request.job_ref)
    head = read.head(db, key, required=True)
    job = get_job(db, key.name)
    ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
    continuation = owner_source_note_task_from_wire_v1(dict(job.continuation), OwnerSourceNoteTaskContinuationV2)
    signed = read_owner_source_note_task_responsibility_v2(db, namespace=auth.cause.namespace,
        original_ref=continuation.responsibility_ref, issuer=readers.issuer)
    if (signed is None or signed[1] != auth or key != job_graph_write(job).key or head.value != job_graph_write(job).value
            or (job.job_id, job.operation_id, job.activity_id, job.budget_ref, job.work_kind) != (
                ids["job_id"], ids["create_operation_id"], ids["activity_id"], auth.cause.parent_budget_lease_ref, TASK_WORK_KIND)
            or evidence.request.task_job_ref != key.token or evidence.request.expected_job_revision != head.revision
            or evidence.current_job_digest != canonical_digest(job) or evidence.request.expected_cancel_generation != job.cancel_epoch
            or job.cancel_epoch or continuation.cancel_generation or (continuation.responsibility_ref, continuation.responsibility_digest) != (
                ids["responsibility_ref"], signed[0].digest) or continuation.authorization_original_ref != auth.original_ref
            or continuation.authorization_original_digest != auth.digest or _utc(job.deadline_utc, "deadline").timestamp() != auth.cause.original_deadline_utc):
        raise ValueError("Owner task lost its exact current SQL/Graph job, responsibility, Root or cancellation generation")
    return read, evidence, auth, job, continuation, signed[0]


def stage_acquire_owner_source_note_task_v1(db, *, frame, request, installed_readers):
    read, evidence, auth, job, continuation, responsibility = require_current_owner_source_note_task_job_v1(
        db, frame=frame, request=request, readers=installed_readers, operation_kind=ACQUIRE_OPERATION)
    if job.phase != "queued" or job.lease_holder is not None or request.holder != responsibility.self_entity_ref:
        raise ValueError("Owner task acquisition must use its actually queued job and fixed Self holder")
    after = plan_job_acquire(job, request.holder, now_utc=_utc_text(datetime.fromtimestamp(frame.now_utc, timezone.utc)),
        lease_seconds=request.lease_seconds)
    if _utc(after.lease_expires_utc, "lease").timestamp() > auth.cause.original_deadline_utc:
        raise ValueError("Owner task worker lease cannot extend its original task deadline")
    return verify_owner_source_note_task_stage_v1(_stage(frame, request, job, after, responsibility, ACQUIRE_OPERATION))


# Every entry is an actual W01 operation kind, never a caller completion label.
_STEP_PRODUCERS = {
    "values": {"prepare_owner_source_note_need_v1"},
    "select": {"input:freeze_owner_source_note_values_parent_v1", "input:freeze_values", "evaluate_values"},
    "prepare_action": {"prepare_personal_candidates_v1", "select_personal_step_v2"},
    "prepare_body": {"prepare_selected_source_note_action_v2"},
    "register_life_plan": {"prepare_source_note_body"},
    "prepare_life": {"register_owner_source_note_life_plan_v1"},
    "execute_life": {"prepare_life", "actual_native_life_adoption"},
    "observe_life": set(),
    "adopt_outcome": {"actual_native_life_adoption"},
    "completed": {"register_owner_source_note_life_outcome_v1", "advance_life", "settle_personal_goal", "actual_native_life_adoption"},
}


def _verify_completed_native_artifact(db, *, prepared, terminal, job, auth):
    from .d11_life_preparation_v1 import D11LifePreparedV1
    from .d11_life_contract_v1 import D11LifeTerminalV1
    from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
    if (type(prepared) is not D11LifePreparedV1 or type(terminal) is not D11LifeTerminalV1
            or prepared.binding != terminal.binding or terminal.status != "completed"
            or prepared.binding.namespace != auth.cause.namespace
            or prepared.binding.installation_id != auth.cause.installation_id
            or prepared.binding.activity_id != job.activity_id
            or prepared.binding.parent_budget_lease_ref != job.budget_ref
            or prepared.plan.project.ref != auth.request.project_ref
            or prepared.plan.input_source.ref != auth.request.body_source_ref
            or terminal.payload.artifact_ref != prepared.binding.artifact_ref):
        raise ValueError("Owner task completion needs its exact signed preparation and actual completed terminal")
    verify_durable_life_artifact_v1(db, prepared, digest=terminal.payload.artifact_digest,
        length=terminal.payload.artifact_length)


def _completed_operation(db, read, ref, *, job, auth, issuer):
    read.committed_operation(db, ref)
    actual = read_adopted_domain_operation_v1(db, auth.cause.namespace, ref)
    if actual is not None:
        read.original(ref, digest=actual["original_digest"])
        if (actual["receipt"].activity_id != job.activity_id
                or actual["payload"]["authority"]["actor"] != read.frame.envelope.authority.actor
                or actual["payload"]["coverage"] not in {"complete", "deferred"}):
            raise ValueError("Owner task completion operation belongs to another actor/activity or held stage")
        return actual["operation_kind"]
    # Native adoption uses its existing atomic Graph bundle and signed Life original.
    from .d11_life_preparation_v1 import TABLE
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
        "AND kind='adopted_life' AND producing_operation_id=? LIMIT 2", (*auth.cause.namespace.as_tuple, ref)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("actual_same_task_completed_W01_operation:" + ref)
    adopted = read_adopted_life_original_v1(db, namespace=auth.cause.namespace, result_ref=rows[0][0], issuer=issuer)
    read.original(rows[0][0], kind="d11.life_adopted_life", digest=canonical_digest(adopted))
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    from .d11_life_preparation_v1 import read_prepared_life_v1
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_signed_Owner_task_native_preparation")
    if terminal.status == "failed":
        from .owner_source_note_native_observation_v1 import read_adopted_owner_source_note_native_v1
        failure = read_adopted_owner_source_note_native_v1(db,authorization=auth,issuer=issuer,expected_status="failed")
        if failure is None or failure[0] != prepared or failure[1] != terminal:
            raise MissingProductionOriginalV1("actual_atomic_Owner_task_Native_failure")
        return "actual_native_life_failure"
    _verify_completed_native_artifact(db, prepared=prepared, terminal=terminal, job=job, auth=auth)
    return "actual_native_life_adoption"


def stage_checkpoint_owner_source_note_task_v1(db, *, frame, request, installed_readers):
    read, evidence, auth, job, old, responsibility = require_current_owner_source_note_task_job_v1(db,
        frame=frame, request=request, readers=installed_readers, operation_kind=CHECKPOINT_OPERATION)
    current = request.continuation
    if (job.phase != "running" or job.lease_holder != request.holder or request.holder != responsibility.self_entity_ref
            or job.fence != request.fence or frame.envelope.authority.worker_fence != job.fence
            or _utc(job.lease_expires_utc,"lease").timestamp() <= frame.now_utc):
        raise ValueError("Owner task checkpoint lost its actual live holder/fence/worker lease")
    immutable = ("cause_original_ref", "cause_original_digest", "authorization_original_ref", "authorization_original_digest",
        "responsibility_ref", "responsibility_digest", "cancel_generation", "source_refs")
    if any(getattr(current,name) != getattr(old,name) for name in immutable):
        raise ValueError("Owner task checkpoint cannot change its original cause/authorization/Root/Self scope")
    before_index, next_index = TASK_STEPS.index(old.step), TASK_STEPS.index(current.step)
    if not before_index <= next_index <= before_index + 1:
        raise ValueError("Owner task checkpoint cannot skip or regress its finite production steps")
    if not set(old.completed_original_refs) <= set(current.completed_original_refs):
        raise ValueError("Owner task checkpoint cannot discard already admitted operation originals")
    kinds = {_completed_operation(db,read,ref,job=job,auth=auth,issuer=installed_readers.issuer)
        for ref in current.completed_original_refs}
    if "actual_native_life_failure" in kinds:
        if (old.step not in {"prepare_life","execute_life"} or current.step != old.step
                or current.pending_effect_refs or current.wait_reason is not None or request.completion_result_ref is not None):
            raise ValueError("actual Native failure only terminates its existing task execution step")
        from .owner_source_note_native_observation_v1 import read_adopted_owner_source_note_native_v1
        from .d11_life_contract_v1 import life_adoption_operation_id_v1
        failure = read_adopted_owner_source_note_native_v1(db,authorization=auth,
            issuer=installed_readers.issuer,expected_status="failed")
        if failure is None:
            raise MissingProductionOriginalV1("actual_Owner_task_failed_Native_adoption")
        failure_operation = life_adoption_operation_id_v1(failure[0].binding)
        if failure_operation not in current.completed_original_refs:
            raise MissingProductionOriginalV1("actual_Owner_task_failure_original_in_checkpoint")
        after = replace(job,continuation=plain_v1(current),phase="failed",result_ref=failure_operation,
            lease_holder=None,lease_expires_utc=None,wake_condition=None)
        return verify_owner_source_note_task_stage_v1(_stage(frame,request,job,after,responsibility,CHECKPOINT_OPERATION))
    if next_index > before_index and not _STEP_PRODUCERS[current.step] <= kinds:
        raise MissingProductionOriginalV1("actual_Owner_task_step_producers:" + current.step)
    if old.step == "prepare_life":
        from .d11_life_preparation_v1 import TABLE
        prepared_rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
            "AND kind='prepared' AND json_extract(payload_json,'$.plan.activity_id')=? LIMIT 2",
            (*auth.cause.namespace.as_tuple,job.activity_id)).fetchall()
        if len(prepared_rows) > 1:
            raise ValueError("Owner task has more than its unique actual Native preparation")
        if prepared_rows and "actual_native_life_adoption" not in kinds:
            raise MissingProductionOriginalV1("actual_Native_adoption_before_frozen_Parent_task_checkpoint")
    if old.step == "execute_life":
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_execution_original_v1
        original = require_owner_source_note_task_execution_original_v1(installed_readers.issued,
            installed_readers.graph, installed_readers.scope)
        if original is None:
            raise MissingProductionOriginalV1("actual_Owner_task_native_preparation_original")
        prepared, claim, terminal = original
        from .d11_life_preparation_v1 import D11LifePreparedV1, read_prepared_life_v1
        from .d11_life_contract_v1 import D11LifeClaimV1, D11LifeTerminalV1
        if (type(prepared) is not D11LifePreparedV1
                or prepared.binding.namespace != auth.cause.namespace
                or prepared.binding.installation_id != auth.cause.installation_id
                or prepared.binding.activity_id != job.activity_id or prepared.binding.parent_budget_lease_ref != job.budget_ref
                or prepared.plan.project.ref != auth.request.project_ref
                or prepared.plan.input_source.ref != auth.request.body_source_ref
                or read_prepared_life_v1(db, binding=prepared.binding, issuer=installed_readers.issuer) != prepared):
            raise ValueError("Owner task execution original belongs to another task, Root, Source or project")
        read.original(prepared.binding.prepared_original_ref)
        read.committed_operation(db, prepared.prepare_operation_id)
        if claim is not None and (type(claim) is not D11LifeClaimV1 or claim.binding != prepared.binding):
            raise ValueError("Owner task Native claim changed its actual signed preparation")
        if terminal is not None and (type(terminal) is not D11LifeTerminalV1
                or terminal.binding != prepared.binding or terminal.claim != claim):
            raise ValueError("Owner task Native terminal changed its actual claim or preparation")
        if (current.step != "observe_life" or terminal is None or terminal.status != "completed"
                or current.pending_effect_refs or current.wait_reason is not None):
            raise MissingProductionOriginalV1("actual_completed_adopted_Owner_task_native_observation")
        _verify_completed_native_artifact(db, prepared=prepared, terminal=terminal, job=job, auth=auth)
    elif current.pending_effect_refs != old.pending_effect_refs:
        raise ValueError("only the actual native execution boundary changes Owner task pending effects")
    if current.step == "completed":
        from ..authority_service.current_owner_source_note_task_v1 import read_completed_owner_source_note_task_v1
        completed = read_completed_owner_source_note_task_v1(db, namespace=auth.cause.namespace, authorization=auth,
            issuer=installed_readers.issuer)
        if (completed is None or completed != evidence.completed_settlement
                or not {completed.settlement_operation_id,completed.progress_operation_id,completed.native_adoption_operation_id}
                    <= set(current.completed_original_refs)
                or request.completion_result_ref != completed.artifact_ref or current.pending_effect_refs or current.wait_reason is not None):
            raise MissingProductionOriginalV1("actual_Owner_task_complete_native_cost_progress_Goal_Plan_chain")
        after = replace(job,continuation=plain_v1(current),phase="completed",result_ref=completed.settlement_operation_id,
            lease_holder=None,lease_expires_utc=None,wake_condition=None)
    elif current.wait_reason is not None:
        wake = {"schema":"d11.owner-source-note-task-wait.v1","reason":current.wait_reason,
            "pending_effect_refs":list(current.pending_effect_refs),"original_deadline_utc":job.deadline_utc}
        after = replace(job,continuation=plain_v1(current),phase="waiting",wake_condition=wake,
            lease_holder=None,lease_expires_utc=None)
    else:
        if current == old: raise MissingProductionOriginalV1("actual_new_Owner_task_checkpoint_fact")
        after = replace(job,continuation=plain_v1(current),wake_condition=None)
    return verify_owner_source_note_task_stage_v1(_stage(frame,request,job,after,responsibility,CHECKPOINT_OPERATION))


def verify_owner_source_note_task_stage_v1(value):
    if type(value) is not OwnerSourceNoteTaskStageV1 or type(value.after_job) is not PersistentJob:
        raise TypeError("actual Owner task job stage required")
    if (value.stage.domain != "d11" or value.stage.operation_kind not in OPERATIONS
            or type(value.request) is not OPERATIONS[value.stage.operation_kind]
            or value.stage.operation_id != value.frame.envelope.identity.operation_id
            or tuple(write for proposal in value.stage.proposals for write in proposal.typed_writes) != (job_graph_write(value.after_job),)
            or value.after_job.work_kind != TASK_WORK_KIND or value.after_job.effect_id is not None):
        raise ValueError("Owner task stage may write only its exact PersistentJob projection")
    return value


def apply_owner_source_note_task_stage_in_transaction_v1(db, *, stage):
    verify_owner_source_note_task_stage_v1(stage)
    if not db.in_transaction: raise ValueError("Owner task mutation must share the W01 transaction")
    if stage.before_job is None:
        actual = create_job(db, stage.after_job, stage.stage.operation_id, canonical_digest(stage.after_job.continuation))
    elif type(stage.request) is AcquireOwnerSourceNoteTaskRequestV1:
        actual = acquire_job(db, stage.before_job.job_id, stage.request.holder,
            now_utc=_utc_text(datetime.fromtimestamp(stage.frame.now_utc, timezone.utc)), lease_seconds=stage.request.lease_seconds)
    else:
        if get_job(db, stage.before_job.job_id) != stage.before_job:
            raise ValueError("Owner task checkpoint SQL job changed before its exact same-W01 mutation")
        actual = _job_from_dict(_job_dict(stage.after_job)); _save_job(db, actual)
        _record_operation(db, actual, stage.stage.operation_id, "checkpoint", canonical_digest(stage.request))
    if actual != stage.after_job: raise ValueError("Owner task real SQL mutation differs from its actual frozen proposal")


def record_owner_source_note_task_execution_after_cas_v1(db, *, frame, stage, receipt, installed_readers):
    verify_owner_source_note_task_stage_v1(stage)
    key = job_graph_write(stage.after_job).key
    if (not db.in_transaction or receipt.status != "committed" or receipt.operation_id != stage.stage.operation_id
            or receipt.write_versions != (GraphVersion(key, (0 if stage.before_job is None else
                next(v.revision for v in stage.stage.read_versions if v.key == key)) + 1),)
            or get_job(db, stage.after_job.job_id) != stage.after_job):
        raise ValueError("Owner task responsibility signature requires its exact job same-W01 receipt")
    if stage.before_job is not None: return ()
    ref = owner_source_note_task_ids_v1(stage.responsibility.namespace, stage.responsibility.owner_operation_id)["responsibility_ref"]
    value = _record(db, issuer=installed_readers.issuer, namespace=stage.responsibility.namespace,
        kind=RESPONSIBILITY_KIND, ref=ref, operation_id=receipt.operation_id, value=stage.responsibility)
    if read_owner_source_note_task_responsibility_v2(db, namespace=stage.responsibility.namespace,
            original_ref=ref, issuer=installed_readers.issuer) is None:
        raise ValueError("Owner task signed responsibility is absent after its actual job CAS")
    return (value,)


def read_plan_owner_source_note_task_execution_v1(db, *, namespace, operation_kind, request, installed_readers):
    evidence = installed_readers.current(); auth = evidence.authorization
    keys = [version.key for version in evidence.read_versions]
    originals = [auth.original_ref, auth.cause.original_ref]
    if operation_kind != CREATE_OPERATION: originals.append(evidence.responsibility_ref)
    if operation_kind == CHECKPOINT_OPERATION:
        from .d11_life_preparation_v1 import TABLE
        for operation_id in request.continuation.completed_original_refs:
            if read_adopted_domain_operation_v1(db, namespace, operation_id) is not None:
                originals.append(operation_id)
            else:
                rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
                    "AND kind='adopted_life' AND producing_operation_id=? LIMIT 2", (*namespace.as_tuple, operation_id)).fetchall()
                if len(rows) != 1:
                    raise MissingProductionOriginalV1("actual_same_task_completed_W01_operation:" + operation_id)
                originals.append(rows[0][0])
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_execution_original_v1
        execution = require_owner_source_note_task_execution_original_v1(installed_readers.issued,
            installed_readers.graph, installed_readers.scope)
        if execution is not None:
            originals.extend((execution[0].binding.prepared_original_ref, execution[0].prepare_operation_id))
        if evidence.completed_settlement is not None:
            keys.extend(version.key for version in evidence.completed_settlement.read_versions)
    return production_read_plan_v1((), keys, auth.source_refs, tuple(dict.fromkeys(originals)))


def decode_owner_source_note_task_job_v1(raw, *, namespace=None):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(PersistentJob)}:
        raise ValueError("Owner task PersistentJob fields must match its closed installed carrier")
    job = PersistentJob(**raw)
    cont = owner_source_note_task_from_wire_v1(dict(job.continuation), OwnerSourceNoteTaskContinuationV2)
    ns = NamespaceId(job.bot_id, job.persona_id)
    if (namespace is not None and namespace != ns or job.work_kind != TASK_WORK_KIND or job.effect_id is not None
            or not job.job_id.startswith("owner-note-job:") or not job.operation_id.startswith("owner-note-create:")
            or not job.activity_id.startswith("owner-note-task:") or job.operator_versions not in ({}, {"d11.personal-semantic-mesh":"1"}) or job.usage != {}
            or job.cancel_epoch != cont.cancel_generation
            or any(NamespaceId.from_key(AtomKey.from_token(ref)) != ns for ref in cont.source_refs)
            or job.phase == "completed" and (cont.step != "completed" or cont.pending_effect_refs or job.result_ref is None)
            or cont.step == "completed" and job.phase != "completed"
            or job.phase == "running" and (job.lease_holder is None or job.lease_expires_utc is None or job.fence < 1)
            or job.lease_expires_utc is not None and _utc(job.lease_expires_utc,"lease") > _utc(job.deadline_utc,"deadline")):
        raise ValueError("Owner task carrier lost its original namespace, bounded phase, cancellation or worker lease")
    if len(canonical_serialize(raw).encode("utf-8")) > 65536:
        raise ValueError("Owner task carrier exceeds its original metadata bound")
    return job
