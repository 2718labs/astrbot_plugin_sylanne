"""Owner cancellation of a signed SourceNote task in its actual W01 CAS."""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d08_project_control_v1 import InstalledProjectControlReadersV1, install_project_control_readers_v1
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, runtime_job_key, job_graph_write
from .jobs import get_job, _save_job, _record_operation, _prior_operation
from .owner_source_note_task_contract_v1 import (OwnerSourceNoteTaskContinuationV2,
    owner_source_note_task_from_wire_v1, owner_source_note_task_ids_v1)
from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2

OPERATION = "cancel_owner_source_note_task_v1"


@dataclass(frozen=True, slots=True)
class CancelOwnerSourceNoteTaskRequestV1:
    owner_operation_id: str

    def __post_init__(self):
        if type(self.owner_operation_id) is not str or not 1 <= len(self.owner_operation_id) <= 128:
            raise ValueError("Owner task cancellation requires the actual bounded original Submit operation ID")


def owner_source_note_task_cancel_operation_id_v1(namespace, owner_operation_id):
    CancelOwnerSourceNoteTaskRequestV1(owner_operation_id)
    return "owner-note-cancel:" + canonical_digest((namespace, owner_operation_id))[:40]


def install_cancel_owner_source_note_task_readers_v1(graph, *, scope, owner_guard, owner_binding):
    return install_project_control_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)


def _authorization(db, *, namespace, request, issuer):
    ids = owner_source_note_task_ids_v1(namespace, request.owner_operation_id)
    from .d11_life_preparation_v1 import TABLE
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
        "AND kind='owner_source_note_task_authorization_v2' AND producing_operation_id=? LIMIT 2",
        (*namespace.as_tuple, request.owner_operation_id)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("actual_signed_Owner_task_to_cancel")
    saved = read_owner_source_note_task_authorization_v2(db, namespace=namespace, original_ref=rows[0][0], issuer=issuer)
    if saved is None or saved[0].cause.owner_operation_id != request.owner_operation_id:
        raise MissingProductionOriginalV1("actual_Owner_task_Submit_to_cancel")
    return ids, saved[0]


def _plan_cancel(job):
    """Exactly jobs.cancel_job transitions, with the final continuation recorded once."""
    if job.phase in {"completed", "failed", "cancelled"}:
        return job
    if job.lease_holder is not None:
        updated = replace(job, phase="draining", cancel_epoch=job.cancel_epoch + 1, fence=job.fence + 1)
    else:
        updated = replace(job, phase="cancelled", cancel_epoch=job.cancel_epoch + 1, wake_condition=None)
    old = owner_source_note_task_from_wire_v1(dict(job.continuation), OwnerSourceNoteTaskContinuationV2)
    return replace(updated, continuation=plain_v1(replace(old, cancel_generation=updated.cancel_epoch)))


@dataclass(frozen=True, slots=True)
class CancelOwnerSourceNoteTaskStageV1:
    frame: object
    request: CancelOwnerSourceNoteTaskRequestV1
    before_job: object
    after_job: object
    stage: object


def stage_cancel_owner_source_note_task_v1(db, *, frame, request, installed_readers):
    if type(request) is not CancelOwnerSourceNoteTaskRequestV1 or type(installed_readers) is not InstalledProjectControlReadersV1:
        raise TypeError("Owner cancellation requires its exact current Owner control binding")
    read = CurrentDomainReadV1(frame); read.check(db)
    readers = installed_readers
    owner, authority = readers.owner_binding, frame.envelope.authority
    if (authority.actor != owner.actor or "workbench.control" not in owner.capabilities
            or authority.purpose != "workbench_user_action" or authority.audience != ("owner",)
            or authority.purpose not in owner.purposes or "owner" not in owner.audiences
            or readers.owner_guard.authorization_head.removeprefix("sha256:") != frame.owner_guard.owner_head_digest
            or frame.owner_guard.grant_ref != owner_grant_key(*authority.namespace.as_tuple).token
            or (frame.owner_guard.grant_revision,frame.owner_guard.grant_digest) != (owner.grant_revision,owner.grant_digest)
            or frame.activation_generation != readers.activation_generation
            or authority.activation_generation != readers.activation_generation):
        raise ValueError("Owner task cancellation lost this actual Owner actor/grant/lease/activation")
    grant = read.head(db, owner_grant_key(*authority.namespace.as_tuple), required=True)
    if grant.revision != frame.owner_guard.grant_revision or canonical_digest(grant.value) != frame.owner_guard.grant_digest:
        raise ValueError("Owner cancellation changed its current Owner grant head")
    ids, auth = _authorization(db, namespace=authority.namespace, request=request, issuer=readers.issuer)
    if (auth.cause.owner_actor_ref != authority.actor
            or frame.envelope.identity.operation_id != owner_source_note_task_cancel_operation_id_v1(authority.namespace,request.owner_operation_id)
            or frame.envelope.identity.activity_id != ids["activity_id"]
            or frame.envelope.parent_budget_lease_ref != auth.cause.parent_budget_lease_ref):
        raise ValueError("Owner cancellation belongs to another original Owner task or Root")
    read.original(auth.original_ref); read.original(auth.cause.original_ref)
    key = runtime_job_key(*authority.namespace.as_tuple,ids["activity_id"],ids["job_id"])
    atom = read.head(db,key,required=True)
    job = get_job(db,ids["job_id"])
    if job is None:
        raise MissingProductionOriginalV1("actual_Owner_task_not_started")
    cont = owner_source_note_task_from_wire_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
    signed = read_owner_source_note_task_responsibility_v2(db,namespace=authority.namespace,
        original_ref=cont.responsibility_ref,issuer=readers.issuer)
    if (signed is None or signed[1] != auth or job_graph_write(job).key != key or atom.value != job_graph_write(job).value
            or job.operation_id != ids["create_operation_id"] or job.activity_id != ids["activity_id"]
            or job.budget_ref != auth.cause.parent_budget_lease_ref
            or cont.authorization_original_ref != auth.original_ref or cont.authorization_original_digest != auth.digest
            or cont.cause_original_ref != auth.cause.original_ref or cont.cause_original_digest != auth.cause.digest
            or cont.responsibility_ref != ids["responsibility_ref"] or cont.responsibility_digest != signed[0].digest
            or cont.source_refs != auth.source_refs or cont.cancel_generation != job.cancel_epoch):
        raise ValueError("Owner cancellation lost its unique actual SQL/Graph job and signed task responsibility")
    read.original(cont.responsibility_ref)
    after = _plan_cancel(job)
    stage = stage_result_v1(frame,"d11",OPERATION,request,
        writes=() if after == job else (job_graph_write(after),),
        provenance={"before_job":job,"after_job":after,"owner_task_responsibility":signed[0],
            "owner_task_authorization_ref":auth.original_ref,"noop":after == job},
        proposal_schema=D11_PROPOSAL_SCHEMA,proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return verify_cancel_owner_source_note_task_stage_v1(CancelOwnerSourceNoteTaskStageV1(frame,request,job,after,stage))


def verify_cancel_owner_source_note_task_stage_v1(stage):
    if type(stage) is not CancelOwnerSourceNoteTaskStageV1 or type(stage.request) is not CancelOwnerSourceNoteTaskRequestV1:
        raise TypeError("actual frozen Owner task cancellation stage required")
    expected = _plan_cancel(stage.before_job)
    if (stage.after_job != expected or stage.stage.domain != "d11" or stage.stage.operation_kind != OPERATION
            or stage.stage.operation_id != stage.frame.envelope.identity.operation_id
            or tuple(write for proposal in stage.stage.proposals for write in proposal.typed_writes)
                != (() if stage.after_job == stage.before_job else (job_graph_write(stage.after_job),))):
        raise ValueError("Owner task cancellation changed the existing deterministic cancel transition")
    return stage


def apply_cancel_owner_source_note_task_in_transaction_v1(db, *, stage):
    verify_cancel_owner_source_note_task_stage_v1(stage)
    if not db.in_transaction or get_job(db,stage.before_job.job_id) != stage.before_job:
        raise ValueError("Owner cancellation must share the actual current job W01 transaction")
    digest = canonical_digest(stage.request)
    prior = _prior_operation(db,stage.before_job,stage.stage.operation_id,"cancel",digest)
    if prior is not None:
        if prior != stage.after_job:
            raise ValueError("Owner cancel operation already has another actual final snapshot")
        return
    # Record the final job once: cancel_epoch and continuation generation match,
    # including the operation snapshot later returned by jobs._prior_operation.
    _save_job(db,stage.after_job)
    _record_operation(db,stage.after_job,stage.stage.operation_id,"cancel",digest)


def record_cancel_owner_source_note_task_after_cas_v1(db, *, frame, stage, receipt, installed_readers):
    verify_cancel_owner_source_note_task_stage_v1(stage)
    key = job_graph_write(stage.after_job).key
    before_version = next(version.revision for version in stage.stage.read_versions if version.key == key)
    expected = () if stage.before_job == stage.after_job else (GraphVersion(key,before_version+1),)
    if (not db.in_transaction or receipt.status != "committed" or receipt.operation_id != stage.stage.operation_id
            or receipt.write_versions != expected or get_job(db,stage.after_job.job_id) != stage.after_job):
        raise ValueError("Owner cancellation receipt lost its exact final SQL/Graph same-W01 member")
    return ()


def read_plan_cancel_owner_source_note_task_v1(db, *, namespace, request, installed_readers):
    ids,auth = _authorization(db,namespace=namespace,request=request,issuer=installed_readers.issuer)
    key = runtime_job_key(*namespace.as_tuple,ids["activity_id"],ids["job_id"])
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),key),(),
        (auth.original_ref,auth.cause.original_ref,ids["responsibility_ref"]))
