"""Persistent, fenced jobs that share the coordinator's business database."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Mapping


MAX_JSON_BYTES = 65_536
MAX_LEASE_SECONDS = 3_600
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PHASES = frozenset({
    "queued", "running", "waiting", "deferred", "draining", "cancelled",
    "completed", "failed", "pending_confirmation",
})


class JobError(RuntimeError):
    pass


class JobConflict(JobError):
    pass


class JobNotRunnable(JobError):
    pass


class JobFenceRejected(JobError):
    pass


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("digest must be 64 lowercase hex characters")
    return value


def _json(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("job JSON must be finite and serializable") from exc
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("job JSON exceeds the bounded payload size")
    return encoded


def _utc(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 35:
        raise ValueError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include an offset")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class PersistentJob:
    job_id: str
    operation_id: str
    activity_id: str
    effect_id: str | None
    bot_id: str
    persona_id: str
    snapshot_ref: str
    phase: str
    work_kind: str
    continuation: Mapping[str, Any]
    wake_condition: Mapping[str, Any] | None
    deadline_utc: str
    budget_ref: str
    resource_ref: str
    operator_versions: Mapping[str, str]
    lease_holder: str | None
    lease_expires_utc: str | None
    fence: int
    cancel_epoch: int
    usage: Mapping[str, int]
    result_ref: str | None
    _canonical_columns: InitVar[object | None] = None

    def __post_init__(self, _canonical_columns) -> None:
        for field, value in (
            ("job_id", self.job_id), ("operation_id", self.operation_id),
            ("activity_id", self.activity_id), ("bot_id", self.bot_id),
            ("persona_id", self.persona_id), ("snapshot_ref", self.snapshot_ref),
            ("work_kind", self.work_kind), ("budget_ref", self.budget_ref),
            ("resource_ref", self.resource_ref),
        ):
            _identifier(value, field)
        if self.effect_id is not None:
            _identifier(self.effect_id, "effect_id")
        if self.phase not in _PHASES:
            raise ValueError("invalid job phase")
        if self.lease_holder is not None:
            _identifier(self.lease_holder, "lease_holder")
        if self.result_ref is not None:
            _identifier(self.result_ref, "result_ref")
        _utc(self.deadline_utc, "deadline_utc")
        _utc(self.lease_expires_utc, "lease_expires_utc")
        if not isinstance(self.fence, int) or self.fence < 0:
            raise ValueError("fence must be a non-negative integer")
        if not isinstance(self.cancel_epoch, int) or self.cancel_epoch < 0:
            raise ValueError("cancel_epoch must be a non-negative integer")
        if (self.lease_holder is None) != (self.lease_expires_utc is None):
            raise ValueError("lease holder and expiry must be present together")
        if self.phase in {"waiting", "queued", "deferred", "cancelled", "completed", "failed"} and self.lease_holder is not None:
            raise ValueError("non-running job cannot retain a worker lease")
        if self.phase == "waiting" and self.wake_condition is None:
            raise ValueError("waiting job requires a wake condition")
        if self.phase != "waiting" and self.wake_condition is not None:
            raise ValueError("only waiting jobs may carry a wake condition")
        if _canonical_columns is None:
            _json(self.continuation)
            _json(self.wake_condition)
            _json(self.operator_versions)
        else:
            from ..authority_service.current_authority_graph_read_v3 import (
                PreparedAuthorityJobColumnsV3,require_authority_job_columns_v3)
            if type(_canonical_columns)is not PreparedAuthorityJobColumnsV3:
                raise TypeError('job columns require an actual issued canonical row original')
            require_authority_job_columns_v3(_canonical_columns,self)
        usage = dict(self.usage)
        if len(usage) > 32:
            raise ValueError("job usage has too many dimensions")
        for name, amount in usage.items():
            _identifier(name, "usage dimension")
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
                raise ValueError("job usage values must be non-negative integers")


def install_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_jobs(
            job_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            activity_id TEXT NOT NULL,
            effect_id TEXT,
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            snapshot_ref TEXT NOT NULL,
            phase TEXT NOT NULL,
            work_kind TEXT NOT NULL,
            continuation_json TEXT NOT NULL,
            wake_condition_json TEXT,
            deadline_utc TEXT NOT NULL,
            budget_ref TEXT NOT NULL,
            resource_ref TEXT NOT NULL,
            operator_versions_json TEXT NOT NULL,
            lease_holder TEXT,
            lease_expires_utc TEXT,
            fence INTEGER NOT NULL,
            cancel_epoch INTEGER NOT NULL,
            usage_json TEXT NOT NULL,
            result_ref TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_job_operations(
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            digest TEXT NOT NULL,
            job_id TEXT NOT NULL,
            job_json TEXT NOT NULL,
            PRIMARY KEY(bot_id,persona_id,operation_id,phase)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS runtime_jobs_d13_namespace_kind "
               "ON runtime_jobs(bot_id,persona_id,work_kind)")


def _job_dict(job: PersistentJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id, "operation_id": job.operation_id,
        "activity_id": job.activity_id, "effect_id": job.effect_id,
        "bot_id": job.bot_id, "persona_id": job.persona_id,
        "snapshot_ref": job.snapshot_ref, "phase": job.phase,
        "work_kind": job.work_kind, "continuation": job.continuation,
        "wake_condition": job.wake_condition, "deadline_utc": job.deadline_utc,
        "budget_ref": job.budget_ref, "resource_ref": job.resource_ref,
        "operator_versions": job.operator_versions,
        "lease_holder": job.lease_holder,
        "lease_expires_utc": job.lease_expires_utc, "fence": job.fence,
        "cancel_epoch": job.cancel_epoch, "usage": job.usage,
        "result_ref": job.result_ref,
    }


def _job_from_dict(value: Mapping[str, Any]) -> PersistentJob:
    if value["work_kind"] == "d11.foreground_cycle.v1":
        if value["continuation"].get("schema") == "d11.owner-source-note-task-continuation.v2":
            from .owner_source_note_task_execution_v1 import decode_owner_source_note_task_job_v1
            return decode_owner_source_note_task_job_v1(value)
        from .foreground_cycle_v1 import decode_foreground_job_v1
        return decode_foreground_job_v1(value)
    return PersistentJob(**value)


def _job_from_row(row) -> PersistentJob:
    from .domain_background_read_v3 import background_json_loads_v3
    if row is None:
        raise JobConflict("job does not exist")
    job = PersistentJob(
        row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8],
        background_json_loads_v3(row[9]), background_json_loads_v3(row[10]) if row[10] is not None else None,
        row[11], row[12], row[13], background_json_loads_v3(row[14]), row[15], row[16],
        row[17], row[18], background_json_loads_v3(row[19]), row[20],
    )
    if job.work_kind == "d11.foreground_cycle.v1":
        return _job_from_dict(_job_dict(job))
    return job


_JOB_SELECT = (
    "SELECT job_id,operation_id,activity_id,effect_id,bot_id,persona_id,snapshot_ref,"
    "phase,work_kind,continuation_json,wake_condition_json,deadline_utc,budget_ref,"
    "resource_ref,operator_versions_json,lease_holder,lease_expires_utc,fence,"
    "cancel_epoch,usage_json,result_ref FROM runtime_jobs WHERE job_id=?"
)


def get_job(db, job_id: str) -> PersistentJob:
    _identifier(job_id, "job_id")
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_job_v3
    bound,job=read_bound_authority_job_v3(db,job_id=job_id)
    if not bound:
        from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
        row=model_reply_scope_point_v3(db,table='runtime_jobs',
            columns=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref','phase','work_kind',
                'continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref','operator_versions_json',
                'lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref'),
            key_columns=('job_id',),key=(job_id,),legacy_reader=lambda:db.execute(_JOB_SELECT,(job_id,)).fetchone())
        job=_job_from_row(row)
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    def family(lease_id,columns):
        return model_reply_scope_point_v3(db,table='runtime_budget_leases',columns=columns,
            key_columns=('lease_id',),key=(lease_id,),legacy_reader=lambda:db.execute(
                'SELECT '+','.join(columns)+' FROM runtime_budget_leases WHERE lease_id=?',(lease_id,)).fetchone())
    if job.work_kind == "d11.foreground_cycle.v1" and job.continuation.get("schema") == "d11.owner-source-note-task-continuation.v2":
        root = family(job.budget_ref,('bot_id','persona_id'))
        if root != (job.bot_id,job.persona_id):
            raise JobConflict("Owner task current job lost its actual original parent namespace")
        return job
    if job.work_kind == "d11.foreground_cycle.v1":
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
        plan = foreground_cycle_from_wire_v1(job.continuation).call_plan
        root = family(job.budget_ref,('bot_id','persona_id'))
        child = family(plan.protected_reply_lease_ref,('parent_id','bot_id','persona_id'))
        if root != (job.bot_id, job.persona_id) or child != (job.budget_ref, job.bot_id, job.persona_id):
            raise JobConflict("foreground current job lost its actual original root/protected-child family")
    return job


def _save_job(db, job: PersistentJob) -> None:
    changed = db.execute(
        "UPDATE runtime_jobs SET snapshot_ref=?,phase=?,continuation_json=?,"
        "wake_condition_json=?,lease_holder=?,lease_expires_utc=?,fence=?,"
        "cancel_epoch=?,usage_json=?,result_ref=? WHERE job_id=?",
        (job.snapshot_ref, job.phase, _json(job.continuation),
         _json(job.wake_condition) if job.wake_condition is not None else None,
         job.lease_holder, job.lease_expires_utc, job.fence, job.cancel_epoch,
         _json(job.usage), job.result_ref, job.job_id),
    ).rowcount
    if changed != 1:
        raise JobConflict("job disappeared")


def _prior_operation(db, job: PersistentJob, operation_id: str,
                     phase: str, digest: str) -> PersistentJob | None:
    row = db.execute(
        "SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? "
        "AND persona_id=? AND operation_id=? AND phase=?",
        (job.bot_id, job.persona_id, operation_id, phase),
    ).fetchone()
    if row is None:
        return None
    if row[0] != digest or row[1] != job.job_id:
        raise JobConflict("operation identity was reused with different input")
    return _job_from_dict(json.loads(row[2]))


def _record_operation(db, job: PersistentJob, operation_id: str,
                      phase: str, digest: str) -> None:
    db.execute(
        "INSERT INTO runtime_job_operations(bot_id,persona_id,operation_id,phase,"
        "digest,job_id,job_json) VALUES(?,?,?,?,?,?,?)",
        (job.bot_id, job.persona_id, operation_id, phase, digest,
         job.job_id, _json(_job_dict(job))),
    )


def create_job(db, job: PersistentJob, operation_id: str, digest: str) -> PersistentJob:
    if not isinstance(job, PersistentJob):
        raise TypeError("job must be PersistentJob")
    _identifier(operation_id, "operation_id")
    _digest(digest)
    row = db.execute(
        "SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? "
        "AND persona_id=? AND operation_id=? AND phase='create'",
        (job.bot_id, job.persona_id, operation_id),
    ).fetchone()
    if row is not None:
        if row[0] != digest or row[1] != job.job_id:
            raise JobConflict("operation identity was reused with different input")
        return _job_from_dict(json.loads(row[2]))
    if db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?", (job.job_id,)).fetchone():
        raise JobConflict("job ID already exists")
    if job.fence != 0 or job.cancel_epoch != 0 or job.lease_holder is not None:
        raise ValueError("new job must not carry a worker lease or prior epochs")
    db.execute(
        "INSERT INTO runtime_jobs(job_id,operation_id,activity_id,effect_id,bot_id,"
        "persona_id,snapshot_ref,phase,work_kind,continuation_json,wake_condition_json,"
        "deadline_utc,budget_ref,resource_ref,operator_versions_json,lease_holder,"
        "lease_expires_utc,fence,cancel_epoch,usage_json,result_ref) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (job.job_id, job.operation_id, job.activity_id, job.effect_id, job.bot_id,
         job.persona_id, job.snapshot_ref, job.phase, job.work_kind,
         _json(job.continuation),
         _json(job.wake_condition) if job.wake_condition is not None else None,
         job.deadline_utc, job.budget_ref, job.resource_ref,
         _json(job.operator_versions), job.lease_holder, job.lease_expires_utc,
         job.fence, job.cancel_epoch, _json(job.usage), job.result_ref),
    )
    _record_operation(db, job, operation_id, "create", digest)
    return job


def acquire_job(db, job_id: str, holder: str, *, now_utc: str,
                lease_seconds: int) -> PersistentJob:
    job = get_job(db, job_id)
    updated = plan_job_acquire(job, holder, now_utc=now_utc,
                               lease_seconds=lease_seconds)
    if updated != job:
        _save_job(db, updated)
    return updated


def plan_job_acquire(job: PersistentJob, holder: str, *, now_utc: str,
                     lease_seconds: int) -> PersistentJob:
    """Preview an exact lease mutation before the fenced graph transaction."""
    if not isinstance(job, PersistentJob):
        raise TypeError("job must be PersistentJob")
    _identifier(holder, "holder")
    now = _utc(now_utc, "now_utc")
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= MAX_LEASE_SECONDS:
        raise ValueError("lease_seconds is outside the supported range")
    if now >= _utc(job.deadline_utc, "deadline_utc"):
        raise JobNotRunnable("job deadline has expired")
    if job.phase == "running":
        expires = _utc(job.lease_expires_utc, "lease_expires_utc")
        if expires is not None and expires > now:
            if job.lease_holder == holder:
                return job
            raise JobNotRunnable("job already has a live worker lease")
        # Expired work may be resumed under a new fencing token.  External
        # effects still require their own execution-journal recovery check.
    elif job.phase != "queued":
        raise JobNotRunnable(f"job phase {job.phase} is not runnable")
    expires = now + timedelta(seconds=lease_seconds)
    if job.work_kind == "d11.foreground_cycle.v1":
        expires = min(expires, _utc(job.deadline_utc, "deadline_utc"))
    return replace(
        job, phase="running", lease_holder=holder,
        lease_expires_utc=_utc_text(expires),
        fence=job.fence + 1,
    )


def _assert_fence(job: PersistentJob, holder: str, fence: int) -> None:
    if (job.phase not in {"running", "draining"} or job.lease_holder != holder
            or job.fence != fence):
        raise JobFenceRejected("worker lease or fencing token is stale")


def checkpoint_job(db, job_id: str, holder: str, fence: int, *,
                   continuation: Mapping[str, Any], usage: Mapping[str, int],
                   snapshot_ref: str | None = None) -> PersistentJob:
    job = get_job(db, job_id)
    _assert_fence(job, holder, fence)
    if job.phase != "running" or job.cancel_epoch:
        raise JobFenceRejected("cancelled work cannot checkpoint a resumable result")
    new_snapshot = snapshot_ref or job.snapshot_ref
    _identifier(new_snapshot, "snapshot_ref")
    new_usage = dict(usage)
    if any(new_usage.get(dimension, 0) < amount
           for dimension, amount in job.usage.items()):
        raise JobConflict("job usage cannot decrease across checkpoint or retry")
    updated = replace(job, snapshot_ref=new_snapshot,
                      continuation=dict(continuation), usage=new_usage)
    _save_job(db, updated)
    return updated


def transition_job(db, job_id: str, holder: str, fence: int, *,
                   target_phase: str, result_ref: str | None = None,
                   wake_condition: Mapping[str, Any] | None = None) -> PersistentJob:
    if target_phase not in {"waiting", "deferred", "completed", "failed", "cancelled", "pending_confirmation"}:
        raise ValueError("invalid worker transition")
    job = get_job(db, job_id)
    _assert_fence(job, holder, fence)
    if job.phase == "draining" and target_phase != "cancelled":
        raise JobFenceRejected("draining job may only acknowledge cancellation")
    if target_phase == "completed" and not result_ref:
        raise ValueError("completed job requires a result reference")
    if result_ref is not None:
        _identifier(result_ref, "result_ref")
    if target_phase == "waiting" and wake_condition is None:
        raise ValueError("waiting transition requires a wake condition")
    updated = replace(
        job, phase=target_phase, result_ref=result_ref,
        wake_condition=dict(wake_condition) if target_phase == "waiting" else None,
        lease_holder=None, lease_expires_utc=None,
    )
    _save_job(db, updated)
    return updated


def wake_job(db, job_id: str, operation_id: str, digest: str) -> PersistentJob:
    _identifier(operation_id, "operation_id")
    _digest(digest)
    job = get_job(db, job_id)
    prior = _prior_operation(db, job, operation_id, "wake", digest)
    if prior is not None:
        return prior
    if job.phase not in {"waiting", "deferred"}:
        raise JobNotRunnable("only waiting or deferred jobs can be woken")
    updated = replace(job, phase="queued", wake_condition=None)
    _save_job(db, updated)
    _record_operation(db, updated, operation_id, "wake", digest)
    return updated


def cancel_job(db, job_id: str, operation_id: str, digest: str) -> PersistentJob:
    _identifier(operation_id, "operation_id")
    _digest(digest)
    job = get_job(db, job_id)
    prior = _prior_operation(db, job, operation_id, "cancel", digest)
    if prior is not None:
        return prior
    if job.phase in {"completed", "failed", "cancelled"}:
        updated = job
    elif job.lease_holder is not None:
        # Retain the holder so draining still occupies its worker slot, but
        # advance the fence so its old result can no longer be published.
        updated = replace(job, phase="draining", cancel_epoch=job.cancel_epoch + 1,
                          fence=job.fence + 1)
    else:
        updated = replace(job, phase="cancelled", cancel_epoch=job.cancel_epoch + 1,
                          wake_condition=None)
    _save_job(db, updated)
    _record_operation(db, updated, operation_id, "cancel", digest)
    return updated


__all__ = [
    "JobConflict", "JobError", "JobFenceRejected", "JobNotRunnable",
    "PersistentJob", "acquire_job", "cancel_job", "checkpoint_job",
    "create_job", "get_job", "install_schema", "plan_job_acquire",
    "transition_job", "wake_job",
]
