"""Durable identity link for a D08 dispatch action and its D11 job.

The binding records an admission-time job fence and cancellation epoch.  It
does not decide whether an action is currently uncancelled or permit sending.
Callers must re-read the job and Authority effect under the final graph fence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from ..runtime_storage_v3 import read_graph_row_v3
from ..contracts import canonical_json
from ..domains.d08.execution import ActionIntent
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, canonical_digest
from .d11_types import job_graph_write
from .dispatch_admission import (
    DispatchAdmissionReceiptV1, DispatchAdmissionV1, load_admission,
)
from .jobs import PersistentJob, get_job


SCHEMA = "sylanne.d08_d11.dispatch_action_job_binding.v1"


def _is_post_c02_reply_waiting_job(
        job: PersistentJob, action: ActionIntent,
        admission: DispatchAdmissionV1) -> bool:
    """Recognize the one signed message job shape held for host takeover."""
    return (
        action.action_kind == "message"
        and action.purpose == "expression"
        and admission.operation_id.startswith("post-c02-reply:")
        and job.work_kind == "message"
        and job.phase == "waiting"
        and job.wake_condition == {
            "kind": "post_c02_reply_host_takeover",
            "operation_id": admission.operation_id,
        }
    )


@dataclass(frozen=True)
class DispatchActionJobBindingV1:
    namespace: str
    action_id: str
    attempt_id: str
    activity_id: str
    effect_id: str
    operation_id: str
    admission_ref: str
    admission_receipt_digest: str
    action_digest: str
    action_graph_revision: int
    job_id: str
    job_graph_revision: int
    job_fence: int
    job_cancel_epoch: int
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unsupported action/job binding schema")
        for name in ("namespace", "action_id", "attempt_id", "activity_id",
                     "effect_id", "operation_id", "admission_ref", "job_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"invalid binding {name}")
        for name in ("admission_receipt_digest", "action_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"invalid binding {name}")
        for name in ("action_graph_revision", "job_graph_revision"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"invalid binding {name}")
        for name in ("job_fence", "job_cancel_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"invalid binding {name}")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def install_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_dispatch_action_job_bindings_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        action_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
        admission_ref TEXT NOT NULL, job_id TEXT NOT NULL,
        binding_json TEXT NOT NULL, binding_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,action_id,attempt_id),
        UNIQUE(bot,persona,admission_ref), UNIQUE(job_id),
        FOREIGN KEY(job_id) REFERENCES runtime_jobs(job_id),
        FOREIGN KEY(bot,persona,admission_ref)
            REFERENCES graph_dispatch_admissions(bot,persona,admission_ref)
    )""")


def _graph_revision(db, key: AtomKey, value: object, kind: str) -> int:
    row = read_graph_row_v3(db, columns=('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=? AND type_name=?', parameters=(key.token, key.owner.bot, key.owner.persona, key.type_name))
    if (row is None or row[2] != 1 or type(row[0]) is not int or row[0] < 1
            or row[1] != canonical_json(value)):
        raise ValueError(f"current {kind} graph row differs")
    return row[0]


def load_action_job_binding(
    db, namespace: NamespaceId, admission_ref: str,
) -> DispatchActionJobBindingV1 | None:
    """Read stored identity evidence; this is neither a cancellation nor send check."""
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace must be NamespaceId")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                  "AND name='graph_dispatch_action_job_bindings_v1'").fetchone() is None:
        return None
    row = db.execute(
        "SELECT action_id,attempt_id,job_id,binding_json,binding_digest "
        "FROM graph_dispatch_action_job_bindings_v1 "
        "WHERE bot=? AND persona=? AND admission_ref=?",
        namespace.as_tuple + (admission_ref,),
    ).fetchone()
    if row is None:
        return None
    data = json.loads(row[3])
    if type(data) is not dict or set(data) != set(DispatchActionJobBindingV1.__dataclass_fields__):
        raise ValueError("stored action/job binding shape differs")
    binding = DispatchActionJobBindingV1(**data)
    if (row[:3] != (binding.action_id, binding.attempt_id, binding.job_id)
            or row[3] != canonical_json(asdict(binding))
            or row[4] != binding.digest
            or binding.namespace != "/".join(namespace.as_tuple)
            or binding.admission_ref != admission_ref):
        raise ValueError("stored action/job binding digest differs")
    admission = load_admission(db, namespace, admission_ref)
    if (admission is None
            or binding.admission_receipt_digest != admission.receipt_digest
            or (binding.activity_id, binding.effect_id, binding.attempt_id,
                binding.operation_id, binding.action_id, binding.action_digest) != (
                    admission.admission.activity_id, admission.admission.effect_id,
                    admission.admission.attempt_id, admission.admission.operation_id,
                    admission.admission.action_ref,
                    admission.admission.action_intent_digest)):
        raise ValueError("stored action/job binding admission differs")
    return binding


def bind_action_job(
    db, action: ActionIntent, receipt: DispatchAdmissionReceiptV1, *, contact_issuance=None,
) -> DispatchActionJobBindingV1:
    """Bind the unique live job to an inserted admission in its graph transaction."""
    if not db.in_transaction:
        raise ValueError("action/job binding requires the graph transaction")
    if type(action) is not ActionIntent or type(receipt) is not DispatchAdmissionReceiptV1:
        raise TypeError("typed action and dispatch admission receipt are required")
    admission = receipt.admission
    parts = admission.namespace.split("/", 1)
    if len(parts) != 2:
        raise ValueError("invalid admission namespace")
    namespace = NamespaceId(*parts)
    if (load_admission(db, namespace, admission.admission_ref) != receipt
            or admission.action_intent_digest != canonical_digest(action)
            or admission.action_ref != action.action_id
            or (admission.activity_id, admission.effect_id,
                admission.attempt_id, admission.operation_id) != (
                    action.identity.activity_id, action.identity.effect_id,
                    action.identity.attempt_id, action.identity.operation_id)):
        raise ValueError("action or admission identity differs")
    contact_job = None
    if contact_issuance is not None:
        from .contact_final_stage_v1 import require_contact_action_job_v1
        from .contact_final_stage_v2 import _ContactFinalCommitWitnessV2, require_contact_action_job_v2
        from .contact_final_stage_v3 import _ContactFinalCommitWitnessV3, require_contact_action_job_v3
        require_contact = require_contact_action_job_v3 if type(contact_issuance) is _ContactFinalCommitWitnessV3 else require_contact_action_job_v2 if type(contact_issuance) is _ContactFinalCommitWitnessV2 else require_contact_action_job_v1
        contact_job = require_contact(contact_issuance, db, action, admission)
    # An exact replay reports only its original historical identity.  Job
    # progress after admission belongs to the final current-state check.
    prior = load_action_job_binding(db, namespace, admission.admission_ref)
    if prior is not None:
        if (prior.action_id, prior.attempt_id, prior.activity_id,
            prior.effect_id, prior.operation_id, prior.action_digest) != (
                action.action_id, admission.attempt_id, admission.activity_id,
                admission.effect_id, admission.operation_id,
                admission.action_intent_digest):
            raise ValueError("action/job binding replay differs")
        return prior
    owner = Owner("activity", *namespace.as_tuple, action.identity.activity_id)
    action_key = AtomKey(owner, "d08.action_intent.v1", action.action_id)
    action_revision = _graph_revision(
        db, action_key, json.loads(json.dumps(asdict(action))), "action")
    if action_revision != action.revision:
        raise ValueError("action graph revision differs")
    rows = db.execute(
        "SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND (operation_id=? OR effect_id=?) ORDER BY job_id",
        namespace.as_tuple + (admission.operation_id, admission.effect_id),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("dispatch admission lacks a unique job")
    job = get_job(db, rows[0][0])
    post_c02_reply_job = _is_post_c02_reply_waiting_job(
        job, action, admission)
    if ((job.bot_id, job.persona_id, job.activity_id, job.effect_id,
         job.operation_id) != (
             *namespace.as_tuple, admission.activity_id, admission.effect_id,
             admission.operation_id)
            or not (job.work_kind == "dispatch" or post_c02_reply_job or (contact_job is not None and job == contact_job))
            or job.budget_ref != admission.budget_lease_ref
            or job.phase not in {"queued", "running", "waiting", "deferred"}
            or job.cancel_epoch != 0):
        raise ValueError("dispatch job identity or cancellation differs")
    graph_job = job_graph_write(job)
    job_revision = _graph_revision(db, graph_job.key, graph_job.value, "job")
    binding = DispatchActionJobBindingV1(
        admission.namespace, action.action_id, admission.attempt_id,
        admission.activity_id, admission.effect_id, admission.operation_id,
        admission.admission_ref, receipt.receipt_digest,
        admission.action_intent_digest, action_revision, job.job_id,
        job_revision, job.fence, job.cancel_epoch,
    )
    install_schema(db)
    if db.execute(
        "SELECT 1 FROM graph_dispatch_action_job_bindings_v1 WHERE bot=? AND persona=? "
        "AND action_id=? AND attempt_id=?",
        namespace.as_tuple + (action.action_id, admission.attempt_id),
    ).fetchone() is not None:
        raise ValueError("action attempt already has a different job binding")
    if db.execute("SELECT 1 FROM graph_dispatch_action_job_bindings_v1 "
                  "WHERE job_id=?", (job.job_id,)).fetchone() is not None:
        raise ValueError("job already belongs to another action attempt")
    db.execute(
        "INSERT INTO graph_dispatch_action_job_bindings_v1 "
        "(bot,persona,action_id,attempt_id,admission_ref,job_id,binding_json,"
        "binding_digest) VALUES(?,?,?,?,?,?,?,?)",
        namespace.as_tuple + (
            action.action_id, admission.attempt_id, admission.admission_ref,
            job.job_id, canonical_json(asdict(binding)), binding.digest,
        ),
    )
    return binding


__all__ = [
    "DispatchActionJobBindingV1", "bind_action_job", "install_schema",
    "load_action_job_binding",
]
