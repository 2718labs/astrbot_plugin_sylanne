"""Fail-closed W01 preflight for a D06 source-correction resolution.

Only graph/authority rows read in the caller's pinned transaction contribute
to this snapshot. No current implementation issues durable D04/D05/D07
reevaluation, D02 actual-cost, and D11 completion/outbox receipts. Therefore
this module deliberately has no resolved-head write or caller-receipt input.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..domains.d06 import source_correction_head_key, validate_source_correction_head
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key
from ..runtime_contracts import NamespaceId
from ..domains.d06.source_correction_resolution import CurrentCorrectionSourceV1
from .d11_types import job_graph_write
from .jobs import get_job


class SourceCorrectionResolutionHold(RuntimeError):
    """The correction barrier must remain pending."""


@dataclass(frozen=True, slots=True)
class SourceCorrectionResolutionPreflightV1:
    head: GraphVersion
    pending_head: dict
    current: CurrentCorrectionSourceV1
    status: str = "HOLD"
    missing_authorities: tuple[str, ...] = (
        "d04_reevaluation_receipt", "d05_reevaluation_receipt",
        "d07_reevaluation_receipt", "d02_actual_cost_receipt",
        "d11_job_outbox_settlement_receipt", "w01_atomic_commit",
    )


@dataclass(frozen=True, slots=True)
class SourceCorrectionDurableStateV1:
    """Observed persisted progress, never an authorization to resolve a head."""

    preflight: SourceCorrectionResolutionPreflightV1
    job_id: str
    job_phase: str
    outbox_ref: str
    outbox_ledger_phase: str
    outbox_graph_phase: str
    d11_budget_state: str
    d11_actual_usage: tuple[tuple[str, int], ...] | None
    status: str = "HOLD"


def _atom(db: sqlite3.Connection, namespace: NamespaceId,
          key: AtomKey) -> tuple[int, dict]:
    if NamespaceId.from_key(key) != namespace:
        raise SourceCorrectionResolutionHold("correction atom crosses namespace; HOLD")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms "
        "WHERE token=? AND bot=? AND persona=?",
        (key.token, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[2] != 1 or type(row[0]) is not int or row[0] < 1:
        raise SourceCorrectionResolutionHold("current correction atom unavailable; HOLD")
    try:
        value = json.loads(row[1])
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionResolutionHold("current correction atom invalid; HOLD") from exc
    if type(value) is not dict:
        raise SourceCorrectionResolutionHold("current correction atom invalid; HOLD")
    return row[0], value


def read_source_correction_resolution_preflight(
        db: sqlite3.Connection, namespace: NamespaceId, source_id: str,
) -> SourceCorrectionResolutionPreflightV1:
    """Re-read current facts under a transaction; never accept a receipt DTO.

    The coordinator must use an Authority V2 read fence before this read and
    repeat it under the future write fence. This preflight cannot lift a head.
    """
    if not db.in_transaction:
        raise SourceCorrectionResolutionHold("resolution needs pinned transaction; HOLD")
    if type(namespace) is not NamespaceId:
        raise TypeError("typed namespace required")
    head_key = source_correction_head_key(namespace, source_id)
    head_revision, head = _atom(db, namespace, head_key)
    try:
        validate_source_correction_head(head_key, head)
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionResolutionHold("current correction head invalid; HOLD") from exc
    if head["state"] != "pending_reevaluation":
        raise SourceCorrectionResolutionHold("correction head is not pending; HOLD")
    source_key = AtomKey.from_token(head["source_ref"])
    correction_key = AtomKey.from_token(head["correction_source_ref"])
    source_revision, source = _atom(db, namespace, source_key)
    correction_revision, correction = _atom(db, namespace, correction_key)
    _, source_access = _atom(db, namespace, access_key(
        *namespace.as_tuple, source_key.owner.subject))
    _, correction_access = _atom(db, namespace, access_key(
        *namespace.as_tuple, correction_key.owner.subject))
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (source_revision != head["source_revision"]
            or source.get("source_id") != source_key.owner.subject
            or correction.get("source_id") != correction_key.owner.subject
            or source_access.get("source_id") != source_key.owner.subject
            or correction_access.get("source_id") != correction_key.owner.subject
            or source_access.get("status") != "active"
            or correction_access.get("status") != "active"
            or epochs is None or len(epochs) != 2
            or type(epochs[0]) is not int or type(epochs[1]) is not int
            or epochs[0] < head["access_epoch"]
            or epochs[1] < head["deletion_epoch"]):
        raise SourceCorrectionResolutionHold("current source access or epoch changed; HOLD")
    current = CurrentCorrectionSourceV1(
        source_key.token, source_revision, correction_key.token,
        correction_revision, epochs[0], epochs[1], "active", "active",
    )
    return SourceCorrectionResolutionPreflightV1(
        GraphVersion(head_key, head_revision), head, current)


def read_source_correction_durable_state_v1(
        db: sqlite3.Connection, namespace: NamespaceId, source_id: str,
) -> SourceCorrectionDurableStateV1:
    """Inspect real D11 progress in one pinned snapshot; keep D06 pending.

    D11 budget settlement is not the missing D02 role-cost receipt. An outbox
    phase is dispatch progress, not proof that D04/D05/D07 reevaluated.
    """
    preflight = read_source_correction_resolution_preflight(
        db, namespace, source_id)
    operation_id = preflight.pending_head["operation_id"]
    rows = db.execute(
        "SELECT b.outbox_ref,b.phase,j.job_id,j.operation_id "
        "FROM graph_bundle_outbox AS b JOIN graph_outbox_jobs AS j "
        "ON j.bot=b.bot AND j.persona=b.persona AND j.outbox_ref=b.outbox_ref "
        "WHERE b.bot=? AND b.persona=? AND b.operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchall()
    if len(rows) != 1 or rows[0][3] != operation_id:
        raise SourceCorrectionResolutionHold("correction D11 outbox binding absent; HOLD")
    outbox_ref, ledger_phase, job_id, _ = rows[0]
    try:
        job = get_job(db, job_id)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise SourceCorrectionResolutionHold("correction D11 job absent; HOLD") from exc
    if ((job.bot_id, job.persona_id, job.operation_id) !=
            (*namespace.as_tuple, operation_id)
            or job.work_kind != "d06.source_correction" or job.effect_id is not None):
        raise SourceCorrectionResolutionHold("correction D11 job identity changed; HOLD")
    job_key = job_graph_write(job).key
    _, graph_job = _atom(db, namespace, job_key)
    if graph_job != job_graph_write(job).value:
        raise SourceCorrectionResolutionHold("correction D11 job projection changed; HOLD")
    outbox_key = AtomKey.from_token(outbox_ref)
    if outbox_key.type_name != "runtime.outbox":
        raise SourceCorrectionResolutionHold("correction D11 outbox identity changed; HOLD")
    _, graph_outbox = _atom(db, namespace, outbox_key)
    if (graph_outbox.get("job_id") != job_id
            or graph_outbox.get("job_ref") != job_key.token
            or graph_outbox.get("operation_id") != operation_id
            or graph_outbox.get("phase") not in {
                "pending", "sending", "ack", "delivered", "failed",
                "unknown", "cancelled"}):
        raise SourceCorrectionResolutionHold("correction D11 outbox projection changed; HOLD")
    reservation = db.execute(
        "SELECT digest,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (job.budget_ref, operation_id),
    ).fetchone()
    if reservation is None or reservation[1] not in {
            "reserved", "settled", "overrun", "pending_confirmation",
            "pending_overrun"}:
        raise SourceCorrectionResolutionHold("correction D11 budget absent; HOLD")
    actual = None
    if reservation[1] == "settled":
        receipt_row = db.execute(
            "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? "
            "AND phase='settle'", namespace.as_tuple + (operation_id,),
        ).fetchone()
        if (receipt_row is None or receipt_row[:2] !=
                (reservation[0], job.budget_ref)):
            raise SourceCorrectionResolutionHold("correction D11 settlement receipt absent; HOLD")
        try:
            receipt = json.loads(receipt_row[2])
            actual_value = json.loads(reservation[2])
        except (TypeError, ValueError) as exc:
            raise SourceCorrectionResolutionHold("correction D11 settlement invalid; HOLD") from exc
        if (type(receipt) is not dict or receipt.get("status") != "settled"
                or receipt.get("operation_id") != operation_id
                or receipt.get("digest") != reservation[0]
                or receipt.get("lease_id") != job.budget_ref
                or type(actual_value) is not dict or not actual_value
                or any(type(name) is not str or not name or type(amount) is not int
                       or amount < 0 for name, amount in actual_value.items())):
            raise SourceCorrectionResolutionHold("correction D11 settlement invalid; HOLD")
        actual = tuple(sorted(actual_value.items()))
    elif reservation[2] is not None and reservation[1] == "reserved":
        raise SourceCorrectionResolutionHold("correction reserved cost has actual usage; HOLD")
    return SourceCorrectionDurableStateV1(
        preflight, job_id, job.phase, outbox_ref, ledger_phase,
        graph_outbox["phase"], reservation[1], actual)


def plan_source_correction_resolution_v1(
        preflight: SourceCorrectionResolutionPreflightV1,
) -> None:
    """Explicit HOLD until every receipt has a durable trusted verifier.

    A caller-provided candidate or receipt cannot satisfy this boundary.
    """
    if type(preflight) is not SourceCorrectionResolutionPreflightV1:
        raise TypeError("typed W01 preflight required")
    raise SourceCorrectionResolutionHold(
        "reevaluation, actual cost and D11 settlement issuers absent; HOLD")


__all__ = (
    "SourceCorrectionResolutionHold", "SourceCorrectionResolutionPreflightV1",
    "SourceCorrectionDurableStateV1", "read_source_correction_durable_state_v1",
    "read_source_correction_resolution_preflight",
    "plan_source_correction_resolution_v1",
)
