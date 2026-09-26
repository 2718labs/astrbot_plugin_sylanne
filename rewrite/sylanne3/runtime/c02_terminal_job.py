"""Complete the original C02 job after a pinned terminal read.

This is a business-transaction component. The coordinator owns the current
Authority write fence, graph/quote/budget checks and graph job projection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import math
import sqlite3
from typing import Callable

from ..authority_service.v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadFactV1, TerminalRecoveryReadRequestV1,
)
from ..authority_service.v2_terminal_c02_recovery_read_service import (
    AuthorityV2TerminalC02RecoveryReadService,
)
from ..runtime_contracts import canonical_digest, canonical_serialize
from .first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from .jobs import (
    JobConflict, JobFenceRejected, PersistentJob, _identifier, _job_from_dict,
    _prior_operation, _record_operation, _utc, get_job,
)
from .terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2, recovery_fact_matches_frozen_v2,
)


_WITNESS_KEY = object()
_OPERATION_PHASE = "terminal_c02_recovery"


class TerminalC02JobHold(JobFenceRejected):
    """The original job or its present authority is no longer eligible."""


@dataclass(frozen=True, slots=True)
class OriginalC02JobLeaseV1:
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    holder: str
    fence: int
    cancel_epoch: int
    lease_expires_utc: str

    def __post_init__(self) -> None:
        for name in ("job_id", "original_operation_id", "acquire_operation_id",
                     "holder"):
            _identifier(getattr(self, name), name)
        if (type(self.fence) is not int or self.fence < 1
                or type(self.cancel_epoch) is not int or self.cancel_epoch != 0
                or _utc(self.lease_expires_utc, "lease_expires_utc") is None):
            raise ValueError("invalid original C02 worker lease")


class _PinnedTerminalRead:
    __slots__ = ("fact",)

    def __init__(self, fact: TerminalRecoveryReadFactV1, key: object) -> None:
        if key is not _WITNESS_KEY:
            raise TypeError("pinned Authority query required")
        self.fact = fact


def pin_finished_terminal_read(
    service: AuthorityV2TerminalC02RecoveryReadService, *, credential: object,
    request: TerminalRecoveryReadRequestV1,
) -> _PinnedTerminalRead:
    """Query the installed Authority service outside the business transaction.

    The service's finished read attempt was created by its pinned read path.
    A caller-supplied fact DTO is deliberately not accepted by the CAS API.
    """
    if (type(service) is not AuthorityV2TerminalC02RecoveryReadService
            or type(request) is not TerminalRecoveryReadRequestV1):
        raise TypeError("installed Authority terminal read service required")
    attempt, fact = service.query(credential=credential, request=request)
    if (attempt is None or attempt.state != "finished"
            or attempt.request != request
            or type(fact) is not TerminalRecoveryReadFactV1
            or fact.request != request
            or fact.permit_digest != attempt.permit_digest
            or fact.result_digest != attempt.result_digest):
        raise TerminalC02JobHold("pinned terminal read is not finished")
    return _PinnedTerminalRead(fact, _WITNESS_KEY)


def complete_original_c02_job_in_transaction(
    db: sqlite3.Connection, *, original: OriginalC02JobLeaseV1,
    seal: FrozenTerminalC02CandidateV2, pinned_read: _PinnedTerminalRead,
    consumer_operation_id: str, result_ref: str, now_utc: float,
    current_gate: Callable[[sqlite3.Connection, PersistentJob,
                            FrozenTerminalC02CandidateV2,
                            TerminalRecoveryReadFactV1], bool],
) -> PersistentJob:
    """CAS only the original running job; caller atomically writes graph/fence.

    ``current_gate`` is the coordinator's *transaction-local* current graph,
    signed quote and budget check under its Authority V2 write fence. It must
    perform no RPC. A successful CAS alone is not a C02 commit or cost settlement.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(original) is not OriginalC02JobLeaseV1
            or type(seal) is not FrozenTerminalC02CandidateV2
            or type(pinned_read) is not _PinnedTerminalRead
            or not callable(current_gate)):
        raise TypeError("same business transaction and pinned C02 inputs required")
    _identifier(consumer_operation_id, "consumer_operation_id")
    _identifier(result_ref, "result_ref")
    if type(now_utc) not in {int, float} or not math.isfinite(now_utc):
        raise ValueError("invalid trusted C02 time")
    fact = pinned_read.fact
    key = seal.original_key
    stable_consumer = first_ingress_c02_consumer_operation_id_v1(
        namespace=key.namespace, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id, call_id=key.call_id,
        binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest,
    )
    if (stable_consumer != consumer_operation_id
            or seal.consumer_operation_id != consumer_operation_id
            or fact.request.consumer_operation_id != consumer_operation_id
            or (original.job_id, original.original_operation_id,
                original.acquire_operation_id) !=
               (key.job_id, key.original_operation_id, key.acquire_operation_id)
            or fact.request.original_key != key
            or fact.result_digest != key.stable_result_digest
            or _utc(original.lease_expires_utc, "lease_expires_utc").timestamp()
            != seal.original_worker_lease_expires_utc):
        raise JobConflict("original C02 result, lease or consumer differs")
    job = get_job(db, original.job_id)
    if (job.bot_id, job.persona_id) != key.namespace.as_tuple:
        raise JobConflict("original C02 namespace differs")
    digest = canonical_digest({
        "schema": "sylanne3.original-c02-terminal-job.v1",
        "original": asdict(original), "seal": asdict(seal),
        "fact_digest": fact.digest, "consumer_operation_id": consumer_operation_id,
        "result_ref": result_ref,
    })
    prior = _prior_operation(db, job, consumer_operation_id, _OPERATION_PHASE, digest)
    if prior is not None:
        if prior != job or job.phase != "completed" or job.result_ref != result_ref:
            raise JobConflict("C02 terminal replay differs from durable job")
        return prior
    if not recovery_fact_matches_frozen_v2(
            seal=seal, fact=fact, trusted_now_utc=float(now_utc)):
        raise TerminalC02JobHold("original C02 recovery deadline or fact differs")
    row = db.execute(
        "SELECT seal_json,bundle_digest,quote_json "
        "FROM graph_first_ingress_c02_candidates_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        key.namespace.as_tuple + (consumer_operation_id,),
    ).fetchone()
    if (row is None or row[:2] !=
            (canonical_serialize(asdict(seal)), seal.bundle_digest)):
        raise TerminalC02JobHold("durable C02 first seal differs")
    try:
        quote_wire = json.loads(row[2])
        if (canonical_serialize(quote_wire) != row[2]
                or canonical_digest(quote_wire) != seal.quote_digest
                or (quote_wire["quote_id"], quote_wire["version"])
                != (seal.quote_id, seal.quote_version)):
            raise ValueError("original quote differs")
    except (TypeError, ValueError, KeyError) as exc:
        raise TerminalC02JobHold("durable C02 original quote differs") from exc
    acquired = db.execute(
        "SELECT i.job_id,i.original_operation_id,i.actor,i.request_digest,"
        "r.request_digest,r.job_json FROM graph_job_acquire_intents_v2 AS i "
        "JOIN graph_job_acquire_receipts_v2 AS r ON r.bot=i.bot "
        "AND r.persona=i.persona AND r.acquire_operation_id=i.acquire_operation_id "
        "WHERE i.bot=? AND i.persona=? AND i.acquire_operation_id=?",
        key.namespace.as_tuple + (original.acquire_operation_id,),
    ).fetchone()
    if (acquired is None or acquired[:3] !=
            (original.job_id, original.original_operation_id, original.holder)
            or acquired[3] != acquired[4]):
        raise TerminalC02JobHold("original C02 acquire receipt differs")
    try:
        acquired_job = _job_from_dict(json.loads(acquired[5]))
    except (TypeError, ValueError, KeyError) as exc:
        raise TerminalC02JobHold("original C02 acquired job is invalid") from exc
    if (acquired_job != job or job.phase != "running"
            or (job.job_id, job.operation_id, job.lease_holder,
                job.lease_expires_utc, job.fence, job.cancel_epoch,
                job.result_ref) !=
               (original.job_id, original.original_operation_id,
                original.holder, original.lease_expires_utc,
                original.fence, original.cancel_epoch, None)):
        raise TerminalC02JobHold("original C02 running lease changed")
    if current_gate(db, job, seal, fact) is not True:
        raise TerminalC02JobHold("current C02 graph or budget gate is closed")
    updated = replace(job, phase="completed", result_ref=result_ref,
                      lease_holder=None, lease_expires_utc=None)
    changed = db.execute(
        "UPDATE runtime_jobs SET phase='completed',result_ref=?,"
        "lease_holder=NULL,lease_expires_utc=NULL WHERE job_id=? "
        "AND operation_id=? AND bot_id=? AND persona_id=? AND phase='running' "
        "AND lease_holder=? AND lease_expires_utc=? AND fence=? "
        "AND cancel_epoch=? AND result_ref IS NULL",
        (result_ref, original.job_id, original.original_operation_id,
         *key.namespace.as_tuple, original.holder, original.lease_expires_utc,
         original.fence, original.cancel_epoch),
    ).rowcount
    if changed != 1:
        raise TerminalC02JobHold("original C02 job CAS lost")
    _record_operation(db, updated, consumer_operation_id, _OPERATION_PHASE, digest)
    return updated


__all__ = ("OriginalC02JobLeaseV1", "TerminalC02JobHold",
           "pin_finished_terminal_read", "complete_original_c02_job_in_transaction")
