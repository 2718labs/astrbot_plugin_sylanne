"""Original C02 terminal recovery changes only the old durable worker job."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
import sqlite3
from unittest.mock import patch

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadAttemptV1,
    TerminalRecoveryReadFactV1, TerminalRecoveryReadRequestV1,
)
from sylanne3.authority_service.v2_terminal_c02_recovery_read_service import (
    AuthorityV2TerminalC02RecoveryReadService,
)
from sylanne3.runtime.c02_terminal_job import (
    OriginalC02JobLeaseV1, TerminalC02JobHold,
    complete_original_c02_job_in_transaction, pin_finished_terminal_read,
)
from sylanne3.runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from sylanne3.runtime.issuers import d06_first_ingress_c02_quote_id
from sylanne3.runtime.jobs import (
    JobConflict, PersistentJob, acquire_job, create_job, get_job, install_schema,
)
from sylanne3.runtime.terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2,
)
from sylanne3.runtime_contracts import (
    NamespaceId, canonical_digest, canonical_serialize,
)


def _time(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def _case():
    db = sqlite3.connect(":memory:", isolation_level=None)
    install_schema(db)
    db.executescript("""
        CREATE TABLE graph_job_acquire_intents_v2(
            bot TEXT, persona TEXT, acquire_operation_id TEXT, job_id TEXT,
            original_operation_id TEXT, actor TEXT, request_digest TEXT);
        CREATE TABLE graph_job_acquire_receipts_v2(
            bot TEXT, persona TEXT, acquire_operation_id TEXT,
            request_digest TEXT, job_json TEXT);
        CREATE TABLE graph_first_ingress_c02_candidates_v2(
            bot TEXT, persona TEXT, operation_id TEXT, seal_json TEXT,
            bundle_digest TEXT, quote_json TEXT);
    """)
    ns = NamespaceId("bot", "persona")
    queued = PersistentJob(
        "job-1", "source-op", "activity-1", None, "bot", "persona",
        "snapshot-1", "queued", "d06.encode_source", {}, None, _time(1100),
        "grant-1", "resource-1", {}, None, None, 0, 0, {}, None)
    create_job(db, queued, "create-op", "a" * 64)
    running = acquire_job(db, "job-1", "worker-1", now_utc=_time(1000),
                          lease_seconds=5)
    lease = OriginalC02JobLeaseV1(
        running.job_id, running.operation_id, "acquire-1", "worker-1",
        running.fence, running.cancel_epoch, running.lease_expires_utc)
    db.execute("INSERT INTO graph_job_acquire_intents_v2 VALUES(?,?,?,?,?,?,?)",
               ("bot", "persona", "acquire-1", "job-1", "source-op",
                "worker-1", "b" * 64))
    db.execute("INSERT INTO graph_job_acquire_receipts_v2 VALUES(?,?,?,?,?)",
               ("bot", "persona", "acquire-1", "b" * 64,
                json.dumps(asdict(running))))
    key = OriginalC02ResultKeyV1(
        "authority-1", "authority-ns", ns, "install-1", "job-1",
        "source-op", "acquire-1", "acquire-1", "call-1", "1" * 64,
        "2" * 64, "3" * 64, "4" * 64, "5" * 64)
    consumer = first_ingress_c02_consumer_operation_id_v1(
        namespace=ns, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id, call_id=key.call_id,
        binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest)
    quote_wire = {"quote_id": d06_first_ingress_c02_quote_id(ns, consumer),
                  "version": 1, "operation_id": consumer}
    seal = FrozenTerminalC02CandidateV2(
        key, "6" * 64, d06_first_ingress_c02_quote_id(ns, consumer), 1,
        canonical_digest(quote_wire), 1001.0, 1005.0, 1099.0, 100.0, 1200.0)
    db.execute("INSERT INTO graph_first_ingress_c02_candidates_v2 VALUES(?,?,?,?,?,?)",
               ("bot", "persona", consumer, canonical_serialize(asdict(seal)),
                seal.bundle_digest, canonical_serialize(quote_wire)))
    request = TerminalRecoveryReadRequestV1(key, consumer, "read-1")
    fact = TerminalRecoveryReadFactV1(request, "8" * 64,
                                      key.stable_result_digest, "9" * 64)
    attempt = TerminalRecoveryReadAttemptV1(request, fact.permit_digest,
                                            "finished", fact.result_digest)
    service = object.__new__(AuthorityV2TerminalC02RecoveryReadService)
    with patch.object(AuthorityV2TerminalC02RecoveryReadService, "query",
                      return_value=(attempt, fact)):
        pinned = pin_finished_terminal_read(
            service, credential=object(), request=request)
    return db, lease, seal, pinned, consumer


def _complete(db, lease, seal, pinned, consumer, **changes):
    args = dict(original=lease, seal=seal, pinned_read=pinned,
                consumer_operation_id=consumer, result_ref="episode-1",
                now_utc=1006.0, current_gate=lambda *_: True)
    args.update(changes)
    return complete_original_c02_job_in_transaction(db, **args)


def test_terminal_c02_cas_and_exact_replay():
    db, lease, seal, pinned, consumer = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        completed = _complete(db, lease, seal, pinned, consumer)
        assert completed.phase == "completed"
        assert completed.lease_holder is None
        assert completed.lease_expires_utc is None
        db.execute("COMMIT")
        db.execute("BEGIN IMMEDIATE")
        assert _complete(db, lease, seal, pinned, consumer, now_utc=1300.0) == completed
        with pytest.raises(JobConflict):
            _complete(db, lease, seal, pinned, consumer, result_ref="episode-2")
        db.execute("ROLLBACK")
    finally:
        db.close()


@pytest.mark.parametrize("change", [
    "not_expired", "cancelled", "renewed", "gate", "seal", "quote",
])
def test_terminal_c02_rejects_stale_or_unauthorized_job(change):
    db, lease, seal, pinned, consumer = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        if change == "cancelled":
            db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id='job-1'")
        if change == "renewed":
            db.execute("UPDATE runtime_jobs SET fence=2,lease_holder='worker-2',"
                       "lease_expires_utc=? WHERE job_id='job-1'", (_time(1020),))
        if change == "seal":
            db.execute("UPDATE graph_first_ingress_c02_candidates_v2 "
                       "SET bundle_digest=?", ("0" * 64,))
        if change == "quote":
            db.execute("UPDATE graph_first_ingress_c02_candidates_v2 "
                       "SET quote_json=?", ('{"quote_id":"other","version":1}',))
        extra = {"now_utc": 1004.0} if change == "not_expired" else {}
        if change == "gate":
            extra["current_gate"] = lambda *_: False
        with pytest.raises(TerminalC02JobHold):
            _complete(db, lease, seal, pinned, consumer, **extra)
        assert get_job(db, "job-1").phase == "running"
        assert db.execute("SELECT COUNT(*) FROM runtime_job_operations "
                          "WHERE phase='terminal_c02_recovery'").fetchone()[0] == 0
        db.execute("ROLLBACK")
    finally:
        db.close()


def test_terminal_c02_requires_pinned_authority_query_not_fact_dto():
    db, lease, seal, pinned, consumer = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(TypeError):
            _complete(db, lease, seal, pinned.fact, consumer)
        db.execute("ROLLBACK")
    finally:
        db.close()
