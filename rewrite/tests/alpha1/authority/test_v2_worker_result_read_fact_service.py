"""Finished worker handoff fact comes only from the original Authority ledger."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_v2_worker_result_read_service import _case
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1,
)
from sylanne3.authority_service.v2_worker_result_read_fact_service import (
    AuthorityV2WorkerResultReadFactService,
)


def _finished(tmp_path, monkeypatch):
    reads, read_request, core, deletion, guard, execution = _case(
        tmp_path, monkeypatch)
    delivery = reads.prepare(credential="ok", request=read_request)
    reads.finish_delivery(credential="ok", delivery=delivery)
    anchor = reads._fences.current_anchor(credential="ok", subject="worker-a")
    write = reads._fences.begin_fence(
        credential="ok", subject="committer-a", holder="holder-a",
        operation="write", operation_id=read_request.consumer_operation_id,
        expected_anchor=anchor)
    service = AuthorityV2WorkerResultReadFactService(
        worker_reads=reads, committer_subject="committer-a",
        committer_holder="holder-a")
    return (service, WorkerResultReadFactRequestV1(read_request, write),
            reads, core, deletion, guard, execution)


def test_fact_from_finished_attempt_and_original_terminal(tmp_path, monkeypatch):
    service, request, reads, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)
    try:
        fact = service.current(credential="ok", request=request)
        assert fact.read_request == request.read_request
        assert fact.write_permit == request.write_permit
        assert fact.result_digest == reads._attempts.read(
            request.read_request).result_digest
        assert fact.terminal_receipt.observation_digest == reads._store._read(
            core._db, request.read_request.call_id).observation_digest
        assert service.current(credential="ok", request=request) == fact
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_fact_denies_unfinished_attempt_wrong_consumer_and_lost_write_fence(
        tmp_path, monkeypatch):
    service, request, reads, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)
    try:
        original_result_digest = reads._attempts.read(
            request.read_request).result_digest
        wrong = replace(request.read_request, consumer_operation_id="other-c02")
        with pytest.raises(AuthorityUnavailable, match="operation differs"):
            service.current(
                credential="ok", request=replace(request, read_request=wrong))
        with core._lock:
            core._db.execute(
                "UPDATE authority_worker_result_read_attempts_v1 "
                "SET state='active',result_digest=NULL WHERE read_attempt_id=?",
                (request.read_request.read_attempt_id,))
        with pytest.raises(AuthorityUnavailable, match="not finished"):
            service.current(credential="ok", request=request)
        with core._lock:
            core._db.execute(
                "UPDATE authority_worker_result_read_attempts_v1 "
                "SET state='finished',result_digest=? WHERE read_attempt_id=?",
                (original_result_digest, request.read_request.read_attempt_id))
        assert service.current(credential="ok", request=request).result_digest == original_result_digest
        reads._fences.finish_fence(
            credential="ok", subject="committer-a", permit=request.write_permit,
            request_id="c02-finished", request_digest="sha256:" + "b" * 64)
        with pytest.raises(AuthorityUnavailable):
            service.current(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_fact_denies_graph_revocation_between_authority_snapshots(
        tmp_path, monkeypatch):
    service, request, reads, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)
    monkeypatch.setattr(reads._graph, "current", lambda *_: False)
    try:
        with pytest.raises(AuthorityUnavailable, match="graph qualification"):
            service.current(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_fact_rechecks_write_fence_after_graph_check(tmp_path, monkeypatch):
    service, request, reads, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)

    def close_write(*_):
        reads._fences.finish_fence(
            credential="ok", subject="committer-a", permit=request.write_permit,
            request_id="c02-concurrent-finish",
            request_digest="sha256:" + "b" * 64)
        return True

    monkeypatch.setattr(reads._graph, "current", close_write)
    try:
        with pytest.raises(AuthorityUnavailable):
            service.current(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
