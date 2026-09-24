"""A fact shape binds the original handoff and the new graph write fence."""

from dataclasses import asdict, replace

import pytest

from rewrite.tests.alpha1.authority.test_v2_worker_result_read_service import _case
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactV1, from_wire, to_wire,
)
from sylanne3.runtime_contracts import canonical_digest


def test_fact_contract_is_content_free_and_binds_both_fences(tmp_path, monkeypatch):
    service, request, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        delivery = service.prepare(credential="ok", request=request)
        service.finish_delivery(credential="ok", delivery=delivery)
        anchor = service._fences.current_anchor(credential="ok", subject="worker-a")
        write = service._fences.begin_fence(
            credential="ok", subject="worker-a", holder="holder-a",
            operation="write", operation_id="c02-commit-1",
            expected_anchor=anchor)
        query = WorkerResultReadFactRequestV1(request, write)
        assert from_wire(to_wire(query), WorkerResultReadFactRequestV1) == query
        finish_id, finish_digest = service._finish_identity(request, delivery.permit)
        fact = WorkerResultReadFactV1(
            request, request.digest, delivery.permit,
            canonical_digest(asdict(delivery.permit)), finish_id, finish_digest,
            delivery.digest, canonical_digest(asdict(service._store._read(
                core._db, request.call_id).intent)),
            delivery.result.terminal_receipt, write,
            canonical_digest(asdict(write)))
        assert from_wire(to_wire(fact), WorkerResultReadFactV1) == fact
        assert "observation" not in to_wire(fact)
        assert "result_json" not in str(to_wire(fact))
        with pytest.raises(ValueError, match="digest"):
            replace(fact, result_digest="0" * 63)
        with pytest.raises(ValueError, match="digest"):
            replace(fact, read_permit_digest="0" * 64)
        with pytest.raises(ValueError, match="identities"):
            replace(fact, terminal_receipt=replace(
                fact.terminal_receipt, call_id="other-call"))
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
