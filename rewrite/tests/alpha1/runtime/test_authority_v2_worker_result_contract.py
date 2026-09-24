"""Worker result read identity is durable without releasing model content."""

import dataclasses
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1, from_wire, to_wire,
)
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_worker_model_result_attempts import (
    AuthorityV2WorkerModelResultAttempts,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.restore_anchor import RestoreAnchor


def request(*, attempt="attempt-1", operation="consumer-1"):
    return WorkerModelResultReadRequestV1(
        authority_id="authority-1", authority_namespace="bot-1/persona-1",
        namespace=NamespaceId("bot-1", "persona-1"),
        installation_id="install-1", job_id="job-1",
        acquire_operation_id="acquire-1", original_operation_id="original-1",
        call_id="call-1", binding_digest="a" * 64,
        model_request_digest="b" * 64,
        consumer_operation_id=operation, read_attempt_id=attempt,
        purpose="first_ingress_c02",
    )


def connection(path):
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    return db


def permit(item, *, token="e" * 32):
    anchor = RestoreAnchor(
        item.authority_id, item.authority_namespace, 1, "delete-journal", 0,
        "genesis", "execution-journal", 0, "genesis", 0, "proof",
    )
    return FencePermitV2(
        item.authority_id, item.authority_namespace, "worker-subject",
        "holder-1", 1, "read", item.read_attempt_id, token, 1, 0, anchor,
    )


def test_strict_wire_and_fixed_purpose():
    item = request()
    raw = to_wire(item)
    assert from_wire(raw, WorkerModelResultReadRequestV1) == item
    with pytest.raises(ValueError):
        from_wire({**raw, "owner_actor_id": "owner"}, WorkerModelResultReadRequestV1)
    with pytest.raises(ValueError):
        from_wire({**raw, "namespace": {"bot_id": "bot-1", "persona_id": "persona-1", "x": 1}}, WorkerModelResultReadRequestV1)
    with pytest.raises(ValueError):
        dataclasses.replace(item, purpose="audit")


def test_result_wire_binds_original_completed_call():
    item = request()
    observation = ModelEgressObservationV1(
        item.authority_id, item.authority_namespace, "worker-1", "model-op-1",
        item.call_id, item.model_request_digest, "completed", "{}", (), (), None,
    )
    receipt = ModelTerminalReceiptV2(
        "a" * 64, item.call_id, item.model_request_digest, "b" * 64,
        observation.digest, "sha256:" + "c" * 64, item.installation_id,
        "d" * 64,
    )
    result = WorkerModelResultReadV1(item, observation, receipt)
    assert from_wire(to_wire(result), WorkerModelResultReadV1) == result
    with pytest.raises(ValueError):
        WorkerModelResultReadV1(item, observation, dataclasses.replace(receipt, call_id="other"))


def test_attempt_retries_conflicts_finish_and_restart(tmp_path):
    path = tmp_path / "authority.db"
    db = connection(path)
    store = AuthorityV2WorkerModelResultAttempts(db, create=True)
    first = request()
    original = store.begin(first, permit=permit(first))
    assert store.begin(first, permit=permit(first)) == original
    with pytest.raises(AuthorityUnavailable):
        store.begin(dataclasses.replace(first, call_id="other-call"), permit=permit(first))
    with pytest.raises(AuthorityUnavailable):
        store.begin(first, permit=permit(first, token="f" * 32))
    store.finish(first, permit=permit(first), result_digest="c" * 64)
    with pytest.raises(AuthorityUnavailable):
        store.begin(first, permit=permit(first))
    assert store.finish(first, permit=permit(first), result_digest="c" * 64) == "c" * 64
    with pytest.raises(AuthorityUnavailable):
        store.finish(first, permit=permit(first), result_digest="d" * 64)
    second = request(attempt="attempt-2")
    assert store.begin(second, permit=permit(second)) != original
    db.close()
    db = connection(path)
    store = AuthorityV2WorkerModelResultAttempts(db)
    assert store.read(first).state == "finished"
    assert store.read(second).state == "active"
    with pytest.raises(AuthorityUnavailable):
        store.begin(first, permit=permit(first))
    db.close()


def test_locked_attempt_rolls_back_with_authority_transaction(tmp_path):
    db = connection(tmp_path / "authority.db")
    store = AuthorityV2WorkerModelResultAttempts(db, create=True)
    db.execute("BEGIN IMMEDIATE")
    store.begin_locked(db, request(), permit=permit(request()))
    db.execute("ROLLBACK")
    assert store.read(request()) is None
    db.close()
