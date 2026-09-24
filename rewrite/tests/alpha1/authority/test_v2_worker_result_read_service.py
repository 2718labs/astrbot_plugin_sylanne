"""Original observed terminal and read attempt share one Authority fence."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from rewrite.tests.alpha1.authority.test_v2_accounting_deletion import _observed_original
from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.current_worker_model_result_graph_verifier import (
    PinnedCurrentWorkerModelResultGraphVerifier,
)
from sylanne3.authority_service.v2_worker_model_result_attempts import (
    AuthorityV2WorkerModelResultAttempts,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1,
)
from sylanne3.authority_service.v2_worker_model_result_read_service import (
    AuthorityV2WorkerModelResultReadService,
)
from sylanne3.runtime_contracts import NamespaceId


def _case(tmp_path, monkeypatch):
    fences, core, _, deletion, guard, execution, _ = installed(tmp_path)
    store, intent = _observed_original(fences, core)
    attempts = AuthorityV2WorkerModelResultAttempts(
        core._db, create=True, lock=core._lock)
    graph = object.__new__(PinnedCurrentWorkerModelResultGraphVerifier)
    monkeypatch.setattr(graph, "current", lambda *_: True)
    service = AuthorityV2WorkerModelResultReadService(
        store=store, fences=fences, attempts=attempts, graph_verifier=graph,
        installation_id="original-install", read_subject="worker-a",
        holder="holder-a")
    request = WorkerModelResultReadRequestV1(
        intent.authority_id, intent.namespace, NamespaceId("bot-a", "persona-a"),
        "original-install", intent.job_id, intent.operation_id,
        intent.budget_reservation_operation_id, intent.call_id, "a" * 64,
        intent.request_digest, "c02-commit-1", "worker-read-1")
    return service, request, core, deletion, guard, execution


def test_observed_original_stays_fenced_until_delivery_finishes(tmp_path, monkeypatch):
    service, request, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        delivery = service.prepare(credential="ok", request=request)
        assert delivery.result.observation.status == "completed"
        assert delivery.result.observation.operation_id == request.acquire_operation_id
        assert delivery.result.terminal_receipt.observation_digest == delivery.result.observation.digest
        assert service._attempts.read(request).state == "active"
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "active"
        with pytest.raises(AuthorityUnavailable, match="already being delivered"):
            service.prepare(credential="ok", request=request)
        with pytest.raises(AuthorityUnavailable, match="still in progress"):
            service.recover_finish(credential="ok", request=request)
        service.finish_delivery(credential="ok", delivery=delivery)
        assert service._attempts.read(request).state == "finished"
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "finished"
        service.recover_finish(credential="ok", request=request)
        with pytest.raises(AuthorityUnavailable):
            service.prepare(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_original_attempt_recovery_is_content_free_and_identity_bound(tmp_path, monkeypatch):
    service, request, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        delivery = service.prepare(credential="ok", request=request)
        with pytest.raises(AuthorityUnavailable):
            service.recover_finish(
                credential="ok", request=replace(request, consumer_operation_id="other"))
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "active"
        with pytest.raises(AuthorityUnavailable, match="still in progress"):
            service.recover_finish(credential="ok", request=request)
        service.abandon_delivery(delivery=delivery)
        service.recover_finish(credential="ok", request=request)
        assert service._attempts.read(request).result_digest == delivery.digest
        with pytest.raises(AuthorityUnavailable, match="not the active handoff"):
            service.finish_delivery(credential="ok", delivery=delivery)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_unpaired_generic_read_fence_cannot_be_adopted_as_worker_attempt(
        tmp_path, monkeypatch):
    service, request, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        anchor = service._fences.current_anchor(credential="ok", subject="worker-a")
        service._fences.begin_fence(
            credential="ok", subject="worker-a", holder="holder-a",
            operation="read", operation_id=request.read_attempt_id,
            expected_anchor=anchor)
        with pytest.raises(AuthorityUnavailable, match="pair differs"):
            service.prepare(credential="ok", request=request)
        assert service._attempts.read(request) is None
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_concurrent_same_attempt_and_recovery_cannot_overtake_handoff(
        tmp_path, monkeypatch):
    service, request, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    entered, release = Event(), Event()
    original_preflight = service._preflight

    def slow_preflight(value):
        entered.set()
        assert release.wait(3)
        return original_preflight(value)

    monkeypatch.setattr(service, "_preflight", slow_preflight)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(service.prepare, credential="ok", request=request)
            assert entered.wait(3)
            second = pool.submit(service.prepare, credential="ok", request=request)
            with pytest.raises(AuthorityUnavailable, match="already being delivered"):
                second.result(timeout=3)
            with pytest.raises(AuthorityUnavailable, match="still in progress"):
                service.recover_finish(credential="ok", request=request)
            release.set()
            delivery = first.result(timeout=3)
        service.abandon_delivery(delivery=delivery)
        service.recover_finish(credential="ok", request=request)
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "finished"
    finally:
        release.set()
        core.close(); deletion.close(); guard.close(); execution.close()
