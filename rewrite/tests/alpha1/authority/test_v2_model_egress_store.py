"""Durable model egress intent, without granting an actual provider send."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import asyncio
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore


def connection(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=5)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def intent(**changes):
    value = ModelEgressIntentV1(
        authority_id="authority", namespace="bot:persona", subject="worker",
        operation_id="job-operation", call_id="call-1", request_digest="a" * 64,
        job_id="job-1", worker_fence=7, fence_token="t" * 32, fence_epoch=3,
        fence_revision=0, anchor_digest="b" * 64,
        source_refs=("source-1",), source_revisions=(("source-1", 4),),
        access_revisions=(("access-1", 3),),
        access_epoch=2, delete_epoch=0, graph_epoch=5, graph_revision=8,
        authority_activation_generation=1, authority_revocation_epoch=0,
        authority_deletion_seq=0, authority_execution_seq=0,
        budget_lease_id="lease-1", budget_reservation_operation_id="reserve-1",
        budget_reservation_digest="c" * 64, budget_ceiling=(("USD", 100),),
        provider_id="provider-1", model_id="model-1",
        provider_config_digest="d" * 64, max_output_tokens=256,
    )
    return replace(value, **changes)


def test_reopen_exact_identity_and_conflict(tmp_path):
    path = tmp_path / "authority.db"
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db, create=True)
        assert store.prepare(intent()).state == "prepared"
        assert store.prepare(intent()).state == "prepared"
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db)
        assert store.read("call-1", subject="worker", namespace="bot:persona").intent == intent()
        with pytest.raises(AuthorityUnavailable):
            store.prepare(intent(request_digest="e" * 64))
        with pytest.raises(AuthorityUnavailable):
            store.prepare(intent(access_revisions=(("access-1", 5),)))
        with pytest.raises(AuthorityUnavailable):
            store.prepare(intent(budget_ceiling=(("USD", 101),)))
        with pytest.raises(AuthorityUnavailable):
            store.prepare(intent(max_output_tokens=512))
        with pytest.raises(AuthorityUnavailable):
            store.read("call-1", subject="another", namespace="bot:persona")


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_max_output_tokens_requires_positive_exact_integer(limit):
    with pytest.raises(ValueError, match="max_output_tokens"):
        intent(max_output_tokens=limit)


def test_dispatch_marker_survives_restart_and_cannot_repeat(tmp_path):
    path = tmp_path / "authority.db"
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db, create=True)
        store.prepare(intent())
        assert store.record_dispatch_started(intent()).state == "dispatch_started"
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db)
        assert store.read("call-1", subject="worker", namespace="bot:persona").state == "dispatch_started"
        with pytest.raises(AuthorityUnavailable):
            store.record_dispatch_started(intent())
        assert store.record_unknown(intent(), observation_digest="e" * 64).state == "unknown"
        with pytest.raises(AuthorityUnavailable):
            store.record_dispatch_started(intent())


def test_observation_is_terminal_and_cannot_precede_dispatch(tmp_path):
    with connection(tmp_path / "authority.db") as db:
        store = AuthorityV2ModelEgressStore(db, create=True)
        store.prepare(intent())
        with pytest.raises(AuthorityUnavailable):
            store.record_observed(intent(), observation_digest="e" * 64)
        store.record_dispatch_started(intent())
        assert store.record_observed(intent(), observation_digest="e" * 64).state == "observed"
        with pytest.raises(AuthorityUnavailable):
            store.record_unknown(intent(), observation_digest="f" * 64)


def test_same_call_id_one_winner_across_connections(tmp_path):
    path = tmp_path / "authority.db"
    with connection(path) as db:
        AuthorityV2ModelEgressStore(db, create=True)
    barrier = Barrier(2)

    def competing(value):
        with connection(path) as db:
            store = AuthorityV2ModelEgressStore(db)
            barrier.wait(timeout=5)
            try:
                store.prepare(value)
                return "prepared"
            except AuthorityUnavailable:
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(competing, (intent(), intent(operation_id="other-operation"))))
    assert sorted(results) == ["conflict", "prepared"]
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db)
        saved = store.read("call-1", subject="worker", namespace="bot:persona")
        assert store.prepare(saved.intent) == saved


def test_dispatch_marker_has_one_winner_across_connections(tmp_path):
    path = tmp_path / "authority.db"
    with connection(path) as db:
        AuthorityV2ModelEgressStore(db, create=True).prepare(intent())
    barrier = Barrier(2)

    def claim(_):
        with connection(path) as db:
            store = AuthorityV2ModelEgressStore(db)
            barrier.wait(timeout=5)
            try:
                store.record_dispatch_started(intent())
                return "claimed"
            except AuthorityUnavailable:
                return "blocked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, range(2))) == ["blocked", "claimed"]


def test_service_remains_hold(tmp_path):
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService

    with connection(tmp_path / "authority.db") as db:
        service = AuthorityV2ModelEgressService(AuthorityV2ModelEgressStore(db, create=True))
        with pytest.raises(AuthorityUnavailable, match="HOLD"):
            asyncio.run(service.begin_handoff(None, "a" * 64))
        with pytest.raises(AuthorityUnavailable, match="HOLD"):
            asyncio.run(service.finish_handoff(None, "a" * 64))
