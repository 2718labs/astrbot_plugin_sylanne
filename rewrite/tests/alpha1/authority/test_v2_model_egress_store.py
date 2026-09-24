"""Durable model egress intent, without granting an actual provider send."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import asyncio
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1,
)
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.model_broker.broker import ProviderResponse


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


def test_same_job_cannot_prepare_different_call_id_even_after_unknown(tmp_path):
    path = tmp_path / "authority.db"
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db, create=True)
        store.prepare(intent())
        store.record_dispatch_started(intent())
        with pytest.raises(AuthorityUnavailable, match="digest-only"):
            store.record_unknown(intent(), observation_digest="e" * 64)
    with connection(path) as db:
        store = AuthorityV2ModelEgressStore(db)
        with pytest.raises(AuthorityUnavailable, match="job already"):
            store.prepare(intent(call_id="call-2", operation_id="job-operation-2"))
        assert store.read("call-1", subject="worker", namespace="bot:persona").state == "dispatch_started"


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_max_output_tokens_requires_positive_exact_integer(limit):
    with pytest.raises(ValueError, match="max_output_tokens"):
        intent(max_output_tokens=limit)


@pytest.mark.parametrize("token", ["_" + "a" * 31, "-" + "a" * 31,
                                     "_" * 256, "-" * 256])
def test_fence_token_accepts_v2_urlsafe_syntax_and_length(token):
    assert intent(fence_token=token).fence_token == token


@pytest.mark.parametrize("token", ["_" + "a" * 30, "a" * 257,
                                     "a" * 31 + ".", "a" * 31 + " ",
                                     "a" * 31 + "é", None])
def test_fence_token_rejects_values_outside_v2_syntax(token):
    with pytest.raises(ValueError, match="fence_token"):
        intent(fence_token=token)


@pytest.mark.parametrize("prefix", ["_", "-"])
def test_v2_fence_token_round_trips_through_recovery(tmp_path, prefix):
    path = tmp_path / "authority.db"
    original = intent(fence_token=prefix + "a" * 31)
    with connection(path) as db:
        AuthorityV2ModelEgressStore(db, create=True).prepare(original)
    with connection(path) as db:
        recovered = AuthorityV2ModelEgressStore(db).read(
            "call-1", subject="worker", namespace="bot:persona")
        assert recovered.intent == original


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
        with pytest.raises(AuthorityUnavailable, match="digest-only"):
            store.record_unknown(intent(), observation_digest="e" * 64)
        with pytest.raises(AuthorityUnavailable):
            store.record_dispatch_started(intent())


def test_observation_is_terminal_and_cannot_precede_dispatch(tmp_path):
    with connection(tmp_path / "authority.db") as db:
        store = AuthorityV2ModelEgressStore(db, create=True)
        store.prepare(intent())
        with pytest.raises(AuthorityUnavailable):
            store.record_observed(intent(), observation_digest="e" * 64)
        store.record_dispatch_started(intent())
        with pytest.raises(AuthorityUnavailable, match="digest-only"):
            store.record_observed(intent(), observation_digest="e" * 64)
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


def test_fenced_prepare_is_atomic_and_recoverable(tmp_path, monkeypatch):
    from rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences import (
        _PEER_A, rpc,
    )
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService

    fixture = rpc.__wrapped__(tmp_path)
    server = next(fixture)
    try:
        fences = server._v2_fences["ns-a"]
        store = AuthorityV2ModelEgressStore(
            fences.core._db, create=True, lock=fences.core._lock)
        service = AuthorityV2ModelEgressService(store, fences)
        anchor = fences.current_anchor(credential=_PEER_A, subject="worker")
        proposed = ModelEgressDraftV1.from_intent(intent(
            namespace="ns-a", authority_id=anchor.authority_id,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
        ))
        original = store.prepare_locked

        def fail_after_fence(db, value):
            raise RuntimeError("simulated failure before commit")

        monkeypatch.setattr(store, "prepare_locked", fail_after_fence)
        with pytest.raises(RuntimeError, match="simulated failure"):
            service.prepare_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                draft=proposed, expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, proposed.operation_id) is None
        assert store._read(fences.core._db, proposed.call_id) is None
        assert fences.core._db.execute(
            "SELECT COUNT(*) FROM authority_model_egress_bindings_v1").fetchone() == (0,)
        monkeypatch.setattr(store, "prepare_locked", original)

        recovery, permit = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=proposed, expected_anchor=anchor)
        assert recovery.state == "prepared"
        assert permit.operation == "model_egress"
        from dataclasses import asdict
        from sylanne3.runtime_contracts import canonical_digest
        assert (recovery.intent.fence_token, recovery.intent.fence_epoch,
                recovery.intent.fence_revision, recovery.intent.anchor_digest) == (
                    permit.token, permit.fence_epoch, permit.revision,
                    canonical_digest(asdict(permit.pinned_anchor)))
        assert service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=proposed, expected_anchor=anchor) == (recovery, permit)
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=recovery.intent) == (recovery, permit)
        for field, value in (
            ("fence_token", "z" * 32), ("fence_epoch", permit.fence_epoch + 1),
            ("fence_revision", permit.revision + 1), ("anchor_digest", "f" * 64),
        ):
            with pytest.raises(AuthorityUnavailable):
                service.recover_fenced(
                    credential=_PEER_A, subject="worker",
                    intent=replace(recovery.intent, **{field: value}))
        with pytest.raises(AuthorityUnavailable, match="job already"):
            service.prepare_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                draft=replace(proposed, call_id="call-2", operation_id="job-operation-2"),
                expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, "job-operation-2") is None

        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder="holder-a")
            with pytest.raises(AuthorityUnavailable, match="fence and call identity mismatch"):
                store._record_dispatch_started_fenced_locked(
                    db, replace(recovery.intent, anchor_digest="f" * 64),
                    permit, fences.fences, current)
            assert store._record_dispatch_started_fenced_locked(
                db, recovery.intent, permit, fences.fences, current).state == "dispatch_started"
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder="holder-a")
            with pytest.raises(AuthorityUnavailable, match="cannot repeat"):
                store._record_dispatch_started_fenced_locked(
                    db, recovery.intent, permit, fences.fences, current)
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass


def test_full_observation_restart_and_atomic_typed_finish(tmp_path, monkeypatch):
    from rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences import _PEER_A, rpc
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService

    fixture = rpc.__wrapped__(tmp_path)
    server = next(fixture)
    try:
        fences = server._v2_fences["ns-a"]
        store = AuthorityV2ModelEgressStore(fences.core._db, create=True,
                                            lock=fences.core._lock)
        service = AuthorityV2ModelEgressService(store, fences)
        anchor = fences.current_anchor(credential=_PEER_A, subject="worker")
        draft = ModelEgressDraftV1.from_intent(intent(
            namespace="ns-a", authority_id=anchor.authority_id,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
        ))
        prepared, permit = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=draft, expected_anchor=anchor)
        original = prepared.intent
        with pytest.raises(AuthorityUnavailable, match="observation"):
            service._finish_observed_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                intent=original, expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, original.operation_id)[6] == "active"
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            store._record_dispatch_started_fenced_locked(
                db, original, permit, fences.fences, current)
        with pytest.raises(ValueError, match="unsent"):
            service._record_provider_observation(
                intent=original,
                response=ProviderResponse("not_dispatched", None, None, None, None))
        assert store.read(original.call_id, subject="worker", namespace="ns-a").state == "dispatch_started"
        with pytest.raises(ValueError, match="original call"):
            service._record_provider_observation(
                intent=replace(original, request_digest="e" * 64),
                response=ProviderResponse("completed", {"answer": "wrong"},
                                          None, None, "wrong-ref"))
        parsed = ProviderResponse("completed", {"answer": {"parts": ["ok", 2]}},
                                  {"input_tokens": 4, "output_tokens": 2},
                                  {"micro_usd": 30}, "provider/ref 1")
        original_history = fences.deletion.has_deletion_history
        monkeypatch.setattr(fences.deletion, "has_deletion_history", lambda _: True)
        with pytest.raises(AuthorityUnavailable, match="deletion history"):
            service._record_provider_observation(intent=original, response=parsed)
        assert store.read(original.call_id, subject="worker", namespace="ns-a").state == "dispatch_started"
        monkeypatch.setattr(fences.deletion, "has_deletion_history", original_history)
        observed = service._record_provider_observation(intent=original, response=parsed)
        assert not hasattr(observed, "observation")
        assert observed.usage == tuple(sorted(parsed.usage.items()))
        with store._tx() as db:
            complete = store._read_observation_locked(db, original)
        assert complete.result == parsed.result
        assert complete.digest == observed.observation_digest
        with pytest.raises(AuthorityUnavailable, match="HOLD: trusted current graph"):
            service.read_observation_fenced(
                credential=_PEER_A, subject="worker", intent=original)
        monkeypatch.setattr(fences.deletion, "has_deletion_history", lambda _: True)
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=original) == (observed, permit)
        monkeypatch.setattr(fences.deletion, "has_deletion_history", original_history)
        with pytest.raises(AuthorityUnavailable, match="already resolved"):
            service._record_provider_observation(intent=original, response=parsed)
        path = fences.core._db.execute("PRAGMA database_list").fetchone()[2]
        with connection(path) as reopened:
            recovered = AuthorityV2ModelEgressStore(reopened).read(
                original.call_id, subject="worker", namespace="ns-a")
            assert recovered == observed
            assert not hasattr(recovered, "observation")
            with pytest.raises(AuthorityUnavailable):
                AuthorityV2ModelEgressStore(reopened).read(
                    original.call_id, subject="other", namespace="ns-a")
        fences.core._db.execute(
            "UPDATE authority_model_egress_observations_v1 SET observation_digest=? WHERE call_id=?",
            ("f" * 64, original.call_id))
        with pytest.raises(AuthorityUnavailable, match="invalid"):
            service._finish_observed_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                intent=original, expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, original.operation_id)[6] == "active"
        fences.core._db.execute(
            "UPDATE authority_model_egress_observations_v1 SET observation_digest=? WHERE call_id=?",
            (observed.observation_digest, original.call_id))
        original_finish = fences.fences.finish_observed_model_egress_locked

        def fail_after_update(*args, **kwargs):
            original_finish(*args, **kwargs)
            raise RuntimeError("simulated lost finish commit")

        monkeypatch.setattr(fences.fences, "finish_observed_model_egress_locked",
                            fail_after_update)
        with pytest.raises(RuntimeError, match="lost finish commit"):
            service._finish_observed_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                intent=original, expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, original.operation_id)[6] == "active"
        monkeypatch.setattr(fences.fences, "finish_observed_model_egress_locked",
                            original_finish)
        assert service._finish_observed_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            intent=original, expected_anchor=anchor) == (observed, permit)
        assert service._finish_observed_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            intent=original, expected_anchor=anchor) == (observed, permit)
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=original) == (observed, permit)
        with connection(path) as reopened:
            assert AuthorityV2ModelEgressStore(reopened).read(
                original.call_id, subject="worker", namespace="ns-a") == observed
        fences.core._db.execute(
            "CREATE TEMP TRIGGER refuse_egress_erasure BEFORE UPDATE ON "
            "authority_model_egress_observation_status_v1 "
            "BEGIN SELECT RAISE(ABORT,'simulated erasure failure'); END")
        with pytest.raises(AuthorityUnavailable, match="SQLite transaction failed"):
            with store._tx() as db:
                store._erase_observation_content_locked(db, original)
        fences.core._db.execute("DROP TRIGGER refuse_egress_erasure")
        with store._tx() as db:
            assert store._read_observation_locked(db, original) == complete
        with store._tx() as db:
            erased = store._erase_observation_content_locked(db, original)
        assert erased.content_erased
        assert (erased.state, erased.observation_digest, erased.usage, erased.cost) == (
            observed.state, observed.observation_digest, observed.usage, observed.cost)
        with store._tx() as db:
            assert store._erase_observation_content_locked(db, original) == erased
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=original) == (erased, permit)
        with store._tx() as db:
            with pytest.raises(AuthorityUnavailable, match="unavailable"):
                store._read_observation_locked(db, original)
        with connection(path) as reopened:
            assert AuthorityV2ModelEgressStore(reopened).read(
                original.call_id, subject="worker", namespace="ns-a") == erased
            assert reopened.execute(
                "SELECT COUNT(*) FROM authority_model_egress_observations_v1 WHERE call_id=?",
                (original.call_id,)).fetchone() == (0,)
        second_draft = replace(draft, operation_id="job-operation-2",
                               call_id="call-2", job_id="job-2")
        second, second_permit = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=second_draft, expected_anchor=anchor)
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            store._record_dispatch_started_fenced_locked(
                db, second.intent, second_permit, fences.fences, current)
        unknown = service._record_provider_observation(
            intent=second.intent,
            response=ProviderResponse("unknown", None, {"input_tokens": 4},
                                      {"micro_usd": 15}, "provider/ref 2"))
        assert unknown.state == "unknown"
        with pytest.raises(AuthorityUnavailable, match="observation"):
            service._finish_observed_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                intent=second.intent, expected_anchor=anchor)
        assert fences.fences._row(fences.core._db, second.intent.operation_id)[6] == "active"
        with store._tx() as db:
            unknown_erased = store._erase_observation_content_locked(db, second.intent)
        assert unknown_erased.content_erased and unknown_erased.usage == unknown.usage
        with store._tx() as db:
            with pytest.raises(AuthorityUnavailable, match="unavailable"):
                store._read_observation_locked(db, second.intent)
        with store._tx() as db:
            assert store._erase_observation_content_locked(db, second.intent) == unknown_erased
        with pytest.raises(AuthorityUnavailable):
            store.prepare(replace(second.intent, call_id="call-3", job_id="job-2",
                                  operation_id="job-operation-3"))
        with connection(path) as reopened:
            assert AuthorityV2ModelEgressStore(reopened).read(
                second.intent.call_id, subject="worker", namespace="ns-a") == unknown_erased
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass


@pytest.mark.parametrize("status", ["completed", "unknown"])
def test_terminal_observation_and_finish_share_authority_commit(tmp_path, monkeypatch, status):
    from rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences import _PEER_A, rpc
    from sylanne3.authority_service.v2_model_egress_contract import ModelEgressObservationV1
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService

    fixture = rpc.__wrapped__(tmp_path)
    server = next(fixture)
    try:
        fences = server._v2_fences["ns-a"]
        store = AuthorityV2ModelEgressStore(fences.core._db, create=True,
                                            lock=fences.core._lock)
        service = AuthorityV2ModelEgressService(store, fences)
        anchor = fences.current_anchor(credential=_PEER_A, subject="worker")
        draft = ModelEgressDraftV1.from_intent(intent(
            namespace="ns-a", authority_id=anchor.authority_id,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq))
        prepared, permit = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=draft, expected_anchor=anchor)
        original = prepared.intent
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            store._record_dispatch_started_fenced_locked(
                db, original, permit, fences.fences, current)
        response = ProviderResponse(
            status, {"answer": "ok"} if status == "completed" else None,
            {"input_tokens": 1}, {"micro_usd": 2}, "provider-ref")
        observation = ModelEgressObservationV1.from_response(original, response)
        original_finish = fences.fences.finish_terminal_model_egress_locked

        def fail_after_finish(*args, **kwargs):
            original_finish(*args, **kwargs)
            raise RuntimeError("lost terminal commit")

        monkeypatch.setattr(fences.fences, "finish_terminal_model_egress_locked",
                            fail_after_finish)
        with pytest.raises(RuntimeError, match="lost terminal commit"):
            with fences._frozen() as (db, deletion_head, execution_head, _):
                current = fences._current_locked(db, deletion_head, execution_head,
                                                  holder="holder-a")
                store._finish_terminal_observation_fenced_locked(
                    db, original, observation, permit, fences.fences, current)
        assert store.read(original.call_id, subject="worker", namespace="ns-a").state == "dispatch_started"
        assert fences.fences._row(fences.core._db, original.operation_id)[6] == "active"
        monkeypatch.setattr(fences.fences, "finish_terminal_model_egress_locked",
                            original_finish)
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            record = store._finish_terminal_observation_fenced_locked(
                db, original, observation, permit, fences.fences, current)
        assert record.state == ("observed" if status == "completed" else "unknown")
        assert fences.fences._row(fences.core._db, original.operation_id)[6] == "finished"
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=original) == (record, permit)
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            assert store._finish_terminal_observation_fenced_locked(
                db, original, observation, permit, fences.fences, current) == record
            changed = ModelEgressObservationV1.from_response(
                original, ProviderResponse("unknown", None, {}, {}, "different-ref"))
            with pytest.raises(AuthorityUnavailable, match="conflict"):
                store._finish_terminal_observation_fenced_locked(
                    db, original, changed, permit, fences.fences, current)
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass


def test_prepared_not_dispatched_closes_only_unsent_fence(tmp_path):
    from rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences import _PEER_A, rpc
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService

    fixture = rpc.__wrapped__(tmp_path)
    server = next(fixture)
    try:
        fences = server._v2_fences["ns-a"]
        store = AuthorityV2ModelEgressStore(fences.core._db, create=True,
                                            lock=fences.core._lock)
        service = AuthorityV2ModelEgressService(store, fences)
        anchor = fences.current_anchor(credential=_PEER_A, subject="worker")
        draft = ModelEgressDraftV1.from_intent(intent(
            namespace="ns-a", authority_id=anchor.authority_id,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq))
        prepared, permit = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=draft, expected_anchor=anchor)
        assert service._finish_prepared_not_dispatched_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            intent=prepared.intent, expected_anchor=anchor) == (prepared, permit)
        assert service._finish_prepared_not_dispatched_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            intent=prepared.intent, expected_anchor=anchor) == (prepared, permit)
        assert fences.fences._row(fences.core._db, prepared.intent.operation_id)[6] == "finished"
        assert service.recover_fenced(
            credential=_PEER_A, subject="worker", intent=prepared.intent) == (prepared, permit)
        second = replace(draft, operation_id="job-operation-2",
                         call_id="call-2", job_id="job-2")
        next_record, _ = service.prepare_fenced(
            credential=_PEER_A, subject="worker", holder="holder-a",
            draft=second, expected_anchor=anchor)
        with fences._frozen() as (db, deletion_head, execution_head, _):
            current = fences._current_locked(db, deletion_head, execution_head,
                                              holder="holder-a")
            store._record_dispatch_started_fenced_locked(
                db, next_record.intent,
                fences.fences._permit(fences.fences._row(db, second.operation_id)),
                fences.fences, current)
        with pytest.raises(AuthorityUnavailable, match="dispatched"):
            service._finish_prepared_not_dispatched_fenced(
                credential=_PEER_A, subject="worker", holder="holder-a",
                intent=next_record.intent, expected_anchor=anchor)
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass