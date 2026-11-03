"""The asyncio host never executes synchronous graph work on its loop."""

import asyncio
from threading import Event, get_ident

import pytest

from sylanne3.contracts import CapacityExceeded
from sylanne3.graph_worker import GraphWorker


class _Store:
    def __init__(self, trace):
        self.trace = trace
        trace.append(("store_open", get_ident()))

    def close(self):
        self.trace.append(("store_close", get_ident()))


def _factory(trace):
    def make_store():
        return _Store(trace)

    def make_coordinator(store):
        trace.append(("coordinator_open", get_ident()))
        return store

    return make_store, make_coordinator


def test_store_coordinator_calls_and_close_share_one_worker_thread():
    async def scenario():
        trace = []
        worker = await GraphWorker.start(*_factory(trace))
        loop_thread = get_ident()
        try:
            first = await worker.call(lambda coordinator: ("call", get_ident()))
            second = await worker.call(lambda coordinator, number: (number, get_ident()), 7)
        finally:
            await worker.close()
        assert first == ("call", second[1])
        assert second[0] == 7
        assert first[1] != loop_thread
        assert {thread for _, thread in trace} == {first[1]}

    asyncio.run(scenario())


def test_blocked_graph_call_does_not_block_event_loop():
    async def scenario():
        gate = Event()
        entered = Event()
        worker = await GraphWorker.start(*_factory([]))
        try:
            def blocked(_coordinator):
                entered.set()
                assert gate.wait(2)
                return "finished"

            work = asyncio.create_task(worker.call(blocked))
            assert await asyncio.to_thread(entered.wait, 1)
            await asyncio.wait_for(asyncio.sleep(0.01), timeout=0.2)
            assert not work.done()
            gate.set()
            assert await asyncio.wait_for(work, timeout=1) == "finished"
        finally:
            gate.set()
            await worker.close()

    asyncio.run(scenario())


def test_cancelled_waiter_keeps_running_slot_and_capacity_is_bounded():
    async def scenario():
        gate = Event()
        entered = Event()
        finished = Event()
        worker = await GraphWorker.start(*_factory([]), capacity=1)
        try:
            def blocked(_coordinator):
                entered.set()
                assert gate.wait(2)
                finished.set()

            waiter = asyncio.create_task(worker.call(blocked))
            assert await asyncio.to_thread(entered.wait, 1)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            with pytest.raises(CapacityExceeded):
                await worker.call(lambda _: "must not enter")
            assert not finished.is_set()
            gate.set()
            await worker.close()
            assert finished.is_set()
        finally:
            gate.set()
            await worker.close()

    asyncio.run(scenario())


def test_close_rejects_new_work_and_drains_queued_calls():
    async def scenario():
        trace = []
        gate = Event()
        entered = Event()
        worker = await GraphWorker.start(*_factory(trace), capacity=2)
        try:
            def blocked(_coordinator):
                entered.set()
                assert gate.wait(2)
                return "first"

            first = asyncio.create_task(worker.call(blocked))
            assert await asyncio.to_thread(entered.wait, 1)
            second = asyncio.create_task(worker.call(lambda _: "second"))
            await asyncio.sleep(0)
            with pytest.raises(CapacityExceeded):
                await worker.call(lambda _: "third")
            closing = asyncio.create_task(worker.close())
            await asyncio.sleep(0)
            with pytest.raises(RuntimeError, match="closed"):
                await worker.call(lambda _: "late")
            assert not closing.done()
            gate.set()
            assert await first == "first"
            assert await second == "second"
            await closing
            assert trace[-1][0] == "store_close"
        finally:
            gate.set()
            await worker.close()

    asyncio.run(scenario())


def test_v2_port_creation_binding_and_shutdown_share_graph_thread():
    async def scenario():
        trace = []
        store_factory, _ = _factory(trace)

        class Port:
            def __init__(self):
                trace.append(("port_open", get_ident()))

            def close(self):
                trace.append(("port_close", get_ident()))

        def make_coordinator(store, port):
            trace.append(("coordinator_open", get_ident()))
            return store, port

        worker = await GraphWorker.start(
            store_factory, make_coordinator, fence_port_factory=Port,
        )
        try:
            worker_thread = await worker.call(lambda _: get_ident())
        finally:
            await worker.close()
        assert [event for event, _ in trace] == [
            "store_open", "port_open", "coordinator_open", "port_close", "store_close",
        ]
        assert worker_thread != get_ident()
        assert {thread for _, thread in trace} == {worker_thread}

    asyncio.run(scenario())


def test_v2_port_and_store_close_when_coordinator_factory_fails():
    async def scenario():
        trace = []
        store_factory, _ = _factory(trace)

        class Port:
            def __init__(self):
                trace.append(("port_open", get_ident()))

            def close(self):
                trace.append(("port_close", get_ident()))

        def fail(_store, _port):
            raise RuntimeError("binding failed")

        with pytest.raises(RuntimeError, match="binding failed"):
            await GraphWorker.start(store_factory, fail, fence_port_factory=Port)
        assert [event for event, _ in trace] == [
            "store_open", "port_open", "port_close", "store_close",
        ]
        assert len({thread for _, thread in trace}) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ("moved", "abandoned", "cleanup_error"))
def test_owned_storage_payload_cleanup_keeps_same_lease(mode):
    """Actual retention ownership; this test issues no Graph/Owner permission."""
    from types import SimpleNamespace
    from sylanne3.graph_worker import OwnedGraphStorageResultV3, _RESULT_ISSUER_V3
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED

    pool = _RuntimeResourcePoolV3()
    baseline = pool.used
    handle = SimpleNamespace(pool=pool, selection_digest="ownership-unit")
    lease = RuntimeStorageOperationV3(_INSTALLED, handle, "ownership-unit", None)
    lease.retain(1024)
    released = []
    def cleanup():
        released.append((lease.closed, pool.used))
        if mode == "cleanup_error":
            raise ValueError("fixture payload cleanup failure")
    payload = {"retained": "value"}
    owned = OwnedGraphStorageResultV3(_RESULT_ISSUER_V3, payload, lease, cleanup)
    if mode == "abandoned":
        owned.release_v3()
    else:
        value, actual_lease = owned.take_value_v3()
        assert value is payload and actual_lease is lease
        owned.release_v3()
        assert released == [] and not lease.closed
        if mode == "cleanup_error":
            with pytest.raises(ValueError, match="fixture payload cleanup failure"):
                actual_lease.release()
        else:
            actual_lease.release()
    assert released == [(mode != "abandoned", baseline + 1024)]
    assert lease.closed and pool.used == baseline
    lease.release()
    owned.release_v3()
    assert len(released) == 1 and pool.used == baseline


@pytest.mark.parametrize("error", (None, RuntimeError, asyncio.CancelledError))
def test_background_consumer_keeps_actual_payload_until_await_finishes(error):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from sylanne3.graph_worker import OwnedGraphStorageResultV3, _RESULT_ISSUER_V3
    from sylanne3.runtime_context import RuntimeContext
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED

    async def scenario():
        pool = _RuntimeResourcePoolV3()
        baseline = pool.used
        handle = SimpleNamespace(pool=pool, selection_digest="background-consumer")
        lease = RuntimeStorageOperationV3(_INSTALLED, handle, "background-consumer", None)
        lease.retain(1024)
        payload = {"status": "progressed", "receipt": {"source_payload": "not-a-status"}}
        released = []

        def cleanup():
            released.append(True)
            payload.clear()

        owned = OwnedGraphStorageResultV3(_RESULT_ISSUER_V3, payload, lease, cleanup)
        summary = None
        with pytest.raises(error) if error is not None else nullcontext():
            with RuntimeContext._background_graph_result_v3(owned) as current:
                try:
                    assert current is payload and not lease.closed
                    await asyncio.sleep(0)
                    assert pool.used == baseline + 1024 and released == []
                    summary = RuntimeContext._background_status_v3(current)
                    if error is not None:
                        raise error()
                finally:
                    current = None
        assert summary == {"status": "progressed"}
        assert released == [True] and payload == {}
        assert lease.closed and pool.used == baseline

    asyncio.run(scenario())


def test_d07_reflection_consumer_unwraps_owned_before_waking(monkeypatch):
    """Consume a real owned result at the worker boundary, without issuing execution rights."""
    import sqlite3
    from threading import RLock
    from types import SimpleNamespace
    from sylanne3.graph_worker import OwnedGraphStorageResultV3, _RESULT_ISSUER_V3
    from sylanne3.runtime.d07_execution_v1 import TABLE
    from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    from sylanne3.runtime import d07_graph_stages_v1
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED

    async def scenario():
        pool = _RuntimeResourcePoolV3()
        baseline = pool.used
        lease = RuntimeStorageOperationV3(_INSTALLED,
            SimpleNamespace(pool=pool, selection_digest="reflection-consumer"),
            "reflection-consumer", None)
        lease.retain(1024)
        payload = {"status": "prepared", "job_id": "actual-job",
                   "prepared_digest": "1" * 64, "source_payload": ["excluded"]}
        owned = OwnedGraphStorageResultV3(_RESULT_ISSUER_V3, payload, lease, payload.clear)
        monkeypatch.setattr(d07_graph_stages_v1,
            "prepare_current_d07_reflection_continuation_v3", lambda *a, **kw: owned)

        class WorkerBoundary:
            async def call(self, callback):
                return callback(None)

        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE " + TABLE +
                       " (bot TEXT,persona TEXT,kind TEXT,original_ref TEXT)")
            db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?)",
                       ("bot", "persona", "reflection_continuation", "reflection"))
            service = object.__new__(InstalledD07ExecutionServiceV1)
            service.worker = WorkerBoundary()
            service._closed = service._reflection_discovery_active = False
            service._reflection_rescan_requested = False
            service.owner_loop = asyncio.get_running_loop()
            service._db = db
            service._store = SimpleNamespace(_lock=RLock())
            service.bundle = SimpleNamespace(installation_policy=SimpleNamespace(
                namespace=NamespaceId("bot", "persona")))
            service.bootstrap = None
            service._wake_seen = set()
            wakes = []

            def wake(job_id):
                assert lease.closed and pool.used == baseline and payload == {}
                wakes.append(job_id)

            service.wake_committed_job_v1 = wake
            result = await service.resume_pending_reflections_v3()
            assert result == ({"status": "prepared", "job_id": "actual-job",
                               "prepared_digest": "1" * 64},)
            assert wakes == ["actual-job"]
            assert service._reflection_discovery_active is False
        finally:
            db.close()

    asyncio.run(scenario())
