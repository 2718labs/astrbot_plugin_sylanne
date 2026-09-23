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
