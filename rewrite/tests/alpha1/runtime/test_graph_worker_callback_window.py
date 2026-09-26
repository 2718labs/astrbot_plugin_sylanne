"""An Authority reverse callback cannot overtake graph calls waiting on Authority."""

import asyncio
from threading import Event

import pytest

from sylanne3.graph_worker import GraphWorker


class _Store:
    def __init__(self, trace):
        self.trace = trace

    def close(self):
        self.trace.append("store closed")


async def _start(trace, *, capacity=2):
    return await GraphWorker.start(lambda: _Store(trace), lambda store: store, capacity=capacity)


def test_callback_drains_all_accepted_authority_waiters_and_reopens_admission():
    async def scenario():
        trace = []
        first_entered, first_release = Event(), Event()
        second_entered, second_release = Event(), Event()
        callback_entered, callback_release = Event(), Event()
        worker = await _start(trace)
        try:
            def ordinary(_store, name, entered, release):
                entered.set()
                assert release.wait(2)
                trace.append(name)
                return name

            def callback(_store):
                callback_entered.set()
                assert callback_release.wait(2)
                trace.append("callback")
                return "callback result"

            first = asyncio.create_task(worker.call(ordinary, "first", first_entered, first_release))
            assert await asyncio.to_thread(first_entered.wait, 1)
            second = asyncio.create_task(worker.call(ordinary, "second", second_entered, second_release))
            await asyncio.sleep(0)  # Admit the queued call before opening the window.
            exclusive = asyncio.create_task(worker.call_exclusive_callback(callback))
            await asyncio.sleep(0)

            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "late ordinary")
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call_exclusive_callback(lambda _: "second callback")
            assert not callback_entered.is_set()

            first_release.set()
            assert await asyncio.to_thread(second_entered.wait, 1)
            assert not callback_entered.is_set()
            second_release.set()
            assert await asyncio.to_thread(callback_entered.wait, 1)
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "during callback")
            callback_release.set()

            assert await first == "first"
            assert await second == "second"
            assert await exclusive == "callback result"
            assert trace == ["first", "second", "callback"]
            assert await worker.call(lambda _: "admitted again") == "admitted again"
        finally:
            first_release.set()
            second_release.set()
            callback_release.set()
            await worker.close()

    asyncio.run(scenario())


def test_failed_callback_reopens_admission_and_close_still_succeeds():
    async def scenario():
        trace = []
        worker = await _start(trace)
        try:
            def fail(_store):
                raise ValueError("callback transaction failed")

            with pytest.raises(ValueError, match="callback transaction failed"):
                await worker.call_exclusive_callback(fail)
            assert await worker.call(lambda _: "ordinary resumed") == "ordinary resumed"
        finally:
            await worker.close()
        assert trace == ["store closed"]

    asyncio.run(scenario())


@pytest.mark.parametrize("abandon", ["cancel", "timeout"])
def test_abandoned_callback_keeps_window_until_close_drains_it(abandon):
    async def scenario():
        trace = []
        ordinary_entered, ordinary_release = Event(), Event()
        callback_entered, callback_release = Event(), Event()
        worker = await _start(trace, capacity=1)
        try:
            def ordinary(_store):
                ordinary_entered.set()
                assert ordinary_release.wait(2)
                trace.append("ordinary finished")

            def callback(_store):
                callback_entered.set()
                assert callback_release.wait(2)
                trace.append("callback finished")

            running = asyncio.create_task(worker.call(ordinary))
            assert await asyncio.to_thread(ordinary_entered.wait, 1)
            waiter = asyncio.create_task(worker.call_exclusive_callback(callback))
            await asyncio.sleep(0)
            if abandon == "cancel":
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
            else:
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(waiter, 0.02)

            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "must not enter")
            closing = asyncio.create_task(worker.close())
            await asyncio.sleep(0)
            assert not closing.done()

            ordinary_release.set()
            assert await asyncio.to_thread(callback_entered.wait, 1)
            assert not closing.done()
            callback_release.set()
            await running
            await asyncio.wait_for(closing, 1)
            assert trace == ["ordinary finished", "callback finished", "store closed"]
        finally:
            ordinary_release.set()
            callback_release.set()
            await worker.close()

    asyncio.run(scenario())
