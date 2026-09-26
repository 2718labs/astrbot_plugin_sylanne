"""A reverse callback uses a graph lease acquired before Authority handoff."""

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


def test_handoff_starts_only_after_ordinary_authority_waiters_drain():
    async def scenario():
        trace = []
        first_entered, first_release = Event(), Event()
        second_entered, second_release = Event(), Event()
        callback_entered, callback_release = Event(), Event()
        authority_started = asyncio.Event()
        allow_callback = asyncio.Event()
        callback_returned = asyncio.Event()
        authority_response = asyncio.Event()
        worker = await _start(trace)
        try:
            def ordinary(_store, name, entered, release):
                entered.set()
                assert release.wait(2)
                trace.append(name)

            def callback(_store):
                callback_entered.set()
                assert callback_release.wait(2)
                trace.append("callback")
                return "callback result"

            async def dispatch_handoff():
                async with worker.exclusive_callback_window() as lease:
                    trace.append("Authority begin_handoff")
                    authority_started.set()
                    await allow_callback.wait()
                    result = await lease.call(callback)
                    callback_returned.set()
                    await authority_response.wait()
                return result

            first = asyncio.create_task(worker.call(ordinary, "first", first_entered, first_release))
            assert await asyncio.to_thread(first_entered.wait, 1)
            second = asyncio.create_task(worker.call(ordinary, "second", second_entered, second_release))
            await asyncio.sleep(0)  # The second graph call is accepted before the lease.
            handoff = asyncio.create_task(dispatch_handoff())
            await asyncio.sleep(0)

            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "late ordinary")
            assert not authority_started.is_set()
            first_release.set()
            assert await asyncio.to_thread(second_entered.wait, 1)
            assert not authority_started.is_set()
            second_release.set()
            await asyncio.wait_for(authority_started.wait(), 1)
            assert trace == ["first", "second", "Authority begin_handoff"]

            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "during Authority RPC")
            with pytest.raises(RuntimeError, match="callback window"):
                async with worker.exclusive_callback_window():
                    pass
            allow_callback.set()
            assert await asyncio.to_thread(callback_entered.wait, 1)
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "during callback")
            callback_release.set()
            await asyncio.wait_for(callback_returned.wait(), 1)
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "before Authority response")
            authority_response.set()

            assert await handoff == "callback result"
            await first
            await second
            assert trace == ["first", "second", "Authority begin_handoff", "callback"]
            assert await worker.call(lambda _: "ordinary resumed") == "ordinary resumed"
        finally:
            first_release.set()
            second_release.set()
            callback_release.set()
            allow_callback.set()
            authority_response.set()
            await worker.close()

    asyncio.run(scenario())


def test_failed_callback_stays_scoped_until_authority_recovery_finishes():
    async def scenario():
        trace = []
        worker = await _start(trace)
        try:
            def fail(_store):
                raise ValueError("callback transaction failed")

            async with worker.exclusive_callback_window() as lease:
                with pytest.raises(ValueError, match="callback transaction failed"):
                    await lease.call(fail)
                with pytest.raises(RuntimeError, match="already submitted"):
                    await lease.call(lambda _: "second callback")
                with pytest.raises(RuntimeError, match="callback window"):
                    await worker.call(lambda _: "before Authority recovery")
            assert await worker.call(lambda _: "ordinary resumed") == "ordinary resumed"
        finally:
            await worker.close()
        assert trace == ["store closed"]

    asyncio.run(scenario())


@pytest.mark.parametrize("abandon", ["cancel", "timeout"])
def test_abandoned_callback_and_concurrent_close_wait_for_lease_exit(abandon):
    async def scenario():
        trace = []
        callback_entered, callback_release = Event(), Event()
        worker = await _start(trace, capacity=1)
        try:
            def callback(_store):
                callback_entered.set()
                assert callback_release.wait(2)
                trace.append("callback finished")

            async with worker.exclusive_callback_window() as lease:
                closing = asyncio.create_task(worker.close())
                await asyncio.sleep(0)
                assert not closing.done()
                waiter = asyncio.create_task(lease.call(callback))
                assert await asyncio.to_thread(callback_entered.wait, 1)
                if abandon == "cancel":
                    waiter.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await waiter
                else:
                    with pytest.raises(TimeoutError):
                        await asyncio.wait_for(waiter, 0.02)
                assert not closing.done()
                callback_release.set()
                # Authority still owns the lease while its response/recovery completes.
                with pytest.raises(RuntimeError, match="closed"):
                    await worker.call(lambda _: "must not enter")
                assert not closing.done()
            await asyncio.wait_for(closing, 1)
            assert trace == ["callback finished", "store closed"]
        finally:
            callback_release.set()
            await worker.close()

    asyncio.run(scenario())


def test_cancelled_lease_acquisition_drains_before_reopening_admission():
    async def scenario():
        trace = []
        entered, release = Event(), Event()
        worker = await _start(trace, capacity=1)
        try:
            def ordinary(_store):
                entered.set()
                assert release.wait(2)

            running = asyncio.create_task(worker.call(ordinary))
            assert await asyncio.to_thread(entered.wait, 1)
            lease = worker.exclusive_callback_window()
            acquiring = asyncio.create_task(lease.__aenter__())
            await asyncio.sleep(0)
            acquiring.cancel()
            with pytest.raises(asyncio.CancelledError):
                await acquiring
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "before drain")
            release.set()
            await running

            async def admission_reopens():
                while True:
                    try:
                        return await worker.call(lambda _: "admitted")
                    except RuntimeError as exc:
                        assert "callback window" in str(exc)
                        await asyncio.sleep(0)

            assert await asyncio.wait_for(admission_reopens(), 1) == "admitted"
        finally:
            release.set()
            await worker.close()

    asyncio.run(scenario())


def test_cancelled_lease_exit_keeps_admission_closed_until_callback_finishes():
    async def scenario():
        trace = []
        entered, release = Event(), Event()
        worker = await _start(trace)
        try:
            def callback(_store):
                entered.set()
                assert release.wait(2)
                trace.append("callback finished")

            lease = worker.exclusive_callback_window()
            await lease.__aenter__()
            running = asyncio.create_task(lease.call(callback))
            assert await asyncio.to_thread(entered.wait, 1)
            exiting = asyncio.create_task(lease.__aexit__(None, None, None))
            await asyncio.sleep(0)
            exiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await exiting
            with pytest.raises(RuntimeError, match="callback window"):
                await worker.call(lambda _: "before callback finishes")
            release.set()
            await running

            async def admission_reopens():
                while True:
                    try:
                        return await worker.call(lambda _: "admitted")
                    except RuntimeError as exc:
                        assert "callback window" in str(exc)
                        await asyncio.sleep(0)

            assert await asyncio.wait_for(admission_reopens(), 1) == "admitted"
        finally:
            release.set()
            await worker.close()
        assert trace == ["callback finished", "store closed"]

    asyncio.run(scenario())
