"""One bounded thread owns the production graph's synchronous lifetime."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
import inspect
from queue import Queue
from threading import BoundedSemaphore, Lock, Thread
from typing import Callable

from .contracts import CapacityExceeded


_STOP = object()


class GraphWorker:
    """Run store creation, coordinator calls, and store close on one thread.

    ``store_factory`` creates a ProductionGraphStore. When supplied,
    ``fence_port_factory`` creates the V2FencePort on the same thread before
    ``coordinator_factory`` binds it to the GraphCoordinator. A submitted callable receives that
    coordinator as its first argument. The fixed capacity counts both running
    and queued ordinary calls until the worker actually finishes them.
    """

    def __init__(self, store_factory: Callable, coordinator_factory: Callable,
                 *, fence_port_factory: Callable | None = None, capacity: int = 8) -> None:
        if not callable(store_factory) or not callable(coordinator_factory):
            raise TypeError("graph worker requires store and coordinator factories")
        if fence_port_factory is not None and not callable(fence_port_factory):
            raise TypeError("graph worker fence port factory must be callable")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("graph worker capacity must be a positive integer")
        self._store_factory = store_factory
        self._coordinator_factory = coordinator_factory
        self._fence_port_factory = fence_port_factory
        self._slots = BoundedSemaphore(capacity)
        # Ordinary work uses capacity slots. The two extra cells hold at most
        # one exclusive callback and the shutdown marker.
        self._queue: Queue = Queue(maxsize=capacity + 2)
        self._lock = Lock()
        self._closed = False
        self._callback_active = False
        self._started: Future = Future()
        self._stopped: Future = Future()
        self._thread = Thread(target=self._run, name="sylanne-graph", daemon=True)

    @classmethod
    async def start(cls, store_factory: Callable, coordinator_factory: Callable,
                    *, fence_port_factory: Callable | None = None,
                    capacity: int = 8) -> GraphWorker:
        worker = cls(store_factory, coordinator_factory,
                     fence_port_factory=fence_port_factory, capacity=capacity)
        worker._thread.start()
        try:
            await asyncio.shield(asyncio.wrap_future(worker._started))
        except BaseException:
            # A cancelled startup must not strand the newly created store.
            try:
                await worker.close()
            except BaseException:
                pass
            raise
        return worker

    def _run(self) -> None:
        store = None
        fence_port = None
        failure = None
        try:
            store = self._store_factory()
            if self._fence_port_factory is None:
                coordinator = self._coordinator_factory(store)
            else:
                fence_port = self._fence_port_factory()
                coordinator = self._coordinator_factory(store, fence_port)
            self._started.set_result(None)
            while True:
                item = self._queue.get()
                if item is _STOP:
                    break
                function, args, outcome, is_callback = item
                deliver = outcome.set_running_or_notify_cancel()
                result = None
                call_failure = None
                try:
                    result = function(coordinator, *args)
                    if inspect.isawaitable(result):
                        if inspect.iscoroutine(result):
                            result.close()
                        raise TypeError("graph worker call must be synchronous")
                except BaseException as exc:
                    call_failure = exc
                finally:
                    if is_callback:
                        with self._lock:
                            self._callback_active = False
                    else:
                        self._slots.release()
                if deliver:
                    if call_failure is None:
                        outcome.set_result(result)
                    else:
                        outcome.set_exception(call_failure)
        except BaseException as exc:
            failure = exc
        finally:
            if fence_port is not None:
                try:
                    fence_port.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            if store is not None:
                try:
                    store.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            if not self._started.done():
                self._started.set_exception(failure)
            if failure is None:
                self._stopped.set_result(None)
            else:
                self._stopped.set_exception(failure)

    async def call(self, function: Callable, *args):
        """Submit one synchronous coordinator call; cancellation leaves it owned."""
        if not callable(function):
            raise TypeError("graph worker call requires a callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("graph worker is closed")
            if self._callback_active:
                raise RuntimeError("graph worker callback window is active")
            if not self._slots.acquire(blocking=False):
                raise CapacityExceeded("graph worker capacity exhausted")
            outcome: Future = Future()
            self._queue.put_nowait((function, args, outcome, False))
        wrapped = asyncio.wrap_future(outcome)
        # An abandoned result can still be an exception; consume it while the
        # underlying graph operation finishes and releases its slot.
        wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        return await asyncio.shield(wrapped)

    async def call_exclusive_callback(self, function: Callable, *args):
        """Drain accepted calls, then run one callback with ordinary admission closed.

        The window stays closed until the worker finishes, even if this waiter
        is cancelled or times out. Concurrent callback requests fail fast.
        """
        if not callable(function):
            raise TypeError("graph worker callback requires a callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("graph worker is closed")
            if self._callback_active:
                raise RuntimeError("graph worker callback window is active")
            self._callback_active = True
            outcome: Future = Future()
            self._queue.put_nowait((function, args, outcome, True))
        wrapped = asyncio.wrap_future(outcome)
        # An abandoned result can still be an exception; consume it while the
        # underlying graph operation finishes and releases its slot.
        wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        return await asyncio.shield(wrapped)

    async def close(self) -> None:
        """Stop admission, drain accepted calls, then close the store on worker."""
        with self._lock:
            if not self._closed:
                self._closed = True
                self._queue.put_nowait(_STOP)
        try:
            await asyncio.shield(asyncio.wrap_future(self._stopped))
        finally:
            await asyncio.to_thread(self._thread.join)


__all__ = ("GraphWorker",)
