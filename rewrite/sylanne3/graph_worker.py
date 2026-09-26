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
_WINDOW_READY = object()
_WINDOW_END = object()


class _ExclusiveCallbackWindow:
    """A dispatcher-held lease spanning Authority handoff and its reverse call."""

    def __init__(self, worker: GraphWorker) -> None:
        self._worker = worker
        self._ready: Future = Future()
        self._ended: Future = Future()
        self._entered = False
        self._ending = False
        self._called = False

    async def __aenter__(self) -> _ExclusiveCallbackWindow:
        worker = self._worker
        with worker._lock:
            if self._entered or self._ending:
                raise RuntimeError("graph worker callback window lease already used")
            if worker._closed:
                raise RuntimeError("graph worker is closed")
            if worker._callback_window is not None:
                raise RuntimeError("graph worker callback window is active")
            worker._callback_window = self
            worker._queue.put_nowait((_WINDOW_READY, self._ready))
        try:
            await asyncio.shield(asyncio.wrap_future(self._ready))
        except BaseException:
            # The marker still drains accepted calls before reopening admission.
            self._end()
            raise
        self._entered = True
        return self

    async def call(self, function: Callable, *args):
        """Submit the one synchronous reverse callback inside this window."""
        if not callable(function):
            raise TypeError("graph worker callback requires a callable")
        worker = self._worker
        with worker._lock:
            if worker._callback_window is not self or not self._entered or self._ending:
                raise RuntimeError("graph worker callback window is not open")
            if self._called:
                raise RuntimeError("graph worker callback already submitted")
            self._called = True
            outcome: Future = Future()
            worker._queue.put_nowait((function, args, outcome, True))
        wrapped = asyncio.wrap_future(outcome)
        wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        return await asyncio.shield(wrapped)

    def _end(self) -> None:
        worker = self._worker
        with worker._lock:
            if not self._ending:
                if worker._callback_window is not self:
                    raise RuntimeError("graph worker callback window is not open")
                self._ending = True
                worker._queue.put_nowait((_WINDOW_END, self, self._ended))

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        self._end()
        await asyncio.shield(asyncio.wrap_future(self._ended))


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
        # Ordinary work uses capacity slots. Two extra cells hold lease
        # barriers or the callback; shutdown waits for an active lease.
        self._queue: Queue = Queue(maxsize=capacity + 2)
        self._lock = Lock()
        self._closed = False
        self._callback_window: _ExclusiveCallbackWindow | None = None
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
                if item[0] is _WINDOW_READY:
                    item[1].set_result(None)
                    continue
                if item[0] is _WINDOW_END:
                    _, _, ended = item
                    with self._lock:
                        self._callback_window = None
                        if self._closed:
                            self._queue.put_nowait(_STOP)
                    ended.set_result(None)
                    continue
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
                    if not is_callback:
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
            if self._callback_window is not None:
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

    def exclusive_callback_window(self) -> _ExclusiveCallbackWindow:
        """Acquire before Authority handoff; release after its response or recovery."""
        return _ExclusiveCallbackWindow(self)

    async def close(self) -> None:
        """Stop admission, drain accepted calls, then close the store on worker."""
        with self._lock:
            if not self._closed:
                self._closed = True
                if self._callback_window is None:
                    self._queue.put_nowait(_STOP)
        try:
            await asyncio.shield(asyncio.wrap_future(self._stopped))
        finally:
            await asyncio.to_thread(self._thread.join)


__all__ = ("GraphWorker",)
