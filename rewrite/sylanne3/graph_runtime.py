"""Bounded, cancellation-owned execution of a compiled graph transaction."""
import asyncio
import contextvars
import threading

from .contracts import CapacityExceeded, Event
from .delivery import _finish
from .graph_types import GraphCandidate
from .operators import OperatorPlan


_IN_RUNTIME = contextvars.ContextVar('sylanne3_graph_runtime', default=frozenset())


class _CombinedCancellation:
    def __init__(self, first, second):
        self.first, self.second = first, second

    def is_set(self):
        return self.first.is_set() or self.second.is_set()


class _OwnedJob:
    def __init__(self, job, abort):
        self.job, self.abort = job, abort

    def step(self, budget, cancelled):
        combined = _CombinedCancellation(self.abort, cancelled)
        if combined.is_set():
            raise asyncio.CancelledError
        result = self.job.step(budget, combined)
        if combined.is_set():
            raise asyncio.CancelledError
        return result


class GraphRuntime:
    """Own admitted operations; the caller owns the shared store and scheduler.

    Synchronous operators must bound their own step cost. Cancellation waits for
    any current step/SQLite call to finish. A cancelled commit may have committed;
    no delivery is performed here. Retrying uses the same immutable event identity.
    """

    def __init__(self, store, scheduler, capacity=8):
        if type(capacity) is not int or capacity < 1:
            raise ValueError('capacity must be a positive integer')
        self.store, self.scheduler = store, scheduler
        self.capacity = capacity
        self._active = set()
        self._closed = False
        self._close_task = None
        self._loop = None

    def _bind_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError('graph runtime belongs to another event loop')
        self._loop = loop
        return loop

    @staticmethod
    async def _sync(function, *args):
        result, cancellation = await _finish(asyncio.create_task(asyncio.to_thread(function, *args)))
        if cancellation is not None:
            raise cancellation
        return result

    async def apply(self, event, plan, changed=None):
        self._bind_loop()
        if self._closed:
            raise RuntimeError('graph runtime is closed')
        if self in _IN_RUNTIME.get():
            raise RuntimeError('graph runtime reentry is not allowed')
        if not isinstance(event, Event) or not isinstance(plan, OperatorPlan):
            raise TypeError('apply requires an Event and compiled OperatorPlan')
        event = Event(event.scope, event.event_id, event.occurred_at, event.kind, event.payload)
        changed = None if changed is None else tuple(changed)
        for key in plan.required_keys:
            if (key.owner.bot, key.owner.persona) != (event.scope.bot, event.scope.persona):
                raise ValueError('operator plan crosses event namespace')
        if len(self._active) >= self.capacity:
            raise CapacityExceeded('graph runtime capacity exhausted')
        task = asyncio.current_task()
        self._active.add(task)
        token = _IN_RUNTIME.set(_IN_RUNTIME.get() | {self})
        try:
            snapshot = await self._sync(self.store.graph_snapshot, plan.required_keys)
            abort = threading.Event()
            work = asyncio.create_task(self.scheduler.run(
                event.scope, _OwnedJob(plan.job(snapshot, changed), abort)))
            cancellation = None
            while True:
                try:
                    writes = await asyncio.shield(work)
                    break
                except asyncio.CancelledError as exc:
                    if work.cancelled():
                        raise
                    cancellation = cancellation or exc
                    abort.set()
            if cancellation is not None:
                raise cancellation
            return await self._sync(self.store.graph_commit, GraphCandidate(
                event, snapshot.versions, writes, snapshot.epochs))
        finally:
            _IN_RUNTIME.reset(token)
            self._active.discard(task)

    async def close(self):
        self._bind_loop()
        if self in _IN_RUNTIME.get():
            raise RuntimeError('an admitted operation cannot close its own runtime')
        self._closed = True
        if self._close_task is None:
            async def drain():
                active = tuple(self._active)
                for task in active:
                    task.cancel()
                if active:
                    await asyncio.gather(*active, return_exceptions=True)
            self._close_task = asyncio.create_task(drain())
        _, cancellation = await _finish(self._close_task)
        if cancellation is not None:
            raise cancellation
