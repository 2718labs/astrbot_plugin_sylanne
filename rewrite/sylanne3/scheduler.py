"""A fixed CPU worker pool with scope round-robin and cooperative cancellation."""
import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import threading
from .contracts import Scope, StepResult, CapacityExceeded

@dataclass(eq=False)
class _Work:
    scope: Scope
    job: object
    loop: object
    future: object
    cancelled: threading.Event = field(default_factory=threading.Event)
    running: bool = False

class BoundedScheduler:
    """Each synchronous step must honor its bounded budget and cancellation token.

    Python cannot safely terminate an uncooperative thread. Such a step retains
    its admission slot until it exits, and close waits for actual worker exit.
    One scheduler belongs to one asyncio event loop. An active job object cannot
    be submitted again, even under another scope. After actual exit it may be
    submitted again; the job itself defines completed-job reuse semantics.
    """
    def __init__(self, workers=2, capacity=32, quantum=4):
        for name, value in (('workers',workers),('capacity',capacity),('quantum',quantum)):
            if type(value) is not int or value < 1: raise ValueError(f'{name} must be a positive integer')
        self._capacity = capacity
        self._quantum = quantum
        self._condition = threading.Condition()
        self._queues = OrderedDict()
        self._active = set()
        self._closed = False
        self._loop = None
        self._close_task = None
        self._threads = [threading.Thread(target=self._worker, name=f'sylanne3-worker-{id(self):x}-{i}') for i in range(workers)]
        for thread in self._threads: thread.start()

    def _enqueue(self, work):
        self._queues.setdefault(work.scope, deque()).append(work)
        self._condition.notify()

    @staticmethod
    def _deliver(work, result=None, error=None):
        if work.future.done(): return
        if work.cancelled.is_set() or isinstance(error, asyncio.CancelledError):
            work.future.cancel()
        elif error is not None:
            work.future.set_exception(error)
        else:
            work.future.set_result(result)

    def _notify_result(self, work, result=None, error=None):
        work.loop.call_soon_threadsafe(self._deliver, work, result, error)

    def _worker(self):
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._closed or bool(self._queues))
                if self._closed: return
                scope, queue = self._queues.popitem(last=False)
                work = queue.popleft()
                if queue: self._queues[scope] = queue
                work.running = True
            result = None
            error = None
            try:
                if not work.cancelled.is_set():
                    result = work.job.step(self._quantum, work.cancelled)
                    if not isinstance(result, StepResult): raise TypeError('job.step must return StepResult')
            except BaseException as exc:
                error = exc
            with self._condition:
                work.running = False
                if self._closed or work.cancelled.is_set() or error is not None or result.done:
                    self._active.discard(work)
                    self._notify_result(work, result.value if result else None, error)
                else:
                    self._enqueue(work)

    async def run(self, scope, job):
        if not isinstance(scope, Scope): raise TypeError('scope must be Scope')
        if not callable(getattr(job, 'step', None)): raise TypeError('job must implement step')
        loop = asyncio.get_running_loop()
        with self._condition:
            if self._closed: raise RuntimeError('scheduler is closed')
            if self._loop is not None and self._loop is not loop:
                raise RuntimeError('scheduler belongs to a different event loop')
            self._loop = loop
            if any(active.job is job for active in self._active):
                raise RuntimeError('job object is already active')
            if len(self._active) >= self._capacity: raise CapacityExceeded('scheduler capacity exhausted')
            work = _Work(scope, job, loop, loop.create_future())
            self._active.add(work)
            self._enqueue(work)
        try:
            return await asyncio.shield(work.future)
        except asyncio.CancelledError:
            with self._condition:
                work.cancelled.set()
                if not work.running:
                    queue = self._queues.get(scope)
                    if queue is not None:
                        try: queue.remove(work)
                        except ValueError: pass
                        if not queue: del self._queues[scope]
                    self._active.discard(work)
                work.future.cancel()
            raise

    def _join(self):
        for thread in self._threads: thread.join()

    async def close(self):
        loop = asyncio.get_running_loop()
        with self._condition:
            if self._loop is not None and self._loop is not loop:
                raise RuntimeError('scheduler belongs to a different event loop')
            if not self._closed:
                self._closed = True
                for work in tuple(self._active):
                    work.cancelled.set()
                    self._notify_result(work)
                    if not work.running: self._active.discard(work)
                self._queues.clear()
                self._condition.notify_all()
            if self._close_task is None:
                self._close_task = loop.create_task(asyncio.to_thread(self._join))
        # Shield ensures a cancelled close caller cannot cancel joining workers.
        await asyncio.shield(self._close_task)
