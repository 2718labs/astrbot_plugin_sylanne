import asyncio
import threading
import unittest
from sylanne3.contracts import Scope, StepResult
from sylanne3.scheduler import BoundedScheduler, CapacityExceeded

S = Scope('b','p','s')
T = Scope('b','p','other')

class BlockingJob:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancel_seen = None
    def step(self, budget, cancelled):
        self.cancel_seen = cancelled
        self.started.set()
        self.release.wait(3)
        return StepResult(True, threading.get_ident())

class CounterJob:
    def __init__(self, name, order, count=1):
        self.name, self.order, self.count = name, order, count
    def step(self, budget, cancelled):
        self.order.append(self.name)
        self.count -= 1
        return StepResult(self.count == 0, self.name)

async def started(job):
    for _ in range(300):
        if job.started.is_set(): return
        await asyncio.sleep(.005)
    raise AssertionError('worker did not start')

class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_capacity_includes_running_and_cancel_waits_for_actual_exit(self):
        scheduler = BoundedScheduler(workers=1, capacity=1, quantum=2)
        job = BlockingJob()
        task = asyncio.create_task(scheduler.run(S, job))
        try:
            await started(job)
            with self.assertRaises(CapacityExceeded): await scheduler.run(S, CounterJob('overflow',[]))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
            self.assertTrue(job.cancel_seen.is_set())
            with self.assertRaises(CapacityExceeded): await scheduler.run(T, CounterJob('still full',[]))
            job.release.set()
        finally:
            job.release.set()
            await scheduler.close()
    async def test_scope_fairness_and_resumable_work(self):
        scheduler = BoundedScheduler(workers=1, capacity=8, quantum=3)
        gate = BlockingJob()
        running = asyncio.create_task(scheduler.run(S, gate))
        tasks=[]
        try:
            await started(gate)
            order=[]
            tasks=[asyncio.create_task(scheduler.run(S, CounterJob('a1',order,3))),
                   asyncio.create_task(scheduler.run(S, CounterJob('a2',order,2))),
                   asyncio.create_task(scheduler.run(T, CounterJob('b',order,2)))]
            await asyncio.sleep(0)
            gate.release.set()
            worker_id = await running
            self.assertNotEqual(worker_id, threading.get_ident())
            self.assertEqual(await asyncio.gather(*tasks), ['a1','a2','b'])
            self.assertLess(order.index('b'), order.index('a2'))
            self.assertEqual(order.count('a1'),3)
        finally:
            gate.release.set()
            await scheduler.close()
    async def test_cancel_pending_removes_it_and_frees_capacity(self):
        scheduler=BoundedScheduler(workers=1,capacity=2)
        gate=BlockingJob()
        first=asyncio.create_task(scheduler.run(S,gate))
        try:
            await started(gate)
            order=[]
            pending=asyncio.create_task(scheduler.run(S,CounterJob('cancelled',order)))
            await asyncio.sleep(0)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError): await pending
            accepted=asyncio.create_task(scheduler.run(T,CounterJob('accepted',order)))
            await asyncio.sleep(0)
            gate.release.set()
            await first
            await accepted
            self.assertEqual(order,['accepted'])
        finally:
            gate.release.set()
            await scheduler.close()
    async def test_close_joins_threads_without_blocking_loop(self):
        scheduler=BoundedScheduler(workers=2,capacity=2)
        gate=BlockingJob()
        run=asyncio.create_task(scheduler.run(S,gate))
        await started(gate)
        close=asyncio.create_task(scheduler.close())
        try:
            await asyncio.sleep(.03)
            self.assertFalse(close.done())
            self.assertTrue(gate.cancel_seen.is_set())
            gate.release.set()
            await asyncio.wait_for(close,2)
            with self.assertRaises(asyncio.CancelledError): await run
            self.assertTrue(all(not t.is_alive() for t in scheduler._threads))
            with self.assertRaises(RuntimeError): await scheduler.run(S,CounterJob('closed',[]))
            await scheduler.close()
        finally:
            gate.release.set()
            await scheduler.close()
    async def test_step_failure_releases_capacity(self):
        class Bad:
            def step(self,budget,cancelled): raise ValueError('bad step')
        scheduler=BoundedScheduler(workers=1,capacity=1)
        try:
            with self.assertRaisesRegex(ValueError,'bad step'): await scheduler.run(S,Bad())
            self.assertEqual(await scheduler.run(S,CounterJob('ok',[])),'ok')
        finally: await scheduler.close()



class SchedulerExtraTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_step_per_job_with_multiple_workers(self):
        import time
        class Guarded:
            def __init__(self):
                self.lock=threading.Lock()
                self.calls=0
            def step(self,budget,cancelled):
                if not self.lock.acquire(blocking=False): raise AssertionError('overlapping step')
                try:
                    if budget != 2: raise AssertionError('wrong quantum')
                    self.calls+=1
                    time.sleep(.001)
                    return StepResult(self.calls==20,self.calls)
                finally: self.lock.release()
        scheduler=BoundedScheduler(workers=4,capacity=4,quantum=2)
        try:
            jobs=[Guarded() for _ in range(4)]
            self.assertEqual(await asyncio.gather(*(scheduler.run(S,j) for j in jobs)),[20]*4)
        finally: await scheduler.close()
    async def test_cancel_close_caller_does_not_abandon_join(self):
        scheduler=BoundedScheduler(workers=1,capacity=1)
        gate=BlockingJob()
        running=asyncio.create_task(scheduler.run(S,gate))
        await started(gate)
        closing=asyncio.create_task(scheduler.close())
        await asyncio.sleep(.01)
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError): await closing
        gate.release.set()
        await scheduler.close()
        with self.assertRaises(asyncio.CancelledError): await running
        self.assertTrue(all(not thread.is_alive() for thread in scheduler._threads))

class SchedulerIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_active_job_rejected_until_actual_exit_then_reusable(self):
        scheduler=BoundedScheduler(workers=2,capacity=3)
        gate=BlockingJob()
        running=asyncio.create_task(scheduler.run(S,gate))
        try:
            await started(gate)
            with self.assertRaisesRegex(RuntimeError,'already active'):
                await scheduler.run(T,gate)
            running.cancel()
            with self.assertRaises(asyncio.CancelledError): await running
            with self.assertRaisesRegex(RuntimeError,'already active'):
                await scheduler.run(T,gate)
            gate.release.set()
            for _ in range(300):
                with scheduler._condition:
                    if not scheduler._active: break
                await asyncio.sleep(.005)
            # Admission permits reuse after actual exit; semantics belong to job.
            self.assertIsInstance(await scheduler.run(T,gate),int)
        finally:
            gate.release.set()
            await scheduler.close()
            if not running.done(): running.cancel()

if __name__ == '__main__': unittest.main()
