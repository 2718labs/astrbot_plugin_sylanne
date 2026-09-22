import asyncio
from pathlib import Path
import tempfile
import threading
import unittest

from sylanne3.contracts import CapacityExceeded, Event, Scope, StaleRead
from sylanne3.graph_runtime import GraphRuntime
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.operators import OperatorSpec, compile_operators
from sylanne3.scheduler import BoundedScheduler


class GraphRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        registry = TypeRegistry()
        registry.register(TypeSpec('state', ('persona', 'relation'), 'state', lambda value: None))
        self.store = GraphStore(Path(self.tmp.name) / 'graph.db', registry)
        self.scheduler = BoundedScheduler(workers=1, capacity=4, quantum=1)
        self.runtime = GraphRuntime(self.store, self.scheduler, capacity=1)
        self.scope = Scope('bot', 'persona', 'scene')
        self.source = AtomKey(Owner('persona', 'bot', 'persona'), 'state', 'need')
        self.output = AtomKey(Owner('relation', 'bot', 'persona', 'friend'), 'state', 'readout')
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, (self.source,))
        await asyncio.to_thread(self.store.graph_commit, GraphCandidate(
            self.event('seed'), snapshot.versions, (GraphWrite(self.source, {'n': 2}),)))

    async def asyncTearDown(self):
        await self.runtime.close()
        await self.scheduler.close()
        await asyncio.to_thread(self.store.close)
        self.tmp.cleanup()

    def event(self, name):
        return Event(self.scope, name, 1.0, 'graph', {})

    def plan(self, compute=None):
        return compile_operators((OperatorSpec('readout', (self.source,), (self.output,),
            compute or (lambda values: {self.output: {'n': values[self.source]['n'] * 2}})),))

    async def test_applies_multi_owner_plan_off_event_loop_and_deduplicates_commit(self):
        event_thread = threading.get_ident()
        threads = []
        def compute(values):
            threads.append(threading.get_ident())
            return {self.output: {'n': values[self.source]['n'] * 2}}
        plan = self.plan(compute)
        receipt = await self.runtime.apply(self.event('apply'), plan)
        self.assertEqual(receipt.status, 'committed')
        self.assertNotEqual(threads[0], event_thread)
        self.assertEqual((await self.runtime.apply(self.event('apply'), plan)).status, 'duplicate')
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, (self.output,))
        self.assertEqual(snapshot.get(self.output).value, {'n': 4})
        self.assertEqual(snapshot.get(self.output).revision, 1)

    async def test_stale_snapshot_and_capacity_reject_without_partial_commit(self):
        entered, release = threading.Event(), threading.Event()
        def compute(values):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test release was not signalled')
            return {self.output: values[self.source]}
        task = asyncio.create_task(self.runtime.apply(self.event('blocked'), self.plan(compute)))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            with self.assertRaises(CapacityExceeded):
                await self.runtime.apply(self.event('overflow'), self.plan())
            current = await asyncio.to_thread(self.store.graph_snapshot, (self.source,))
            await asyncio.to_thread(self.store.graph_commit, GraphCandidate(
                self.event('changed'), current.versions, (GraphWrite(self.source, {'n': 8}),)))
        finally:
            release.set()
        with self.assertRaises(StaleRead):
            await task
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, (self.output,))
        self.assertEqual(snapshot.get(self.output).revision, 0)

    async def test_repeated_cancel_joins_running_operator_and_does_not_commit(self):
        entered, release = threading.Event(), threading.Event()
        def compute(values):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test release was not signalled')
            return {self.output: values[self.source]}
        task = asyncio.create_task(self.runtime.apply(self.event('cancelled'), self.plan(compute)))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, (self.output,))
        self.assertEqual(snapshot.get(self.output).revision, 0)
        self.assertEqual((await self.runtime.apply(self.event('after-cancel'), self.plan())).status, 'committed')

    async def test_close_keeps_shared_resources_available(self):
        await self.runtime.close()
        with self.assertRaises(RuntimeError):
            await self.runtime.apply(self.event('closed'), self.plan())
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, self.plan().required_keys)
        writes = await self.scheduler.run(self.scope, self.plan().job(snapshot))
        self.assertEqual(writes[0].value, {'n': 4})

    async def test_cancel_during_commit_joins_and_preserves_actual_committed_result(self):
        entered, release = threading.Event(), threading.Event()
        commit = self.store.graph_commit
        def slow_commit(candidate):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test release was not signalled')
            return commit(candidate)
        self.store.graph_commit = slow_commit
        task = asyncio.create_task(self.runtime.apply(self.event('commit-cancel'), self.plan()))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.store.graph_commit = commit
        snapshot = await asyncio.to_thread(self.store.graph_snapshot, (self.output,))
        self.assertEqual(snapshot.get(self.output).revision, 1)
        self.assertEqual(snapshot.get(self.output).value, {'n': 4})
        self.assertEqual((await self.runtime.apply(self.event('commit-cancel'), self.plan())).status, 'duplicate')


if __name__ == '__main__':
    unittest.main()
