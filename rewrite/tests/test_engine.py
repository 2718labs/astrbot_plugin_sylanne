import asyncio
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from sylanne3.contracts import Scope, Event
from sylanne3.store import Store
from sylanne3.scheduler import BoundedScheduler
from sylanne3.native import NativeKernel
from sylanne3.engine import Engine, SemanticConflict
from sylanne3.delivery import RecordingTransport, DeliveryFailed, dispatch


REFERENCE_LIBRARY = Path(__file__).resolve().parents[1] / "native" / "target" / "release" / (
    "sylanne3_kernel.dll" if sys.platform == "win32" else
    "libsylanne3_kernel.dylib" if sys.platform == "darwin" else
    "libsylanne3_kernel.so"
)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / 'state.sqlite')
        self.scheduler = BoundedScheduler(workers=2, capacity=16, quantum=1)
        self.transport = RecordingTransport()
        self.kernel = NativeKernel(REFERENCE_LIBRARY, developer_reference=True)
        self.engine = Engine(self.store, self.scheduler, self.kernel, self.transport)
        self.scope = Scope('bot', 'alice', 'session')

    async def asyncTearDown(self):
        await self.scheduler.close()
        self.store.close()
        self.tmp.cleanup()

    def evidence(self, eid='one', drive=(6., 0.), start=0., end=1., scope=None):
        scope = scope or self.scope
        return Event(scope, eid, end, 'interpretation', {
            'interpretation_id': eid, 'subject': {'bot': scope.bot, 'persona': scope.persona, 'session': scope.session},
            'proposition': 'A typed fixture attribution', 'drive': list(drive), 'start_at': start})

    async def test_real_chain_correction_duplicate_history_and_isolation(self):
        first = await self.engine.handle(self.evidence())
        self.assertEqual(first.delivery_status, 'delivered')
        self.assertGreater(first.reaction[0], 0)
        duplicate = await self.engine.handle(self.evidence())
        self.assertEqual(duplicate.status, 'duplicate')
        self.assertEqual(len(self.transport.sent), 1)
        other = Scope('bot', 'bob', 'session')
        await self.engine.handle(self.evidence('other', scope=other))
        before = self.store.snapshot(other, ('reaction',))
        correction = await self.engine.handle(Event(self.scope, 'fix', 3., 'correction', {'target_interpretation_id': 'one'}))
        self.assertEqual(correction.reaction, (0., 0.))
        self.assertNotEqual(first.action.expression, correction.action.expression)
        self.assertEqual(self.store.snapshot(other, ('reaction',)), before)
        actions = self.store.snapshot(self.scope, ('actions',)).get('actions').value['items']
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(a['delivery_status'] == 'delivered' for a in actions.values()))
        self.assertEqual(len(self.transport.sent), 3)

    async def test_replay_keeps_valid_evidence_and_original_time(self):
        await self.engine.handle(self.evidence('bad', (6., 0.), 0., 1.))
        await self.engine.handle(self.evidence('good', (0., 4.), 1., 2.))
        actual = await self.engine.handle(Event(self.scope, 'fix', 3., 'correction', {'target_interpretation_id': 'bad'}))
        other = Scope('bot', 'control', 'session')
        await self.engine.handle(self.evidence('zero', (0., 0.), 0., 1., other))
        await self.engine.handle(self.evidence('good-control', (0., 4.), 1., 2., other))
        expected = await self.engine.handle(Event(other, 'fix-control', 3., 'correction', {'target_interpretation_id': 'zero'}))
        for a, b in zip(actual.reaction, expected.reaction):
            self.assertAlmostEqual(a, b, places=8)
        self.assertGreater(actual.reaction[1], 0.)

    async def test_cross_scope_subject_rejected_and_missing_correction_rejected(self):
        ev = self.evidence()
        ev.payload['subject']['persona'] = 'other'
        with self.assertRaises(SemanticConflict):
            await self.engine.handle(ev)
        with self.assertRaises(SemanticConflict):
            await self.engine.handle(Event(self.scope, 'fix', 1., 'correction', {'target_interpretation_id': 'absent'}))
        self.assertEqual(self.transport.sent, [])

    async def test_send_exception_is_unknown_and_not_retried(self):
        class AcceptedThenBroken:
            calls = 0
            async def send(inner, action):
                inner.calls += 1
                raise RuntimeError('connection dropped after possible acceptance')
        sink = AcceptedThenBroken()
        engine = Engine(self.store, self.scheduler, self.kernel, sink)
        result = await engine.handle(self.evidence())
        self.assertEqual(result.delivery_status, 'unknown')
        await engine.handle(self.evidence())
        self.assertEqual(sink.calls, 1)

    async def test_definite_failure_is_failed(self):
        class Rejected:
            async def send(inner, action):
                raise DeliveryFailed('definitely rejected before acceptance')
        result = await Engine(self.store, self.scheduler, self.kernel, Rejected()).handle(self.evidence())
        self.assertEqual(result.delivery_status, 'failed')

    async def test_cancel_after_send_entry_records_unknown(self):
        entered = asyncio.Event()
        class Blocking:
            async def send(inner, action):
                entered.set()
                await asyncio.Event().wait()
        engine = Engine(self.store, self.scheduler, self.kernel, Blocking())
        task = asyncio.create_task(engine.handle(self.evidence()))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        outbox = self.store.snapshot(self.scope, ('outbox',)).get('outbox').value['items']
        self.assertEqual(next(iter(outbox.values()))['status'], 'unknown')
        self.assertEqual((await engine.handle(self.evidence())).status, 'duplicate')

    async def test_counterfactual_relevant_state_and_irrelevant_proposition(self):
        positive = await self.engine.handle(self.evidence())
        negative = await self.engine.handle(self.evidence('negative', (-6., 0.), scope=Scope('b', 'p', 's')))
        same = self.evidence('same', scope=Scope('c', 'p', 's'))
        same.payload['proposition'] = 'Different wording, same typed evidence'
        alternate = await self.engine.handle(same)
        self.assertNotEqual(positive.action.expression, negative.action.expression)
        self.assertEqual(positive.action.expression, alternate.action.expression)

    async def test_superseded_pending_action_is_not_sent(self):
        pending = await self.engine.prepare(self.evidence())
        self.assertEqual(pending.delivery_status, 'pending')
        await self.engine.handle(Event(self.scope, 'fix', 2., 'correction', {'target_interpretation_id': 'one'}))
        outcome = await dispatch(self.store, self.transport, pending.action)
        self.assertEqual(outcome, 'not_claimed')
        self.assertEqual(len(self.transport.sent), 1)
        row = self.store.snapshot(self.scope, ('outbox',)).get('outbox').value['items'][pending.action.action_id]
        self.assertEqual(row['status'], 'superseded')

    async def test_same_event_id_different_scope_has_distinct_action_id(self):
        first = await self.engine.handle(self.evidence())
        second = await self.engine.handle(self.evidence(scope=Scope('other', 'alice', 'session')))
        self.assertNotEqual(first.action.action_id, second.action.action_id)

    async def test_revision_change_invalidates_pending_claim(self):
        from sylanne3.contracts import Candidate, Write
        prepared = await self.engine.prepare(self.evidence())
        snapshot = self.store.snapshot(self.scope, ('reaction',))
        value = snapshot.get('reaction').value
        value['state'] = [99., 99.]
        self.store.commit(Candidate(Event(self.scope, 'external-state-change', 1., 'fixture', {}),
                                    snapshot.versions, (Write('reaction', value),)))
        self.assertEqual(await dispatch(self.store, self.transport, prepared.action), 'not_claimed')
        self.assertEqual(self.transport.sent, [])
    async def test_concurrent_candidates_reject_stale_complete_chain(self):
        # Instrument the real SQLite store only to hold two detached snapshots at
        # the same revision. All commit, scheduler and native work remains real.
        barrier = threading.Barrier(2)
        class SynchronizedStore(Store):
            def snapshot(inner, scope, names):
                value = super().snapshot(scope, names)
                if tuple(names) == ('reaction', 'interpretations', 'actions', 'outbox'):
                    barrier.wait(timeout=5)
                return value
        self.store.close()
        self.store = SynchronizedStore(Path(self.tmp.name) / 'race.sqlite')
        self.engine = Engine(self.store, self.scheduler, self.kernel, self.transport)
        results = await asyncio.gather(self.engine.prepare(self.evidence('a')),
                                       self.engine.prepare(self.evidence('b')))
        self.assertEqual(sorted(r.status for r in results), ['committed', 'stale'])
        rows = self.store.snapshot(self.scope, ('actions',)).get('actions').value['items']
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.transport.sent, [])

    async def test_restart_does_not_resend_and_retains_history(self):
        first = await self.engine.handle(self.evidence())
        self.store.close()
        self.store = Store(Path(self.tmp.name) / 'state.sqlite')
        sink = RecordingTransport()
        engine = Engine(self.store, self.scheduler, self.kernel, sink)
        duplicate = await engine.handle(self.evidence())
        self.assertEqual(duplicate.status, 'duplicate')
        self.assertEqual(duplicate.action, first.action)
        self.assertEqual(sink.sent, [])
    async def test_cancel_during_claim_commit_is_settled_without_send(self):
        entered = threading.Event()
        release = threading.Event()
        class DelayedClaimStore(Store):
            def commit(inner, candidate):
                if candidate.event.kind == '_delivery_sending':
                    entered.set()
                    if not release.wait(5):
                        raise RuntimeError('test release timed out')
                return super().commit(candidate)
        self.store.close()
        self.store = DelayedClaimStore(Path(self.tmp.name) / 'claim-race.sqlite')
        engine = Engine(self.store, self.scheduler, self.kernel, self.transport)
        task = asyncio.create_task(engine.handle(self.evidence()))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        row = self.store.snapshot(self.scope, ('outbox',)).get('outbox').value['items']
        item = next(iter(row.values()))
        self.assertEqual(item['status'], 'failed')
        self.assertEqual(item['detail'], 'cancelled_before_send')
        self.assertEqual(self.transport.sent, [])

    async def _cancel_during_prepare_commit(self, cancel_count):
        entered = threading.Barrier(2)
        release = threading.Event()

        class DelayedPrepareStore(Store):
            def commit(inner, candidate):
                if candidate.event.kind == 'interpretation':
                    entered.wait(timeout=5)
                    if not release.wait(5):
                        raise RuntimeError('test release timed out')
                return super().commit(candidate)

        self.store.close()
        path = Path(self.tmp.name) / f'prepare-cancel-{cancel_count}.sqlite'
        self.store = DelayedPrepareStore(path)
        engine = Engine(self.store, self.scheduler, self.kernel, self.transport)
        task = asyncio.create_task(engine.handle(self.evidence()))
        await asyncio.to_thread(entered.wait, 5)
        try:
            for _ in range(cancel_count):
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done(), 'prepare returned before its commit thread exited')
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.transport.sent, [])

        # Reopen the real database connection to prove the completed commit is
        # durable and its four-atom dependency chain is coherent.
        self.store.close()
        self.store = Store(path)
        snapshot = self.store.snapshot(self.scope, ('reaction', 'interpretations', 'actions', 'outbox'))
        self.assertEqual({atom.revision for atom in snapshot.atoms}, {1})
        reaction = snapshot.get('reaction').value
        ledger = snapshot.get('interpretations').value
        actions = snapshot.get('actions').value['items']
        outbox = snapshot.get('outbox').value['items']
        self.assertEqual(reaction['source_event_id'], 'one')
        action_id = ledger['events']['one']['action_id']
        self.assertEqual(set(actions), {action_id})
        self.assertEqual(set(outbox), {action_id})
        self.assertEqual(actions[action_id]['delivery_status'], 'pending')
        self.assertEqual(outbox[action_id]['status'], 'pending')

        await self.scheduler.close()
        self.store.close()

    async def test_cancel_during_prepare_commit_waits_and_never_dispatches(self):
        await self._cancel_during_prepare_commit(1)

    async def test_second_cancel_during_prepare_commit_still_waits_and_never_dispatches(self):
        await self._cancel_during_prepare_commit(2)
