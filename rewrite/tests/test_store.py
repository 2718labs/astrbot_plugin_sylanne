import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from sylanne3.contracts import Scope, Event, Candidate, Write, AtomVersion
from sylanne3.store import Store, StaleRead, EventConflict

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'state.db'
        self.store = Store(self.path)
        self.scope = Scope('bot', 'persona', 'session')
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def candidate(self, event_id='e', names=('x',), values=None, scope=None):
        scope = scope or self.scope
        snap = self.store.snapshot(scope, names)
        return Candidate(Event(scope, event_id, 1., 'test', {}), snap.versions,
                         tuple(Write(n, v) for n,v in (values or {'x': {'n': [1]}}).items()))
    def test_absence_restart_and_boundary_copies(self):
        snap = self.store.snapshot(self.scope, ['x'])
        self.assertEqual(snap.versions, (AtomVersion('x', 0),))
        self.assertIsNone(snap.get('unrequested'))
        candidate = self.candidate()
        self.store.commit(candidate)
        candidate.writes[0].value['n'].append(99)
        first = self.store.snapshot(self.scope, ['x'])
        first.get('x').value['n'].append(88)
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.snapshot(self.scope, ['x']).get('x').value, {'n': [1]})
    def test_complete_read_set_atomic_stale_absence(self):
        stale = self.candidate('stale', ('x','dependency'), {'x': {'n': 2}})
        self.store.commit(self.candidate('dependency', ('dependency',), {'dependency': {}}))
        with self.assertRaises(StaleRead): self.store.commit(stale)
        self.assertEqual(self.store.snapshot(self.scope, ['x']).get('x').revision, 0)
        current = self.candidate('stale', ('x','dependency'), {'x': {'n': 2}})
        self.assertEqual(self.store.commit(current).status, 'committed')
    def test_duplicate_and_conflicting_event(self):
        c = self.candidate()
        receipt = self.store.commit(c)
        duplicate = self.store.commit(c)
        self.assertEqual(duplicate.status, 'duplicate')
        self.assertEqual(duplicate.revisions, receipt.revisions)
        changed = Candidate(Event(self.scope, 'e', 1., 'test', {'changed': True}), c.reads, c.writes)
        with self.assertRaises(EventConflict): self.store.commit(changed)
    def test_scope_keys_include_every_component(self):
        for i, scope in enumerate((self.scope, Scope('other','persona','session'), Scope('bot','other','session'), Scope('bot','persona','other'))):
            self.store.commit(self.candidate('same', scope=scope, values={'x': {'i': i}}))
            self.assertEqual(self.store.snapshot(scope, ['x']).get('x').value, {'i': i})
    def test_validation_before_mutation(self):
        c = self.candidate(names=('x','y'), values={'x': {}, 'y': {}})
        c.writes[1].value['bad'] = float('nan')
        with self.assertRaises(ValueError): self.store.commit(c)
        self.assertEqual(self.store.snapshot(self.scope, ['x','y']).versions, (AtomVersion('x',0),AtomVersion('y',0)))
        for invalid in (Candidate(c.event, (), (Write('x', {}),)), Candidate(c.event, (AtomVersion('x',0),)*2, ()), Candidate(c.event, (AtomVersion('x',0),), (Write('x',{}),)*2)):
            with self.assertRaises(ValueError): self.store.commit(invalid)
    def test_database_failure_rolls_back_writes_and_event(self):
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE TRIGGER reject_y BEFORE INSERT ON atoms WHEN NEW.name = 'y' BEGIN SELECT RAISE(ABORT, 'injected'); END")
        conn.commit()
        c = self.candidate(names=('x','y'), values={'x': {}, 'y': {}})
        with self.assertRaises(sqlite3.IntegrityError): self.store.commit(c)
        self.assertEqual(self.store.snapshot(self.scope, ['x']).get('x').revision, 0)
        conn.execute('DROP TRIGGER reject_y')
        conn.commit()
        conn.close()
        self.assertEqual(self.store.commit(c).status, 'committed')
    def test_independent_connection_cas(self):
        other = Store(self.path)
        try:
            c = self.candidate()
            other.commit(c)
            changed = Candidate(Event(self.scope, 'second', 1., 'test', {}), c.reads, c.writes)
            with self.assertRaises(StaleRead): self.store.commit(changed)
        finally: other.close()



class StoreConcurrencyTests(unittest.TestCase):
    def test_simultaneous_connections_only_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        with tempfile.TemporaryDirectory() as folder:
            stores = [Store(Path(folder) / 'shared.db') for _ in range(2)]
            scope = Scope('b','p','s')
            barrier = threading.Barrier(2)
            def race(i):
                candidate = Candidate(Event(scope, str(i), 0, 'test', {}), (AtomVersion('x',0),), (Write('x',{'winner':i}),))
                barrier.wait(timeout=3)
                try:
                    return stores[i].commit(candidate).status
                except StaleRead:
                    return 'stale'
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(race, range(2)))
                self.assertCountEqual(results,['committed','stale'])
                self.assertEqual(stores[0].snapshot(scope,['x']).get('x').revision,1)
            finally:
                for store in stores: store.close()

if __name__ == '__main__': unittest.main()
