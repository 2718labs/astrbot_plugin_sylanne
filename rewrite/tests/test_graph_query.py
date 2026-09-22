import tempfile
import unittest
from pathlib import Path
from sylanne3.contracts import Event, EventConflict, Scope, StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry, TypeSpec


class GraphQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        registry = TypeRegistry()
        registry.register(TypeSpec('record', ('event',), 'state', lambda value: None))
        self.store = GraphStore(Path(self.tmp.name) / 'test.db', registry)
        self.addCleanup(self.store.close)
        self.scope = Scope('bot', 'persona', 'scene')

    def write(self, name):
        key = AtomKey(Owner('event', 'bot', 'persona', name), 'record', 'record')
        event = Event(self.scope, name, 1, 'test', {})
        snapshot = self.store.graph_snapshot((key,))
        self.store.graph_commit(GraphCandidate(event, snapshot.versions, (GraphWrite(key, {'name': name}),)))
        return event

    def test_pages_are_ordered_and_guard_against_intervening_writes(self):
        for name in ('a', 'b', 'c'):
            self.write(name)
        first = self.store.graph_query('bot', 'persona', limit=2)
        self.assertEqual([a.value['name'] for a in first.snapshot.atoms], ['a', 'b'])
        second = self.store.graph_query('bot', 'persona', after=first.next_after,
            expected_epoch=first.snapshot.epochs[0], limit=2)
        self.assertEqual([a.value['name'] for a in second.snapshot.atoms], ['c'])
        self.assertIsNone(second.next_after)
        self.write('d')
        with self.assertRaises(StaleRead):
            self.store.graph_query('bot', 'persona', after=first.next_after,
                                   expected_epoch=first.snapshot.epochs[0])

    def test_empty_query_has_epoch_and_filters_do_not_cross_namespace(self):
        empty = self.store.graph_query('bot', 'persona', type_names=('record',))
        self.assertEqual(empty.snapshot.epochs[0].revision, 0)
        self.write('a')
        self.assertEqual(self.store.graph_query('other', 'persona').snapshot.atoms, ())
        self.assertEqual(self.store.graph_query('bot', 'persona', subject='missing').snapshot.atoms, ())
        with self.assertRaises(StaleRead):
            self.store.graph_query('bot', 'persona', expected_epoch=empty.snapshot.epochs[0])

    def test_receipt_lookup_checks_event_content(self):
        event = self.write('a')
        self.assertEqual(self.store.graph_event_receipt(event).status, 'duplicate')
        with self.assertRaises(EventConflict):
            self.store.graph_event_receipt(Event(self.scope, 'a', 1, 'test', {'different': True}))
        self.assertIsNone(self.store.graph_event_receipt(Event(self.scope, 'absent', 1, 'test', {})))

    def test_query_validates_limits_types_and_cursor_namespace(self):
        for limit in (True, 0, 513, 1.5):
            with self.assertRaises((TypeError, ValueError)):
                self.store.graph_query('bot', 'persona', limit=limit)
        with self.assertRaises(KeyError):
            self.store.graph_query('bot', 'persona', type_names=('unknown',))
        foreign = AtomKey(Owner('event', 'other', 'persona', 'a'), 'record', 'record')
        with self.assertRaises(ValueError):
            self.store.graph_query('bot', 'persona', after=foreign)


if __name__ == '__main__':
    unittest.main()
