"""Cross-domain correction scenarios on the authoritative SQLite graph."""
from pathlib import Path
import tempfile
import unittest

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry, TypeSpec,
)
from sylanne3.graph_store import GraphStore
from sylanne3.operators import OperatorSpec, compile_operators


class GraphCausalityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        registry = TypeRegistry()
        registry.register(TypeSpec('record', frozenset({'event'}), 'source', lambda v: None, immutable=True))
        registry.register(TypeSpec('judgment', frozenset({'event', 'relation'}), 'state', lambda v: None))
        registry.register(TypeSpec('view', frozenset({'persona', 'scene'}), 'projection', lambda v: None))
        self.store = GraphStore(Path(self.tmp.name) / 'character.sqlite3', registry)
        self.addCleanup(self.store.close)
        self.scope = Scope('bot', 'sylanne', 'room')
        self.source = AtomKey(Owner('event', 'bot', 'sylanne', 'missed-meeting'), 'record', 'actual')
        self.interpretation = AtomKey(Owner('event', 'bot', 'sylanne', 'missed-meeting'), 'judgment', 'current')
        self.relation = AtomKey(Owner('relation', 'bot', 'sylanne', 'alice'), 'judgment', 'reliability')
        self.narrative = AtomKey(Owner('persona', 'bot', 'sylanne'), 'view', 'project-history')
        self.other = AtomKey(Owner('relation', 'bot', 'sylanne', 'bob'), 'judgment', 'reliability')

    def event(self, name):
        return Event(self.scope, name, 10.0, 'test', {'cause': name})

    def seed(self):
        keys = (self.source, self.interpretation, self.relation, self.narrative, self.other)
        snapshot = self.store.graph_snapshot(keys)
        self.store.graph_commit(GraphCandidate(self.event('seed'), snapshot.versions, (
            GraphWrite(self.source, {'statement': 'meeting did not occur', 'sent': 'I am disappointed'}),
            GraphWrite(self.interpretation, {'responsibility': 1}),
            GraphWrite(self.relation, {'penalty': 2}, (self.interpretation,)),
            GraphWrite(self.narrative, {'penalty': 2}, (self.relation,)),
            GraphWrite(self.other, {'penalty': 0}),
        )))

    def test_correction_invalidates_current_views_but_preserves_actual_experience(self):
        self.seed()
        before = self.store.graph_snapshot((self.source, self.interpretation, self.relation, self.narrative, self.other))
        stale = GraphCandidate(self.event('stale-reply'), before.versions,
                               (GraphWrite(self.narrative, {'penalty': 99}, (self.relation,)),))
        self.store.graph_commit(GraphCandidate(self.event('correction'), before.versions,
                               (GraphWrite(self.interpretation, {'responsibility': 0}),)))
        after = self.store.graph_snapshot(tuple(a.key for a in before.atoms))
        self.assertEqual(after.get(self.source), before.get(self.source))
        self.assertEqual(after.get(self.other), before.get(self.other))
        self.assertFalse(after.get(self.relation).valid)
        self.assertFalse(after.get(self.narrative).valid)
        with self.assertRaises(StaleRead):
            self.store.graph_commit(stale)

        plan = compile_operators((
            OperatorSpec('relationship', (self.interpretation,), (self.relation,),
                         lambda values: {self.relation: {'penalty': 2 * values[self.interpretation]['responsibility']}}),
            OperatorSpec('narrative', (self.relation,), (self.narrative,),
                         lambda values: {self.narrative: {'penalty': values[self.relation]['penalty']}}),
        ))
        snapshot = self.store.graph_snapshot(plan.required_keys)
        writes = plan.evaluate(snapshot, changed={self.interpretation})
        self.store.graph_commit(GraphCandidate(self.event('rebuild'), snapshot.versions, writes, snapshot.epochs))
        current = self.store.graph_snapshot((self.source, self.relation, self.narrative))
        self.assertTrue(current.get(self.relation).valid)
        self.assertTrue(current.get(self.narrative).valid)
        self.assertEqual(current.get(self.relation).value, {'penalty': 0})
        self.assertEqual(current.get(self.narrative).value, {'penalty': 0})
        self.assertEqual(current.get(self.source), before.get(self.source))

    def test_fresh_intermediate_does_not_leave_its_old_summary_current(self):
        self.seed()
        snapshot = self.store.graph_snapshot((self.interpretation, self.relation))
        self.store.graph_commit(GraphCandidate(self.event('partial-rebuild'), snapshot.versions, (
            GraphWrite(self.interpretation, {'responsibility': 0}),
            GraphWrite(self.relation, {'penalty': 0}, (self.interpretation,)),
        )))
        after = self.store.graph_snapshot((self.relation, self.narrative))
        self.assertTrue(after.get(self.relation).valid)
        self.assertFalse(after.get(self.narrative).valid)

    def test_new_evidence_expires_a_query_even_if_its_old_hits_did_not_change(self):
        self.seed()
        snapshot = self.store.graph_snapshot((self.interpretation,))
        new_source = AtomKey(Owner('event', 'bot', 'sylanne', 'new-counterevidence'), 'record', 'actual')
        missing = self.store.graph_snapshot((new_source,))
        self.store.graph_commit(GraphCandidate(self.event('new-evidence'), missing.versions,
                               (GraphWrite(new_source, {'statement': 'the meeting was cancelled jointly'}),)))
        self.assertEqual(self.store.graph_snapshot((self.interpretation,)).atoms, snapshot.atoms)
        with self.assertRaises(StaleRead):
            self.store.graph_commit(GraphCandidate(self.event('cached-answer'), snapshot.versions, (), snapshot.epochs))


if __name__ == '__main__':
    unittest.main()
