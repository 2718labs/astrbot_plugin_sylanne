import sqlite3
import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import Event, EventConflict, Scope, StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey,
    GraphCandidate,
    GraphVersion,
    GraphWrite,
    NamespaceEpoch,
    Owner,
    TypeRegistry,
    TypeSpec,
)


def object_with_n(value):
    if "n" not in value or type(value["n"]) is not int:
        raise ValueError("n must be an integer")


def registry(state_version=1):
    result = TypeRegistry()
    result.register(TypeSpec("source", ("persona", "event"), "source", object_with_n,
                             immutable=True, schema_version=state_version))
    result.register(TypeSpec("state", ("persona", "relation", "scene"), "state", object_with_n,
                             schema_version=state_version))
    result.register(TypeSpec("derived", ("persona", "relation", "activity"), "projection", object_with_n,
                             schema_version=state_version))
    return result


class GraphTypeTests(unittest.TestCase):
    def test_owner_key_roundtrip_and_detached_values(self):
        owner = Owner("relation", "bot", "persona", "friend")
        key = AtomKey(owner, "state", "affinity")
        self.assertEqual(AtomKey.from_token(key.token), key)
        with self.assertRaises(ValueError):
            Owner("persona", "bot", "persona", "unexpected")
        with self.assertRaises(ValueError):
            Owner("relation", "bot", "persona")

        value = {"n": 1, "nested": [1]}
        write = GraphWrite(key, value)
        value["nested"].append(2)
        self.assertEqual(write.value, {"n": 1, "nested": [1]})


class GraphStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "graph.db"
        self.types = registry()
        self.store = GraphStore(self.path, self.types)
        self.scope = Scope("bot", "persona", "session")
        self.persona = Owner("persona", "bot", "persona")
        self.relation = Owner("relation", "bot", "persona", "friend")
        self.source = AtomKey(self.persona, "source", "experience")
        self.state = AtomKey(self.persona, "state", "mood")
        self.middle = AtomKey(self.relation, "derived", "interpretation")
        self.leaf = AtomKey(self.persona, "derived", "response")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def event(self, event_id, payload=None, scope=None):
        return Event(scope or self.scope, event_id, 1.0, "graph-test", payload or {})

    def candidate(self, event_id, keys, writes, epochs=(), payload=None, scope=None):
        snapshot = self.store.graph_snapshot(keys)
        return GraphCandidate(self.event(event_id, payload, scope), snapshot.versions,
                              tuple(writes), tuple(epochs))

    def commit_one(self, event_id, key, value, dependencies=()):
        keys = (key,) + tuple(dep for dep in dependencies if dep != key)
        return self.store.graph_commit(
            self.candidate(event_id, keys, (GraphWrite(key, value, dependencies),))
        )

    def test_multi_owner_atomic_commit_and_validation_rollback(self):
        snap = self.store.graph_snapshot((self.state, self.middle))
        receipt = self.store.graph_commit(GraphCandidate(
            self.event("multi"), snap.versions,
            (GraphWrite(self.state, {"n": 1}), GraphWrite(self.middle, {"n": 2}, (self.state,))),
        ))
        self.assertEqual(receipt.status, "committed")
        self.assertEqual(receipt.revisions, (GraphVersion(self.state, 1), GraphVersion(self.middle, 1)))
        self.assertEqual(receipt.epoch, NamespaceEpoch("bot", "persona", 1))

        before = self.store.graph_snapshot((self.state, self.middle))
        bad = GraphCandidate(self.event("bad"), before.versions,
                             (GraphWrite(self.state, {"n": 3}), GraphWrite(self.middle, {"n": "bad"})))
        with self.assertRaises(ValueError):
            self.store.graph_commit(bad)
        self.assertEqual(self.store.graph_snapshot((self.state, self.middle)).versions, before.versions)

    def test_absent_read_epoch_cas_and_namespace_isolation(self):
        snap = self.store.graph_snapshot((self.state,))
        self.assertEqual(snap.get(self.state).revision, 0)
        self.assertFalse(snap.get(self.state).valid)
        self.assertEqual(snap.epochs, (NamespaceEpoch("bot", "persona", 0),))
        phantom_guard = GraphCandidate(self.event("guarded"), snap.versions,
                                       (GraphWrite(self.state, {"n": 1}),), snap.epochs)

        other_key = AtomKey(Owner("persona", "other", "persona"), "state", "mood")
        other_scope = Scope("other", "persona", "session")
        other_snap = self.store.graph_snapshot((other_key,))
        self.store.graph_commit(GraphCandidate(self.event("other", scope=other_scope), other_snap.versions,
                                               (GraphWrite(other_key, {"n": 8}),)))
        self.assertEqual(self.store.graph_commit(phantom_guard).status, "committed")

        stale_epoch = self.store.graph_epoch("bot", "persona")
        fresh_key = AtomKey(self.persona, "state", "other")
        fresh = self.store.graph_snapshot((fresh_key,))
        self.commit_one("advance", self.middle, {"n": 2})
        guarded = GraphCandidate(self.event("stale-epoch"), fresh.versions,
                                 (GraphWrite(fresh_key, {"n": 3}),), (stale_epoch,))
        with self.assertRaises(StaleRead):
            self.store.graph_commit(guarded)

    def test_restart_duplicate_conflict_and_schema_catalog(self):
        candidate = self.candidate("same", (self.state,), (GraphWrite(self.state, {"n": 1}),))
        first = self.store.graph_commit(candidate)
        self.store.close()
        self.store = GraphStore(self.path, registry())
        self.assertEqual(self.store.graph_commit(candidate).status, "duplicate")
        self.assertEqual(self.store.graph_commit(candidate).revisions, first.revisions)
        conflicting = GraphCandidate(self.event("same", {"changed": True}), candidate.reads, candidate.writes)
        with self.assertRaises(EventConflict):
            self.store.graph_commit(conflicting)
        self.store.close()
        with self.assertRaises(ValueError):
            GraphStore(self.path, registry(state_version=2))
        self.store = GraphStore(self.path, registry())

    def test_event_retry_with_a_fresh_snapshot_is_still_duplicate(self):
        event = self.event("retry")
        initial = self.store.graph_snapshot((self.state,))
        first = self.store.graph_commit(GraphCandidate(
            event, initial.versions, (GraphWrite(self.state, {"n": 1}),), initial.epochs
        ))
        fresh = self.store.graph_snapshot((self.state,))
        duplicate = self.store.graph_commit(GraphCandidate(
            event, fresh.versions, (GraphWrite(self.state, {"n": 99}),), fresh.epochs
        ))
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(duplicate.revisions, first.revisions)
        current = self.store.graph_snapshot((self.state,)).get(self.state)
        self.assertEqual((current.revision, current.value), (1, {"n": 1}))

    def test_registry_is_frozen_at_store_construction(self):
        late = TypeSpec("late", ("persona",), "cache", object_with_n)
        self.types.register(late)
        late_key = AtomKey(self.persona, "late", "entry")
        with self.assertRaises(KeyError):
            self.store.graph_snapshot((late_key,))

    def test_transitive_old_edges_cross_fresh_intermediate_and_history(self):
        self.commit_one("state", self.state, {"n": 1})
        self.commit_one("middle", self.middle, {"n": 1}, (self.state,))
        self.commit_one("leaf", self.leaf, {"n": 1}, (self.middle,))
        snap = self.store.graph_snapshot((self.state, self.middle, self.leaf))
        receipt = self.store.graph_commit(GraphCandidate(
            self.event("refresh"), snap.versions,
            (GraphWrite(self.state, {"n": 2}), GraphWrite(self.middle, {"n": 2}, (self.state,))),
        ))
        after = self.store.graph_snapshot((self.state, self.middle, self.leaf))
        self.assertTrue(after.get(self.middle).valid)
        self.assertFalse(after.get(self.leaf).valid)
        self.assertEqual(receipt.invalidated, (GraphVersion(self.leaf, 2),))

        rows = self.store._db.execute(
            "SELECT revision, valid FROM graph_history WHERE token=? ORDER BY revision", (self.leaf.token,)
        ).fetchall()
        self.assertEqual(rows, [(1, 1), (2, 0)])

    def test_rejects_dependency_that_will_be_indirectly_invalidated(self):
        self.commit_one("state", self.state, {"n": 1})
        self.commit_one("middle", self.middle, {"n": 1}, (self.state,))
        self.commit_one("leaf", self.leaf, {"n": 1}, (self.middle,))
        before = self.store.graph_snapshot((self.state, self.middle, self.leaf))
        candidate = GraphCandidate(
            self.event("invalid-dependency"), before.versions,
            (GraphWrite(self.state, {"n": 2}), GraphWrite(self.leaf, {"n": 2}, (self.middle,))),
        )
        with self.assertRaises(ValueError):
            self.store.graph_commit(candidate)
        self.assertEqual(self.store.graph_snapshot((self.state, self.middle, self.leaf)).versions,
                         before.versions)

    def test_immutable_source_and_cycle_rejection(self):
        self.commit_one("source", self.source, {"n": 1})
        source = self.store.graph_snapshot((self.source,)).get(self.source)
        with self.assertRaises(ValueError):
            self.store.graph_commit(GraphCandidate(self.event("overwrite"), (GraphVersion(self.source, source.revision),),
                                                   (GraphWrite(self.source, {"n": 2}),)))
        absent_middle = self.store.graph_snapshot((self.middle,)).versions
        with self.assertRaises(ValueError):
            self.store.graph_commit(GraphCandidate(self.event("immutable-dependency"),
                                                   (GraphVersion(self.source, source.revision),) + absent_middle,
                                                   (GraphWrite(self.source, {"n": 1}, (self.middle,)),)))

        a = AtomKey(self.persona, "derived", "a")
        b = AtomKey(self.persona, "derived", "b")
        snap = self.store.graph_snapshot((a, b))
        self.store.graph_commit(GraphCandidate(self.event("a"), snap.versions,
                                               (GraphWrite(a, {"n": 1}, (b,)),)))
        snap = self.store.graph_snapshot((a, b))
        with self.assertRaises(ValueError):
            self.store.graph_commit(GraphCandidate(self.event("cycle"), snap.versions,
                                                   (GraphWrite(b, {"n": 1}, (a,)),)))

    def test_observed_absence_dependency_is_invalidated_when_key_appears(self):
        query = AtomKey(self.persona, "derived", "negative-query")
        future = AtomKey(self.persona, "state", "future-evidence")
        snap = self.store.graph_snapshot((query, future))
        self.store.graph_commit(GraphCandidate(
            self.event("negative"), snap.versions,
            (GraphWrite(query, {"n": 0}, (future,)),),
        ))
        self.assertTrue(self.store.graph_snapshot((query,)).get(query).valid)
        future_snapshot = self.store.graph_snapshot((future,))
        receipt = self.store.graph_commit(GraphCandidate(
            self.event("arrival"), future_snapshot.versions,
            (GraphWrite(future, {"n": 1}),),
        ))
        self.assertEqual(receipt.invalidated, (GraphVersion(query, 2),))
        self.assertFalse(self.store.graph_snapshot((query,)).get(query).valid)

    def test_detached_snapshot_candidate_and_persisted_values(self):
        value = {"n": 1, "items": [1]}
        write = GraphWrite(self.state, value)
        candidate = self.candidate("detach", (self.state,), (write,))
        value["items"].append(2)
        write.value["items"].append(3)
        self.store.graph_commit(candidate)
        first = self.store.graph_snapshot((self.state,))
        first.get(self.state).value["items"].append(4)
        self.assertEqual(self.store.graph_snapshot((self.state,)).get(self.state).value,
                         {"n": 1, "items": [1]})


if __name__ == "__main__":
    unittest.main()
