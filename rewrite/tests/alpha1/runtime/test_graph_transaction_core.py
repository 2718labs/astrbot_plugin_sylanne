import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec,
)


class GraphTransactionCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        registry = TypeRegistry()
        registry.register(TypeSpec("state", ("persona",), "state", lambda value: None))
        self.store = GraphStore(Path(self.temp.name) / "graph.db", registry)
        self.capability = object()
        self.store._coordinator_capability = self.capability
        self.key = AtomKey(Owner("persona", "bot", "persona"), "state", "one")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def candidate(self, event_id="event", revision=0):
        event = Event(Scope("bot", "persona", "session"), event_id, 1.0,
                      "test", {"event_id": event_id})
        return GraphCandidate(event, (GraphVersion(self.key, revision),),
                              (GraphWrite(self.key, {"value": 1}),))

    def test_core_joins_caller_transaction_and_leaves_commit_to_caller(self):
        with self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            self.store._db.execute("CREATE TABLE extra (value TEXT)")
            self.store._db.execute("INSERT INTO extra VALUES ('observation')")
            seen = []
            receipt = self.store._graph_commit_in_transaction(
                self.candidate(), _capability=self.capability,
                _guard=lambda db: seen.append(db.execute("SELECT value FROM extra").fetchone()[0]),
                _receipt_hook=lambda db, result: db.execute(
                    "INSERT INTO extra VALUES (?)", (result.status,)),
            )
            self.assertEqual(receipt.status, "committed")
            self.assertEqual(seen, ["observation"])
            self.assertTrue(self.store._db.in_transaction)
            self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0], 1)
            self.store._db.execute("ROLLBACK")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0], 0)

    def test_core_duplicate_and_error_do_not_end_caller_transaction(self):
        self.store.graph_commit(self.candidate())
        with self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            self.store._db.execute("CREATE TABLE extra (value TEXT)")
            receipt = self.store._graph_commit_in_transaction(
                self.candidate(revision=1), _capability=self.capability,
                _receipt_hook=lambda db, result: db.execute(
                    "INSERT INTO extra VALUES (?)", (result.status,)),
            )
            self.assertEqual(receipt.status, "duplicate")
            with self.assertRaises(StaleRead):
                self.store._graph_commit_in_transaction(
                    self.candidate("stale"), _capability=self.capability)
            self.assertTrue(self.store._db.in_transaction)
            self.assertEqual(self.store._db.execute("SELECT value FROM extra").fetchone()[0],
                             "duplicate")
            self.store._db.execute("ROLLBACK")

    def test_core_requires_capability_and_caller_transaction(self):
        with self.assertRaises(PermissionError):
            self.store._graph_commit_in_transaction(self.candidate())
        with self.assertRaises(RuntimeError):
            self.store._graph_commit_in_transaction(
                self.candidate(), _capability=self.capability)

    def test_core_hook_failure_leaves_rollback_to_caller(self):
        def fail_hook(db, receipt):
            raise RuntimeError("receipt failed")

        with self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.store._graph_commit_in_transaction(
                    self.candidate(), _capability=self.capability,
                    _receipt_hook=fail_hook)
            self.assertTrue(self.store._db.in_transaction)
            self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0], 1)
            self.store._db.execute("ROLLBACK")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0], 0)

    def test_public_commit_keeps_phase_and_rollback_semantics(self):
        def fail_hook(db, receipt):
            raise RuntimeError("receipt failed")

        phase = {}
        receipt = self.store.graph_commit(self.candidate(), _transaction_state=phase)
        self.assertEqual(receipt.status, "committed")
        self.assertEqual(phase["phase"], "committed")
        with self.assertRaisesRegex(RuntimeError, "receipt failed"):
            self.store.graph_commit(
                self.candidate("next", revision=1),
                _receipt_hook=fail_hook,
                _transaction_state=phase,
            )
        self.assertEqual(phase["phase"], "rolled_back")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
