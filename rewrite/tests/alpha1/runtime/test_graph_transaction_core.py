import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.runtime.dispatch_check_reissue import (
    DispatchCheckReissueHold, NegativeQueryClosureV1,
    ProvisionalCheckCandidateV1, reissue_and_require_identical_checks,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    CheckReceipt, FenceScope, NamespaceId, QueryEpoch, VersionedRef,
)
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, NamespaceEpoch, Owner,
    TypeRegistry, TypeSpec,
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

    def test_provisional_stage_exposes_e_plus_one_then_leaves_no_graph_or_side_effects(self):
        first = self.candidate()
        stage = GraphCandidate(
            first.event, first.reads, first.writes,
            (NamespaceEpoch("bot", "persona", 0),))
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                with self.store._provisional_graph_stage_in_transaction(
                        stage, _capability=self.capability) as tentative:
                    self.assertEqual(tentative.status, "committed")
                    self.assertEqual(tentative.epoch.revision, 1)
                    self.assertEqual(db.execute(
                        "SELECT revision,value FROM graph_atoms WHERE token=?",
                        (self.key.token,)).fetchone()[0], 1)
                    self.assertEqual(db.execute(
                        "SELECT revision FROM graph_epochs WHERE bot='bot' "
                        "AND persona='persona'").fetchone(), (1,))
                    db.execute("CREATE TABLE provisional_side_effect(value TEXT)")
                    db.execute("INSERT INTO provisional_side_effect VALUES('must_rollback')")
                self.assertIsNone(db.execute(
                    "SELECT revision FROM graph_atoms WHERE token=?",
                    (self.key.token,)).fetchone())
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_events").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_history").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_epochs").fetchone(), (0,))
                self.assertIsNone(db.execute(
                    "SELECT name FROM sqlite_master WHERE name='provisional_side_effect'").fetchone())
                final = self.store._graph_commit_in_transaction(
                    stage, _capability=self.capability)
                self.assertEqual(final.epoch.revision, 1)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        self.assertEqual(self.store._db.execute(
            "SELECT COUNT(*) FROM graph_events").fetchone(), (1,))

    def test_provisional_stage_failure_rolls_back_only_its_savepoint(self):
        first = self.candidate()
        stage = GraphCandidate(
            first.event, first.reads, first.writes,
            (NamespaceEpoch("bot", "persona", 0),))
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("CREATE TABLE retained(value TEXT)")
                db.execute("INSERT INTO retained VALUES('before_stage')")
                with self.assertRaisesRegex(RuntimeError, "check unavailable"):
                    with self.store._provisional_graph_stage_in_transaction(
                            stage, _capability=self.capability):
                        raise RuntimeError("check unavailable")
                self.assertEqual(db.execute(
                    "SELECT value FROM retained").fetchone(), ("before_stage",))
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_events").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_atoms").fetchone(), (0,))
                db.execute("ROLLBACK")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def test_final_hook_reissues_or_rolls_back_on_read_check_and_head_drift(self):
        namespace = NamespaceId("bot", "persona")
        anchor = RestoreAnchor(
            "authority", "authority-ns", 1, "delete-log", 0, "genesis",
            "execute-log", 0, "genesis", 0, "proof")
        permit = FencePermitV2(
            "authority", "authority-ns", "subject", "holder", 1,
            "write", "write-event", "T" * 32, 1, 1, anchor)
        scope = FenceScope(
            namespace, "authority-ns", 1, "write", "write-event",
            permit, anchor, NamespaceEpoch("bot", "persona", 0), 0)
        receipt = CheckReceipt(
            "commitment_conflict", "persona:persona", "action",
            "expression", (VersionedRef(self.key.token, 1),),
            "full", "pass", 100.0, "d08.commitment_conflict")
        closure = ProvisionalCheckCandidateV1(
            "session", "event", 1, anchor, "snapshot-digest", permit.token,
            (VersionedRef(self.key.token, 1),),
            (NegativeQueryClosureV1(
                "no-conflicting-action", QueryEpoch(namespace, "all", 1),
                (VersionedRef(self.key.token, 1),), 0, "full"),),
            (receipt,))
        candidate = GraphCandidate(
            self.candidate().event, self.candidate().reads,
            self.candidate().writes, (NamespaceEpoch("bot", "persona", 0),))
        drifts = (
            ("positive", replace(closure, positive_reads=(
                VersionedRef(self.key.token, 2),)), scope),
            ("negative", replace(closure, negative_queries=(replace(
                closure.negative_queries[0], scanned_versions=()),)), scope),
            ("coverage", replace(closure, checks=(replace(
                receipt, coverage="partial", result="unknown"),)), scope),
            ("issuer", replace(closure, checks=(replace(
                receipt, issuer="other-issuer"),)), scope),
            ("expiry", replace(closure, checks=(replace(
                receipt, valid_until=9.0),)), scope),
            ("authority-head", closure, replace(
                scope, pinned_anchor=replace(
                    anchor, execution_seq=1,
                    execution_digest="sha256:" + "a" * 64),
                permit=replace(
                    permit, pinned_anchor=replace(
                        anchor, execution_seq=1,
                        execution_digest="sha256:" + "a" * 64)))),
        )
        for label, reissued, effective_scope in drifts:
            with self.subTest(label=label), self.store._lock:
                db = self.store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    with self.assertRaises(DispatchCheckReissueHold):
                        self.store._graph_commit_in_transaction(
                            candidate, _capability=self.capability,
                            _receipt_hook=lambda db, final: (
                                reissue_and_require_identical_checks(
                                    db, closure, final, effective_scope,
                                    now_utc=10.0,
                                    installed_reissuer=lambda *_: reissued)),
                        )
                finally:
                    db.execute("ROLLBACK")
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_events").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM graph_atoms").fetchone(), (0,))


    def test_production_dispatch_admission_cannot_omit_final_reissue(self):
        store = ProductionGraphStore(
            Path(self.temp.name) / "production.db", TypeRegistry())
        try:
            graph = GraphCoordinator.__new__(GraphCoordinator)
            graph._GraphCoordinator__store = store
            graph._GraphCoordinator__dispatch_admission_issuer = object()
            with self.assertRaisesRegex(
                    UnavailableGuard, "requires final check reissue"):
                graph._issue_dispatch_admission(
                    None, None, None, None, None, None, None, None,
                    graph_receipt=None, v2_write=None, now_utc=None,
                    projection=None)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
