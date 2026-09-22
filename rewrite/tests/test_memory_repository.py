import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import CapacityExceeded, Event, EventConflict, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphSnapshot, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    InterpretationRecord,
    SourceRecord,
    access_key,
    interpretation_key,
    register_memory_types,
    source_key,
)


class MemoryRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "memory.db"
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(self.path, registry)
        self.repo = MemoryRepository(self.store, "bot", "persona")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def event(self, event_id, payload=None, *, persona="persona"):
        return Event(Scope("bot", persona, "session"), event_id, 1.0,
                     "memory-test", payload or {})

    def source(self, source_id, *, text=None, source_kind="observed",
               assertion_status="confirmed", recorded_at=1.0, occurred_at=1.0,
               audiences=("public",), purposes=("expression",), parents=()):
        return SourceRecord(
            source_id, text or f"text-{source_id}", "speaker", source_kind,
            assertion_status, occurred_at, recorded_at, f"root-{source_id}",
            audiences, purposes, parents,
        )

    def interpretation(self, iid, sources, *, status="confirmed", recorded_at=2.0,
                       valid_from=1.0, valid_to=None, claim=None):
        return InterpretationRecord(
            iid, tuple(sources), "subject", claim or f"claim-{iid}", status,
            valid_from, recorded_at, valid_to,
        )

    def test_ingest_is_atomic_and_source_is_immutable(self):
        source = self.source("s1")
        receipt = self.repo.ingest(self.event("ingest"), source)
        self.assertEqual(receipt.status, "committed")

        snapshot = self.store.graph_snapshot((
            source_key("bot", "persona", "s1"),
            access_key("bot", "persona", "s1"),
        ))
        self.assertEqual(tuple(atom.revision for atom in snapshot.atoms), (1, 1))
        self.assertEqual(self.repo.read_source(
            "s1", audience="public", purpose="expression"), source)

        with self.assertRaises(ValueError):
            self.repo.ingest(self.event("overwrite"), self.source("s1", text="changed"))
        self.assertEqual(self.repo.read_source(
            "s1", audience="public", purpose="expression"), source)

    def test_duplicate_preflight_and_operation_arguments_bind_event_identity(self):
        source = self.source("s1")
        first = self.repo.ingest(self.event("same"), source)
        duplicate = self.repo.ingest(self.event("same"), source)
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(duplicate.revisions, first.revisions)

        self.repo.set_access(self.event("later"), "s1", audiences=("self",),
                             purposes=("context",), status="active", recorded_at=3.0)
        self.assertEqual(self.repo.ingest(self.event("same"), source).status, "duplicate")

        with self.assertRaises(EventConflict):
            self.repo.ingest(self.event("same"), self.source("s1", text="different"))

    def test_scope_isolated_and_private_source_is_not_disclosed(self):
        with self.assertRaises(ValueError):
            self.repo.ingest(self.event("wrong", persona="other"), self.source("x"))
        source = self.source("private", audiences=("self",), purposes=("context",))
        self.repo.ingest(self.event("private"), source)
        self.assertIsNone(self.repo.read_source(
            "private", audience="public", purpose="expression"))
        self.assertEqual(self.repo.read_source(
            "private", audience="self", purpose="context"), source)

    def test_parent_constraints_and_ancestor_withdrawal_propagate(self):
        parent = self.source("parent", audiences=("self",), purposes=("context",))
        self.repo.ingest(self.event("parent"), parent)
        with self.assertRaises(ValueError):
            self.repo.ingest(self.event("broad-child"), self.source(
                "broad", audiences=("self", "public"), purposes=("context",),
                parents=("parent",)))

        child = self.source("child", audiences=("self",), purposes=("context",),
                            parents=("parent",))
        self.repo.ingest(self.event("child"), child)
        self.assertEqual(self.repo.read_source(
            "child", audience="self", purpose="context"), child)
        self.repo.set_access(self.event("withdraw"), "parent", audiences=("self",),
                             purposes=("context",), status="withdrawn", recorded_at=3.0)
        self.assertIsNone(self.repo.read_source(
            "child", audience="self", purpose="context"))

    def test_simulated_ancestry_cannot_be_laundered(self):
        simulated = self.source("sim", source_kind="simulated", assertion_status="unknown")
        self.repo.ingest(self.event("sim"), simulated)
        with self.assertRaises(ValueError):
            self.repo.ingest(self.event("launder"), self.source(
                "launder", source_kind="observed", parents=("sim",)))
        derived = self.source("derived", source_kind="simulated", parents=("sim",))
        self.repo.ingest(self.event("derived"), derived)

    def test_confirmed_interpretation_requires_observed_support(self):
        reported = self.source("report", source_kind="reported", assertion_status="reported")
        self.repo.ingest(self.event("report"), reported)
        with self.assertRaises(ValueError):
            self.repo.interpret(self.event("false-confirm"), self.interpretation(
                "i1", ("report",), status="confirmed"))

        provisional = self.interpretation("i1", ("report",), status="reported")
        self.repo.interpret(self.event("reported-interpretation"), provisional)
        self.assertEqual(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression"), provisional)

    def test_interpretation_revision_is_monotonic_and_rebuilds_invalid_current(self):
        source = self.source("s1")
        self.repo.ingest(self.event("source"), source)
        first = self.interpretation("i1", ("s1",), recorded_at=3.0, claim="first")
        self.repo.interpret(self.event("first"), first)
        with self.assertRaises(ValueError):
            self.repo.interpret(self.event("same-time"), self.interpretation(
                "i1", ("s1",), recorded_at=3.0, claim="bad"))

        self.repo.set_access(self.event("restrict"), "s1", audiences=("self",),
                             purposes=("context",), status="active", recorded_at=4.0)
        atom = self.store.graph_snapshot((interpretation_key("bot", "persona", "i1"),)).atoms[0]
        self.assertFalse(atom.valid)

        corrected = self.interpretation("i1", ("s1",), recorded_at=5.0, claim="corrected")
        self.repo.interpret(self.event("correct"), corrected)
        self.assertEqual(self.repo.read_interpretation(
            "i1", audience="self", purpose="context"), corrected)
        self.assertEqual(self.repo.read_source(
            "s1", audience="self", purpose="context"), source)

    def test_current_access_governs_history_and_time_boundaries(self):
        source = self.source("s1", recorded_at=2.0)
        self.repo.ingest(self.event("source"), source)
        record = self.interpretation("i1", ("s1",), recorded_at=4.0,
                                     valid_from=10.0, valid_to=20.0)
        self.repo.interpret(self.event("interpret"), record)
        self.assertIsNone(self.repo.read_source(
            "s1", audience="public", purpose="expression", as_known_at=1.0))
        self.assertIsNone(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression", as_known_at=3.0))
        self.assertEqual(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression", valid_at=10.0), record)
        self.assertIsNone(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression", valid_at=20.0))

        self.repo.set_access(self.event("withdraw"), "s1", audiences=("public",),
                             purposes=("expression",), status="withdrawn", recorded_at=6.0)
        self.assertIsNone(self.repo.read_source(
            "s1", audience="public", purpose="expression", as_known_at=5.0))

    def test_retracted_or_invalid_interpretation_is_not_returned(self):
        self.repo.ingest(self.event("source"), self.source("s1"))
        retracted = self.interpretation("i1", ("s1",), status="retracted")
        self.repo.interpret(self.event("retract"), retracted)
        self.assertIsNone(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression"))

    def test_evidence_snapshot_is_coherent_complete_and_sanitized(self):
        self.repo.ingest(self.event("parent"), self.source("parent"))
        self.repo.ingest(self.event("child"), self.source("child", parents=("parent",)))
        record, proof = self.repo.read_source_evidence(
            "child", audience="public", purpose="expression")
        self.assertEqual(record.source_id, "child")
        self.assertIsInstance(proof, GraphSnapshot)
        self.assertEqual(len(proof.atoms), 4)
        self.assertTrue(all(atom.value == {} for atom in proof.atoms))
        self.assertEqual(len(proof.epochs), 1)

    def test_evidence_traversal_has_a_hard_unique_atom_bound(self):
        self.repo.ingest(self.event("parent"), self.source("parent"))
        self.repo.ingest(self.event("child"), self.source("child", parents=("parent",)))
        with self.assertRaises(CapacityExceeded):
            self.repo.read_source_evidence(
                "child", audience="public", purpose="expression", max_nodes=3)
        for invalid in (True, 0, 4097):
            with self.assertRaises((TypeError, ValueError)):
                self.repo.read_source_evidence(
                    "child", audience="public", purpose="expression", max_nodes=invalid)

    def test_observed_but_unconfirmed_source_cannot_confirm_a_claim(self):
        disputed = self.source("s1", source_kind="observed",
                               assertion_status="disputed")
        self.repo.ingest(self.event("source"), disputed)
        with self.assertRaises(ValueError):
            self.repo.interpret(self.event("interpret"), self.interpretation(
                "i1", ("s1",), status="confirmed"))

    def test_access_requires_tuples_and_checks_all_ancestors(self):
        self.repo.ingest(self.event("root"), self.source(
            "root", audiences=("self", "public"), purposes=("context",)))
        self.repo.ingest(self.event("middle"), self.source(
            "middle", audiences=("self", "public"), purposes=("context",),
            parents=("root",)))
        self.repo.ingest(self.event("leaf"), self.source(
            "leaf", audiences=("self",), purposes=("context",),
            parents=("middle",)))
        with self.assertRaises((TypeError, ValueError)):
            self.repo.set_access(self.event("bad-container"), "leaf",
                                 audiences="self", purposes=("context",),
                                 status="active", recorded_at=3.0)

        self.repo.set_access(self.event("narrow-root"), "root", audiences=("self",),
                             purposes=("context",), status="active", recorded_at=3.0)
        with self.assertRaises(ValueError):
            self.repo.set_access(self.event("bypass-root"), "leaf",
                                 audiences=("self", "public"), purposes=("context",),
                                 status="active", recorded_at=4.0)

        self.repo.set_access(self.event("withdraw-root"), "root", audiences=("self",),
                             purposes=("context",), status="withdrawn", recorded_at=5.0)
        receipt = self.repo.set_access(self.event("withdraw-leaf"), "leaf",
                                       audiences=("self",), purposes=("context",),
                                       status="withdrawn", recorded_at=6.0)
        self.assertEqual(receipt.status, "committed")

    def test_ancestor_access_change_invalidates_interpretation(self):
        self.repo.ingest(self.event("root"), self.source("root"))
        self.repo.ingest(self.event("child"), self.source("child", parents=("root",)))
        self.repo.interpret(self.event("interpret"), self.interpretation("i1", ("child",)))
        self.repo.set_access(self.event("restrict-root"), "root", audiences=("self",),
                             purposes=("context",), status="active", recorded_at=4.0)
        atom = self.store.graph_snapshot((
            interpretation_key("bot", "persona", "i1"),)).atoms[0]
        self.assertFalse(atom.valid)
        denied, proof = self.repo.read_interpretation_evidence(
            "i1", audience="self", purpose="context", max_nodes=1)
        self.assertIsNone(denied)
        self.assertEqual(len(proof.atoms), 1)
        self.assertFalse(proof.atoms[0].valid)
        self.assertTrue(all(proof_atom.value == {} for proof_atom in proof.atoms))

    def test_records_and_duplicate_receipts_survive_reopen(self):
        source = self.source("s1")
        event = self.event("source")
        self.repo.ingest(event, source)
        record = self.interpretation("i1", ("s1",))
        self.repo.interpret(self.event("interpret"), record)
        self.store.close()
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(self.path, registry)
        self.repo = MemoryRepository(self.store, "bot", "persona")
        self.assertEqual(self.repo.read_source(
            "s1", audience="public", purpose="expression"), source)
        self.assertEqual(self.repo.read_interpretation(
            "i1", audience="public", purpose="expression"), record)
        self.assertEqual(self.repo.ingest(event, source).status, "duplicate")

    def test_two_connection_duplicate_commit_between_preflight_and_domain_read(self):
        registry = TypeRegistry()
        register_memory_types(registry)
        second_store = GraphStore(self.path, registry)
        second_repo = MemoryRepository(second_store, "bot", "persona")
        source = self.source("raced")
        event = self.event("raced-ingest")
        original_lookup = self.store.graph_event_receipt
        injected = False

        def commit_from_second_connection(bound_event):
            nonlocal injected
            prior = original_lookup(bound_event)
            if prior is None and not injected:
                injected = True
                second_repo.ingest(event, source)
            return prior

        self.store.graph_event_receipt = commit_from_second_connection
        try:
            receipt = self.repo.ingest(event, source)
        finally:
            self.store.graph_event_receipt = original_lookup
            second_store.close()

        self.assertTrue(injected)
        self.assertEqual(receipt.status, "duplicate")
        atom = self.store.graph_snapshot((
            source_key("bot", "persona", "raced"),)).atoms[0]
        self.assertEqual(atom.revision, 1)
        self.assertEqual(SourceRecord.from_dict(atom.value), source)


if __name__ == "__main__":
    unittest.main()
