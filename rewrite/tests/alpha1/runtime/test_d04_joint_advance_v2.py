"""Two-member W01 receipt persistence and member interval conflict gates."""

from dataclasses import replace
import sqlite3
import tempfile
from pathlib import Path
import unittest

from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d04_joint_advance_v2 import (
    JointAdvanceHold, ProductAdvanceEvidenceV2, ProductAdvanceMemberV2,
    install_joint_advance_store_v2, preflight_joint_advance_v2,
    read_joint_advance_v2, record_joint_advance_v2,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


H = "a" * 64


class JointAdvanceV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "graph.sqlite"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE graph_bundle_operations (
                bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,
                activity_id TEXT,
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE graph_events (
                bot TEXT, persona TEXT, session TEXT, event_id TEXT,
                revisions TEXT);
            CREATE TABLE graph_product_advances (
                bot TEXT, persona TEXT, operation_id TEXT, process_id TEXT);
            CREATE TABLE graph_d04_root_originals_v1 (
                bot TEXT, persona TEXT, operation_id TEXT);
            CREATE TABLE graph_epochs (
                bot TEXT, persona TEXT, revision INTEGER);
            CREATE TABLE graph_authority_epochs (
                bot TEXT, persona TEXT, access_epoch INTEGER, delete_epoch INTEGER);
            CREATE TABLE graph_recovery_metadata_v2 (
                bot TEXT, persona TEXT, requirements_json TEXT, graph_revision INTEGER);
            CREATE TABLE graph_atoms (
                token TEXT PRIMARY KEY, revision INTEGER, value TEXT, valid INTEGER);
        """)
        install_joint_advance_store_v2(self.db)
        self.ns = NamespaceId("bot:one", "alice")
        self.owner = Owner("persona", "bot:one", "alice")
        self.db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*self.ns.as_tuple, 1))
        self.db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
                        (*self.ns.as_tuple, 0, 0))
        self.db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?)",
                        (*self.ns.as_tuple, canonical_json({"graph_incarnation":
                                                            "incarnation:one"}), 1))
        self.db.execute("INSERT INTO graph_d04_root_originals_v1 VALUES(?,?,?)",
                        (*self.ns.as_tuple, "root"))
        refs = tuple(sorted(AtomKey(self.owner, "d04.numeric_checkpoint.v1", name).token
                            for name in ("block:a", "block:b")))
        members = []
        for pos, ref in enumerate(refs):
            state = AtomKey(self.owner, "d04.feeling_state.v1", f"state:{pos}").token
            before = {"cursor": 0, "block": pos}
            after = {"cursor": 1, "block": pos}
            before_state = {"cursor": 0, "block": pos, "kind": "feeling"}
            next_state = {"cursor": 1, "block": pos, "kind": "feeling"}
            self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                            (ref, 1, canonical_json(before)))
            self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                            (state, 1, canonical_json(before_state)))
            members.append(ProductAdvanceMemberV2(
                ref, "root", 1, canonical_digest(before),
                state, 1, canonical_digest(before_state), H, 0.0,
                2, canonical_digest(after), 0.01, state, 2,
                canonical_digest(next_state)))
        self.members = tuple(members)
        self.evidence = ProductAdvanceEvidenceV2(
            "d11.product_advance_evidence.v2", self.ns, "advance:one", H,
            "process:one", "replay:one", 0.0, 1.0, self.members,
            H, "incarnation:one", 1, 1, 0, 0, H, H, H, H, H, H, H, H, H, H, H,
            (("family:one", H),), H, H)
        self.db.commit()

    def _write(self):
        self.db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?)",
                        (*self.ns.as_tuple, self.evidence.operation_id,
                         self.evidence.bundle_digest, "activity:one"))
        writes = [[m.checkpoint_ref, m.next_revision] for m in self.members]
        writes.extend([m.output_state_ref, m.output_state_revision]
                      for m in self.members)
        self.db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?)",
                        (*self.ns.as_tuple, "activity:one", self.evidence.operation_id,
                         canonical_json(writes)))
        for pos, member in enumerate(self.members):
            self.db.execute("UPDATE graph_atoms SET revision=?,value=? WHERE token=?",
                            (2, canonical_json({"cursor": 1, "block": pos}),
                             member.checkpoint_ref))
            self.db.execute("UPDATE graph_atoms SET revision=?,value=? WHERE token=?",
                            (2, canonical_json({"cursor": 1, "block": pos,
                                                "kind": "feeling"}),
                             member.output_state_ref))

    def test_two_member_receipt_persists_replays_and_rejects_overlap(self):
        self.db.execute("BEGIN IMMEDIATE")
        preflight = preflight_joint_advance_v2(
            self.db, self.evidence,
            trusted_local_verifier=lambda _db, e: e.closure_digest == H)
        self._write()
        self.assertEqual(record_joint_advance_v2(
            self.db, self.evidence, preflight=preflight),
            "recorded_pending_transaction_commit")
        self.db.commit()
        reopened = sqlite3.connect(self.path)
        try:
            self.assertEqual(read_joint_advance_v2(
                reopened, self.ns, self.evidence.operation_id), self.evidence)
        finally:
            reopened.close()
        self.db.execute("BEGIN IMMEDIATE")
        self.assertEqual(preflight_joint_advance_v2(
            self.db, self.evidence, trusted_local_verifier=None), "duplicate")
        self.assertEqual(record_joint_advance_v2(
            self.db, self.evidence, preflight=preflight), "duplicate")
        overlapping = replace(
            self.evidence, operation_id="advance:two", replay_key="replay:two",
            members=tuple(replace(m, predecessor_operation_id="advance:one",
                                  predecessor_revision=2,
                                  predecessor_value_digest=m.next_value_digest,
                                  predecessor_state_revision=2,
                                  predecessor_state_value_digest=m.output_state_digest,
                                  inherited_error_bound=m.next_error_bound,
                                  next_revision=3,
                                  output_state_revision=3) for m in self.members))
        with self.assertRaisesRegex(JointAdvanceHold, "overlaps"):
            preflight_joint_advance_v2(
                self.db, overlapping, trusted_local_verifier=lambda *_: True)
        self.db.rollback()

    def test_candidate_only_proof_and_legacy_gap_hold(self):
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(JointAdvanceHold, "trusted joint issuer"):
            preflight_joint_advance_v2(self.db, self.evidence,
                                       trusted_local_verifier=None)
        self.db.execute("INSERT INTO graph_product_advances VALUES(?,?,?,?)",
                        (*self.ns.as_tuple, "legacy", "process:one"))
        with self.assertRaisesRegex(JointAdvanceHold, "lack numeric checkpoint member IDs"):
            preflight_joint_advance_v2(self.db, self.evidence,
                                       trusted_local_verifier=lambda *_: True)
        self.db.rollback()

    def test_missing_committed_member_schema_is_explicit_hold(self):
        other = sqlite3.connect(":memory:")
        try:
            with self.assertRaisesRegex(JointAdvanceHold, "committed-member V2"):
                read_joint_advance_v2(other, self.ns, "advance:one")
        finally:
            other.close()


if __name__ == "__main__":
    unittest.main()
