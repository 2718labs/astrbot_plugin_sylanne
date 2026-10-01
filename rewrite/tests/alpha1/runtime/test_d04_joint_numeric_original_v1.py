"""A joint graph commit and its 24-axis original share one SQLite transaction."""

from dataclasses import replace
import json
import sqlite3
import unittest

from sylanne3.domains.d04.joint_numeric_receipt import (
    D04FamilyContributionDoseV1, D04JointMemberNumericResultV1,
    D04JointNumericReceiptCandidateV1, D04NumericOutputIntervalV1,
)
from sylanne3.domains.d04.encoding_baseline_v2 import ProjectionNumericErrorV2
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d04_joint_advance_v2 import (
    JointAdvanceHold, JointNumericOriginalVerificationV1,
    ProductAdvanceEvidenceV2, ProductAdvanceMemberV2,
    install_joint_advance_store_v2, preflight_joint_advance_v2,
    preflight_joint_numeric_original_v1, read_current_joint_numeric_original_v1,
    record_joint_advance_v2, record_joint_numeric_original_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


H = "a" * 64


class JointNumericOriginalTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE graph_bundle_operations (
                bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,
                activity_id TEXT, PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE graph_events (
                bot TEXT, persona TEXT, session TEXT, event_id TEXT, revisions TEXT);
            CREATE TABLE graph_product_advances (bot TEXT, persona TEXT, operation_id TEXT);
            CREATE TABLE graph_d04_root_originals_v1 (
                bot TEXT, persona TEXT, operation_id TEXT);
            CREATE TABLE graph_epochs (bot TEXT, persona TEXT, revision INTEGER);
            CREATE TABLE graph_authority_epochs (
                bot TEXT, persona TEXT, access_epoch INTEGER, delete_epoch INTEGER);
            CREATE TABLE graph_recovery_metadata_v2 (
                bot TEXT, persona TEXT, requirements_json TEXT, graph_revision INTEGER);
            CREATE TABLE graph_atoms (
                token TEXT PRIMARY KEY, revision INTEGER, value TEXT, valid INTEGER);
            CREATE TABLE graph_history (
                token TEXT, revision INTEGER, event_bot TEXT, event_persona TEXT,
                event_session TEXT, event_id TEXT, value TEXT, valid INTEGER);
        """)
        install_joint_advance_store_v2(self.db)
        self.ns = NamespaceId("bot:one", "alice")
        owner = Owner("persona", *self.ns.as_tuple)
        self.db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*self.ns.as_tuple, 1))
        self.db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
                        (*self.ns.as_tuple, 0, 0))
        self.db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?)",
                        (*self.ns.as_tuple,
                         canonical_serialize({"graph_incarnation": "inc:one"}), 1))
        self.db.execute("INSERT INTO graph_d04_root_originals_v1 VALUES(?,?,?)",
                        (*self.ns.as_tuple, "root"))
        members = []
        for index in range(2):
            checkpoint = AtomKey(owner, "d04.numeric_checkpoint.v1",
                                 f"block:{index}").token
            state = AtomKey(owner, "d04.feeling_state.v1", f"block:{index}").token
            before = {"cursor": 0, "block": index}
            after = {"cursor": 1, "block": index}
            self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                            (checkpoint, 1, canonical_serialize(before)))
            self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                            (state, 1, canonical_serialize(before)))
            members.append(ProductAdvanceMemberV2(
                checkpoint, "root", 1, canonical_digest(before), state, 1,
                canonical_digest(before), H, 0.0, 2, canonical_digest(after),
                0.01, state, 2, canonical_digest(after),
            ))
        self.evidence = ProductAdvanceEvidenceV2(
            "d11.product_advance_evidence.v2", self.ns, "advance:one", H,
            "process:one", "replay:one", 0.0, 1.0, tuple(members), H,
            "inc:one", 1, 1, 0, 0, H, H, H, H, H, H, H, H, H, H, H,
            (("family:one", H),), H, H,
        )
        outputs = tuple(D04NumericOutputIntervalV1(axis, f"output:{index}",
                                                       0.0, 1.0)
                        for index, axis in enumerate(REGISTERED_AXIS_IDS))
        doses = tuple(D04NumericOutputIntervalV1(axis, f"output:{index}",
                                                     -1.0, 1.0)
                      for index, axis in enumerate(REGISTERED_AXIS_IDS))
        numeric_members = tuple(D04JointMemberNumericResultV1(
            item.checkpoint_ref, outputs,
            (D04FamilyContributionDoseV1("family:one", ("source:one",),
                                         outputs, doses),),
        ) for item in members)
        content = dict(
            namespace=self.ns, component_digest=H, read_values_digest=H,
            graph_incarnation="inc:one", graph_revision=1, graph_epoch=1,
            access_epoch=0, delete_epoch=0, role_start=0.0, role_end=1.0,
            operator_version="operator:one", native_manifest_sha256=H,
            native_sha256=H, native_abi_version=2,
            source_versions=(("drive:one", 1, "source:one", 1,
                              "access:one", 1, "family:one"),),
            member_refs=tuple(m.checkpoint_ref for m in members),
            full_transcript_sha256=H,
            family_transcripts=(("family:one", H),),
            math_transcript_sha256=H, members=numeric_members,
        )
        self.numeric = D04JointNumericReceiptCandidateV1(
            **content, receipt_digest=canonical_digest(content))
        self.verification = JointNumericOriginalVerificationV1(
            "policy:one", "policy:v1", H, "readout:one", "readout:v1", H,
            H, ProjectionNumericErrorV2(0.1, 0.1, 0.1, 0.1, H),
        )
        self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                        ("source:one", 1, "{}"))
        self.db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                        ("access:one", 1, "{}"))
        self.db.commit()

    def _write(self):
        evidence = self.evidence
        self.db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?)",
                        (*self.ns.as_tuple, evidence.operation_id,
                         evidence.bundle_digest, "activity:one"))
        writes = []
        for index, member in enumerate(evidence.members):
            for ref, revision in ((member.checkpoint_ref, member.next_revision),
                                  (member.output_state_ref,
                                   member.output_state_revision)):
                value = canonical_serialize({"cursor": 1, "block": index})
                writes.append((ref, revision))
                self.db.execute("UPDATE graph_atoms SET revision=?,value=? WHERE token=?",
                                (revision, value, ref))
                self.db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,1)",
                                (ref, revision, *self.ns.as_tuple, "activity:one",
                                 evidence.operation_id, value))
        self.db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?)",
                        (*self.ns.as_tuple, "activity:one", evidence.operation_id,
                         json.dumps(writes)))

    def test_atomic_original_current_read_and_conflicts(self):
        self.db.execute("BEGIN IMMEDIATE")
        joint = preflight_joint_advance_v2(
            self.db, self.evidence, trusted_local_verifier=lambda *_: True)
        numeric = preflight_joint_numeric_original_v1(
            self.db, self.evidence, self.numeric, joint_preflight=joint,
            trusted_local_numeric_verifier=lambda *_: self.verification)
        self._write()
        record_joint_advance_v2(self.db, self.evidence, preflight=joint)
        self.assertEqual(record_joint_numeric_original_v1(
            self.db, self.evidence, self.numeric, preflight=numeric),
            "recorded_pending_transaction_commit")
        self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        kwargs = dict(
            expected_graph_incarnation="inc:one", expected_graph_revision=1,
            expected_graph_epoch=1, expected_access_epoch=0,
            expected_delete_epoch=0, expected_policy_digest=H,
            expected_readout_sha256=H,
            trusted_current_verifier=lambda *_: True,
        )
        original = read_current_joint_numeric_original_v1(
            self.db, self.ns, self.evidence.operation_id,
            self.evidence.members[0].checkpoint_ref, **kwargs)
        self.assertEqual(original.original_revision, 2)
        self.assertEqual(original.receipt, self.numeric)
        self.assertEqual(original.adoption_receipt_digest, self.evidence.digest)
        self.assertEqual(original.verification, self.verification)
        with self.assertRaisesRegex(JointAdvanceHold, "Owner proof"):
            read_current_joint_numeric_original_v1(
                self.db, self.ns, self.evidence.operation_id,
                self.evidence.members[0].checkpoint_ref,
                **{**kwargs, "trusted_current_verifier": None})
        self.assertEqual(record_joint_numeric_original_v1(
            self.db, self.evidence, self.numeric, preflight=numeric), "duplicate")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE graph_d04_joint_numeric_originals_v1 "
                            "SET numeric_receipt_digest=?", ("b" * 64,))
        self.db.rollback()

    def test_unsigned_candidate_cannot_promote_and_history_is_required(self):
        self.db.execute("BEGIN IMMEDIATE")
        joint = preflight_joint_advance_v2(
            self.db, self.evidence, trusted_local_verifier=lambda *_: True)
        with self.assertRaisesRegex(JointAdvanceHold, "trusted numeric replay"):
            preflight_joint_numeric_original_v1(
                self.db, self.evidence, self.numeric, joint_preflight=joint,
                trusted_local_numeric_verifier=None)
        with self.assertRaisesRegex(JointAdvanceHold, "trusted numeric replay rejected"):
            preflight_joint_numeric_original_v1(
                self.db, self.evidence, self.numeric, joint_preflight=joint,
                trusted_local_numeric_verifier=lambda *_: True)
        incomplete = replace(self.numeric, members=(replace(
            self.numeric.members[0], full=self.numeric.members[0].full[:-1]),
            *self.numeric.members[1:]))
        with self.assertRaisesRegex(JointAdvanceHold, "identity differs"):
            preflight_joint_numeric_original_v1(
                self.db, self.evidence, incomplete, joint_preflight=joint,
                trusted_local_numeric_verifier=lambda *_: True)
        numeric = preflight_joint_numeric_original_v1(
            self.db, self.evidence, self.numeric, joint_preflight=joint,
            trusted_local_numeric_verifier=lambda *_: self.verification)
        self._write()
        record_joint_advance_v2(self.db, self.evidence, preflight=joint)
        self.db.execute("DELETE FROM graph_history WHERE token=?",
                        (self.evidence.members[0].checkpoint_ref,))
        with self.assertRaisesRegex(JointAdvanceHold, "graph history differs"):
            record_joint_numeric_original_v1(
                self.db, self.evidence, self.numeric, preflight=numeric)
        self.db.rollback()
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM graph_d04_joint_advances_v2").fetchone(), (0,))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM graph_d04_joint_numeric_originals_v1").fetchone(),
                         (0,))


if __name__ == "__main__":
    unittest.main()
