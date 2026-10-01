"""Transactional C04 baseline storage; graph rows here are fixture evidence."""

from dataclasses import asdict, fields, replace
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.c04_projection_issuer_v3 import (
    conditional_encoding_baseline_contract_v3,
)
from sylanne3.domains.d04.encoding_baseline import CommittedRef
from sylanne3.domains.d04.root import NumericCheckpoint, RootAssetBindings, RootBlockIdentity
from sylanne3.graph_types import AtomKey, GraphVersion
from sylanne3.runtime.c04_encoding_baseline_store_v3 import (
    C04EncodingBaselineStoreHold, install_c04_encoding_baseline_store_v3,
    read_c04_encoding_baseline_v3, record_c04_encoding_baseline_v3,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


_fixture_path = Path(__file__).resolve().parents[1] / "d04/test_c04_projection_issuer_v3.py"
_fixture_spec = importlib.util.spec_from_file_location("c04_d04_test_fixture", _fixture_path)
assert _fixture_spec is not None and _fixture_spec.loader is not None
d04_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(d04_fixture)


def _schema(db):
    db.executescript("""
        CREATE TABLE graph_bundle_operations (
            bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,
            activity_id TEXT, effect_id TEXT, commit_seq INTEGER,
            receipt_json TEXT, PRIMARY KEY(bot,persona,operation_id));
        CREATE TABLE graph_events (
            bot TEXT, persona TEXT, session TEXT, event_id TEXT,
            reads TEXT, revisions TEXT, epoch_revision INTEGER, invalidated TEXT,
            PRIMARY KEY(bot,persona,session,event_id));
        CREATE TABLE graph_history (
            token TEXT, revision INTEGER, value TEXT, valid INTEGER,
            PRIMARY KEY(token,revision));
        CREATE TABLE graph_d04_joint_advances_v2 (
            bot TEXT, persona TEXT, operation_id TEXT, evidence_digest TEXT,
            PRIMARY KEY(bot,persona,operation_id));
        CREATE TABLE graph_d04_joint_numeric_originals_v1 (
            bot TEXT, persona TEXT, operation_id TEXT,
            numeric_receipt_json TEXT, numeric_receipt_digest TEXT,
            verification_json TEXT, verification_digest TEXT,
            PRIMARY KEY(bot,persona,operation_id));
        CREATE TABLE graph_d04_joint_output_originals_v1 (
            bot TEXT, persona TEXT, operation_id TEXT, evidence_digest TEXT,
            original_json TEXT, original_digest TEXT, write_set_digest TEXT,
            PRIMARY KEY(bot,persona,operation_id));
    """)
    install_c04_encoding_baseline_store_v3(db)


def _operation(db, namespace, operation_id, reads=(), *, epoch=1):
    activity = "activity:" + operation_id
    db.execute(
        "INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
        (*namespace.as_tuple, operation_id, "a" * 64, activity, None, 1,
         canonical_json({"ledger_refs": [], "outbox_refs": []})),
    )
    db.execute(
        "INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?)",
        (*namespace.as_tuple, activity, operation_id,
         canonical_serialize(tuple((item.key.token, item.revision) for item in reads)),
         canonical_serialize(()), epoch, canonical_serialize(())),
    )


def _checkpoint(member, operation, namespace, readout_sha):
    assets = RootAssetBindings(
        "scheme:test", "operator:test", "parameter:test", "coupling:test",
        "readout:test", "a" * 64, "b" * 64, "c" * 64, "d" * 64,
        readout_sha,
    )
    block = RootBlockIdentity(
        "block:a", "template:test", "feeling", "entity:test",
        "meaning:test", "authored:test",
    )
    return NumericCheckpoint(
        "checkpoint:test", namespace.as_tuple, block, assets, assets.digest,
        tuple(axis.axis_id for axis in member.axes), (2.0,) * 24,
        ((2.0, 2.0),) * 24, 0.0, "trusted_abi2", "e" * 64,
        1.0, CommittedRef(member.predecessor_state_ref, 2), "f" * 64,
        operation, "root", "8" * 64,
    )


class C04EncodingBaselineStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "graph.sqlite"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(lambda: self.db.close())
        _schema(self.db)
        fixture = d04_fixture.C04V3PureIssuerTests(
            "test_source_member_selection_and_error_are_original_bound")
        fixture.setUp()
        member, drive = fixture._member("block:a", fixture.source_a, 0.25)
        output, numeric = fixture._pair((member,), (drive,), "operation:joint")
        checkpoint = _checkpoint(member, output.operation_id, fixture.namespace,
                                 fixture.asset.asset_sha256)
        member = replace(member, next_checkpoint=checkpoint)
        body = {field.name: getattr(output, field.name)
                for field in fields(output)
                if field.name not in {"original_digest", "status"}}
        body["members"] = (member,)
        output = replace(output, members=(member,),
                         original_digest=canonical_digest(body))
        self.fixture = fixture
        self.output = output
        self.drive = drive
        self.numeric = numeric
        self.source = fixture.source_a

    def _ready(self):
        db, fixture = self.db, self.fixture
        db.execute("BEGIN")
        _operation(db, fixture.namespace, self.output.operation_id)
        joint_receipt = self._receipt(self.output.operation_id)
        self.numeric = replace(
            self.numeric,
            adoption_receipt_digest=canonical_digest(asdict(joint_receipt)),
        )
        proof = fixture._baseline(
            self.output, self.numeric, (self.drive,), self.source,
        )
        original = conditional_encoding_baseline_contract_v3(
            proof, encoding_operation_id="operation:baseline",
            owner_epoch=2, access_epoch=1, delete_epoch=1,
        )
        reads = tuple(GraphVersion(AtomKey.from_token(item.ref), item.revision)
                      for item in (original.source, original.perspective,
                                   *original.interpretations,
                                   *(value.feeling for value in original.members),
                                   *(value.checkpoint for value in original.members)))
        _operation(db, fixture.namespace, original.encoding_operation_id,
                   reads, epoch=2)
        for item in reads:
            db.execute("INSERT INTO graph_history VALUES(?,?,?,?)",
                       (item.key.token, item.revision, "{}", 1))
        db.execute("INSERT INTO graph_d04_joint_advances_v2 VALUES(?,?,?,?)",
                   (*fixture.namespace.as_tuple, self.output.operation_id, "b" * 64))
        db.execute("INSERT INTO graph_d04_joint_numeric_originals_v1 VALUES(?,?,?,?,?,?,?)",
                   (*fixture.namespace.as_tuple, self.output.operation_id,
                    canonical_serialize(asdict(self.numeric.receipt)),
                    self.numeric.receipt.receipt_digest,
                    canonical_serialize(asdict(self.numeric.verification)),
                    canonical_digest(asdict(self.numeric.verification))))
        db.execute("INSERT INTO graph_d04_joint_output_originals_v1 VALUES(?,?,?,?,?,?,?)",
                   (*fixture.namespace.as_tuple, self.output.operation_id,
                    "b" * 64, canonical_serialize(asdict(self.output)),
                    self.output.original_digest, self.output.write_set_digest))
        return original, proof

    def _receipt(self, operation):
        from sylanne3.runtime.c04_encoding_baseline_store_v3 import _receipt

        return _receipt(self.db, self.fixture.namespace, operation)

    def test_exact_retry_conflict_and_cold_open_read(self):
        original, proof = self._ready()
        first = record_c04_encoding_baseline_v3(
            self.db, original=original, proof=proof,
            numeric_original=self.numeric, historical_closure_digest="c" * 64,
        )
        again = record_c04_encoding_baseline_v3(
            self.db, original=original, proof=proof,
            numeric_original=self.numeric, historical_closure_digest="c" * 64,
        )
        self.assertEqual(first.record_digest, again.record_digest)
        with self.assertRaisesRegex(C04EncodingBaselineStoreHold, "retry|differs"):
            record_c04_encoding_baseline_v3(
                self.db, original=original, proof=proof,
                numeric_original=self.numeric, historical_closure_digest="d" * 64,
            )
        self.db.commit()
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.db.execute("BEGIN")
        found = read_c04_encoding_baseline_v3(
            self.db, namespace=self.fixture.namespace,
            encoding_operation_id=original.encoding_operation_id,
            source_ref=original.source.ref,
        )
        self.assertEqual(found.original, original)
        self.assertEqual(found.proof, proof)
        self.assertEqual(found.record_digest, first.record_digest)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE graph_c04_encoding_baselines_v3 SET proof_digest=?",
                ("0" * 64,),
            )
        self.db.rollback()

    def test_transaction_rollback_leaves_no_baseline(self):
        original, proof = self._ready()
        record_c04_encoding_baseline_v3(
            self.db, original=original, proof=proof,
            numeric_original=self.numeric, historical_closure_digest="c" * 64,
        )
        self.db.rollback()
        self.db.execute("BEGIN")
        with self.assertRaisesRegex(C04EncodingBaselineStoreHold, "absent"):
            read_c04_encoding_baseline_v3(
                self.db, namespace=self.fixture.namespace,
                encoding_operation_id=original.encoding_operation_id,
                source_ref=original.source.ref,
            )
        self.db.rollback()

    def test_cold_read_rejects_modified_proof_even_if_trigger_is_removed(self):
        original, proof = self._ready()
        record_c04_encoding_baseline_v3(
            self.db, original=original, proof=proof,
            numeric_original=self.numeric, historical_closure_digest="c" * 64,
        )
        self.db.commit()
        self.db.execute("DROP TRIGGER graph_c04_encoding_baseline_no_update_v3")
        self.db.execute(
            "UPDATE graph_c04_encoding_baselines_v3 SET proof_digest=?",
            ("0" * 64,),
        )
        self.db.commit()
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.db.execute("BEGIN")
        with self.assertRaisesRegex(C04EncodingBaselineStoreHold, "malformed"):
            read_c04_encoding_baseline_v3(
                self.db, namespace=self.fixture.namespace,
                encoding_operation_id=original.encoding_operation_id,
                source_ref=original.source.ref,
            )
        self.db.rollback()


if __name__ == "__main__":
    unittest.main()
