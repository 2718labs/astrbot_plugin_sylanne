"""W01 provisions the immutable joint output original with its graph journal."""

from pathlib import Path

import pytest

from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.runtime.d04_joint_output_original_store_v1 import (
    D04JointOutputOriginalHold, read_current_d04_joint_output_source_closure_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


def test_joint_output_schema_is_immutable_and_rolled_back_with_graph(tmp_path: Path):
    store = GraphStore(tmp_path / "graph.db", TypeRegistry())
    try:
        db = store._db
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'",
        )}
        assert {"graph_d04_joint_advances_v2",
                "graph_d04_joint_numeric_originals_v1",
                "graph_d04_joint_output_originals_v1"}.issubset(tables)
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO graph_bundle_operations "
                   "(bot,persona,operation_id,digest,activity_id,effect_id,"
                   "commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                   ("bot", "persona", "op", "a" * 64, "activity", None, 1,
                    '{"ledger_refs":[],"outbox_refs":[]}'))
        db.execute("INSERT INTO graph_d04_joint_advances_v2 "
                   "(bot,persona,operation_id,process_id,replay_key,role_start,"
                   "role_end,evidence_json,evidence_digest,bundle_digest) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?)",
                   ("bot", "persona", "op", "process", "replay", 0.0, 1.0,
                    "{}", "b" * 64, "a" * 64))
        db.execute("INSERT INTO graph_d04_joint_output_originals_v1 "
                   "VALUES(?,?,?,?,?,?,?)",
                   ("bot", "persona", "op", "b" * 64, "{}", "c" * 64,
                    "d" * 64))
        with pytest.raises(Exception, match="immutable"):
            db.execute("UPDATE graph_d04_joint_output_originals_v1 "
                       "SET original_digest=? WHERE operation_id=?",
                       ("e" * 64, "op"))
        db.execute("ROLLBACK")
        assert db.execute(
            "SELECT 1 FROM graph_d04_joint_output_originals_v1",
        ).fetchone() is None
    finally:
        store.close()


@pytest.mark.parametrize("changed", ("access", "correction"))
def test_sealed_source_closure_rejects_current_revocation_or_correction(
        tmp_path: Path, changed: str):
    """Controlled GraphStore proof read; no installed ABI2/product issuer is claimed."""
    store = GraphStore(tmp_path / "graph.db", TypeRegistry())
    namespace = NamespaceId("bot:one", "alice")
    source = source_key(*namespace.as_tuple, "source:one")
    access = access_key(*namespace.as_tuple, "source:one")
    correction = source_correction_head_key(namespace, "source:one")
    record = SourceRecord(
        "source:one", "evidence", "speaker", "reported", "reported",
        1.0, 2.0, "family:one", ("owner",), ("context",), (),
    )
    access_value = {"source_id": "source:one", "audiences": ["owner"],
                    "purposes": ["context"], "status": "active",
                    "recorded_at": 2.0}

    def insert_atom(key, value):
        db.execute(
            "INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)",
            (key.token, key.owner.bot, key.owner.persona, key.owner.kind,
             key.owner.subject, key.type_name, key.name, 1,
             canonical_serialize(value), 1),
        )

    try:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        insert_atom(source, record.to_dict())
        insert_atom(access, access_value)
        db.execute("INSERT INTO graph_bundle_operations "
                   "(bot,persona,operation_id,digest,activity_id,effect_id,"
                   "commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                   namespace.as_tuple + ("op", "a" * 64, "activity", None, 1,
                                         '{"ledger_refs":[],"outbox_refs":[]}'))
        db.execute("INSERT INTO graph_d04_joint_advances_v2 "
                   "(bot,persona,operation_id,process_id,replay_key,role_start,"
                   "role_end,evidence_json,evidence_digest,bundle_digest) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?)",
                   namespace.as_tuple + ("op", "process", "replay", 0.0, 1.0,
                                         "{}", "b" * 64, "a" * 64))
        db.execute("INSERT INTO graph_d04_joint_output_originals_v1 VALUES(?,?,?,?,?,?,?)",
                   namespace.as_tuple + ("op", "b" * 64, "{}", "c" * 64,
                                         "d" * 64))
        rows = tuple(sorted((
            (source.token, 1, True, canonical_digest(record.to_dict())),
            (access.token, 1, True, canonical_digest(access_value)),
            (correction.token, 0, False, canonical_digest({})),
        )))
        body = {"schema": "d04.joint-output-closure.v1",
                "component_digest": "e" * 64, "audience": ("owner",),
                "purpose": "context", "rows": rows}
        db.execute("INSERT INTO graph_d04_joint_output_closures_v1 "
                   "VALUES(?,?,?,?,?,?)",
                   namespace.as_tuple + ("op", "b" * 64,
                                         canonical_serialize(body), canonical_digest(body)))
        db.commit()
        db.execute("BEGIN")
        snapshot = read_current_d04_joint_output_source_closure_v1(
            db, namespace, "op", "b" * 64, "e" * 64, 1)
        assert {atom.key for atom in snapshot.atoms} == {source, access, correction}
        db.rollback()
        db.execute("BEGIN IMMEDIATE")
        if changed == "access":
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access.token,))
        else:
            insert_atom(correction, {"source_id": "source:one", "revision": 1})
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(D04JointOutputOriginalHold, match="read changed|negative read changed"):
            read_current_d04_joint_output_source_closure_v1(
                db, namespace, "op", "b" * 64, "e" * 64, 2)
        db.rollback()
    finally:
        store.close()
