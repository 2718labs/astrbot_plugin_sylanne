"""D03/D05 source dependencies retain their own access scope."""

import json
import sqlite3

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.natural_prebatch_receipts_v2 import (
    _current_structural_source_closure,
)
from sylanne3.runtime_contracts import NamespaceId


def test_context_only_structural_ancestry_is_current_but_revocation_or_correction_holds():
    namespace = NamespaceId("bot", "persona")
    audience = "owner"
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms (token TEXT, bot TEXT, persona TEXT, "
               "revision INTEGER, value TEXT, valid INTEGER)")
    atoms = []
    for source_id, parents in (("parent", ()), ("role-source", ("parent",))):
        key = source_key(*namespace.as_tuple, source_id)
        access = access_key(*namespace.as_tuple, source_id)
        record = SourceRecord(
            source_id, "structural evidence", "sender", "reported", "reported",
            None, 1.0, source_id, (audience,), ("context",),
            parent_source_ids=parents,
        )
        values = (
            (key, record.to_dict()),
            (access, {"source_id": source_id, "audiences": [audience],
                      "purposes": ["context"], "status": "active",
                      "recorded_at": 1.0}),
        )
        for atom_key, value in values:
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,1)",
                       (atom_key.token, *namespace.as_tuple, 1, json.dumps(value)))
            atoms.append(GraphAtom(atom_key, 1, value))
    snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch(*namespace.as_tuple, 1),))
    db.commit()
    try:
        db.execute("BEGIN IMMEDIATE")
        versions, absent = _current_structural_source_closure(
            db, snapshot, namespace,
            (source_key(*namespace.as_tuple, "role-source").token,),
        )
        assert len(versions) == 4
        assert absent == tuple(sorted(
            source_correction_head_key(namespace, source_id).token
            for source_id in ("parent", "role-source")))

        parent_access = access_key(*namespace.as_tuple, "parent")
        restricted = {"source_id": "parent", "audiences": [audience],
                      "purposes": ["expression"], "status": "active",
                      "recorded_at": 1.0}
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps(restricted), parent_access.token))
        restricted_snapshot = GraphSnapshot(tuple(
            GraphAtom(atom.key, atom.revision,
                      restricted if atom.key == parent_access else atom.value)
            for atom in snapshot.atoms), snapshot.epochs)
        with pytest.raises(ValueError, match="current purpose and audience"):
            _current_structural_source_closure(
                db, restricted_snapshot, namespace,
                (source_key(*namespace.as_tuple, "role-source").token,),
            )
        original_access = next(atom.value for atom in snapshot.atoms
                               if atom.key == parent_access)
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps(original_access), parent_access.token))
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                   (parent_access.token,))
        with pytest.raises(ValueError, match="staged graph atom differs"):
            _current_structural_source_closure(
                db, snapshot, namespace,
                (source_key(*namespace.as_tuple, "role-source").token,),
            )
        db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?",
                   (parent_access.token,))
        correction = source_correction_head_key(namespace, "parent")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,1)",
                   (correction.token, *namespace.as_tuple, 1, "{}"))
        with pytest.raises(ValueError, match="correction head"):
            _current_structural_source_closure(
                db, snapshot, namespace,
                (source_key(*namespace.as_tuple, "role-source").token,),
            )
    finally:
        db.rollback()
        db.close()
