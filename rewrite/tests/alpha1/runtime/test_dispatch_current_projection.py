"""Current D03/D05 inventory must be complete inside one graph transaction."""

import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime.dispatch_current_projection import read_current_dispatch_projection
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


def _case():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,type_name TEXT,
                                 revision INTEGER,value TEXT,valid INTEGER);
    """)
    namespace = NamespaceId("bot", "persona")
    role = GraphAtom(
        AtomKey(Owner("scene", "bot", "persona", "scene:one"),
                "d03.role_binding", "binding:one"),
        2, {"role_binding_id": "binding:one"},
    )
    boundary = GraphAtom(
        AtomKey(Owner("relation", "bot", "persona", "entity:user"),
                "d05.boundary_rule", "boundary:one"),
        1, {"rule_id": "boundary:one"},
    )
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 5))
    for atom in (role, boundary):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            atom.key.token, "bot", "persona", atom.key.type_name,
            atom.revision, canonical_json(atom.value), 1,
        ))
    snapshot = GraphSnapshot((role, boundary), (NamespaceEpoch("bot", "persona", 5),))
    query = QueryEpoch(namespace, "all", 5)
    return db, namespace, snapshot, query


def test_complete_current_projection_is_stable_within_graph_transaction():
    db, namespace, snapshot, query = _case()
    try:
        with pytest.raises(ValueError, match="graph transaction"):
            read_current_dispatch_projection(db, namespace, snapshot, query)
        db.execute("BEGIN IMMEDIATE")
        result = read_current_dispatch_projection(db, namespace, snapshot, query)
        assert result.role_bindings == (snapshot.atoms[0],)
        assert result.boundary_rules == (snapshot.atoms[1],)
        assert result.digest == read_current_dispatch_projection(
            db, namespace, snapshot, query).digest
    finally:
        db.close()


def test_missing_domain_row_or_changed_epoch_rejects_projection():
    db, namespace, snapshot, query = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        partial = GraphSnapshot(snapshot.atoms[:1], snapshot.epochs)
        with pytest.raises(ValueError, match="omits"):
            read_current_dispatch_projection(db, namespace, partial, query)
        db.execute("UPDATE graph_epochs SET revision=6")
        with pytest.raises(ValueError, match="epoch changed"):
            read_current_dispatch_projection(db, namespace, snapshot, query)
    finally:
        db.close()
