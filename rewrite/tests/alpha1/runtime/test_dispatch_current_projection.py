"""Current D03/D05 inventory must be complete inside one graph transaction."""

import sqlite3
from dataclasses import asdict, replace

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d03.context import ContextProvider, RoleBinding, RoleBindingRequest
from sylanne3.domains.d05.relationship import BoundaryRule
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
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


def _typed_case():
    db, namespace, _, query = _case()
    source = source_key("bot", "persona", "source-1")
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        source.token, "bot", "persona", "memory.source", 1,
        canonical_json({"source_id": "source-1"}), 1,
    ))
    binding = RoleBinding(
        "binding:one", "persona:persona", "friend", "entity:user", None,
        "scene:one", "direct", "private", (), 1, None, 1,
        ("source:one",), 2, "active",
    )
    rule = BoundaryRule(
        "boundary:one", "persona:persona", "entity:user", "message",
        "conversation", "scene:one", "allow", "self_internal",
        (source.token,), (), (), 1, None, 1, "actor", (), "active",
    )
    atoms = (
        GraphAtom(
            AtomKey(Owner("scene", "bot", "persona", "scene:one"),
                    "d03.role_binding", "binding:one"),
            2, {**asdict(binding), "norm_refs": list(binding.norm_refs),
                "source_refs": list(binding.source_refs)},
        ),
        GraphAtom(
            AtomKey(Owner("relation", "bot", "persona", "entity:user"),
                    "d05.boundary_rule", "boundary:one"),
            1, {**asdict(rule), **{
                name: list(getattr(rule, name)) for name in (
                    "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs",
                )
            }},
        ),
    )
    for atom in atoms:
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (
            canonical_json(atom.value), atom.key.token,
        ))
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 5),))
    provider = ContextProvider()
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1", "roles": ("friend",), "norms": (),
    }, None)
    request = RoleBindingRequest(
        "persona:persona", "entity:user", None, "scene:one", "message",
        "respond", 2, True,
    )
    return db, namespace, snapshot, query, provider, request


def test_typed_domain_reads_from_one_complete_sqlite_transaction():
    db, namespace, snapshot, query, provider, request = _typed_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        projection = read_current_dispatch_projection(db, namespace, snapshot, query)
        role, boundary = derive_current_domain_reads(db, projection, request, provider)
        assert role.status == "complete"
        assert role.matched_bindings == ("binding:one",)
        assert role.query_epoch == QueryEpoch(namespace, "d03.role_binding", 5)
        assert role.read_versions[0].key == snapshot.atoms[0].key
        assert role.request == request
        assert boundary.coverage == "full"
        assert boundary.rules[0].rule_id == "boundary:one"
        assert boundary.query_epoch == QueryEpoch(namespace, "d05.boundary", 5)
        assert {(ref.ref, ref.version) for ref in boundary.input_versions} == {
            ("d05.boundary", 5), ("boundary:one", 1),
        }
    finally:
        db.close()


def test_typed_reads_reject_omitted_or_changed_current_rows():
    db, namespace, snapshot, query, provider, request = _typed_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        projection = read_current_dispatch_projection(db, namespace, snapshot, query)
        with pytest.raises(ValueError, match="digest changed"):
            derive_current_domain_reads(
                db, replace(projection, boundary_rules=()), request, provider,
            )
        db.execute("UPDATE graph_atoms SET revision=2 WHERE token=?", (
            snapshot.atoms[1].key.token,
        ))
        with pytest.raises(ValueError, match="row changed"):
            derive_current_domain_reads(db, projection, request, provider)
    finally:
        db.close()
