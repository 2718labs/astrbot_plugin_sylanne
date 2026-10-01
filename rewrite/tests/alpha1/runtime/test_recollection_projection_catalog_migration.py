"""Only reviewed types may append to a populated graph catalogue."""

import sqlite3

import pytest

from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.domains.d08 import GoalExecutionProvider, NATURAL_PLAN_TYPE_V2
from sylanne3.domains.d12 import graph_type_specs as d12_graph_type_specs
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, TypeSpec
from sylanne3.runtime.d11_types import D11RuntimeProvider
from sylanne3.runtime.role_resources import ROLE_RESOURCES_TYPE
from sylanne3.runtime.source_attachment_graph_v2 import SOURCE_MEDIA_TYPE_V2


PROJECTION_TYPE = "d06.recollection_projection.v1"
ACTIVE_HEAD_TYPE = "d12.active_scheme_head.v1"
CONCERN_ROUND_TYPE = "d07.concern_round.v1"
APPEND_TYPES = frozenset({PROJECTION_TYPE, ROLE_RESOURCES_TYPE,
                          ACTIVE_HEAD_TYPE, CONCERN_ROUND_TYPE,
                          NATURAL_PLAN_TYPE_V2, SOURCE_MEDIA_TYPE_V2})


def _registries(present=()):
    old = TypeRegistry()
    current = TypeRegistry()
    base = TypeSpec("test.state", ("persona",), "state", lambda _: None,
                    writer_domain="d06", schema_hash="a" * 64)
    old.register(base)
    current.register(base)
    specs = (D06DomainProvider.type_specs() + D07DomainProvider.type_specs() +
             GoalExecutionProvider().register_types() +
             D11RuntimeProvider().type_specs() + d12_graph_type_specs())
    assert APPEND_TYPES <= {spec.name for spec in specs}
    for spec in specs:
        current.register(spec)
        if spec.name not in APPEND_TYPES or spec.name in present:
            old.register(spec)
    return old, current


def _populated_old_graph(path, registry):
    store = ProductionGraphStore(path, registry)
    try:
        store._db.execute(
            "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
            "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ('["persona","bot","persona",null,"test.state","one"]',
             "bot", "persona", "persona", None, "test.state", "one", 1,
             "{}", 1),
        )
    finally:
        store.close()


@pytest.mark.parametrize("present", [
    (), (ROLE_RESOURCES_TYPE,), (PROJECTION_TYPE,),
    (ACTIVE_HEAD_TYPE,), (ROLE_RESOURCES_TYPE, ACTIVE_HEAD_TYPE),
    (CONCERN_ROUND_TYPE,),
    (NATURAL_PLAN_TYPE_V2,),
    (SOURCE_MEDIA_TYPE_V2,),
    (PROJECTION_TYPE, ACTIVE_HEAD_TYPE),
    (ROLE_RESOURCES_TYPE, PROJECTION_TYPE),
    (ROLE_RESOURCES_TYPE, PROJECTION_TYPE, ACTIVE_HEAD_TYPE),
])
def test_populated_graph_appends_each_exact_missing_type(tmp_path, present):
    previous, current = _registries(present)
    path = tmp_path / "graph.db"
    _populated_old_graph(path, previous)

    upgraded = ProductionGraphStore(path, current)
    try:
        assert upgraded._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='test.state'"
        ).fetchone() == (1,)
        for table in ("graph_type_catalog", "graph_type_authority"):
            names = {row[0] for row in upgraded._db.execute(
                f"SELECT name FROM {table}",
            )}
            assert names == {spec.name for spec in current.specs}
    finally:
        upgraded.close()
    reopened = ProductionGraphStore(path, current)
    reopened.close()


def test_fresh_graph_installs_reviewed_types_without_migration(tmp_path):
    _, current = _registries()
    store = ProductionGraphStore(tmp_path / "fresh.db", current)
    try:
        assert store._db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone() == (0,)
        for table in ("graph_type_catalog", "graph_type_authority"):
            rows = store._db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE name IN (?,?,?,?,?,?)",
                tuple(sorted(APPEND_TYPES)),
            ).fetchone()
            assert rows == (6,)
    finally:
        store.close()


def test_populated_graph_without_writer_authority_stays_legacy(tmp_path):
    previous, _ = _registries()
    path = tmp_path / "legacy.db"
    _populated_old_graph(path, previous)
    db = sqlite3.connect(path)
    try:
        db.execute("DELETE FROM graph_type_authority")
        db.commit()
    finally:
        db.close()

    with pytest.raises(ValueError, match="legacy graph requires explicit writer-authority migration"):
        ProductionGraphStore(path, previous)
    db = sqlite3.connect(path)
    try:
        assert db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM graph_type_authority").fetchone() == (0,)
    finally:
        db.close()


@pytest.mark.parametrize("fault", [
    "old_owner", "old_schema_version", "old_schema_hash", "new_atom",
    "split_catalogue", "other_new_type",
])
def test_other_catalogue_drift_rejects_without_partial_append(tmp_path, fault):
    previous, current = _registries()
    path = tmp_path / "graph.db"
    _populated_old_graph(path, previous)
    if fault == "other_new_type":
        current.register(TypeSpec(
            "test.unreviewed", ("persona",), "state", lambda _: None,
            writer_domain="d06", schema_hash="b" * 64,
        ))
    else:
        db = sqlite3.connect(path, isolation_level=None)
        try:
            if fault == "old_owner":
                db.execute(
                    "UPDATE graph_type_catalog SET owner_kinds='[\"persona\"]' "
                    "WHERE name='d06.recollection.v1'",
                )
            elif fault == "old_schema_version":
                db.execute(
                    "UPDATE graph_type_catalog SET schema_version=2 "
                    "WHERE name='d06.recollection.v1'",
                )
            elif fault == "old_schema_hash":
                db.execute(
                    "UPDATE graph_type_authority SET schema_hash=? "
                    "WHERE name='d06.recollection.v1'", ("f" * 64,),
                )
            elif fault == "new_atom":
                db.execute(
                    "INSERT INTO graph_atoms(token,bot,persona,owner_kind,"
                    "subject,type_name,name,revision,value,valid) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    ("untrusted-projection", "bot", "persona", "activity",
                     "activity:one", PROJECTION_TYPE, "one", 1, "{}", 1),
                )
            else:
                row = ProductionGraphStore._catalog_row(
                    current.spec(PROJECTION_TYPE),
                )
                db.execute(
                    "INSERT INTO graph_type_catalog"
                    "(name,owner_kinds,storage_role,immutable,schema_version) "
                    "VALUES(?,?,?,?,?)", row,
                )
        finally:
            db.close()

    with pytest.raises(ValueError, match="catalogue|catalog"):
        ProductionGraphStore(path, current)
    db = sqlite3.connect(path)
    try:
        for table in ("graph_type_catalog", "graph_type_authority"):
            untouched = (APPEND_TYPES - {PROJECTION_TYPE}
                         if fault == "split_catalogue" and
                            table == "graph_type_catalog" else APPEND_TYPES)
            assert all(db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE name=?", (name,),
            ).fetchone() == (0,) for name in untouched)
    finally:
        db.close()
