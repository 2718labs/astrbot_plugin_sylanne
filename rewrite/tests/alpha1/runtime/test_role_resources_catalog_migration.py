"""Only the D11 role-resource type may be added to an existing v2 catalogue."""

import sqlite3

import pytest

from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, TypeSpec
from sylanne3.runtime.d11_types import D11RuntimeProvider
from sylanne3.runtime.role_resources import ROLE_RESOURCES_TYPE


def _registries():
    previous = TypeRegistry()
    current = TypeRegistry()
    state = TypeSpec("test.state", ("persona",), "state", lambda _: None,
                     writer_domain="d06", schema_hash="a" * 64)
    previous.register(state)
    current.register(state)
    for spec in D11RuntimeProvider().type_specs():
        current.register(spec)
        if spec.name != ROLE_RESOURCES_TYPE:
            previous.register(spec)
    return previous, current


def _old_database(path, previous):
    store = ProductionGraphStore(path, previous)
    # A populated v2 graph must keep its existing rows through catalogue upgrade.
    store._db.execute(
        "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,"
        "name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ('["persona","bot","persona",null,"test.state","one"]',
         "bot", "persona", "persona", None, "test.state", "one", 1, "{}", 1),
    )
    store.close()


def test_existing_v2_catalogue_adds_only_role_resources(tmp_path):
    previous, current = _registries()
    path = tmp_path / "graph.db"
    _old_database(path, previous)

    upgraded = ProductionGraphStore(path, current)
    try:
        assert upgraded._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='test.state'"
        ).fetchone() == (1,)
        for table in ("graph_type_catalog", "graph_type_authority"):
            assert upgraded._db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE name=?",
                (ROLE_RESOURCES_TYPE,),
            ).fetchone() == (1,)
    finally:
        upgraded.close()
    reopened = ProductionGraphStore(path, current)
    reopened.close()


@pytest.mark.parametrize("tamper", ["catalog", "authority", "new_atom"])
def test_v2_catalogue_migration_rejects_other_differences(tmp_path, tamper):
    previous, current = _registries()
    path = tmp_path / "graph.db"
    _old_database(path, previous)
    db = sqlite3.connect(path, isolation_level=None)
    try:
        if tamper == "catalog":
            db.execute("UPDATE graph_type_catalog SET storage_role='cache' "
                       "WHERE name='test.state'")
        elif tamper == "authority":
            db.execute("UPDATE graph_type_authority SET schema_hash=? "
                       "WHERE name='test.state'", ("b" * 64,))
        else:
            db.execute(
                "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("untrusted-new-atom", "bot", "persona", "persona", None,
                 ROLE_RESOURCES_TYPE, "primary", 1, "{}", 1),
            )
    finally:
        db.close()

    with pytest.raises(ValueError, match="catalogue|catalog"):
        ProductionGraphStore(path, current)
    db = sqlite3.connect(path)
    try:
        for table in ("graph_type_catalog", "graph_type_authority"):
            assert db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE name=?",
                (ROLE_RESOURCES_TYPE,),
            ).fetchone() == (0,)
    finally:
        db.close()
