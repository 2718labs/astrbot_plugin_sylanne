"""D04 v2 graph identities remain reserved until formal issuance exists."""

import pytest

from sylanne3.domains.d04.affect import AffectProvider
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, TypeSpec


NAMES = ("d04.encoding_baseline.v2", "d04.encoding_projection_receipt.v2")


def test_unsigned_d04_v2_graph_writes_are_rejected():
    specs = {spec.name: spec for spec in AffectProvider().type_specs()}
    assert set(NAMES) <= set(AffectProvider().register_types())
    for name in NAMES:
        spec = specs[name]
        assert spec.immutable and spec.schema_version == 2
        assert spec.writer_domain == "d04" and spec.owner_kinds == ("event",)
        with pytest.raises(ValueError, match="no installed issuer"):
            spec.validator({"schema": name, "status": "candidate_unadopted"})


def test_populated_graph_only_appends_reserved_d04_v2_types(tmp_path):
    old = TypeRegistry()
    current = TypeRegistry()
    base = TypeSpec("test.state", ("persona",), "state", lambda value: value,
                    writer_domain="d04", schema_hash="a" * 64)
    old.register(base)
    current.register(base)
    specs = {spec.name: spec for spec in AffectProvider().type_specs()}
    for name in NAMES:
        current.register(specs[name])
    path = tmp_path / "graph.db"
    store = ProductionGraphStore(path, old)
    store.close()
    upgraded = ProductionGraphStore(path, current)
    try:
        assert {row[0] for row in upgraded._db.execute(
            "SELECT name FROM graph_type_catalog"
        )} == {"test.state", *NAMES}
        assert upgraded._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN (?,?)", NAMES,
        ).fetchone() == (0,)
    finally:
        upgraded.close()
