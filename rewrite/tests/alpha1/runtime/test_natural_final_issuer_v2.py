"""D11 natural final inspection is transaction-bound and never a send permit."""

import sqlite3

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.natural_final_issuer_v2 import (
    NaturalFinalIssuerHold, _current_value, inspect_natural_final_d11_v2,
)


def test_natural_final_issuer_requires_a_held_write_transaction():
    db = sqlite3.connect(":memory:")
    try:
        with pytest.raises(NaturalFinalIssuerHold) as error:
            inspect_natural_final_d11_v2(
                db, None, None, None, None, (), d11_issuer=None,
                now_utc=1.0)
        assert error.value.missing == ("graph.current_write_transaction",)
    finally:
        db.close()


def test_natural_final_issuer_rejects_untrusted_material_inside_transaction():
    db = sqlite3.connect(":memory:")
    try:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(NaturalFinalIssuerHold) as error:
            inspect_natural_final_d11_v2(
                db, None, None, None, None, (), d11_issuer=None,
                now_utc=1.0)
        assert error.value.missing == ("natural.typed_final_transaction_material",)
    finally:
        db.rollback()
        db.close()


def test_current_graph_value_requires_valid_namespace_head():
    db = sqlite3.connect(":memory:")
    key = AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                  "d09.natural_verified_segment_batch.v2", "batch:one")
    try:
        db.execute("CREATE TABLE graph_atoms("
                   "token TEXT, bot TEXT, persona TEXT, revision INTEGER, "
                   "value TEXT, valid INTEGER)")
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                   (key.token, "bot", "persona", 1, '{"payload":"one"}', 1))
        assert _current_value(db, key.token, ("bot", "persona"),
                              key.type_name) == {"payload": "one"}
        with pytest.raises(NaturalFinalIssuerHold) as wrong_namespace:
            _current_value(db, key.token, ("bot", "other"), key.type_name)
        assert wrong_namespace.value.missing == ("natural.current_graph_atom_scope",)
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (key.token,))
        with pytest.raises(NaturalFinalIssuerHold) as revoked:
            _current_value(db, key.token, ("bot", "persona"), key.type_name)
        assert revoked.value.missing == ("natural.current_graph_atom_absent",)
    finally:
        db.rollback()
        db.close()
