"""Authority independently reconstructs the selected D07 evidence ancestry."""

import json
import sqlite3

import pytest

from rewrite.tests.alpha1.d07.test_qualified_attention_read import (
    NAMESPACE, _snapshot,
)
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.contracts import canonical_json
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.memory_types import access_key, source_key


AUDIENCE = "conversation:private"


def _graph():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms (token TEXT, revision INTEGER, value TEXT, valid INTEGER)")
    db.execute("CREATE TABLE graph_first_ingress_identity_v1 "
               "(bot TEXT, persona TEXT, source_ref TEXT, conversation_ref TEXT)")
    snapshot = _snapshot(parents=("ancestor",))
    for atom in snapshot.atoms:
        value = dict(atom.value)
        if atom.key.type_name == "memory.source":
            value["audiences"] = [AUDIENCE]
            value["purposes"] = ["expression"]
        elif atom.key.type_name == "memory.access":
            value["audiences"] = [AUDIENCE]
            value["purposes"] = ["expression"]
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?)",
                   (atom.key.token, atom.revision, canonical_json(value),
                    int(atom.valid)))
    db.execute("INSERT INTO graph_first_ingress_identity_v1 VALUES (?,?,?,?)",
               (*NAMESPACE.as_tuple, "selected", AUDIENCE))
    return db


def _read(db):
    root = source_key(*NAMESPACE.as_tuple, "selected")
    return PinnedCurrentModelEgressGraphVerifier._reply_snapshot(
        db, NAMESPACE, root.token, 1, 10.0)


def test_authority_reads_the_full_ancestry_and_negative_correction_heads():
    db = _graph()
    try:
        snapshot, attention = _read(db)
        assert attention.ticket.source_refs == (
            source_key(*NAMESPACE.as_tuple, "selected").token,)
        assert len(snapshot.versions) == 8
        assert {item.key.owner.subject for item in snapshot.atoms
                if item.key.type_name == "memory.source"} == {
                    "selected", "ancestor"}
        assert {item.revision for item in snapshot.atoms
                if item.key.type_name == "d06.source_correction_head.v1"} == {0}
    finally:
        db.close()


@pytest.mark.parametrize("mutation", ["missing_ancestor", "revoked_access", "corrected"])
def test_authority_holds_when_an_ancestor_changes(mutation):
    db = _graph()
    try:
        if mutation == "missing_ancestor":
            token = source_key(*NAMESPACE.as_tuple, "ancestor").token
            db.execute("DELETE FROM graph_atoms WHERE token=?", (token,))
        elif mutation == "revoked_access":
            token = access_key(*NAMESPACE.as_tuple, "ancestor").token
            row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                             (token,)).fetchone()
            value = json.loads(row[0])
            value["status"] = "withdrawn"
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_json(value), token))
        else:
            token = source_correction_head_key(NAMESPACE, "ancestor").token
            db.execute("UPDATE graph_atoms SET revision=1,valid=1 WHERE token=?",
                       (token,))
        with pytest.raises((ValueError, KeyError, TypeError)):
            _read(db)
    finally:
        db.close()
