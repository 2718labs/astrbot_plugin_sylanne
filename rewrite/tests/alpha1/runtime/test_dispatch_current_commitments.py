"""The D08 graph read is complete, but execution and cancellation remain HOLD."""

from dataclasses import asdict
import json
import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d08.execution import ActionOutcome, Commitment
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime.dispatch_current_commitments import read_current_d08_conflict_facts
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


def _case():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT PRIMARY KEY,bot TEXT,persona TEXT,
                                 type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
    """)
    namespace = NamespaceId("bot", "persona")
    commitment = Commitment(
        "commitment:one", 2, "persona:persona", "entity:user", "reply",
        "unilateral", "private_intention", "pending", None,
        (), (), None, ("source:one",),
    )
    outcome = ActionOutcome(
        "outcome:one", "action:one", "effect:one", "attempt:one",
        "unknown", "unconfirmed", (), (), ("effect:one",), "settlement:one", 1,
    )
    atoms = (
        GraphAtom(
            AtomKey(Owner("relation", "bot", "persona", "entity:user"),
                    "d08.commitment.v1", commitment.commitment_id),
            2, json.loads(json.dumps(asdict(commitment))),
        ),
        GraphAtom(
            AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                    "d08.action_outcome.v1", outcome.outcome_id),
            1, json.loads(json.dumps(asdict(outcome))),
        ),
    )
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 5))
    for atom in atoms:
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            atom.key.token, "bot", "persona", atom.key.type_name,
            atom.revision, canonical_json(atom.value), 1,
        ))
    return db, namespace, GraphSnapshot(
        atoms, (NamespaceEpoch("bot", "persona", 5),),
    ), QueryEpoch(namespace, "all", 5)


def test_current_graph_facts_are_typed_but_execution_coverage_holds():
    db, namespace, snapshot, query = _case()
    try:
        with pytest.raises(ValueError, match="graph transaction"):
            read_current_d08_conflict_facts(db, namespace, snapshot, query)
        db.execute("BEGIN IMMEDIATE")
        facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
        assert facts.commitments[0].commitment_id == "commitment:one"
        assert facts.action_outcomes[0].outcome_id == "outcome:one"
        assert facts.query_epoch == QueryEpoch(namespace, "d08.conflict_graph", 5)
        assert {version.key for version in facts.graph_versions} == {
            atom.key for atom in snapshot.atoms
        }
        assert facts.status == "hold"
        assert facts.missing_sources == (
            "atomic_execution_effect_read", "current_action_cancellation_read",
        )
    finally:
        db.close()


def test_missing_or_changed_current_graph_row_rejects_d08_read():
    db, namespace, snapshot, query = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        partial = GraphSnapshot(snapshot.atoms[:1], snapshot.epochs)
        with pytest.raises(ValueError, match="omits"):
            read_current_d08_conflict_facts(db, namespace, partial, query)
        db.execute("UPDATE graph_atoms SET revision=3 WHERE token=?", (
            snapshot.atoms[0].key.token,
        ))
        with pytest.raises(ValueError, match="row changed"):
            read_current_d08_conflict_facts(db, namespace, snapshot, query)
    finally:
        db.close()
