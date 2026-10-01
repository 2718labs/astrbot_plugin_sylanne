"""A complete SQL frame cannot turn private evidence into group expression."""

import sqlite3

from sylanne3.contracts import canonical_json
from sylanne3.domains.d03.current_cross_scene_social import (
    read_current_cross_scene_social_v1,
)
from sylanne3.runtime_contracts import QueryEpoch

from rewrite.tests.alpha1.d03.test_cross_scene_social import (
    CONTRIBUTION, DESTINATION, GROUP, NS, SOURCE, graph,
)


def _db(path, snapshot):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,"
               "revision INTEGER,value TEXT,valid INTEGER,type_name TEXT)")
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*NS.as_tuple, 7))
    db.executemany("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        (atom.key.token, *NS.as_tuple, atom.revision,
         canonical_json(atom.value), int(atom.valid), atom.key.type_name)
        for atom in snapshot.atoms
    ))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return db


def _read(db, snapshot):
    return read_current_cross_scene_social_v1(
        db, snapshot, QueryEpoch(NS, "all", 7), SOURCE.token, namespace=NS,
        target_scene_ref=GROUP, audience_scope=DESTINATION,
        relationship_contribution_key=CONTRIBUTION.key, now_utc=2.0,
    )


def test_private_to_group_leak_remains_hold_inside_current_sql_transaction():
    snapshot = graph()
    db = _db(":memory:", snapshot)
    try:
        result = _read(db, snapshot)
        assert result.status == "hold"
        assert result.reasons == ("source_not_disclosable_to_group",)
        assert result.candidate.disclosure_status == "restricted"
        assert "d03.account_binding:complete_current_set" in result.negative_predicates
    finally:
        db.close()


def test_stale_role_or_account_row_rejected_even_with_old_positive_snapshot():
    snapshot = graph(source_audiences=("direct:sender", DESTINATION),
                     access_audiences=("direct:sender", DESTINATION))
    db = _db(":memory:", snapshot)
    try:
        assert _read(db, snapshot).reasons == ("current_group_membership_unavailable",)
        db.execute("UPDATE graph_atoms SET revision=revision+1 WHERE type_name='d03.role_binding' "
                   "AND token LIKE '%group%'")
        assert _read(db, snapshot).reasons == ("current_social_row_set_changed",)
        db.execute("UPDATE graph_atoms SET revision=revision+1 WHERE type_name='d03.account_binding'")
        assert _read(db, snapshot).reasons == ("current_social_row_set_changed",)
    finally:
        db.close()


def test_restart_rechecks_revoked_access_and_rejects_old_snapshot(tmp_path):
    snapshot = graph(source_audiences=("direct:sender", DESTINATION),
                     access_audiences=("direct:sender", DESTINATION))
    path = tmp_path / "social.sqlite"
    db = _db(path, snapshot)
    assert _read(db, snapshot).reasons == ("current_group_membership_unavailable",)
    db.commit()
    db.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE graph_atoms SET value=? WHERE type_name='memory.access'", (
        canonical_json({"source_id": "private-one", "audiences": ["direct:sender"],
                        "purposes": ["context", "expression"], "status": "revoked",
                        "recorded_at": 1.0}),
    ))
    db.commit()
    db.close()
    db = sqlite3.connect(path)
    db.execute("BEGIN IMMEDIATE")
    try:
        assert _read(db, snapshot).reasons == ("current_social_row_set_changed",)
    finally:
        db.close()
