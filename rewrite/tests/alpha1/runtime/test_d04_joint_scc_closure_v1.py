"""The joint inventory must expose topology while refusing an unsigned solve."""

from dataclasses import asdict
import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.numeric_coupling import (
    NumericCoupling, REGISTERED_AXIS_IDS, SCHEME_VERSION, TEMPLATE, FACTOR_KIND,
    coupling_id,
)
from sylanne3.domains.d04.root import (
    NumericCheckpoint, RootAssetBindings, RootBlockIdentity,
    encode_numeric_checkpoint,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.d04_joint_scc_closure_v1 import (
    D04JointSccClosureHold, read_d04_joint_scc_inventory_in_transaction,
)


def _db():
    db = sqlite3.connect(":memory:")
    db.executescript("""
      CREATE TABLE graph_atoms(token TEXT PRIMARY KEY, bot TEXT, persona TEXT,
        type_name TEXT, revision INTEGER, value TEXT, valid INTEGER);
      CREATE TABLE graph_epochs(bot TEXT, persona TEXT, revision INTEGER);
      CREATE TABLE graph_authority_epochs(bot TEXT, persona TEXT,
        access_epoch INTEGER, delete_epoch INTEGER);
      CREATE TABLE graph_recovery_metadata_v2(bot TEXT, persona TEXT,
        requirements_json TEXT, graph_revision INTEGER);
      CREATE TABLE graph_type_catalog(name TEXT, schema_version INTEGER);
    """)
    db.execute("INSERT INTO graph_epochs VALUES('bot','persona',7)")
    db.execute("INSERT INTO graph_authority_epochs VALUES('bot','persona',2,3)")
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?)",
               ("bot", "persona", canonical_json({"graph_incarnation": "inc"}), 5))
    db.executemany("INSERT INTO graph_type_catalog VALUES(?,1)", (
        (name,) for name in ("d04.numeric_checkpoint.v1",
                             "d04.numeric_coupling.v1",
                             "d04.sourced_numeric_drive.v1")))
    db.commit()
    db.execute("BEGIN")
    return db


def _checkpoint(db, name):
    owner = Owner("persona", "bot", "persona")
    key = AtomKey(owner, "d04.numeric_checkpoint.v1", name)
    state = AtomKey(owner, "d04.feeling_state.v1", name)
    assets = RootAssetBindings(
        SCHEME_VERSION, "operator", "parameter", "coupling", "readout",
        *("0" * 64 for _ in range(5)),
    )
    # The graph row is structurally real; the store and issuer still need to
    # authenticate its claimed certificate and paired state before any solve.
    from sylanne3.domains.d04.encoding_baseline import CommittedRef
    checkpoint = NumericCheckpoint(
        name, ("bot", "persona"), RootBlockIdentity(name, "template", "feeling",
                                                   "object", "meaning", "source"),
        assets, assets.digest, REGISTERED_AXIS_IDS, (0.0,) * 24,
        ((0.0, 0.0),) * 24, 0.0, "trusted_initial_box", "0" * 64,
        0.0, CommittedRef(state.token, 1), "0" * 64, "operation", "none", None,
    )
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,1)",
               (key.token, "bot", "persona", key.type_name, 1,
                canonical_json(encode_numeric_checkpoint(checkpoint))))
    return key


def _edge(db, left, right, name):
    axis = REGISTERED_AXIS_IDS[0]
    endpoints = sorted(((left.token, axis), (right.token, axis)))
    edge = NumericCoupling(coupling_id(*endpoints[0], *endpoints[1]), 1,
                           SCHEME_VERSION, *endpoints[0], *endpoints[1],
                           TEMPLATE, FACTOR_KIND, 0.1,
                           AtomKey(Owner("event", "bot", "persona", name),
                                   "memory.source", "record").token, 0.0, 1.0)
    key = AtomKey(left.owner, "d04.numeric_coupling.v1", edge.edge_id)
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,1)",
               (key.token, "bot", "persona", key.type_name, 1,
                canonical_json(asdict(edge))))
    return key


def _read(db, root):
    return read_d04_joint_scc_inventory_in_transaction(
        db, namespace=NamespaceId("bot", "persona"), checkpoint_ref=root.token,
        expected_graph_epoch=7, expected_graph_revision=5,
        expected_graph_incarnation="inc", expected_access_epoch=2,
        expected_delete_epoch=3,
    )


def test_component_contains_transitive_member_and_all_internal_edges():
    db = _db()
    a, b, c, isolated = (_checkpoint(db, x) for x in "abci")
    ab = _edge(db, a, b, "source-ab")
    bc = _edge(db, b, c, "source-bc")
    inventory = _read(db, a)
    assert tuple(row.ref for row in inventory.members) == tuple(sorted((a.token, b.token, c.token)))
    assert tuple(row.ref for row in inventory.edges) == tuple(sorted((ab.token, bc.token)))
    assert GraphVersion(isolated, 1) not in inventory.read_versions
    assert inventory.status == "hold"
    assert "joint_numeric_compiler_and_adoption_missing" in inventory.hold_reasons
    assert inventory.query_epoch == 7
    assert inventory.schema_versions == tuple((name, 1) for name in sorted((
        "d04.numeric_checkpoint.v1", "d04.numeric_coupling.v1",
        "d04.sourced_numeric_drive.v1")))
    assert inventory.access_epoch == 2 and inventory.delete_epoch == 3


def test_changed_epoch_and_truncated_scan_fail_closed():
    db = _db()
    a, b = (_checkpoint(db, x) for x in "ab")
    _edge(db, a, b, "source-ab")
    with pytest.raises(D04JointSccClosureHold, match="epoch"):
        read_d04_joint_scc_inventory_in_transaction(
            db, namespace=NamespaceId("bot", "persona"), checkpoint_ref=a.token,
            expected_graph_epoch=6, expected_graph_revision=5,
            expected_graph_incarnation="inc", expected_access_epoch=2,
            expected_delete_epoch=3,
        )
    with pytest.raises(D04JointSccClosureHold, match="bound"):
        read_d04_joint_scc_inventory_in_transaction(
            db, namespace=NamespaceId("bot", "persona"), checkpoint_ref=a.token,
            expected_graph_epoch=7, expected_graph_revision=5,
            expected_graph_incarnation="inc", expected_access_epoch=2,
            expected_delete_epoch=3, max_numeric_rows=2,
        )


def test_correction_head_is_observed_and_forces_hold():
    db = _db()
    a = _checkpoint(db, "a")
    head = source_correction_head_key(NamespaceId("bot", "persona"), "source")
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,1)",
               (head.token, "bot", "persona", head.type_name, 1,
                canonical_json({"status": "corrected"})))
    inventory = _read(db, a)
    assert head.token in tuple(row.ref for row in inventory.corrections)
    assert "source_correction_head_present" in inventory.hold_reasons
    assert "member_graph_state_missing" in inventory.hold_reasons
    assert inventory.status == "hold"
