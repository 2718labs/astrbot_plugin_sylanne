"""Natural dispatch admission reads the current V2 graph original."""

import json
import sqlite3
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from sylanne3.domains.d03 import RoleBinding
from sylanne3.graph_types import AtomKey, GraphAtom, Owner
from sylanne3.runtime.dispatch_current_projection import CurrentDispatchProjectionV1
from sylanne3.runtime.natural_dispatch_admission_v2 import (
    NaturalDispatchAdmissionHold, _atom, _current_natural_role_binding,
    issue_natural_dispatch_admission_v2,
    natural_dispatch_segment_payload_ref_v2,
)
from sylanne3.runtime_contracts import NamespaceId


def test_natural_admission_requires_held_graph_write_transaction():
    db = sqlite3.connect(":memory:")
    try:
        with pytest.raises(NaturalDispatchAdmissionHold,
                           match="graph write transaction required"):
            issue_natural_dispatch_admission_v2(
                db=db, bundle=None, evidence=None, final=None, runtime=None,
                checks=(), graph_receipt=None, scope=None,
                clock_reading=None, clock_policy=None, owner_guard=None,
                current_effect=None, effect_snapshot=None, route=None,
                snapshot=None, query=None, projection=None, now_utc=1.0)
    finally:
        db.close()


def test_current_natural_batch_reader_rejects_v1_and_revoked_rows():
    db = sqlite3.connect(":memory:")
    namespace = NamespaceId("bot", "persona")
    owner = Owner("activity", "bot", "persona", "activity:one")
    v1 = AtomKey(owner, "d09.verified_segment_batch.v1", "batch:one")
    v2 = AtomKey(owner, "d09.natural_verified_segment_batch.v2", "batch:two")
    try:
        db.execute("CREATE TABLE graph_atoms(token TEXT, bot TEXT, persona TEXT, "
                   "revision INTEGER, value TEXT, valid INTEGER)")
        db.execute("BEGIN IMMEDIATE")
        for key in (v1, v2):
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                       (key.token, "bot", "persona", 1,
                        json.dumps({"source": key.type_name}), 1))
        with pytest.raises(NaturalDispatchAdmissionHold,
                           match="scope differs"):
            _atom(db, namespace, v1.token, v2.type_name)
        with pytest.raises(ValueError, match="natural V2 batch"):
            natural_dispatch_segment_payload_ref_v2(v1.token, 0)
        assert _atom(db, namespace, v2.token, v2.type_name) == {
            "source": v2.type_name}
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (v2.token,))
        with pytest.raises(NaturalDispatchAdmissionHold,
                           match="original absent"):
            _atom(db, namespace, v2.token, v2.type_name)
    finally:
        db.rollback()
        db.close()


def test_current_scene_role_uses_d03_wildcard_and_rejects_ambiguous_selection():
    db = sqlite3.connect(":memory:")
    namespace = NamespaceId("bot", "persona")
    role = RoleBinding(
        "binding:private", "persona:persona", "friend", None, None,
        "scene:private", "private", "private", (), 0.0, None, 1,
        ("source:scene",), 1, "active",
    )
    key = AtomKey(Owner("scene", "bot", "persona", "scene:private"),
                  "d03.role_binding", role.role_binding_id)
    atom = GraphAtom(key, 1, json.loads(json.dumps(asdict(role))))
    action = SimpleNamespace(target_ref="entity:account", action_kind="reply",
                             purpose="expression")
    route = SimpleNamespace(scene_ref="scene:private")
    projection = CurrentDispatchProjectionV1(namespace, 1, (atom,), (), "digest")
    try:
        db.execute("CREATE TABLE graph_atoms(token TEXT, bot TEXT, persona TEXT, "
                   "revision INTEGER, value TEXT, valid INTEGER)")
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                   (key.token, "bot", "persona", 1, json.dumps(atom.value), 1))
        assert _current_natural_role_binding(
            db, projection, namespace, action, route, key.token, 1, 1.0,
        ) == role
        with pytest.raises(NaturalDispatchAdmissionHold, match="ambiguous"):
            _current_natural_role_binding(
                db, projection, namespace, action, route, key.token, 2, 1.0,
            )

        other = replace(role, role_binding_id="binding:second")
        other_key = AtomKey(key.owner, key.type_name, other.role_binding_id)
        other_atom = GraphAtom(other_key, 1, json.loads(json.dumps(asdict(other))))
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                   (other_key.token, "bot", "persona", 1,
                    json.dumps(other_atom.value), 1))
        duplicate = replace(projection, role_bindings=(atom, other_atom))
        with pytest.raises(NaturalDispatchAdmissionHold, match="ambiguous"):
            _current_natural_role_binding(
                db, duplicate, namespace, action, route, key.token, 1, 1.0,
            )
    finally:
        db.rollback()
        db.close()
