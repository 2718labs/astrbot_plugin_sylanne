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


@pytest.mark.parametrize("mode", ("metadata", "undeclared_metadata", "invalid_tail"))
def test_initial_locator_codec_preserves_whole_eof_without_other_receipt_body(mode):
    """Actual SQL/stream codec only: this issues no Source/Owner/dispatch proof."""
    from hashlib import sha256
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.runtime.c09_paged_sql_v2 import C09BatchBudgetV2, C09SqlByteMeterV2
    from sylanne3.runtime.natural_dispatch_initial_read_v1 import _NaturalInitialReadV1
    from sylanne3.runtime.natural_dispatch_locator_metadata_v1 import NaturalDispatchLocatorMetadataColumnV1
    from sylanne3.runtime_storage_v3 import (
        RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED,
    )

    metadata = {"schema": "sylanne.natural_dispatch_read_locator.v1", "profile_version": 1,
        "metadata": {}, "metadata_byte_count": 2, "metadata_sha256": sha256(b"{}").hexdigest()}
    if mode == "undeclared_metadata":
        metadata["metadata"]["body"] = "not a declared metadata field"
    raw = json.dumps({"a_other_original": {"body": "UNSELECTED" * 8192},
        "natural_dispatch_read_locator": metadata, "z_other_original": ["also excluded"]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if mode == "invalid_tail":
        raw = raw[:-1] + b",}"
    pool = _RuntimeResourcePoolV3()
    baseline = pool.used
    operation = RuntimeStorageOperationV3(_INSTALLED,
        SimpleNamespace(pool=pool, selection_digest="initial-metadata-codec"),
        "initial-metadata-codec", 100.0)
    db = sqlite3.connect(":memory:")
    owner = object.__new__(_NaturalInitialReadV1)
    owner.db, owner.operation, owner.namespace = db, operation, NamespaceId("bot", "persona")
    owner.selected_operation_id = "committed:codec-only"
    try:
        db.execute("CREATE TABLE graph_bundle_operations(bot TEXT,persona TEXT,operation_id TEXT,receipt_json TEXT)")
        db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?)",
            ("bot", "persona", owner.selected_operation_id, raw.decode("ascii")))
        db.commit()
        column = NaturalDispatchLocatorMetadataColumnV1(owner, owner.selected_operation_id)
        def read_to_eof():
            for _ in range(1024):
                meter = C09SqlByteMeterV2(C09BatchBudgetV2(100, 262144, 25000000, 250000000, 8388608))
                if column.advance(meter):
                    return
            pytest.fail("finite complete original was not consumed")
        if mode == "metadata":
            read_to_eof()
            assert column.complete and column.raw == metadata
            assert (column.sha256, column.byte_count) == (sha256(raw).hexdigest(), len(raw))
            assert column.value is None and column.nodes == {} and column.fragment == b""
        elif mode == "undeclared_metadata":
            with pytest.raises(AuthorityUnavailable, match="undeclared metadata field"):
                read_to_eof()
            assert not column.complete
        else:
            with pytest.raises(ValueError):
                read_to_eof()
            assert not column.complete
    finally:
        db.close()
        operation.release()
    assert pool.used == baseline


def test_natural_p2_closed_projection_preserves_unprepared_head_and_family_boundaries():
    """Coverage view codec only: no READ/Source/Owner/P2 authority is issued."""
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.graph_types import GraphAtom, NamespaceEpoch
    from sylanne3.domains.d03 import AccountBinding
    from sylanne3.runtime.natural_dispatch_p2_read_v1 import NaturalP2ClosedProjectionV1
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED
    namespace = NamespaceId("bot", "persona")
    owner = Owner("persona", *namespace.as_tuple)
    account_key = AtomKey(owner, "d03.account_binding", "account:current")
    hidden = AtomKey(Owner("event", *namespace.as_tuple, "world:hidden"), "d03.world_event", "current")
    erased = AtomKey(owner, "d03.account_binding", "account:erased")
    missing = AtomKey(owner, "d03.account_binding", "account:missing")
    binding = AccountBinding("account:current", "platform", "sender", "entity:sender", hidden.token, 0.0, None)
    value = asdict(binding)
    heads = {account_key.token: (account_key.token, 1, 1, account_key.type_name, "cell:account"),
        hidden.token: (hidden.token, 3, 1, hidden.type_name, "cell:hidden"),
        erased.token: (erased.token, 4, 0, erased.type_name, "cell:erased")}
    pool = _RuntimeResourcePoolV3()
    baseline = pool.used
    operation = RuntimeStorageOperationV3(_INSTALLED,
        SimpleNamespace(pool=pool, selection_digest="natural-coverage-view"), "natural-coverage-view", 100.0)
    reader = SimpleNamespace(operation=operation, controls={account_key.token: GraphAtom(account_key, 1, value, True)},
        access={}, body_atoms={}, graph_stamp=(None, NamespaceEpoch(*namespace.as_tuple, 1)),
        census=SimpleNamespace(heads=heads, head_count=3, head_root="1" * 64))
    try:
        projection = NaturalP2ClosedProjectionV1(reader)
        assert projection.get(account_key).value == value
        assert projection.get(missing) is None
        with pytest.raises(AuthorityUnavailable, match="head exists but its Body was not prepared"):
            projection.get(hidden)
        invalid = projection.get(erased)
        assert invalid.revision == 4 and not invalid.valid and invalid.value == {}
        assert len(projection.atoms_for_types_v3(frozenset({"d03.account_binding"}))) == 1
        with pytest.raises(AuthorityUnavailable, match="no full Body census"):
            projection.atoms_for_types_v3(frozenset({"d03.world_event"}))
        with pytest.raises(AuthorityUnavailable, match="does not claim every namespace Body"):
            _ = projection.atoms
    finally:
        operation.release()
    assert pool.used == baseline
