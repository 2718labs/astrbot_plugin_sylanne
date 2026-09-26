"""Private D11 preflight sees the complete current D04 numeric topology."""

from dataclasses import asdict
import json

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04 import (
    AffectAxis, AffectProvider, AffectScheme, CommittedRef, MoodField,
    NumericCheckpoint, RootAssetBindings, RootBlockIdentity,
    build_numeric_coupling_write, encode_numeric_checkpoint,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d06 import D06DomainProvider, source_correction_head_key
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphVersion, Owner, TypeRegistry
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_snapshot_compiler import (
    AFFECT_SHA256, OPERATOR_SHA256, PARAMETER_BOUNDS,
)
from sylanne3.runtime.authoritative_coupling_snapshot import (
    CouplingSnapshotHold, FIXED_COUPLING_VERSION, FIXED_OPERATOR_VERSION,
    FIXED_PARAMETER_VERSION, read_unsigned_d04_coupling_snapshot_candidate,
)
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


def _insert(db, namespace, key, value, *, valid=True):
    db.execute(
        "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
        "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (key.token, *namespace.as_tuple, key.owner.kind, key.owner.subject,
         key.type_name, key.name, 1,
         canonical_json(json.loads(json.dumps(value))), int(valid)),
    )


def _add_checkpoint(db, namespace, scheme, assets, source, block_id):
    owner = Owner("persona", *namespace.as_tuple)
    mood_key = AtomKey(owner, "d04.mood_field.v1", block_id)
    checkpoint_key = AtomKey(owner, "d04.numeric_checkpoint.v1", block_id)
    mood = MoodField(block_id, scheme.scheme_version,
                     ((REGISTERED_AXIS_IDS[0], 0.2),), (source.token,),
                     scheme.parameter_version, scheme.coupling_version, 1.0)
    _insert(db, namespace, mood_key, asdict(mood))
    checkpoint = NumericCheckpoint(
        "checkpoint:" + block_id, namespace.as_tuple,
        RootBlockIdentity(block_id, "template-1", "mood", None, None,
                          source.owner.subject),
        assets, assets.digest, REGISTERED_AXIS_IDS, (2.0,) * 24,
        ((1.9, 2.1),) * 24, 0.11, "trusted_initial_box", "f" * 64,
        1.0, CommittedRef(mood_key.token, 1), "a" * 64,
        "adopt:" + block_id, "none", None,
    )
    _insert(db, namespace, checkpoint_key, encode_numeric_checkpoint(checkpoint))
    return checkpoint_key


def _fixture(tmp_path):
    namespace = NamespaceId("bot", "persona")
    registry = TypeRegistry()
    for spec in D06DomainProvider.type_specs() + AffectProvider().type_specs():
        registry.register(spec)
    store = GraphStore(tmp_path / "coupling.db", registry)
    scheme = AffectScheme(
        "d04.affect.scheme.v1", SCHEME_VERSION, FIXED_OPERATOR_VERSION,
        FIXED_PARAMETER_VERSION, FIXED_COUPLING_VERSION,
        tuple(AffectAxis(axis, "normalized", axis)
              for axis in REGISTERED_AXIS_IDS), PARAMETER_BOUNDS,
    )
    assets = RootAssetBindings(
        SCHEME_VERSION, scheme.operator_version, scheme.parameter_version,
        scheme.coupling_version, "readout-1", AFFECT_SHA256,
        OPERATOR_SHA256, "c" * 64, "d" * 64, "e" * 64,
    )
    source = source_key(*namespace.as_tuple, "source-1")
    db = store._db
    _insert(db, namespace, source, SourceRecord(
        "source-1", "private source literal", "owner", "authored",
        "reported", 0.0, 0.0, "family-1", ("owner",), ("context",),
    ).to_dict())
    _insert(db, namespace, access_key(*namespace.as_tuple, "source-1"), {
        "source_id": "source-1", "audiences": ["owner"],
        "purposes": ["context"], "status": "active", "recorded_at": 0.0,
    })
    root = _add_checkpoint(db, namespace, scheme, assets, source, "block-root")
    db.execute("INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,1)",
               namespace.as_tuple)
    db.execute("INSERT INTO graph_authority_epochs(bot,persona,access_epoch,"
               "delete_epoch) VALUES(?,?,0,0)", namespace.as_tuple)
    db.execute("INSERT INTO graph_recovery_metadata_v2(bot,persona,schema,"
               "requirements_json,graph_revision) VALUES(?,?,?,?,1)",
               namespace.as_tuple + ("sylanne3.authority.v2",
                                     canonical_json({"graph_incarnation": "graph:one"}),))
    for kind, version in (("scheme", scheme.scheme_version),
                          ("operator", scheme.operator_version)):
        db.execute("INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                   "VALUES(?,?,?,'current',?)", namespace.as_tuple + (kind, version))
    return store, namespace, scheme, assets, source, root


def _read(store, namespace, scheme, assets, root, *, max_numeric_rows=512,
          query_revision=1):
    db = store._db
    db.execute("BEGIN IMMEDIATE")
    try:
        return read_unsigned_d04_coupling_snapshot_candidate(
            db, namespace=namespace, registry=store._registry,
            scheme=scheme, checkpoint_ref=root.token,
            expected_query_epoch=QueryEpoch(namespace, "all", query_revision),
            expected_graph_incarnation="graph:one", expected_graph_revision=1,
            expected_access_epoch=0, expected_delete_epoch=0,
            expected_asset_digest=assets.digest, audience=("owner",),
            purpose="context", max_numeric_rows=max_numeric_rows,
        )
    finally:
        db.execute("ROLLBACK")


def test_unsigned_root_binds_24_axes_source_and_absent_correction_head(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        candidate = _read(store, namespace, scheme, assets, root)
        assert candidate.status == "unsigned_candidate_hold"
        assert candidate.axis_ids == REGISTERED_AXIS_IDS
        assert candidate.checkpoint_ref == root.token
        assert candidate.checkpoint_revision == 1
        assert candidate.fixed_template_asset_digest == assets.digest
        assert candidate.graph_incarnation == "graph:one"
        assert candidate.numeric_coupling_versions == ()
        assert GraphVersion(source_correction_head_key(namespace, "source-1"), 0) \
            in candidate.read_versions
        assert "private source literal" not in repr(candidate)
        original = json.loads(store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (root.token,),
        ).fetchone()[0])
        store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                          (canonical_json({**original,
                                           "readout_proof_digest": "b" * 64}),
                           root.token))
        changed = _read(store, namespace, scheme, assets, root)
        assert changed.checkpoint_revision == candidate.checkpoint_revision
        assert changed.checkpoint_value_digest != candidate.checkpoint_value_digest
        assert changed.snapshot_digest != candidate.snapshot_digest
        head = source_correction_head_key(namespace, "source-1")
        correction = source_key(*namespace.as_tuple, "correction-1")
        target = AtomKey(Owner("event", *namespace.as_tuple, "meaning-1"),
                         "memory.interpretation", "current")
        _insert(store._db, namespace, head, {
            "source_ref": source.token, "source_revision": 1,
            "correction_source_ref": correction.token,
            "target_refs": [target.token], "operation_id": "correction-1",
            "state": "pending_reevaluation", "access_epoch": 0,
            "deletion_epoch": 0,
        })
        with pytest.raises(CouplingSnapshotHold, match="lost current access"):
            _read(store, namespace, scheme, assets, root)
        assert not store._db.in_transaction
    finally:
        store.close()


def test_root_edge_holds_but_unrelated_current_edge_is_enumerated(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        other = _add_checkpoint(store._db, namespace, scheme, assets, source, "block-other")
        third = _add_checkpoint(store._db, namespace, scheme, assets, source, "block-third")
        unrelated = build_numeric_coupling_write(
            scheme=scheme, edge_version=1, left_ref=other.token,
            left_axis=REGISTERED_AXIS_IDS[0], right_ref=third.token,
            right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
            source_ref=source.token, effective_from=0.0, effective_until=10.0,
        )
        _insert(store._db, namespace, unrelated.key, unrelated.value)
        candidate = _read(store, namespace, scheme, assets, root)
        assert candidate.numeric_coupling_versions == (GraphVersion(unrelated.key, 1),)
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                          (third.token,))
        with pytest.raises(CouplingSnapshotHold, match="endpoint closure"):
            _read(store, namespace, scheme, assets, root)
        store._db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?",
                          (third.token,))
        store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                          (canonical_json({**unrelated.value,
                                           "factor_kind": "unknown_factor"}),
                           unrelated.key.token))
        with pytest.raises(CouplingSnapshotHold, match="unknown numeric coupling"):
            _read(store, namespace, scheme, assets, root)
        store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                          (canonical_json(unrelated.value), unrelated.key.token))
        involving_root = build_numeric_coupling_write(
            scheme=scheme, edge_version=1, left_ref=root.token,
            left_axis=REGISTERED_AXIS_IDS[0], right_ref=other.token,
            right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
            source_ref=source.token, effective_from=20.0, effective_until=30.0,
        )
        _insert(store._db, namespace, involving_root.key, involving_root.value)
        with pytest.raises(CouplingSnapshotHold, match="joint solve"):
            _read(store, namespace, scheme, assets, root)
    finally:
        store.close()


def test_stale_epoch_scan_bound_and_revoked_source_hold(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        with pytest.raises(CouplingSnapshotHold, match="epoch"):
            _read(store, namespace, scheme, assets, root, query_revision=0)
        _add_checkpoint(store._db, namespace, scheme, assets, source, "block-other")
        with pytest.raises(CouplingSnapshotHold, match="complete page"):
            _read(store, namespace, scheme, assets, root, max_numeric_rows=1)
        access = access_key(*namespace.as_tuple, "source-1")
        value = json.loads(store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (access.token,),
        ).fetchone()[0])
        store._db.execute("UPDATE graph_atoms SET value=?,revision=2 WHERE token=?",
                          (canonical_json({**value, "status": "withdrawn"}),
                           access.token))
        with pytest.raises(CouplingSnapshotHold, match="unavailable"):
            _read(store, namespace, scheme, assets, root)
    finally:
        store.close()
