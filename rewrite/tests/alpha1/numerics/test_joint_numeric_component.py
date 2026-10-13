"""The joint graph candidate retains every active edge and drive."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04 import (
    CommittedRef, FeelingState, RootBlockIdentity, decode_numeric_checkpoint,
    encode_numeric_checkpoint,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, build_numeric_coupling_write
from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.joint_numeric_component import JointNumericHold, read_joint_numeric_component
from sylanne3.runtime_contracts import QueryEpoch

from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import (
    _add_checkpoint, _fixture, _insert,
)
from rewrite.tests.alpha1.runtime.test_current_numeric_sources import _drive


def _component(tmp_path, *, edge_interval=(1.0, 2.0), include_second_drive=True):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    other = _add_checkpoint(store._db, namespace, scheme, assets, source, "block-other")
    edge = build_numeric_coupling_write(
        scheme=scheme, edge_version=1, left_ref=root.token,
        left_axis=REGISTERED_AXIS_IDS[0], right_ref=other.token,
        right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
        source_ref=source.token, effective_from=edge_interval[0],
        effective_until=edge_interval[1],
    )
    _insert(store._db, namespace, edge.key, edge.value)
    for checkpoint in (root, other) if include_second_drive else (root,):
        drive = sourced_numeric_drive_write(_drive(checkpoint, source))
        _insert(store._db, namespace, drive.key, drive.value)
    return store, namespace, scheme, root, other, edge


def _read(store, namespace, scheme, root, *, life_source_bridge=None):
    store._db.execute("BEGIN IMMEDIATE")
    try:
        return read_joint_numeric_component(
            store._db, namespace=namespace, registry=store._registry,
            scheme=scheme, root_ref=root.token, role_start=1.0, role_end=2.0,
            expected_query_epoch=QueryEpoch(namespace, "all", 1),
            expected_graph_incarnation="graph:one", expected_graph_revision=1,
            expected_access_epoch=0, expected_delete_epoch=0,
            audience=("owner",), purpose="context",
            _life_source_bridge=life_source_bridge,
        )
    finally:
        store._db.execute("ROLLBACK")


def test_complete_two_block_component_is_unsigned_hold(tmp_path):
    store, namespace, scheme, root, other, edge = _component(tmp_path)
    try:
        result = _read(store, namespace, scheme, root)
        assert result.checkpoint_refs == tuple(sorted((root.token, other.token)))
        assert result.edges[0].edge_id == edge.value["edge_id"]
        assert len(result.block_drives) == 2
        assert result.query_epoch.revision == 1
        assert result.status == "hold"
        assert "joint_operator_asset_and_abi2_binding" in result.missing_sources
    finally:
        store.close()


def test_transitive_edge_expands_component_and_requires_third_drive(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        middle = _add_checkpoint(store._db, namespace, scheme, assets, source, "middle")
        third = _add_checkpoint(store._db, namespace, scheme, assets, source, "third")
        for left, right in ((root, middle), (middle, third)):
            edge = build_numeric_coupling_write(
                scheme=scheme, edge_version=1, left_ref=left.token,
                left_axis=REGISTERED_AXIS_IDS[0], right_ref=right.token,
                right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
                source_ref=source.token, effective_from=1.0, effective_until=2.0,
            )
            _insert(store._db, namespace, edge.key, edge.value)
        for checkpoint in (root, middle):
            drive = sourced_numeric_drive_write(_drive(checkpoint, source))
            _insert(store._db, namespace, drive.key, drive.value)
        with pytest.raises(JointNumericHold, match="no complete interval drive"):
            _read(store, namespace, scheme, root)
        third_drive = sourced_numeric_drive_write(_drive(third, source))
        _insert(store._db, namespace, third_drive.key, third_drive.value)
        result = _read(store, namespace, scheme, root)
        assert result.checkpoint_refs == tuple(sorted((root.token, middle.token, third.token)))
        assert len(result.edges) == 2
    finally:
        store.close()


@pytest.mark.parametrize("case", ("missing_drive", "partial_edge", "stale_epoch"))
def test_incomplete_component_never_drops_an_edge_or_block(tmp_path, case):
    store, namespace, scheme, root, _other, edge = _component(
        tmp_path, include_second_drive=case != "missing_drive",
        edge_interval=(1.5, 2.5) if case == "partial_edge" else (1.0, 2.0),
    )
    try:
        if case == "stale_epoch":
            store._db.execute("UPDATE graph_epochs SET revision=2")
        with pytest.raises(JointNumericHold):
            _read(store, namespace, scheme, root)
    finally:
        store.close()


def test_new_feeling_joint_freezes_current_interpretation_and_source_closure(tmp_path):
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        source = source_key(*namespace.as_tuple, "source-1")
        for spec in D07DomainProvider.type_specs():
            store._registry.register(spec)
        drive = sourced_numeric_drive_write(_drive(root, source))
        interpretation_key = AtomKey(
            Owner("activity", *namespace.as_tuple, "activity-1"),
            "d07.current_interpretation.v1", "interpretation-1",
        )
        feeling_key = AtomKey(
            Owner("persona", *namespace.as_tuple), "d04.feeling_state.v1", root.name,
        )
        feeling = FeelingState(
            root.name, source.token, scheme.scheme_version, scheme.operator_version,
            ((REGISTERED_AXIS_IDS[0], 0.2),), ("facet-1",),
            (interpretation_key.token,), (drive.key.token,), (source.token,),
            scheme.parameter_version, scheme.coupling_version, 1.0,
        )
        _insert(store._db, namespace, feeling_key, asdict(feeling))
        encoded = store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (root.token,),
        ).fetchone()[0]
        checkpoint = decode_numeric_checkpoint(json.loads(encoded))
        checkpoint = replace(
            checkpoint,
            block=RootBlockIdentity(root.name, "template-1", "feeling",
                                    source.token, "facet-1", source.owner.subject),
            graph_state=CommittedRef(feeling_key.token, 1),
        )
        store._db.execute(
            "UPDATE graph_atoms SET value=? WHERE token=?",
            (canonical_json(encode_numeric_checkpoint(checkpoint)), root.token),
        )
        with pytest.raises(JointNumericHold, match="interpretation original is unavailable"):
            _read(store, namespace, scheme, root)
        _insert(store._db, namespace, interpretation_key, {
            "schema": "d07.current_interpretation.v1",
            "interpretation_id": "interpretation-1", "activity_id": "activity-1",
            "question_key": "question:memory", "proposition": "source remains relevant",
            "stance": "support", "subjective_conviction": 0.7,
            "evidence_status": "insufficient", "source_refs": [source.token],
            "source_families": ["family-1"], "meaningful_unknowns": [],
            "current": True,
        })
        result = _read(store, namespace, scheme, root)
        assert GraphVersion(interpretation_key, 1) in result.read_versions
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?", (interpretation_key.token,),
        )
        with pytest.raises(JointNumericHold, match="interpretation original is unavailable"):
            _read(store, namespace, scheme, root)
    finally:
        store.close()


def test_ordinary_derived_source_cannot_use_life_joint_bridge(tmp_path):
    from sylanne3.memory_types import SourceRecord, access_key
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        assert len(_read(store, namespace, scheme, root).block_drives) == 2
        source = source_key(*namespace.as_tuple, "source-1")
        original = SourceRecord.from_dict(json.loads(store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (source.token,),
        ).fetchone()[0]))
        parent = replace(original, source_id="source-parent", provenance_root="family-parent")
        _insert(store._db, namespace, source_key(*namespace.as_tuple, parent.source_id), parent.to_dict())
        _insert(store._db, namespace, access_key(*namespace.as_tuple, parent.source_id), {
            "source_id": parent.source_id, "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 0.0,
        })
        derived = replace(original, source_kind="internal", parent_source_ids=(parent.source_id,))
        store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
            (canonical_json(derived.to_dict()), source.token))
        changes = store._db.total_changes
        with pytest.raises(JointNumericHold, match="requires an independent root source"):
            _read(store, namespace, scheme, root)
        assert store._db.total_changes == changes
    finally:
        store.close()


def test_constructed_life_bridge_has_no_private_issuance(tmp_path):
    from sylanne3.runtime.d06_life_numeric_joint_v1 import _LifeJointSourceBridgeV1
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        assert len(_read(store, namespace, scheme, root).block_drives) == 2
        unissued = _LifeJointSourceBridgeV1(object(), object(), None, None)
        changes = store._db.total_changes
        with pytest.raises(ValueError, match="requires its live private issuance"):
            _read(store, namespace, scheme, root, life_source_bridge=unissued)
        assert store._db.total_changes == changes
    finally:
        store.close()
