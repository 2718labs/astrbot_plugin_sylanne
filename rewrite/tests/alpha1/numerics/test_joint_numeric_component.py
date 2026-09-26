"""The joint graph candidate retains every active edge and drive."""

import pytest

from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, build_numeric_coupling_write
from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
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


def _read(store, namespace, scheme, root):
    store._db.execute("BEGIN IMMEDIATE")
    try:
        return read_joint_numeric_component(
            store._db, namespace=namespace, registry=store._registry,
            scheme=scheme, root_ref=root.token, role_start=1.0, role_end=2.0,
            expected_query_epoch=QueryEpoch(namespace, "all", 1),
            expected_graph_incarnation="graph:one", expected_graph_revision=1,
            expected_access_epoch=0, expected_delete_epoch=0,
            audience=("owner",), purpose="context",
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
