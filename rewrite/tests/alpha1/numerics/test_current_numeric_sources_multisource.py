"""Fenced multi-source D04 drive inventory stays an unsigned candidate."""

from dataclasses import replace
from fractions import Fraction

import pytest

from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.authoritative_coupling_snapshot import CouplingSnapshotHold
from sylanne3.runtime.current_numeric_sources import read_current_d04_numeric_sources_v2

from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import (
    _fixture, _insert, _read,
)
from rewrite.tests.alpha1.runtime.test_current_numeric_sources import _drive


def _second(store, namespace, root, *, provenance_root="family-2", interval=(1.0, 2.0)):
    source = source_key(*namespace.as_tuple, "source-2")
    _insert(store._db, namespace, source, SourceRecord(
        "source-2", "second source literal", "owner", "authored",
        "reported", 0.0, 0.0, provenance_root, ("owner",), ("context",),
    ).to_dict())
    _insert(store._db, namespace, access_key(*namespace.as_tuple, "source-2"), {
        "source_id": "source-2", "audiences": ["owner"],
        "purposes": ["context"], "status": "active", "recorded_at": 0.0,
    })
    drive = _drive(root, source)
    if interval != (1.0, 2.0):
        from sylanne3.domains.d04.numeric_drive import numeric_drive_id
        drive = replace(drive, drive_id=numeric_drive_id(root.token, source.token, *interval),
                        role_start=interval[0], role_end=interval[1])
    write = sourced_numeric_drive_write(drive)
    _insert(store._db, namespace, write.key, write.value)
    return source, write


def _read_v2(store, candidate, scheme, refs):
    store._db.execute("BEGIN IMMEDIATE")
    try:
        return read_current_d04_numeric_sources_v2(
            store._db, candidate=candidate, registry=store._registry,
            scheme=scheme, drive_refs=refs, audience=("owner",), purpose="context",
        )
    finally:
        store._db.execute("ROLLBACK")


def test_two_root_sources_are_summed_and_all_versions_are_pinned(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        first = sourced_numeric_drive_write(_drive(root, source))
        _insert(store._db, namespace, first.key, first.value)
        second_source, second = _second(store, namespace, root)
        candidate = _read(store, namespace, scheme, assets, root)
        result = _read_v2(store, candidate, scheme, (first.key.token, second.key.token))
        assert result.drive == (float(Fraction(1, 10) * 0 +
                                      Fraction.from_float(0.1) * 2),) * 24
        assert result.drive_versions == tuple(sorted(
            (GraphVersion(first.key, 1), GraphVersion(second.key, 1)),
            key=lambda item: item.key.token))
        assert GraphVersion(second_source, 1) in result.read_versions
        assert GraphVersion(access_key(*namespace.as_tuple, "source-2"), 1) in result.read_versions
        assert result.query_epoch == candidate.query_epoch
        assert result.status == "hold"
        assert "semantic_drive_mapping_issuer_verification" in result.missing_sources
    finally:
        store.close()


@pytest.mark.parametrize("case", ("omitted", "duplicate", "overlap"))
def test_incomplete_or_ambiguous_multisource_inventory_holds(tmp_path, case):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        first = sourced_numeric_drive_write(_drive(root, source))
        _insert(store._db, namespace, first.key, first.value)
        _, second = _second(store, namespace, root,
                            provenance_root="family-1" if case == "duplicate" else "family-2",
                            interval=(1.5, 2.5) if case == "overlap" else (1.0, 2.0))
        candidate = _read(store, namespace, scheme, assets, root)
        refs = (first.key.token,) if case == "omitted" else (first.key.token, second.key.token)
        with pytest.raises(CouplingSnapshotHold):
            _read_v2(store, candidate, scheme, refs)
    finally:
        store.close()
