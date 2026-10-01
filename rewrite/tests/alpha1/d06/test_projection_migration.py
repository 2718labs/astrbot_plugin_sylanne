"""A D06 sidecar seal cannot authorize a copied target projection."""

import shutil
import sqlite3

import pytest

from sylanne3.domains.d06.projection_index import (
    DurableSourceProjectionIndex, SourceIndexEpochPage, SourceIndexMutation,
)
from sylanne3.domains.d06.projection_migration import (
    inspect_target_projection_rebuild_v1, seal_projection_namespace_v1,
)
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


def test_namespace_seal_requires_rebuild_and_rejects_copied_or_incomplete_state(tmp_path):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "one").token
    origin = tmp_path / "source-sidecar.db"
    target = tmp_path / "target-sidecar.db"
    index = DurableSourceProjectionIndex(origin)
    try:
        index.begin_generation(namespace, "source-generation")
        index.apply_page("source-generation", SourceIndexEpochPage(
            namespace, 1, (SourceIndexMutation(source, 1, 1, True),),
        ))
        index.apply_page("source-generation", SourceIndexEpochPage(
            namespace, 2,
            (SourceIndexMutation(source, 1, 2, False, "revocation"),),
        ))
        index.activate(namespace, "source-generation",
                       NamespaceEpoch(*namespace.as_tuple, 2))
    finally:
        index.close()

    seal = seal_projection_namespace_v1(origin, namespace)
    assert seal.active_watermark == 2
    assert seal.source_count == 0
    assert seal.block_count == 1
    assert seal_projection_namespace_v1(origin, namespace).content_digest == seal.content_digest
    plan = inspect_target_projection_rebuild_v1(
        seal, target_path=target, source_path=origin,
        target_graph_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
        new_generation_id="target-replay",
    )
    assert plan.status == "hold_w01_target_graph_replay_and_authority"
    assert not target.exists()
    shutil.copyfile(origin, target)
    with pytest.raises(ValueError, match="already has"):
        inspect_target_projection_rebuild_v1(
            seal, target_path=target, source_path=origin,
            target_graph_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
            new_generation_id="target-replay",
        )
    with pytest.raises(ValueError, match="cannot reuse"):
        inspect_target_projection_rebuild_v1(
            seal, target_path=origin, source_path=origin,
            target_graph_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
            new_generation_id="target-replay",
        )
    with sqlite3.connect(origin) as db:
        db.execute("DELETE FROM d06_index_receipts WHERE epoch=1")
    with pytest.raises(ValueError, match="do not cover"):
        seal_projection_namespace_v1(origin, namespace)
