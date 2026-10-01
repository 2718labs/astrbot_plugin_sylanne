"""The D06 projection purge excludes stale source addresses across generations."""

from pathlib import Path
import sqlite3

import pytest

from sylanne3.domains.d06.deletion_index_erase import erase_d06_projection_index_v1
from sylanne3.domains.d06.deletion_index_inventory import read_d06_index_deletion_inventory_v1
from sylanne3.domains.d06.projection_index import (
    DurableSourceProjectionIndex, SourceIndexEpochPage, SourceIndexMutation,
)
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


def test_erasure_removes_current_and_retained_rows_and_replays_idempotently(tmp_path: Path):
    path = tmp_path / "installed-index.sqlite"
    namespace = NamespaceId("bot", "persona")
    epoch = NamespaceEpoch("bot", "persona", 1)
    stale = source_key("bot", "persona", "stale").token
    keep = source_key("bot", "persona", "keep").token
    index = DurableSourceProjectionIndex(path)
    try:
        for generation in ("old", "current"):
            index.begin_generation(namespace, generation)
            index.apply_page(generation, SourceIndexEpochPage(namespace, 1, (
                SourceIndexMutation(stale, 1, 1, True),
                SourceIndexMutation(keep, 1, 1, True),
            )))
        index.activate(namespace, "current", epoch)
        before = read_d06_index_deletion_inventory_v1(path, namespace, graph_epoch=epoch)
        assert before.scan_complete and stale in before.active_source_refs
        assert stale in before.inactive_source_refs

        receipt = erase_d06_projection_index_v1(
            path, namespace, graph_epoch=epoch, source_refs=(stale,),
            operation_id="delete-stale", expected_inventory_digest=before.sidecar_digest,
        )
        assert receipt.erased_rows == 2
        assert receipt.tombstoned_refs == 1
        assert erase_d06_projection_index_v1(
            path, namespace, graph_epoch=epoch, source_refs=(stale,),
            operation_id="delete-stale", expected_inventory_digest=before.sidecar_digest,
        ) == receipt
        with pytest.raises(ValueError, match="inventory changed"):
            erase_d06_projection_index_v1(
                path, namespace, graph_epoch=epoch, source_refs=(keep,),
                operation_id="different", expected_inventory_digest=before.sidecar_digest,
            )

        after = read_d06_index_deletion_inventory_v1(path, namespace, graph_epoch=epoch)
        assert stale not in after.active_source_refs
        assert stale not in after.inactive_source_refs
        assert stale in after.blocked_source_refs
        assert index.candidate_page(namespace, current_epoch=epoch).candidates == (
            SourceIndexMutation(keep, 1, 1, True),
        )
        index.activate(namespace, "old", epoch)
        assert index.candidate_page(namespace, current_epoch=epoch).candidates == (
            SourceIndexMutation(keep, 1, 1, True),
        )
        with sqlite3.connect(path) as db:
            assert db.execute("SELECT count(*) FROM d06_index_receipts").fetchone() == (2,)
            assert db.execute("SELECT reason FROM d06_index_source_blocks WHERE source_ref=?",
                              (stale,)).fetchone() == ("deletion",)
    finally:
        index.close()
