"""A typed authored-root claim cannot enter the generic graph writer."""

import pytest

from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry

from rewrite.tests.alpha1.contracts.test_d04_root_adoption_contract_v2 import (
    _bundle, _envelope, _evidence,
)
from dataclasses import replace


def test_generic_root_evidence_is_held_before_any_graph_write() -> None:
    envelope = _envelope()
    base = _bundle(envelope)
    evidence = _evidence(envelope)
    bundle = _bundle(envelope, replace(
        evidence, bundle_digest=base.root_digest_with(evidence),
    ))
    graph = GraphCoordinator.__new__(GraphCoordinator)

    with pytest.raises(UnavailableGuard, match="dedicated installed adoption"):
        graph.commit_domain_bundle(bundle, object())
    with pytest.raises(UnavailableGuard, match="dedicated installed adoption"):
        graph._commit_domain_bundle_v2(bundle, object())
    with pytest.raises(UnavailableGuard, match="dedicated installed adoption"):
        graph._commit_domain_bundle_fenced(bundle, object())


def test_root_v2_original_schema_is_provisioned_on_new_and_reopened_graph(tmp_path) -> None:
    path = tmp_path / "root-graph.db"
    for _ in range(2):
        store = GraphStore(path, TypeRegistry())
        try:
            db = store._db
            assert db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='graph_d04_root_adoption_originals_v2'",
            ).fetchone() == (1,)
            assert {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name='graph_d04_root_adoption_originals_v2'",
            )} == {"graph_d04_root_adoption_no_update_v2",
                   "graph_d04_root_adoption_no_delete_v2"}
        finally:
            store.close()
