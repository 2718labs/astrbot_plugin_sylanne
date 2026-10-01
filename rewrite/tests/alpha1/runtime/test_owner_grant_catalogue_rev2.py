"""The Owner rev2 validator upgrades only its exact prior catalogue hash."""

import hashlib
import json

import pytest

from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import (
    OWNER_GRANT_TYPE, GraphCandidate, GraphVersion, GraphWrite,
    owner_grant_key, owner_grant_spec,
)
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ROLE


def test_owner_catalogue_rev1_hash_reopens_with_exact_rev2_validator(tmp_path):
    live = _real_owner_chain(tmp_path)
    graph = live.resources[0]
    old = hashlib.sha256(
        b"sylanne3.graph.owner_grant.v1:strict:pending").hexdigest()
    try:
        with graph._lock:
            graph._db.execute(
                "UPDATE graph_type_authority SET schema_hash=? WHERE name=?",
                (old, OWNER_GRANT_TYPE),
            )
        reopened = ProductionGraphStore(tmp_path / "business.db", graph._registry)
        try:
            assert reopened._db.execute(
                "SELECT schema_hash FROM graph_type_authority WHERE name=?",
                (OWNER_GRANT_TYPE,),
            ).fetchone() == (owner_grant_spec().schema_hash,)
        finally:
            reopened.close()
        key = owner_grant_key(*ROLE.as_tuple)
        original = json.loads(graph._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (key.token,),
        ).fetchone()[0])
        revoked = {**original, "grant_revision": 2, "state": "revoked"}
        epoch = GraphStore.graph_epoch(
            graph, *ROLE.as_tuple, _capability=graph._coordinator_capability)
        with pytest.raises(PermissionError, match="Owner grant"):
            GraphStore.graph_commit(
                graph,
                GraphCandidate(
                    Event(Scope(*ROLE.as_tuple, "unauthorized"),
                          "rev2-bypass", 0, "revoke", {}),
                    (GraphVersion(key, 1),), (GraphWrite(key, revoked),), (epoch,),
                ),
                _capability=graph._coordinator_capability,
            )
        assert graph._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?", (key.token,),
        ).fetchone() == (1,)
        with graph._lock:
            graph._db.execute(
                "UPDATE graph_type_authority SET schema_hash=? WHERE name=?",
                ("0" * 64, OWNER_GRANT_TYPE),
            )
        with pytest.raises(ValueError, match="catalogue"):
            ProductionGraphStore(tmp_path / "business.db", graph._registry)
    finally:
        for resource in live.resources:
            resource.close()
