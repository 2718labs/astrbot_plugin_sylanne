"""The natural P2 helper cannot mint a claim outside a real graph transaction."""

from pathlib import Path

import pytest

from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.natural_dispatch_claim_v2 import (
    NaturalDispatchClaimHold, prepare_natural_dispatch_claim_v2,
)


def test_natural_p2_requires_real_graph_transaction_and_typed_evidence(tmp_path: Path):
    store = GraphStore(tmp_path / "natural-p2.db", TypeRegistry())
    arguments = dict(
        namespace=None, admission_receipt=None, request=None,
        evidence=None, operation=None, batch={}, original_scope_proof=None,
        current_route=None, context=None, binding=None, claimed=None,
        witness=None, authority_snapshot=None, now_utc=1.0,
    )
    try:
        with pytest.raises(NaturalDispatchClaimHold, match="typed final natural"):
            prepare_natural_dispatch_claim_v2(db=store._db, **arguments)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(NaturalDispatchClaimHold,
                                   match="typed final natural"):
                    prepare_natural_dispatch_claim_v2(db=store._db, **arguments)
                assert store._db.execute(
                    "SELECT COUNT(*) FROM graph_events").fetchone()[0] == 0
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()
