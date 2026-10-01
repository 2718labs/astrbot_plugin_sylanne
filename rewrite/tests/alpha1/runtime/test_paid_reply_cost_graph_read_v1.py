"""The reply gate must join host cost identity to durable graph/D11 rows.

The accounting port in this fixture is synthetic; this exercises the
coordinator's persisted SQL read, not a production Authority qualification.
"""

from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from test_first_encoding_cost_graph_commit import _case


def test_paid_reply_cost_read_requires_graph_atom_and_budget_settle(tmp_path):
    store, coordinator, bootstrap, namespace, intent, _accounting = _case(
        tmp_path, work_kind="reply")
    try:
        cost = coordinator.commit_post_c02_reply_model_cost_v1(
            bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        queued = SimpleNamespace(
            original_operation_id="original",
            quote=SimpleNamespace(
                quote_id="quote", version=1,
                parent_budget_lease_ref="lease", effect_id=None),
        )
        progress = SimpleNamespace(
            run=SimpleNamespace(preparation=SimpleNamespace(intent=intent)),
            cost=cost,
        )
        with store._lock:
            store._db.execute("BEGIN")
            try:
                coordinator._verify_paid_reply_model_cost_locked(
                    namespace, queued, progress)
            finally:
                store._db.execute("ROLLBACK")
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?", (cost.cost_ref,))
        store._db.commit()
        with store._lock:
            store._db.execute("BEGIN")
            try:
                with pytest.raises(UnavailableGuard, match="graph or budget"):
                    coordinator._verify_paid_reply_model_cost_locked(
                        namespace, queued, progress)
            finally:
                store._db.execute("ROLLBACK")
        store._db.execute(
            "UPDATE graph_atoms SET valid=1 WHERE token=?", (cost.cost_ref,))
        store._db.execute(
            "UPDATE runtime_budget_operations SET receipt_json='{}' "
            "WHERE operation_id='original' AND phase='settle'")
        store._db.commit()
        with store._lock:
            store._db.execute("BEGIN")
            try:
                with pytest.raises(UnavailableGuard, match="graph or budget"):
                    coordinator._verify_paid_reply_model_cost_locked(
                        namespace, queued, progress)
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()
